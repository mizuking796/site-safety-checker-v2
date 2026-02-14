/**
 * Site Safety Checker — Cloudflare Worker
 *
 * Endpoints:
 *   GET  /fetch?url=<encoded>  — Fetch target site HTML + headers
 *   POST /models/*             — Gemini API passthrough (CORS proxy)
 */

const ALLOWED_ORIGINS = [
  'https://mizuking796.github.io',
  'http://localhost',
  'http://127.0.0.1',
  'null', // file:// origin
];

function getCorsHeaders(request) {
  const origin = request.headers.get('Origin') || '';
  if (ALLOWED_ORIGINS.some(o => origin === o || origin.startsWith(o + ':') || origin.startsWith(o + '/'))) {
    return {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-API-Key',
    };
  }
  return {
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-API-Key',
  };
}

const MAX_HTML_SIZE = 200 * 1024; // 200KB
const MAX_RELATED_HTML_SIZE = 50 * 1024; // 50KB per related page
const MAX_PROXY_BODY = 500 * 1024; // 500KB
const FETCH_TIMEOUT = 10000; // 10s
const RELATED_FETCH_TIMEOUT = 5000; // 5s per related page
const MAX_REDIRECTS = 5;
const MAX_RELATED_PAGES = 5;
const ALLOWED_CHARSETS = ['utf-8','shift_jis','euc-jp','iso-8859-1','windows-1252','shift-jis','windows-31j'];

// Important page patterns for related page discovery
const PAGE_PATTERNS = [
  { type: 'commerce_law', priority: 1,
    urlRe: /\/(tokushoho|law|commerce|trading|scta|tokutei)/i,
    textRe: /特定商取引|特商法|返品[特交]|返金[ポ規]/i },
  { type: 'company_info', priority: 2,
    urlRe: /\/(company|about|corporate|info|gaiyou|kaisya)/i,
    textRe: /会社概要|企業情報|運営会社|運営者情報|about\s*us/i },
  { type: 'privacy_policy', priority: 3,
    urlRe: /\/(privacy|privacypolicy)/i,
    textRe: /プライバシー|個人情報保護|privacy/i },
  { type: 'contact', priority: 4,
    urlRe: /\/(contact|inquiry|otoiawase|toiawase)/i,
    textRe: /お問い合わせ|連絡先|contact/i },
];

// Comprehensive private IP check (IPv4 + IPv6)
function isPrivateIP(hostname) {
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, '');

  // Literal blocklist
  if (['localhost','0.0.0.0','::1','::','0','127.0.0.1'].includes(h)) return true;

  // IPv6 patterns
  if (h.includes(':')) {
    if (h.startsWith('::ffff:')) return true;  // IPv4-mapped IPv6
    if (h.startsWith('fe80')) return true;      // link-local
    if (h.startsWith('fd') || h.startsWith('fc')) return true;  // unique local
    if (h === '::1' || h === '::') return true;
    return false;
  }

  // Block single-integer decimal IP (e.g., 2130706433 = 127.0.0.1)
  if (/^\d+$/.test(h)) return true;

  // Block hex IP (e.g., 0x7f000001)
  if (/^0x/i.test(h)) return true;

  // IPv4 decimal-dot
  const parts = h.split('.');
  if (parts.length === 4 && parts.every(p => /^\d+$/.test(p))) {
    // Block octal notation (leading zeros)
    if (parts.some(p => p.length > 1 && p.startsWith('0'))) return true;

    const a = parseInt(parts[0]);
    const b = parseInt(parts[1]);
    if (a === 0) return true;                            // 0.0.0.0/8
    if (a === 10) return true;                           // 10.0.0.0/8
    if (a === 100 && b >= 64 && b <= 127) return true;  // 100.64.0.0/10 (CGNAT)
    if (a === 127) return true;                          // 127.0.0.0/8
    if (a === 169 && b === 254) return true;             // 169.254.0.0/16
    if (a === 172 && b >= 16 && b <= 31) return true;    // 172.16.0.0/12
    if (a === 192 && b === 168) return true;             // 192.168.0.0/16
    if (a === 198 && (b === 18 || b === 19)) return true;// 198.18.0.0/15
  }

  // Non-decimal IPv4 (octal/hex mixed) — block if hostname looks like a numeric IP
  if (/^[0-9ox.]+$/i.test(h) && !/^[\d.]+$/.test(h)) return true;

  return false;
}

// Manual redirect following with SSRF check at each hop
async function fetchWithRedirects(url, signal) {
  let currentUrl = url;
  const redirectChain = [];

  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    const parsed = new URL(currentUrl);
    if (isPrivateIP(parsed.hostname)) {
      return { error: 'Redirect to private IP blocked', status: 403 };
    }

    // Use parsed.href to ensure IDN domains are converted to Punycode
    const resp = await fetch(parsed.href, {
      signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; SiteSafetyChecker/1.0)',
        'Accept': 'text/html,application/xhtml+xml,*/*',
        'Accept-Language': 'ja,en;q=0.9',
      },
      redirect: 'manual',
    });

    if ([301, 302, 303, 307, 308].includes(resp.status)) {
      const location = resp.headers.get('Location');
      if (!location) break;
      const nextUrl = new URL(location, currentUrl).toString();
      redirectChain.push(nextUrl);
      currentUrl = nextUrl;
      continue;
    }

    return { resp, finalUrl: currentUrl, redirectChain };
  }

  return { error: 'Too many redirects', status: 502 };
}

// Extract same-domain links from HTML using regex (Workers have no DOMParser)
function extractSameDomainLinks(html, baseUrl) {
  const links = [];
  const baseHost = new URL(baseUrl).hostname;
  const re = /<a\s[^>]*href\s*=\s*["']([^"'#]+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    try {
      const href = new URL(m[1], baseUrl);
      if (href.hostname === baseHost && href.protocol.startsWith('http')) {
        const text = m[2].replace(/<[^>]*>/g, '').trim();
        links.push({ url: href.href, text });
      }
    } catch {}
  }
  // Deduplicate by path (ignore query/hash)
  const seen = new Set();
  return links.filter(l => {
    const key = l.url.split('?')[0].split('#')[0];
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// Classify links by importance pattern, return top N
function classifyLinks(links, maxCount) {
  const matched = []; // { url, type, priority }
  const typeUsed = new Set();

  for (const link of links) {
    for (const pat of PAGE_PATTERNS) {
      if (typeUsed.has(pat.type)) continue;
      if (pat.urlRe.test(link.url) || pat.textRe.test(link.text)) {
        matched.push({ url: link.url, type: pat.type, priority: pat.priority });
        typeUsed.add(pat.type);
        break;
      }
    }
  }

  return matched
    .sort((a, b) => a.priority - b.priority)
    .slice(0, maxCount);
}

// Fetch a single related page with size limit and timeout
async function fetchRelatedPage(target, baseHost) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), RELATED_FETCH_TIMEOUT);

  try {
    const result = await fetchWithRedirects(target.url, controller.signal);
    clearTimeout(timeout);

    if (result.error) {
      clearTimeout(timeout);
      return { url: target.url, type: target.type, status: 0, html: '' };
    }

    const { resp, finalUrl } = result;

    // Skip if redirected to a different domain
    try {
      if (new URL(finalUrl).hostname !== baseHost) {
        return { url: target.url, type: target.type, status: 0, html: '' };
      }
    } catch {
      return { url: target.url, type: target.type, status: 0, html: '' };
    }

    const ct = resp.headers.get('content-type') || '';
    if (!ct.includes('text/html') && !ct.includes('application/xhtml')) {
      return { url: target.url, type: target.type, status: resp.status, html: '' };
    }

    const arrayBuf = await resp.arrayBuffer();
    const bytes = arrayBuf.byteLength > MAX_RELATED_HTML_SIZE
      ? arrayBuf.slice(0, MAX_RELATED_HTML_SIZE)
      : arrayBuf;

    let charset = 'utf-8';
    const charsetMatch = ct.match(/charset=([^\s;]+)/i);
    if (charsetMatch && ALLOWED_CHARSETS.includes(charsetMatch[1].toLowerCase())) {
      charset = charsetMatch[1];
    }
    let html;
    try {
      html = new TextDecoder(charset, { fatal: false }).decode(bytes);
    } catch {
      html = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    }

    return { url: target.url, type: target.type, status: resp.status, html };
  } catch {
    clearTimeout(timeout);
    return { url: target.url, type: target.type, status: 0, html: '' };
  }
}

async function handleFetch(request, url, relatedCount) {
  // Require valid Gemini API key for /fetch to prevent open proxy abuse
  const apiKey = request.headers.get('X-API-Key');
  if (!apiKey || !/^AIza[A-Za-z0-9_-]{35}$/.test(apiKey)) {
    return jsonResponse(request, { error: 'Missing or invalid API key' }, 401);
  }

  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return jsonResponse(request, { error: 'Invalid URL' }, 400);
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return jsonResponse(request, { error: 'Only HTTP/HTTPS supported' }, 400);
  }

  if (isPrivateIP(parsed.hostname)) {
    return jsonResponse(request, { error: 'Private IP addresses not allowed' }, 403);
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT);

    const result = await fetchWithRedirects(url, controller.signal);

    if (result.error) {
      clearTimeout(timeout);
      return jsonResponse(request, { error: result.error }, result.status);
    }

    const { resp, finalUrl, redirectChain } = result;

    // Collect response headers
    const headers = {};
    for (const [k, v] of resp.headers.entries()) {
      headers[k.toLowerCase()] = v;
    }

    // Read HTML (limit size) — timeout covers body read too
    const contentType = headers['content-type'] || '';
    const isHtml = contentType.includes('text/html') || contentType.includes('application/xhtml');
    let html = '';

    if (isHtml) {
      const arrayBuf = await resp.arrayBuffer();
      clearTimeout(timeout);
      const bytes = arrayBuf.byteLength > MAX_HTML_SIZE
        ? arrayBuf.slice(0, MAX_HTML_SIZE)
        : arrayBuf;

      let charset = 'utf-8';
      const charsetMatch = contentType.match(/charset=([^\s;]+)/i);
      if (charsetMatch && ALLOWED_CHARSETS.includes(charsetMatch[1].toLowerCase())) {
        charset = charsetMatch[1];
      }
      try {
        html = new TextDecoder(charset, { fatal: false }).decode(bytes);
      } catch {
        html = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
      }
    } else {
      clearTimeout(timeout);
    }

    // Fetch related pages if requested and main page is HTML
    let related = [];
    if (relatedCount > 0 && isHtml && html) {
      const baseHost = new URL(finalUrl).hostname;
      const links = extractSameDomainLinks(html, finalUrl);
      const targets = classifyLinks(links, relatedCount);

      if (targets.length > 0) {
        const results = await Promise.allSettled(
          targets.map(t => fetchRelatedPage(t, baseHost))
        );
        related = results
          .filter(r => r.status === 'fulfilled' && r.value.status > 0)
          .map(r => r.value);
      }
    }

    const responseData = {
      status: resp.status,
      finalUrl,
      redirected: redirectChain.length > 0,
      redirectChain,
      isHtml,
      headers,
      html,
    };
    if (related.length > 0) {
      responseData.related = related;
    }

    return jsonResponse(request, responseData);

  } catch (e) {
    if (e.name === 'AbortError') {
      return jsonResponse(request, { error: 'Fetch timeout' }, 504);
    }
    return jsonResponse(request, { error: `Failed to fetch: ${e.message || 'unknown error'}` }, 502);
  }
}

async function handleGeminiProxy(request, path) {
  // Strict path validation: only allow generateContent, require alphanumeric start
  if (!/^models\/[a-zA-Z][\w.-]*:generateContent$/.test(path)) {
    return jsonResponse(request, { error: 'Invalid API path' }, 400);
  }

  // API key from header (not query param)
  const apiKey = request.headers.get('X-API-Key');
  if (!apiKey) {
    return jsonResponse(request, { error: 'Missing API key' }, 401);
  }

  // Body size limit
  const body = request.method === 'POST' ? await request.text() : undefined;
  if (body && body.length > MAX_PROXY_BODY) {
    return jsonResponse(request, { error: 'Request body too large' }, 413);
  }

  const geminiUrl = `https://generativelanguage.googleapis.com/v1beta/${path}?key=${encodeURIComponent(apiKey)}`;

  const resp = await fetch(geminiUrl, {
    method: request.method,
    headers: { 'Content-Type': 'application/json' },
    body,
  });

  const respBody = await resp.text();
  const cors = getCorsHeaders(request);
  return new Response(respBody, {
    status: resp.status,
    headers: {
      'Content-Type': 'application/json',
      ...cors,
    },
  });
}

function jsonResponse(request, data, status = 200) {
  const cors = getCorsHeaders(request);
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...cors,
    },
  });
}

export default {
  async fetch(request) {
    const cors = getCorsHeaders(request);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    if (path === '/fetch' && request.method === 'GET') {
      const targetUrl = url.searchParams.get('url');
      if (!targetUrl) {
        return jsonResponse(request, { error: 'Missing url parameter' }, 400);
      }
      const relatedParam = parseInt(url.searchParams.get('related') || '0', 10);
      const relatedCount = Math.max(0, Math.min(MAX_RELATED_PAGES, isNaN(relatedParam) ? 0 : relatedParam));
      return handleFetch(request, targetUrl, relatedCount);
    }

    if (path.startsWith('/models/')) {
      const geminiPath = path.slice(1);
      return handleGeminiProxy(request, geminiPath);
    }

    if (path === '/' || path === '/health') {
      return jsonResponse(request, { status: 'ok', service: 'Site Safety Checker Worker' });
    }

    return jsonResponse(request, { error: 'Not found' }, 404);
  },
};
