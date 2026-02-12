(function() {
'use strict';

// ============================================================
// Config & Storage
// ============================================================
const STORAGE_KEY = 'ssc_config';
const DEFAULT_WORKER_URL = 'https://site-safety-checker.mizuki-tools.workers.dev';

function loadConfig() {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY)) || {}; } catch { return {}; }
}
function saveConfig(cfg) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(cfg));
}

function hasConsent() {
  return !!localStorage.getItem('ssc_consent');
}
function setConsent() {
  localStorage.setItem('ssc_consent', new Date().toISOString().slice(0, 10));
}

function loadSensitivity() {
  return localStorage.getItem('ssc_sensitivity') || 'standard';
}
function saveSensitivity(val) {
  localStorage.setItem('ssc_sensitivity', val);
}

// ============================================================
// Router
// ============================================================
const screens = ['screenConsent', 'screenSetup', 'screenCheck', 'screenResults', 'screenSettings'];

function showScreen(id) {
  screens.forEach(s => {
    const el = document.getElementById(s);
    if (el) el.hidden = (s !== id);
  });
}

// ============================================================
// URL Analyzer (client-side, no network)
// ============================================================
const UrlAnalyzer = {
  SUSPICIOUS_TLDS: ['xyz','top','icu','buzz','club','online','site','fun','monster','click',
    'link','work','rest','gq','ml','cf','ga','tk','pw','cc','ws','info','bid','stream','racing',
    'download','win','review','trade','loan','cricket','science','party','date'],

  BRANDS: ['amazon','rakuten','yahoo','google','apple','microsoft','facebook','instagram',
    'twitter','paypal','netflix','docomo','softbank','mercari','paypay',
    'smbc','mufg','mizuho','jpbank','aeon','familymart','lawson','uniqlo'],

  analyze(urlStr) {
    const result = {
      domain_trust: 100,
      tech_safety: 100,
      issues: []
    };

    let url;
    try { url = new URL(urlStr); } catch {
      return { domain_trust: 0, tech_safety: 0, issues: [{ title: '無効なURL', severity: 'critical' }] };
    }

    // HTTP check
    if (url.protocol === 'http:') {
      result.tech_safety -= 30;
      result.issues.push({ title: 'SSL未使用（HTTP）', severity: 'high', desc: '暗号化されていない通信です。' });
    }

    // IP address URL
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(url.hostname)) {
      result.domain_trust -= 40;
      result.issues.push({ title: 'IPアドレスURL', severity: 'high', desc: 'ドメイン名ではなくIPアドレスが使われています。' });
    }

    // Suspicious TLD
    const tld = url.hostname.split('.').pop().toLowerCase();
    if (this.SUSPICIOUS_TLDS.includes(tld)) {
      result.domain_trust -= 20;
      result.issues.push({ title: `不審なTLD (.${tld})`, severity: 'medium', desc: '詐欺サイトで多用されるトップレベルドメインです。' });
    }

    // Excessive subdomains
    const parts = url.hostname.split('.');
    if (parts.length > 4) {
      result.domain_trust -= 15;
      result.issues.push({ title: '過剰なサブドメイン', severity: 'medium', desc: `${parts.length}階層のサブドメインがあります。` });
    }

    // Brand typosquatting
    const hostLower = url.hostname.toLowerCase().replace(/[^a-z0-9]/g, '');
    for (const brand of this.BRANDS) {
      if (hostLower.includes(brand) && !url.hostname.endsWith('.' + brand + '.com') &&
          !url.hostname.endsWith('.' + brand + '.co.jp') && !url.hostname.endsWith('.' + brand + '.jp') &&
          url.hostname !== brand + '.com' && url.hostname !== brand + '.co.jp' && url.hostname !== brand + '.jp' &&
          url.hostname !== 'www.' + brand + '.com' && url.hostname !== 'www.' + brand + '.co.jp') {
        result.domain_trust -= 30;
        result.issues.push({
          title: `ブランド偽装の疑い（${brand}）`,
          severity: 'high',
          desc: `「${brand}」を含むが公式ドメインではありません。`
        });
        break;
      }
    }

    // IDN homograph — only flag if mixed scripts or resembles a known brand
    // Pure Japanese/Chinese/Korean IDN domains are legitimate (e.g. 君塚法律事務所.com)
    if (/xn--/.test(url.hostname)) {
      let decoded;
      try { decoded = new URL(urlStr).hostname; } catch { decoded = url.hostname; }
      // Check if it contains Latin characters mixed with non-Latin (homograph risk)
      const hasLatin = /[a-zA-Z]/.test(decoded.replace(/\.[a-z]+$/, ''));
      const hasNonLatin = /[^\x00-\x7F]/.test(decoded);
      if (hasLatin && hasNonLatin) {
        // Mixed scripts: possible homograph attack (e.g. аmazon.com with Cyrillic а)
        result.domain_trust -= 25;
        result.issues.push({ title: 'IDNホモグラフの疑い', severity: 'high', desc: 'ドメイン名にラテン文字と非ラテン文字が混在しています。ブランド偽装の可能性があります。' });
      }
      // Pure non-Latin IDN (Japanese, etc.) — no penalty, it's normal
    }

    // Suspicious path keywords
    const pathLower = (url.pathname + url.search).toLowerCase();
    const suspiciousPath = ['login','signin','verify','secure','account','update','confirm','banking','wallet'];
    const found = suspiciousPath.filter(k => pathLower.includes(k));
    if (found.length >= 2) {
      result.domain_trust -= 10;
      result.issues.push({ title: '不審なパスキーワード', severity: 'low', desc: `パスに「${found.join('」「')}」が含まれています。` });
    }

    // Excessive hyphens in hostname (4+)
    const hyphenCount = (url.hostname.match(/-/g) || []).length;
    if (hyphenCount >= 4) {
      result.domain_trust -= 10;
      result.issues.push({ title: '過剰なハイフン', severity: 'low', desc: `ホスト名に${hyphenCount}個のハイフンがあります。` });
    }

    // Abnormal port
    if (url.port && !['80','443',''].includes(url.port)) {
      result.tech_safety -= 15;
      result.issues.push({ title: '異常なポート番号', severity: 'medium', desc: `ポート ${url.port} が使用されています。` });
    }

    // Excessive path depth (6+)
    const pathSegments = url.pathname.split('/').filter(Boolean);
    if (pathSegments.length >= 6) {
      result.domain_trust -= 10;
      result.issues.push({ title: '過剰なパス深度', severity: 'low', desc: `パスが${pathSegments.length}階層あります。` });
    }

    // Long URL — check path length only (exclude query params like gclid, utm_*, fbclid)
    const pathLen = (url.origin + url.pathname).length;
    if (pathLen > 200) {
      result.domain_trust -= 5;
      result.issues.push({ title: '異常に長いURL', severity: 'low', desc: `パス長: ${pathLen}文字` });
    }

    // Clamp
    result.domain_trust = Math.max(0, Math.min(100, result.domain_trust));
    result.tech_safety = Math.max(0, Math.min(100, result.tech_safety));

    return result;
  }
};

// ============================================================
// HTML Content Extractor (DOMParser, client-side)
// ============================================================
const HtmlExtractor = {
  extract(html, baseUrl) {
    const parser = new DOMParser();
    const doc = parser.parseFromString(html, 'text/html');
    const result = {};

    // Title
    result.title = doc.title || '';

    // Meta
    result.meta = {};
    doc.querySelectorAll('meta').forEach(m => {
      const name = m.getAttribute('name') || m.getAttribute('property') || '';
      const content = m.getAttribute('content') || '';
      if (name && content) result.meta[name.toLowerCase()] = content.slice(0, 200);
    });

    // Headings
    result.headings = [];
    doc.querySelectorAll('h1,h2,h3').forEach(h => {
      const t = h.textContent.trim();
      if (t) result.headings.push(t.slice(0, 200));
    });
    result.headings = result.headings.slice(0, 20);

    // Body text: head 8000 chars + tail 2000 chars (for footer/operator info)
    const bodyTextFull = (doc.body ? doc.body.textContent : '').replace(/\s+/g, ' ').trim();
    if (bodyTextFull.length <= 10000) {
      result.bodyText = bodyTextFull;
    } else {
      const head = bodyTextFull.slice(0, 8000);
      const tail = bodyTextFull.slice(-2000);
      result.bodyText = head + '\n[...中略...]\n' + tail;
    }
    result._bodyTextFull = bodyTextFull; // keep full text for regex checks

    // Links analysis
    const links = Array.from(doc.querySelectorAll('a[href]'));
    const externalLinks = [];
    let host;
    try { host = new URL(baseUrl).hostname; } catch { host = ''; }
    links.forEach(a => {
      try {
        const href = new URL(a.href, baseUrl);
        if (href.hostname && href.hostname !== host) {
          externalLinks.push(href.hostname);
        }
      } catch {}
    });
    result.externalLinkCount = externalLinks.length;
    result.externalDomains = [...new Set(externalLinks)].slice(0, 20);

    // Forms
    const forms = doc.querySelectorAll('form');
    result.forms = [];
    forms.forEach(f => {
      const inputs = Array.from(f.querySelectorAll('input')).map(i => ({
        type: i.type || 'text',
        name: i.name || ''
      }));
      const hasPassword = inputs.some(i => i.type === 'password');
      const hasCard = inputs.some(i => /card|credit|cvv|ccv/i.test(i.name));
      result.forms.push({ action: f.action || '', method: f.method || 'get', hasPassword, hasCard, inputCount: inputs.length });
    });

    // Scripts analysis — only flag heavy obfuscation, not normal minified/analytics code
    const scripts = doc.querySelectorAll('script');
    let inlineScriptChars = 0;
    let obfuscationSuspect = false;
    scripts.forEach(s => {
      if (!s.src) {
        const code = s.textContent || '';
        inlineScriptChars += code.length;
        // Only flag if multiple suspicious patterns co-occur in the SAME script block
        // Single atob() or eval() is common in analytics/tag managers
        const suspiciousCount = [
          /eval\s*\(/.test(code),
          /atob\s*\(/.test(code),
          /fromCharCode/.test(code),
          /\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}/i.test(code), // 3+ hex escapes
          /\\u[0-9a-f]{4}.*\\u[0-9a-f]{4}.*\\u[0-9a-f]{4}/i.test(code), // 3+ unicode escapes
          /document\.write\s*\(/.test(code) && /unescape|decodeURI/.test(code),
        ].filter(Boolean).length;
        if (suspiciousCount >= 2) {
          obfuscationSuspect = true;
        }
      }
    });
    result.inlineScriptChars = inlineScriptChars;
    result.obfuscationSuspect = obfuscationSuspect;

    // Operator info presence — check FULL body text (not truncated) AND link text/href
    const fullText = bodyTextFull.toLowerCase();
    const linkTexts = links.map(a => (a.textContent || '').toLowerCase() + ' ' + (a.getAttribute('href') || '').toLowerCase()).join(' ');
    const allText = fullText + ' ' + linkTexts;
    // Organization info: corporate, law firm, medical, NPO, etc.
    const ORG_INFO_RE = /会社概要|企業情報|企業概要|運営会社|運営者情報|運営情報|事業者[名情]|販売[者業]|屋号|事務所[概名情]|代表弁護士|弁護士登録番号|所属弁護士会|代表取締役|代表者|代表理事|理事長|院長|施設長|クリニック概要|医院概要|病院概要|法人[概情]|団体概要|組織概要|about\s*us|company\s*info|corporate/i;
    result.hasCompanyInfo = ORG_INFO_RE.test(allText);
    // Contact: phone, email, address, access
    result.hasContact = /お問い合わせ|連絡先|contact|電話番号|tel[：:]|mail[：:]|所在地|住所|アクセス[マ情]|fax[：:]/i.test(allText);
    result.hasPrivacyPolicy = /プライバシー|privacy|個人情報保護/i.test(allText);
    result.hasCommerceLaw = /特定商取引|特商法|返品[特交]|返金[ポ規]/i.test(allText);
    // Distinguish: found as link (to another page) vs found in page content
    result.companyInfoInContent = ORG_INFO_RE.test(fullText);
    result.commerceLawInContent = /特定商取引|特商法/i.test(fullText);

    // Hidden elements
    const allEls = doc.querySelectorAll('*');
    let hiddenFormFields = 0;
    allEls.forEach(el => {
      const style = el.getAttribute('style') || '';
      if (/display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0/.test(style)) {
        if (el.tagName === 'INPUT' || el.tagName === 'FORM') hiddenFormFields++;
      }
    });
    result.hiddenFormFields = hiddenFormFields;

    return result;
  }
};

// ============================================================
// Gemini API Client
// ============================================================
const GeminiClient = {
  async analyze(config, urlStr, urlAnalysis, htmlContent, headers, cancelSignal) {
    const workerUrl = (config.workerUrl || DEFAULT_WORKER_URL).replace(/\/+$/, '');
    const apiKey = config.apiKey;

    const sensitivity = loadSensitivity();
    const prompt = this._buildPrompt(urlStr, urlAnalysis, htmlContent, headers, sensitivity);
    const schema = this._responseSchema();

    const body = {
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: {
        responseMimeType: 'application/json',
        responseSchema: schema,
        temperature: 0.1
      }
    };

    const resp = await fetch(`${workerUrl}/models/gemini-2.5-flash:generateContent`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-Key': apiKey },
      body: JSON.stringify(body),
      signal: _combinedSignal(cancelSignal, 60000)
    });

    if (!resp.ok) {
      const errText = await resp.text();
      if (resp.status === 429) {
        throw new Error('Gemini APIの利用上限に達しました。しばらく待ってから再度お試しください。');
      }
      throw new Error(`Gemini API error ${resp.status}: ${errText.slice(0, 200)}`);
    }

    const data = await resp.json();
    const text = data.candidates?.[0]?.content?.parts?.[0]?.text;
    if (!text) throw new Error('Gemini returned empty response');
    let parsed;
    try { parsed = JSON.parse(text); } catch { throw new Error('AI応答のJSON解析に失敗しました'); }
    if (!parsed.scores || typeof parsed.scores.domain_trust !== 'number') {
      throw new Error('AI応答に必須フィールドがありません');
    }
    return parsed;
  },

  // Prescreen: identify relevant categories by keyword matching
  _prescreenCategories(urlAnalysis, htmlContent) {
    const P = window.SSC_PATTERNS;
    if (!P || !P.categories) return [2, 3, 4];

    const parts = [];
    if (htmlContent) {
      if (htmlContent.title) parts.push(htmlContent.title);
      if (htmlContent.headings) parts.push(htmlContent.headings.join(' '));
      if (htmlContent.bodyText) parts.push(htmlContent.bodyText.slice(0, 5000));
    }
    const text = parts.join(' ').toLowerCase();

    const results = P.categories.map(cat => {
      let matchCount = 0;
      for (const kw of cat.keywords) {
        if (text.includes(kw.toLowerCase())) matchCount++;
      }
      return { id: cat.id, matchCount };
    });

    // Force-include based on URL analysis issues
    const issues = urlAnalysis.issues || [];
    if (issues.some(i => i.title.includes('ブランド偽装'))) {
      const r = results.find(x => x.id === 3);
      if (r) r.matchCount = Math.max(r.matchCount, 2);
    }
    if (issues.some(i => i.title.includes('不審なTLD'))) {
      const r = results.find(x => x.id === 4);
      if (r) r.matchCount = Math.max(r.matchCount, 1);
    }

    const matched = results.filter(r => r.matchCount > 0)
      .sort((a, b) => b.matchCount - a.matchCount)
      .slice(0, 5);

    if (matched.length === 0) return [2, 3, 4]; // defaults: investment, phishing, fake shop
    return matched.map(r => r.id);
  },

  _buildPrompt(urlStr, urlAnalysis, htmlContent, headers, sensitivity) {
    const P = window.SSC_PATTERNS;
    const today = new Date().toISOString().slice(0, 10);

    // Prescreen categories
    const matchedIds = this._prescreenCategories(urlAnalysis, htmlContent);
    const matchedCats = P.categories.filter(c => matchedIds.includes(c.id));
    const bodyLower = (htmlContent?.bodyText || '').toLowerCase();
    const adRelevant = P.adViolations.keywords.some(kw => bodyLower.includes(kw.toLowerCase()));

    let sensitivityInstruction = '';
    if (sensitivity === 'high') {
      sensitivityInstruction = '\n## 感度設定: 高感度モード\n疑わしい場合は積極的に低スコアを付けてください。グレーゾーンのサイトは安全側ではなく危険側に寄せて判定してください。\n';
    } else if (sensitivity === 'low') {
      sensitivityInstruction = '\n## 感度設定: 低感度モード\n明確な根拠がある場合のみ低スコアを付けてください。グレーゾーンのサイトは危険側ではなく安全側に寄せて判定してください。\n';
    }

    return `あなたはサイバーセキュリティ専門家です。以下のウェブサイト情報を分析し、詐欺・危険サイトかどうかを判定してください。
本日の日付: ${today}

## 回答ルール（最重要・厳守）
0. **必ず日本語で回答してください。** findings/detected_categories/summaryの全フィールドを日本語で記述すること。
1. findingsのquoteには、サイト本文からの「そのまま引用」のみ記載。存在しない文言を捏造しない。
2. 引用できる原文がない場合はquoteを空文字にする。
3. detected_categoriesのevidenceも、サイト内の具体的表現を根拠として示す。
4. 正当なサイトには高スコアを付ける。疑わしい点がなければ安全と判定する。
5. 推測や可能性だけで低スコアを付けない。具体的根拠がある場合のみ減点する。ただし根拠が明確な場合は躊躇なく低スコアを付けること。
6. 複数カテゴリの部分一致だけで危険と判定しない。文脈と全体像を重視する。ただし、19カテゴリの手口パターンに明確に合致する場合は、scam_patternを20以下にすること。
7. この分析は「現時点でのこのページの内容」のみが対象。過去の行政処分歴や企業の評判は判断材料にしない。
8. 誤検知防止ガイドは正当なサービスを守るためのもの。詐欺サイトが正当なサービスの特徴を装っている場合（例: 偽の登録番号、コピペされた免責文）は保護対象外。
${sensitivityInstruction}
## 対象URL
${urlStr}

## クライアント側URL分析結果
- ドメイン信頼スコア: ${urlAnalysis.domain_trust}/100
- 技術安全スコア: ${urlAnalysis.tech_safety}/100
- 検出された問題: ${urlAnalysis.issues.length > 0 ? urlAnalysis.issues.map(i => i.title).join(', ') : 'なし'}

## HTTPレスポンスヘッダー
${headers ? Object.entries(headers).map(([k,v]) => `${k}: ${v}`).join('\n') : '取得不可'}

## サイトコンテンツ
タイトル: ${htmlContent?.title || '不明'}
見出し: ${htmlContent?.headings?.join(' / ') || 'なし'}
本文テキスト:
${htmlContent?.bodyText || '取得不可'}

外部リンク数: ${htmlContent?.externalLinkCount || 0}
外部ドメイン: ${htmlContent?.externalDomains?.join(', ') || 'なし'}
フォーム: ${htmlContent?.forms?.length || 0}個${htmlContent?.forms?.some(f => f.hasPassword) ? '（パスワード入力あり）' : ''}${htmlContent?.forms?.some(f => f.hasCard) ? '（クレジットカード入力あり）' : ''}
インラインスクリプト: ${htmlContent?.inlineScriptChars || 0}文字
難読化の疑い: ${htmlContent?.obfuscationSuspect ? 'あり' : 'なし'}
隠しフォーム要素: ${htmlContent?.hiddenFormFields || 0}個
会社概要: ${htmlContent?.companyInfoInContent ? 'ページ内に記載あり' : htmlContent?.hasCompanyInfo ? 'リンクあり（別ページに存在）' : 'なし'}
連絡先: ${htmlContent?.hasContact ? 'あり' : 'なし'}
プライバシーポリシー: ${htmlContent?.hasPrivacyPolicy ? 'あり' : 'なし'}
特定商取引法表記: ${htmlContent?.commerceLawInContent ? 'ページ内に記載あり' : htmlContent?.hasCommerceLaw ? 'リンクあり（別ページに存在）' : 'なし'}

## 検出すべき詐欺・違法サイトカテゴリ一覧（19種）
以下は全19カテゴリの概要です。詳細パターンは、事前スクリーニングで関連性が高いと判定されたカテゴリのみ提供します。該当しないカテゴリでも明らかな詐欺パターンがあれば報告してください。

${P.categoryIndex}

## 詳細パターン（スクリーニング結果: ${matchedCats.map(c => 'Cat' + c.id).join(', ')}）
${matchedCats.map(c => c.promptText).join('\n\n')}
${adRelevant ? '\n' + P.adViolations.promptText : ''}

${P.falsePositiveGuide}
## 評価基準
各次元を0-100で評価（100が最も安全）:
- domain_trust: ドメイン信頼性（URL構造、TLD、ブランド偽装、SSL）
- content_safety: コンテンツ安全性（不審キーワード、煽り表現、緊急性）
- operator_transparency: 運営者透明性（特商法表記、会社概要、連絡先）
- claim_credibility: 主張の信頼性（誇大広告、非現実的保証、法令違反表現）
- scam_pattern: 詐欺パターン非合致度（既知パターンとの非類似度。高いほど安全）
- tech_safety: 技術的安全性（SSL、難読化、隠しフォーム）

`;
  },

  _responseSchema() {
    return {
      type: 'object',
      properties: {
        scores: {
          type: 'object',
          properties: {
            domain_trust: { type: 'number' },
            content_safety: { type: 'number' },
            operator_transparency: { type: 'number' },
            claim_credibility: { type: 'number' },
            scam_pattern: { type: 'number' },
            tech_safety: { type: 'number' }
          },
          required: ['domain_trust','content_safety','operator_transparency','claim_credibility','scam_pattern','tech_safety']
        },
        overall_risk: { type: 'string', enum: ['safe','low','medium','high','critical'] },
        detected_categories: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              category: { type: 'string' },
              confidence: { type: 'string', enum: ['high','medium','low'] },
              evidence: { type: 'string' }
            },
            required: ['category','confidence','evidence']
          }
        },
        findings: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              dimension: { type: 'string' },
              severity: { type: 'string', enum: ['critical','high','medium','low','info'] },
              title: { type: 'string' },
              description: { type: 'string' },
              quote: { type: 'string' }
            },
            required: ['dimension','severity','title','description']
          }
        },
        summary: { type: 'string' }
      },
      required: ['scores','overall_risk','detected_categories','findings','summary']
    };
  }
};

// ============================================================
// Score Integrator
// ============================================================
const ScoreIntegrator = {
  DIMENSIONS: [
    { key: 'domain_trust', label: 'ドメイン信頼性', shortLabel: 'ドメイン' },
    { key: 'content_safety', label: 'コンテンツ安全性', shortLabel: 'コンテンツ' },
    { key: 'operator_transparency', label: '運営者透明性', shortLabel: '運営者' },
    { key: 'claim_credibility', label: '主張の信頼性', shortLabel: '主張' },
    { key: 'scam_pattern', label: '詐欺パターン非合致', shortLabel: '詐欺パターン' },
    { key: 'tech_safety', label: '技術的安全性', shortLabel: '技術' }
  ],

  // Sensitivity thresholds
  SENSITIVITY_THRESHOLDS: {
    high:     { criticalDim: 20, warnDim: 35, scamPattern: 35 },
    standard: { criticalDim: 15, warnDim: 30, scamPattern: 30 },
    low:      { criticalDim: 10, warnDim: 20, scamPattern: 20 }
  },

  integrate(clientAnalysis, aiResult) {
    const scores = {};

    if (aiResult) {
      // Blend client + AI for domain_trust and tech_safety
      scores.domain_trust = Math.round(clientAnalysis.domain_trust * 0.4 + aiResult.scores.domain_trust * 0.6);
      scores.tech_safety = Math.round(clientAnalysis.tech_safety * 0.4 + aiResult.scores.tech_safety * 0.6);
      // AI-only for other dimensions
      scores.content_safety = aiResult.scores.content_safety;
      scores.operator_transparency = aiResult.scores.operator_transparency;
      scores.claim_credibility = aiResult.scores.claim_credibility;
      scores.scam_pattern = aiResult.scores.scam_pattern;
    } else {
      // Client-only fallback
      scores.domain_trust = clientAnalysis.domain_trust;
      scores.tech_safety = clientAnalysis.tech_safety;
      scores.content_safety = 50;
      scores.operator_transparency = 50;
      scores.claim_credibility = 50;
      scores.scam_pattern = 50;
    }

    // Clamp all
    for (const k of Object.keys(scores)) {
      scores[k] = Math.max(0, Math.min(100, scores[k]));
    }

    // Load sensitivity thresholds
    const sensitivity = loadSensitivity();
    const thresholds = this.SENSITIVITY_THRESHOLDS[sensitivity] || this.SENSITIVITY_THRESHOLDS.standard;

    // Overall risk
    const avg = Object.values(scores).reduce((a, b) => a + b, 0) / 6;
    let risk;
    if (avg >= 80) risk = 'safe';
    else if (avg >= 60) risk = 'low';
    else if (avg >= 40) risk = 'medium';
    else if (avg >= 20) risk = 'high';
    else risk = 'critical';

    // Override: escalate based on critical dimensions (sensitivity-adjusted)
    const criticalDims = Object.values(scores).filter(v => v <= thresholds.criticalDim).length;
    const warnDims = Object.values(scores).filter(v => v <= thresholds.warnDim).length;
    if (criticalDims >= 2 || scores.scam_pattern <= thresholds.criticalDim) {
      // Multiple critical axes or scam pattern match → force high
      if (risk === 'safe' || risk === 'low' || risk === 'medium') risk = 'high';
    } else if (scores.scam_pattern <= thresholds.scamPattern || warnDims >= 3) {
      // Low scam pattern or many warning axes → at least medium
      if (risk === 'safe' || risk === 'low') risk = 'medium';
    } else if (criticalDims === 1 && risk === 'safe') {
      // Single critical axis on otherwise safe site → nudge to low
      risk = 'low';
    }

    // Use AI's overall_risk if available and more severe
    if (aiResult) {
      const riskOrder = ['safe','low','medium','high','critical'];
      const aiIdx = riskOrder.indexOf(aiResult.overall_risk);
      const calcIdx = riskOrder.indexOf(risk);
      if (aiIdx > calcIdx) risk = aiResult.overall_risk;
    }

    return { scores, risk };
  }
};

// ============================================================
// Radar Chart (Canvas)
// ============================================================
const RadarChart = {
  draw(canvasId, scores) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const dpr = window.devicePixelRatio || 1;
    const size = 300;
    canvas.width = size * dpr;
    canvas.height = size * dpr;
    canvas.style.width = size + 'px';
    canvas.style.height = size + 'px';
    const ctx = canvas.getContext('2d');
    ctx.scale(dpr, dpr);

    const cx = size / 2;
    const cy = size / 2;
    const r = 100;
    const dims = ScoreIntegrator.DIMENSIONS;
    const n = dims.length;
    const angleStep = (Math.PI * 2) / n;
    const startAngle = -Math.PI / 2;

    // Background
    ctx.clearRect(0, 0, size, size);

    // Grid (5 levels)
    for (let level = 1; level <= 5; level++) {
      const lr = (r * level) / 5;
      ctx.beginPath();
      for (let i = 0; i <= n; i++) {
        const angle = startAngle + angleStep * (i % n);
        const x = cx + lr * Math.cos(angle);
        const y = cy + lr * Math.sin(angle);
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.closePath();
      ctx.strokeStyle = '#E0E4E8';
      ctx.lineWidth = 1;
      ctx.stroke();
    }

    // Axis lines
    for (let i = 0; i < n; i++) {
      const angle = startAngle + angleStep * i;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.lineTo(cx + r * Math.cos(angle), cy + r * Math.sin(angle));
      ctx.strokeStyle = '#D0D4D8';
      ctx.lineWidth = 1;
      ctx.stroke();
    }

    // Data polygon
    const values = dims.map(d => (scores[d.key] || 0) / 100);
    const avg = values.reduce((a, b) => a + b, 0) / values.length * 100;

    // Determine color based on average
    let fillColor, strokeColor;
    if (avg >= 70) {
      fillColor = 'rgba(39, 174, 96, 0.25)';
      strokeColor = '#27AE60';
    } else if (avg >= 40) {
      fillColor = 'rgba(243, 156, 18, 0.25)';
      strokeColor = '#F39C12';
    } else {
      fillColor = 'rgba(231, 76, 60, 0.25)';
      strokeColor = '#E74C3C';
    }

    ctx.beginPath();
    for (let i = 0; i <= n; i++) {
      const idx = i % n;
      const angle = startAngle + angleStep * idx;
      const vr = r * values[idx];
      const x = cx + vr * Math.cos(angle);
      const y = cy + vr * Math.sin(angle);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    }
    ctx.closePath();
    ctx.fillStyle = fillColor;
    ctx.fill();
    ctx.strokeStyle = strokeColor;
    ctx.lineWidth = 2.5;
    ctx.stroke();

    // Data points
    for (let i = 0; i < n; i++) {
      const angle = startAngle + angleStep * i;
      const vr = r * values[i];
      const x = cx + vr * Math.cos(angle);
      const y = cy + vr * Math.sin(angle);
      ctx.beginPath();
      ctx.arc(x, y, 4, 0, Math.PI * 2);
      ctx.fillStyle = strokeColor;
      ctx.fill();
    }

    // Labels
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.font = '12px -apple-system, BlinkMacSystemFont, sans-serif';
    ctx.fillStyle = '#555';
    const labelR = r + 22;
    for (let i = 0; i < n; i++) {
      const angle = startAngle + angleStep * i;
      const x = cx + labelR * Math.cos(angle);
      const y = cy + labelR * Math.sin(angle);
      ctx.fillText(dims[i].shortLabel, x, y);
    }
  }
};

// ============================================================
// Progress Manager
// ============================================================
const SAFETY_TIPS = [
  // --- メール・メッセージ ---
  '知らない送信元からのメールのリンクは開かないようにしましょう',
  '「アカウントが停止されました」というメールは、まず公式サイトで確認を',
  'メールの差出人名は簡単に偽装できます。アドレスのドメインを確認しましょう',
  '添付ファイル付きの不審なメールは開かずに削除しましょう',
  'メールのリンクにマウスを乗せると、実際のURLを確認できます',
  '「至急」「緊急」で始まるメールほど、落ち着いて対処しましょう',
  '宅配不在通知のSMSのリンクは偽物の可能性があります',
  '銀行やカード会社がメールでパスワードを聞くことはありません',
  'SMSで届く認証コードは、自分が操作したとき以外は入力しないで',
  '不審なメールは転送せず、公式の問い合わせ窓口に相談しましょう',
  // --- パスワード・認証 ---
  'パスワードは使い回さず、サイトごとに異なるものを設定しましょう',
  '二要素認証（2FA）を設定すると、不正ログインのリスクが大幅に減ります',
  'パスワードマネージャーを使えば、複雑なパスワードも管理が楽です',
  '「1234」「password」などの簡単なパスワードは数秒で破られます',
  '生年月日や電話番号をパスワードに使うのは避けましょう',
  '定期的なパスワード変更より、十分な長さと複雑さが重要です',
  'ログイン画面のURLが正しいか、毎回確認する習慣をつけましょう',
  '公共のPCでログインした後は、必ずログアウトしましょう',
  'パスワードをブラウザに保存する場合は、端末のロックも忘れずに',
  'パスワードリスト攻撃を防ぐため、同じパスワードの使い回しは厳禁です',
  // --- URL・サイト確認 ---
  'URLがhttps://で始まるか確認しましょう',
  'URLに見慣れない文字列が長く続く場合は注意が必要です',
  '正規サイトのURLをブックマークしておくと、偽サイトを避けられます',
  'ドメイン名の「l」と「1」、「o」と「0」の違いに注意しましょう',
  'URLの末尾が.xyz .top .icu など見慣れないTLDは要注意です',
  '検索結果の上位に表示される広告リンクが偽サイトのこともあります',
  'QRコードの上にシールが貼られていないか確認しましょう',
  '短縮URLは展開してから開く習慣をつけましょう',
  'Wi-Fiログインページを装った偽サイトに注意しましょう',
  'リダイレクトが多いサイトは、不正な誘導の可能性があります',
  // --- ネットショッピング ---
  '特定商取引法の表記がないネットショップは要注意です',
  '相場より極端に安い商品は、偽物や詐欺の可能性があります',
  '支払い方法が銀行振込のみの通販サイトは注意が必要です',
  'レビューが極端に良いだけの商品は、サクラレビューの可能性があります',
  '通販サイトの会社住所をGoogleマップで確認してみましょう',
  '海外通販は返品・返金のハードルが高いことを覚えておきましょう',
  '初めてのショップでは少額の買い物から試すのが安全です',
  'クレジットカードの明細は定期的にチェックしましょう',
  '代引きでも届いた中身が注文と違う詐欺があります',
  'フリマアプリでは必ずアプリ内決済を利用し、外部での直接取引は避けましょう',
  // --- 投資・お金 ---
  '「確実に儲かる」投資話は詐欺の可能性が高いです',
  '「元本保証」をうたう投資商品は法律上ほぼ存在しません',
  '知人からの投資勧誘でも、マルチ商法の可能性を疑いましょう',
  '暗号資産の「必ず値上がりする」という話は信じないでください',
  'FX自動売買ツールの高額販売は、ほとんどが詐欺です',
  '投資セミナーの参加費が無料でも、高額商材の勧誘に注意',
  '「今だけ」「あなただけ」の投資話は典型的な詐欺の手口です',
  '金融庁の登録がない業者での投資は極めて危険です',
  '海外の無登録FX業者は出金できなくなるトラブルが多発しています',
  'SNSで見かける投資成功体験は、演出されたものがほとんどです',
  // --- SNS・個人情報 ---
  '個人情報を求めるサイトは、本物かどうか公式サイトから確認を',
  'SNSのDMで届く副業・投資の誘いに注意しましょう',
  'SNSのプロフィール情報から個人を特定されることがあります',
  '位置情報付きの写真をSNSに投稿すると、居場所が特定されます',
  'フォロワーが多いアカウントでも、なりすましの可能性があります',
  'オンラインで知り合った人にお金を送ることは避けましょう',
  'SNSの「診断系アプリ」でアカウント連携する前に権限を確認しましょう',
  '子どもの写真をSNSに投稿するときは位置情報と制服に注意',
  'ダイレクトメッセージのリンクは、知人からでも慎重に開きましょう',
  '退会したいサービスのアカウントは放置せず削除しましょう',
  // --- 詐欺の手口 ---
  'ウイルス感染警告が突然表示されても、慌てて電話しないでください',
  'サイトの日本語が不自然な場合、海外の詐欺サイトの可能性があります',
  '「当選しました」という通知は、応募していなければ詐欺です',
  '「未払い料金があります」という連絡は、まず公式に確認を',
  '警察や裁判所を名乗る電話でも、お金を振り込ませることはありません',
  '「被害を回復します」という勧誘は、二次被害の入り口です',
  '還付金があるとATMに誘導するのは、典型的な詐欺です',
  'マイナンバーを電話で聞き出そうとする行為は詐欺です',
  'ワンクリック詐欺で請求画面が出ても、お金を払う必要はありません',
  '架空請求のハガキが届いても、記載の電話番号には絶対に電話しないで',
  // --- 闇バイト・副業 ---
  '「簡単作業で高収入」は闇バイトの典型的な募集文句です',
  '「荷物を受け取るだけ」のバイトは犯罪に加担させられます',
  '「口座を貸すだけ」は犯罪です。自分の口座を他人に使わせないで',
  '「即日払い・日払い」を強調するバイト募集は要注意です',
  'Telegramでの仕事募集は、犯罪組織の可能性が高いです',
  '身分証の写真を送ると、脅迫や犯罪に悪用されます',
  '一度関わると抜け出せなくなるのが闇バイトの怖さです',
  '副業紹介の初期費用を請求されたら、それは副業詐欺です',
  '知らない相手に自分の銀行口座情報を教えてはいけません',
  '「マニュアル通りにやるだけ」という仕事は指示型犯罪の可能性があります',
  // --- デバイス・ソフトウェア ---
  'OSやアプリのアップデートはセキュリティ修正が含まれるため、早めに適用を',
  '公式ストア以外からアプリをインストールするのは危険です',
  '無料VPNアプリの中には通信内容を盗み見るものがあります',
  '使わなくなったアプリは定期的に削除しましょう',
  'スマホの画面ロックは必ず設定しましょう',
  'Bluetoothは使わないときはオフにしておくと安全です',
  '公共のUSB充電ポートはデータ窃取のリスクがあります',
  'PCのWebカメラは使わないときはカバーをしておくと安心です',
  '古いルーターのファームウェアは脆弱性が放置されがちです',
  'ブラウザの拡張機能は信頼できるものだけに絞りましょう',
  // --- Wi-Fi・通信 ---
  '公共Wi-Fiでのネットバンキングやカード決済は避けましょう',
  'カフェなどの無料Wi-Fiでは、VPNの利用を検討しましょう',
  '見覚えのないWi-Fiに自動接続していないか確認しましょう',
  'ホテルのWi-Fiでも、重要な情報のやりとりには注意が必要です',
  '自宅のWi-Fiパスワードは初期設定のまま使わず変更しましょう',
  // --- その他 ---
  '不審に思ったら、消費者ホットライン「188」に相談できます',
  'サイバー犯罪の被害は警察の「#9110」に相談できます',
  '国民生活センターのサイトで最新の詐欺手口を確認できます',
  '家族や友人と詐欺の手口を共有しておくと、被害を防げます',
  '「おかしいな」と思ったら、一人で判断せず誰かに相談しましょう'
];

const ProgressMgr = {
  _tipIdx: 0,
  _tipTimer: null,

  show() {
    document.getElementById('progressOverlay').hidden = false;
    this._tipIdx = Math.floor(Math.random() * SAFETY_TIPS.length);
    this._showTip();
    this._tipTimer = setInterval(() => this._showTip(), 4000);
  },

  hide() {
    document.getElementById('progressOverlay').hidden = true;
    if (this._tipTimer) { clearInterval(this._tipTimer); this._tipTimer = null; }
  },

  update(stage, pct) {
    document.getElementById('progressStage').textContent = stage;
    document.getElementById('progressBar').style.width = pct + '%';
    document.getElementById('progressPct').textContent = Math.round(pct) + '%';
  },

  _showTip() {
    document.getElementById('progressTip').textContent = SAFETY_TIPS[this._tipIdx % SAFETY_TIPS.length];
    this._tipIdx++;
  }
};

// ============================================================
// Results Renderer
// ============================================================
const ResultsRenderer = {
  RISK_LABELS: {
    safe: { text: '問題は見つかりませんでした', icon: '\u2714' },
    low: { text: '軽微な注意点があります', icon: '\u2139' },
    medium: { text: '確認をおすすめする点があります', icon: '\u26A0' },
    high: { text: '注意が必要な要素が見つかりました', icon: '\u26A0' },
    critical: { text: '複数の深刻な懸念があります', icon: '\u2718' }
  },

  render(url, integrated, aiResult, clientAnalysis, incomplete) {
    const { scores, risk } = integrated;

    // Risk banner
    const banner = document.getElementById('riskBanner');
    banner.className = 'risk-banner ' + risk;
    const rl = this.RISK_LABELS[risk] || this.RISK_LABELS.medium;
    document.getElementById('riskIcon').textContent = rl.icon;
    document.getElementById('riskLevel').textContent = rl.text;
    try { document.getElementById('riskUrl').textContent = new URL(url).hostname; } catch { document.getElementById('riskUrl').textContent = url; }

    // Radar chart
    RadarChart.draw('radarChart', scores);

    // Score bars
    const barsEl = document.getElementById('scoreBars');
    let barsHtml = '';
    ScoreIntegrator.DIMENSIONS.forEach(dim => {
      const val = Math.max(0, Math.min(100, Math.round(Number(scores[dim.key]) || 0)));
      let cls;
      if (val >= 80) cls = 'safe';
      else if (val >= 60) cls = 'low';
      else if (val >= 40) cls = 'medium';
      else if (val >= 20) cls = 'high';
      else cls = 'critical';

      barsHtml += `
        <div class="score-bar-item">
          <div class="score-bar-label">
            <span class="score-bar-name">${this._esc(dim.label)}</span>
            <span class="score-bar-value">${val}</span>
          </div>
          <div class="score-bar-track">
            <div class="score-bar-fill ${cls}" style="width:${val}%"></div>
          </div>
        </div>`;
    });
    barsEl.innerHTML = barsHtml;

    // Detected categories
    const catCard = document.getElementById('categoriesCard');
    const catList = document.getElementById('categoriesList');
    if (aiResult && aiResult.detected_categories && aiResult.detected_categories.length > 0) {
      catCard.hidden = false;
      const validConf = ['high','medium','low'];
      catList.innerHTML = aiResult.detected_categories.map(c => `
        <div style="margin-bottom:8px">
          <span class="category-tag ${validConf.includes(c.confidence) ? c.confidence : 'medium'}">${this._esc(c.category)}</span>
          <div class="category-evidence">${this._esc(c.evidence)}</div>
        </div>
      `).join('');
    } else {
      catCard.hidden = true;
    }

    // Findings
    const findCard = document.getElementById('findingsCard');
    const findList = document.getElementById('findingsList');
    const allFindings = [];

    // Client findings
    clientAnalysis.issues.forEach(iss => {
      allFindings.push({
        dimension: 'URL分析',
        severity: iss.severity,
        title: iss.title,
        description: iss.desc || '',
        quote: ''
      });
    });

    // AI findings
    if (aiResult && aiResult.findings) {
      aiResult.findings.forEach(f => allFindings.push(f));
    }

    if (allFindings.length > 0) {
      findCard.hidden = false;
      findList.innerHTML = allFindings.map(f => `
        <div class="finding-item">
          <div class="finding-header">
            <span class="finding-severity ${f.severity}"></span>
            <span class="finding-title">${this._esc(f.title)}</span>
            <span class="finding-dimension">${this._esc(f.dimension)}</span>
          </div>
          ${f.description ? `<div class="finding-desc">${this._esc(f.description)}</div>` : ''}
          ${f.quote ? `<div class="finding-quote">${this._esc(f.quote)}</div>` : ''}
        </div>
      `).join('');
    } else {
      findCard.hidden = true;
    }

    // Summary
    const sumCard = document.getElementById('summaryCard');
    if (aiResult && aiResult.summary) {
      sumCard.hidden = false;
      document.getElementById('summaryText').textContent = aiResult.summary;
    } else {
      sumCard.hidden = true;
    }

    // Incomplete notice
    const noticeEl = document.getElementById('incompleteNotice');
    if (incomplete) {
      noticeEl.hidden = false;
      document.getElementById('incompleteText').textContent = incomplete;
    } else {
      noticeEl.hidden = true;
    }

    showScreen('screenResults');
  },

  _escDiv: null,
  _esc(s) {
    if (!s) return '';
    if (!this._escDiv) this._escDiv = document.createElement('div');
    this._escDiv.textContent = s;
    return this._escDiv.innerHTML;
  }
};

// ============================================================
// Main Analysis Flow
// ============================================================
let isChecking = false;
let checkAbortController = null;

// Combine cancel signal + timeout into one signal
function _combinedSignal(cancelSignal, timeoutMs) {
  if (!cancelSignal) return AbortSignal.timeout(timeoutMs);
  if (typeof AbortSignal.any === 'function') {
    return AbortSignal.any([cancelSignal, AbortSignal.timeout(timeoutMs)]);
  }
  // Fallback for older browsers
  const c = new AbortController();
  const tid = setTimeout(() => { if (!c.signal.aborted) c.abort(); }, timeoutMs);
  cancelSignal.addEventListener('abort', () => { clearTimeout(tid); if (!c.signal.aborted) c.abort(); }, { once: true });
  return c.signal;
}

async function runCheck(urlStr) {
  if (isChecking) return;
  checkAbortController?.abort();
  checkAbortController = new AbortController();
  const cancelSignal = checkAbortController.signal;
  isChecking = true;
  const config = loadConfig();
  let incomplete = null;
  let aiResult = null;
  let htmlContent = null;
  let headers = null;

  ProgressMgr.show();

  try {
    // Stage 1: URL analysis + Worker fetch
    ProgressMgr.update('URL構造を分析中...', 5);
    const clientAnalysis = UrlAnalyzer.analyze(urlStr);
    ProgressMgr.update('サイトを取得中...', 15);

    let fetchData = null;
    try {
      const workerUrl = (config.workerUrl || DEFAULT_WORKER_URL).replace(/\/+$/, '');
      const fetchResp = await fetch(`${workerUrl}/fetch?url=${encodeURIComponent(urlStr)}`, {
        headers: config.apiKey ? { 'X-API-Key': config.apiKey } : {},
        signal: _combinedSignal(cancelSignal, 15000)
      });
      if (fetchResp.ok) {
        fetchData = await fetchResp.json();
        if (fetchData.error) {
          incomplete = `サイトの取得に失敗しました（${fetchData.error}）。URL分析のみの部分的な結果です。`;
          fetchData = null;
        }
      } else {
        let errDetail = `HTTP ${fetchResp.status}`;
        try { const errJson = await fetchResp.json(); errDetail = errJson.error || errDetail; } catch {}
        incomplete = `サイトの取得に失敗しました（${errDetail}）。URL分析のみの部分的な結果です。`;
      }
    } catch (e) {
      incomplete = 'サイトの取得に失敗しました（' + (e.name === 'TimeoutError' ? 'タイムアウト' : e.message) + '）。URL分析のみの部分的な結果です。';
    }

    // Stage 2: Extract content from fetched HTML
    ProgressMgr.update('コンテンツを解析中...', 35);
    if (fetchData) {
      headers = fetchData.headers || null;
      if (fetchData.html) {
        htmlContent = HtmlExtractor.extract(fetchData.html, urlStr);
      }

      // Check redirects
      if (fetchData.redirected && fetchData.finalUrl && fetchData.finalUrl !== urlStr) {
        // Detect login/session redirect
        const finalLower = fetchData.finalUrl.toLowerCase();
        if (/\/(login|signin|session|auth|sso|cas|oauth|saml)\b/i.test(finalLower)) {
          incomplete = 'ログインが必要なページのため、内容を取得できませんでした。「テキスト貼り付け」モードでページ内容をコピペして分析できます。';
        }
        clientAnalysis.issues.push({
          title: 'リダイレクト検出',
          severity: 'low',
          desc: `最終URL: ${fetchData.finalUrl}`
        });
      }

      // Tech safety adjustments from extracted content
      if (htmlContent) {
        if (htmlContent.obfuscationSuspect) {
          clientAnalysis.tech_safety = Math.max(0, clientAnalysis.tech_safety - 20);
          clientAnalysis.issues.push({ title: 'スクリプト難読化の疑い', severity: 'medium', desc: 'eval/atob/fromCharCode等の難読化パターンが検出されました。' });
        }
        if (htmlContent.hiddenFormFields > 0) {
          clientAnalysis.tech_safety = Math.max(0, clientAnalysis.tech_safety - 15);
          clientAnalysis.issues.push({ title: '隠しフォーム要素', severity: 'medium', desc: `${htmlContent.hiddenFormFields}個の非表示フォーム要素があります。` });
        }
      }
    }

    // Stage 3: Gemini AI analysis
    if (config.apiKey) {
      ProgressMgr.update('AI分析中...', 55);
      try {
        aiResult = await GeminiClient.analyze(config, urlStr, clientAnalysis, htmlContent, headers, cancelSignal);
        ProgressMgr.update('AI分析中...', 85);
      } catch (e) {
        if (cancelSignal.aborted) throw e; // Re-throw if canceled
        if (!incomplete) {
          incomplete = 'AI分析に失敗しました（' + e.message.slice(0, 100) + '）。部分的な結果です。';
        } else {
          incomplete += ' AI分析も失敗しました。';
        }
      }
    } else {
      incomplete = (incomplete || '') + ' APIキーが未設定のためAI分析をスキップしました。';
    }

    // Check if canceled before rendering
    if (cancelSignal.aborted) return;

    // Stage 4: Integrate & render
    ProgressMgr.update('結果を統合中...', 95);
    const integrated = ScoreIntegrator.integrate(clientAnalysis, aiResult);

    ProgressMgr.update('完了', 100);
    await sleep(200);

    if (cancelSignal.aborted) return;
    ProgressMgr.hide();
    ResultsRenderer.render(urlStr, integrated, aiResult, clientAnalysis, incomplete ? incomplete.trim() : null);

  } catch (e) {
    if (cancelSignal.aborted) return; // Silently exit if canceled
    console.error('Analysis error:', e);
    ProgressMgr.hide();
    alert('分析中にエラーが発生しました: ' + (e.message || '不明なエラー'));
    showScreen('screenCheck');
  } finally {
    isChecking = false;
  }
}

// Text paste analysis mode
async function runTextCheck(urlStr, pastedText) {
  if (isChecking) return;
  const config = loadConfig();
  if (!config.apiKey) {
    alert('APIキーが設定されていません。設定画面からAPIキーを入力してください。');
    return;
  }
  checkAbortController?.abort();
  checkAbortController = new AbortController();
  const cancelSignal = checkAbortController.signal;
  isChecking = true;
  let incomplete = null;
  let aiResult = null;

  // Build minimal clientAnalysis
  let clientAnalysis = { domain_trust: 50, tech_safety: 50, issues: [] };
  if (urlStr) {
    clientAnalysis = UrlAnalyzer.analyze(urlStr);
  } else {
    incomplete = 'URLが未入力のため、URL構造分析はスキップされました。';
  }

  // Build minimal htmlContent from pasted text
  const htmlContent = {
    title: '',
    headings: [],
    bodyText: pastedText.slice(0, 10000),
    externalLinkCount: 0,
    externalDomains: [],
    forms: [],
    inlineScriptChars: 0,
    obfuscationSuspect: false,
    hiddenFormFields: 0,
    hasCompanyInfo: /会社概要|企業情報|運営会社|事務所[概名]|代表弁護士|代表取締役|代表者/i.test(pastedText),
    hasContact: /お問い合わせ|連絡先|電話番号|所在地|住所/i.test(pastedText),
    hasPrivacyPolicy: /プライバシー|個人情報保護/i.test(pastedText),
    hasCommerceLaw: /特定商取引|特商法/i.test(pastedText),
    companyInfoInContent: true,
    commerceLawInContent: /特定商取引|特商法/i.test(pastedText),
  };

  ProgressMgr.show();

  try {
    ProgressMgr.update('テキストを分析中...', 20);

    // Gemini analysis
    ProgressMgr.update('AI分析中...', 40);
    try {
      aiResult = await GeminiClient.analyze(config, urlStr || '(URLなし・テキスト直接入力)', clientAnalysis, htmlContent, null, cancelSignal);
      ProgressMgr.update('スコアを統合中...', 85);
    } catch (e) {
      if (cancelSignal.aborted) throw e;
      const msg = e.message || '';
      incomplete = (incomplete ? incomplete + ' ' : '') + `AI分析に失敗しました（${msg}）。部分的な結果です。`;
    }

    if (cancelSignal.aborted) return;
    const integrated = ScoreIntegrator.integrate(clientAnalysis, aiResult);
    ProgressMgr.update('完了', 100);
    await sleep(200);

    if (cancelSignal.aborted) return;
    ProgressMgr.hide();
    ResultsRenderer.render(urlStr || '(テキスト入力)', integrated, aiResult, clientAnalysis, incomplete ? incomplete.trim() : null);

  } catch (e) {
    if (cancelSignal.aborted) return;
    console.error('Analysis error:', e);
    ProgressMgr.hide();
    alert('分析中にエラーが発生しました: ' + (e.message || '不明なエラー'));
    showScreen('screenCheck');
  } finally {
    isChecking = false;
  }
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ============================================================
// Init & Event Binding
// ============================================================
function init() {
  const config = loadConfig();

  // Determine initial screen
  if (!hasConsent()) {
    showScreen('screenConsent');
  } else if (config.apiKey) {
    showScreen('screenCheck');
  } else {
    showScreen('screenSetup');
  }

  // Remove legacy workerUrl if it matches default (privacy: don't persist default URL)
  if (config.workerUrl === DEFAULT_WORKER_URL) {
    delete config.workerUrl;
    saveConfig(config);
  }

  function validateWorkerUrl(url) {
    try {
      const u = new URL(url);
      if (u.protocol !== 'https:') { alert('Worker URLはhttps://で始まる必要があります。'); return false; }
      return true;
    } catch { alert('有効なURLを入力してください。'); return false; }
  }

  // Consent
  document.getElementById('consentCheckbox').addEventListener('change', (e) => {
    document.getElementById('btnConsent').disabled = !e.target.checked;
  });

  document.getElementById('btnConsent').addEventListener('click', () => {
    setConsent();
    const cfg = loadConfig();
    if (cfg.apiKey) {
      showScreen('screenCheck');
    } else {
      showScreen('screenSetup');
    }
  });

  // Setup save (API key only, Worker URL auto-set)
  document.getElementById('btnSetupSave').addEventListener('click', () => {
    const apiKey = document.getElementById('setupApiKey').value.trim();
    if (!apiKey) {
      alert('APIキーを入力してください。');
      return;
    }
    if (!/^AIza[A-Za-z0-9_-]{35}$/.test(apiKey)) {
      alert('APIキーの形式が正しくありません。AIzaで始まる39文字のキーを入力してください。');
      return;
    }
    const cfg = loadConfig();
    cfg.apiKey = apiKey;
    saveConfig(cfg);
    showScreen('screenCheck');
  });

  // Home
  function resetAndGoHome() {
    document.getElementById('inputUrl').value = '';
    document.getElementById('inputText').value = '';
    document.getElementById('inputTextUrl').value = '';
    document.getElementById('urlError').hidden = true;
    // Reset to URL tab
    document.querySelectorAll('.mode-tab').forEach(t => t.classList.toggle('active', t.dataset.mode === 'url'));
    document.getElementById('modeUrl').hidden = false;
    document.getElementById('modeText').hidden = true;
    const cfg = loadConfig();
    if (!hasConsent()) showScreen('screenConsent');
    else if (cfg.apiKey) showScreen('screenCheck');
    else showScreen('screenSetup');
  }

  document.getElementById('btnHome').addEventListener('click', resetAndGoHome);

  // Settings
  document.getElementById('btnSettings').addEventListener('click', () => {
    const cfg = loadConfig();
    document.getElementById('settingsApiKey').value = cfg.apiKey || '';
    document.getElementById('settingsWorkerUrl').value = cfg.workerUrl || '';
    // Set sensitivity radio (validate value to prevent selector injection)
    const sens = loadSensitivity();
    if (['high', 'standard', 'low'].includes(sens)) {
      const radio = document.querySelector(`input[name="sensitivity"][value="${sens}"]`);
      if (radio) radio.checked = true;
    }
    showScreen('screenSettings');
  });

  document.getElementById('btnSettingsSave').addEventListener('click', () => {
    const apiKey = document.getElementById('settingsApiKey').value.trim();
    const workerUrlInput = document.getElementById('settingsWorkerUrl').value.trim();
    if (!apiKey) {
      alert('APIキーを入力してください。');
      return;
    }
    if (!/^AIza[A-Za-z0-9_-]{35}$/.test(apiKey)) {
      alert('APIキーの形式が正しくありません。AIzaで始まる39文字のキーを入力してください。');
      return;
    }
    const cfgToSave = { apiKey };
    if (workerUrlInput) {
      if (!validateWorkerUrl(workerUrlInput)) return;
      cfgToSave.workerUrl = workerUrlInput;
    }
    saveConfig(cfgToSave);
    // Save sensitivity
    const sensRadio = document.querySelector('input[name="sensitivity"]:checked');
    if (sensRadio) saveSensitivity(sensRadio.value);
    showScreen('screenCheck');
  });

  document.getElementById('btnSettingsBack').addEventListener('click', () => {
    const cfg = loadConfig();
    if (!hasConsent()) showScreen('screenConsent');
    else if (cfg.apiKey) showScreen('screenCheck');
    else showScreen('screenSetup');
  });

  // Show terms from settings
  document.getElementById('btnShowTerms').addEventListener('click', () => {
    showScreen('screenConsent');
    // Ensure checkbox and button reflect already-consented state
    if (hasConsent()) {
      document.getElementById('consentCheckbox').checked = true;
      document.getElementById('btnConsent').disabled = false;
    }
  });

  // Check
  document.getElementById('btnCheck').addEventListener('click', () => {
    const urlInput = document.getElementById('inputUrl');
    const errEl = document.getElementById('urlError');
    let urlStr = urlInput.value.trim();

    // Auto-prefix https
    if (urlStr && !/^https?:\/\//i.test(urlStr)) {
      urlStr = 'https://' + urlStr;
      urlInput.value = urlStr;
    }

    // Validate
    try {
      const u = new URL(urlStr);
      if (!['http:', 'https:'].includes(u.protocol)) throw new Error('invalid');
    } catch {
      errEl.textContent = '有効なURLを入力してください。';
      errEl.hidden = false;
      return;
    }

    errEl.hidden = true;
    runCheck(urlStr);
  });

  // Enter key on URL input
  document.getElementById('inputUrl').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      document.getElementById('btnCheck').click();
    }
  });

  // Mode tabs
  document.querySelectorAll('.mode-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.mode-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      const mode = tab.dataset.mode;
      document.getElementById('modeUrl').hidden = mode !== 'url';
      document.getElementById('modeText').hidden = mode !== 'text';
    });
  });

  // Text check
  document.getElementById('btnCheckText').addEventListener('click', () => {
    const errEl = document.getElementById('urlError');
    const textVal = document.getElementById('inputText').value.trim();
    let urlVal = document.getElementById('inputTextUrl').value.trim();

    if (!textVal) {
      errEl.textContent = 'サイトの内容を貼り付けてください。';
      errEl.hidden = false;
      return;
    }
    if (textVal.length < 50) {
      errEl.textContent = 'テキストが短すぎます。ページ全体をコピーしてください。';
      errEl.hidden = false;
      return;
    }

    // Auto-prefix https
    if (urlVal && !/^https?:\/\//i.test(urlVal)) {
      urlVal = 'https://' + urlVal;
      document.getElementById('inputTextUrl').value = urlVal;
    }
    // Validate URL if provided
    if (urlVal) {
      try {
        const u = new URL(urlVal);
        if (!['http:', 'https:'].includes(u.protocol)) throw new Error('invalid');
      } catch {
        urlVal = '';
      }
    }

    errEl.hidden = true;
    runTextCheck(urlVal, textVal);
  });

  // New check
  document.getElementById('btnNewCheck').addEventListener('click', resetAndGoHome);

  // Cancel check — abort in-flight requests
  document.getElementById('btnCancelCheck').addEventListener('click', () => {
    checkAbortController?.abort();
    isChecking = false;
    ProgressMgr.hide();
    showScreen('screenCheck');
  });
}

document.addEventListener('DOMContentLoaded', init);

})();
