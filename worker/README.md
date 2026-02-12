# Site Safety Checker Worker デプロイ手順

## 前提
- Cloudflare アカウント
- Wrangler CLI (`npm install -g wrangler`)

## セットアップ

1. **Wrangler ログイン**
```bash
wrangler login
```

2. **デプロイ**
```bash
cd worker/
wrangler deploy
```

3. **動作確認**
```bash
curl https://site-safety-checker.<your-subdomain>.workers.dev/health
```

## エンドポイント

| パス | メソッド | 説明 |
|------|----------|------|
| `/fetch?url=<encoded>` | GET | 対象サイトHTML取得（要X-API-Key） |
| `/models/*` | POST | Gemini APIプロキシ（要X-API-Key） |
| `/health` | GET | ヘルスチェック |

## セキュリティ
- CORS: 許可オリジンのみ（GitHub Pages + localhost）
- /fetch, /models: X-API-Keyヘッダー必須
- HTML取得: 最大200KB
- タイムアウト: 10秒
- プライベートIPアドレスはブロック（SSRF防止）
