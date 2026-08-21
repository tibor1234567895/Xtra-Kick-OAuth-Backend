# Xtra-Kick-OAuth-Backend

Minimal OAuth token proxy for Kick, used by the Xtra-Kick Android app.

Kick's OAuth clients are treated as confidential, so the authorization code exchange, refresh, revoke and introspect requests need a client secret. This service keeps that secret server-side and exposes four small endpoints the app calls instead. It stores nothing: no users, no tokens, no sessions.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/healthz` | Health check |
| POST | `/v1/kick/oauth/exchange` | Authorization code + PKCE verifier to tokens |
| POST | `/v1/kick/oauth/refresh` | Refresh token to new tokens |
| POST | `/v1/kick/oauth/revoke` | Revoke an access or refresh token |
| POST | `/v1/kick/oauth/introspect` | Check token status against Kick |

All POST endpoints take JSON bodies:

```json
// exchange
{ "code": "...", "codeVerifier": "...", "redirectUri": "https://localhost/callback" }

// refresh
{ "refreshToken": "..." }

// revoke
{ "token": "...", "tokenTypeHint": "access_token" }

// introspect
{ "token": "..." }
```

## Request signing (optional)

If `APP_HMAC_SECRET` is set, every `/v1/kick/oauth` request must include three headers:

- `X-Auth-Timestamp`: unix time in seconds
- `X-Auth-Nonce`: a unique string per request
- `X-Auth-Signature`: hex HMAC-SHA256 of `timestamp\nnonce\nMETHOD\npathname\nsha256hex(rawBody)` keyed with `APP_HMAC_SECRET`

Requests outside the timestamp window (`HMAC_TIMESTAMP_TOLERANCE_SECONDS`, default 300) or reusing a nonce are rejected. If `APP_HMAC_SECRET` is empty, signature checks are disabled.

## Setup

1. Copy `.env.example` to `.env` and fill in values.
2. Install dependencies: `npm install`
3. Start: `npm start` (or use `KickOauthBackend.bat` / `KickOauthBackend.sh`)
4. Run tests: `npm test`

## Configuration

- `KICK_CLIENT_ID`, `KICK_CLIENT_SECRET`: your Kick application credentials. Required.
- `ALLOWED_REDIRECT_URIS`: comma-separated exact HTTPS redirect URIs. Required.
- `APP_HMAC_SECRET`: enables HMAC request signing when set. Optional.
- `HMAC_TIMESTAMP_TOLERANCE_SECONDS`: clock tolerance for signed requests. Default `300`.
- `UPSTREAM_TIMEOUT_MS`: Kick API timeout. Default `10000`.
- `TRUST_PROXY`: express trust proxy setting. Default `loopback`. `true` is rejected on purpose because it would let a spoofed `X-Forwarded-For` header defeat the rate limiters.
- `PORT`, `LOG_LEVEL`: defaults `8080` and `info`.

## Security notes

- Tokens, codes and secrets are never logged (pino redaction) and never persisted.
- Per-endpoint rate limits, Helmet headers, 32kb body cap and strict input validation.
- Redirect URIs must be HTTPS and exactly match the allowlist.
- The Android app that uses this backend signs its requests with the same `APP_HMAC_SECRET`. Note that anything embedded in an APK can be extracted by a determined attacker; signing raises the effort bar, it is not absolute protection.
