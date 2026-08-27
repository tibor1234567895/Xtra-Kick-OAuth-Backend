# Kick OAuth Backend Proxy

Minimal OAuth proxy for Kick token operations.

## Endpoints
- `GET /healthz`
- `POST /v1/kick/oauth/exchange`
- `POST /v1/kick/oauth/refresh`
- `POST /v1/kick/oauth/revoke`
- `POST /v1/kick/oauth/introspect`
- `POST /v1/metrics/ping` (enabled when `METRICS_SALT` is set)
- `GET /v1/metrics/stats` (requires `METRICS_ADMIN_TOKEN`)
- `GET /v1/metrics/dashboard` (requires `METRICS_DASHBOARD_FILE` to point at a static HTML page)

## Setup
1. Copy `.env.example` to `.env` and fill values.
2. Install dependencies: `npm install`
3. Set `ALLOWED_REDIRECT_URIS` to the exact HTTPS callback URIs configured in Kick.
4. Start server: `npm start`

## Configuration
- `KICK_CLIENT_ID` and `KICK_CLIENT_SECRET` are required.
- `ALLOWED_REDIRECT_URIS` is required and must be a comma-separated list of exact HTTPS redirect URIs.
- `APP_HMAC_SECRET` must be set for internet-facing deployments. The only
  unauthenticated mode is the explicit development setting
  `ALLOW_UNAUTHENTICATED_OAUTH=true`.
- `UPSTREAM_TIMEOUT_MS` defaults to `10000`.
- `TRUST_PROXY` defaults to `loopback`.
- `LOG_LEVEL` defaults to `info`.
- `METRICS_MAX_DEVICES_PER_MONTH` defaults to `100000` and bounds anonymous
  metrics storage for the active month.

## Notes
- Keep `KICK_CLIENT_SECRET` only on backend.
- Configure Kick dev dashboard redirect URI to `https://localhost/callback`.
- Keep real client IDs, client secrets, access tokens, refresh tokens, and authorization codes out of docs and logs.
- Do not treat an HMAC secret shipped in the Android APK as confidential. The
  long-term fix is to replace shared APK signing with a public-client auth
  design; keep the server-side HMAC as defense-in-depth during that migration.

## Ubuntu service

After pulling and installing production dependencies, restart the existing systemd service:

```bash
npm ci --omit=dev
npm test
sudo systemctl restart KickOauthBackend.service
sudo systemctl status KickOauthBackend.service
```

Follow its logs with:

```bash
journalctl -u KickOauthBackend.service -f
```
