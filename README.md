# Kick OAuth Backend Proxy

Minimal OAuth proxy for Kick token operations.

## Endpoints
- `GET /healthz`
- `POST /v1/kick/oauth/exchange`
- `POST /v1/kick/oauth/refresh`
- `POST /v1/kick/oauth/revoke`
- `POST /v1/kick/oauth/introspect`
- `POST /v1/metrics/ping` (enabled when `METRICS_SALT` is set)
- `POST /v1/metrics/crash` (requires app HMAC signing and metrics enabled)
- `POST /v1/metrics/crash/dismiss` (requires `METRICS_ADMIN_TOKEN`)
- `GET /v1/metrics/stats` (requires `METRICS_ADMIN_TOKEN`)
- `GET /v1/metrics/dashboard` (static operations cockpit; requires `METRICS_DASHBOARD_FILE`)
- `GET /v1/metrics/dashboard/v2` (backward-compatible alias for the operations dashboard)

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
- `METRICS_RETENTION_MONTHS` defaults to `3` (stats can chart up to 90 days).
- `METRICS_MAX_EVERSEEN` defaults to `250000` and caps the install-dedup set.
- The stats payload includes DAU/WAU/MAU, deduplicated installs, new-vs-returning
  daily series, version/OS/country breakdowns, and 7-day backend health counters
  (per-endpoint request outcomes, OAuth grant outcomes, ping rejections, and
  account-capture results).
- The dashboard HTML is intentionally public as a login shell; its `/v1/metrics/stats`
  data request requires `METRICS_ADMIN_TOKEN`. It supports 30/60/90-day ranges,
  auto-refresh, and reads `?days=` from `/v1/metrics/stats`.

## Notes
- Playback-start counts track content changes per engine, excluding buffering and
  pause/resume of the same content. Content identifiers stay in app memory and are
  never uploaded. The app retains these counters until the ping response includes
  `X-Playback-Starts-Accepted: 1`, so an older backend cannot silently discard them.
  Deploy the backend before releasing the app to start collecting them immediately.
- Watch-time and player-preference distributions describe each reporting device's
  latest values in the current calendar month, not individual sessions or a seven-day
  history. Preserve the existing data; corrected clients replace their own snapshots.
- Crash reporting is enabled by default under **Settings > System & Advanced > Send crash reports**,
  and also requires **Anonymous usage statistics**. Existing disabled settings are preserved;
  no preference migration forces reporting back on. Release builds save up to five pending
  Java/Kotlin uncaught exceptions in app-private storage excluded from backups and retry
  on a later foreground launch, independently of the daily ping. Disabling either switch
  clears pending reports. Native crashes and ANRs are not captured by this handler.
- Reports contain only a random per-crash retry ID, app version/build, Android SDK,
  process CPU architecture and configured live-player preference (IVS/Media3/unknown),
  crash timestamp, and bounded exception types and stack frames (cause chain only).
  They exclude exception messages, thread names, device/account identifiers, and diagnostic logs.
- The backend stores up to 200 crash groups and 20,000 retry IDs for 90 days in
  `<METRICS_DATA_FILE>.crashes.json`. It rejects new reports at the retry-ID capacity
  rather than double-counting retries. Expiration runs on reads, writes, startup,
  and once per minute while running. A successful response requires persistence.
  Crash details are included only in the admin-protected stats response and displayed
  under **Reported Uncaught Crashes**. No new environment variables are needed.
- Crash-detail counts are separate from daily-ping crash counts; older counts cannot
  be expanded into reports. Offline reports expire after 90 days when the app next processes
  its queue. The configured live-player preference does not identify the engine active at
  the moment of a crash, particularly for VODs. Old clients without these fields report unknown.
- Crash requests bypass application access logging, including invalid or failed uploads.
  Unexpected request errors log only a fixed error code/message. Aggregate request outcomes
  and in-memory rate limits remain enabled. Reverse-proxy and infrastructure logs are a
  separate boundary; do not claim complete anonymity based only on the report payload.
- Keep `KICK_CLIENT_SECRET` only on backend.
- Configure Kick dev dashboard redirect URI to `https://localhost/callback`.
- Keep real client IDs, client secrets, access tokens, refresh tokens, and authorization codes out of docs and logs.
- Do not treat an HMAC secret shipped in the Android APK as confidential. The
  long-term fix is to replace shared APK signing with a public-client auth
  design; keep the server-side HMAC as defense-in-depth during that migration.
- Country approximation for anonymous usage pings uses the `geoip-country`
  package, which bundles data derived from GeoLite2 created by MaxMind
  (https://www.maxmind.com). Only the resolved two-letter country code is
  stored; request IPs are never persisted. Set `METRICS_GEOIP=off` to disable.

## Ubuntu service

### Crash-report proxy logging

Read-only inspection on 2026-11-11 confirmed Caddy access logging is enabled for the backend
hostname, with no crash-route exclusion. Before activating crash uploads in production, add
the following inside the existing `kickauth.tiborlaszlo.ovh` site block:

```caddyfile
@crashReports path_regexp crashReports (?i)^/v1/metrics/crash/?$
skip_log @crashReports
```

The deployed Caddy uses the older directive name `skip_log`; Caddy 2.8+ calls it `log_skip`.
This covers case variants and the optional trailing slash accepted by Express. It leaves
other endpoint access logs enabled. This directive covers access logs; runtime/transport
error logs and any upstream provider logs need a separate privacy review. Keep debug logging
disabled in production. The repository change does not modify or reload Caddy.

After reviewing the full Caddyfile, validate it before an explicitly authorized reload:

```bash
sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
sudo systemctl reload caddy
```

Verify a test crash request is absent from both access and service logs, including the
backend-unavailable case, before describing production reporting as anonymous.

### Backend update

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
