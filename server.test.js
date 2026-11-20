import assert from "node:assert/strict";
import http from "node:http";
import { createHash, createSign, generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { runInNewContext, Script } from "node:vm";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { setImmediate as settle } from "node:timers/promises";
import pino from "pino";
import { WebSocketServer } from "ws";
import { backfillStoredSubscriptions, computeHmacSignature, createApp, createCountryLookup, loadConfig, redactPaths, startServer } from "./server.js";
import { createMetricsStore } from "./metrics.js";
import { CRASH_RETENTION_MS, MAX_CRASH_GROUPS, MAX_CRASH_EVENTS, crashReportSchema, createCrashReportStore } from "./crash-reports.js";
import {
  clearChannelResolutionCache,
  clearKickPublicKeyCache,
  channelResolutionCache,
  createFcmStore,
  createLiveStreamPoller,
  createPusherRelay,
  getKickPublicKey,
  handleWebhookLiveEvent,
  negativeResolutionCache,
  scheduleKickSubscriptionSync,
  sendLivePushNotification,
  syncKickEventSubscriptions,
  verifyKickWebhookSignature,
} from "./fcm.js";

const baseEnv = {
  KICK_CLIENT_ID: "client-id",
  KICK_CLIENT_SECRET: "client-secret",
  ALLOWED_REDIRECT_URIS: "https://localhost/callback,https://127.0.0.1/callback",
  UPSTREAM_TIMEOUT_MS: "50",
  TRUST_PROXY: "false",
  LOG_LEVEL: "silent",
  ALLOW_UNAUTHENTICATED_OAUTH: "true",
  FCM_PUSHER_RELAY_ENABLED: "false",
  FCM_SERVICE_ACCOUNT_KEY_PATH: "none",
};

test("webhook quotas apply before JSON parsing and leave ordinary traffic independent", async () => {
  for (const [body, rejection] of [["{", 400], [JSON.stringify({ data: "x".repeat(33_000) }), 413], ["{}", 400]]) {
    const app = appWithFetch(() => { throw new Error("No upstream request expected"); });
    await withServer(app, async (baseUrl) => {
      const paths = ["/api/events/webhook", "/v1/events/webhook/", "/V1/EVENTS/WEBHOOK?audit=1"];
      for (let i = 0; i <= 600; i++) {
        const response = await fetch(`${baseUrl}${paths[i % paths.length]}`, {
          method: "POST", headers: { "Content-Type": "application/json" }, body,
        });
        await response.text();
        assert.equal(response.status, i < 600 ? rejection : 429, `request ${i + 1}`);
      }
      assert.equal((await fetch(`${baseUrl}/healthz`)).status, 200);
    });
  }
});

function config(overrides = {}) {
  return loadConfig({ ...baseEnv, ...overrides });
}

function appWithFetch(fetchImpl, overrides = {}) {
  return createApp(config(overrides), { fetch: fetchImpl });
}

function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function validExchangeBody(overrides = {}) {
  return {
    code: "authorization-code",
    codeVerifier: "a".repeat(43),
    redirectUri: "https://localhost/callback",
    ...overrides,
  };
}

async function withServer(app, block) {
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  try {
    return await block(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

async function httpRequest(baseUrl, method, path, body, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers: Object.keys(headers).length > 0 ? headers : undefined,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  let parsed = {};
  if (text) { try { parsed = JSON.parse(text); } catch { parsed = { raw: text }; } }
  return {
    status: response.status,
    headers: Object.fromEntries(response.headers.entries()),
    body: parsed,
  };
}

function signedHeaders({ secret, method, path, bodyObject, timestamp, nonce }) {
  const body = JSON.stringify(bodyObject);
  const resolvedTimestamp = timestamp ?? String(Math.floor(Date.now() / 1000));
  const resolvedNonce = nonce ?? `nonce-${Math.random()}`;
  const signature = computeHmacSignature(secret, {
    timestamp: resolvedTimestamp,
    nonce: resolvedNonce,
    method,
    pathname: new URL(path, "http://internal").pathname,
    bodySha256: createHash("sha256").update(body).digest("hex"),
  });
  return {
    "Content-Type": "application/json",
    "X-Auth-Timestamp": resolvedTimestamp,
    "X-Auth-Nonce": resolvedNonce,
    "X-Auth-Signature": signature,
  };
}

test("malformed JSON returns a controlled 400 without reaching upstream", async () => {
  const app = appWithFetch(() => { throw new Error("Upstream must not be called"); });
  await withServer(app, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/v1/kick/oauth/exchange`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: "{",
    });
    assert.equal(response.status, 400);
    assert.match(response.headers.get("content-type"), /application\/json/);
    assert.deepEqual(await response.json(), { code: "invalid_json", message: "Invalid JSON" });
  });
});

test("oversized JSON returns a controlled 413 without reaching upstream", async () => {
  const app = appWithFetch(() => { throw new Error("Upstream must not be called"); });
  await withServer(app, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/v1/kick/oauth/exchange`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ value: "x".repeat(40000) }),
    });
    assert.equal(response.status, 413);
    assert.deepEqual(await response.json(), { code: "payload_too_large", message: "Request body too large" });
  });
});

async function signedRequest(baseUrl, method, path, bodyObject, overrides = {}) {
  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers: signedHeaders({ secret: overrides.secret ?? "hmac-secret", method, path, bodyObject, ...overrides }),
    body: JSON.stringify(bodyObject),
  });
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) : {} };
}

test("invalid exchange payload returns 400", async () => {
  const app = appWithFetch(async () => jsonResponse(200, {}));

  const response = await withServer(app, (baseUrl) =>
    httpRequest(baseUrl, "POST", "/v1/kick/oauth/exchange", {
      code: "",
      codeVerifier: "short",
      redirectUri: "https://localhost/callback",
    })
  );

  assert.equal(response.status, 400);
  assert.equal(response.body.code, "invalid_request");
});

test("loadConfig rejects missing HMAC unless explicitly allowed", () => {
  assert.throws(
    () => loadConfig({ ...baseEnv, ALLOW_UNAUTHENTICATED_OAUTH: "false" }),
    /APP_HMAC_SECRET is required/
  );
});

test("allowed redirect URI reaches mocked upstream", async () => {
  let upstreamBody;
  const app = appWithFetch(async (_url, options) => {
    upstreamBody = options.body;
    return jsonResponse(200, {
      access_token: "access-token",
      refresh_token: "refresh-token",
      expires_in: 3600,
      token_type: "Bearer",
      scope: "user:read chat:write",
    });
  });

  const response = await withServer(app, (baseUrl) =>
    httpRequest(baseUrl, "POST", "/v1/kick/oauth/exchange", validExchangeBody())
  );

  assert.equal(response.status, 200);
  assert.equal(response.body.access_token, "access-token");
  assert.equal(upstreamBody.get("redirect_uri"), "https://localhost/callback");
  assert.equal(upstreamBody.get("client_secret"), "client-secret");
});

test("unknown HTTPS redirect URI returns invalid_redirect_uri", async () => {
  const app = appWithFetch(async () => jsonResponse(200, {}));

  const response = await withServer(app, (baseUrl) =>
    httpRequest(baseUrl, "POST", "/v1/kick/oauth/exchange", validExchangeBody({ redirectUri: "https://example.com/callback" }))
  );

  assert.equal(response.status, 400);
  assert.deepEqual(response.body, {
    code: "invalid_redirect_uri",
    message: "Redirect URI is not allowed",
  });
});

test("non-HTTPS redirect URI returns invalid_redirect_uri", async () => {
  const app = appWithFetch(async () => jsonResponse(200, {}));

  const response = await withServer(app, (baseUrl) =>
    httpRequest(baseUrl, "POST", "/v1/kick/oauth/exchange", validExchangeBody({ redirectUri: "http://localhost/callback" }))
  );

  assert.equal(response.status, 400);
  assert.equal(response.body.code, "invalid_redirect_uri");
});

test("slow upstream request aborts and maps to 502", async () => {
  const app = appWithFetch(
    async (_url, options) =>
      new Promise((_resolve, reject) => {
        options.signal.addEventListener("abort", () => {
          const error = new Error("aborted");
          error.name = "AbortError";
          reject(error);
        });
      }),
    { UPSTREAM_TIMEOUT_MS: "10" }
  );

  const response = await withServer(app, (baseUrl) =>
    httpRequest(baseUrl, "POST", "/v1/kick/oauth/refresh", { refreshToken: "refresh-token" })
  );

  assert.equal(response.status, 502);
  assert.deepEqual(response.body, {
    code: "upstream_unavailable",
    message: "Kick OAuth request timed out",
  });
});

test("Kick OAuth error maps to safe response without token leakage", async () => {
  const app = appWithFetch(async () =>
    jsonResponse(400, {
      error: "invalid_grant",
      error_description: "secret access-token refresh-token authorization-code",
    })
  );

  const response = await withServer(app, (baseUrl) =>
    httpRequest(baseUrl, "POST", "/v1/kick/oauth/refresh", { refreshToken: "refresh-token" })
  );

  assert.equal(response.status, 400);
  assert.deepEqual(response.body, {
    code: "invalid_grant",
    message: "Kick OAuth grant is invalid",
  });
  assert.doesNotMatch(JSON.stringify(response.body), /secret|refresh-token|authorization-code/);
});

test("introspection 401 maps to inactive token response", async () => {
  const app = appWithFetch(async () => jsonResponse(401, { message: "token secret-token inactive" }));

  const response = await withServer(app, (baseUrl) =>
    httpRequest(baseUrl, "POST", "/v1/kick/oauth/introspect", { token: "secret-token" })
  );

  assert.equal(response.status, 200);
  assert.deepEqual(response.body, {
    active: false,
    exp: null,
    client_id: null,
    user_id: null,
    username: null,
    scope: null,
  });
});

test("route-specific rate limit returns 429", async () => {
  const app = appWithFetch(async () => jsonResponse(200, { active: true }));

  const response = await withServer(app, async (baseUrl) => {
    let lastResponse;
    for (let i = 0; i < 61; i += 1) {
      lastResponse = await httpRequest(baseUrl, "POST", "/v1/kick/oauth/introspect", { token: `token-${i}` });
    }
    return lastResponse;
  });

  assert.equal(response.status, 429);
  assert.deepEqual(response.body, { code: "rate_limited", message: "Too many requests" });
});

test("healthz includes security headers", async () => {
  const app = appWithFetch(async () => jsonResponse(200, {}));

  const response = await withServer(app, (baseUrl) => httpRequest(baseUrl, "GET", "/healthz"));

  assert.equal(response.status, 200);
  assert.equal(response.body.ok, true);
  assert.equal(response.headers["x-powered-by"], undefined);
  assert.equal(response.headers["x-content-type-options"], "nosniff");
  assert.equal(response.headers["x-frame-options"], "SAMEORIGIN");
});

test("pino redacts sensitive request fields", () => {
  const logs = [];
  const logger = pino(
    {
      level: "info",
      redact: { paths: redactPaths, censor: "[REDACTED]" },
    },
    {
      write: (line) => logs.push(line),
    }
  );

  logger.info({
    req: {
      headers: {
        authorization: "Bearer access-token",
        "x-admin-token": "fallback-admin-token",
      },
      body: {
        code: "authorization-code",
        codeVerifier: "code-verifier",
        refreshToken: "refresh-token",
        token: "secret-token",
      },
    },
  });

  const line = logs.join("");
  assert.doesNotMatch(
    line,
    /access-token|fallback-admin-token|authorization-code|code-verifier|refresh-token|secret-token/
  );
  assert.match(line, /\[REDACTED]/);
});

const hmacEnv = { ...baseEnv, APP_HMAC_SECRET: "hmac-secret" };

test("valid HMAC signature is accepted", async () => {
  const app = createApp(loadConfig(hmacEnv), { fetch: async () => jsonResponse(200, {}) });

  const response = await withServer(app, (baseUrl) =>
    signedRequest(baseUrl, "POST", "/v1/kick/oauth/introspect", { token: "secret-token" })
  );

  assert.equal(response.status, 200);
});

test("missing signature headers return 401 when HMAC is required", async () => {
  const app = createApp(loadConfig(hmacEnv), { fetch: async () => jsonResponse(200, {}) });

  const response = await withServer(app, (baseUrl) =>
    httpRequest(baseUrl, "POST", "/v1/kick/oauth/introspect", { token: "secret-token" })
  );

  assert.equal(response.status, 401);
  assert.deepEqual(response.body, { code: "unauthorized", message: "Request signature is invalid" });
});

test("wrong signature returns 401", async () => {
  const app = createApp(loadConfig(hmacEnv), { fetch: async () => jsonResponse(200, {}) });

  const response = await withServer(app, (baseUrl) =>
    signedRequest(baseUrl, "POST", "/v1/kick/oauth/introspect", { token: "secret-token" }, { secret: "wrong-secret" })
  );

  assert.equal(response.status, 401);
});

test("stale timestamp returns 401", async () => {
  const app = createApp(loadConfig(hmacEnv), { fetch: async () => jsonResponse(200, {}) });
  const staleTimestamp = String(Math.floor(Date.now() / 1000) - 3600);

  const response = await withServer(app, (baseUrl) =>
    signedRequest(baseUrl, "POST", "/v1/kick/oauth/introspect", { token: "secret-token" }, { timestamp: staleTimestamp })
  );

  assert.equal(response.status, 401);
});

test("nonce reuse returns 401", async () => {
  const app = createApp(loadConfig(hmacEnv), { fetch: async () => jsonResponse(200, {}) });

  await withServer(app, async (baseUrl) => {
    const nonce = "fixed-nonce";
    const first = await signedRequest(baseUrl, "POST", "/v1/kick/oauth/introspect", { token: "token-1" }, { nonce });
    const second = await signedRequest(baseUrl, "POST", "/v1/kick/oauth/introspect", { token: "token-2" }, { nonce });
    assert.equal(first.status, 200);
    assert.equal(second.status, 401);
  });
});

test("healthz stays open when HMAC is required", async () => {
  const app = createApp(loadConfig(hmacEnv), { fetch: async () => jsonResponse(200, {}) });

  const response = await withServer(app, (baseUrl) => httpRequest(baseUrl, "GET", "/healthz"));

  assert.equal(response.status, 200);
});

test("unsigned requests pass when no HMAC secret is configured", async () => {
  const app = appWithFetch(async () => jsonResponse(200, {}));

  const response = await withServer(app, (baseUrl) =>
    httpRequest(baseUrl, "POST", "/v1/kick/oauth/introspect", { token: "secret-token" })
  );

  assert.equal(response.status, 200);
});



function metricsEnv(overrides = {}) {
  return {
    ...baseEnv,
    METRICS_SALT: "test-salt-32-bytes-padding-padding",
    METRICS_ACCOUNT_SALT: "test-account-salt-padding-padding",
    METRICS_ADMIN_TOKEN: "admin-secret",
    METRICS_DATA_FILE: "memory",
    ...overrides,
  };
}

function appWithMetrics(fetchImpl, overrides = {}) {
  const cfg = loadConfig(metricsEnv(overrides));
  const store = createMetricsStore({
    salt: cfg.metrics.salt,
    accountSalt: cfg.metrics.accountSalt,
    dataPath: null,
  });
  return { app: createApp(cfg, { fetch: fetchImpl, metrics: store, crashReports: createCrashReportStore() }), store };
}

function makePingBody(version = "1.0.0") {
  // 64 hex chars, any value: the server re-hashes with the salt.
  return { pid: "a".repeat(64), v: version };
}

test("ping records a new install and reflects in stats", async () => {
  const { app, store } = appWithMetrics(async () => jsonResponse(200, {}));

  const response = await withServer(app, (baseUrl) =>
    httpRequest(baseUrl, "POST", "/v1/metrics/ping", makePingBody())
  );

  assert.equal(response.status, 204);
  const stats = store.computeStats();
  assert.equal(stats.mau, 1);
  assert.equal(stats.dauToday, 1);
  assert.equal(stats.totalInstalls, 1);
  assert.equal(stats.versions.length, 1);
  assert.equal(stats.versions[0].version, "1.0.0");
  store.close();
});

test("ping dedupes same hash within a day and does not inflate installs", async () => {
  const { app, store } = appWithMetrics(async () => jsonResponse(200, {}));

  await withServer(app, async (baseUrl) => {
    await httpRequest(baseUrl, "POST", "/v1/metrics/ping", makePingBody());
    await httpRequest(baseUrl, "POST", "/v1/metrics/ping", makePingBody("1.0.1"));
  });

  const stats = store.computeStats();
  assert.equal(stats.mau, 1);
  assert.equal(stats.totalInstalls, 1);
  assert.equal(stats.versions[0].version, "1.0.1");
  store.close();
});

test("ping rejects malformed payloads", async () => {
  const { app, store } = appWithMetrics(async () => jsonResponse(200, {}));

  const response = await withServer(app, (baseUrl) =>
    httpRequest(baseUrl, "POST", "/v1/metrics/ping", { pid: "not-hex", v: "1" })
  );

  assert.equal(response.status, 400);
  assert.equal(response.body.code, "invalid_request");
  store.close();
});

test("ping counts playback starts by engine and rejects out-of-range values", async () => {
  const { app, store } = appWithMetrics(async () => jsonResponse(200, {}));

  const ok = await withServer(app, (baseUrl) =>
    httpRequest(baseUrl, "POST", "/v1/metrics/ping", { ...makePingBody(), si: 3, se: 2 })
  );
  assert.equal(ok.status, 204);
  assert.equal(ok.headers["x-playback-starts-accepted"], "1");
  const bad = await withServer(app, (baseUrl) =>
    httpRequest(baseUrl, "POST", "/v1/metrics/ping", { ...makePingBody("1.0.1"), si: 200_000 })
  );
  assert.equal(bad.status, 400);

  const stats = store.computeStats();
  assert.deepEqual(stats.counters.today.engineSessions, { ivs: 3, exo: 2 });
  store.close();
});

test("metrics device cap returns 429 without adding another device", () => {
  const store = createMetricsStore({
    salt: "s",
    accountSalt: "s",
    dataPath: null,
    maxDevicesPerMonth: 1,
  });
  store.recordPing({ pidHash: "a".repeat(64), version: "1", clientEpoch: aMonthString() });
  assert.throws(
    () => store.recordPing({ pidHash: "b".repeat(64), version: "1", clientEpoch: aMonthString(), accountAid: "c".repeat(64) }),
    (error) => error.status === 429 && error.code === "metrics_capacity_reached"
  );
  assert.equal(store.computeStats().mau, 1);
  assert.equal(store.computeStats().pingAccountsMau, 0);
  store.close();
});

test("metrics caps ping accounts from returning devices before changing their data", () => {
  const store = createMetricsStore({ salt: "s", maxDevicesPerMonth: 1 });
  const now = new Date();
  const ping = { pidHash: "a".repeat(64), version: "1", accountAid: "b".repeat(64), c: 1, wt: "1" };
  store.recordPing(ping, now);
  const before = structuredClone(store.state);

  assert.throws(
    () => store.recordPing({ ...ping, version: "2", accountAid: "c".repeat(64), c: 5, wt: "3" }, now),
    (error) => error.status === 429 && error.code === "metrics_capacity_reached"
  );
  assert.deepEqual(store.state, before);
  store.recordPing({ ...ping, c: 0 }, now);
  store.recordPing({ pidHash: ping.pidHash, version: "2" }, now);
  const stats = store.computeStats(now);
  assert.equal(stats.mau, 1);
  assert.equal(stats.pingAccountsMau, 1);
  assert.equal(stats.counters.today.crashes.total, 1);
  store.close();
});

test("a full ping account bucket rejects a new device without recording it", () => {
  const store = createMetricsStore({ salt: "s", maxDevicesPerMonth: 2 });
  const now = new Date();
  const ping = { pidHash: "a".repeat(64), version: "1", accountAid: "b".repeat(64) };
  store.recordPing(ping, now);
  store.recordPing({ ...ping, accountAid: "c".repeat(64) }, now);
  const before = structuredClone(store.state);
  assert.throws(
    () => store.recordPing({ ...ping, pidHash: "d".repeat(64), accountAid: "e".repeat(64) }, now),
    (error) => error.status === 429 && error.code === "metrics_capacity_reached"
  );
  assert.deepEqual(store.state, before);
  assert.equal(store.computeStats(now).mau, 1);
  store.close();
});

test("ping account capacity survives reload and resets for a new month", () => {
  const dir = mkdtempSync(join(tmpdir(), "metrics-ping-cap-"));
  const options = { salt: "s", maxDevicesPerMonth: 1, dataPath: join(dir, "metrics.json") };
  const now = new Date();
  const ping = { pidHash: "a".repeat(64), version: "1", accountAid: "b".repeat(64) };
  let store = createMetricsStore(options);
  try {
    store.recordPing(ping, now);
    store.close();
    store = createMetricsStore(options);
    const nextAccount = { ...ping, accountAid: "c".repeat(64) };
    assert.throws(() => store.recordPing(nextAccount, now), (error) => error.status === 429);
    store.recordPing(ping, now);
    assert.equal(store.computeStats(now).pingAccountsMau, 1);

    const nextMonth = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1));
    store.recordPing(nextAccount, nextMonth);
    assert.equal(store.computeStats(nextMonth).pingAccountsMau, 1);
    assert.equal(store.computeStats(now).pingAccountsMau, 1);
  } finally {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("ping endpoint hidden when METRICS_SALT is unset", async () => {
  const app = appWithFetch(async () => jsonResponse(200, {}));
  const response = await withServer(app, (baseUrl) =>
    httpRequest(baseUrl, "POST", "/v1/metrics/ping", makePingBody())
  );
  assert.equal(response.status, 404);
});

test("stats endpoint requires admin token", async () => {
  const { app, store } = appWithMetrics(async () => jsonResponse(200, {}));

  const noToken = await withServer(app, (baseUrl) => httpRequest(baseUrl, "GET", "/v1/metrics/stats"));
  assert.equal(noToken.status, 401);

  const wrongToken = await withServer(app, (baseUrl) =>
    httpRequest(baseUrl, "GET", "/v1/metrics/stats", undefined, { headers: { Authorization: "Bearer wrong" } })
  );
  assert.equal(wrongToken.status, 401);

  const ok = await withServer(app, (baseUrl) =>
    httpRequest(baseUrl, "GET", "/v1/metrics/stats", undefined, { headers: { Authorization: "Bearer admin-secret" } })
  );
  assert.equal(ok.status, 200);
  assert.equal(typeof ok.body.mau, "number");
  assert.equal(ok.body.fcm.monitoredStreamers, 0);
  assert.ok(Number.isFinite(Date.parse(ok.body.fcm.delivery.since)));
  assert.equal(ok.body.fcm.poller.active, false);
  assert.equal(ok.body.fcm.webhook.configured, false);
  assert.equal(ok.body.fcm.webhook.lastReceivedAt, null);
  store.close();
});

test("stats endpoint hidden when METRICS_ADMIN_TOKEN is unset", async () => {
  const { app, store } = appWithMetrics(async () => jsonResponse(200, {}), { METRICS_ADMIN_TOKEN: "" });
  const response = await withServer(app, (baseUrl) => httpRequest(baseUrl, "GET", "/v1/metrics/stats"));
  assert.equal(response.status, 404);
  store.close();
});

test("dashboard shell loads without admin token while stats stays protected", async () => {
  const { app, store } = appWithMetrics(async () => jsonResponse(200, {}), {
    METRICS_DASHBOARD_FILE: join(process.cwd(), "dashboard.html"),
  });

  await withServer(app, async (baseUrl) => {
    const noToken = await httpRequest(baseUrl, "GET", "/v1/metrics/dashboard");
    assert.equal(noToken.status, 200);
    assert.match(noToken.headers["content-type"], /text\/html/);
    assert.match(noToken.body.raw, /Xtra Backend Ops/);
    assert.match(noToken.body.raw, /Connecting to backend telemetry/);

    const stats = await httpRequest(baseUrl, "GET", "/v1/metrics/stats");
    assert.equal(stats.status, 401);
  });
  store.close();
});

test("dashboard is served on /v1/metrics/dashboard and aliased on /v2", async () => {
  const { app, store } = appWithMetrics(async () => jsonResponse(200, {}), {
    METRICS_DASHBOARD_FILE: join(process.cwd(), "dashboard.html"),
  });

  await withServer(app, async (baseUrl) => {
    const main = await httpRequest(baseUrl, "GET", "/v1/metrics/dashboard");
    assert.equal(main.status, 200);
    assert.match(main.headers["content-type"], /text\/html/);
    assert.match(main.body.raw, /Xtra Backend Ops/);

    const v2 = await httpRequest(baseUrl, "GET", "/v1/metrics/dashboard/v2");
    assert.equal(v2.status, 200);
    assert.match(v2.headers["content-type"], /text\/html/);
    assert.match(v2.body.raw, /Xtra Backend Ops/);

    const stats = await httpRequest(baseUrl, "GET", "/v1/metrics/stats");
    assert.equal(stats.status, 401);
  });
  store.close();
});

test("account counter records hashed sub once per month", () => {
  const store = createMetricsStore({ salt: "a".repeat(32), accountSalt: "b".repeat(32), dataPath: null });
  const first = store.recordAccount({ sub: "user-42" });
  const second = store.recordAccount({ sub: "user-42" });
  assert.equal(first.isNewSession, true);
  assert.equal(second.isNewSession, false);
  const stats = store.computeStats();
  assert.equal(stats.accountsMau, 1);
  store.close();
});

function sha256HexClient(value) {
  return createHash("sha256").update(value).digest("hex");
}

test("new install with unknown account is counted and registers the account", () => {
  const store = createMetricsStore({ salt: "a".repeat(32), accountSalt: "b".repeat(32), dataPath: null });
  const result = store.recordPing({
    pidHash: "a".repeat(64),
    version: "2.0.0",
    clientEpoch: aMonthString(),
    accountAid: sha256HexClient("user-42"),
  });
  assert.equal(result.isNewInstall, true);
  const stats = store.computeStats();
  assert.equal(stats.totalInstalls, 1);
  store.close();
});

test("reinstall by a known account does not count as a new install", () => {
  const store = createMetricsStore({ salt: "a".repeat(32), accountSalt: "b".repeat(32), dataPath: null });
  store.recordAccount({ sub: "user-42" });
  const result = store.recordPing({
    pidHash: "b".repeat(64),
    version: "2.0.0",
    clientEpoch: aMonthString(),
    accountAid: sha256HexClient("user-42"),
  });
  assert.equal(result.isNewInstall, false);
  assert.equal(store.computeStats().totalInstalls, 0);
  store.close();
});

test("install is revoked when a recent install turns out to be a known account", () => {
  const store = createMetricsStore({ salt: "a".repeat(32), accountSalt: "b".repeat(32), dataPath: null });
  const pidHash = "c".repeat(64);
  const aid = sha256HexClient("user-42");

  // Fresh device pings before login: no account hash, counted as install.
  store.recordPing({ pidHash, version: "2.0.0", clientEpoch: aMonthString() });
  assert.equal(store.computeStats().totalInstalls, 1);

  // User logs in; next ping carries the account hash of a pre-existing account.
  store.recordAccount({ sub: "user-42" });
  store.recordPing({ pidHash, version: "2.0.0", clientEpoch: aMonthString(), accountAid: aid });
  assert.equal(store.computeStats().totalInstalls, 0);
  const month = store.state.devices[aMonthString()];
  assert.ok(!month[pidHash].n, "install day bit should be cleared");
  store.close();
});

test("install by a self-registered account is not revoked later", () => {
  const store = createMetricsStore({ salt: "a".repeat(32), accountSalt: "b".repeat(32), dataPath: null });
  const pidHash = "d".repeat(64);
  const aid = sha256HexClient("user-42");

  store.recordPing({ pidHash, version: "2.0.0", clientEpoch: aMonthString(), accountAid: aid });
  assert.equal(store.computeStats().totalInstalls, 1);
  store.recordPing({ pidHash, version: "2.0.0", clientEpoch: aMonthString(), accountAid: aid });
  assert.equal(store.computeStats().totalInstalls, 1);
  store.close();
});

test("old installs without a first-seen day are never revoked", () => {
  const store = createMetricsStore({ salt: "a".repeat(32), accountSalt: "b".repeat(32), dataPath: null });
  const pidHash = "e".repeat(64);
  store.recordAccount({ sub: "user-42" });
  // Simulate a pre-linkage entry: counted install with no t marker.
  store.recordPing({ pidHash, version: "2.0.0", clientEpoch: aMonthString() });
  const month = store.state.devices[aMonthString()];
  delete month[pidHash].t;
  month[pidHash].n = 1;
  store.recordPing({ pidHash, version: "2.0.0", clientEpoch: aMonthString(), accountAid: sha256HexClient("user-42") });
  assert.equal(store.computeStats().totalInstalls, 1);
  store.close();
});

test("retention series tracks install cohorts across days", () => {
  const store = createMetricsStore({ salt: "a".repeat(32), accountSalt: "b".repeat(32), dataPath: null });
  const now = new Date();
  const yesterday = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - 1));
  const firstDevice = "a".repeat(64);
  const secondDevice = "b".repeat(64);

  store.recordPing({ pidHash: firstDevice, version: "2.0.0", clientEpoch: monthStringOf(yesterday) }, yesterday);
  // Second install today: separate cohort, must not inflate yesterday's.
  store.recordPing({ pidHash: secondDevice, version: "2.0.0", clientEpoch: monthStringOf(now) }, now);
  // First device returns today (day 1 for its cohort).
  store.recordPing({ pidHash: firstDevice, version: "2.0.0", clientEpoch: monthStringOf(now) }, now);

  const stats = store.computeStats();
  assert.equal(stats.retention.length, 2);
  const yesterdayCohort = stats.retention.find((r) => r.date === yesterday.toISOString().slice(0, 10));
  const todayCohort = stats.retention.find((r) => r.date === now.toISOString().slice(0, 10));
  assert.equal(yesterdayCohort.size, 1);
  assert.equal(yesterdayCohort.d1, 100);
  assert.equal(todayCohort.size, 1);
  assert.equal(todayCohort.d1, null);
  store.close();
});

test("baselineDate is recorded for stores with existing traffic", () => {
  const store = createMetricsStore({ salt: "a".repeat(32), accountSalt: "b".repeat(32), dataPath: null });
  store.recordPing({ pidHash: "f".repeat(64), version: "2.0.0", clientEpoch: aMonthString() });
  const stats = store.computeStats();
  assert.ok(stats.baselineDate, "baselineDate should be derived from first counter day");
  store.close();
});

test("recordPing stores a validated geo country code", () => {
  const store = createMetricsStore({ salt: "a".repeat(32), accountSalt: "b".repeat(32), dataPath: null });
  const pidHash = "a".repeat(64);
  store.recordPing({ pidHash, version: "2.0.0", clientEpoch: aMonthString(), geoCountry: "si" });
  store.recordPing({ pidHash: "b".repeat(64), version: "2.0.0", clientEpoch: aMonthString(), geoCountry: "TOOLONG" });
  const month = store.state.devices[aMonthString()];
  assert.equal(month[pidHash].gc, "SI");
  assert.ok(!month["b".repeat(64)].gc, "invalid geo country must be ignored");
  const stats = store.computeStats();
  assert.deepEqual(stats.geoCountries, [
    { label: "SI", count: 1 },
    { label: "unknown", count: 1 },
  ]);
  store.close();
});

test("country lookup resolves public IPs and skips private or disabled setups", () => {
  const enabled = createCountryLookup({ geoipEnabled: true });
  assert.equal(enabled("8.8.8.8"), "US");
  assert.equal(enabled("127.0.0.1"), null);
  assert.equal(enabled(""), null);
  const disabled = createCountryLookup({ geoipEnabled: false });
  assert.equal(disabled("8.8.8.8"), null);
});

test("pings from private addresses store no geo country", async () => {
  const { app, store } = appWithMetrics(async () => jsonResponse(200, {}));
  await withServer(app, (baseUrl) =>
    httpRequest(baseUrl, "POST", "/v1/metrics/ping", makePingBody())
  );
  const stats = store.computeStats();
  assert.deepEqual(stats.geoCountries, [{ label: "unknown", count: 1 }]);
  store.close();
});

test("store reload keeps new fields and install dedup working", () => {
  const dir = mkdtempSync(join(tmpdir(), "metrics-reload-"));
  const file = join(dir, "m.json");
  const aid = sha256HexClient("user-42");
  const first = "a".repeat(64);
  try {
    const store = createMetricsStore({ salt: "s", accountSalt: "s", dataPath: file });
    store.recordPing({ pidHash: first, version: "2.0.0", clientEpoch: aMonthString(), accountAid: aid, geoCountry: "si", sessions: 3 });
    store.close();

    const reloaded = createMetricsStore({ salt: "s", accountSalt: "s", dataPath: file });
    assert.ok(reloaded.computeStats().baselineDate, "baselineDate must survive reload");

    // Same device pings again after reload: no second install.
    reloaded.recordPing({ pidHash: first, version: "2.0.0", clientEpoch: aMonthString(), accountAid: aid, geoCountry: "de" });
    assert.equal(reloaded.computeStats().totalInstalls, 1);

    // A second device with the known account after reload: not a new install.
    reloaded.recordPing({ pidHash: "b".repeat(64), version: "2.0.0", clientEpoch: aMonthString(), accountAid: aid });
    assert.equal(reloaded.computeStats().totalInstalls, 1);

    const month = reloaded.state.devices[aMonthString()];
    assert.equal(month[first].gc, "DE", "geo country should update on later pings");
    assert.equal(month[first].am, 1, "account registration marker must survive reload");
    assert.ok(month[first].t, "first-seen day must survive reload");
    reloaded.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("install is deduped across months for a returning device", () => {
  const store = createMetricsStore({ salt: "s", accountSalt: "s", dataPath: null });
  const pidHash = "c".repeat(64);
  const now = new Date();
  const prevMonth = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 15));

  store.recordPing({ pidHash, version: "2.0.0", clientEpoch: monthStringOf(prevMonth) }, prevMonth);
  store.recordPing({ pidHash, version: "2.1.0", clientEpoch: monthStringOf(now) }, now);

  const stats = store.computeStats();
  assert.equal(stats.totalInstalls, 1);
  assert.equal(stats.mau, 1);
  store.close();
});

test("ping v2 fields surface in stats and series", async () => {
  const { app, store } = appWithMetrics(async () => jsonResponse(200, {}));

  await withServer(app, (baseUrl) =>
    httpRequest(baseUrl, "POST", "/v1/metrics/ping", { ...makePingBody(), os: "34", cc: "de", s: 3 })
  );

  const stats = store.computeStats();
  assert.equal(stats.os[0].label, "34");
  assert.equal(stats.countries[0].label, "DE");
  assert.equal(stats.sessionsToday, 3);
  assert.equal(stats.wau, 1);
  const today = stats.dauSeries[stats.dauSeries.length - 1];
  assert.equal(today.dau, 1);
  assert.equal(today.new, 1);
  assert.equal(today.returning, 0);
  store.close();
});

test("same-day returning pings keep new/returning split intact", async () => {
  const { app, store } = appWithMetrics(async () => jsonResponse(200, {}));

  await withServer(app, async (baseUrl) => {
    await httpRequest(baseUrl, "POST", "/v1/metrics/ping", makePingBody());
    await httpRequest(baseUrl, "POST", "/v1/metrics/ping", makePingBody());
  });

  const today = store.computeStats().dauSeries.at(-1);
  assert.equal(today.dau, 1);
  assert.equal(today.new, 1);
  assert.equal(today.returning, 0);
  store.close();
});

test("weekly activity deduplicates devices across month and year boundaries", () => {
  const store = createMetricsStore({ salt: "s", dataPath: null, retentionMonths: 24 });
  const now = new Date(Date.UTC(new Date().getUTCFullYear() + 1, 0, 3));
  const currentMonth = monthStringOf(now);
  const previousMonth = monthStringOf(new Date(Date.UTC(now.getUTCFullYear(), 0, 0)));
  store.state.devices[previousMonth] = {
    returning: { d: (1 << 30) | (1 << 29) },
    previousOnly: { d: 1 << 27 },
    tooOld: { d: 1 << 26 },
    empty: null,
  };
  store.state.devices[currentMonth] = {
    returning: { d: 1 },
    currentOnly: { d: 1 << 2 },
    futureOnly: { d: 1 << 3 },
    inactive: { d: 0 },
  };

  assert.equal(store.computeStats(now).wau, 3);
  store.close();
});

test("weekly activity matches daily union for varied masks and window positions", () => {
  const store = createMetricsStore({ salt: "s", dataPath: null, retentionMonths: 24 });
  let seed = 42;
  const nextMask = () => {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    return seed & 0x7fffffff;
  };
  const year = new Date().getUTCFullYear() + 1;
  for (const month of [0, 1, 2, 11]) {
    const currentMonth = monthStringOf(new Date(Date.UTC(year, month, 1)));
    const previousMonth = monthStringOf(new Date(Date.UTC(year, month, 0)));
    store.state.devices = {};
    for (const key of [previousMonth, currentMonth]) {
      store.state.devices[key] = Object.fromEntries(
        Array.from({ length: 100 }, (_, index) => [`device-${index}`, { d: nextMask() }])
      );
    }
    for (const day of [1, 3, 7, 8, 28]) {
      const now = new Date(Date.UTC(year, month, day, 23, 59));
      const expected = new Set();
      for (let offset = 0; offset < 7; offset++) {
        const date = new Date(Date.UTC(year, month, day - offset));
        const bucket = store.state.devices[monthStringOf(date)] || {};
        const bit = 1 << (date.getUTCDate() - 1);
        for (const [hash, entry] of Object.entries(bucket)) {
          if (entry.d & bit) expected.add(hash);
        }
      }
      assert.equal(store.computeStats(now).wau, expected.size, now.toISOString());
    }
  }
  store.close();
});

test("endpoint and oauth outcome counters are recorded", async () => {
  const { app, store } = appWithMetrics(async () =>
    jsonResponse(400, { error: "invalid_grant" })
  );

  await withServer(app, async (baseUrl) => {
    await httpRequest(baseUrl, "POST", "/v1/metrics/ping", makePingBody());
    await httpRequest(baseUrl, "POST", "/v1/kick/oauth/refresh", { refreshToken: "refresh-token" });
  });

  const counters = store.computeStats().counters.today;
  assert.equal(counters.endpoints["POST /v1/metrics/ping"].ok, 1);
  assert.equal(counters.endpoints["POST /v1/kick/oauth/refresh"].r4, 1);
  assert.equal(counters.oauth.invalid_grant, 1);
  store.close();
});

async function waitFor(condition, timeoutMs = 1000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (condition()) return true;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  return condition();
}

test("successful exchange records account via token introspection", async () => {
  const fetchCalls = [];
  const { app, store } = appWithMetrics(async (url, options) => {
    fetchCalls.push({ url, headers: options?.headers, body: String(options?.body || "") });
    if (String(url).includes("/oauth/token") && !String(url).includes("introspect")) {
      return jsonResponse(200, { access_token: "at", refresh_token: "rt", expires_in: 3600 });
    }
    return jsonResponse(200, { data: { active: true, user_id: "42", username: "tester" } });
  });

  await withServer(app, async (baseUrl) => {
    await httpRequest(baseUrl, "POST", "/v1/kick/oauth/exchange", validExchangeBody());
    await waitFor(() => store.computeStats().accountsMau === 1);
  });

  const introspectCall = fetchCalls.find((c) => String(c.url).includes("introspect"));
  assert.ok(introspectCall, "expected an introspect call");
  assert.equal(introspectCall.headers?.Authorization, "Bearer at");
  const stats = store.computeStats();
  assert.equal(stats.accountsMau, 1);
  const accountBucket = latestAccountBucket(store);
  assert.equal(accountBucket.recorded, 1);
  store.close();
});

test("successful exchange falls back to users endpoint when introspect omits user_id", async () => {
  const fetchCalls = [];
  const { app, store } = appWithMetrics(async (url, options) => {
    fetchCalls.push({ url, headers: options?.headers });
    if (String(url).includes("/oauth/token") && !String(url).includes("introspect")) {
      return jsonResponse(200, { access_token: "at", refresh_token: "rt", expires_in: 3600 });
    }
    if (String(url).includes("introspect")) {
      return jsonResponse(200, { data: { active: true, client_id: "client-id", token_type: "user" } });
    }
    if (String(url).includes("/public/v1/users")) {
      return jsonResponse(200, { data: [{ user_id: "99", name: "fallbackUser" }] });
    }
    return jsonResponse(404, {});
  });

  await withServer(app, async (baseUrl) => {
    await httpRequest(baseUrl, "POST", "/v1/kick/oauth/exchange", validExchangeBody());
    await waitFor(() => store.computeStats().accountsMau === 1);
  });

  const userCall = fetchCalls.find((c) => String(c.url).includes("/public/v1/users"));
  assert.ok(userCall, "expected a /public/v1/users fallback call");
  assert.equal(userCall.headers?.Authorization, "Bearer at");
  const stats = store.computeStats();
  assert.equal(stats.accountsMau, 1);
  const accountBucket = latestAccountBucket(store);
  assert.equal(accountBucket.recorded, 1);
  store.close();
});

test("scanner probe endpoints are rejected and categorized as OTHER in metrics", async () => {
  const { app, store } = appWithMetrics(async () => jsonResponse(200, {}));

  await withServer(app, async (baseUrl) => {
    const envRes = await httpRequest(baseUrl, "GET", "/v1/.env");
    assert.equal(envRes.status, 404);
    assert.deepEqual(envRes.body, { code: "not_found", message: "Not found" });

    const gqlRes = await httpRequest(baseUrl, "POST", "/v1/graphql", { query: "{}" });
    assert.equal(gqlRes.status, 404);

    const unknownRes = await httpRequest(baseUrl, "GET", "/v1/random-scan-path");
    assert.equal(unknownRes.status, 404);
  });

  const counters = store.computeStats().counters.today;
  assert.ok(counters.endpoints["OTHER / 404"], "expected OTHER / 404 bucket");
  assert.equal(counters.endpoints["OTHER / 404"].r4, 3);
  assert.equal(counters.endpoints["GET /v1/.env"], undefined);
  assert.equal(counters.endpoints["POST /v1/graphql"], undefined);
  store.close();
});

test("introspect failure increments account counter instead of failing silently", async () => {
  const { app, store } = appWithMetrics(async (url) => {
    if (String(url).includes("/oauth/token") && !String(url).includes("introspect")) {
      return jsonResponse(200, { access_token: "at", refresh_token: "rt", expires_in: 3600 });
    }
    return jsonResponse(401, { message: "unauthorized" });
  });

  await withServer(app, async (baseUrl) => {
    await httpRequest(baseUrl, "POST", "/v1/kick/oauth/exchange", validExchangeBody());
    await waitFor(() => Object.keys(store.state.counters).length > 0 && Object.keys(latestAccountBucket(store)).length > 0);
  });

  const accountBucket = latestAccountBucket(store);
  assert.equal(accountBucket.introspect_http_401, 1);
  assert.equal(store.computeStats().accountsMau, 0);
  store.close();
});

test("ping rejection counters track invalid payloads", async () => {
  const { app, store } = appWithMetrics(async () => jsonResponse(200, {}));

  await withServer(app, async (baseUrl) => {
    await httpRequest(baseUrl, "POST", "/v1/metrics/ping", { pid: "nothex", v: "1" });
  });

  const pingCounters = store.state.counters[Object.keys(store.state.counters)[0]].ping;
  assert.equal(pingCounters.invalid, 1);
  store.close();
});

test("stats honors days query parameter", async () => {
  const { app, store } = appWithMetrics(async () => jsonResponse(200, {}));

  const response = await withServer(app, (baseUrl) =>
    httpRequest(baseUrl, "GET", "/v1/metrics/stats?days=30", undefined, {
      headers: { Authorization: "Bearer admin-secret" },
    })
  );

  assert.equal(response.status, 200);
  assert.equal(response.body.dauSeries.length, 30);
  store.close();
});

test("schema 1 store file is migrated without losing data", () => {
  const dir = mkdtempSync(join(tmpdir(), "metrics-v1-"));
  const file = join(dir, "m.json");
  const month = monthStringOf(new Date());
  try {
    writeFileSync(
      file,
      JSON.stringify({
        version: 1,
        totalInstalls: 7,
        devices: { [month]: { ["e".repeat(64)]: { v: "1.0.0", d: 1 } } },
        accounts: { [month]: { "sub1": true } },
      })
    );
    const store = createMetricsStore({ salt: "s", accountSalt: "s", dataPath: file });
    const stats = store.computeStats();
    assert.equal(stats.totalInstalls, 7);
    assert.equal(stats.mau, 1);
    assert.equal(stats.accountsMau, 1);

    // First v2 ping counts once as install (baseline), then dedup applies.
    store.recordPing({ pidHash: "f".repeat(64), version: "2.0.0", clientEpoch: month });
    store.recordPing({ pidHash: "f".repeat(64), version: "2.0.0", clientEpoch: month });
    assert.equal(store.computeStats().totalInstalls, 8);
    store.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

function monthStringOf(date) {
  return `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, "0")}`;
}

function latestAccountBucket(store) {
  const days = Object.keys(store.state.counters).sort();
  return store.state.counters[days[days.length - 1]].account;
}

test("metrics store persists and reloads across instances", () => {
  const dir = mkdtempSync(join(tmpdir(), "metrics-"));
  const file = join(dir, "m.json");
  try {
    const a = createMetricsStore({ salt: "s", accountSalt: "s", dataPath: file });
    a.recordPing({ pidHash: "d".repeat(64), version: "1.0.0", clientEpoch: aMonthString() });
    a.flushSync();
    a.close();
    const b = createMetricsStore({ salt: "s", accountSalt: "s", dataPath: file });
    const stats = b.computeStats();
    assert.equal(stats.mau, 1);
    assert.equal(stats.totalInstalls, 1);
    b.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

function aMonthString() {
  const d = new Date();
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}`;
}

test("fcm store subscribes and creates reverse index", () => {
  const store = createFcmStore({ dataFile: null });
  const tokenA = "a".repeat(32);
  const tokenB = "b".repeat(32);

  store.subscribe({ token: tokenA, kickUserId: "1001", channelIds: ["500", "600"] });
  store.subscribe({ token: tokenB, kickUserId: "1002", channelIds: ["600", "700"] });

  assert.deepEqual(store.getTokensForChannel("500"), [tokenA]);
  assert.deepEqual(store.getTokensForChannel("600").sort(), [tokenA, tokenB].sort());
  assert.deepEqual(store.getTokensForChannel("700"), [tokenB]);
  assert.deepEqual(store.getTokensForChannel("999"), []);

  const stats = store.stats();
  assert.equal(stats.totalTokens, 2);
  assert.equal(stats.activeChannels, 3);

  store.unsubscribe({ token: tokenA });
  assert.deepEqual(store.getTokensForChannel("500"), []);
  assert.deepEqual(store.getTokensForChannel("600"), [tokenB]);
  assert.equal(store.stats().totalTokens, 1);
  assert.equal(store.stats().activeChannels, 2);
});

test("push stats count resolved streamers once across aliases and expose unresolved keys", () => {
  clearChannelResolutionCache();
  const store = createFcmStore();
  const resolved = { userId: "42", channelId: "44", slug: "alias-streamer", expiresAt: Date.now() + 60000 };
  for (const key of ["42", "44", "alias-streamer"]) channelResolutionCache.set(key, resolved);
  channelResolutionCache.set("expired", { userId: "99", expiresAt: 0 });
  store.subscribe({ token: "one", channelIds: ["42", "44", "alias-streamer", "unknown", "expired"] });
  store.subscribe({ token: "two", channelIds: ["alias-streamer"] });
  const stats = store.stats();
  assert.equal(stats.totalTokens, 2);
  assert.equal(stats.activeChannels, 5);
  assert.equal(stats.monitoredStreamers, 1);
  assert.equal(stats.unresolvedChannelKeys, 2);
  assert.ok(Number.isFinite(Date.parse(stats.delivery.since)));
  assert.equal(store.stats().delivery.since, stats.delivery.since);
  store.unsubscribe({ token: "one" });
  assert.equal(store.stats().monitoredStreamers, 1);
  assert.equal(store.stats().unresolvedChannelKeys, 0);
  clearChannelResolutionCache();
});

test("fcm store persists across instances", () => {
  const dir = mkdtempSync(join(tmpdir(), "fcm-"));
  const file = join(dir, "fcm.json");
  const token = "x".repeat(32);

  try {
    const a = createFcmStore({ dataFile: file });
    a.subscribe({ token, kickUserId: "123", channelIds: ["456"] });
    a.flushSync();

    const b = createFcmStore({ dataFile: file });
    assert.deepEqual(b.getTokensForChannel("456"), [token]);
    assert.equal(b.stats().totalTokens, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("POST /v1/fcm/subscribe validates payload and records subscription", async () => {
  const fcmStore = createFcmStore({ dataFile: null });
  const app = createApp(config(), { fcmStore, messaging: null, pusherRelay: null });

  await withServer(app, async (baseUrl) => {
    const token = "fcm_test_token_123456789012345";
    const res = await httpRequest(baseUrl, "POST", "/v1/fcm/subscribe", {
      token,
      kick_user_id: "999",
      channel_ids: ["100", "200"],
    });

    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.equal(res.body.subscribed_channels, 2);
    assert.deepEqual(fcmStore.getTokensForChannel("100"), [token]);

    const unregRes = await httpRequest(baseUrl, "POST", "/v1/fcm/unsubscribe", {
      token,
    });
    assert.equal(unregRes.status, 200);
    assert.equal(unregRes.body.ok, true);
    assert.equal(unregRes.body.unsubscribed, true);
    assert.deepEqual(fcmStore.getTokensForChannel("100"), []);
  });
});

test("sendLivePushNotification handles multicast response and prunes invalid tokens", async () => {
  const fcmStore = createFcmStore({ dataFile: null });
  const validToken = "valid_token_123456789012345";
  const invalidToken = "invalid_token_1234567890123";

  fcmStore.subscribe({ token: validToken, channelIds: ["888"] });
  fcmStore.subscribe({ token: invalidToken, channelIds: ["888"] });

  const mockMessaging = {
    sendEachForMulticast: async (payload) => {
      return {
        successCount: 1,
        failureCount: 1,
        responses: [
          { success: true },
          { success: false, error: { code: "messaging/registration-token-not-registered" } },
        ],
      };
    },
  };

  const result = await sendLivePushNotification({
    messaging: mockMessaging,
    tokens: [validToken, invalidToken],
    userId: "888",
    channelSlug: "teststreamer",
    title: "teststreamer is live!",
    description: "Playing Minecraft",
    profilePicture: "https://example.com/avatar.jpg",
    logger: null,
    fcmStore,
  });

  assert.equal(result.successCount, 1);
  assert.equal(result.failureCount, 1);
  assert.deepEqual(result.invalidTokens, [invalidToken]);
  assert.deepEqual(fcmStore.getTokensForChannel("888"), [validToken]);
  const delivery = fcmStore.stats().delivery;
  assert.equal(delivery.alertsDispatched, 1);
  assert.equal(delivery.multicastSuccess, 1);
  assert.equal(delivery.multicastFailure, 1);
  assert.equal(delivery.tokensPruned, 1);
});

test("handleLiveEvent matches subscribers by channelId, userId, and slug", async () => {
  const fcmStore = createFcmStore({ dataFile: null });
  const tokenChannel = "token_channel_668";
  const tokenUser = "token_user_676";
  const tokenSlug = "token_slug_xqc";
  const tokenUnrelated = "token_unrelated_999";

  fcmStore.subscribe({ token: tokenChannel, channelIds: ["668"] });
  fcmStore.subscribe({ token: tokenUser, channelIds: ["676"] });
  fcmStore.subscribe({ token: tokenSlug, channelIds: ["xqc"] });
  fcmStore.subscribe({ token: tokenUnrelated, channelIds: ["999"] });

  let sentPayload = null;
  const mockMessaging = {
    sendEachForMulticast: async (payload) => {
      sentPayload = payload;
      return {
        successCount: payload.tokens.length,
        failureCount: 0,
        responses: payload.tokens.map(() => ({ success: true })),
      };
    },
  };

  const relay = createPusherRelay({
    fcmStore,
    messaging: mockMessaging,
    logger: null,
  });

  const kickLiveMessage = {
    event: "App\\Events\\NotifyFollowersStreamHasStarted",
    channel: "channel.668",
    data: JSON.stringify({
      user_id: 676,
      title: "xQc is live!",
      description: "Chatting",
      path: "/xqc",
      profile_picture: "https://example.com/avatar.jpg",
    }),
  };

  relay.handleLiveEvent(kickLiveMessage);
  relay.close();

  assert.ok(sentPayload, "Multicast payload should have been sent");
  assert.equal(sentPayload.data.type, "stream_live");
  assert.equal(sentPayload.data.channel_id, "668");
  assert.equal(sentPayload.data.user_id, "676");
  assert.equal(sentPayload.data.channel_slug, "xqc");
  assert.deepEqual(new Set(sentPayload.tokens), new Set([tokenChannel, tokenUser, tokenSlug]));
  assert.ok(!sentPayload.tokens.includes(tokenUnrelated));
});

test("sendLivePushNotification includes channel_id and properly trims leading slashes from slug", async () => {
  let capturedPayload = null;
  const mockMessaging = {
    sendEachForMulticast: async (payload) => {
      capturedPayload = payload;
      return { successCount: 1, failureCount: 0, responses: [{ success: true }] };
    },
  };

  await sendLivePushNotification({
    messaging: mockMessaging,
    tokens: ["dummy_token_1234567890"],
    channelId: "668",
    userId: "676",
    channelSlug: "/xqc",
    title: "xQc is live!",
    description: "Just Chatting",
    profilePicture: "https://example.com/pfp.jpg",
    logger: null,
  });

  assert.ok(capturedPayload);
  assert.equal(capturedPayload.data.channel_id, "668");
  assert.equal(capturedPayload.data.user_id, "676");
  assert.equal(capturedPayload.data.channel_slug, "xqc");
  assert.equal(capturedPayload.android.priority, "high");
});

test("multicast sends no more than 500 tokens per batch and continues after failures", async () => {
  const sizes = [];
  const fcmStore = createFcmStore();
  const messaging = {
    async sendEachForMulticast({ tokens }) {
      sizes.push(tokens.length);
      if (sizes.length === 2) throw new Error("temporary failure");
      return { successCount: tokens.length, failureCount: 0, responses: tokens.map(() => ({ success: true })) };
    },
  };
  const result = await sendLivePushNotification({
    messaging, tokens: Array.from({ length: 1001 }, (_, index) => `token-${index}`), channelSlug: "test",
    fcmStore, source: "webhook",
  });
  assert.deepEqual(sizes, [500, 500, 1]);
  assert.equal(result.successCount, 501);
  assert.equal(result.failureCount, 500);
  const delivery = fcmStore.stats().delivery;
  assert.equal(delivery.alertsDispatched, 1);
  assert.equal(delivery.notificationsSent, 1001);
  assert.equal(delivery.multicastSuccess, 501);
  assert.equal(delivery.multicastFailure, 500);
  assert.equal(delivery.sources.webhook, 1);
  assert.equal(delivery.recentAlerts.length, 1);
  assert.equal(delivery.recentAlerts[0].recipients, 1001);
  assert.equal(delivery.recentAlerts[0].successCount, 501);
  assert.equal(delivery.recentAlerts[0].failureCount, 500);
});

test("invalid tokens in later multicast batches are pruned using that batch's indices", async () => {
  const fcmStore = createFcmStore();
  const tokens = Array.from({ length: 501 }, (_, index) => `token-${index}`);
  fcmStore.subscribe({ token: tokens[0], channelIds: ["test"] });
  fcmStore.subscribe({ token: tokens[500], channelIds: ["test"] });
  const messaging = {
    async sendEachForMulticast({ tokens: batch }) {
      const invalid = batch.length === 1;
      return {
        successCount: invalid ? 0 : batch.length,
        failureCount: invalid ? 1 : 0,
        responses: batch.map(() => invalid
          ? { success: false, error: { code: "messaging/registration-token-not-registered" } }
          : { success: true }),
      };
    },
  };
  const result = await sendLivePushNotification({ messaging, tokens, fcmStore, channelSlug: "test" });
  assert.equal(result.successCount, 500);
  assert.equal(result.failureCount, 1);
  assert.deepEqual(result.invalidTokens, [tokens[500]]);
  assert.deepEqual(fcmStore.getTokensForChannel("test"), [tokens[0]]);
  assert.equal(fcmStore.stats().delivery.alertsDispatched, 1);
  assert.equal(fcmStore.stats().delivery.tokensPruned, 1);
});

test("failed multicast batches record one failed alert and empty sends record none", async () => {
  const fcmStore = createFcmStore();
  const messaging = { async sendEachForMulticast() { throw new Error("unavailable"); } };
  const options = { messaging, fcmStore, channelSlug: "test", source: "poller" };
  await sendLivePushNotification({ ...options, tokens: [] });
  await sendLivePushNotification({ ...options, messaging: null, tokens: ["token"] });
  assert.equal(fcmStore.stats().delivery.alertsDispatched, 0);

  const result = await sendLivePushNotification({ ...options, tokens: Array(501).fill("token") });
  assert.equal(result.successCount, 0);
  assert.equal(result.failureCount, 501);
  const delivery = fcmStore.stats().delivery;
  assert.equal(delivery.alertsDispatched, 1);
  assert.equal(delivery.notificationsSent, 501);
  assert.equal(delivery.multicastFailure, 501);
  assert.equal(delivery.sources.poller, 1);
  assert.equal(delivery.recentAlerts.length, 1);
});

test("stale alias resolution cannot change a replacement subscription", () => {
  const store = createFcmStore();
  const first = store.subscribe({ token: "test-token", channelIds: ["old"] });
  store.subscribe({ token: "test-token", channelIds: ["new"] });
  assert.equal(store.addAliasesToToken("test-token", ["stale"], first.revision), 0);
  assert.deepEqual(store.getTokensForChannel("stale"), []);
});

test("fcmStore.addAliasesToToken adds new channels to existing token without wiping old ones", () => {
  const store = createFcmStore({ dataFile: null });
  const token = "x".repeat(32);
  store.subscribe({ token, channelIds: ["xqc"] });

  assert.deepEqual(store.getTokensForChannel("xqc"), [token]);
  assert.deepEqual(store.getTokensForChannel("668"), []);

  const added = store.addAliasesToToken(token, ["668", "676", "xqc"]);
  assert.equal(added, 2); // 668 and 676 added, xqc was already present

  assert.deepEqual(store.getTokensForChannel("xqc"), [token]);
  assert.deepEqual(store.getTokensForChannel("668"), [token]);
  assert.deepEqual(store.getTokensForChannel("676"), [token]);
});

test("POST /v1/fcm/subscribe resolves non-numeric slugs in the background", async () => {
  const fcmStore = createFcmStore({ dataFile: null });
  const token = "z".repeat(32);

  const mockFetch = async (url) => {
    if (url.includes("/channels/xqc")) {
      return {
        ok: true,
        json: async () => ({ id: 668, user_id: 676, slug: "xqc" }),
      };
    }
    return { ok: false, status: 404 };
  };

  const app = createApp(
    config({
      fcm: { pusherRelayEnabled: false },
    }),
    {
      fcmStore,
      messaging: null,
      fetch: mockFetch,
    }
  );

  await withServer(app, async (baseUrl) => {
    const response = await httpRequest(baseUrl, "POST", "/v1/fcm/subscribe", {
      token,
      channel_ids: ["xqc"],
    });

    assert.equal(response.status, 200);
    assert.equal(response.body.ok, true);

    // Wait briefly for the background resolution promise to settle
    await new Promise((r) => setTimeout(r, 60));

    // Verify that numeric channel 668 and user 676 were added as aliases to the token
    assert.deepEqual(fcmStore.getTokensForChannel("668"), [token]);
    assert.deepEqual(fcmStore.getTokensForChannel("676"), [token]);
    assert.deepEqual(fcmStore.getTokensForChannel("xqc"), [token]);
  });
});

test("POST /v1/fcm/subscribe resolves numeric broadcaster user IDs via app access token in the background", async () => {
  clearChannelResolutionCache();
  const fcmStore = createFcmStore({ dataFile: null });
  const token = "w".repeat(32);

  const mockFetch = async (url, options = {}) => {
    if (url.includes("/oauth/token")) {
      return {
        ok: true,
        json: async () => ({ access_token: "test_app_token", expires_in: 3600 }),
      };
    }
    if (url.includes("/public/v1/channels?") && url.includes("broadcaster_user_id=1235212")) {
      return {
        ok: true,
        json: async () => ({
          data: [{ broadcaster_user_id: 1235212, slug: "kookie" }],
        }),
      };
    }
    if (url.includes("/api/v2/channels/kookie")) {
      return {
        ok: true,
        json: async () => ({ id: 1193742, user_id: 1235212, slug: "kookie" }),
      };
    }
    return { ok: false, status: 404 };
  };

  const app = createApp(
    config({
      fcm: { pusherRelayEnabled: false },
    }),
    {
      fcmStore,
      messaging: null,
      fetch: mockFetch,
    }
  );

  await withServer(app, async (baseUrl) => {
    const response = await httpRequest(baseUrl, "POST", "/v1/fcm/subscribe", {
      token,
      channel_ids: ["1235212"],
    });

    assert.equal(response.status, 200);
    assert.equal(response.body.ok, true);

    // Wait briefly for background resolution to settle
    await new Promise((r) => setTimeout(r, 100));

    // Verify channel ID 1193742, user ID 1235212, and slug kookie were all registered to token
    assert.deepEqual(fcmStore.getTokensForChannel("1193742"), [token]);
    assert.deepEqual(fcmStore.getTokensForChannel("1235212"), [token]);
    assert.deepEqual(fcmStore.getTokensForChannel("kookie"), [token]);
  });
});

test("backfillStoredSubscriptions resolves stored numeric user IDs and adds channel aliases", async () => {
  clearChannelResolutionCache();
  const fcmStore = createFcmStore({ dataFile: null });
  const token = "v".repeat(32);
  fcmStore.subscribe({ token, channelIds: ["1235212"] });

  let synced = false;
  const mockPusherRelay = {
    syncSubscriptions() {
      synced = true;
    },
  };

  const mockFetch = async (url) => {
    if (url.includes("/oauth/token")) {
      return {
        ok: true,
        json: async () => ({ access_token: "app_token", expires_in: 3600 }),
      };
    }
    if (url.includes("/public/v1/channels?") && url.includes("broadcaster_user_id=1235212")) {
      return {
        ok: true,
        json: async () => ({
          data: [{ broadcaster_user_id: 1235212, slug: "kookie" }],
        }),
      };
    }
    if (url.includes("/api/v2/channels/kookie")) {
      return {
        ok: true,
        json: async () => ({ id: 1193742, user_id: 1235212, slug: "kookie" }),
      };
    }
    return { ok: false, status: 404 };
  };

  await backfillStoredSubscriptions(fcmStore, mockPusherRelay, {
    config: { kickClientId: "test-client", kickClientSecret: "test-secret" },
    fetchFn: mockFetch,
  });

  assert.equal(synced, true);
  assert.deepEqual(fcmStore.getTokensForChannel("1193742"), [token]);
  assert.deepEqual(fcmStore.getTokensForChannel("1235212"), [token]);
  assert.deepEqual(fcmStore.getTokensForChannel("kookie"), [token]);
});

test("createLiveStreamPoller detects stream start, sends notification, and dedupes repeat polls", async () => {
  clearChannelResolutionCache();
  const fcmStore = createFcmStore({ dataFile: null });
  const token = "w".repeat(32);
  fcmStore.subscribe({ token, channelIds: ["131146"] });

  let sentPayload = null;
  const mockMessaging = {
    async sendEachForMulticast(payload) {
      sentPayload = payload;
      return { successCount: payload.tokens.length, failureCount: 0, responses: payload.tokens.map(() => ({ success: true })) };
    },
  };

  let mockIsLive = true;
  let mockStartTime = "2026-09-04 08:53:37";

  const mockFetch = async (url) => {
    if (url.includes("/oauth/token")) {
      return {
        ok: true,
        json: async () => ({ access_token: "mock-app-token", expires_in: 3600 }),
      };
    }
    if (url.includes("/public/v1/channels?") && url.includes("broadcaster_user_id=131146")) {
      return {
        ok: true,
        json: async () => ({
          data: [
            {
              broadcaster_user_id: 131146,
              channel_id: 129698,
              slug: "dougthegiant",
              stream_title: "Doug Stream Live",
              channel_description: "Giant gaming",
              profile_picture: "https://example.com/avatar.jpg",
              banner_picture: "https://example.com/banner.jpg",
              stream: {
                is_live: mockIsLive,
                start_time: mockStartTime,
                viewer_count: 50,
              },
            },
          ],
        }),
      };
    }
    return { ok: false, status: 404 };
  };

  const poller = createLiveStreamPoller({
    fcmStore,
    messaging: mockMessaging,
    config: { kickClientId: "test-client", kickClientSecret: "test-secret" },
    fetchFn: mockFetch,
    pollIntervalMs: 60_000,
  });

  try {
    // 1. First cycle (warm-up): seeds seenStreams but does NOT dispatch notifications
    await poller.checkLiveStreams();
    assert.equal(sentPayload, null, "Warm-up cycle should not dispatch any notification");
    assert.equal(poller.getSeenStreams().has("131146"), true, "Warm-up should seed seenStreams");

    // 2. Second cycle while stream is still running: dedup (same start_time, no notification)
    await poller.checkLiveStreams();
    assert.equal(sentPayload, null, "Notification should be deduped for ongoing stream");

    // 3. Stream goes offline
    mockIsLive = false;
    await poller.checkLiveStreams();
    assert.equal(sentPayload, null);
    assert.equal(poller.getSeenStreams().has("131146"), false, "Offline stream pruned from seenStreams");

    // 4. Stream goes live again with new start time — should notify (warm-up is over)
    mockIsLive = true;
    mockStartTime = "2026-09-04 12:00:00";
    await poller.checkLiveStreams();
    assert.ok(sentPayload !== null, "Notification dispatched for new stream start after warm-up");
    assert.deepEqual(sentPayload.tokens, [token]);
    assert.equal(sentPayload.data.channel_slug, "dougthegiant");
    assert.equal(sentPayload.data.channel_id, "129698");
    assert.equal(sentPayload.data.user_id, "131146");
    assert.equal(sentPayload.data.title, "Doug Stream Live");
    assert.equal(sentPayload.data.description, "");
    assert.equal(sentPayload.data.profile_picture, "https://example.com/avatar.jpg");
  } finally {
    poller.close();
  }
});

test("failed webhook delivery can retry the same stream without duplicating a successful retry", async () => {
  clearChannelResolutionCache();
  const fcmStore = createFcmStore({ dataFile: null });
  fcmStore.subscribe({ token: "retry-token", channelIds: ["42", "retry-streamer"] });
  const seenStreams = new Map();
  let calls = 0;
  let failFirst;
  const messaging = {
    async sendEachForMulticast(payload) {
      if (++calls === 1) return await new Promise((_, reject) => { failFirst = reject; });
      return { successCount: payload.tokens.length, failureCount: 0, responses: payload.tokens.map(() => ({ success: true })) };
    },
  };
  const options = { eventType: "livestream.status.updated", fcmStore, messaging, seenStreams,
    payload: { broadcaster: { user_id: 42, channel_slug: "retry-streamer" }, is_live: true, started_at: "2026-11-05T12:00:00Z" } };

  const firstDelivery = handleWebhookLiveEvent(options);
  await handleWebhookLiveEvent({ ...options, payload: { ...options.payload, is_live: false } });
  assert.equal((await handleWebhookLiveEvent(options)).duplicate, true);
  assert.equal(calls, 1);
  failFirst(new Error("temporary FCM outage"));
  const failed = await firstDelivery;
  assert.equal(failed.delivery.failureCount, 1);
  assert.equal(seenStreams.has("42"), false);
  const retried = await handleWebhookLiveEvent(options);
  assert.equal(retried.delivery.successCount, 1);
  assert.equal((await handleWebhookLiveEvent(options)).duplicate, true);
  assert.equal(calls, 2);
});

test("an older failed webhook delivery cannot clear a newer stream's deduplication state", async () => {
  clearChannelResolutionCache();
  const fcmStore = createFcmStore({ dataFile: null });
  fcmStore.subscribe({ token: "overlap-token", channelIds: ["42", "overlap-streamer"] });
  const seenStreams = new Map();
  let failOld;
  let calls = 0;
  const messaging = {
    async sendEachForMulticast(payload) {
      if (++calls === 1) return await new Promise((_, reject) => { failOld = reject; });
      return { successCount: payload.tokens.length, failureCount: 0, responses: payload.tokens.map(() => ({ success: true })) };
    },
  };
  const options = { eventType: "livestream.status.updated", fcmStore, messaging, seenStreams };
  const payload = { broadcaster: { user_id: 42, channel_slug: "overlap-streamer" }, is_live: true };
  const oldDelivery = handleWebhookLiveEvent({ ...options, payload: { ...payload, started_at: "2026-11-05T12:00:00Z" } });
  const current = { ...payload, started_at: "2026-11-05T13:00:00Z" };
  await handleWebhookLiveEvent({ ...options, payload: current });
  failOld(new Error("old request failed"));
  await oldDelivery;

  assert.equal(seenStreams.get("42"), current.started_at);
  assert.equal((await handleWebhookLiveEvent({ ...options, payload: current })).duplicate, true);
  assert.equal(calls, 2);
});

test("poller and webhook deduplicate equivalent UTC start-time formats after warmup", async () => {
  clearChannelResolutionCache();
  const fcmStore = createFcmStore({ dataFile: null });
  fcmStore.subscribe({ token: "format-token", channelIds: ["42", "format-streamer"] });
  const seenStreams = new Map();
  let live = false;
  let calls = 0;
  const messaging = {
    async sendEachForMulticast(payload) {
      calls++;
      return { successCount: payload.tokens.length, failureCount: 0, responses: payload.tokens.map(() => ({ success: true })) };
    },
  };
  const poller = createLiveStreamPoller({ fcmStore, messaging, seenStreams,
    config: { kickClientId: "test-client", kickClientSecret: "test-secret" },
    fetchFn: async (url) => url.includes("/oauth/token")
      ? jsonResponse(200, { access_token: "test-app-token", expires_in: 3600 })
      : jsonResponse(200, { data: [{ broadcaster_user_id: 42, channel_id: 44, slug: "format-streamer",
        stream: { is_live: live, start_time: "2026-11-05 12:00:00" } }] }),
  });
  try {
    await poller.checkLiveStreams();
    live = true;
    await handleWebhookLiveEvent({ eventType: "livestream.status.updated", fcmStore, messaging, seenStreams,
      payload: { broadcaster: { user_id: 42, channel_slug: "format-streamer" }, is_live: true, started_at: "2026-11-05T12:00:00.000Z" } });
    live = false;
    await poller.checkLiveStreams();
    live = true;
    await poller.checkLiveStreams();
    assert.equal(calls, 1);
    const options = { eventType: "livestream.status.updated", fcmStore, messaging, seenStreams };
    const broadcast = { broadcaster: { user_id: 42, channel_slug: "format-streamer" }, is_live: true,
      started_at: "2026-11-05T12:00:00.000Z" };
    await handleWebhookLiveEvent({ ...options, payload: { ...broadcast, is_live: false } });
    await handleWebhookLiveEvent({ ...options, payload: broadcast });
    assert.equal(calls, 1);
    await handleWebhookLiveEvent({ ...options, payload: { ...broadcast, started_at: "2026-11-05T12:30:00Z" } });
    assert.equal(calls, 2);
    await handleWebhookLiveEvent({ ...options, payload: broadcast });
    assert.equal(calls, 2);
  } finally {
    poller.close();
  }
});

test("poller resolves offline streamer aliases for accurate monitoring counts", async () => {
  clearChannelResolutionCache();
  const store = createFcmStore();
  store.subscribe({ token: "offline-token", channelIds: ["42", "44", "offline-streamer"] });
  let channelId = 44;
  const poller = createLiveStreamPoller({
    fcmStore: store, messaging: {}, config: { kickClientId: "test", kickClientSecret: "test" },
    fetchFn: async url => url.includes("/oauth/token")
      ? jsonResponse(200, { access_token: "test-token", expires_in: 3600 })
      : jsonResponse(200, { data: [{ broadcaster_user_id: 42, channel_id: channelId, slug: "offline-streamer", stream: null }] }),
  });
  try {
    await poller.checkLiveStreams();
    const stats = store.stats();
    assert.equal(stats.monitoredStreamers, 1);
    assert.equal(stats.unresolvedChannelKeys, 0);
    assert.equal(stats.delivery.alertsDispatched, 0);
    channelId = undefined;
    await poller.checkLiveStreams();
    assert.equal(channelResolutionCache.get("42").channelId, "44");
  } finally {
    poller.close();
    clearChannelResolutionCache();
  }
});

test("poller health records token failures, partial upstream failures, and recovery", async () => {
  clearChannelResolutionCache();
  const store = createFcmStore();
  store.subscribe({ token: "health-token", channelIds: ["42", "unresolved"] });
  let failToken = true;
  let failSlug = false;
  let throwRequest = false;
  const poller = createLiveStreamPoller({
    fcmStore: store, messaging: {}, config: { kickClientId: "test", kickClientSecret: "test" },
    fetchFn: async url => {
      if (url.includes("/oauth/token")) return failToken ? jsonResponse(503, {})
        : jsonResponse(200, { access_token: "health-token", expires_in: 3600 });
      if (throwRequest) throw new Error("upstream unavailable");
      return failSlug && url.includes("slug=") ? jsonResponse(503, {}) : jsonResponse(200, { data: [] });
    },
  });
  try {
    assert.equal(poller.getStatus().lastSuccessAt, null);
    await poller.checkLiveStreams();
    assert.equal(poller.getStatus().lastErrorCode, "app_token_unavailable");
    assert.equal(poller.getStatus().lastSuccessAt, null);
    failToken = false;
    await poller.checkLiveStreams();
    assert.ok(poller.getStatus().lastSuccessAt);
    assert.equal(poller.getStatus().lastCycleSucceeded, true);
    const lastSuccess = poller.getStatus().lastSuccessAt;
    failSlug = true;
    await poller.checkLiveStreams();
    assert.equal(poller.getStatus().lastErrorCode, "upstream_http_503");
    assert.equal(poller.getStatus().lastSuccessAt, lastSuccess);
    assert.equal(poller.getStatus().failedCycles, 2);
    failSlug = false;
    await poller.checkLiveStreams();
    assert.equal(poller.getStatus().lastCycleSucceeded, true);
    assert.equal(poller.getStatus().lastErrorCode, "upstream_http_503");
    throwRequest = true;
    await poller.checkLiveStreams();
    assert.equal(poller.getStatus().lastErrorCode, "upstream_request_failed");
  } finally {
    poller.close();
    assert.equal(poller.getStatus().active, false);
  }
});

test("Pusher relay shares stream deduplication with webhook delivery", async () => {
  clearChannelResolutionCache();
  const fcmStore = createFcmStore({ dataFile: null });
  fcmStore.subscribe({ token: "pusher-shared-token", channelIds: ["42", "pusher-streamer"] });
  const seenStreams = new Map();
  let calls = 0;
  const messaging = {
    async sendEachForMulticast(payload) {
      calls++;
      return { successCount: payload.tokens.length, failureCount: 0, responses: payload.tokens.map(() => ({ success: true })) };
    },
  };
  const relay = createPusherRelay({ fcmStore, messaging, seenStreams });
  try {
    await handleWebhookLiveEvent({ eventType: "livestream.status.updated", fcmStore, messaging, seenStreams,
      payload: { broadcaster: { user_id: 42, channel_slug: "pusher-streamer" }, is_live: true, started_at: "2026-11-05T12:00:00Z" } });
    await relay.handleLiveEvent({ channel: "channel.44", data: { user_id: 42, path: "/pusher-streamer", start_time: "2026-11-05 12:00:00" } });
    assert.equal(calls, 1);
  } finally {
    relay.close();
  }
});

test("getKickPublicKey fetches and caches public key", async () => {
  clearKickPublicKeyCache();
  let fetchCount = 0;
  const mockFetch = async (url) => {
    fetchCount++;
    assert.ok(url.includes("/public/v1/public-key"));
    return {
      ok: true,
      json: async () => ({
        data: {
          public_key: "-----BEGIN PUBLIC KEY-----\nMOCK_KEY\n-----END PUBLIC KEY-----",
        },
        message: "OK",
      }),
    };
  };

  const key1 = await getKickPublicKey({ fetchFn: mockFetch });
  assert.equal(key1, "-----BEGIN PUBLIC KEY-----\nMOCK_KEY\n-----END PUBLIC KEY-----");
  assert.equal(fetchCount, 1);

  // Cached call
  const key2 = await getKickPublicKey({ fetchFn: mockFetch });
  assert.equal(key2, key1);
  assert.equal(fetchCount, 1);

  clearKickPublicKeyCache();
});

test("verifyKickWebhookSignature verifies RSA-SHA256 signature and rejects invalid/stale", () => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const pubPem = publicKey.export({ type: "spki", format: "pem" });

  const messageId = "msg_test_123";
  const now = Date.now();
  const timestamp = new Date(now).toISOString();
  const rawBody = JSON.stringify({ hello: "world" });

  const signer = createSign("RSA-SHA256");
  signer.update(`${messageId}.${timestamp}.${rawBody}`);
  const validSignature = signer.sign(privateKey, "base64");

  // 1. Valid signature
  assert.equal(
    verifyKickWebhookSignature({
      publicKey: pubPem,
      messageId,
      timestamp,
      signature: validSignature,
      rawBody,
      now,
    }),
    true
  );

  // 2. Tampered body
  assert.equal(
    verifyKickWebhookSignature({
      publicKey: pubPem,
      messageId,
      timestamp,
      signature: validSignature,
      rawBody: JSON.stringify({ hello: "tampered" }),
      now,
    }),
    false
  );

  // 3. Invalid signature
  assert.equal(
    verifyKickWebhookSignature({
      publicKey: pubPem,
      messageId,
      timestamp,
      signature: "aW52YWxpZA==",
      rawBody,
      now,
    }),
    false
  );

  // 4. Stale timestamp (10 minutes ago, default tolerance 5 minutes)
  assert.equal(
    verifyKickWebhookSignature({
      publicKey: pubPem,
      messageId,
      timestamp: new Date(now - 10 * 60 * 1000).toISOString(),
      signature: validSignature,
      rawBody,
      now,
    }),
    false
  );

  // 5. Missing headers/body
  assert.equal(
    verifyKickWebhookSignature({
      publicKey: pubPem,
      messageId: "",
      timestamp,
      signature: validSignature,
      rawBody,
    }),
    false
  );
});

test("handleWebhookLiveEvent dispatches notification and updates seenStreams", async () => {
  const fcmStore = createFcmStore();
  const token = "fcm-token-user-webhook-1234567890";
  fcmStore.subscribe({
    token,
    channelIds: ["131146", "dougthegiant"],
  });

  let sentPayload = null;
  const mockMessaging = {
    sendEachForMulticast: async (payload) => {
      sentPayload = payload;
      return { successCount: payload.tokens.length, failureCount: 0, responses: payload.tokens.map(() => ({ success: true })) };
    },
  };

  const seenStreams = new Map();

  // 1. Stream goes live
  const livePayload = {
    broadcaster: {
      user_id: 131146,
      username: "dougthegiant",
      channel_slug: "dougthegiant",
      profile_picture: "https://example.com/avatar.jpg",
    },
    is_live: true,
    title: "Awesome Live Stream",
    started_at: "2026-10-24T18:00:00Z",
  };

  const result1 = await handleWebhookLiveEvent({
    eventType: "livestream.status.updated",
    payload: livePayload,
    fcmStore,
    messaging: mockMessaging,
    seenStreams,
  });

  assert.equal(result1.ok, true);
  assert.equal(result1.is_live, true);
  assert.ok(sentPayload !== null);
  assert.deepEqual(sentPayload.tokens, [token]);
  assert.equal(sentPayload.data.channel_slug, "dougthegiant");
  assert.equal(sentPayload.data.title, "Awesome Live Stream");
  assert.equal(seenStreams.get("131146"), "2026-10-24T18:00:00Z");

  // 2. Duplicate live webhook (same started_at)
  sentPayload = null;
  const result2 = await handleWebhookLiveEvent({
    eventType: "livestream.status.updated",
    payload: livePayload,
    fcmStore,
    messaging: mockMessaging,
    seenStreams,
  });

  assert.equal(result2.ok, true);
  assert.equal(result2.duplicate, true);
  assert.equal(sentPayload, null, "Should not dispatch duplicate notification");

  // 3. Stream ends (is_live: false)
  const offlinePayload = {
    broadcaster: {
      user_id: 131146,
      channel_slug: "dougthegiant",
    },
    is_live: false,
  };

  const result3 = await handleWebhookLiveEvent({
    eventType: "livestream.status.updated",
    payload: offlinePayload,
    fcmStore,
    messaging: mockMessaging,
    seenStreams,
  });

  assert.equal(result3.ok, true);
  assert.equal(result3.is_live, false);
  assert.equal(seenStreams.has("131146"), false, "Stream pruned from seenStreams on offline");
});

test("POST /api/events/webhook and /v1/events/webhook validate signatures and handle live events", async () => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const pubPem = publicKey.export({ type: "spki", format: "pem" });

  clearKickPublicKeyCache();

  const fcmStore = createFcmStore();
  const token = "fcm-token-webhook-server-test-123456";
  fcmStore.subscribe({
    token,
    channelIds: ["999888", "gamerstreamer"],
  });

  let sentPayload = null;
  const mockMessaging = {
    sendEachForMulticast: async (payload) => {
      sentPayload = payload;
      return { successCount: payload.tokens.length, failureCount: 0, responses: payload.tokens.map(() => ({ success: true })) };
    },
  };

  const mockFetch = async (url) => {
    if (url.includes("/public/v1/public-key")) {
      return {
        ok: true,
        json: async () => ({
          data: { public_key: pubPem },
          message: "OK",
        }),
      };
    }
    return { ok: false, status: 404 };
  };

  const app = createApp(config(), {
    fetch: mockFetch,
    fcmStore,
    messaging: mockMessaging,
  });
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;

  try {
    // 1. Missing headers -> 400
    const res1 = await fetch(`http://127.0.0.1:${port}/api/events/webhook`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    assert.equal(res1.status, 400);
    assert.equal(app.locals.kickWebhookHandler.getStatus().lastReceivedAt, null);
    assert.equal(app.locals.kickWebhookHandler.getStatus().lastErrorCode, "missing_signature_headers");

    // 2. Invalid signature -> 401
    const res2 = await fetch(`http://127.0.0.1:${port}/api/events/webhook`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Kick-Event-Message-Id": "msg_invalid_sig",
        "Kick-Event-Message-Timestamp": new Date().toISOString(),
        "Kick-Event-Signature": "aW52YWxpZA==",
        "Kick-Event-Type": "livestream.status.updated",
      },
      body: JSON.stringify({}),
    });
    assert.equal(res2.status, 401);

    // 3. Valid signature -> 200 and dispatches push
    const messageId = "msg_valid_1";
    const timestamp = new Date().toISOString();
    const eventBody = JSON.stringify({
      broadcaster: {
        user_id: 999888,
        username: "gamerstreamer",
        channel_slug: "gamerstreamer",
        profile_picture: "https://example.com/pfp.jpg",
      },
      is_live: true,
      title: "Epic Gaming Live",
      started_at: "2026-10-24T18:30:00Z",
    });

    const signer = createSign("RSA-SHA256");
    signer.update(`${messageId}.${timestamp}.${eventBody}`);
    const signature = signer.sign(privateKey, "base64");

    const res3 = await fetch(`http://127.0.0.1:${port}/api/events/webhook`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Kick-Event-Message-Id": messageId,
        "Kick-Event-Message-Timestamp": timestamp,
        "Kick-Event-Signature": signature,
        "Kick-Event-Type": "livestream.status.updated",
      },
      body: eventBody,
    });
    assert.equal(res3.status, 200);
    const body3 = await res3.json();
    assert.equal(body3.ok, true);
    assert.ok(sentPayload !== null);
    assert.deepEqual(sentPayload.tokens, [token]);
    assert.equal(sentPayload.data.channel_slug, "gamerstreamer");

    // 4. Duplicate messageId replay -> 200 duplicate
    const res4 = await fetch(`http://127.0.0.1:${port}/api/events/webhook`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Kick-Event-Message-Id": messageId,
        "Kick-Event-Message-Timestamp": timestamp,
        "Kick-Event-Signature": signature,
        "Kick-Event-Type": "livestream.status.updated",
      },
      body: eventBody,
    });
    assert.equal(res4.status, 200);
    const body4 = await res4.json();
    assert.equal(body4.duplicate, true);

    // 5. Also works on /v1/events/webhook
    const msgV1Id = "msg_v1_test";
    const tsV1 = new Date().toISOString();
    const signerV1 = createSign("RSA-SHA256");
    signerV1.update(`${msgV1Id}.${tsV1}.${eventBody}`);
    const sigV1 = signerV1.sign(privateKey, "base64");

    const res5 = await fetch(`http://127.0.0.1:${port}/v1/events/webhook`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Kick-Event-Message-Id": msgV1Id,
        "Kick-Event-Message-Timestamp": tsV1,
        "Kick-Event-Signature": sigV1,
        "Kick-Event-Type": "livestream.status.updated",
      },
      body: eventBody,
    });
    assert.equal(res5.status, 200);
    const status = app.locals.kickWebhookHandler.getStatus();
    assert.equal(status.configured, true);
    assert.equal(status.verifiedEvents, 2);
    assert.equal(status.errors, 2);
    assert.equal(status.lastErrorCode, "invalid_signature");
    assert.ok(status.lastReceivedAt);
  } finally {
    server.close();
    clearKickPublicKeyCache();
  }
});

test("Webhook and Live Poller share seenStreams and prevent duplicate alerts", async () => {
  const fcmStore = createFcmStore();
  const token = "fcm-token-shared-dedup-12345";
  fcmStore.subscribe({
    token,
    channelIds: ["555444", "sharedstreamer"],
  });

  let notificationsCount = 0;
  const mockMessaging = {
    sendEachForMulticast: async (payload) => {
      notificationsCount++;
      return { successCount: payload.tokens.length, failureCount: 0, responses: payload.tokens.map(() => ({ success: true })) };
    },
  };

  const seenStreams = new Map();

  const mockFetch = async (url) => {
    if (url.includes("/oauth/token")) {
      return {
        ok: true,
        json: async () => ({ access_token: "mock-app-token", expires_in: 3600 }),
      };
    }
    if (url.includes("/public/v1/channels?")) {
      return {
        ok: true,
        json: async () => ({
          data: [
            {
              broadcaster_user_id: 555444,
              channel_id: 555444,
              slug: "sharedstreamer",
              stream: {
                is_live: true,
                start_time: "2026-10-24T19:00:00Z",
              },
            },
          ],
        }),
      };
    }
    return { ok: false, status: 404 };
  };

  const poller = createLiveStreamPoller({
    fcmStore,
    messaging: mockMessaging,
    config: { kickClientId: "cid", kickClientSecret: "csec" },
    fetchFn: mockFetch,
    seenStreams,
    pollIntervalMs: 60_000,
  });

  try {
    // 1. Webhook arrives FIRST when stream goes live
    await handleWebhookLiveEvent({
      eventType: "livestream.status.updated",
      payload: {
        broadcaster: { user_id: 555444, channel_slug: "sharedstreamer" },
        is_live: true,
        started_at: "2026-10-24T19:00:00Z",
      },
      fcmStore,
      messaging: mockMessaging,
      seenStreams,
    });

    assert.equal(notificationsCount, 1, "Webhook sent 1 notification");
    assert.equal(seenStreams.get("555444"), "2026-10-24T19:00:00Z");

    // 2. Poller runs after warmup: sees stream with same start_time, SKIPS notification
    await poller.checkLiveStreams(); // First poll warmup
    await poller.checkLiveStreams(); // Second poll regular check
    assert.equal(notificationsCount, 1, "Poller did NOT duplicate webhook notification!");
  } finally {
    poller.close();
  }
});

test("syncKickEventSubscriptions creates missing webhook subscriptions on Kick", async () => {
  const fcmStore = createFcmStore();
  fcmStore.subscribe({
    token: "tok1",
    channelIds: ["111222", "333444"],
  });

  const createdSubs = [];
  const existingSubs = [
    { broadcaster_user_id: 111222, event: "livestream.status.updated" },
  ];

  const mockFetch = async (url, options = {}) => {
    if (url.includes("/oauth/token")) {
      return {
        ok: true,
        json: async () => ({ access_token: "mock-app-token", expires_in: 3600 }),
      };
    }
    if (url.endsWith("/public/v1/events/subscriptions") && (!options.method || options.method === "GET")) {
      return {
        ok: true,
        json: async () => ({ data: existingSubs }),
      };
    }
    if (url.endsWith("/public/v1/events/subscriptions") && options.method === "POST") {
      const parsedBody = JSON.parse(options.body);
      createdSubs.push(parsedBody);
      return {
        ok: true,
        json: async () => ({
          data: {
            id: `sub_${parsedBody.broadcaster_user_id}`,
            ...parsedBody,
          },
        }),
      };
    }
    return { ok: false, status: 404 };
  };

  const result = await syncKickEventSubscriptions({
    fcmStore,
    fetchFn: mockFetch,
    clientId: "cid",
    clientSecret: "csec",
  });

  assert.equal(result.synced, 2);
  assert.equal(result.added, 1);
  assert.equal(createdSubs.length, 1);
  assert.equal(createdSubs[0].broadcaster_user_id, 333444);
  assert.equal(createdSubs[0].method, "webhook");
  assert.deepEqual(createdSubs[0].events, [{ name: "livestream.status.updated", version: 1 }]);
});

test("subscription sync preserves existing subscriptions when listing fails and can recover", async () => {
  clearChannelResolutionCache();
  for (const failure of [429, 503, "network", "invalid"]) {
    const store = createFcmStore();
    store.subscribe({ token: "sync-token", channelIds: ["42", "43"] });
    let recovering = false;
    let posts = 0;
    const options = {
      fcmStore: store, clientId: "test", clientSecret: "test", throttleMs: 0, retryDelayMs: 0,
      fetchFn: async (url, request = {}) => {
        if (url.includes("/oauth/token")) return jsonResponse(200, { access_token: "sync-token", expires_in: 3600 });
        if (request.method === "POST") {
          posts++;
          return jsonResponse(200, { data: [] });
        }
        if (recovering) return jsonResponse(200, { data: [{ broadcaster_user_id: 42, event: "livestream.status.updated" }] });
        if (failure === "network") throw new Error("network unavailable");
        if (failure === "invalid") return jsonResponse(200, {});
        return jsonResponse(failure, {});
      },
    };
    assert.deepEqual(await syncKickEventSubscriptions(options), { synced: 0, added: 0, retryAfterMs: 60000 });
    assert.equal(posts, 0, `Listing failure ${failure} must not recreate existing subscriptions`);
    recovering = true;
    assert.equal((await syncKickEventSubscriptions(options)).added, 1);
    assert.equal(posts, 1);
  }
});

test("subscription sync stops the batch after persistent rate limiting", async () => {
  clearChannelResolutionCache();
  const store = createFcmStore();
  store.subscribe({ token: "rate-limit-token", channelIds: ["42", "43", "44"] });
  let posts = 0;
  const result = await syncKickEventSubscriptions({
    fcmStore: store, clientId: "test", clientSecret: "test", throttleMs: 0, retryDelayMs: 0,
    fetchFn: async (url, request = {}) => {
      if (url.includes("/oauth/token")) return jsonResponse(200, { access_token: "sync-token", expires_in: 3600 });
      if (request.method !== "POST") return jsonResponse(200, { data: [] });
      posts++;
      return jsonResponse(429, {});
    },
  });
  assert.equal(result.added, 0);
  assert.equal(posts, 2, "Retry once, then stop without attempting the remaining streamers");
});

test("syncKickEventSubscriptions retries on 429 rate limit and succeeds", async () => {
  clearChannelResolutionCache();
  const fcmStore = createFcmStore();
  fcmStore.subscribe({
    token: "tok2",
    channelIds: ["999888"],
  });

  let postAttempts = 0;
  const mockFetch = async (url, options = {}) => {
    if (url.includes("/oauth/token")) {
      return {
        ok: true,
        json: async () => ({ access_token: "mock-app-token", expires_in: 3600 }),
      };
    }
    if (url.endsWith("/public/v1/events/subscriptions") && (!options.method || options.method === "GET")) {
      return {
        ok: true,
        json: async () => ({ data: [] }),
      };
    }
    if (url.endsWith("/public/v1/events/subscriptions") && options.method === "POST") {
      postAttempts++;
      if (postAttempts === 1) {
        return { ok: false, status: 429, body: { message: "Too Many Requests" } };
      }
      const parsedBody = JSON.parse(options.body);
      return {
        ok: true,
        json: async () => ({
          data: {
            id: `sub_${parsedBody.broadcaster_user_id}`,
            ...parsedBody,
          },
        }),
      };
    }
    return { ok: false, status: 404 };
  };

  const result = await syncKickEventSubscriptions({
    fcmStore,
    fetchFn: mockFetch,
    clientId: "cid",
    clientSecret: "csec",
    throttleMs: 0,
    retryDelayMs: 5,
  });

  assert.equal(result.synced, 1);
  assert.equal(result.added, 1);
  assert.equal(postAttempts, 2);
});

test("subscription scheduler honors server cooldown and includes channels added while waiting", async t => {
  clearChannelResolutionCache();
  t.mock.timers.enable({ apis: ["setTimeout", "Date"], now: Date.now() });
  const store = createFcmStore();
  store.subscribe({ token: "scheduled-token", channelIds: ["42"] });
  let blocked = true;
  let listings = 0;
  const posts = [];
  const options = {
    fcmStore: store, clientId: "test", clientSecret: "test", throttleMs: 0,
    fetchFn: async (url, request = {}) => {
      if (url.includes("/oauth/token")) return jsonResponse(200, { access_token: "test", expires_in: 3600 });
      if (request.method === "POST") {
        posts.push(JSON.parse(request.body).broadcaster_user_id);
        return jsonResponse(200, {});
      }
      listings++;
      return blocked ? new Response("", { status: 429, headers: { "Retry-After": "120" } })
        : jsonResponse(200, { data: [{ broadcaster_user_id: 42, event: "livestream.status.updated" }] });
    },
  };
  assert.equal((await scheduleKickSubscriptionSync(options)).retryAfterMs, 120000);
  store.subscribe({ token: "scheduled-token", channelIds: ["42", "43"] });
  for (let i = 0; i < 10; i++) await scheduleKickSubscriptionSync(options);
  assert.equal(listings, 1);
  assert.equal(posts.length, 0);
  blocked = false;
  t.mock.timers.tick(119999);
  await settle();
  assert.equal(listings, 1);
  t.mock.timers.tick(1);
  await settle();
  assert.equal(listings, 2);
  assert.deepEqual(posts, [43]);
  t.mock.timers.tick(3600000);
  await settle();
  assert.equal(listings, 2, "Successful sync cancels further retries");
});

test("subscription scheduler backs off repeated failures, caps the delay, and resets after recovery", async t => {
  clearChannelResolutionCache();
  t.mock.timers.enable({ apis: ["setTimeout", "Date"], now: Date.now() });
  const store = createFcmStore();
  store.subscribe({ token: "backoff-token", channelIds: ["42"] });
  let listings = 0;
  let blocked = true;
  const delays = [];
  const options = {
    fcmStore: store, clientId: "test", clientSecret: "test",
    logger: {
      info() {},
      warn: (details, msg) => { if (msg === "kick_webhook_sync_retry_scheduled") delays.push(details.delayMs); },
    },
    fetchFn: async url => {
      if (url.includes("/oauth/token")) return jsonResponse(200, { access_token: "test", expires_in: 36000 });
      listings++;
      return blocked ? jsonResponse(503, {})
        : jsonResponse(200, { data: [{ broadcaster_user_id: 42, event: "livestream.status.updated" }] });
    },
  };
  await scheduleKickSubscriptionSync(options);
  for (const delay of [60000, 120000, 240000, 480000, 900000]) {
    const before = listings;
    t.mock.timers.tick(delay - 1);
    await settle();
    assert.equal(listings, before);
    t.mock.timers.tick(1);
    await settle();
    assert.equal(listings, before + 1);
  }
  assert.deepEqual(delays, [60000, 120000, 240000, 480000, 900000, 900000]);
  blocked = false;
  t.mock.timers.tick(900000);
  await settle();
  blocked = true;
  await scheduleKickSubscriptionSync(options);
  assert.equal(delays.at(-1), 60000);
});

test("subscription scheduler resumes partial progress without recreating successful subscriptions", async t => {
  clearChannelResolutionCache();
  t.mock.timers.enable({ apis: ["setTimeout", "Date"], now: Math.floor(Date.now() / 1000) * 1000 });
  const store = createFcmStore();
  store.subscribe({ token: "partial-token", channelIds: ["42", "43"] });
  const registered = new Set();
  const posts = [];
  let blocked = true;
  const options = {
    fcmStore: store, clientId: "test", clientSecret: "test", throttleMs: 0,
    fetchFn: async (url, request = {}) => {
      if (url.includes("/oauth/token")) return jsonResponse(200, { access_token: "test", expires_in: 3600 });
      if (request.method !== "POST") return jsonResponse(200, {
        data: [...registered].map(id => ({ broadcaster_user_id: id, event: "livestream.status.updated" })),
      });
      const id = JSON.parse(request.body).broadcaster_user_id;
      posts.push(id);
      if (id === 43 && blocked) return new Response("", {
        status: 429, headers: { "Retry-After": new Date(Date.now() + 180000).toUTCString() },
      });
      registered.add(id);
      return jsonResponse(200, {});
    },
  };
  const first = await scheduleKickSubscriptionSync(options);
  assert.equal(first.added, 1);
  assert.equal(first.retryAfterMs, 180000);
  assert.deepEqual(posts, [42, 43], "Server cooldown prevents the immediate retry too");
  store.subscribe({ token: "partial-token", channelIds: ["42", "43", "44"] });
  blocked = false;
  t.mock.timers.tick(180000);
  await settle();
  assert.deepEqual(posts, [42, 43, 43, 44]);
  assert.equal(registered.size, 3);
});

test("subscription scheduler coalesces an active sync and preserves cooldown for queued requests", async t => {
  clearChannelResolutionCache();
  t.mock.timers.enable({ apis: ["setTimeout", "Date"], now: Date.now() });
  const store = createFcmStore();
  store.subscribe({ token: "overlap-sync-token", channelIds: ["42"] });
  let release;
  let listings = 0;
  const options = {
    fcmStore: store, clientId: "test", clientSecret: "test",
    fetchFn: async url => {
      if (url.includes("/oauth/token")) return jsonResponse(200, { access_token: "test", expires_in: 3600 });
      if (++listings === 1) return new Promise(resolve => { release = resolve; });
      return jsonResponse(200, { data: [{ broadcaster_user_id: 42, event: "livestream.status.updated" }] });
    },
  };
  const first = scheduleKickSubscriptionSync(options);
  await settle();
  assert.equal(scheduleKickSubscriptionSync(options), first);
  release(new Response("", { status: 429, headers: { "Retry-After": "90" } }));
  await first;
  await settle();
  assert.equal(listings, 1, "Queued requests cannot bypass the cooldown");
  t.mock.timers.tick(90000);
  await settle();
  assert.equal(listings, 2);
});

test("subscription scheduler follows successful active runs with fresh subscriptions and isolates stores", async () => {
  clearChannelResolutionCache();
  const firstStore = createFcmStore();
  firstStore.subscribe({ token: "first-store", channelIds: ["42"] });
  const secondStore = createFcmStore();
  secondStore.subscribe({ token: "second-store", channelIds: ["99"] });
  let release;
  let listings = 0;
  const registered = new Set();
  const posts = [];
  const firstOptions = {
    fcmStore: firstStore, clientId: "test", clientSecret: "test", throttleMs: 0,
    fetchFn: async (url, request = {}) => {
      if (url.includes("/oauth/token")) return jsonResponse(200, { access_token: "test", expires_in: 3600 });
      if (request.method !== "POST") {
        if (++listings === 1) return new Promise(resolve => { release = resolve; });
        return jsonResponse(200, { data: [...registered].map(id => ({ broadcaster_user_id: id, event: "livestream.status.updated" })) });
      }
      const id = JSON.parse(request.body).broadcaster_user_id;
      posts.push(id);
      registered.add(id);
      return jsonResponse(200, {});
    },
  };
  const first = scheduleKickSubscriptionSync(firstOptions);
  await settle();
  const second = await scheduleKickSubscriptionSync({
    fcmStore: secondStore, clientId: "test", clientSecret: "test",
    fetchFn: async () => jsonResponse(200, { data: [{ broadcaster_user_id: 99, event: "livestream.status.updated" }] }),
  });
  assert.equal(second.synced, 1, "An unrelated store is not blocked by an in-flight sync");
  firstStore.subscribe({ token: "first-store", channelIds: ["42", "43"] });
  assert.equal(scheduleKickSubscriptionSync(firstOptions), first);
  release(jsonResponse(200, { data: [] }));
  await first;
  await settle();
  assert.equal(listings, 2);
  assert.deepEqual(posts, [42, 43]);
});

test("subscription scheduler retries transient failures but does not loop on permanent errors", async t => {
  t.mock.timers.enable({ apis: ["setTimeout", "Date"], now: Date.now() });
  for (const failure of ["token", "network", "invalid", "post-network", "post-503", 503, 401, 403, 404, "post-400"]) {
    clearChannelResolutionCache();
    const store = createFcmStore();
    store.subscribe({ token: "failure-token", channelIds: ["42"] });
    let failing = true;
    let created = 0;
    let requests = 0;
    const options = {
      fcmStore: store, clientId: "test", clientSecret: "test", throttleMs: 0,
      fetchFn: async (url, request = {}) => {
        requests++;
        if (url.includes("/oauth/token")) return failing && failure === "token" ? jsonResponse(503, {})
          : jsonResponse(200, { access_token: "test", expires_in: 3600 });
        if (request.method === "POST") {
          if (failing && failure === "post-network") throw new Error("network unavailable");
          if (failing && failure === "post-503") return jsonResponse(503, {});
          if (failing && failure === "post-400") return jsonResponse(400, {});
          created++;
          return jsonResponse(200, {});
        }
        if (failing && failure === "network") throw new Error("network unavailable");
        if (failing && failure === "invalid") return jsonResponse(200, {});
        if (failing && typeof failure === "number") return jsonResponse(failure, {});
        return jsonResponse(200, { data: [] });
      },
    };
    const result = await scheduleKickSubscriptionSync(options);
    const transient = ![401, 403, 404, "post-400"].includes(failure);
    assert.equal(Boolean(result.retryAfterMs), transient, String(failure));
    const before = requests;
    failing = false;
    t.mock.timers.tick(60000);
    await settle();
    assert.equal(created, transient ? 1 : 0, String(failure));
    if (!transient) assert.equal(requests, before);
  }
});

test("subscription Retry-After values are bounded and malformed values use the default delay", async () => {
  clearChannelResolutionCache();
  const store = createFcmStore();
  store.subscribe({ token: "header-token", channelIds: ["42"] });
  for (const [header, expected] of [["garbage", 60000], ["0", 60000], ["-5", 60000], ["2592000", 86400000]]) {
    const result = await syncKickEventSubscriptions({
      fcmStore: store, clientId: "test", clientSecret: "test",
      fetchFn: async url => url.includes("/oauth/token")
        ? jsonResponse(200, { access_token: "test", expires_in: 3600 })
        : new Response("", { status: 429, headers: { "Retry-After": header } }),
    });
    assert.equal(result.retryAfterMs, expected, header);
  }
});

test("ping accepts pe, c, wt and reflects player engines, watch time, and crashes in stats", async () => {
  const store = createMetricsStore({ salt: "salt-test-fleet" });
  const pid1 = "1111111111111111111111111111111111111111111111111111111111111111";
  const pid2 = "2222222222222222222222222222222222222222222222222222222222222222";
  const now = new Date();

  store.recordPing({
    pidHash: store.hashPid(pid1),
    version: "2.55.0",
    clientEpoch: `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, "0")}`,
    pe: "ivs",
    c: 2,
    wt: "3",
  }, now);

  store.recordPing({
    pidHash: store.hashPid(pid2),
    version: "2.55.0",
    clientEpoch: `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, "0")}`,
    pe: "exo",
    c: 0,
    wt: "2",
  }, now);

  const stats = store.computeStats(now);
  const ivs = stats.playerEngines.find((p) => p.code === "ivs");
  const exo = stats.playerEngines.find((p) => p.code === "exo");
  assert.equal(ivs.count, 1);
  assert.equal(exo.count, 1);

  const wt3 = stats.watchTime.find((w) => w.code === "3");
  const wt2 = stats.watchTime.find((w) => w.code === "2");
  assert.equal(wt3.count, 1);
  assert.equal(wt2.count, 1);

  assert.equal(stats.counters.today.crashes?.total, 2);
});

test("watch time labels match the buckets sent by released Android clients", () => {
  const store = createMetricsStore({ salt: "watch-buckets" });
  for (const code of ["0", "1", "2", "3"]) {
    store.recordPing({ pidHash: code.repeat(64), version: "2.55.0", wt: code });
  }
  assert.deepEqual(store.computeStats().watchTime, [
    { code: "0", label: "< 15 min", count: 1 },
    { code: "1", label: "15 min – 1 hr", count: 1 },
    { code: "2", label: "1 hr – 3 hr", count: 1 },
    { code: "3", label: "3 hr or more", count: 1 },
  ]);
  store.close();
});

test("upstream latency percentiles compute correctly", () => {
  const store = createMetricsStore({ salt: "salt-lat-test" });
  for (let i = 1; i <= 100; i++) {
    store.recordUpstreamLatency(i * 10);
  }
  const stats = store.computeStats(new Date());
  assert.equal(stats.upstreamLatency.count, 100);
  assert.equal(stats.upstreamLatency.p50, 510);
  assert.equal(stats.upstreamLatency.p95, 960);
  assert.equal(stats.upstreamLatency.max, 1000);
});

test("telemetry coverage calculates ratio of ping accounts vs oauth accounts", () => {
  const store = createMetricsStore({ salt: "salt-cov-test" });
  const now = new Date();
  const epoch = `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, "0")}`;

  // 4 OAuth accounts
  store.recordAccount({ sub: "user-1" }, now);
  store.recordAccount({ sub: "user-2" }, now);
  store.recordAccount({ sub: "user-3" }, now);
  store.recordAccount({ sub: "user-4" }, now);

  // 3 of them also ping
  store.recordPing({
    pidHash: store.hashPid("3333333333333333333333333333333333333333333333333333333333333333"),
    version: "2.55.0",
    clientEpoch: epoch,
    accountAid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  }, now);
  store.recordPing({
    pidHash: store.hashPid("4444444444444444444444444444444444444444444444444444444444444444"),
    version: "2.55.0",
    clientEpoch: epoch,
    accountAid: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  }, now);
  store.recordPing({
    pidHash: store.hashPid("5555555555555555555555555555555555555555555555555555555555555555"),
    version: "2.55.0",
    clientEpoch: epoch,
    accountAid: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  }, now);

  const stats = store.computeStats(now);
  assert.equal(stats.accountsMau, 4);
  assert.equal(stats.pingAccountsMau, 3);
  assert.equal(stats.telemetryCoverage, 0.75);
});

function makeCrashReport(overrides = {}) {
  return {
    id: "12345678-1234-4234-8234-123456789abc",
    version: "2.54.0",
    build: 25400,
    sdk: 35,
    abi: "arm64-v8a",
    liveEnginePreference: "ivs",
    crashedAt: Date.now(),
    exceptions: [{ type: "java.lang.IllegalStateException", frames: [
      { class: "com.xtrakick.app.Example", method: "play", file: "Example.kt", line: 42 },
    ] }],
    ...overrides,
  };
}

test("crash endpoint requires HMAC, rejects private fields, deduplicates, and protects details", async () => {
  const secret = "crash-test-secret";
  const { app, store } = appWithMetrics(async () => jsonResponse(200, {}), { APP_HMAC_SECRET: secret });
  const path = "/v1/metrics/crash";
  const report = makeCrashReport();
  await withServer(app, async baseUrl => {
    assert.equal((await httpRequest(baseUrl, "POST", path, report)).status, 401);
    const invalid = { ...report, message: "Bearer private-token" };
    const rejected = await httpRequest(baseUrl, "POST", path, invalid, {
      headers: signedHeaders({ secret, method: "POST", path, bodyObject: invalid }),
    });
    assert.equal(rejected.status, 400);
    assert.ok(!JSON.stringify(rejected.body).includes("private-token"));
    for (let i = 0; i < 2; i++) {
      assert.equal((await httpRequest(baseUrl, "POST", path, report, {
        headers: signedHeaders({ secret, method: "POST", path, bodyObject: report }),
      })).status, 204);
    }
    assert.equal((await httpRequest(baseUrl, "GET", "/v1/metrics/stats")).status, 401);
    const stats = await httpRequest(baseUrl, "GET", "/v1/metrics/stats", undefined, {
      headers: { Authorization: "Bearer admin-secret" },
    });
    assert.equal(stats.status, 200);
    assert.equal(stats.headers["cache-control"], "no-store");
    assert.equal(stats.body.crashReports.length, 1);
    assert.equal(stats.body.crashReports[0].count, 1);
    assert.equal(stats.body.crashReports[0].exceptions[0].frames[0].line, 42);
    assert.equal(stats.body.crashReports[0].id, undefined);
    assert.deepEqual(stats.body.counters.today.endpoints[`POST ${path}`], { hmac: 1, r4: 2, ok: 2 });
  });
  store.close();
  app.locals.crashReports.close();
});

test("crash upload stays disabled without signing even in unauthenticated development mode", async () => {
  const { app, store } = appWithMetrics(async () => jsonResponse(200, {}));
  const response = await withServer(app, baseUrl => httpRequest(baseUrl, "POST", "/v1/metrics/crash", makeCrashReport()));
  assert.equal(response.status, 401);
  store.close();
  app.locals.crashReports.close();
});

test("crash dismissal route requires admin, validates, and hides a group until it recurs", async () => {
  const secret = "crash-test-secret";
  const { app, store } = appWithMetrics(async () => jsonResponse(200, {}), { APP_HMAC_SECRET: secret });
  const path = "/v1/metrics/crash";
  const report = makeCrashReport();
  await withServer(app, async baseUrl => {
    assert.equal((await httpRequest(baseUrl, "POST", path, report, {
      headers: signedHeaders({ secret, method: "POST", path, bodyObject: report }),
    })).status, 204);
    const auth = { headers: { Authorization: "Bearer admin-secret" } };
    assert.equal((await httpRequest(baseUrl, "POST", "/v1/metrics/crash/dismiss", { signature: "abc" })).status, 401);
    assert.equal((await httpRequest(baseUrl, "POST", "/v1/metrics/crash/dismiss", { signature: "abc" }, auth)).status, 400);
    const statsBefore = await httpRequest(baseUrl, "GET", "/v1/metrics/stats", undefined, auth);
    assert.equal(statsBefore.status, 200);
    assert.equal(statsBefore.body.crashReportsHidden, 0);
    const signature = statsBefore.body.crashReports[0].signature;
    assert.equal((await httpRequest(baseUrl, "POST", "/v1/metrics/crash/dismiss", { signature }, auth)).status, 204);
    const statsHidden = await httpRequest(baseUrl, "GET", "/v1/metrics/stats", undefined, auth);
    assert.deepEqual(statsHidden.body.crashReports, []);
    assert.equal(statsHidden.body.crashReportsHidden, 1);
    const recurring = { ...report, id: "22345678-1234-4234-8234-123456789abc", crashedAt: Date.now() + 5 };
    assert.equal((await httpRequest(baseUrl, "POST", path, recurring, {
      headers: signedHeaders({ secret, method: "POST", path, bodyObject: recurring }),
    })).status, 204);
    const statsAgain = await httpRequest(baseUrl, "GET", "/v1/metrics/stats", undefined, auth);
    assert.equal(statsAgain.body.crashReports.length, 1);
    assert.equal(statsAgain.body.crashReportsHidden, 0);
  });
  store.close();
  app.locals.crashReports.close();
});

test("crash schema rejects unknown fields, unsafe frames, and unbounded traces", () => {
  for (const report of [
    makeCrashReport({ pid: "user-id" }),
    makeCrashReport({ abi: "device-identifier" }),
    makeCrashReport({ liveEnginePreference: "https://private.example" }),
    makeCrashReport({ exceptions: [{ type: "Error", extra: "secret", frames: [] }] }),
    makeCrashReport({ exceptions: [{ type: "Error", message: "", frames: [] }] }),
    makeCrashReport({ exceptions: [{ type: "Error", message: "line1\nline2", frames: [] }] }),
    makeCrashReport({ exceptions: [{ type: "Error", message: "a".repeat(201), frames: [] }] }),
    makeCrashReport({ exceptions: [{ type: "<script>alert(1)</script>", frames: [] }] }),
    makeCrashReport({ exceptions: [{ type: "Error", frames: Array(33).fill(makeCrashReport().exceptions[0].frames[0]) }] }),
    makeCrashReport({ exceptions: Array(9).fill({ type: "Error", frames: [] }) }),
  ]) assert.equal(crashReportSchema.safeParse(report).success, false);
});

test("crash schema accepts optional exception message and groups across differing messages", () => {
  const base = makeCrashReport();
  const first = makeCrashReport({
    id: "22345678-1234-4234-8234-123456789abc",
    exceptions: [{ ...base.exceptions[0], message: "Failed resolution of: Landroid/net/http/HttpEngine;" }],
  });
  const second = makeCrashReport({
    id: "32345678-1234-4234-8234-123456789abc",
    exceptions: [{ ...base.exceptions[0], message: "a".repeat(200) }],
  });
  assert.equal(crashReportSchema.safeParse(first).success, true);
  assert.equal(crashReportSchema.safeParse(second).success, true);

  const store = createCrashReportStore();
  try {
    const t0 = Date.now();
    store.record(base, t0);
    const sigWithoutMsg = store.list(t0)[0].signature;
    store.record(first, t0 + 1);
    store.record(second, t0 + 2);
    const listed = store.list(t0 + 2);
    assert.equal(listed.length, 1);
    assert.equal(listed[0].signature, sigWithoutMsg);
    assert.equal(listed[0].count, 3);
    assert.equal(listed[0].exceptions[0].message, "a".repeat(200));
  } finally {
    store.close();
  }
});

test("crash store persists retries, groups occurrences, and expires data on disk", () => {
  const dir = mkdtempSync(join(tmpdir(), "crash-reports-"));
  const dataPath = join(dir, "crashes.json");
  const now = Date.now();
  let store;
  try {
    store = createCrashReportStore({ dataPath });
    const report = makeCrashReport({ crashedAt: now });
    store.record(report, now);
    store.close();
    store = createCrashReportStore({ dataPath });
    store.record(report, now + 1);
    assert.equal(store.list(now + 1)[0].count, 1);
    store.record(makeCrashReport({ id: "22345678-1234-4234-8234-123456789abc", crashedAt: now + 2 }), now + 2);
    assert.equal(store.list(now + 2)[0].count, 2);
    // Counts and firstSeen must age out even when a signature keeps recurring.
    assert.equal(store.list(now + CRASH_RETENTION_MS + 1)[0].count, 1);
    assert.equal(store.list(now + CRASH_RETENTION_MS + 1)[0].firstSeen, now + 2);
    assert.deepEqual(store.list(now + CRASH_RETENTION_MS + 3), []);
    store.close();
    store = createCrashReportStore({ dataPath });
    assert.deepEqual(store.list(), []);
  } finally {
    store?.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("crash dismissals persist across restarts and reappear when the crash recurs", () => {
  const dir = mkdtempSync(join(tmpdir(), "crash-reports-"));
  const dataPath = join(dir, "crashes.json");
  const now = Date.now();
  let store;
  try {
    store = createCrashReportStore({ dataPath });
    store.record(makeCrashReport({ crashedAt: now }), now);
    const signature = store.list(now)[0].signature;
    store.dismiss(signature, now + 10);
    assert.deepEqual(store.list(now + 10), []);
    assert.equal(store.count(now + 10), 1);
    store.close();
    store = createCrashReportStore({ dataPath });
    assert.deepEqual(store.list(now + 20), []);
    // A recurring crash of the same signature bumps lastSeen past the dismissal.
    store.record(makeCrashReport({ id: "22345678-1234-4234-8234-123456789abc", crashedAt: now + 30 }), now + 30);
    const visible = store.list(now + 30);
    assert.equal(visible.length, 1);
    assert.equal(visible[0].count, 2);
  } finally {
    store?.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("crash storage caps groups and keeps deduplication IDs for evicted groups", () => {
  const store = createCrashReportStore();
  const now = Date.now();
  try {
    for (let i = 0; i <= MAX_CRASH_GROUPS; i++) {
      store.record(makeCrashReport({
        id: `${i.toString(16).padStart(8, "0")}-1234-4234-8234-123456789abc`,
        build: i + 1,
        crashedAt: now,
      }), now);
    }
    assert.equal(store.list(now).length, MAX_CRASH_GROUPS);
    // Old IDs still deduplicate even if their group has been evicted.
    store.record(makeCrashReport({ id: "00000000-1234-4234-8234-123456789abc", build: 1 }), now);
    assert.equal(store.list(now).length, MAX_CRASH_GROUPS);
  } finally { store.close(); }
});

test("crash retry capacity rejects new IDs without losing existing retry deduplication", () => {
  const dir = mkdtempSync(join(tmpdir(), "crash-capacity-"));
  const dataPath = join(dir, "crashes.json");
  const now = Date.now();
  const events = Array.from({ length: MAX_CRASH_EVENTS }, (_, i) => ({
    id: `${i.toString(16).padStart(8, "0")}-1234-4234-8234-123456789abc`,
    signature: "a".repeat(64), receivedAt: now,
  }));
  writeFileSync(dataPath, JSON.stringify({ reports: [], events }));
  const store = createCrashReportStore({ dataPath });
  try {
    assert.throws(() => store.record(makeCrashReport(), now), error => error.status === 429);
    store.record(makeCrashReport({ id: events[0].id }), now);
    assert.deepEqual(store.list(now), []);
    const later = now + CRASH_RETENTION_MS + 1;
    store.record(makeCrashReport({ crashedAt: later }), later);
    assert.equal(store.list(later)[0].count, 1);
  } finally {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("expired and future-dated crash reports are discarded", () => {
  const store = createCrashReportStore();
  const now = Date.now();
  store.record(makeCrashReport({ crashedAt: now - CRASH_RETENTION_MS }), now);
  store.record(makeCrashReport({ crashedAt: now + 300_001 }), now);
  assert.deepEqual(store.list(now), []);
  store.close();
});

test("crash details last 90 days and older clients get unknown technical context", () => {
  assert.equal(CRASH_RETENTION_MS, 90 * 86_400_000);
  const legacy = makeCrashReport();
  delete legacy.abi;
  delete legacy.liveEnginePreference;
  const parsed = crashReportSchema.parse(legacy);
  assert.equal(parsed.abi, "unknown");
  assert.equal(parsed.liveEnginePreference, "unknown");
  const store = createCrashReportStore();
  const now = Date.now();
  const sixtyDaysAgo = now - 60 * 86_400_000;
  store.record({ ...parsed, crashedAt: sixtyDaysAgo }, sixtyDaysAgo);
  assert.equal(store.list(now).length, 1);
  store.close();
});

test("crash requests never enter access logs, including rejected and failed uploads", async () => {
  const logs = [];
  const cfg = loadConfig(metricsEnv({ APP_HMAC_SECRET: "crash-test-secret", TRUST_PROXY: "loopback" }));
  cfg.logger = pino({ level: "info" }, { write(line) { logs.push(JSON.parse(line)); } });
  const metrics = createMetricsStore({ salt: "s" });
  const crashReports = createCrashReportStore();
  const app = createApp(cfg, { metrics, crashReports });
  const path = "/V1/METRICS/CRASH/?private-query=private-query-value";
  const headers = {
    "X-Forwarded-For": "203.0.113.42", "X-Real-IP": "203.0.113.42",
    "User-Agent": "private-user-agent", Cookie: "account=private-cookie",
    Authorization: "Bearer private-authorization", "X-Request-ID": "private-request-id",
  };
  const send = (baseUrl, report) => httpRequest(baseUrl, "POST", path, report, { headers: {
    ...headers, ...signedHeaders({ secret: cfg.appHmacSecret, method: "POST", path, bodyObject: report }),
  } });
  try {
    await withServer(app, async baseUrl => {
      await httpRequest(baseUrl, "GET", "/healthz");
      assert.ok(logs.some(log => log.req?.url === "/healthz"), "Normal endpoint logging stays enabled");
      logs.length = 0;
      assert.equal((await httpRequest(baseUrl, "POST", path, makeCrashReport(), { headers })).status, 401);
      assert.equal((await send(baseUrl, makeCrashReport())).status, 204);
      assert.equal((await send(baseUrl, makeCrashReport({ message: "private-message" }))).status, 400);
      const malformed = await fetch(baseUrl + path, { method: "POST", headers: { ...headers, "Content-Type": "application/json" }, body: "{private-message" });
      assert.equal(malformed.status, 400);
      await malformed.text();
      const oversized = await httpRequest(baseUrl, "POST", path, { message: "private-message".repeat(4000) }, { headers });
      assert.equal(oversized.status, 413);
      crashReports.record = () => { throw new Error("private-storage-error"); };
      assert.equal((await send(baseUrl, makeCrashReport())).status, 503);
      let response;
      for (let i = 0; i < 4; i++) response = await send(baseUrl, makeCrashReport());
      assert.equal(response.status, 429);
      const unexpected = await fetch(baseUrl + path, { method: "POST", headers: {
        ...headers, "Content-Type": "application/json; charset=private-charset",
      }, body: "{}" });
      assert.equal(unexpected.status, 500);
      await unexpected.text();
    });
    assert.equal(logs.length, 1);
    assert.equal(logs[0].code, "crash_request_failed");
    assert.equal(logs[0].req, undefined);
    assert.equal(logs[0].err, undefined);
    assert.doesNotMatch(JSON.stringify(logs), /private-|203\.0\.113\.42|remoteAddress|forwarded/i);
    assert.ok(metrics.computeStats().counters.today.endpoints["OTHER / 404"]);
  } finally {
    metrics.close();
    crashReports.close();
  }
});

test("failed crash persistence does not consume the retry ID or count", () => {
  const dir = mkdtempSync(join(tmpdir(), "crash-disk-failure-"));
  const blocked = join(dir, "blocked");
  writeFileSync(blocked, "not a directory");
  const store = createCrashReportStore({ dataPath: join(blocked, "crashes.json") });
  try {
    const report = makeCrashReport();
    assert.throws(() => store.record(report));
    assert.deepEqual(store.list(), []);
    rmSync(blocked);
    store.record(report);
    assert.equal(store.list()[0].count, 1);
  } finally {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("corrupt crash storage preserves its file and does not take down other telemetry", async () => {
  const dir = mkdtempSync(join(tmpdir(), "crash-corrupt-"));
  const dataPath = join(dir, "crashes.json");
  writeFileSync(dataPath, "corrupt data");
  const crashes = createCrashReportStore({ dataPath });
  const metrics = createMetricsStore({ salt: "s" });
  const cfg = loadConfig(metricsEnv({ APP_HMAC_SECRET: "crash-test-secret" }));
  try {
    assert.throws(() => crashes.record(makeCrashReport()));
    assert.throws(() => crashes.list());
    assert.equal(readFileSync(dataPath, "utf8"), "corrupt data");
    const app = createApp(cfg, { metrics, crashReports: crashes });
    const response = await withServer(app, baseUrl => httpRequest(baseUrl, "GET", "/v1/metrics/stats", undefined, {
      headers: { Authorization: "Bearer admin-secret" },
    }));
    assert.equal(response.status, 200);
    assert.equal(response.body.crashReportsUnavailable, true);
    assert.equal(response.body.totalInstalls, 0);
  } finally {
    crashes.close();
    metrics.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("dashboard crash details render untrusted strings only as text", () => {
  const html = readFileSync(new URL("./dashboard.html", import.meta.url), "utf8");
  new Script(html.match(/<script>([\s\S]*?)<\/script>/)[1]);
  function node() {
    return {
      children: [], style: {}, textContent: "",
      append(...children) { this.children.push(...children); },
      set innerHTML(_value) { throw new Error("Crash details must use textContent"); },
    };
  }
  const container = node();
  const document = { getElementById: () => container, createElement: node };
  const start = html.indexOf("function showCrashReports(");
  const end = html.indexOf("function renderEndpointHealthTable(", start);
  const render = runInNewContext(html.slice(start, end) + ";showCrashReports", { document });
  const report = makeCrashReport();
  report.exceptions[0].type = "<script>throw new Error('injection')</script>";
  report.exceptions[0].message = "<img src=x onerror=alert(1)>";
  const receivedAt = Date.UTC(2026, 10, 15, 14, 49, 18);
  render([{ ...report, count: 1, lastSeen: receivedAt }]);
  const details = container.children[1];
  assert.match(details.children[0].textContent, /<script>/);
  const received = details.children[0].children[0];
  assert.equal(received.textContent, `Last received: ${new Date(receivedAt).toLocaleString(undefined, { timeZoneName: "short" })}`);
  assert.match(received.style.cssText, /display:block/);
  assert.match(details.children[2].textContent, /: <img src=x onerror=alert\(1\)>/);
  assert.match(details.children[2].textContent, /Example\.kt:42/);
  render([]);
  assert.match(container.children.at(-1).textContent, /No crash details received/);
});

test("push dashboard reports observed health, session scope, and Firebase acceptance", () => {
  const html = readFileSync(new URL("./dashboard.html", import.meta.url), "utf8");
  const helpers = html.slice(html.indexOf("function escapeHtml("), html.indexOf("let regionNames"));
  const start = html.indexOf("function renderFcmTab(");
  const end = html.indexOf("function renderOpsTab(", start);
  const render = runInNewContext(helpers + html.slice(start, end) + ";renderFcmTab");
  const empty = render({});
  assert.match(empty, /Since backend restart/);
  assert.match(empty, /Status unavailable/);
  assert.doesNotMatch(empty, /100%|Active \(Primary\)|Webhooks &amp; Poller Active/);

  const fcm = {
    totalTokens: 322, activeChannels: 1737, monitoredStreamers: 211, unresolvedChannelKeys: 5,
    delivery: { since: new Date().toISOString(), alertsDispatched: 60, notificationsSent: 91,
      multicastSuccess: 90, multicastFailure: 1 },
    webhook: { configured: true, errors: 1, lastErrorCode: "<img src=x onerror=alert(1)>" },
    poller: { active: true, intervalSeconds: 60, lastCycleSucceeded: false, failedCycles: 1,
      lastSuccessAt: new Date().toISOString(), lastErrorCode: "upstream_http_503" },
  };
  const failed = render({ fcm });
  assert.match(failed, /99%/);
  assert.match(failed, /90 accepted · 1 rejected/);
  assert.match(failed, /211/);
  assert.match(failed, /5 unresolved lookup keys/);
  assert.doesNotMatch(failed, /1,737/);
  assert.match(failed, /Awaiting verified traffic/);
  assert.match(failed, /Last poll failed/);
  assert.match(failed, /&lt;img/);
  assert.doesNotMatch(failed, /<img/);

  fcm.webhook.lastReceivedAt = new Date().toISOString();
  fcm.poller.lastCycleSucceeded = true;
  const recovered = render({ fcm });
  assert.match(recovered, /Verified traffic received/);
  assert.match(recovered, /Last poll succeeded/);
  assert.match(recovered, /upstream_http_503/);
  assert.doesNotMatch(recovered, /Last poll failed/);
  fcm.poller.lastSuccessAt = new Date(Date.now() - 240000).toISOString();
  assert.match(render({ fcm }), /No recent successful poll/);
});

test("dashboard disables the date range only for session-scoped push counters", () => {
  const html = readFileSync(new URL("./dashboard.html", import.meta.url), "utf8");
  const start = html.indexOf("function render(d)");
  const end = html.indexOf("function renderOverviewTab(", start);
  const root = {};
  const rangeSelect = {};
  const state = { activeTab: "fcm" };
  const render = runInNewContext(html.slice(start, end) + ";render", {
    root, rangeSelect, state, document: { querySelectorAll: () => [] },
    escapeHtml: String, renderFcmTab: () => "push content", renderSystemTab: () => "system content",
  });
  render({ currentMonth: "2026-11" });
  assert.equal(rangeSelect.disabled, true);
  assert.match(rangeSelect.title, /current backend session/);
  assert.match(root.innerHTML, /Push counters: since backend restart/);
  assert.doesNotMatch(root.innerHTML, /Telemetry period/);
  state.activeTab = "system";
  render({ currentMonth: "2026-11" });
  assert.equal(rangeSelect.disabled, false);
  assert.equal(rangeSelect.title, "");
  assert.match(root.innerHTML, /Telemetry period 2026-11/);
});

test("dashboard counts HMAC rejections within 4xx and rate limits as failed requests", () => {
  const html = readFileSync(new URL("./dashboard.html", import.meta.url), "utf8");
  const start = html.indexOf("function renderEndpointHealthTable(");
  const end = html.indexOf("function renderDiagCounters(", start);
  const state = { healthRange: "today" };
  const render = runInNewContext(html.slice(start, end) + ";renderEndpointHealthTable", {
    state, fmt: value => String(value), escapeHtml: value => String(value),
  });
  const store = createMetricsStore({ salt: "endpoint-counts" });
  const endpoint = "POST /v1/metrics/crash";
  try {
    store.countersHmacRejected(endpoint);
    for (const status of [401, 204, 400, 400, 413]) store.countersEndpoint(endpoint, status);
    for (const range of ["today", "week"]) {
      state.healthRange = range;
      const table = render(store.computeStats());
      assert.match(table, /<td class="num">5<\/td>/);
      assert.match(table, /80% failure/);
      assert.match(table, /1 hmac \(4xx\)/);
      assert.match(table, /HMAC rejections are included in 4xx/);
    }

    store.countersEndpoint(endpoint, 429);
    const limited = render(store.computeStats());
    assert.match(limited, /<td class="num">6<\/td>/);
    assert.match(limited, /83% failure/);
    for (let i = 0; i < 7; i++) store.countersEndpoint("POST /v1/limited", 429);
    const sorted = render(store.computeStats());
    assert.ok(sorted.indexOf("/limited") < sorted.indexOf("/metrics/crash"));
    assert.match(sorted, /100% failure/);
    assert.match(render({}), /No endpoint telemetry available/);
  } finally {
    store.close();
  }
});

test("crash endpoint retains client retry eligibility when storage fails and rate limits uploads", async () => {
  const secret = "crash-test-secret";
  const { app, store } = appWithMetrics(async () => jsonResponse(200, {}), { APP_HMAC_SECRET: secret });
  const path = "/v1/metrics/crash";
  const report = makeCrashReport();
  app.locals.crashReports.record = () => { throw new Error("disk full"); };
  await withServer(app, async baseUrl => {
    for (let i = 0; i < 6; i++) {
      const response = await httpRequest(baseUrl, "POST", path, report, {
        headers: signedHeaders({ secret, method: "POST", path, bodyObject: report }),
      });
      assert.equal(response.status, i < 5 ? 503 : 429);
    }
  });
  store.close();
  app.locals.crashReports.close();
});

test("POST /v1/kick/oauth/refresh happy path returns tokens and records account metrics", async () => {
  let upstreamBody;
  const { app, store } = appWithMetrics(async (url, options) => {
    if (String(url).includes("/oauth/token") && !String(url).includes("introspect")) {
      upstreamBody = options.body;
      return jsonResponse(200, {
        access_token: "fresh-access-token",
        refresh_token: "fresh-refresh-token",
        expires_in: 7200,
        token_type: "Bearer",
        scope: "user:read",
      });
    }
    return jsonResponse(200, { data: { active: true, user_id: "777", username: "refreshed_user" } });
  });

  try {
    await withServer(app, async (baseUrl) => {
      const invalid = await httpRequest(baseUrl, "POST", "/v1/kick/oauth/refresh", { refreshToken: "" });
      assert.equal(invalid.status, 400);
      assert.equal(invalid.body.code, "invalid_request");

      const res = await httpRequest(baseUrl, "POST", "/v1/kick/oauth/refresh", {
        refreshToken: "old-refresh-token",
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.access_token, "fresh-access-token");
      assert.equal(res.body.refresh_token, "fresh-refresh-token");
      assert.equal(res.body.expires_in, 7200);
      assert.equal(upstreamBody.get("grant_type"), "refresh_token");
      assert.equal(upstreamBody.get("refresh_token"), "old-refresh-token");
      assert.equal(upstreamBody.get("client_id"), "client-id");
      assert.equal(upstreamBody.get("client_secret"), "client-secret");
      await waitFor(() => store.computeStats().accountsMau === 1);
    });
    const stats = store.computeStats();
    assert.equal(stats.accountsMau, 1);
    assert.equal(stats.counters.today.oauth.refresh_ok, 1);
    assert.ok(stats.upstreamLatency.count >= 1);
  } finally {
    store.close();
    app.locals.crashReports.close();
  }
});

test("POST /v1/kick/oauth/revoke validates input, forwards tokenTypeHint, and handles errors", async () => {
  let upstreamBody;
  let shouldFail = false;
  const app = appWithFetch(async (_url, options) => {
    upstreamBody = options.body;
    if (shouldFail) {
      return jsonResponse(503, { error: "server_error" });
    }
    return jsonResponse(200, {});
  });

  await withServer(app, async (baseUrl) => {
    const invalid = await httpRequest(baseUrl, "POST", "/v1/kick/oauth/revoke", { token: "" });
    assert.equal(invalid.status, 400);
    assert.equal(invalid.body.code, "invalid_request");

    const invalidHint = await httpRequest(baseUrl, "POST", "/v1/kick/oauth/revoke", {
      token: "tok-1",
      tokenTypeHint: "invalid_hint",
    });
    assert.equal(invalidHint.status, 400);

    const ok = await httpRequest(baseUrl, "POST", "/v1/kick/oauth/revoke", {
      token: "tok-to-revoke",
      tokenTypeHint: "refresh_token",
    });
    assert.equal(ok.status, 200);
    assert.deepEqual(ok.body, { revoked: true });
    assert.equal(upstreamBody.get("token"), "tok-to-revoke");
    assert.equal(upstreamBody.get("token_type_hint"), "refresh_token");
    assert.equal(upstreamBody.get("client_id"), "client-id");
    assert.equal(upstreamBody.get("client_secret"), "client-secret");

    shouldFail = true;
    const failed = await httpRequest(baseUrl, "POST", "/v1/kick/oauth/revoke", {
      token: "tok-to-revoke",
    });
    assert.equal(failed.status, 502);
    assert.equal(failed.body.code, "upstream_unavailable");
  });
});

test("GET /v1/fcm/stats enforces admin token and returns store stats", async () => {
  const fcmStore = createFcmStore({ dataFile: null });
  fcmStore.subscribe({ token: "t".repeat(32), channelIds: ["101", "202"] });
  const cfg = loadConfig(metricsEnv());
  const metrics = createMetricsStore({ salt: cfg.metrics.salt, accountSalt: cfg.metrics.accountSalt, dataPath: null });
  const crashReports = createCrashReportStore();
  const app = createApp(cfg, { fcmStore, metrics, crashReports, messaging: null, pusherRelay: null });

  try {
    await withServer(app, async (baseUrl) => {
      const unauth = await httpRequest(baseUrl, "GET", "/v1/fcm/stats");
      assert.equal(unauth.status, 401);

      const wrong = await httpRequest(baseUrl, "GET", "/v1/fcm/stats", undefined, {
        headers: { "X-Admin-Token": "wrong" },
      });
      assert.equal(wrong.status, 401);

      const ok = await httpRequest(baseUrl, "GET", "/v1/fcm/stats", undefined, {
        headers: { Authorization: "Bearer admin-secret" },
      });
      assert.equal(ok.status, 200);
      assert.equal(ok.body.ok, true);
      assert.equal(ok.body.stats.totalTokens, 1);
      assert.equal(ok.body.stats.activeChannels, 2);
    });
  } finally {
    metrics.close();
    crashReports.close();
    fcmStore.close();
  }
});

test("POST /v1/fcm/unsubscribe handles unknown tokens, validation errors, and conditional relay sync", async () => {
  const fcmStore = createFcmStore({ dataFile: null });
  let syncCalls = 0;
  const mockPusherRelay = {
    syncSubscriptions() {
      syncCalls++;
    },
  };
  const app = createApp(config(), { fcmStore, messaging: null, pusherRelay: mockPusherRelay });
  const token = "fcm_unsub_edge_token_1234567890";
  fcmStore.subscribe({ token, channelIds: ["100"] });

  await withServer(app, async (baseUrl) => {
    const bad = await httpRequest(baseUrl, "POST", "/v1/fcm/unsubscribe", { token: "short" });
    assert.equal(bad.status, 400);
    assert.equal(bad.body.code, "invalid_request");

    const unknown = await httpRequest(baseUrl, "POST", "/v1/fcm/unsubscribe", {
      token: "unknown_token_123456789012345",
    });
    assert.equal(unknown.status, 200);
    assert.deepEqual(unknown.body, { ok: true, unsubscribed: false });
    assert.equal(syncCalls, 0, "Unsubscribing a non-existent token must not sync Pusher relay");

    const removed = await httpRequest(baseUrl, "POST", "/v1/fcm/unsubscribe", { token });
    assert.equal(removed.status, 200);
    assert.deepEqual(removed.body, { ok: true, unsubscribed: true });
    assert.equal(syncCalls, 1);

    const repeat = await httpRequest(baseUrl, "POST", "/v1/fcm/unsubscribe", { token });
    assert.equal(repeat.status, 200);
    assert.deepEqual(repeat.body, { ok: true, unsubscribed: false });
    assert.equal(syncCalls, 1);
  });
});

test("createPusherRelay lifecycle connects, syncs subscriptions, handles ping/pong, and ignores kick_fcm_test_event", async () => {
  const fcmStore = createFcmStore({ dataFile: null });
  const token = "pusher_lifecycle_token_123456789";
  fcmStore.subscribe({ token, channelIds: ["555"] });

  const serverReceived = [];
  let serverSocket = null;
  const wss = new WebSocketServer({ host: "127.0.0.1", port: 0 });
  await new Promise((resolve) => wss.once("listening", resolve));
  const { port } = wss.address();

  wss.on("connection", (ws) => {
    serverSocket = ws;
    ws.on("message", (raw) => {
      serverReceived.push(JSON.parse(raw.toString()));
    });
  });

  let dispatchedCount = 0;
  const mockMessaging = {
    async sendEachForMulticast(payload) {
      dispatchedCount++;
      return {
        successCount: payload.tokens.length,
        failureCount: 0,
        responses: payload.tokens.map(() => ({ success: true })),
      };
    },
  };

  const relay = createPusherRelay({
    fcmStore,
    messaging: mockMessaging,
    logger: null,
    wsUrl: `ws://127.0.0.1:${port}`,
  });

  try {
    await waitFor(() => relay.getStatus().state === "connected" && serverReceived.length >= 1);
    assert.equal(relay.getStatus().subscribedChannels, 1);
    assert.ok(relay.getStatus().lastHeartbeat);
    assert.ok(serverReceived.some((m) => m.event === "pusher:subscribe" && m.data?.channel === "channel.555"));

    // Server sends pusher:ping -> relay responds with pusher:pong
    serverSocket.send(JSON.stringify({ event: "pusher:ping", data: {} }));
    await waitFor(() => serverReceived.some((m) => m.event === "pusher:pong"));

    // Server sends pusher:connection_established
    serverSocket.send(
      JSON.stringify({
        event: "pusher:connection_established",
        data: JSON.stringify({ socket_id: "1.1", activity_timeout: 60 }),
      })
    );

    // Update subscriptions: replace 555 with 777
    fcmStore.subscribe({ token, channelIds: ["777"] });
    relay.syncSubscriptions();
    await waitFor(() =>
      serverReceived.some((m) => m.event === "pusher:unsubscribe" && m.data?.channel === "channel.555") &&
      serverReceived.some((m) => m.event === "pusher:subscribe" && m.data?.channel === "channel.777")
    );
    assert.equal(relay.getStatus().subscribedChannels, 1);

    // Removed kick_fcm_test_event must be ignored
    serverSocket.send(
      JSON.stringify({
        event: "kick_fcm_test_event",
        channel: "channel.777",
        data: JSON.stringify({ title: "Should not trigger" }),
      })
    );
    await new Promise((r) => setTimeout(r, 30));
    assert.equal(dispatchedCount, 0, "kick_fcm_test_event must not trigger push notifications");

    // Real NotifyFollowersStreamHasStarted triggers push once, and duplicate without start_time is deduped
    const realMsg = JSON.stringify({
      event: "NotifyFollowersStreamHasStarted",
      channel: "channel.777",
      data: JSON.stringify({ title: "Real Live Stream" }),
    });
    serverSocket.send(realMsg);
    await waitFor(() => dispatchedCount === 1);
    serverSocket.send(realMsg);
    await new Promise((r) => setTimeout(r, 30));
    assert.equal(dispatchedCount, 1, "Retransmitted start-time-less Pusher event must be deduplicated");
  } finally {
    relay.close();
    assert.equal(relay.getStatus().state, "offline");
    await new Promise((resolve) => wss.close(resolve));
  }
});

test("B1.1: /v1/fcm/subscribe caps uncached slug resolutions at 25, negatively caches 404s, and refuses to persist unresolved bogus slugs", async () => {
  clearChannelResolutionCache();
  const fcmStore = createFcmStore({ dataFile: null });
  const fetchedSlugs = [];

  const mockFetch = async (url) => {
    const match = String(url).match(/\/api\/v2\/channels\/([^/?]+)/);
    if (match) {
      const slug = decodeURIComponent(match[1]);
      fetchedSlugs.push(slug);
      if (slug === "valid-streamer") {
        return {
          ok: true,
          status: 200,
          json: async () => ({ id: 9001, user_id: 9002, slug: "valid-streamer" }),
        };
      }
      return { ok: false, status: 404 };
    }
    return { ok: false, status: 404 };
  };

  // Pre-seed one already-cached slug in fcmStore + resolution cache so we verify it doesn't count against the 25 uncached cap
  const app = createApp(config({ fcm: { pusherRelayEnabled: false } }), {
    fcmStore,
    messaging: null,
    fetch: mockFetch,
  });
  channelResolutionCache.set("already-active-slug", {
    channelId: "8001",
    userId: "8002",
    slug: "already-active-slug",
    expiresAt: Date.now() + 60_000,
  });
  fcmStore.subscribe({ token: "existing_seed_token_1234567890", channelIds: ["already-active-slug"] });

  await withServer(app, async (baseUrl) => {
    const token = "dos_protection_token_1234567890";
    const fakeSlugs = Array.from({ length: 60 }, (_, i) => `fake-slug-${i + 1}`);
    const res1 = await httpRequest(baseUrl, "POST", "/v1/fcm/subscribe", {
      token,
      channel_ids: ["already-active-slug", "valid-streamer", ...fakeSlugs],
    });
    assert.equal(res1.status, 200);
    await waitFor(() => fetchedSlugs.length === 25);
    await new Promise((r) => setTimeout(r, 40));

    // Only 25 uncached slugs were queried over the network (valid-streamer + 24 fake slugs)
    assert.equal(fetchedSlugs.length, 25);
    assert.ok(fetchedSlugs.includes("valid-streamer"));

    // Valid streamer aliases were added, already-active-slug was kept, and ZERO fake slugs were persisted!
    assert.deepEqual(fcmStore.getTokensForChannel("valid-streamer"), [token]);
    assert.deepEqual(fcmStore.getTokensForChannel("9001"), [token]);
    assert.deepEqual(fcmStore.getTokensForChannel("9002"), [token]);
    assert.ok(fcmStore.getTokensForChannel("already-active-slug").includes(token));
    for (const fake of fakeSlugs) {
      assert.deepEqual(fcmStore.getTokensForChannel(fake), [], `${fake} must not be persisted`);
    }

    // The 24 queried fake slugs are now in negativeResolutionCache; a repeat request for them makes 0 network calls
    const countBefore = fetchedSlugs.length;
    const res2 = await httpRequest(baseUrl, "POST", "/v1/fcm/subscribe", {
      token,
      channel_ids: ["valid-streamer", ...fakeSlugs.slice(0, 24)],
    });
    assert.equal(res2.status, 200);
    await new Promise((r) => setTimeout(r, 40));
    assert.equal(fetchedSlugs.length, countBefore, "Negatively cached 404 slugs and positively cached slugs must not hit upstream");
    assert.ok(negativeResolutionCache.has("fake-slug-1"));
  });

  clearChannelResolutionCache();
});

test("B1.1b: fcmStore normalizes slugs to lowercase, caps channel_ids per token at 500, and poller bounds slug queries per cycle", async () => {
  clearChannelResolutionCache();
  const fcmStore = createFcmStore({ dataFile: null, maxChannelsPerToken: 500 });
  const token = "cap_and_case_token_1234567890";

  const channels = ["MixedCaseStreamer", ...Array.from({ length: 520 }, (_, i) => `ch-${i}`)];
  const sub = fcmStore.subscribe({ token, channelIds: channels });
  assert.equal(sub.subscribedChannels, 500);
  assert.deepEqual(fcmStore.getTokensForChannel("mixedcasestreamer"), [token]);
  assert.deepEqual(fcmStore.getTokensForChannel("MIXEDCASESTREAMER"), [token]);
  assert.equal(fcmStore.addAliasesToToken(token, ["extra-alias"]), 0, "Cannot exceed maxChannelsPerToken via addAliasesToToken");

  let slugQueries = 0;
  const poller = createLiveStreamPoller({
    fcmStore,
    messaging: {},
    config: { kickClientId: "cid", kickClientSecret: "csec" },
    maxSlugPollsPerCycle: 10,
    slugPollConcurrency: 5,
    fetchFn: async (url) => {
      if (url.includes("/oauth/token")) {
        return jsonResponse(200, { access_token: "tok", expires_in: 3600 });
      }
      if (url.includes("slug=")) {
        slugQueries++;
        return jsonResponse(404, {});
      }
      return jsonResponse(200, { data: [] });
    },
  });

  try {
    await poller.checkLiveStreams();
    assert.equal(slugQueries, 10, "Poller must cap slug queries per cycle");
  } finally {
    poller.close();
    clearChannelResolutionCache();
  }
});

test("B1.2: HMAC middleware validates nonce length <= 128, signature hex format, and caps seenNonces size", async () => {
  const cfg = { ...loadConfig(hmacEnv), maxSeenNonces: 3 };
  const app = createApp(cfg, { fetch: async () => jsonResponse(200, {}) });

  await withServer(app, async (baseUrl) => {
    const path = "/v1/kick/oauth/introspect";
    const body = { token: "secret-token" };

    // 1. Oversized nonce (> 128 chars) is rejected with 401
    const longNonce = "n".repeat(129);
    const resLongNonce = await signedRequest(baseUrl, "POST", path, body, { nonce: longNonce });
    assert.equal(resLongNonce.status, 401);

    // 2. Non-hex or wrong-length signature is rejected with 401 without crashing timingSafeEqual
    for (const badSig of ["not-hex", "z".repeat(64), "a".repeat(63), "a".repeat(65)]) {
      const headers = signedHeaders({ secret: "hmac-secret", method: "POST", path, bodyObject: body });
      headers["X-Auth-Signature"] = badSig;
      const resBadSig = await httpRequest(baseUrl, "POST", path, body, { headers });
      assert.equal(resBadSig.status, 401);
    }

    // 3. seenNonces cap (maxSeenNonces = 3): inserting 4 distinct nonces evicts the oldest one
    for (const n of ["n1", "n2", "n3"]) {
      assert.equal((await signedRequest(baseUrl, "POST", path, body, { nonce: n })).status, 200);
    }
    // Replaying n3 (still in cache) fails with 401
    assert.equal((await signedRequest(baseUrl, "POST", path, body, { nonce: "n3" })).status, 401);
    // Inserting n4 evicts oldest (n1)
    assert.equal((await signedRequest(baseUrl, "POST", path, body, { nonce: "n4" })).status, 200);
    assert.equal((await signedRequest(baseUrl, "POST", path, body, { nonce: "n2" })).status, 401);
    assert.equal((await signedRequest(baseUrl, "POST", path, body, { nonce: "n1" })).status, 200);
  });
});

test("B1.3: Express 4 async handlers forward rejected promises and thrown errors to 500 error middleware", async () => {
  const brokenFcmStore = {
    getActiveChannels: () => [],
    subscribe: () => { throw new Error("subscribe exploded"); },
    unsubscribe: () => { throw new Error("unsubscribe exploded"); },
    stats: () => { throw new Error("fcm stats exploded"); },
  };
  const brokenMetrics = {
    countersEndpoint() {},
    computeStats: async () => { throw new Error("metrics stats exploded"); },
    close() {},
  };
  const cfg = loadConfig(metricsEnv());
  const app = createApp(cfg, {
    fcmStore: brokenFcmStore,
    metrics: brokenMetrics,
    messaging: null,
    pusherRelay: null,
    crashReports: createCrashReportStore(),
  });

  try {
    await withServer(app, async (baseUrl) => {
      const subRes = await httpRequest(baseUrl, "POST", "/v1/fcm/subscribe", {
        token: "valid_token_123456789012345",
        channel_ids: ["100"],
      });
      assert.equal(subRes.status, 500);
      assert.equal(subRes.body.code, "internal_error");

      const unsubRes = await httpRequest(baseUrl, "POST", "/v1/fcm/unsubscribe", {
        token: "valid_token_123456789012345",
      });
      assert.equal(unsubRes.status, 500);
      assert.equal(unsubRes.body.code, "internal_error");

      const fcmStatsRes = await httpRequest(baseUrl, "GET", "/v1/fcm/stats", undefined, {
        headers: { Authorization: "Bearer admin-secret" },
      });
      assert.equal(fcmStatsRes.status, 500);
      assert.equal(fcmStatsRes.body.code, "internal_error");

      const statsRes = await httpRequest(baseUrl, "GET", "/v1/metrics/stats", undefined, {
        headers: { Authorization: "Bearer admin-secret" },
      });
      assert.equal(statsRes.status, 500);
      assert.equal(statsRes.body.code, "internal_error");
    });
  } finally {
    app.locals.crashReports?.close?.();
  }
});

test("B1.4: fcmStore.close() and startServer SIGTERM flush pending debounced state to disk", async () => {
  const dir = mkdtempSync(join(tmpdir(), "graceful-shutdown-"));
  const fcmFile = join(dir, "fcm.json");
  const metricsFile = join(dir, "metrics.json");

  const probe = http.createServer();
  await new Promise((resolve) => probe.listen(0, "127.0.0.1", resolve));
  const freePort = probe.address().port;
  await new Promise((resolve) => probe.close(resolve));

  try {
    const server = startServer(
      {
        ...metricsEnv(),
        PORT: String(freePort),
        FCM_DATA_FILE: fcmFile,
        METRICS_DATA_FILE: metricsFile,
      },
      { messaging: null, pusherRelay: null, crashReports: createCrashReportStore() }
    );
    if (!server.listening) {
      await new Promise((resolve) => server.once("listening", resolve));
    }
    const { port } = server.address();
    const baseUrl = `http://127.0.0.1:${port}`;

    // Trigger debounced writes (1s for FCM, 2s for metrics) and immediately emit SIGTERM before timers fire
    const subRes = await httpRequest(baseUrl, "POST", "/v1/fcm/subscribe", {
      token: "shutdown_flush_token_1234567890",
      channel_ids: ["12345"],
    });
    assert.equal(subRes.status, 200);

    const pingRes = await httpRequest(baseUrl, "POST", "/v1/metrics/ping", makePingBody("3.0.0"));
    assert.equal(pingRes.status, 204);

    process.emit("SIGTERM");
    await new Promise((resolve) => server.once("close", resolve));

    const persistedFcm = JSON.parse(readFileSync(fcmFile, "utf8"));
    assert.equal(persistedFcm.length, 1);
    assert.equal(persistedFcm[0].token, "shutdown_flush_token_1234567890");
    assert.deepEqual(persistedFcm[0].channelIds, ["12345"]);

    const persistedMetrics = JSON.parse(readFileSync(metricsFile, "utf8"));
    assert.equal(persistedMetrics.totalInstalls, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("B1.5: webhook verifies RSA signature before dedupe check, returns 500 on transient error without burning messageId, and refreshes rotated public key", async () => {
  const keyPair1 = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const pubPem1 = keyPair1.publicKey.export({ type: "spki", format: "pem" });
  const keyPair2 = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const pubPem2 = keyPair2.publicKey.export({ type: "spki", format: "pem" });

  clearKickPublicKeyCache();

  const fcmStore = createFcmStore({ dataFile: null });
  const token = "webhook_hardening_token_1234567890";
  fcmStore.subscribe({ token, channelIds: ["777888", "rotatedstreamer"] });

  let currentPubPem = pubPem1;
  let pubKeyFetches = 0;
  let failFcmOnce = false;
  let pushedCount = 0;

  const mockMessaging = {
    async sendEachForMulticast(payload) {
      if (failFcmOnce) {
        failFcmOnce = false;
        throw new Error("Transient Firebase 503");
      }
      pushedCount++;
      return {
        successCount: payload.tokens.length,
        failureCount: 0,
        responses: payload.tokens.map(() => ({ success: true })),
      };
    },
  };

  const mockFetch = async (url) => {
    if (url.includes("/public/v1/public-key")) {
      pubKeyFetches++;
      return {
        ok: true,
        status: 200,
        json: async () => ({ data: { public_key: currentPubPem } }),
      };
    }
    return { ok: false, status: 404 };
  };

  const app = createApp(config(), {
    fetch: mockFetch,
    fcmStore,
    messaging: mockMessaging,
  });

  try {
    await withServer(app, async (baseUrl) => {
      const messageId = "msg_poison_target_1";
      const timestamp = new Date().toISOString();
      const bodyStr = JSON.stringify({
        broadcaster: { user_id: 777888, channel_slug: "rotatedstreamer" },
        is_live: true,
        title: "Hardened Webhook Stream",
        started_at: "2026-11-20T18:00:00Z",
      });

      // 1. Unauthenticated attacker tries to poison messageId before Kick delivers it -> gets 401
      const poisonAttempt = await fetch(`${baseUrl}/v1/events/webhook`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Kick-Event-Message-Id": messageId,
          "Kick-Event-Message-Timestamp": timestamp,
          "Kick-Event-Signature": "aW52YWxpZA==",
          "Kick-Event-Type": "livestream.status.updated",
        },
        body: bodyStr,
      });
      assert.equal(poisonAttempt.status, 401);
      assert.equal(pubKeyFetches, 1, "Recent key (<5m) must not be re-fetched on invalid signature");

      // 2. Real signed webhook arrives, but FCM has a transient outage -> returns 500 without marking messageId seen
      const signWith = (privKey, id, ts, raw) => {
        const s = createSign("RSA-SHA256");
        s.update(`${id}.${ts}.${raw}`);
        return s.sign(privKey, "base64");
      };
      const validSig1 = signWith(keyPair1.privateKey, messageId, timestamp, bodyStr);

      failFcmOnce = true;
      const transientFail = await fetch(`${baseUrl}/v1/events/webhook`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Kick-Event-Message-Id": messageId,
          "Kick-Event-Message-Timestamp": timestamp,
          "Kick-Event-Signature": validSig1,
          "Kick-Event-Type": "livestream.status.updated",
        },
        body: bodyStr,
      });
      assert.equal(transientFail.status, 500);
      assert.equal(pushedCount, 0);

      // 3. Kick retries the exact same messageId -> succeeds (200) and dispatches push!
      const retryOk = await fetch(`${baseUrl}/v1/events/webhook`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Kick-Event-Message-Id": messageId,
          "Kick-Event-Message-Timestamp": timestamp,
          "Kick-Event-Signature": validSig1,
          "Kick-Event-Type": "livestream.status.updated",
        },
        body: bodyStr,
      });
      assert.equal(retryOk.status, 200);
      assert.equal((await retryOk.json()).duplicate, undefined);
      assert.equal(pushedCount, 1);

      // 4. Unauthenticated replay of an already-seen messageId must still get 401 (not 200 duplicate!)
      const unauthReplay = await fetch(`${baseUrl}/v1/events/webhook`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Kick-Event-Message-Id": messageId,
          "Kick-Event-Message-Timestamp": timestamp,
          "Kick-Event-Signature": "aW52YWxpZA==",
          "Kick-Event-Type": "livestream.status.updated",
        },
        body: bodyStr,
      });
      assert.equal(unauthReplay.status, 401);

      // 5. Public key rotation: age cached key > 5 min by seeding cache with older timestamp via getKickPublicKey
      clearKickPublicKeyCache();
      await getKickPublicKey({ fetchFn: mockFetch, now: Date.now() - 6 * 60 * 1000 });
      const fetchesBeforeRotation = pubKeyFetches;
      currentPubPem = pubPem2;

      const rotatedMsgId = "msg_rotated_key_2";
      const rotatedBody = JSON.stringify({
        broadcaster: { user_id: 777888, channel_slug: "rotatedstreamer" },
        is_live: true,
        title: "Second Stream With Rotated Key",
        started_at: "2026-11-20T19:00:00Z",
      });
      const validSig2 = signWith(keyPair2.privateKey, rotatedMsgId, timestamp, rotatedBody);

      const rotatedRes = await fetch(`${baseUrl}/v1/events/webhook`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Kick-Event-Message-Id": rotatedMsgId,
          "Kick-Event-Message-Timestamp": timestamp,
          "Kick-Event-Signature": validSig2,
          "Kick-Event-Type": "livestream.status.updated",
        },
        body: rotatedBody,
      });
      assert.equal(rotatedRes.status, 200);
      assert.equal(pubKeyFetches, fetchesBeforeRotation + 1, "Key older than 5 min is refreshed once on sig mismatch");
      assert.equal(pushedCount, 2);
    });
  } finally {
    clearKickPublicKeyCache();
    fcmStore.close();
  }
});

test("B1.6: metrics computeStats is immune to Object.prototype keys, kick_user_id enforces .max(64), and crash/dismiss rate-limits before auth", async () => {
  const store = createMetricsStore({ salt: "proto-safety-salt" });
  const now = new Date();
  const epoch = monthStringOf(now);

  for (const [idx, protoKey] of ["toString", "constructor", "valueOf", "__proto__", "hasOwnProperty"].entries()) {
    store.recordPing(
      {
        pidHash: String(idx + 1).repeat(64),
        version: protoKey,
        clientEpoch: epoch,
        os: "35",
        cc: "DE",
      },
      now
    );
  }
  // Also test prototype keys directly in bucket fields
  store.state.devices[epoch]["9".repeat(64)] = {
    v: "constructor",
    d: 1 << (now.getUTCDate() - 1),
    os: "toString",
    cc: "constructor",
    gc: "valueOf",
  };

  const stats = store.computeStats(now);
  assert.ok(stats.versions.every((entry) => typeof entry.count === "number" && Number.isFinite(entry.count)));
  assert.ok(stats.os.every((entry) => typeof entry.count === "number" && Number.isFinite(entry.count)));
  assert.ok(stats.countries.every((entry) => typeof entry.count === "number" && Number.isFinite(entry.count)));
  assert.ok(stats.geoCountries.every((entry) => typeof entry.count === "number" && Number.isFinite(entry.count)));
  const constructorVersion = stats.versions.find((v) => v.version === "constructor");
  assert.equal(constructorVersion.count, 2);
  store.close();

  // Verify kick_user_id .max(64) and /v1/metrics/crash/dismiss limiter before requireAdminToken
  const { app, store: appStore } = appWithMetrics(async () => jsonResponse(200, {}));
  try {
    await withServer(app, async (baseUrl) => {
      const tooLongUserId = await httpRequest(baseUrl, "POST", "/v1/fcm/subscribe", {
        token: "valid_token_123456789012345",
        kick_user_id: "u".repeat(65),
        channel_ids: ["100"],
      });
      assert.equal(tooLongUserId.status, 400);
      assert.equal(tooLongUserId.body.code, "invalid_request");

      let lastStatus = 0;
      for (let i = 0; i < 11; i++) {
        const res = await httpRequest(baseUrl, "POST", "/v1/metrics/crash/dismiss", {
          signature: "a".repeat(64),
        });
        lastStatus = res.status;
        assert.equal(res.status, i < 10 ? 401 : 429);
      }
      assert.equal(lastStatus, 429);
    });
  } finally {
    appStore.close();
    app.locals.crashReports?.close?.();
  }
});







