import assert from "node:assert/strict";
import http from "node:http";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import pino from "pino";
import { computeHmacSignature, createApp, loadConfig, redactPaths } from "./server.js";
import { createMetricsStore } from "./metrics.js";
import { createFcmStore, createPusherRelay, sendLivePushNotification } from "./fcm.js";

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
  return { app: createApp(cfg, { fetch: fetchImpl, metrics: store }), store };
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

test("metrics device cap returns 429 without adding another device", () => {
  const store = createMetricsStore({
    salt: "s",
    accountSalt: "s",
    dataPath: null,
    maxDevicesPerMonth: 1,
  });
  store.recordPing({ pidHash: "a".repeat(64), version: "1", clientEpoch: aMonthString() });
  assert.throws(
    () => store.recordPing({ pidHash: "b".repeat(64), version: "1", clientEpoch: aMonthString() }),
    (error) => error.status === 429 && error.code === "metrics_capacity_reached"
  );
  assert.equal(store.computeStats().mau, 1);
  store.close();
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

    const stats = await httpRequest(baseUrl, "GET", "/v1/metrics/stats");
    assert.equal(stats.status, 401);
  });
  store.close();
});

test("account counter records hashed sub once per month", () => {
  const store = createMetricsStore({ salt: "a".repeat(32), accountSalt: "b".repeat(32), dataPath: null });
  const subHash = store.hashSub("user-42");
  const first = store.recordAccount({ subHash });
  const second = store.recordAccount({ subHash });
  assert.equal(first.isNewSession, true);
  assert.equal(second.isNewSession, false);
  const stats = store.computeStats();
  assert.equal(stats.accountsMau, 1);
  store.close();
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


