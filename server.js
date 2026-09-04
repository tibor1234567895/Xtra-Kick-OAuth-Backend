import "dotenv/config";
import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import pino from "pino";
import pinoHttp from "pino-http";
import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import {
  createMetricsStore,
  loadMetricsConfig,
  requireAdminToken,
} from "./metrics.js";
import {
  channelResolutionCache,
  createFcmStore,
  createLiveStreamPoller,
  createPusherRelay,
  initFirebaseMessaging,
  loadFcmConfig,
  resolveKickBroadcasterUserIds,
  resolveKickChannel,
} from "./fcm.js";

const KICK_TOKEN_URL = "https://id.kick.com/oauth/token";
const KICK_REVOKE_URL = "https://id.kick.com/oauth/revoke";
const KICK_INTROSPECT_URL = "https://id.kick.com/oauth/token/introspect";
const TIMEOUT_MESSAGE = "Kick OAuth request timed out";
const REDACTED = "[REDACTED]";

export const redactPaths = [
  "req.headers.authorization",
  "req.headers['x-admin-token']",
  "req.body.code_verifier",
  "req.body.refresh_token",
  "req.body.code",
  "req.body.codeVerifier",
  "req.body.refreshToken",
  "req.body.token",
  "res.body.access_token",
  "res.body.refresh_token",
  "res.body.token",
  "access_token",
  "refresh_token",
  "token",
  "code",
  "codeVerifier",
  "refreshToken",
  "client_secret",
  "clientSecret",
];

export function loadConfig(env = process.env) {
  const logger = pino({
    level: env.LOG_LEVEL || "info",
    redact: { paths: redactPaths, censor: REDACTED },
  });

  const port = Number(env.PORT || 8080);
  const upstreamTimeoutMs = Number(env.UPSTREAM_TIMEOUT_MS || 10_000);
  const allowedRedirectUris = parseAllowedRedirectUris(env.ALLOWED_REDIRECT_URIS);
  const appHmacSecret = (env.APP_HMAC_SECRET || "").trim();
  const allowUnauthenticatedOAuth = env.ALLOW_UNAUTHENTICATED_OAUTH === "true";
  const hmacToleranceSeconds = Number(env.HMAC_TIMESTAMP_TOLERANCE_SECONDS || 300);
  const metrics = loadMetricsConfig(env);
  const fcm = loadFcmConfig(env);

  if (!Number.isInteger(port) || port <= 0) {
    throw new Error("PORT must be a positive integer");
  }
  if (!Number.isInteger(upstreamTimeoutMs) || upstreamTimeoutMs <= 0) {
    throw new Error("UPSTREAM_TIMEOUT_MS must be a positive integer");
  }
  if (!Number.isInteger(hmacToleranceSeconds) || hmacToleranceSeconds <= 0) {
    throw new Error("HMAC_TIMESTAMP_TOLERANCE_SECONDS must be a positive integer");
  }
  if (!env.KICK_CLIENT_ID || !env.KICK_CLIENT_SECRET) {
    throw new Error("KICK_CLIENT_ID and KICK_CLIENT_SECRET are required");
  }
  if (allowedRedirectUris.size === 0) {
    throw new Error("ALLOWED_REDIRECT_URIS must contain at least one HTTPS URI");
  }
  if (!appHmacSecret && !allowUnauthenticatedOAuth) {
    throw new Error("APP_HMAC_SECRET is required unless ALLOW_UNAUTHENTICATED_OAUTH=true");
  }

  return {
    port,
    logger,
    kickClientId: env.KICK_CLIENT_ID,
    kickClientSecret: env.KICK_CLIENT_SECRET,
    trustProxy: parseTrustProxy(env.TRUST_PROXY),
    upstreamTimeoutMs,
    allowedRedirectUris,
    appHmacSecret,
    allowUnauthenticatedOAuth,
    hmacToleranceSeconds,
    metrics,
    fcm,
  };
}

export const KNOWN_ENDPOINTS = new Set([
  "POST /v1/kick/oauth/exchange",
  "POST /v1/kick/oauth/refresh",
  "POST /v1/kick/oauth/revoke",
  "POST /v1/kick/oauth/introspect",
  "POST /v1/metrics/ping",
  "GET /v1/metrics/stats",
  "GET /v1/metrics/dashboard",
  "POST /v1/fcm/subscribe",
  "POST /v1/fcm/unsubscribe",
  "GET /v1/fcm/stats",
  "GET /healthz",
]);

const BLOCKED_PROBE_REGEX = /(\.env|\.git|\.php|\.bak|\.asp|\.jsp|graphql|wp-admin|phpmyadmin|\.\.)/i;

export function createApp(config, deps = {}) {
  const app = express();
  const upstreamFetch = deps.fetch || globalThis.fetch;

  app.disable("x-powered-by");
  app.set("trust proxy", config.trustProxy);
  app.use(createLimiter(180));
  app.use(helmet({ contentSecurityPolicy: false }));

  const metrics = deps.metrics || (config.metrics?.enabled
    ? createMetricsStore({
        salt: config.metrics.salt,
        accountSalt: config.metrics.accountSalt,
        dataPath: config.metrics.dataPath,
        retentionMonths: config.metrics.retentionMonths,
        maxDevicesPerMonth: config.metrics.maxDevicesPerMonth,
        maxEverSeen: config.metrics.maxEverSeen,
      })
    : null);

  if (metrics) {
    app.use((req, res, next) => {
      const rawEndpoint = `${req.method} ${req.originalUrl.split("?")[0]}`;
      const endpoint = KNOWN_ENDPOINTS.has(rawEndpoint) ? rawEndpoint : "OTHER / 404";
      res.on("finish", () => {
        try {
          metrics.countersEndpoint(endpoint, res.statusCode);
        } catch {
          // Counters are best-effort.
        }
      });
      return next();
    });
  }

  app.use((req, res, next) => {
    if (BLOCKED_PROBE_REGEX.test(req.originalUrl)) {
      return res.status(404).json({ code: "not_found", message: "Not found" });
    }
    return next();
  });
  app.use(
    express.json({
      limit: "32kb",
      verify: (req, _res, buf) => {
        req.rawBody = buf;
      },
    })
  );
  app.use(pinoHttp({ logger: config.logger }));

  const requireHmac = config.appHmacSecret ? createHmacMiddleware(config, metrics) : null;
  const registerPost = (path, limiter, handler) =>
    app.post(path, ...(requireHmac ? [requireHmac] : []), limiter, handler);

  const fcmStore = deps.fcmStore || createFcmStore({
    dataFile: config.fcm?.dataFile,
    logger: config.logger,
  });
  const messaging = deps.messaging !== undefined
    ? deps.messaging
    : initFirebaseMessaging({
        serviceAccountPath: config.fcm?.serviceAccountPath,
        logger: config.logger,
      });
  const pusherRelay = deps.pusherRelay !== undefined
    ? deps.pusherRelay
    : (config.fcm?.pusherRelayEnabled && messaging
        ? createPusherRelay({ fcmStore, messaging, logger: config.logger })
        : null);
  const liveStreamPoller = deps.liveStreamPoller !== undefined
    ? deps.liveStreamPoller
    : (messaging && config.kickClientId && config.kickClientSecret
        ? createLiveStreamPoller({
            fcmStore,
            messaging,
            config,
            fetchFn: upstreamFetch,
            logger: config.logger,
          })
        : null);

  app.locals.fcmStore = fcmStore;
  app.locals.pusherRelay = pusherRelay;
  app.locals.liveStreamPoller = liveStreamPoller;

  if (pusherRelay && fcmStore) {
    backfillStoredSubscriptions(fcmStore, pusherRelay, {
      logger: config.logger,
      config,
      fetchFn: upstreamFetch,
    }).catch(() => {});
  }

  app.use("/v1/kick/oauth", createLimiter(120));
  registerPost("/v1/kick/oauth/exchange", createLimiter(20), exchangeHandler(config, upstreamFetch, metrics));
  registerPost("/v1/kick/oauth/refresh", createLimiter(30), refreshHandler(config, upstreamFetch, metrics));
  registerPost("/v1/kick/oauth/revoke", createLimiter(30), revokeHandler(config, upstreamFetch));
  registerPost("/v1/kick/oauth/introspect", createLimiter(60), introspectHandler(config, upstreamFetch));

  if (metrics) {
    app.use("/v1/metrics", createLimiter(120));
    registerPost("/v1/metrics/ping", createLimiter(10), pingHandler(metrics));
    app.get("/v1/metrics/stats", requireAdminToken(config.metrics), statsHandler(metrics));
    if (config.metrics.dashPath) {
      // The page is only a login shell; its data request remains token-protected.
      app.get("/v1/metrics/dashboard", dashboardHandler(config.metrics));
    }
  }

  app.use("/v1/fcm", createLimiter(120));
  registerPost("/v1/fcm/subscribe", createLimiter(30), fcmSubscribeHandler(fcmStore, pusherRelay, { upstreamFetch, config }));
  registerPost("/v1/fcm/unsubscribe", createLimiter(30), fcmUnsubscribeHandler(fcmStore));
  if (config.metrics?.adminToken) {
    app.get("/v1/fcm/stats", requireAdminToken(config.metrics), fcmStatsHandler(fcmStore));
  }

  app.get("/healthz", (_req, res) => {
    res.status(200).json({ ok: true });
  });

  app.use((_req, res) => {
    return res.status(404).json({ code: "not_found", message: "Not found" });
  });

  app.use((err, req, res, _next) => {
    req.log.error({ err: { message: err.message, code: err.code, status: err.status } }, "unhandled error");
    return res.status(500).json({ code: "internal_error", message: "Unexpected server error" });
  });

  return app;
}

const exchangeSchema = z.object({
  code: z.string().min(1),
  codeVerifier: z.string().min(43).max(128).regex(/^[A-Za-z0-9._~-]+$/),
  redirectUri: z.string().url(),
});

const refreshSchema = z.object({
  refreshToken: z.string().min(1),
});

const revokeSchema = z.object({
  token: z.string().min(1),
  tokenTypeHint: z.enum(["access_token", "refresh_token"]).optional(),
});

const fcmSubscribeSchema = z.object({
  token: z.string().trim().min(20).max(500),
  kick_user_id: z.string().trim().optional(),
  channel_ids: z.array(z.string().trim().min(1).max(100)).max(500),
});

const fcmUnsubscribeSchema = z.object({
  token: z.string().trim().min(20).max(500),
});

const introspectSchema = z.object({
  token: z.string().min(1),
});

const pingSchema = z.object({
  pid: z.string().regex(/^[0-9a-f]{64}$/),
  v: z.string().min(1).max(32).regex(/^[A-Za-z0-9._\-+ ]*$/),
  os: z.string().regex(/^\d{1,3}$/).optional(),
  cc: z.string().regex(/^[A-Za-z]{2}$/).optional(),
  s: z.number().int().min(0).max(100_000).optional(),
});

function createLimiter(max) {
  return rateLimit({
    windowMs: 60_000,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    message: { code: "rate_limited", message: "Too many requests" },
  });
}

export function hmacCanonicalString({ timestamp, nonce, method, pathname, bodySha256 }) {
  return `${timestamp}\n${nonce}\n${method}\n${pathname}\n${bodySha256}`;
}

export function computeHmacSignature(secret, parts) {
  return createHmac("sha256", secret).update(hmacCanonicalString(parts)).digest("hex");
}

function unauthorized(res) {
  return res.status(401).json({ code: "unauthorized", message: "Request signature is invalid" });
}

function createHmacMiddleware(config, metrics = null) {
  const toleranceMs = config.hmacToleranceSeconds * 1000;
  const seenNonces = new Map();
  const cleanup = setInterval(() => {
    const now = Date.now();
    for (const [nonce, expiresAt] of seenNonces) {
      if (expiresAt <= now) seenNonces.delete(nonce);
    }
  }, Math.min(toleranceMs, 60_000));
  cleanup.unref();

  return function requireHmac(req, res, next) {
    const timestamp = req.get("x-auth-timestamp");
    const nonce = req.get("x-auth-nonce");
    const signature = req.get("x-auth-signature");

    const reject = () => {
      try {
        metrics?.countersHmacRejected(`${req.method} ${new URL(req.originalUrl, "http://internal").pathname}`);
      } catch {
        // Counters are best-effort.
      }
      return unauthorized(res);
    };

    if (!timestamp || !nonce || !signature || typeof nonce !== "string") {
      return reject();
    }
    if (!/^\d+$/.test(timestamp)) {
      return reject();
    }
    const now = Date.now();
    if (Math.abs(now - Number(timestamp) * 1000) > toleranceMs) {
      return reject();
    }

    let pathname;
    try {
      pathname = new URL(req.originalUrl, "http://internal").pathname;
    } catch {
      return reject();
    }

    const bodySha256 = createHash("sha256")
      .update(req.rawBody ?? Buffer.alloc(0))
      .digest("hex");
    const expected = Buffer.from(
      computeHmacSignature(config.appHmacSecret, {
        timestamp,
        nonce,
        method: req.method,
        pathname,
        bodySha256,
      }),
      "hex"
    );
    const provided = Buffer.from(signature.toLowerCase(), "hex");
    if (expected.length !== provided.length || !timingSafeEqual(expected, provided)) {
      return reject();
    }

    const nonceExpiresAt = now + 2 * toleranceMs;
    const previousExpiry = seenNonces.get(nonce);
    if (previousExpiry && previousExpiry > now) {
      return reject();
    }
    seenNonces.set(nonce, nonceExpiresAt);

    return next();
  };
}

function parseAllowedRedirectUris(value) {
  if (!value) return new Set();
  return new Set(
    value
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean)
      .map(normalizeRedirectUri)
  );
}

function parseTrustProxy(value) {
  if (!value) return "loopback";
  if (value === "false") return false;
  // `trust proxy: true` makes req.ip the leftmost, entirely client-controlled
  // X-Forwarded-For entry. Every rate limiter keys on req.ip, and those limiters are
  // the only control on /refresh, /revoke and /introspect — so one spoofed header per
  // request turns all of them into no-ops. Require a hop count or an explicit
  // address/subnet instead.
  if (value === "true") {
    throw new Error(
      'TRUST_PROXY=true is not accepted: it trusts the entire X-Forwarded-For chain and ' +
        'defeats every rate limiter. Use a hop count (e.g. TRUST_PROXY=1), a specific ' +
        'address or subnet, "loopback", or "false".'
    );
  }
  if (/^\d+$/.test(value)) return Number(value);
  return value;
}

function normalizeRedirectUri(value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("ALLOWED_REDIRECT_URIS contains an invalid URI");
  }
  if (parsed.protocol !== "https:") {
    throw new Error("ALLOWED_REDIRECT_URIS may only contain HTTPS URIs");
  }
  return parsed.toString();
}

function isAllowedRedirectUri(value, allowedRedirectUris) {
  try {
    return allowedRedirectUris.has(normalizeRedirectUri(value));
  } catch {
    return false;
  }
}

function toForm(data) {
  const form = new URLSearchParams();
  for (const [key, value] of Object.entries(data)) {
    if (value !== undefined && value !== null && value !== "") {
      form.append(key, String(value));
    }
  }
  return form;
}

function safeOAuthErrorMessage(code) {
  if (code === "invalid_grant") return "Kick OAuth grant is invalid";
  if (code === "invalid_scope") return "Kick OAuth scope is invalid";
  if (code === "upstream_unavailable") return "Kick OAuth service is unavailable";
  return "Kick OAuth request failed";
}

function mapKickOAuthError(body, status) {
  const raw = typeof body === "object" && body !== null ? body : {};
  const error = typeof raw.error === "string" ? raw.error : "oauth_error";

  let code = "upstream_error";
  let responseStatus = status;
  if (error === "invalid_grant") code = "invalid_grant";
  else if (error === "invalid_scope") code = "invalid_scope";
  else if (status >= 500) {
    code = "upstream_unavailable";
    responseStatus = 502;
  }

  return {
    status: responseStatus,
    code,
    message: safeOAuthErrorMessage(code),
  };
}

async function fetchWithTimeout(upstreamFetch, url, options, timeoutMs) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await upstreamFetch(url, { ...options, signal: controller.signal });
  } catch (error) {
    if (error?.name === "AbortError" || controller.signal.aborted) {
      const timeoutError = new Error(TIMEOUT_MESSAGE);
      timeoutError.status = 502;
      timeoutError.code = "upstream_unavailable";
      throw timeoutError;
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

async function readJson(response) {
  const text = await response.text();
  try {
    return text ? JSON.parse(text) : {};
  } catch {
    return {};
  }
}

async function postKickForm(config, upstreamFetch, url, payload) {
  const response = await fetchWithTimeout(
    upstreamFetch,
    url,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body: toForm(payload),
    },
    config.upstreamTimeoutMs
  );

  const parsed = await readJson(response);

  if (!response.ok) {
    const mapped = mapKickOAuthError(parsed, response.status);
    const error = new Error(mapped.message);
    error.status = mapped.status;
    error.code = mapped.code;
    throw error;
  }

  return parsed;
}

async function postKickAuthed(config, upstreamFetch, url, accessToken) {
  const response = await fetchWithTimeout(
    upstreamFetch,
    url,
    {
      method: "POST",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${accessToken}`,
      },
    },
    config.upstreamTimeoutMs
  );

  return {
    ok: response.ok,
    status: response.status,
    body: await readJson(response),
  };
}

function validationError(res, parsed) {
  return res.status(400).json({ code: "invalid_request", message: parsed.error.issues[0]?.message || "Invalid payload" });
}

function sendOAuthError(req, res, error, fallbackMessage, logMessage) {
  const status = error.status || 502;
  const code = error.code || "upstream_error";
  const message = error.message || fallbackMessage;
  req.log.warn({ err: { code, status, message } }, logMessage);
  return res.status(status).json({ code, message });
}

function exchangeHandler(config, upstreamFetch, metrics) {
  return async (req, res) => {
    const parsed = exchangeSchema.safeParse(req.body);
    if (!parsed.success) return validationError(res, parsed);
    if (!isAllowedRedirectUri(parsed.data.redirectUri, config.allowedRedirectUris)) {
      return res.status(400).json({ code: "invalid_redirect_uri", message: "Redirect URI is not allowed" });
    }

    try {
      const data = await postKickForm(config, upstreamFetch, KICK_TOKEN_URL, {
        grant_type: "authorization_code",
        code: parsed.data.code,
        redirect_uri: normalizeRedirectUri(parsed.data.redirectUri),
        code_verifier: parsed.data.codeVerifier,
        client_id: config.kickClientId,
        client_secret: config.kickClientSecret,
      });

      const responseBody = tokenResponse(data);
      if (metrics) {
        metrics.countersOauth("exchange_ok");
        if (responseBody.access_token) {
          recordAccountFromAccessToken({
            accessToken: responseBody.access_token,
            metrics,
            upstreamFetch,
            config,
          }).catch(() => {});
        }
      }
      return res.status(200).json(responseBody);
    } catch (error) {
      metrics?.countersOauth(error.code || "exchange_error");
      return sendOAuthError(req, res, error, "OAuth exchange failed", "exchange failed");
    }
  };
}

function refreshHandler(config, upstreamFetch, metrics) {
  return async (req, res) => {
    const parsed = refreshSchema.safeParse(req.body);
    if (!parsed.success) return validationError(res, parsed);

    try {
      const data = await postKickForm(config, upstreamFetch, KICK_TOKEN_URL, {
        grant_type: "refresh_token",
        refresh_token: parsed.data.refreshToken,
        client_id: config.kickClientId,
        client_secret: config.kickClientSecret,
      });

      const responseBody = tokenResponse(data);
      if (metrics) {
        metrics.countersOauth("refresh_ok");
        if (responseBody.access_token) {
          recordAccountFromAccessToken({
            accessToken: responseBody.access_token,
            metrics,
            upstreamFetch,
            config,
          }).catch(() => {});
        }
      }
      return res.status(200).json(responseBody);
    } catch (error) {
      metrics?.countersOauth(error.code || "refresh_error");
      return sendOAuthError(req, res, error, "OAuth refresh failed", "refresh failed");
    }
  };
}

function revokeHandler(config, upstreamFetch) {
  return async (req, res) => {
    const parsed = revokeSchema.safeParse(req.body);
    if (!parsed.success) return validationError(res, parsed);

    try {
      await postKickForm(config, upstreamFetch, KICK_REVOKE_URL, {
        token: parsed.data.token,
        token_type_hint: parsed.data.tokenTypeHint,
        client_id: config.kickClientId,
        client_secret: config.kickClientSecret,
      });

      return res.status(200).json({ revoked: true });
    } catch (error) {
      return sendOAuthError(req, res, error, "OAuth revoke failed", "revoke failed");
    }
  };
}

function introspectHandler(config, upstreamFetch) {
  return async (req, res) => {
    const parsed = introspectSchema.safeParse(req.body);
    if (!parsed.success) return validationError(res, parsed);

    try {
      const upstream = await postKickAuthed(config, upstreamFetch, KICK_INTROSPECT_URL, parsed.data.token);
      const data = typeof upstream.body?.data === "object" && upstream.body?.data !== null ? upstream.body.data : {};

      if (upstream.status === 401) {
        req.log.info({ upstreamStatus: upstream.status }, "introspect inactive");
        return res.status(200).json(inactiveTokenResponse());
      }

      if (!upstream.ok) {
        const error = new Error(upstream.status >= 500 ? "Kick OAuth service is unavailable" : "Kick OAuth request failed");
        error.status = upstream.status >= 500 ? 502 : upstream.status;
        error.code = upstream.status >= 500 ? "upstream_unavailable" : "upstream_error";
        throw error;
      }

      return res.status(200).json({
        active: Boolean(data.active),
        exp: data.exp,
        client_id: data.client_id,
        user_id: data.user_id,
        username: data.username,
        scope: data.scope,
      });
    } catch (error) {
      return sendOAuthError(req, res, error, "OAuth introspect failed", "introspect failed");
    }
  };
}

function fcmSubscribeHandler(fcmStore, pusherRelay, { upstreamFetch, config } = {}) {
  return async (req, res) => {
    const parsed = fcmSubscribeSchema.safeParse(req.body);
    if (!parsed.success) return validationError(res, parsed);

    const result = fcmStore.subscribe({
      token: parsed.data.token,
      kickUserId: parsed.data.kick_user_id,
      channelIds: parsed.data.channel_ids,
    });
    pusherRelay?.syncSubscriptions();

    // In the background, resolve any slugs or keys so numeric channel_ids are guaranteed
    // to be subscribed on the Pusher WebSocket and registered to the device token.
    const token = parsed.data.token;
    const channelIds = parsed.data.channel_ids;
    const fetchFn = upstreamFetch || globalThis.fetch;
    const logger = req.log || config?.logger;

    (async () => {
      try {
        const nonNumeric = channelIds.filter((id) => !/^\d+$/.test(id));
        const numericIds = channelIds.filter((id) => /^\d+$/.test(id));
        if (nonNumeric.length === 0 && numericIds.length === 0) return;

        const resolvedIds = [];
        // 1. Resolve non-numeric slugs with controlled concurrency
        if (nonNumeric.length > 0) {
          const BATCH_SIZE = 5;
          for (let i = 0; i < nonNumeric.length; i += BATCH_SIZE) {
            const batch = nonNumeric.slice(i, i + BATCH_SIZE);
            const results = await Promise.all(
              batch.map((slug) => resolveKickChannel(slug, { fetchFn, logger }))
            );
            for (const r of results) {
              if (r) {
                if (r.channelId) resolvedIds.push(r.channelId);
                if (r.userId) resolvedIds.push(r.userId);
              }
            }
          }
        }

        // 2. Resolve numeric broadcaster user IDs that are not yet known as channelIds
        if (numericIds.length > 0) {
          const unknownNumeric = numericIds.filter((id) => {
            const cached = channelResolutionCache.get(id);
            return !cached || cached.channelId !== id;
          });
          if (unknownNumeric.length > 0) {
            const results = await resolveKickBroadcasterUserIds(unknownNumeric, {
              fetchFn,
              logger,
              clientId: config?.kickClientId,
              clientSecret: config?.kickClientSecret,
            });
            for (const r of results) {
              if (r) {
                if (r.channelId) resolvedIds.push(r.channelId);
                if (r.userId) resolvedIds.push(r.userId);
                if (r.slug) resolvedIds.push(r.slug);
              }
            }
          }
        }

        if (resolvedIds.length > 0) {
          const added = fcmStore.addAliasesToToken(token, resolvedIds);
          if (added > 0) {
            pusherRelay?.syncSubscriptions();
            logger?.info({ token: token.slice(-8), resolvedCount: resolvedIds.length, added }, "fcm_slugs_resolved_and_synced");
          }
        }
      } catch (err) {
        logger?.warn({ err: err.message }, "fcm_background_resolution_failed");
      }
    })().catch(() => {});

    return res.status(200).json({
      ok: true,
      subscribed_channels: result.subscribedChannels,
    });
  };
}

function fcmUnsubscribeHandler(fcmStore) {
  return async (req, res) => {
    const parsed = fcmUnsubscribeSchema.safeParse(req.body);
    if (!parsed.success) return validationError(res, parsed);

    const removed = fcmStore.unsubscribe({ token: parsed.data.token });
    return res.status(200).json({ ok: true, unsubscribed: removed });
  };
}

function fcmStatsHandler(fcmStore) {
  return async (_req, res) => {
    return res.status(200).json({ ok: true, stats: fcmStore.stats() });
  };
}

export async function backfillStoredSubscriptions(fcmStore, pusherRelay, { logger, config, fetchFn = globalThis.fetch } = {}) {
  try {
    const allChannels = fcmStore.getActiveChannels();
    const nonNumeric = allChannels.filter((id) => !/^\d+$/.test(id));
    const numeric = allChannels.filter((id) => /^\d+$/.test(id));

    let aliasesAdded = 0;

    // 1. Resolve non-numeric slugs
    for (const slug of nonNumeric) {
      const res = await resolveKickChannel(slug, { fetchFn, logger });
      if (res && res.channelId) {
        const tokens = fcmStore.getTokensForChannel(slug);
        for (const tok of tokens) {
          aliasesAdded += fcmStore.addAliasesToToken(tok, [res.channelId, res.userId].filter(Boolean));
        }
      }
    }

    // 2. Resolve numeric IDs that may be broadcaster user IDs
    const unknownNumeric = numeric.filter((id) => {
      const cached = channelResolutionCache.get(id);
      return !cached || cached.channelId !== id;
    });

    if (unknownNumeric.length > 0) {
      const resolved = await resolveKickBroadcasterUserIds(unknownNumeric, {
        fetchFn,
        logger,
        clientId: config?.kickClientId,
        clientSecret: config?.kickClientSecret,
      });
      for (const res of resolved) {
        if (res && res.channelId) {
          const keys = [res.userId, res.slug].filter(Boolean);
          for (const k of keys) {
            const tokens = fcmStore.getTokensForChannel(k);
            for (const tok of tokens) {
              aliasesAdded += fcmStore.addAliasesToToken(tok, [res.channelId, res.userId, res.slug].filter(Boolean));
            }
          }
        }
      }
    }

    if (aliasesAdded > 0) {
      pusherRelay?.syncSubscriptions();
      logger?.info({ aliasesAdded }, "fcm_backfill_aliases_added_and_synced");
    }
  } catch (err) {
    logger?.warn({ err: err.message }, "fcm_backfill_failed");
  }
}

function tokenResponse(data) {
  return {
    access_token: data.access_token,
    refresh_token: data.refresh_token,
    expires_in: data.expires_in,
    token_type: data.token_type,
    scope: data.scope,
  };
}

function inactiveTokenResponse() {
  return {
    active: false,
    exp: null,
    client_id: null,
    user_id: null,
    username: null,
    scope: null,
  };
}

export function startServer(env = process.env, deps = {}) {
  const config = loadConfig(env);
  const app = createApp(config, deps);
  return app.listen(config.port, () => {
    config.logger.info({ port: config.port, trustProxy: config.trustProxy }, "Kick OAuth backend running");
  });
}

function pingHandler(metrics) {
  return async (req, res) => {
    const parsed = pingSchema.safeParse(req.body);
    if (!parsed.success) {
      try {
        metrics.countersPing("invalid");
      } catch {
        // Counters are best-effort.
      }
      return validationError(res, parsed);
    }
    try {
      const pidHash = metrics.hashPid(parsed.data.pid);
      const now = new Date();
      const month = `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, "0")}`;
      metrics.recordPing(
        {
          pidHash,
          version: parsed.data.v,
          clientEpoch: month,
          os: parsed.data.os,
          cc: parsed.data.cc,
          sessions: parsed.data.s,
        },
        now
      );
      return res.status(204).end();
    } catch (error) {
      try {
        metrics.countersPing(error.code === "metrics_capacity_reached" ? "capacity" : "epoch");
      } catch {
        // Counters are best-effort.
      }
      req.log.warn({ err: { message: error.message, code: error.code } }, "ping rejected");
      return res.status(error.status || 400).json({ code: error.code || "invalid_request", message: error.message });
    }
  };
}

function statsHandler(metrics) {
  return async (req, res) => {
    const daysParam = req.query.days;
    const days = typeof daysParam === "string" && /^\d{1,3}$/.test(daysParam) ? Number(daysParam) : 60;
    const payload = metrics.computeStats(new Date(), days);
    return res.status(200).json(payload);
  };
}

function dashboardHandler(metricsConfig) {
  return async (_req, res) => {
    if (!metricsConfig.dashPath || !existsSync(metricsConfig.dashPath)) {
      return res.status(404).json({ code: "not_found", message: "Not found" });
    }
    try {
      const html = readFileSync(metricsConfig.dashPath, "utf8");
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.setHeader("Cache-Control", "no-store");
      res.setHeader("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'");
      return res.status(200).send(html);
    } catch (error) {
      return res.status(500).json({ code: "internal_error", message: "Dashboard unavailable" });
    }
  };
}

async function recordAccountFromAccessToken({ accessToken, metrics, upstreamFetch, config }) {
  if (!accessToken || !metrics) return;
  try {
    const upstream = await postKickAuthed(config, upstreamFetch, KICK_INTROSPECT_URL, accessToken);
    if (!upstream.ok) {
      metrics.countersAccount(`introspect_http_${upstream.status}`);
      return;
    }
    const data = typeof upstream.body?.data === "object" && upstream.body?.data !== null
      ? upstream.body.data
      : upstream.body;

    if (data?.active === false) {
      metrics.countersAccount("inactive");
      return;
    }

    let subRaw = data?.user_id ?? data?.sub ?? null;
    if (subRaw === null || subRaw === undefined) {
      try {
        const userRes = await fetchWithTimeout(
          upstreamFetch,
          "https://api.kick.com/public/v1/users",
          {
            method: "GET",
            headers: {
              Accept: "application/json",
              Authorization: `Bearer ${accessToken}`,
            },
          },
          config.upstreamTimeoutMs
        );
        if (userRes.ok) {
          const userBody = await readJson(userRes);
          const userData = Array.isArray(userBody?.data) ? userBody.data[0] : userBody?.data;
          subRaw = userData?.user_id ?? userData?.id ?? null;
        }
      } catch {
        // Fallback user fetch is best-effort.
      }
    }

    if (subRaw === null || subRaw === undefined) {
      metrics.countersAccount("no_sub");
      return;
    }
    const subHash = metrics.hashSub(String(subRaw));
    metrics.recordAccount({ subHash });
    metrics.countersAccount("recorded");
  } catch {
    metrics.countersAccount("error");
  }
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];

if (isMain) {
  try {
    startServer();
  } catch (error) {
    const logger = pino({ level: process.env.LOG_LEVEL || "info" });
    logger.error({ err: { message: error.message } }, "Kick OAuth backend failed to start");
    process.exit(1);
  }
}
