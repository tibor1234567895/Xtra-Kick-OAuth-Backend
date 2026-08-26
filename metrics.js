// Anonymous usage counters for the Kick OAuth backend.
//
// Storage shape on disk (single JSON object):
//   {
//     "version": 1,
//     "totalInstalls": 42,
//     "devices": { "2026-08": { "<pidHash>": { "v": "1.4.2", "d": 5 } } },
//     "accounts": { "2026-08": { "<subHash>": true } }
//   }
//
// Months not in `retentionMonths` are pruned on each write and on each stats
// call. All hashes are SHA-256 over (raw + salt); no raw identifiers are
// persisted and the salt is not stored with the data.

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

export const SCHEMA_VERSION = 1;

export function loadMetricsConfig(env = process.env) {
  const salt = (env.METRICS_SALT || "").trim();
  const accountSalt = (env.METRICS_ACCOUNT_SALT || salt).trim();
  const adminToken = (env.METRICS_ADMIN_TOKEN || "").trim();
  const dataPath = env.METRICS_DATA_FILE
    ? resolve(env.METRICS_DATA_FILE)
    : resolve("./data/metrics.json");
  const retentionMonths = Math.max(1, Number(env.METRICS_RETENTION_MONTHS || 2));
  const dashPath = env.METRICS_DASHBOARD_FILE
    ? resolve(env.METRICS_DASHBOARD_FILE)
    : null;
  return {
    enabled: salt.length > 0,
    salt,
    accountSalt,
    adminToken,
    dataPath,
    retentionMonths,
    dashPath,
  };
}

function monthKey(date) {
  const year = date.getUTCFullYear();
  const month = String(date.getUTCMonth() + 1).padStart(2, "0");
  return `${year}-${month}`;
}

function dayIndexUtc(date) {
  return date.getUTCDate();
}

function addMonths(monthString, delta) {
  const [y, m] = monthString.split("-").map(Number);
  const date = new Date(Date.UTC(y, m - 1 + delta, 1));
  return monthKey(date);
}

function hashWithSalt(salt, value) {
  return createHash("sha256").update(salt).update(String(value)).digest("hex");
}

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const ah = createHash("sha256").update(a).digest();
  const bh = createHash("sha256").update(b).digest();
  if (ah.length !== bh.length) return false;
  return timingSafeEqual(ah, bh);
}

function emptyState() {
  return { version: SCHEMA_VERSION, totalInstalls: 0, devices: {}, accounts: {} };
}

function ensureDir(filePath) {
  const dir = dirname(filePath);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
}

export function createMetricsStore(options = {}) {
  const { salt, accountSalt, dataPath } = options;
  let { retentionMonths } = options;
  if (!Number.isInteger(retentionMonths) || retentionMonths < 1) retentionMonths = 2;
  if (!salt) {
    throw new Error("createMetricsStore: salt is required");
  }
  const accSalt = accountSalt || salt;

  let state = emptyState();
  let pendingFlush = null;

  if (dataPath && existsSync(dataPath)) {
    try {
      const raw = readFileSync(dataPath, "utf8");
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === "object") {
        state = {
          version: SCHEMA_VERSION,
          totalInstalls: Number(parsed.totalInstalls) || 0,
          devices: parsed.devices && typeof parsed.devices === "object" ? parsed.devices : {},
          accounts: parsed.accounts && typeof parsed.accounts === "object" ? parsed.accounts : {},
        };
      }
    } catch (error) {
      // Corrupt store: keep in-memory only, do not overwrite file until we get a successful write.
      state = emptyState();
      // eslint-disable-next-line no-console
      console.warn({ err: { message: error.message } }, "metrics: failed to load state, starting empty");
    }
  }

  function flushSync() {
    if (!dataPath) return;
    ensureDir(dataPath);
    const tmp = `${dataPath}.tmp`;
    writeFileSync(tmp, JSON.stringify(state));
    renameSync(tmp, dataPath);
    pendingFlush = null;
  }

  function scheduleFlush() {
    if (!dataPath) return;
    if (pendingFlush) return;
    pendingFlush = setTimeout(() => {
      try {
        flushSync();
      } catch {
        // Swallow: counters are best-effort.
      }
    }, 2_000);
    if (typeof pendingFlush.unref === "function") pendingFlush.unref();
  }

  function prune(retention = retentionMonths) {
    const today = new Date();
    const cutoff = addMonths(monthKey(today), -retention);
    for (const key of Object.keys(state.devices)) {
      if (key < cutoff) delete state.devices[key];
    }
    for (const key of Object.keys(state.accounts)) {
      if (key < cutoff) delete state.accounts[key];
    }
  }

  function ensureMonth(month, kind) {
    if (!state[kind][month]) state[kind][month] = {};
    return state[kind][month];
  }

  function recordPing({ pidHash, version, clientEpoch }, now = new Date()) {
    if (typeof pidHash !== "string" || !/^[0-9a-f]{64}$/.test(pidHash)) {
      throw new Error("recordPing: invalid pidHash");
    }
    const serverEpoch = monthKey(now);
    if (clientEpoch !== null && clientEpoch !== undefined && clientEpoch !== serverEpoch) {
      const expectedPrev = addMonths(serverEpoch, -1);
      if (clientEpoch !== expectedPrev) {
        throw new Error("recordPing: epoch mismatch");
      }
    }
    const safeVersion = String(version || "").slice(0, 32) || "unknown";
    prune();
    const month = ensureMonth(serverEpoch, "devices");
    const existing = month[pidHash];
    const dayBit = 1 << (dayIndexUtc(now) - 1);
    if (existing) {
      existing.d |= dayBit;
      if (safeVersion) existing.v = safeVersion;
      scheduleFlush();
      return { isNewInstall: false, month: serverEpoch };
    }
    month[pidHash] = { v: safeVersion, d: dayBit };
    state.totalInstalls += 1;
    scheduleFlush();
    return { isNewInstall: true, month: serverEpoch };
  }

  function recordAccount({ subHash }, now = new Date()) {
    if (typeof subHash !== "string" || subHash.length === 0) {
      throw new Error("recordAccount: invalid subHash");
    }
    prune();
    const month = ensureMonth(monthKey(now), "accounts");
    if (month[subHash]) return { isNewSession: false };
    month[subHash] = true;
    scheduleFlush();
    return { isNewSession: true };
  }

  function hashSub(rawSub) {
    return hashWithSalt(accSalt, rawSub);
  }

  function hashPid(rawPid) {
    return hashWithSalt(salt, rawPid);
  }

  function popcount(int) {
    let n = int >>> 0;
    let count = 0;
    while (n) {
      n &= n - 1;
      count += 1;
    }
    return count;
  }

  function buildDauSeries(stateRef, now) {
    const today = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
    const series = [];
    for (let offset = 59; offset >= 0; offset -= 1) {
      const d = new Date(today);
      d.setUTCDate(today.getUTCDate() - offset);
      const m = monthKey(d);
      const day = dayIndexUtc(d);
      const bit = 1 << (day - 1);
      const bucket = stateRef.devices[m];
      let count = 0;
      if (bucket) {
        for (const entry of Object.values(bucket)) {
          if (entry && (entry.d & bit) !== 0) count += 1;
        }
      }
      series.push({
        date: d.toISOString().slice(0, 10),
        dau: count,
      });
    }
    return series;
  }

  function computeStats(now = new Date()) {
    prune();
    const month = monthKey(now);
    const devicesBucket = state.devices[month] || {};
    const accountsBucket = state.accounts[month] || {};
    const todayBit = 1 << (dayIndexUtc(now) - 1);
    let dauToday = 0;
    const versions = {};
    for (const entry of Object.values(devicesBucket)) {
      if (!entry) continue;
      if ((entry.d & todayBit) !== 0) dauToday += 1;
      const v = entry.v || "unknown";
      versions[v] = (versions[v] || 0) + 1;
    }
    const mau = Object.keys(devicesBucket).length;
    const accountsMau = Object.keys(accountsBucket).length;
    const dauSeries = buildDauSeries(state, now);
    return {
      generatedAt: now.toISOString(),
      currentMonth: month,
      totalInstalls: state.totalInstalls,
      mau,
      dauToday,
      stickiness: mau > 0 ? Math.round((dauToday / mau) * 1000) / 1000 : 0,
      accountsMau,
      versions: Object.entries(versions)
        .map(([version, count]) => ({ version, count }))
        .sort((a, b) => b.count - a.count),
      dauSeries,
    };
  }

  function close() {
    if (pendingFlush) {
      clearTimeout(pendingFlush);
      pendingFlush = null;
    }
    try {
      flushSync();
    } catch {
      // ignore
    }
  }

  return {
    recordPing,
    recordAccount,
    hashSub,
    hashPid,
    computeStats,
    prune,
    flushSync,
    close,
    get state() {
      return state;
    },
  };
}

export function requireAdminToken(metricsConfig) {
  return function checkAdmin(req, res, next) {
    if (!metricsConfig.adminToken) {
      return res.status(404).json({ code: "not_found", message: "Not found" });
    }
    const header = String(req.get("authorization") || "");
    const provided = header.toLowerCase().startsWith("bearer ")
      ? header.slice(7).trim()
      : String(req.get("x-admin-token") || "").trim();
    if (!safeEqual(provided, metricsConfig.adminToken)) {
      return res.status(401).json({ code: "unauthorized", message: "Invalid admin token" });
    }
    return next();
  };
}

export function generateSalt(byteCount = 32) {
  return randomBytes(byteCount).toString("hex");
}

export { safeEqual, hashWithSalt };

export const __testing = {
  join,
};
