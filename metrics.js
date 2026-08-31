// Anonymous usage counters for the Kick OAuth backend.
//
// Storage shape on disk (single JSON object), schema version 2:
//   {
//     "version": 2,
//     "totalInstalls": 42,
//     "devices": { "2026-08": { "<pidHash>": { "v": "1.4.2", "d": 5, "n": 1, "os": "35", "cc": "DE", "s": 3 } } },
//     "accounts": { "2026-08": { "<subHash>": true } },
//     "everSeen": "<concatenated 16-hex pidHash prefixes, install dedup>",
//     "counters": { "2026-08-31": { "endpoints": {...}, "oauth": {...}, "ping": {...}, "account": {...} } }
//   }
//
// Per-device fields: `v` app version, `d` active-day bitmask (1..31), `n`
// new-install-day bitmask, `os` last-reported Android API level, `cc`
// last-reported coarse locale country, `s` last-reported sessions that day.
//
// Months not in `retentionMonths` are pruned on each write and on each stats
// call; daily counters are pruned after `COUNTER_DAYS`. All hashes are SHA-256
// over (raw + salt); no raw identifiers, IPs, or usage traces are persisted and
// the salt is not stored with the data. `everSeen` stores only 64-bit hash
// prefixes so returning devices are not recounted as installs; it is never
// used to track activity and is capped in size.
//
// Schema 1 files (monthly-rotating pids, no everSeen/counters) are migrated in
// place: existing buckets are kept, everSeen starts empty so every first v2
// ping counts once as an install (one-time baseline shift), then dedup applies.

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

export const SCHEMA_VERSION = 2;
export const COUNTER_DAYS = 35;
export const EVERSEEN_PREFIX_CHARS = 16;

export function loadMetricsConfig(env = process.env) {
  const salt = (env.METRICS_SALT || "").trim();
  const accountSalt = (env.METRICS_ACCOUNT_SALT || salt).trim();
  const adminToken = (env.METRICS_ADMIN_TOKEN || "").trim();
  const dataPath = env.METRICS_DATA_FILE
    ? resolve(env.METRICS_DATA_FILE)
    : resolve("./data/metrics.json");
  const retentionMonths = Math.max(1, Number(env.METRICS_RETENTION_MONTHS || 3));
  const maxDevicesPerMonth = Math.max(1, Number(env.METRICS_MAX_DEVICES_PER_MONTH || 100_000));
  const maxEverSeen = Math.max(1000, Number(env.METRICS_MAX_EVERSEEN || 250_000));
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
    maxDevicesPerMonth,
    maxEverSeen,
    dashPath,
  };
}

function monthKey(date) {
  const year = date.getUTCFullYear();
  const month = String(date.getUTCMonth() + 1).padStart(2, "0");
  return `${year}-${month}`;
}

function dayKey(date) {
  return date.toISOString().slice(0, 10);
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
  return {
    version: SCHEMA_VERSION,
    totalInstalls: 0,
    devices: {},
    accounts: {},
    everSeen: "",
    counters: {},
  };
}

function ensureDir(filePath) {
  const dir = dirname(filePath);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
}

function clampInt(value, min, max, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.round(n)));
}

export function createMetricsStore(options = {}) {
  const { salt, accountSalt, dataPath } = options;
  let { retentionMonths, maxDevicesPerMonth, maxEverSeen } = options;
  if (!Number.isInteger(retentionMonths) || retentionMonths < 1) retentionMonths = 3;
  if (!Number.isInteger(maxDevicesPerMonth) || maxDevicesPerMonth < 1) maxDevicesPerMonth = 100_000;
  if (!Number.isInteger(maxEverSeen) || maxEverSeen < 1000) maxEverSeen = 250_000;
  if (!salt) {
    throw new Error("createMetricsStore: salt is required");
  }
  const accSalt = accountSalt || salt;

  let state = emptyState();
  let everSeenSet = new Set();
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
          everSeen: typeof parsed.everSeen === "string" ? parsed.everSeen : "",
          counters: parsed.counters && typeof parsed.counters === "object" ? parsed.counters : {},
        };
        for (let i = 0; i + EVERSEEN_PREFIX_CHARS <= state.everSeen.length; i += EVERSEEN_PREFIX_CHARS) {
          everSeenSet.add(state.everSeen.slice(i, i + EVERSEEN_PREFIX_CHARS));
        }
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
      } finally {
        pendingFlush = null;
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
    const counterCutoff = dayKey(new Date(today.getTime() - COUNTER_DAYS * 86_400_000));
    for (const key of Object.keys(state.counters)) {
      if (key < counterCutoff) delete state.counters[key];
    }
  }

  function ensureMonth(month, kind) {
    if (!state[kind][month]) state[kind][month] = {};
    return state[kind][month];
  }

  function counterBucket(now) {
    const key = dayKey(now);
    if (!state.counters[key]) {
      state.counters[key] = { endpoints: {}, oauth: {}, ping: {}, account: {} };
    }
    const bucket = state.counters[key];
    for (const part of ["endpoints", "oauth", "ping", "account"]) {
      if (!bucket[part] || typeof bucket[part] !== "object") bucket[part] = {};
    }
    return { key, bucket };
  }

  function bump(map, name, field, amount = 1) {
    if (!map[name] || typeof map[name] !== "object") map[name] = {};
    map[name][field] = (map[name][field] || 0) + amount;
  }

  function bumpPlain(map, name, amount = 1) {
    map[name] = (Number(map[name]) || 0) + amount;
  }

  function countersEndpoint(endpoint, statusCode) {
    const { bucket } = counterBucket(new Date());
    const entry = bucket.endpoints;
    if (!entry[endpoint] || typeof entry[endpoint] !== "object") entry[endpoint] = {};
    const status = Number(statusCode) || 0;
    if (status >= 200 && status < 400) bump(entry, endpoint, "ok");
    else if (status === 429) bump(entry, endpoint, "limited");
    else if (status >= 500) bump(entry, endpoint, "r5");
    else bump(entry, endpoint, "r4");
    scheduleFlush();
  }

  function countersHmacRejected(endpoint) {
    const { bucket } = counterBucket(new Date());
    bump(bucket.endpoints, endpoint, "hmac", 1);
    scheduleFlush();
  }

  function countersOauth(code) {
    const { bucket } = counterBucket(new Date());
    bumpPlain(bucket.oauth, code, 1);
    scheduleFlush();
  }

  function countersPing(code) {
    const { bucket } = counterBucket(new Date());
    bumpPlain(bucket.ping, code, 1);
    scheduleFlush();
  }

  function countersAccount(code) {
    const { bucket } = counterBucket(new Date());
    bumpPlain(bucket.account, code, 1);
    scheduleFlush();
  }

  // Returns true only when this device hash was seen for the first time
  // (i.e. it is a genuine new install); false when known or at capacity.
  function markEverSeen(pidHash) {
    const prefix = pidHash.slice(0, EVERSEEN_PREFIX_CHARS);
    if (everSeenSet.has(prefix)) return false;
    if (everSeenSet.size >= maxEverSeen) return false;
    everSeenSet.add(prefix);
    state.everSeen += prefix;
    return true;
  }

  function recordPing({ pidHash, version, clientEpoch, os, cc, sessions }, now = new Date()) {
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
    const safeOs = typeof os === "string" && /^\d{1,3}$/.test(os) ? os.slice(0, 3) : null;
    const safeCc = typeof cc === "string" && /^[A-Za-z]{2}$/.test(cc) ? cc.toUpperCase() : null;
    const safeSessions = clampInt(sessions, 0, 100_000, null);
    prune();
    const month = ensureMonth(serverEpoch, "devices");
    const existing = month[pidHash];
    const dayBit = 1 << (dayIndexUtc(now) - 1);
    if (existing) {
      existing.d |= dayBit;
      if (safeVersion) existing.v = safeVersion;
      if (safeOs) existing.os = safeOs;
      if (safeCc) existing.cc = safeCc;
      if (safeSessions !== null) existing.s = safeSessions;
      scheduleFlush();
      return { isNewInstall: false, month: serverEpoch };
    }
    if (Object.keys(month).length >= maxDevicesPerMonth) {
      const error = new Error("metrics device capacity reached");
      error.status = 429;
      error.code = "metrics_capacity_reached";
      throw error;
    }
    const entry = { v: safeVersion, d: dayBit };
    if (safeOs) entry.os = safeOs;
    if (safeCc) entry.cc = safeCc;
    if (safeSessions !== null) entry.s = safeSessions;
    if (markEverSeen(pidHash)) {
      entry.n = dayBit;
      state.totalInstalls += 1;
    }
    // If everSeen is at capacity the device is recorded for activity but not
    // counted as an install; install totals become best-effort at that point.
    month[pidHash] = entry;
    scheduleFlush();
    return { isNewInstall: Boolean(entry.n), month: serverEpoch };
  }

  function recordAccount({ subHash }, now = new Date()) {
    if (typeof subHash !== "string" || subHash.length === 0) {
      throw new Error("recordAccount: invalid subHash");
    }
    prune();
    const month = ensureMonth(monthKey(now), "accounts");
    if (month[subHash]) return { isNewSession: false };
    if (Object.keys(month).length >= maxDevicesPerMonth) {
      const error = new Error("metrics account capacity reached");
      error.status = 429;
      error.code = "metrics_capacity_reached";
      throw error;
    }
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

  function buildDauSeries(stateRef, now, days) {
    const today = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
    const dayCountsByMonth = {};
    const newCountsByMonth = {};

    // Single-pass bitmask aggregation per active month bucket: O(N) instead of O(days * N)
    for (const [month, bucket] of Object.entries(stateRef.devices)) {
      if (!bucket) continue;
      const counts = new Uint32Array(32);
      const newCounts = new Uint32Array(32);
      for (const entry of Object.values(bucket)) {
        if (!entry || !entry.d) continue;
        const mask = entry.d;
        for (let day = 1; day <= 31; day++) {
          if ((mask & (1 << (day - 1))) !== 0) counts[day]++;
        }
        const newMask = entry.n || 0;
        for (let day = 1; day <= 31; day++) {
          if ((newMask & (1 << (day - 1))) !== 0) newCounts[day]++;
        }
      }
      dayCountsByMonth[month] = counts;
      newCountsByMonth[month] = newCounts;
    }

    const series = [];
    for (let offset = days - 1; offset >= 0; offset -= 1) {
      const d = new Date(today);
      d.setUTCDate(today.getUTCDate() - offset);
      const m = monthKey(d);
      const day = dayIndexUtc(d);
      const dau = dayCountsByMonth[m] ? dayCountsByMonth[m][day] : 0;
      const fresh = newCountsByMonth[m] ? newCountsByMonth[m][day] : 0;
      series.push({
        date: d.toISOString().slice(0, 10),
        dau,
        new: fresh,
        returning: Math.max(0, dau - fresh),
      });
    }
    return series;
  }

  function computeWeeklyActive(now, windowDays) {
    const active = new Set();
    for (let offset = 0; offset < windowDays; offset += 1) {
      const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
      d.setUTCDate(d.getUTCDate() - offset);
      const bucket = state.devices[monthKey(d)];
      if (!bucket) continue;
      const dayBit = 1 << (dayIndexUtc(d) - 1);
      for (const [hash, entry] of Object.entries(bucket)) {
        if (entry && (entry.d & dayBit) !== 0) active.add(hash);
      }
    }
    return active.size;
  }

  function rollupCounters(now, days) {
    const rollup = { endpoints: {}, oauth: {}, ping: {}, account: {} };
    for (let offset = 0; offset < days; offset += 1) {
      const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
      d.setUTCDate(d.getUTCDate() - offset);
      const bucket = state.counters[dayKey(d)];
      if (!bucket) continue;
      for (const part of Object.keys(rollup)) {
        const source = bucket[part] || {};
        for (const [name, value] of Object.entries(source)) {
          if (typeof value !== "object" || value === null) {
            rollup[part][name] = (Number(rollup[part][name]) || 0) + (Number(value) || 0);
            continue;
          }
          if (!rollup[part][name] || typeof rollup[part][name] !== "object") rollup[part][name] = {};
          for (const [field, fieldValue] of Object.entries(value)) {
            rollup[part][name][field] = (rollup[part][name][field] || 0) + (Number(fieldValue) || 0);
          }
        }
      }
    }
    return rollup;
  }

  function computeStats(now = new Date(), days = 60) {
    prune();
    const seriesDays = clampInt(days, 1, 90, 60);
    const month = monthKey(now);
    const devicesBucket = state.devices[month] || {};
    const accountsBucket = state.accounts[month] || {};
    const todayBit = 1 << (dayIndexUtc(now) - 1);
    let dauToday = 0;
    let newToday = 0;
    let sessionsToday = 0;
    const versions = {};
    const osCounts = {};
    const countryCounts = {};
    for (const entry of Object.values(devicesBucket)) {
      if (!entry) continue;
      if ((entry.d & todayBit) !== 0) {
        dauToday += 1;
        if (((entry.n || 0) & todayBit) !== 0) newToday += 1;
        sessionsToday += clampInt(entry.s, 0, 100_000, 0);
      }
      const v = entry.v || "unknown";
      versions[v] = (versions[v] || 0) + 1;
      const osKey = entry.os || "unknown";
      osCounts[osKey] = (osCounts[osKey] || 0) + 1;
      const ccKey = entry.cc || "unknown";
      countryCounts[ccKey] = (countryCounts[ccKey] || 0) + 1;
    }
    const mau = Object.keys(devicesBucket).length;
    const accountsMau = Object.keys(accountsBucket).length;
    const dauSeries = buildDauSeries(state, now, seriesDays);
    const toRanked = (counts) =>
      Object.entries(counts)
        .map(([label, count]) => ({ label, count }))
        .sort((a, b) => b.count - a.count);
    return {
      generatedAt: now.toISOString(),
      currentMonth: month,
      totalInstalls: state.totalInstalls,
      mau,
      wau: computeWeeklyActive(now, 7),
      dauToday,
      newToday,
      sessionsToday,
      stickiness: mau > 0 ? Math.round((dauToday / mau) * 1000) / 1000 : 0,
      accountsMau,
      versions: Object.entries(versions)
        .map(([version, count]) => ({ version, count }))
        .sort((a, b) => b.count - a.count),
      os: toRanked(osCounts),
      countries: toRanked(countryCounts),
      dauSeries,
      counters: {
        today: rollupCounters(now, 1),
        week: rollupCounters(now, 7),
      },
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
    countersEndpoint,
    countersHmacRejected,
    countersOauth,
    countersPing,
    countersAccount,
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
