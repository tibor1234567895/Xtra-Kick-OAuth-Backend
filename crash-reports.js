import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { z } from "zod";

export const CRASH_RETENTION_MS = 90 * 86_400_000;
export const MAX_CRASH_GROUPS = 200;
export const MAX_CRASH_EVENTS = 20_000;
const MAX_PERMANENT_MUTES = MAX_CRASH_EVENTS;
const symbol = z.string().min(1).max(200).regex(/^[A-Za-z0-9_.$<>-]+$/);
export const crashReportSchema = z.object({
  id: z.uuid(),
  version: z.string().min(1).max(32).regex(/^[A-Za-z0-9._+ -]+$/),
  build: z.number().int().min(1).max(2_147_483_647),
  sdk: z.number().int().min(21).max(999),
  abi: z.enum(["arm64-v8a", "armeabi-v7a", "x86", "x86_64", "unknown"]).default("unknown"),
  liveEnginePreference: z.enum(["ivs", "exo", "unknown"]).default("unknown"),
  crashedAt: z.number().int().min(1).max(8_640_000_000_000_000),
  exceptions: z.array(z.object({
    type: symbol,
    message: z.string().min(1).max(200).regex(/^[\x20-\x7E]+$/).optional(),
    frames: z.array(z.object({
      class: symbol,
      method: symbol,
      file: z.string().min(1).max(120).regex(/^[A-Za-z0-9_.$-]+$/),
      line: z.number().int().min(-2).max(2_147_483_647),
    }).strict()).max(32),
  }).strict()).min(1).max(8),
}).strict();

export function createCrashReportStore({ dataPath = null } = {}) {
  let state = { reports: [], events: [], dismissed: {}, muted: {}, minBuild: 0 };
  let loadFailed = false;
  if (dataPath && existsSync(dataPath)) {
    try {
      const parsed = JSON.parse(readFileSync(dataPath, "utf8"));
      if (!Array.isArray(parsed.reports) || !Array.isArray(parsed.events)) throw new Error("Invalid crash report store");
      const parsedMinBuild = Number.isInteger(parsed.minBuild) && parsed.minBuild >= 0 && parsed.minBuild <= 2_147_483_647
        ? parsed.minBuild
        : 0;
      state = { dismissed: {}, muted: {}, ...parsed, minBuild: parsedMinBuild };
    } catch {
      loadFailed = true;
    }
  }

  function save(next) {
    if (dataPath) {
      mkdirSync(dirname(dataPath), { recursive: true });
      writeFileSync(`${dataPath}.tmp`, JSON.stringify(next), { mode: 0o600 });
      renameSync(`${dataPath}.tmp`, dataPath);
    }
    state = next;
  }

  function pruned(now) {
    const cutoff = now - CRASH_RETENTION_MS;
    const events = state.events.filter(e => e.receivedAt > cutoff).slice(-MAX_CRASH_EVENTS);
    const counts = new Map();
    for (const event of events) {
      const count = counts.get(event.signature) || { count: 0, firstSeen: event.receivedAt };
      count.count++;
      counts.set(event.signature, count);
    }
    const dismissed = {};
    for (const [signature, at] of Object.entries(state.dismissed || {})) {
      if (at > cutoff) dismissed[signature] = at;
    }
    return {
      reports: state.reports.filter(r => counts.has(r.signature)).slice(-MAX_CRASH_GROUPS)
        .map(r => ({ ...r, ...counts.get(r.signature) })),
      events,
      dismissed,
      muted: state.muted || {},
      minBuild: state.minBuild || 0,
    };
  }

  function prune(now = Date.now()) {
    const next = pruned(now);
    if (next.reports.length !== state.reports.length || next.events.length !== state.events.length) save(next);
  }

  function record(input, now = Date.now()) {
    if (loadFailed) throw new Error("Crash report storage unavailable");
    const report = crashReportSchema.parse(input);
    if (report.crashedAt <= now - CRASH_RETENTION_MS || report.crashedAt > now + 300_000) return;
    const next = pruned(now);
    if (next.events.some(e => e.id === report.id)) return;
    // Never discard retry IDs while their reports may still be uploaded.
    if (next.events.length >= MAX_CRASH_EVENTS) {
      const error = new Error("Crash report capacity reached");
      error.status = 429;
      throw error;
    }
    const { id, crashedAt, ...details } = report;
    const signatureInput = {
      ...details,
      exceptions: details.exceptions.map(({ message: _message, ...exception }) => exception),
    };
    const signature = createHash("sha256").update(JSON.stringify(signatureInput)).digest("hex");
    const existing = next.reports.find(r => r.signature === signature);
    next.reports = next.reports.filter(r => r.signature !== signature);
    next.reports.push({
      ...details,
      signature,
      count: (existing?.count || 0) + 1,
      firstSeen: existing?.firstSeen || now,
      lastSeen: now,
      crashedAt,
    });
    next.reports = next.reports.slice(-MAX_CRASH_GROUPS);
    next.events.push({ id, signature, receivedAt: now });
    // Acknowledge only after persistence succeeds, so a client can safely retry.
    save(next);
  }

  // Dismissal hides a group until something new happens for it: any later event
  // for the same signature bumps lastSeen past the dismissal timestamp, so the
  // group reappears on its own ("show again if it happens again"). With
  // permanent=true ("mute"), the exact signature stays hidden even if old
  // clients keep hitting it. Because the signature covers version and build, a
  // different crash on the same build or the same stack on a new build always
  // produces a new signature and still appears.
  function dismissMany(signatures, now = Date.now(), { permanent = false } = {}) {
    if (loadFailed) throw new Error("Crash report storage unavailable");
    if (!Array.isArray(signatures) || signatures.length < 1 || signatures.length > 50 ||
        signatures.some(s => typeof s !== "string" || !/^[0-9a-f]{64}$/.test(s))) {
      const error = new Error("Invalid signature");
      error.status = 400;
      throw error;
    }
    const next = pruned(now);
    const field = permanent ? "muted" : "dismissed";
    const target = { ...next[field] };
    for (const signature of signatures) {
      target[signature] = now;
    }
    if (permanent && Object.keys(target).length > MAX_PERMANENT_MUTES) {
      const error = new Error("Permanent crash mute capacity reached");
      error.status = 409;
      throw error;
    }
    next[field] = target;
    save(next);
  }

  function dismiss(signature, now = Date.now(), options) {
    dismissMany([signature], now, options);
  }

  function setMinBuild(minBuild, now = Date.now()) {
    if (loadFailed) throw new Error("Crash report storage unavailable");
    if (!Number.isInteger(minBuild) || minBuild < 0 || minBuild > 2_147_483_647) {
      const error = new Error("Invalid minBuild");
      error.status = 400;
      throw error;
    }
    const next = pruned(now);
    next.minBuild = minBuild;
    save(next);
  }

  try { prune(); } catch { loadFailed = true; }
  const timer = setInterval(() => {
    try { prune(); } catch { /* Retry expiration on the next read or timer. */ }
  }, 60_000);
  timer.unref();
  return {
    record,
    dismiss,
    dismissMany,
    setMinBuild,
    minBuild() {
      if (loadFailed) throw new Error("Crash report storage unavailable");
      return state.minBuild || 0;
    },
    count(now = Date.now()) {
      if (loadFailed) throw new Error("Crash report storage unavailable");
      prune(now);
      return state.reports.length;
    },
    list(now = Date.now(), { includeBelowMinBuild = false } = {}) {
      if (loadFailed) throw new Error("Crash report storage unavailable");
      prune(now);
      const dismissed = state.dismissed || {};
      const muted = state.muted || {};
      const floor = includeBelowMinBuild ? 0 : (state.minBuild || 0);
      return state.reports.slice().reverse()
        .filter(r => !muted[r.signature] && !(dismissed[r.signature] && r.lastSeen <= dismissed[r.signature]) && r.build >= floor);
    },
    close() { clearInterval(timer); },
  };
}
