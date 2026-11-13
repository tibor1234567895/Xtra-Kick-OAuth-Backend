import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { z } from "zod";

export const CRASH_RETENTION_MS = 90 * 86_400_000;
export const MAX_CRASH_GROUPS = 200;
export const MAX_CRASH_EVENTS = 20_000;
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
    frames: z.array(z.object({
      class: symbol,
      method: symbol,
      file: z.string().min(1).max(120).regex(/^[A-Za-z0-9_.$-]+$/),
      line: z.number().int().min(-2).max(2_147_483_647),
    }).strict()).max(32),
  }).strict()).min(1).max(8),
}).strict();

export function createCrashReportStore({ dataPath = null } = {}) {
  let state = { reports: [], events: [], dismissed: {} };
  let loadFailed = false;
  if (dataPath && existsSync(dataPath)) {
    try {
      const parsed = JSON.parse(readFileSync(dataPath, "utf8"));
      if (!Array.isArray(parsed.reports) || !Array.isArray(parsed.events)) throw new Error("Invalid crash report store");
      state = { dismissed: {}, ...parsed };
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
    const signature = createHash("sha256").update(JSON.stringify(details)).digest("hex");
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
  // group reappears on its own ("show again if it happens again"). Because the
  // signature covers version and build, the same stack on a new build is a new
  // group and is never affected by an old dismissal.
  function dismiss(signature, now = Date.now()) {
    if (loadFailed) throw new Error("Crash report storage unavailable");
    if (typeof signature !== "string" || !/^[0-9a-f]{64}$/.test(signature)) {
      const error = new Error("Invalid signature");
      error.status = 400;
      throw error;
    }
    const next = pruned(now);
    next.dismissed = { ...next.dismissed, [signature]: now };
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
    count(now = Date.now()) {
      if (loadFailed) throw new Error("Crash report storage unavailable");
      prune(now);
      return state.reports.length;
    },
    list(now = Date.now()) {
      if (loadFailed) throw new Error("Crash report storage unavailable");
      prune(now);
      const dismissed = state.dismissed || {};
      return state.reports.slice().reverse()
        .filter(r => !(dismissed[r.signature] && r.lastSeen <= dismissed[r.signature]));
    },
    close() { clearInterval(timer); },
  };
}
