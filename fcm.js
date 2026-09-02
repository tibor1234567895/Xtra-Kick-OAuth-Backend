import { existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import WebSocket from "ws";
import admin from "firebase-admin";
import { getMessaging } from "firebase-admin/messaging";

const PUSHER_URL = "wss://ws-us2.pusher.com/app/32cbd69e4b950bf97679?protocol=7&client=js&version=8.5.0&flash=false";

export function loadFcmConfig(env = process.env) {
  const serviceAccountPath = env.FCM_SERVICE_ACCOUNT_KEY_PATH || "./firebase-service-account.json";
  const dataFile = env.FCM_DATA_FILE || "./data/fcm_subscriptions.json";
  const pusherRelayEnabled = env.FCM_PUSHER_RELAY_ENABLED !== "false";
  return {
    serviceAccountPath,
    dataFile,
    pusherRelayEnabled,
  };
}

export function createFcmStore({ dataFile, logger } = {}) {
  const tokens = new Map(); // token -> { kickUserId, channelIds: Set, updatedAt, lastActiveAt }
  const channelIndex = new Map(); // channelId -> Set<token>
  let saveTimer = null;

  function load() {
    if (!dataFile || !existsSync(dataFile)) return;
    try {
      const raw = readFileSync(dataFile, "utf8");
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        for (const item of parsed) {
          if (item && typeof item.token === "string") {
            const channelSet = new Set(Array.isArray(item.channelIds) ? item.channelIds.map(String) : []);
            tokens.set(item.token, {
              kickUserId: item.kickUserId ? String(item.kickUserId) : null,
              channelIds: channelSet,
              updatedAt: item.updatedAt || Date.now(),
              lastActiveAt: item.lastActiveAt || Date.now(),
            });
            for (const ch of channelSet) {
              if (!channelIndex.has(ch)) channelIndex.set(ch, new Set());
              channelIndex.get(ch).add(item.token);
            }
          }
        }
      }
      logger?.info({ count: tokens.size, channels: channelIndex.size }, "fcm_store_loaded");
    } catch (err) {
      logger?.warn({ err: err.message }, "fcm_store_load_failed");
    }
  }

  function scheduleSave() {
    if (!dataFile) return;
    if (saveTimer) return;
    saveTimer = setTimeout(() => {
      saveTimer = null;
      persist();
    }, 1000);
    if (typeof saveTimer.unref === "function") saveTimer.unref();
  }

  function persist() {
    if (!dataFile) return;
    try {
      const dir = dirname(dataFile);
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true });
      }
      const data = [];
      for (const [token, info] of tokens.entries()) {
        data.push({
          token,
          kickUserId: info.kickUserId,
          channelIds: Array.from(info.channelIds),
          updatedAt: info.updatedAt,
          lastActiveAt: info.lastActiveAt,
        });
      }
      const tmpFile = `${dataFile}.${Date.now()}.tmp`;
      writeFileSync(tmpFile, JSON.stringify(data), "utf8");
      renameSync(tmpFile, dataFile);
    } catch (err) {
      logger?.error({ err: err.message }, "fcm_store_persist_failed");
    }
  }

  load();

  return {
    subscribe({ token, kickUserId, channelIds }) {
      const normalizedToken = String(token).trim();
      const normalizedChannels = new Set((channelIds || []).map((id) => String(id).trim()).filter(Boolean));
      const now = Date.now();

      const existing = tokens.get(normalizedToken);
      if (existing) {
        for (const oldCh of existing.channelIds) {
          if (!normalizedChannels.has(oldCh)) {
            const set = channelIndex.get(oldCh);
            if (set) {
              set.delete(normalizedToken);
              if (set.size === 0) channelIndex.delete(oldCh);
            }
          }
        }
      }

      for (const ch of normalizedChannels) {
        if (!channelIndex.has(ch)) channelIndex.set(ch, new Set());
        channelIndex.get(ch).add(normalizedToken);
      }

      tokens.set(normalizedToken, {
        kickUserId: kickUserId ? String(kickUserId).trim() : null,
        channelIds: normalizedChannels,
        updatedAt: now,
        lastActiveAt: now,
      });

      scheduleSave();
      return { token: normalizedToken, subscribedChannels: normalizedChannels.size };
    },

    unsubscribe({ token }) {
      const normalizedToken = String(token).trim();
      const existing = tokens.get(normalizedToken);
      if (!existing) return false;

      for (const ch of existing.channelIds) {
        const set = channelIndex.get(ch);
        if (set) {
          set.delete(normalizedToken);
          if (set.size === 0) channelIndex.delete(ch);
        }
      }
      tokens.delete(normalizedToken);
      scheduleSave();
      return true;
    },

    getTokensForChannel(channelId) {
      const normalized = String(channelId).trim();
      const set = channelIndex.get(normalized);
      return set ? Array.from(set) : [];
    },

    getActiveChannels() {
      return Array.from(channelIndex.keys());
    },

    pruneInvalidTokens(invalidTokens) {
      if (!Array.isArray(invalidTokens) || invalidTokens.length === 0) return 0;
      let count = 0;
      for (const tok of invalidTokens) {
        if (this.unsubscribe({ token: tok })) count++;
      }
      return count;
    },

    stats() {
      return {
        totalTokens: tokens.size,
        activeChannels: channelIndex.size,
      };
    },

    flushSync() {
      if (saveTimer) {
        clearTimeout(saveTimer);
        saveTimer = null;
      }
      persist();
    },
  };
}

export function initFirebaseMessaging({ serviceAccountPath, logger } = {}) {
  if (!serviceAccountPath || !existsSync(serviceAccountPath)) {
    logger?.info({ path: serviceAccountPath }, "fcm_service_account_not_found_skipping");
    return null;
  }
  try {
    const raw = readFileSync(serviceAccountPath, "utf8");
    const serviceAccount = JSON.parse(raw);
    // firebase-admin v14 moved the app/credential helpers to top-level named
    // exports (admin.apps / admin.credential no longer exist).
    const app = admin.getApps().length > 0
      ? admin.getApp()
      : admin.initializeApp({
          credential: admin.cert(serviceAccount),
        });
    logger?.info("fcm_firebase_admin_initialized");
    return getMessaging(app);
  } catch (err) {
    logger?.error({ err: err.message }, "fcm_firebase_admin_init_failed");
    return null;
  }
}

export async function sendLivePushNotification({
  messaging,
  tokens,
  channelId,
  userId,
  channelSlug,
  title,
  description,
  profilePicture,
  logger,
  fcmStore,
}) {
  if (!messaging || !tokens || tokens.length === 0) return { successCount: 0, failureCount: 0 };

  const cleanSlug = String(channelSlug || userId || "").trim().replace(/^\/+/, "");
  const payload = {
    tokens,
    data: {
      type: "stream_live",
      channel_id: String(channelId || ""),
      user_id: String(userId || ""),
      channel_slug: cleanSlug,
      title: String(title || `${cleanSlug} is live!`),
      description: String(description || ""),
      profile_picture: String(profilePicture || ""),
      timestamp: String(Date.now()),
    },
    android: {
      priority: "high",
    },
  };

  try {
    const response = await messaging.sendEachForMulticast(payload);
    const invalidTokens = [];
    response.responses.forEach((resp, idx) => {
      if (!resp.success && resp.error) {
        const code = resp.error.code;
        if (
          code === "messaging/invalid-registration-token" ||
          code === "messaging/registration-token-not-registered"
        ) {
          invalidTokens.push(tokens[idx]);
        }
      }
    });

    if (invalidTokens.length > 0 && fcmStore) {
      fcmStore.pruneInvalidTokens(invalidTokens);
    }

    logger?.info(
      {
        channel: cleanSlug,
        success: response.successCount,
        failure: response.failureCount,
        pruned: invalidTokens.length,
      },
      "fcm_live_notification_dispatched"
  );

    return {
      successCount: response.successCount,
      failureCount: response.failureCount,
      invalidTokens,
    };
  } catch (err) {
    logger?.error({ err: err.message, channel: cleanSlug }, "fcm_live_notification_failed");
    return { successCount: 0, failureCount: tokens.length, error: err.message };
  }
}

export function createPusherRelay({ fcmStore, messaging, logger }) {
  let ws = null;
  let isClosed = false;
  let reconnectTimeout = null;
  let pingInterval = null;
  let pongTimeout = null;
  let subscribedChannels = new Set();

  function startHeartbeat(activityTimeoutSec = 120) {
    stopHeartbeat();
    const intervalMs = Math.max(10000, Math.floor((activityTimeoutSec * 1000) / 2));
    pingInterval = setInterval(() => {
      if (ws && ws.readyState === WebSocket.OPEN) {
        try {
          ws.send(JSON.stringify({ event: "pusher:ping", data: {} }));
          if (!pongTimeout) {
            pongTimeout = setTimeout(() => {
              logger?.warn("pusher_relay_pong_timeout_reconnecting");
              if (ws) ws.close();
            }, 30000);
            if (typeof pongTimeout.unref === "function") pongTimeout.unref();
          }
        } catch (e) {
          // send failure will trigger close
        }
      }
    }, intervalMs);
    if (typeof pingInterval.unref === "function") pingInterval.unref();
  }

  function stopHeartbeat() {
    if (pingInterval) {
      clearInterval(pingInterval);
      pingInterval = null;
    }
    if (pongTimeout) {
      clearTimeout(pongTimeout);
      pongTimeout = null;
    }
  }

  function connect() {
    if (isClosed) return;
    try {
      ws = new WebSocket(PUSHER_URL);

      ws.on("open", () => {
        logger?.info("pusher_relay_connected");
        subscribedChannels.clear();
        startHeartbeat(120);
        syncSubscriptions();
      });

      ws.on("message", (raw) => {
        try {
          const msg = JSON.parse(raw.toString());
          if (msg.event === "pusher:ping") {
            ws.send(JSON.stringify({ event: "pusher:pong", data: {} }));
            return;
          }
          if (msg.event === "pusher:pong") {
            if (pongTimeout) {
              clearTimeout(pongTimeout);
              pongTimeout = null;
            }
            return;
          }
          if (msg.event === "pusher:connection_established") {
            let timeout = 120;
            try {
              const estData = typeof msg.data === "string" ? JSON.parse(msg.data) : msg.data;
              if (estData?.activity_timeout) timeout = Number(estData.activity_timeout);
            } catch {}
            startHeartbeat(timeout);
            syncSubscriptions();
            return;
          }
          if (
            msg.event === "kick_fcm_test_event" ||
            msg.event === "NotifyFollowersStreamHasStarted" ||
            msg.event === "App\\Events\\NotifyFollowersStreamHasStarted"
          ) {
            handleLiveEvent(msg);
          }
        } catch (e) {
          // ignore parsing error
        }
      });

      ws.on("close", () => {
        logger?.warn("pusher_relay_disconnected");
        stopHeartbeat();
        ws = null;
        scheduleReconnect();
      });

      ws.on("error", (err) => {
        logger?.warn({ err: err.message }, "pusher_relay_socket_error");
      });
    } catch (err) {
      scheduleReconnect();
    }
  }

  function scheduleReconnect() {
    if (isClosed || reconnectTimeout) return;
    reconnectTimeout = setTimeout(() => {
      reconnectTimeout = null;
      connect();
    }, 5000);
    if (typeof reconnectTimeout.unref === "function") reconnectTimeout.unref();
  }

  function syncSubscriptions() {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    const activeChannels = fcmStore.getActiveChannels();
    for (const ch of activeChannels) {
      const pusherChannel = `channel.${ch}`;
      if (!subscribedChannels.has(pusherChannel)) {
        ws.send(
          JSON.stringify({
            event: "pusher:subscribe",
            data: { auth: "", channel: pusherChannel },
          })
        );
        subscribedChannels.add(pusherChannel);
      }
    }
  }

  function handleLiveEvent(msg) {
    try {
      const data = typeof msg.data === "string" ? JSON.parse(msg.data) : (msg.data || {});
      const channelFromPusher = typeof msg.channel === "string" ? msg.channel.replace(/^channel\./, "").trim() : null;
      const userId = data.user_id ? String(data.user_id).trim() : null;
      const channelIdFromData = data.channel_id ? String(data.channel_id).trim() : null;
      const slug = String(data.path || data.slug || data.channel_slug || "")
        .trim()
        .replace(/^\/+/, "")
        .toLowerCase();

      const candidateKeys = [channelFromPusher, channelIdFromData, userId, slug].filter(Boolean);
      const tokenSet = new Set();
      for (const key of candidateKeys) {
        for (const tok of fcmStore.getTokensForChannel(key)) {
          tokenSet.add(tok);
        }
      }
      const tokens = Array.from(tokenSet);
      if (tokens.length === 0) return;

      sendLivePushNotification({
        messaging,
        tokens,
        channelId: channelFromPusher || channelIdFromData,
        userId,
        channelSlug: slug || channelFromPusher || userId,
        title: data.title,
        description: data.description,
        profilePicture: data.profile_picture,
        logger,
        fcmStore,
      });
    } catch (e) {
      logger?.warn({ err: e.message }, "pusher_relay_event_handling_failed");
    }
  }

  connect();

  return {
    syncSubscriptions,
    handleLiveEvent,
    close() {
      isClosed = true;
      stopHeartbeat();
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
      if (ws) {
        ws.close();
        ws = null;
      }
    },
  };
}