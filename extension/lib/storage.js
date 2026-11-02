/* PhishGuard — local storage layer (settings, history, cache, session) */
(function () {
  "use strict";

  const PG = (globalThis.PG = globalThis.PG || {});
  const { invoke, api, clamp, randomId, sha256Hex } = PG.utils;
  const CONST = PG.constants;

  const KEYS = {
    settings: "pg_settings",
    history: "pg_history",
    cache: "pg_cache",
    hosts: "pg_hosts",
    stats: "pg_stats",
    sessionPrefix: "pg_s:",
  };

  const SCHEMA_VERSION = 2;

  const DEFAULT_SETTINGS = {
    schemaVersion: SCHEMA_VERSION,
    protection: true,
    blockMalicious: true,
    blockSuspicious: false,
    blockThreshold: 70,
    suspiciousThreshold: 40,
    notifications: true,
    pageBanners: true,
    markLinks: true,
    scanOnVisit: true,
    deepScanOnVisit: false,
    apiKeys: { urlhaus: "", virustotal: "" },
    allowlist: [],
    cacheTtlHours: 12,
    historyLimit: 100,
    redactHistory: true,
    showScoreBadge: true,
    warnOnHttpLogin: true,
  };

  let settingsCache = null;
  let settingsLoad = null;
  let invalidationBound = false;

  function sanitizeSettings(input) {
    const out = { ...DEFAULT_SETTINGS };
    if (!input || typeof input !== "object") return out;

    const boolKeys = [
      "protection", "blockMalicious", "blockSuspicious", "notifications",
      "pageBanners", "markLinks", "scanOnVisit", "deepScanOnVisit",
      "redactHistory", "showScoreBadge", "warnOnHttpLogin",
    ];
    for (const key of boolKeys) {
      if (typeof input[key] === "boolean") out[key] = input[key];
    }

    const num = (value, min, max, fallback) => {
      const n = Number(value);
      return Number.isFinite(n) ? clamp(Math.round(n), min, max) : fallback;
    };
    out.blockThreshold = num(input.blockThreshold, 50, 100, DEFAULT_SETTINGS.blockThreshold);
    out.suspiciousThreshold = num(input.suspiciousThreshold, 10, 90, DEFAULT_SETTINGS.suspiciousThreshold);
    if (out.suspiciousThreshold >= out.blockThreshold) {
      out.suspiciousThreshold = Math.max(10, out.blockThreshold - 10);
    }
    out.cacheTtlHours = num(input.cacheTtlHours, 1, 168, DEFAULT_SETTINGS.cacheTtlHours);
    out.historyLimit = num(input.historyLimit, 10, 500, DEFAULT_SETTINGS.historyLimit);

    const keys = input.apiKeys && typeof input.apiKeys === "object" ? input.apiKeys : {};
    out.apiKeys = {
      urlhaus: typeof keys.urlhaus === "string" ? keys.urlhaus.trim().slice(0, 200) : "",
      virustotal: typeof keys.virustotal === "string" ? keys.virustotal.trim().slice(0, 200) : "",
    };

    out.allowlist = Array.isArray(input.allowlist)
      ? [...new Set(input.allowlist
        .map((entry) => normalizeHost(entry))
        .filter(Boolean))]
        .slice(0, 500)
      : [];

    return out;
  }

  function normalizeHost(value) {
    let host = String(value == null ? "" : value).trim().toLowerCase();
    if (!host) return "";
    host = host.replace(/^\*\./, "").replace(/^https?:\/\//, "").replace(/\/.*$/, "");
    host = host.replace(/^\.+/, "").replace(/\.+$/, "");
    if (!/^[a-z0-9._-]+$/.test(host)) return "";
    if (!host.includes(".") && host !== "localhost") return "";
    return host;
  }

  async function readKey(key, fallback) {
    try {
      const data = await invoke(api.storage.local, "get", key);
      const value = data ? data[key] : undefined;
      return value === undefined || value === null ? fallback : value;
    } catch {
      return fallback;
    }
  }

  async function writeKey(key, value) {
    try {
      await invoke(api.storage.local, "set", { [key]: value });
      return true;
    } catch {
      return false;
    }
  }

  function bindInvalidation() {
    if (invalidationBound || !api.storage || !api.storage.onChanged) return;
    invalidationBound = true;
    api.storage.onChanged.addListener((changes, area) => {
      if (area !== "local") return;
      if (changes[KEYS.settings]) {
        settingsCache = sanitizeSettings(changes[KEYS.settings].newValue);
      }
    });
  }

  async function getSettings(force) {
    bindInvalidation();
    if (settingsCache && !force) return { ...settingsCache, apiKeys: { ...settingsCache.apiKeys }, allowlist: [...settingsCache.allowlist] };
    if (settingsLoad) return settingsLoad;
    settingsLoad = (async () => {
      const raw = await readKey(KEYS.settings, null);
      settingsCache = sanitizeSettings(raw);
      settingsLoad = null;
      return { ...settingsCache, apiKeys: { ...settingsCache.apiKeys }, allowlist: [...settingsCache.allowlist] };
    })();
    return settingsLoad;
  }

  async function saveSettings(patch) {
    const current = await getSettings(true);
    const next = sanitizeSettings({ ...current, ...(patch || {}), apiKeys: { ...current.apiKeys, ...((patch && patch.apiKeys) || {}) } });
    settingsCache = next;
    await writeKey(KEYS.settings, next);
    return next;
  }

  async function resetSettings() {
    settingsCache = { ...DEFAULT_SETTINGS, apiKeys: { ...DEFAULT_SETTINGS.apiKeys }, allowlist: [] };
    await writeKey(KEYS.settings, settingsCache);
    return settingsCache;
  }

  function isAllowlisted(host, settings) {
    const h = String(host || "").toLowerCase();
    if (!h) return false;
    const list = (settings && settings.allowlist) || [];
    return list.some((entry) => h === entry || h.endsWith(`.${entry}`));
  }

  async function addToAllowlist(value) {
    const host = normalizeHost(value);
    if (!host) throw new Error("Enter a valid domain, e.g. example.com");
    const settings = await getSettings();
    if (!isAllowlisted(host, settings)) {
      settings.allowlist = [...settings.allowlist, host];
      await saveSettings({ allowlist: settings.allowlist });
    }
    return host;
  }

  async function removeFromAllowlist(value) {
    const host = normalizeHost(value);
    const settings = await getSettings();
    await saveSettings({ allowlist: settings.allowlist.filter((entry) => entry !== host) });
    return host;
  }

  async function isTrustedDomain(host) {
    const root = PG.utils.rootDomain(host);
    const settings = await getSettings();
    if (isAllowlisted(host, settings)) return true;
    return CONST.TRUSTED_DOMAINS.has(root) || CONST.TRUSTED_DOMAINS.has(host);
  }

  async function getHistory(limit) {
    const list = await readKey(KEYS.history, []);
    const safe = Array.isArray(list) ? list : [];
    return Number.isFinite(limit) ? safe.slice(0, limit) : safe;
  }

  async function addHistory(entry) {
    if (!entry || !entry.url) return null;
    const settings = await getSettings();
    const item = {
      id: entry.id || randomId(),
      url: entry.url,
      host: entry.host || PG.utils.hostOf(entry.url),
      score: clamp(Number(entry.score) || 0, 0, 100),
      level: entry.level || "safe",
      reasons: Array.isArray(entry.reasons) ? entry.reasons.slice(0, 8) : [],
      sources: entry.sources || null,
      deep: !!entry.deep,
      trigger: entry.trigger || "manual",
      createdAt: entry.createdAt || Date.now(),
    };
    const list = await getHistory();
    list.unshift(item);
    // De-duplicate rapid repeats of the same URL.
    const seen = new Set();
    const trimmed = [];
    for (const row of list) {
      const key = `${row.url}|${Math.floor((row.createdAt || 0) / 60000)}`;
      if (seen.has(key)) continue;
      seen.add(key);
      trimmed.push(row);
      if (trimmed.length >= settings.historyLimit) break;
    }
    await writeKey(KEYS.history, trimmed);
    return item;
  }

  async function clearHistory() {
    await writeKey(KEYS.history, []);
    return true;
  }

  async function getStats() {
    const stats = await readKey(KEYS.stats, null);
    return {
      scans: 0,
      deepScans: 0,
      blocked: 0,
      lastScanAt: 0,
      installedAt: Date.now(),
      ...(stats && typeof stats === "object" ? stats : {}),
    };
  }

  async function bumpStats(patch) {
    const stats = await getStats();
    for (const [key, value] of Object.entries(patch || {})) {
      if (typeof value === "number" && key !== "installedAt") {
        stats[key] = (Number(stats[key]) || 0) + value;
      } else {
        stats[key] = value;
      }
    }
    stats.lastScanAt = Date.now();
    await writeKey(KEYS.stats, stats);
    return stats;
  }

  async function getCache() {
    const cache = await readKey(KEYS.cache, {});
    return cache && typeof cache === "object" ? cache : {};
  }

  async function getCachedScan(url, settings) {
    const cfg = settings || (await getSettings());
    const key = await sha256Hex(url);
    const cache = await getCache();
    const entry = cache[key];
    if (!entry || !entry.result) return null;
    const ttl = (cfg.cacheTtlHours || 12) * 3600 * 1000;
    if (Date.now() - (entry.ts || 0) > ttl) return null;
    return { ...entry.result, cached: true };
  }

  async function setCachedScan(url, result, settings) {
    const cfg = settings || (await getSettings());
    const key = await sha256Hex(url);
    const cache = await getCache();
    cache[key] = { ts: Date.now(), result };
    await pruneCache(cache, cfg);
    return true;
  }

  async function pruneCache(cacheInput, settings) {
    const cfg = settings || (await getSettings());
    const now = Date.now();
    const ttl = (cfg.cacheTtlHours || 12) * 3600 * 1000;
    const cache = cacheInput || (await getCache());
    const entries = Object.entries(cache)
      .filter(([, value]) => value && now - (value.ts || 0) <= ttl)
      .sort((a, b) => (b[1].ts || 0) - (a[1].ts || 0))
      .slice(0, 400);
    const out = Object.fromEntries(entries);
    if (!cacheInput) await writeKey(KEYS.cache, out);
    return out;
  }

  async function getHostVerdicts() {
    const hosts = await readKey(KEYS.hosts, {});
    return hosts && typeof hosts === "object" ? hosts : {};
  }

  async function getHostVerdict(host) {
    if (!host) return null;
    const hosts = await getHostVerdicts();
    const root = PG.utils.rootDomain(host);
    const entry = hosts[host] || hosts[root];
    if (!entry) return null;
    const maxAge = entry.level === "malicious" ? 7 * 24 * 3600 * 1000 : 24 * 3600 * 1000;
    if (Date.now() - (entry.ts || 0) > maxAge) return null;
    return entry;
  }

  async function setHostVerdict(host, result) {
    if (!host || !result) return;
    if (result.level === "safe" && !(result.sources && result.sources.urlhaus && result.sources.urlhaus.listed)) return;
    const hosts = await getHostVerdicts();
    hosts[PG.utils.rootDomain(host)] = {
      score: result.score,
      level: result.level,
      reasons: (result.reasons || []).slice(0, 8),
      sources: result.sources || null,
      deep: !!result.deep,
      ts: Date.now(),
    };
    const entries = Object.entries(hosts)
      .sort((a, b) => (b[1].ts || 0) - (a[1].ts || 0))
      .slice(0, 800);
    await writeKey(KEYS.hosts, Object.fromEntries(entries));
  }

  async function getBadHosts() {
    const hosts = await getHostVerdicts();
    return Object.entries(hosts)
      .filter(([, value]) => value && (value.level === "malicious" || value.level === "suspicious"))
      .map(([host, value]) => ({ host, level: value.level, score: value.score, ts: value.ts }));
  }

  async function clearCache() {
    await writeKey(KEYS.cache, {});
    await writeKey(KEYS.hosts, {});
    return true;
  }

  /* ------------------------------ session ------------------------------ */

  function hasSessionStorage() {
    return !!(api.storage && api.storage.session && api.storage.session.get);
  }

  async function sessionGet(key) {
    try {
      if (hasSessionStorage()) {
        const data = await invoke(api.storage.session, "get", key);
        return data ? data[key] : undefined;
      }
      const data = await invoke(api.storage.local, "get", KEYS.sessionPrefix + key);
      return data ? data[KEYS.sessionPrefix + key] : undefined;
    } catch {
      return undefined;
    }
  }

  async function sessionSet(key, value) {
    try {
      if (hasSessionStorage()) {
        await invoke(api.storage.session, "set", { [key]: value });
      } else {
        await invoke(api.storage.local, "set", { [KEYS.sessionPrefix + key]: value });
      }
      return true;
    } catch {
      return false;
    }
  }

  async function sessionRemove(key) {
    try {
      if (hasSessionStorage() && api.storage.session.remove) {
        await invoke(api.storage.session, "remove", key);
      } else {
        await invoke(api.storage.local, "remove", KEYS.sessionPrefix + key);
      }
      return true;
    } catch {
      return false;
    }
  }

  /* ------------------------------ export ------------------------------- */

  async function exportAll() {
    const data = await invoke(api.storage.local, "get", null);
    return {
      exportedAt: new Date().toISOString(),
      app: "PhishGuard",
      schemaVersion: SCHEMA_VERSION,
      data,
    };
  }

  async function importAll(payload) {
    const data = payload && payload.data ? payload.data : payload;
    if (!data || typeof data !== "object") throw new Error("Invalid backup file");
    const allowed = {};
    for (const key of Object.values(KEYS)) {
      if (key.startsWith("pg_s:")) continue;
      if (data[key] !== undefined) allowed[key] = data[key];
    }
    if (!allowed[KEYS.settings]) throw new Error("Backup does not contain PhishGuard settings");
    allowed[KEYS.settings] = sanitizeSettings(allowed[KEYS.settings]);
    await invoke(api.storage.local, "set", allowed);
    settingsCache = null;
    return true;
  }

  async function resetAll() {
    await invoke(api.storage.local, "clear");
    // Bypasses, cached verdicts and tab state live in session storage too.
    if (api.storage.session && api.storage.session.clear) {
      try {
        await invoke(api.storage.session, "clear");
      } catch {
        /* session storage may be unavailable */
      }
    }
    settingsCache = null;
    return true;
  }

  PG.storage = {
    KEYS,
    DEFAULT_SETTINGS,
    SCHEMA_VERSION,
    normalizeHost,
    getSettings,
    saveSettings,
    resetSettings,
    isAllowlisted,
    addToAllowlist,
    removeFromAllowlist,
    isTrustedDomain,
    getHistory,
    addHistory,
    clearHistory,
    getStats,
    bumpStats,
    getCachedScan,
    setCachedScan,
    pruneCache,
    getHostVerdicts,
    getHostVerdict,
    setHostVerdict,
    getBadHosts,
    clearCache,
    sessionGet,
    sessionSet,
    sessionRemove,
    exportAll,
    importAll,
    resetAll,
  };
})();
