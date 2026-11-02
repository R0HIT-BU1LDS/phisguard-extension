/* PhishGuard — MV3 background worker (navigation guard, badges, messaging) */
"use strict";

// Chrome loads classic worker scripts via importScripts; Firefox loads the
// same files through manifest "background.scripts" before this file runs.
if (typeof importScripts === "function" && !(globalThis.PG && globalThis.PG.scanner)) {
  importScripts(
    "lib/utils.js",
    "lib/constants.js",
    "lib/storage.js",
    "lib/heuristics.js",
    "lib/providers.js",
    "lib/scanner.js",
    "lib/local-keys.js",
  );
}

(function () {
  const PG = globalThis.PG;
  const { api, invoke, hostOf, parseUrl, isLocalHost } = PG.utils;
  const storage = PG.storage;
  const scanner = PG.scanner;
  const action = api.action || api.browserAction;

  const BADGE_COLORS = { safe: "#22c55e", suspicious: "#f59e0b", malicious: "#ef4444" };
  const BYPASS_MS = 10 * 60 * 1000;
  const NAV_DEDUPE_MS = 1200;

  const tabStates = new Map();      // tabId -> { url, host, result, ts, dismissed }
  const bypassHosts = new Map();    // host -> expiry timestamp
  const navGuards = new Map();      // tabId -> { url, ts }
  const blockingTabs = new Set();   // tabId currently being redirected
  const deepScans = new Map();      // tabId -> url currently being deep-scanned

  /* ----------------------------- small helpers ----------------------------- */

  function isWebUrl(url) {
    return typeof url === "string" && /^https?:\/\//i.test(url);
  }

  function isExtensionUrl(url) {
    try {
      return typeof url === "string" && url.startsWith(api.runtime.getURL(""));
    } catch {
      return false;
    }
  }

  function extensionPage(path, params) {
    const base = api.runtime.getURL(path);
    if (!params) return base;
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== null && value !== "") query.set(key, String(value));
    }
    const qs = query.toString();
    return qs ? `${base}?${qs}` : base;
  }

  function warningUrl(result) {
    return extensionPage("warning/warning.html", { id: result.id, u: result.url });
  }

  function appUrl(params) {
    return extensionPage("app/app.html", params);
  }

  async function safeCall(area, method, ...args) {
    try {
      return await invoke(area, method, ...args);
    } catch {
      return null;
    }
  }

  async function saveTabState(tabId, state) {
    if (tabId == null || tabId < 0) return;
    tabStates.set(tabId, state);
    await storage.sessionSet(`tab:${tabId}`, state);
  }

  async function readTabState(tabId) {
    if (tabStates.has(tabId)) return tabStates.get(tabId);
    const state = await storage.sessionGet(`tab:${tabId}`);
    if (state) tabStates.set(tabId, state);
    return state || null;
  }

  async function clearTabState(tabId) {
    tabStates.delete(tabId);
    await storage.sessionRemove(`tab:${tabId}`);
  }

  async function getSettings() {
    return storage.getSettings();
  }

  /* -------------------------------- badges -------------------------------- */

  async function updateBadge(tabId, result, settings) {
    if (!action || tabId == null || tabId < 0) return;
    try {
      if (!result || result.skipped) {
        await safeCall(action, "setBadgeText", { tabId, text: "" });
        await safeCall(action, "setTitle", { tabId, title: "PhishGuard" });
        return;
      }
      if (result.trusted === "allowlist") {
        await safeCall(action, "setBadgeText", { tabId, text: "" });
        await safeCall(action, "setTitle", { tabId, title: `PhishGuard: trusted site — ${result.host}` });
        return;
      }
      const cfg = settings || (await getSettings());
      const label = PG.utils.levelLabel(result.level);
      const show = cfg.showScoreBadge && result.level !== "safe";
      await safeCall(action, "setBadgeText", { tabId, text: show ? String(result.score) : "" });
      if (show) {
        await safeCall(action, "setBadgeBackgroundColor", { tabId, color: BADGE_COLORS[result.level] || "#38bdf8" });
      }
      await safeCall(action, "setTitle", {
        tabId,
        title: `PhishGuard: ${label} — ${result.host} (${result.score}/100)`,
      });
    } catch {
      /* tab may have closed */
    }
  }

  async function refreshActiveBadge() {
    try {
      const tabs = await invoke(api.tabs, "query", { active: true, currentWindow: true });
      const tab = tabs && tabs[0];
      if (!tab) return;
      const state = await readTabState(tab.id);
      const settings = await getSettings();
      if (state && state.result && (state.url === tab.url || (state.blocked && !isWebUrl(tab.url)))) {
        await updateBadge(tab.id, state.result, settings);
      } else {
        await updateBadge(tab.id, null, settings);
      }
    } catch {
      /* ignore */
    }
  }

  /* ------------------------------ notifications --------------------------- */

  async function notify(result, kind) {
    const settings = await getSettings();
    if (!settings.notifications) return;
    if (!result || result.level === "safe") return;
    if (result.level === "suspicious" && kind === "blocked") return;
    if (!api.notifications || !api.notifications.create) return;

    const id = `pg-${result.id}-${kind}`;
    await storage.sessionSet(`notif:${id}`, { scanId: result.id, url: result.url, kind });
    const title = kind === "blocked"
      ? "PhishGuard blocked a dangerous site"
      : result.level === "malicious"
        ? "PhishGuard warning: malicious site detected"
        : "PhishGuard warning: suspicious site";
    const message = `${result.host} scored ${result.score}/100 (${PG.utils.levelLabel(result.level)})`;

    try {
      await invoke(api.notifications, "create", id, {
        type: "basic",
        iconUrl: api.runtime.getURL("icons/icon128.png"),
        title,
        message,
        priority: 2,
        requireInteraction: kind === "blocked",
      });
    } catch {
      try {
        await invoke(api.notifications, "create", {
          type: "basic",
          iconUrl: api.runtime.getURL("icons/icon128.png"),
          title,
          message,
        });
      } catch {
        /* notifications unavailable */
      }
    }
  }

  /* -------------------------------- bypasses ------------------------------ */

  async function isBypassed(host) {
    if (!host) return false;
    const cached = bypassHosts.get(host);
    if (cached && cached > Date.now()) return true;
    const stored = await storage.sessionGet(`bypass:${host}`);
    if (typeof stored === "number" && stored > Date.now()) {
      bypassHosts.set(host, stored);
      return true;
    }
    return false;
  }

  async function setBypass(host, ms) {
    const until = Date.now() + (ms || BYPASS_MS);
    bypassHosts.set(host, until);
    await storage.sessionSet(`bypass:${host}`, until);
    return until;
  }

  /* ----------------------------- scan + guard ----------------------------- */

  async function scanForNavigation(url, settings) {
    return scanner.scan(url, {
      deep: false,
      record: false,
      trigger: "navigation",
      settings,
    });
  }

  async function blockTab(tabId, result, options) {
    if (tabId == null || tabId < 0) return false;
    if (blockingTabs.has(tabId)) return false;
    blockingTabs.add(tabId);
    try {
      const settings = await getSettings();
      if (!scanner.shouldBlock(result, settings)) return false;

      // Remember where the user came from so "Back to safety" has somewhere safe to go.
      const tab = await safeCall(api.tabs, "get", tabId);
      if (tab && isWebUrl(tab.url) && tab.url !== result.url) {
        result.previousUrl = tab.url;
      }

      await storage.sessionSet(`scan:${result.id}`, result);
      await saveTabState(tabId, {
        tabId,
        url: result.url,
        host: result.host,
        result,
        ts: Date.now(),
        blocked: true,
        previousUrl: result.previousUrl || null,
      });
      await storage.bumpStats({ blocked: 1 });
      await updateBadge(tabId, result, settings);
      await notify(result, "blocked");

      if (!(options && options.dryRun)) {
        await safeCall(api.tabs, "update", tabId, { url: warningUrl(result) });
      }
      return true;
    } finally {
      setTimeout(() => blockingTabs.delete(tabId), 1500);
    }
  }

  async function runNavigationGuard(details) {
    if (!details || details.frameId !== 0) return;
    if (!isWebUrl(details.url)) return;
    if (isExtensionUrl(details.url)) return;

    const settings = await getSettings();
    if (!settings.protection || !settings.scanOnVisit) return;

    const host = hostOf(details.url);
    if (!host || isLocalHost(host)) return;
    if (await isBypassed(host)) return;

    const guard = navGuards.get(details.tabId);
    if (guard && guard.url === details.url && Date.now() - guard.ts < NAV_DEDUPE_MS) return;
    navGuards.set(details.tabId, { url: details.url, ts: Date.now() });

    const result = await scanForNavigation(details.url, settings);
    await saveTabState(details.tabId, {
      tabId: details.tabId,
      url: details.url,
      host,
      result,
      ts: Date.now(),
      blocked: false,
    });
    await updateBadge(details.tabId, result, settings);

    if (scanner.shouldBlock(result, settings)) {
      await blockTab(details.tabId, result);
    }
  }

  async function maybeDeepScanOnVisit(tabId, url, existing) {
    const settings = await getSettings();
    if (!settings.protection || !settings.deepScanOnVisit) return;
    const configured = PG.providers.configured(settings.apiKeys);
    if (!configured.any) return;
    const host = hostOf(url);
    if (!host || isLocalHost(host)) return;
    if (await isBypassed(host)) return;
    if (existing && (existing.trusted === "allowlist" || existing.trusted === "reputation")) return;

    const key = `${tabId}`;
    if (deepScans.get(key) === url) return;
    deepScans.set(key, url);
    try {
      const result = await scanner.scan(url, {
        deep: true,
        record: "risky",
        trigger: "auto",
        settings,
      });
      const state = await readTabState(tabId);
      if (state && state.url !== url) return; // user navigated away
      await saveTabState(tabId, { ...state, tabId, url, host, result, ts: Date.now() });
      await updateBadge(tabId, result, settings);
      await pushBanner(tabId, result);
      if (scanner.shouldBlock(result, settings) && !(await isBypassed(host))) {
        await blockTab(tabId, result);
      }
    } catch {
      /* ignore network failures */
    } finally {
      if (deepScans.get(key) === url) deepScans.delete(key);
    }
  }

  async function pushBanner(tabId, result) {
    const settings = await getSettings();
    if (!settings.pageBanners) return;
    await safeCall(api.tabs, "sendMessage", tabId, { type: "PG_SHOW_BANNER", result });
  }

  async function handleCommitted(details) {
    if (!details || details.frameId !== 0) return;
    if (!isWebUrl(details.url)) return;
    const settings = await getSettings();
    if (!settings.protection || !settings.scanOnVisit) return;

    const host = hostOf(details.url);
    if (!host || isLocalHost(host)) return;

    let state = await readTabState(details.tabId);
    if (!state || state.url !== details.url) {
      const result = await scanForNavigation(details.url, settings);
      state = { tabId: details.tabId, url: details.url, host, result, ts: Date.now(), blocked: false };
      await saveTabState(details.tabId, state);
      await updateBadge(details.tabId, result, settings);
      if (scanner.shouldBlock(result, settings) && !(await isBypassed(host))) {
        await blockTab(details.tabId, result);
        return;
      }
    }

    if (settings.deepScanOnVisit && !state.blocked) {
      maybeDeepScanOnVisit(details.tabId, details.url, state.result);
    }
  }

  /* ------------------------------ tab helpers ----------------------------- */

  /**
   * Popup messages have no sender.tab, so resolve the focused tab explicitly.
   * Without this "PG_TAB_STATE" / "PG_SCAN_TAB" fail with no tab id.
   */
  async function resolveActiveTabId() {
    const tabs = await safeCall(api.tabs, "query", { active: true, currentWindow: true });
    const tab = tabs && tabs[0];
    return tab && tab.id != null ? tab.id : null;
  }

  async function getTabState(requestedTabId) {
    let tabId = requestedTabId;
    if (tabId == null || tabId < 0) tabId = await resolveActiveTabId();
    if (tabId == null) return { tab: null, unsupported: true, result: null };

    const tab = await safeCall(api.tabs, "get", tabId);
    if (!tab) return { tab: null, unsupported: true, result: null };
    const url = tab.url || tab.pendingUrl || "";
    const settings = await getSettings();
    let state = await readTabState(tabId);

    if (!isWebUrl(url)) {
      return {
        tab: { id: tab.id, url, title: tab.title || "" },
        url,
        unsupported: true,
        isWarning: isExtensionUrl(url) && url.includes("warning/warning.html"),
        result: null,
        settings: publicSettings(settings),
      };
    }

    if (!state || state.url !== url) {
      const result = await scanner.scan(url, { deep: false, record: false, trigger: "tab", settings });
      state = { tabId, url, host: hostOf(url), result, ts: Date.now(), blocked: false };
      await saveTabState(tabId, state);
      await updateBadge(tabId, result, settings);
    }

    return {
      tab: { id: tab.id, url, title: tab.title || "" },
      url,
      host: state.host,
      result: state.result,
      blocked: !!state.blocked,
      settings: publicSettings(settings),
    };
  }

  function publicSettings(settings) {
    return {
      protection: settings.protection,
      blockMalicious: settings.blockMalicious,
      blockSuspicious: settings.blockSuspicious,
      blockThreshold: settings.blockThreshold,
      suspiciousThreshold: settings.suspiciousThreshold,
      notifications: settings.notifications,
      pageBanners: settings.pageBanners,
      markLinks: settings.markLinks,
      deepScanOnVisit: settings.deepScanOnVisit,
      scanOnVisit: settings.scanOnVisit,
      keys: PG.providers.configured(settings.apiKeys),
      allowlist: settings.allowlist.slice(0, 200),
    };
  }

  /* -------------------------------- messages ------------------------------ */

  async function handleMessage(message, sender) {
    const type = message && message.type;
    const senderTabId = sender && sender.tab ? sender.tab.id : undefined;

    switch (type) {
      case "PG_PING":
        return { ok: true, version: api.runtime.getManifest().version };

      case "PG_SETTINGS_GET":
        return publicSettings(await getSettings());

      case "PG_SETTINGS_FULL":
        return getSettings();

      case "PG_SETTINGS_SET": {
        const saved = await storage.saveSettings(message.settings || {});
        await refreshActiveBadge();
        return publicSettings(saved);
      }

      case "PG_SETTINGS_RESET": {
        const saved = await storage.resetSettings();
        await refreshActiveBadge();
        return publicSettings(saved);
      }

      case "PG_TAB_STATE":
        return getTabState(message.tabId != null ? message.tabId : senderTabId);

      case "PG_SCAN": {
        const settings = await getSettings();
        const result = await scanner.scan(message.url, {
          deep: !!message.deep,
          force: !!message.force,
          trigger: message.trigger || "manual",
          record: message.record === false ? false : message.record,
          settings,
        });
        const tabId = message.tabId != null ? message.tabId : senderTabId;
        if (tabId != null && isWebUrl(message.url)) {
          const state = await readTabState(tabId);
          const isCurrentTab = state && state.url === result.url;
          if (isCurrentTab) {
            await saveTabState(tabId, { ...state, result, ts: Date.now() });
            await updateBadge(tabId, result, settings);
            await pushBanner(tabId, result);
          }
        }
        return result;
      }

      case "PG_SCAN_TAB": {
        let tabId = message.tabId != null ? message.tabId : senderTabId;
        if (tabId == null) tabId = await resolveActiveTabId();
        const tab = tabId == null ? null : await safeCall(api.tabs, "get", tabId);
        if (!tab || !isWebUrl(tab.url)) throw new Error("This tab cannot be scanned");
        const settings = await getSettings();
        const result = await scanner.scan(tab.url, {
          deep: message.deep !== false,
          force: !!message.force,
          trigger: "manual",
          settings,
        });
        await saveTabState(tabId, { tabId, url: tab.url, host: hostOf(tab.url), result, ts: Date.now(), blocked: false });
        await updateBadge(tabId, result, settings);
        await pushBanner(tabId, result);
        return result;
      }

      case "PG_HISTORY":
        return storage.getHistory(message.limit || 100);

      case "PG_HISTORY_CLEAR":
        await storage.clearHistory();
        return true;

      case "PG_STATS":
        return storage.getStats();

      case "PG_ALLOWLIST_ADD": {
        const host = await storage.addToAllowlist(message.host);
        await refreshActiveBadge();
        return { host };
      }

      case "PG_ALLOWLIST_REMOVE": {
        const host = await storage.removeFromAllowlist(message.host);
        await refreshActiveBadge();
        return { host };
      }

      case "PG_ALLOWLIST_CHECK":
        return { allowlisted: storage.isAllowlisted(message.host, await getSettings()) };

      case "PG_BYPASS": {
        const host = PG.storage.normalizeHost(message.host);
        if (!host) throw new Error("Invalid host");
        const until = await setBypass(host, message.ms);
        return { host, until };
      }

      case "PG_PROCEED": {
        const parsed = parseUrl(message.url);
        if (!parsed) throw new Error("Invalid URL");
        await setBypass(parsed.host);
        const tabId = senderTabId != null ? senderTabId : message.tabId;
        if (tabId != null) {
          await safeCall(api.tabs, "update", tabId, { url: parsed.url });
        } else {
          await safeCall(api.tabs, "create", { url: parsed.url });
        }
        return { url: parsed.url };
      }

      case "PG_TRUST": {
        const parsed = parseUrl(message.url);
        if (!parsed) throw new Error("Invalid URL");
        const host = await storage.addToAllowlist(parsed.host);
        const settings = await getSettings();
        await storage.bumpStats({ allowed: 1 });
        if (message.clearVerdict) {
          const hosts = await storage.getHostVerdicts();
          if (hosts[parsed.registrable]) {
            delete hosts[parsed.registrable];
            await invoke(api.storage.local, "set", { [storage.KEYS.hosts]: hosts });
          }
        }
        if (message.proceed) {
          await setBypass(parsed.host);
          const tabId = senderTabId != null ? senderTabId : message.tabId;
          if (tabId != null) await safeCall(api.tabs, "update", tabId, { url: parsed.url });
          else await safeCall(api.tabs, "create", { url: parsed.url });
        }
        await refreshActiveBadge();
        return { host, settings: publicSettings(settings) };
      }

      case "PG_OPEN_WARNING": {
        const result = message.result || (message.url ? await scanner.scan(message.url, { deep: false, record: false, trigger: "manual" }) : null);
        if (!result) throw new Error("Nothing to show");
        await storage.sessionSet(`scan:${result.id}`, result);
        await safeCall(api.tabs, "create", { url: warningUrl(result) });
        return { id: result.id };
      }

      case "PG_BACK_TO_SAFETY": {
        const tabId = senderTabId != null ? senderTabId : message.tabId;
        const previous = message.previousUrl;
        if (tabId == null) return { closed: false };
        if (isWebUrl(previous)) {
          await safeCall(api.tabs, "update", tabId, { url: previous });
          return { navigated: previous };
        }
        const removed = await safeCall(api.tabs, "remove", tabId);
        if (removed !== null) return { closed: true };
        await safeCall(api.tabs, "update", tabId, { url: appUrl() });
        return { closed: false };
      }

      case "PG_LEAVE_TO_WARNING": {
        const result = message.result;
        if (!result) throw new Error("Nothing to show");
        await storage.sessionSet(`scan:${result.id}`, result);
        if (senderTabId != null) {
          await safeCall(api.tabs, "update", senderTabId, { url: warningUrl(result) });
        } else {
          await safeCall(api.tabs, "create", { url: warningUrl(result) });
        }
        return true;
      }

      case "PG_OPEN_APP": {
        const url = appUrl({ u: message.url || "", deep: message.deep ? "1" : "" });
        await safeCall(api.tabs, "create", { url });
        return { url };
      }

      case "PG_OPEN_OPTIONS":
        await safeCall(api.runtime, "openOptionsPage");
        return true;

      case "PG_GET_SCAN":
        return storage.sessionGet(`scan:${message.id}`);

      case "PG_BAD_HOSTS":
        return storage.getBadHosts();

      case "PG_CLEAR_CACHE":
        await storage.clearCache();
        return true;

      case "PG_EXPORT":
        return storage.exportAll();

      case "PG_IMPORT": {
        await storage.importAll(message.payload);
        return true;
      }

      case "PG_RESET_ALL":
        await storage.resetAll();
        bypassHosts.clear();
        tabStates.clear();
        navGuards.clear();
        deepScans.clear();
        await refreshActiveBadge();
        return true;

      case "PG_PAGE_STATUS": {
        const tabId = senderTabId;
        if (tabId == null) return null;
        const settings = await getSettings();
        const state = await readTabState(tabId);
        let result = state && state.url === (sender.tab && sender.tab.url) ? state.result : null;
        if (!result && sender.tab && isWebUrl(sender.tab.url)) {
          result = await scanner.scan(sender.tab.url, { deep: false, record: false, trigger: "page", settings });
          await saveTabState(tabId, { tabId, url: sender.tab.url, host: hostOf(sender.tab.url), result, ts: Date.now() });
          await updateBadge(tabId, result, settings);
        }
        return {
          result,
          host: sender.tab ? hostOf(sender.tab.url) : "",
          settings: {
            protection: settings.protection,
            pageBanners: settings.pageBanners,
            markLinks: settings.markLinks,
            warnOnHttpLogin: settings.warnOnHttpLogin,
          },
          badHosts: settings.markLinks ? await storage.getBadHosts() : [],
        };
      }

      case "PG_BANNER_DISMISSED": {
        if (senderTabId == null) return true;
        const state = await readTabState(senderTabId);
        if (state) await saveTabState(senderTabId, { ...state, dismissed: true, dismissedAt: Date.now() });
        return true;
      }

      case "PG_REPORT_FALSE_POSITIVE": {
        const parsed = parseUrl(message.url || (sender.tab && sender.tab.url));
        if (!parsed) throw new Error("Invalid URL");
        await storage.addToAllowlist(parsed.host);
        await storage.bumpStats({ falsePositives: 1 });
        await refreshActiveBadge();
        return { host: parsed.host };
      }

      case "PG_NOTIFY_TEST": {
        const settings = await getSettings();
        if (!settings.notifications) throw new Error("Notifications are turned off in settings");
        await invoke(api.notifications, "create", {
          type: "basic",
          iconUrl: api.runtime.getURL("icons/icon128.png"),
          title: "PhishGuard test alert",
          message: "Notifications are working. You will be alerted about dangerous sites.",
        });
        return true;
      }

      default:
        throw new Error(`Unknown message type: ${type}`);
    }
  }

  api.runtime.onMessage.addListener((message, sender, sendResponse) => {
    Promise.resolve()
      .then(() => handleMessage(message, sender))
      .then((data) => sendResponse({ ok: true, data }))
      .catch((err) => sendResponse({ ok: false, error: (err && err.message) || String(err) }));
    return true; // async response
  });

  /* ------------------------------ event wiring ---------------------------- */

  api.webNavigation.onBeforeNavigate.addListener((details) => {
    runNavigationGuard(details).catch(() => {});
  });

  api.webNavigation.onHistoryStateUpdated.addListener((details) => {
    runNavigationGuard(details).catch(() => {});
  });

  api.webNavigation.onCommitted.addListener((details) => {
    handleCommitted(details).catch(() => {});
  });

  api.tabs.onRemoved.addListener((tabId) => {
    clearTabState(tabId);
    navGuards.delete(tabId);
    deepScans.delete(tabId);
  });

  api.tabs.onActivated.addListener(async (info) => {
    try {
      const state = await readTabState(info.tabId);
      const settings = await getSettings();
      if (state && state.result) await updateBadge(info.tabId, state.result, settings);
    } catch {
      /* ignore */
    }
  });

  api.storage.onChanged.addListener((changes, area) => {
    if (area !== "local" || !changes[storage.KEYS.settings]) return;
    refreshActiveBadge();
  });

  /* ------------------------------ context menus --------------------------- */

  async function createContextMenus() {
    if (!api.contextMenus) return;
    await safeCall(api.contextMenus, "removeAll");
    const items = [
      { id: "pg-scan-link", title: "Scan link with PhishGuard", contexts: ["link"] },
      { id: "pg-scan-page", title: "Scan this page with PhishGuard", contexts: ["page"] },
      { id: "pg-scan-selection", title: "Scan selected URL with PhishGuard", contexts: ["selection"] },
      { id: "pg-trust-site", title: "Trust this site with PhishGuard", contexts: ["page"] },
    ];
    for (const item of items) {
      try {
        await invoke(api.contextMenus, "create", item);
      } catch {
        /* menu may already exist */
      }
    }
  }

  async function contextScan(url) {
    const settings = await getSettings();
    const result = await scanner.scan(url, { deep: true, trigger: "context", settings });
    await storage.sessionSet(`scan:${result.id}`, result);
    if (scanner.shouldBlock(result, settings) || result.level === "malicious") {
      await notify(result, "blocked");
      await safeCall(api.tabs, "create", { url: warningUrl(result) });
    } else {
      await safeCall(api.tabs, "create", { url: appUrl({ u: result.url }) });
    }
    return result;
  }

  if (api.contextMenus && api.contextMenus.onClicked) {
    api.contextMenus.onClicked.addListener(async (info, tab) => {
      try {
        if (info.menuItemId === "pg-scan-link" && info.linkUrl) {
          await contextScan(info.linkUrl);
        } else if (info.menuItemId === "pg-scan-page" && tab && isWebUrl(tab.url)) {
          const settings = await getSettings();
          const result = await scanner.scan(tab.url, { deep: true, trigger: "context", settings });
          await saveTabState(tab.id, { tabId: tab.id, url: tab.url, host: hostOf(tab.url), result, ts: Date.now() });
          await updateBadge(tab.id, result, settings);
          await pushBanner(tab.id, result);
          if (scanner.shouldBlock(result, settings)) await blockTab(tab.id, result);
          else await notify(result, "warning");
        } else if (info.menuItemId === "pg-scan-selection" && info.selectionText) {
          const candidate = info.selectionText.trim();
          if (PG.utils.isScannableUrl(candidate)) await contextScan(candidate);
          else await safeCall(api.tabs, "create", { url: appUrl({ u: candidate }) });
        } else if (info.menuItemId === "pg-trust-site" && tab && isWebUrl(tab.url)) {
          const host = await storage.addToAllowlist(hostOf(tab.url));
          await notify(
            { id: PG.utils.randomId(), url: tab.url, host, score: 0, level: "safe" },
            "warning",
          );
        }
      } catch {
        /* ignore */
      }
    });
  }

  /* -------------------------------- omnibox ------------------------------- */

  if (api.omnibox) {
    api.omnibox.onInputChanged.addListener((text, suggest) => {
      const value = text.trim();
      if (!value) return;
      suggest([
        { content: value, description: `Scan “${value}” with PhishGuard` },
        { content: value, description: "Opens the PhishGuard console with a deep scan" },
      ]);
    });
    api.omnibox.onInputEntered.addListener((text) => {
      const value = text.trim();
      if (!value) return;
      safeCall(api.tabs, "create", { url: appUrl({ u: value, deep: "1" }) });
    });
  }

  /* -------------------------------- commands ------------------------------ */

  if (api.commands && api.commands.onCommand) {
    api.commands.onCommand.addListener(async (command) => {
      try {
        const tabs = await invoke(api.tabs, "query", { active: true, currentWindow: true });
        const tab = tabs && tabs[0];
        if (!tab) return;
        if (command === "scan-current-tab" && isWebUrl(tab.url)) {
          const settings = await getSettings();
          const result = await scanner.scan(tab.url, { deep: true, trigger: "shortcut", settings });
          await saveTabState(tab.id, { tabId: tab.id, url: tab.url, host: hostOf(tab.url), result, ts: Date.now() });
          await updateBadge(tab.id, result, settings);
          await pushBanner(tab.id, result);
          if (scanner.shouldBlock(result, settings)) await blockTab(tab.id, result);
          else await notify(result, "warning");
        } else if (command === "open-console") {
          await safeCall(api.tabs, "create", { url: appUrl() });
        }
      } catch {
        /* ignore */
      }
    });
  }

  /* ------------------------------ notifications --------------------------- */

  if (api.notifications && api.notifications.onClicked) {
    api.notifications.onClicked.addListener(async (id) => {
      try {
        const meta = await storage.sessionGet(`notif:${id}`);
        if (!meta) return;
        const result = await storage.sessionGet(`scan:${meta.scanId}`);
        if (result) {
          await safeCall(api.tabs, "create", { url: warningUrl(result) });
        } else {
          await safeCall(api.tabs, "create", { url: appUrl({ u: meta.url }) });
        }
        await safeCall(api.notifications, "clear", id);
      } catch {
        /* ignore */
      }
    });
  }

  /* ------------------------------- lifecycle ------------------------------ */

  // Unpacked dev builds may ship an optional local-keys.json next to the
  // bundle. Seed any missing API keys once so testers do not have to paste
  // them in. Packaged installs have no such file, so this is a silent no-op.
  PG.localKeys.seedLocalKeys().catch(() => {});

  api.runtime.onInstalled.addListener((details) => {
    createContextMenus();
    PG.localKeys.seedLocalKeys().catch(() => {});
    storage.getSettings().catch(() => {});
    if (details && details.reason === "install") {
      storage.bumpStats({ installedAt: Date.now() });
      safeCall(api.tabs, "create", { url: appUrl({ welcome: "1" }) });
    }
    if (api.alarms) {
      api.alarms.create("pg-maintenance", { periodInMinutes: 360 });
    }
  });

  api.runtime.onStartup.addListener(() => {
    createContextMenus();
    PG.localKeys.seedLocalKeys().catch(() => {});
    storage.pruneCache();
  });

  if (api.alarms && api.alarms.onAlarm) {
    api.alarms.onAlarm.addListener((alarm) => {
      if (alarm.name === "pg-maintenance") {
        storage.pruneCache();
        storage.getSettings().then((settings) => {
          storage.getHistory(settings.historyLimit + 5);
        });
      }
    });
  }

  // Warm caches when the worker wakes.
  getSettings().catch(() => {});
})();
