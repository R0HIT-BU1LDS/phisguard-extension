/* PhishGuard — popup controller */
(function () {
  "use strict";

  const PG = globalThis.PG;
  const U = PG.utils;
  const ui = PG.ui;
  const api = U.api;

  const $ = (id) => document.getElementById(id);

  const state = {
    settings: null,
    tabState: null,
    history: [],
    busy: false,
    tabResult: null,
  };

  function icons() {
    $("toggleProtection").appendChild(ui.icon("power"));
    $("openOptions").appendChild(ui.icon("settings"));
    $("globeIcon").appendChild(ui.icon("globe"));
    $("historyIcon").appendChild(ui.icon("history"));
  }

  function showError(message) {
    const box = $("scanError");
    box.textContent = message;
    box.classList.remove("hidden");
  }

  function clearError() {
    $("scanError").classList.add("hidden");
    $("scanError").textContent = "";
  }

  function setBusy(busy, label) {
    state.busy = busy;
    $("scanLoading").classList.toggle("hidden", !busy);
    $("loadingText").textContent = label || "Checking threat intelligence…";
    $("scanBtn").disabled = busy;
    $("scanTabBtn").disabled = busy;
    $("urlInput").disabled = busy;
  }

  function applySettings(settings) {
    if (!settings) return;
    state.settings = settings;
    const on = !!settings.protection;
    $("protectionStatus").textContent = on ? "Protection on" : "Protection off";
    $("protectionStatus").classList.toggle("off", !on);
    const toggle = $("toggleProtection");
    toggle.classList.toggle("active", on);
    toggle.title = on ? "Turn protection off" : "Turn protection on";
    toggle.setAttribute("aria-pressed", String(on));
    toggle.setAttribute("aria-label", on ? "Turn protection off" : "Turn protection on");

    const keys = settings.keys || {};
    const deep = $("deepScan");
    const hasKeys = !!(keys.urlhaus || keys.virustotal);
    deep.disabled = !hasKeys;
    if (!hasKeys) deep.checked = false;
    $("keysHint").textContent = keys.urlhaus && keys.virustotal
      ? "URLhaus + VirusTotal"
      : keys.virustotal
        ? "VirusTotal connected"
        : keys.urlhaus
          ? "URLhaus connected"
          : "No API keys";

    $("footerNote").textContent = settings.deepScanOnVisit
      ? "Automatic deep scans are on."
      : "On-device rules run on every tab.";
  }

  function levelTone(level) {
    return level === "malicious" ? "malicious" : level === "suspicious" ? "suspicious" : "safe";
  }

  function saveReport(result) {
    try {
      const name = ui.downloadReport(result, "html");
      ui.toast(`Report saved as ${name}`);
    } catch (err) {
      ui.toast(err.message || "Could not save report", true);
    }
  }

  function resultActions(result) {
    const actions = [
      {
        label: "Copy report",
        icon: "copy",
        onClick: async () => {
          const ok = await ui.copyText(ui.plainTextReport(result));
          ui.toast(ok ? "Report copied to clipboard" : "Could not copy report", !ok);
        },
      },
      {
        label: "Save report",
        icon: "download",
        title: "Download a printable HTML report",
        onClick: () => saveReport(result),
      },
    ];
    if (!result.skipped && result.trusted !== "allowlist" && result.host) {
      actions.push({
        label: "Trust domain",
        icon: "check",
        onClick: () => trustDomain(result.host, result.url),
      });
    }
    actions.push({
      label: "Full report",
      icon: "external",
      onClick: () => openFullReport(result),
    });
    return actions;
  }

  async function openFullReport(result) {
    try {
      if (result.level === "safe") {
        await PG.send({ type: "PG_OPEN_APP", url: result.url, deep: false });
      } else {
        await PG.send({ type: "PG_OPEN_WARNING", result });
      }
      window.close();
    } catch (err) {
      ui.toast(err.message, true);
    }
  }

  async function trustDomain(host, url) {
    try {
      await PG.send({ type: "PG_TRUST", url: url || `https://${host}`, clearVerdict: true });
      ui.toast(`${host} added to trusted sites`);
      await refresh();
    } catch (err) {
      ui.toast(err.message, true);
    }
  }

  function renderTab(tabState) {
    state.tabState = tabState;
    const hostEl = $("siteHost");
    const subEl = $("siteSub");
    const container = $("tabResult");
    const scanBtn = $("scanTabBtn");

    hostEl.classList.remove("unsupported");
    $("siteActions").classList.add("hidden");
    container.classList.add("hidden");
    container.textContent = "";

    if (!tabState || !tabState.tab) {
      hostEl.textContent = "No active tab";
      subEl.textContent = "Open a website to scan it.";
      scanBtn.disabled = true;
      return;
    }

    if (tabState.unsupported) {
      hostEl.textContent = "This page can't be scanned";
      hostEl.classList.add("unsupported");
      subEl.textContent = "Browser settings, new-tab and extension pages are never scanned.";
      scanBtn.disabled = true;
      $("openReport").classList.add("hidden");
      return;
    }

    scanBtn.disabled = false;
    const result = tabState.result;
    state.tabResult = result;
    hostEl.textContent = tabState.host || U.hostOf(tabState.url) || "Unknown host";

    if (!result) {
      subEl.textContent = "Run a scan to check this page.";
      return;
    }

    subEl.textContent = `${U.levelLabel(result.level)} · risk ${result.score}/100 · ${U.timeAgo(result.scannedAt)}`;
    ui.renderReport(result, container, { compact: true, maxReasons: 3, actions: [] });
    container.classList.remove("hidden");

    $("siteActions").classList.remove("hidden");
    $("openReport").onclick = () => openFullReport(result);
    $("saveReport").onclick = () => saveReport(result);
    const trusted = result.trusted === "allowlist" || result.skipped;
    $("trustSite").classList.toggle("hidden", trusted);
    $("trustSite").onclick = () => trustDomain(tabState.host, tabState.url);
  }

  function renderHistory(entries) {
    state.history = entries || [];
    const list = $("historyList");
    list.textContent = "";
    if (!state.history.length) {
      const empty = document.createElement("li");
      empty.className = "empty";
      empty.style.cursor = "default";
      empty.textContent = "No scans yet. Analyze a link to get started.";
      list.appendChild(empty);
      return;
    }

    for (const entry of state.history.slice(0, 6)) {
      const item = document.createElement("li");
      item.title = "Open this scan in the PhishGuard console";
      const dot = document.createElement("span");
      dot.className = "dot";
      dot.style.background = ui.LEVEL_COLORS[entry.level] || ui.LEVEL_COLORS.safe;

      const text = document.createElement("div");
      text.className = "text";
      const host = document.createElement("div");
      host.className = "host";
      host.textContent = entry.host || U.hostOf(entry.url) || entry.url;
      const meta = document.createElement("div");
      meta.className = "meta";
      meta.textContent = `${U.timeAgo(entry.createdAt)} · ${U.shortUrl(entry.url, 46)}`;
      meta.title = entry.url;
      text.appendChild(host);
      text.appendChild(meta);

      const score = document.createElement("span");
      score.className = "score";
      score.textContent = String(entry.score);
      score.style.color = ui.LEVEL_COLORS[entry.level] || ui.LEVEL_COLORS.safe;

      item.appendChild(dot);
      item.appendChild(text);
      item.appendChild(score);
      item.addEventListener("click", () => {
        PG.send({ type: "PG_OPEN_APP", url: entry.url }).catch((err) => ui.toast(err.message, true));
        window.close();
      });
      list.appendChild(item);
    }
  }

  async function scanTab() {
    if (state.busy) return;
    clearError();
    setBusy(true, "Scanning this page…");
    try {
      const deep = $("deepScan").checked && !$("deepScan").disabled;
      const result = await PG.send({ type: "PG_SCAN_TAB", deep });
      state.tabResult = result;
      const container = $("tabResult");
      container.textContent = "";
      ui.renderReport(result, container, { compact: true, maxReasons: 4, actions: resultActions(result) });
      container.classList.remove("hidden");
      $("siteSub").textContent = `${U.levelLabel(result.level)} · risk ${result.score}/100 · just now`;
      $("siteActions").classList.add("hidden");
      const tab = state.tabState;
      renderHistory(await PG.send({ type: "PG_HISTORY", limit: 6 }));
      if (tab) state.tabState = { ...tab, result };
    } catch (err) {
      showError(err.message || "Scan failed");
    } finally {
      setBusy(false);
    }
  }

  async function scanUrl() {
    if (state.busy) return;
    clearError();
    const value = $("urlInput").value.trim();
    if (!value) {
      showError("Paste a link first — for example https://example.com");
      $("urlInput").focus();
      return;
    }
    const deep = $("deepScan").checked && !$("deepScan").disabled;
    setBusy(true, deep ? "Querying URLhaus and VirusTotal…" : "Applying on-device rules…");
    const container = $("scanResult");
    container.classList.add("hidden");
    container.textContent = "";
    try {
      const result = await PG.send({ type: "PG_SCAN", url: value, deep });
      ui.renderReport(result, container, { compact: false, maxReasons: 8, actions: resultActions(result) });
      container.classList.remove("hidden");
      if (!deep && state.settings && state.settings.keys.any) {
        ui.toast("Offline scan complete — enable deep scan for feed data");
      }
      renderHistory(await PG.send({ type: "PG_HISTORY", limit: 6 }));
    } catch (err) {
      showError(err.message || "Scan failed");
    } finally {
      setBusy(false);
    }
  }

  async function loadAll() {
    const [settings, tabState, history] = await Promise.all([
      PG.send({ type: "PG_SETTINGS_GET" }),
      PG.send({ type: "PG_TAB_STATE" }),
      PG.send({ type: "PG_HISTORY", limit: 6 }),
    ]);
    applySettings(settings);
    renderTab(tabState);
    renderHistory(history);
  }

  async function refresh() {
    try {
      await loadAll();
    } catch (err) {
      ui.toast(err.message, true);
    }
  }

  function bind() {
    $("toggleProtection").addEventListener("click", async () => {
      try {
        const next = !(state.settings && state.settings.protection);
        const settings = await PG.send({ type: "PG_SETTINGS_SET", settings: { protection: next } });
        applySettings(settings);
        ui.toast(next ? "Protection enabled" : "Protection paused");
      } catch (err) {
        ui.toast(err.message, true);
      }
    });

    $("openOptions").addEventListener("click", () => {
      PG.send({ type: "PG_OPEN_OPTIONS" }).catch(() => {});
    });

    $("scanTabBtn").addEventListener("click", scanTab);
    $("scanForm").addEventListener("submit", (event) => {
      event.preventDefault();
      scanUrl();
    });

    $("openConsole").addEventListener("click", () => {
      PG.send({ type: "PG_OPEN_APP" }).catch((err) => ui.toast(err.message, true));
      window.close();
    });

    $("clearHistory").addEventListener("click", async () => {
      if (!window.confirm("Clear all local scan history?")) return;
      try {
        await PG.send({ type: "PG_HISTORY_CLEAR" });
        renderHistory([]);
        ui.toast("History cleared");
      } catch (err) {
        ui.toast(err.message, true);
      }
    });

    $("footerLink").addEventListener("click", () => {
      U.invoke(api.tabs, "create", { url: api.runtime.getURL("options/options.html#privacy") }).catch(() => {});
    });

    document.addEventListener("keydown", (event) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        $("urlInput").focus();
        $("urlInput").select();
      }
    });

    $("urlInput").addEventListener("input", clearError);
  }

  async function boot() {
    icons();
    bind();
    try {
      await loadAll();
    } catch (err) {
      showError(err.message || "PhishGuard background is not responding. Close and reopen the popup.");
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot, { once: true });
  } else {
    boot();
  }
})();
