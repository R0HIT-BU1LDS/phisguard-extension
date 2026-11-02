/* PhishGuard — full-page local console */
(function () {
  "use strict";

  const PG = globalThis.PG;
  const U = PG.utils;
  const ui = PG.ui;
  const api = U.api;

  const $ = (id) => document.getElementById(id);
  const params = new URLSearchParams(window.location.search);

  const state = {
    settings: null,
    stats: null,
    history: [],
    filter: "all",
    result: null,
    busy: false,
  };

  function icons() {
    $("settingsBtn").appendChild(ui.icon("settings"));
    $("globeIcon").appendChild(ui.icon("globe"));
    $("welcomeIcon").appendChild(ui.icon("shield"));
    $("emptyIcon").appendChild(ui.icon("shield"));
    $("settingsBtn").appendChild(document.createTextNode("Settings"));
  }

  function hasKeys() {
    const keys = (state.settings && state.settings.keys) || {};
    return !!(keys.urlhaus || keys.virustotal);
  }

  function applySettings(settings) {
    state.settings = settings;
    const on = !!settings.protection;
    const pill = $("protectionPill");
    pill.className = `pill ${on ? "safe" : ""}`.trim();
    pill.textContent = "";
    if (on) {
      const dot = document.createElement("span");
      dot.className = "live-dot";
      pill.appendChild(dot);
    }
    pill.appendChild(document.createTextNode(on ? " Protection on" : " Protection off"));

    $("optProtection").checked = on;
    $("optBlockSuspicious").checked = !!settings.blockSuspicious;
    $("optDeepOnVisit").checked = !!settings.deepScanOnVisit;

    const keys = settings.keys || {};
    const deep = $("deepScan");
    deep.disabled = !hasKeys();
    if (!hasKeys()) deep.checked = false;
    $("keysHint").textContent = keys.urlhaus && keys.virustotal
      ? "URLhaus + VirusTotal connected"
      : keys.virustotal
        ? "VirusTotal connected"
        : keys.urlhaus
          ? "URLhaus connected"
          : "No API keys configured — offline rules only";

    const urlhaus = $("urlhausStatus");
    urlhaus.textContent = keys.urlhaus ? "Connected" : "Not configured";
    urlhaus.className = `pill ${keys.urlhaus ? "safe" : ""}`.trim();
    const vt = $("virustotalStatus");
    vt.textContent = keys.virustotal ? "Connected" : "Not configured";
    vt.className = `pill ${keys.virustotal ? "safe" : ""}`.trim();

    renderTrusted(settings.allowlist || []);
  }

  function renderStats() {
    const stats = state.stats || {};
    $("statScans").textContent = String(stats.scans || 0);
    $("statBlocked").textContent = String(stats.blocked || 0);
    $("statTrusted").textContent = String((state.settings && state.settings.allowlist.length) || 0);
    $("statDeep").textContent = String(stats.deepScans || 0);
  }

  function renderTrusted(list) {
    const container = $("trustedList");
    container.textContent = "";
    $("trustedCount").textContent = String(list.length);
    if (!list.length) {
      const empty = document.createElement("span");
      empty.className = "tiny muted";
      empty.textContent = "No trusted domains. Sites you trust skip automatic blocking.";
      container.appendChild(empty);
      return;
    }
    for (const host of list) {
      const item = document.createElement("span");
      item.className = "trusted-item";
      item.appendChild(document.createTextNode(host));
      const remove = document.createElement("button");
      remove.type = "button";
      remove.title = `Remove ${host} from trusted domains`;
      remove.setAttribute("aria-label", `Remove ${host}`);
      remove.appendChild(ui.icon("x"));
      remove.addEventListener("click", () => removeTrusted(host));
      item.appendChild(remove);
      container.appendChild(item);
    }
  }

  function renderHistory() {
    const body = $("historyBody");
    body.textContent = "";
    const filtered = state.history.filter((entry) => state.filter === "all" || entry.level === state.filter);
    $("historyCount").textContent = String(state.history.length);
    $("historyEmpty").classList.toggle("hidden", filtered.length > 0);

    for (const entry of filtered) {
      const tr = document.createElement("tr");
      tr.title = "Load this address into the scanner";
      tr.addEventListener("click", () => {
        const target = String(entry.url || "").replace(/\/…$/, "");
        $("urlInput").value = target;
        $("urlInput").focus();
        window.scrollTo({ top: 0, behavior: "smooth" });
        if (/…/.test(entry.url)) ui.toast("Loaded the redacted address — edit it if you need the full URL");
      });

      const statusCell = document.createElement("td");
      const pill = ui.pill(U.levelLabel(entry.level), entry.level === "malicious" ? "malicious" : entry.level === "suspicious" ? "suspicious" : "safe");
      statusCell.appendChild(pill);

      const addrCell = document.createElement("td");
      addrCell.className = "addr";
      const host = document.createElement("div");
      host.className = "host";
      host.textContent = entry.host || U.hostOf(entry.url) || "unknown";
      const url = document.createElement("div");
      url.className = "url";
      url.textContent = entry.url;
      url.title = entry.url;
      addrCell.appendChild(host);
      addrCell.appendChild(url);

      const scoreCell = document.createElement("td");
      scoreCell.className = "score";
      scoreCell.textContent = String(entry.score);
      scoreCell.style.color = ui.LEVEL_COLORS[entry.level] || "";

      const sourceCell = document.createElement("td");
      sourceCell.className = "source";
      sourceCell.textContent = entry.deep ? "Deep scan" : entry.trigger === "auto" ? "Auto check" : "Offline";

      const whenCell = document.createElement("td");
      whenCell.className = "right tiny muted";
      whenCell.textContent = U.timeAgo(entry.createdAt);
      whenCell.title = U.formatDateTime(entry.createdAt);

      tr.appendChild(statusCell);
      tr.appendChild(addrCell);
      tr.appendChild(scoreCell);
      tr.appendChild(sourceCell);
      tr.appendChild(whenCell);
      body.appendChild(tr);
    }
  }

  function progressMessages(deep) {
    const base = ["Validating the address…", "Applying offline heuristics…"];
    if (deep) base.push("Querying URLhaus…", "Querying VirusTotal vendors…", "Combining signals…");
    base.push("Preparing the report…");
    return base;
  }

  function startProgress(deep) {
    const messages = progressMessages(deep);
    const wrap = $("scanProgress");
    const text = $("progressText");
    wrap.classList.remove("hidden");
    $("result").classList.add("hidden");
    $("resultEmpty").classList.add("hidden");
    let index = 0;
    text.textContent = messages[0];
    const timer = setInterval(() => {
      index = Math.min(index + 1, messages.length - 1);
      text.textContent = messages[index];
    }, 900);
    return () => {
      clearInterval(timer);
      wrap.classList.add("hidden");
    };
  }

  function resultActions(result) {
    const actions = [
      {
        label: "Copy report",
        icon: "copy",
        onClick: async () => {
          const ok = await ui.copyText(ui.plainTextReport(result));
          ui.toast(ok ? "Report copied" : "Could not copy report", !ok);
        },
      },
      {
        label: "Save report",
        icon: "download",
        title: "Download a printable HTML report",
        onClick: () => {
          try {
            const name = ui.downloadReport(result, "html");
            ui.toast(`Report saved as ${name}`);
          } catch (err) {
            ui.toast(err.message || "Could not save report", true);
          }
        },
      },
      {
        label: result.level === "safe" ? "Open interstitial" : "Open warning page",
        icon: "external",
        onClick: async () => {
          try {
            await PG.send({ type: "PG_OPEN_WARNING", result });
          } catch (err) {
            ui.toast(err.message, true);
          }
        },
      },
    ];
    if (!result.skipped && result.trusted !== "allowlist") {
      actions.push({
        label: "Trust domain",
        icon: "check",
        onClick: () => trustDomain(result.host),
      });
    }
    if (hasKeys()) {
      actions.push({
        label: "Re-scan deep",
        icon: "refresh",
        onClick: () => runScan(result.url, { deep: true, force: true }),
      });
    }
    return actions;
  }

  function renderResult(result) {
    state.result = result;
    const container = $("result");
    $("resultEmpty").classList.add("hidden");
    container.textContent = "";
    ui.renderReport(result, container, { maxReasons: 10, actions: resultActions(result) });
    container.classList.remove("hidden");
    $("resultMeta").textContent = `${result.deep ? "Deep scan" : "Offline scan"} · ${U.formatDateTime(result.scannedAt)}`;
  }

  async function runScan(rawUrl, options) {
    if (state.busy) return;
    const opts = options || {};
    const url = String(rawUrl || "").trim();
    if (!url) {
      ui.toast("Enter a URL first", true);
      $("urlInput").focus();
      return;
    }

    let deep = !!opts.deep;
    if (deep && !hasKeys()) {
      deep = false;
      ui.toast("Add API keys in settings to use deep scans");
    }

    state.busy = true;
    $("scanSubmit").disabled = true;
    $("urlInput").disabled = true;
    $("resultMeta").textContent = "";
    const stop = startProgress(deep);

    try {
      const result = await PG.send({
        type: "PG_SCAN",
        url,
        deep,
        force: opts.force !== false,
        trigger: "console",
      });
      renderResult(result);
      await refreshData();
    } catch (err) {
      $("resultEmpty").classList.remove("hidden");
      $("resultEmpty").innerHTML = "";
      const p = document.createElement("p");
      p.textContent = err.message || "Scan failed";
      p.style.color = "#fca5a5";
      $("resultEmpty").appendChild(p);
      ui.toast(err.message || "Scan failed", true);
    } finally {
      stop();
      state.busy = false;
      $("scanSubmit").disabled = false;
      $("urlInput").disabled = false;
    }
  }

  async function refreshData() {
    try {
      const [settings, stats, history] = await Promise.all([
        PG.send({ type: "PG_SETTINGS_GET" }),
        PG.send({ type: "PG_STATS" }),
        PG.send({ type: "PG_HISTORY", limit: 100 }),
      ]);
      applySettings(settings);
      state.stats = stats;
      state.history = history;
      renderStats();
      renderHistory();
    } catch {
      /* keep current view */
    }
  }

  async function trustDomain(host) {
    try {
      await PG.send({ type: "PG_ALLOWLIST_ADD", host });
      ui.toast(`${host} is now trusted`);
      await refreshData();
    } catch (err) {
      ui.toast(err.message, true);
    }
  }

  async function removeTrusted(host) {
    try {
      await PG.send({ type: "PG_ALLOWLIST_REMOVE", host });
      ui.toast(`${host} removed from trusted domains`);
      await refreshData();
    } catch (err) {
      ui.toast(err.message, true);
    }
  }

  function bind() {
    $("scanForm").addEventListener("submit", (event) => {
      event.preventDefault();
      runScan($("urlInput").value, { deep: $("deepScan").checked });
    });

    $("settingsBtn").onclick = () => PG.send({ type: "PG_OPEN_OPTIONS" }).catch(() => {});
    $("openOptions").onclick = () => PG.send({ type: "PG_OPEN_OPTIONS" }).catch(() => {});
    $("keysBtn").onclick = () => PG.send({ type: "PG_OPEN_OPTIONS" }).catch(() => {});

    for (const [id, key] of [
      ["optProtection", "protection"],
      ["optBlockSuspicious", "blockSuspicious"],
      ["optDeepOnVisit", "deepScanOnVisit"],
    ]) {
      $(id).addEventListener("change", async (event) => {
        try {
          const settings = await PG.send({
            type: "PG_SETTINGS_SET",
            settings: { [key]: event.target.checked },
          });
          applySettings(settings);
          renderStats();
          ui.toast("Settings updated");
        } catch (err) {
          ui.toast(err.message, true);
          event.target.checked = !event.target.checked;
        }
      });
    }

    $("historyFilters").addEventListener("click", (event) => {
      const button = event.target.closest("button[data-level]");
      if (!button) return;
      state.filter = button.dataset.level;
      for (const child of $("historyFilters").querySelectorAll("button")) {
        child.classList.toggle("active", child === button);
      }
      renderHistory();
    });

    $("clearHistory").addEventListener("click", async () => {
      if (!window.confirm("Clear all local scan history?")) return;
      try {
        await PG.send({ type: "PG_HISTORY_CLEAR" });
        state.history = [];
        renderHistory();
        ui.toast("History cleared");
      } catch (err) {
        ui.toast(err.message, true);
      }
    });

    $("exportHistory").addEventListener("click", () => {
      if (!state.history.length) {
        ui.toast("Nothing to export yet", true);
        return;
      }
      const payload = {
        app: "PhishGuard",
        exportedAt: new Date().toISOString(),
        note: "Local scan history. URLs may be redacted according to your privacy setting.",
        entries: state.history,
      };
      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = `phishguard-history-${new Date().toISOString().slice(0, 10)}.json`;
      link.click();
      setTimeout(() => URL.revokeObjectURL(link.href), 1500);
      ui.toast("History exported");
    });

    $("trustForm").addEventListener("submit", async (event) => {
      event.preventDefault();
      const value = $("trustInput").value.trim();
      if (!value) return;
      try {
        await PG.send({ type: "PG_ALLOWLIST_ADD", host: value });
        $("trustInput").value = "";
        ui.toast("Domain trusted");
        await refreshData();
      } catch (err) {
        ui.toast(err.message, true);
      }
    });

    $("welcomeDismiss").onclick = () => $("welcomeCard").classList.add("hidden");
    $("welcomeSetup").onclick = () => PG.send({ type: "PG_OPEN_OPTIONS" }).catch(() => {});
    $("welcomeDemo").onclick = () => {
      $("welcomeCard").classList.add("hidden");
      $("urlInput").value = "https://example.com";
      runScan("https://example.com", { deep: false });
    };

    $("privacyBtn").onclick = () => {
      PG.send({ type: "PG_OPEN_OPTIONS" }).catch(() => {});
    };
    $("aboutBtn").onclick = () => {
      PG.send({ type: "PG_OPEN_OPTIONS" }).catch(() => {});
    };
  }

  async function boot() {
    icons();
    bind();
    try {
      $("version").textContent = `v${api.runtime.getManifest().version}`;
    } catch {
      $("version").textContent = "";
    }

    try {
      const [settings, stats, history] = await Promise.all([
        PG.send({ type: "PG_SETTINGS_GET" }),
        PG.send({ type: "PG_STATS" }),
        PG.send({ type: "PG_HISTORY", limit: 100 }),
      ]);
      applySettings(settings);
      state.stats = stats;
      state.history = history;
      renderStats();
      renderHistory();
    } catch (err) {
      ui.toast(err.message || "Could not load PhishGuard data", true);
    }

    if (params.get("welcome") === "1") {
      $("welcomeCard").classList.remove("hidden");
    }

    const initial = params.get("u");
    if (initial) {
      $("urlInput").value = initial;
      const deep = params.get("deep") === "1" && hasKeys();
      if (deep) $("deepScan").checked = true;
      runScan(initial, { deep });
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot, { once: true });
  } else {
    boot();
  }
})();
