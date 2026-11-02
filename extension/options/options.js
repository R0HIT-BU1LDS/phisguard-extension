/* PhishGuard — options page controller */
(function () {
  "use strict";

  const PG = globalThis.PG;
  const U = PG.utils;
  const ui = PG.ui;
  const uiApi = U.api;
  const C = PG.constants;

  const $ = (id) => document.getElementById(id);

  const state = {
    settings: null,
    loading: true,
    saveTimer: 0,
    saveSeq: 0,
    lastSavedSeq: 0,
  };

  /* ------------------------------- helpers -------------------------------- */

  function setSaveState(text, tone) {
    const el = $("saveState");
    el.textContent = text;
    el.className = `save-state${tone ? ` ${tone}` : ""}`;
  }

  function scheduleSave(patch, options) {
    if (state.loading) return;
    const opts = options || {};
    const seq = ++state.saveSeq;

    // Merge rapid changes so quickly toggling two switches never drops one.
    state.pending = state.pending || {};
    for (const [key, value] of Object.entries(patch || {})) {
      if (key === "apiKeys" && value && typeof value === "object") {
        state.pending.apiKeys = { ...(state.pending.apiKeys || {}), ...value };
      } else {
        state.pending[key] = value;
      }
    }

    clearTimeout(state.saveTimer);
    setSaveState("Saving…");
    state.saveTimer = setTimeout(async () => {
      const payload = state.pending || {};
      state.pending = {};
      try {
        await saveNow(payload);
        if (seq === state.saveSeq) {
          state.lastSavedSeq = seq;
          setSaveState("All changes saved", "saved");
          setTimeout(() => {
            if (state.lastSavedSeq === state.saveSeq) {
              const el = $("saveState");
              el.classList.remove("saved");
              el.textContent = "All changes saved";
            }
          }, 2200);
        }
      } catch (err) {
        setSaveState(err.message || "Could not save", "error");
        ui.toast(err.message || "Could not save settings", true);
      }
    }, opts.immediate ? 0 : 320);
  }

  async function saveNow(patch) {
    // The setter replies with the public settings shape (no keys or history
    // options), so re-read the full object before repainting the form.
    await PG.send({ type: "PG_SETTINGS_SET", settings: patch });
    const saved = await PG.send({ type: "PG_SETTINGS_FULL" });
    applySettings(saved, { silent: true });
    return saved;
  }

  function bindToggle(id, key) {
    $(id).addEventListener("change", (event) => {
      scheduleSave({ [key]: event.target.checked }, { immediate: true });
      if (key === "protection") updateMasterUi(event.target.checked);
    });
  }

  function updateMasterUi(on) {
    const group = $("protectionGroup");
    group.style.opacity = on ? "1" : "0.5";
    group.style.pointerEvents = on ? "" : "none";
  }

  function fill(section) {
    for (const button of document.querySelectorAll(".nav-item")) {
      button.classList.toggle("active", button.dataset.section === section);
    }
    for (const panel of document.querySelectorAll(".panel")) {
      panel.classList.toggle("active", panel.id === `section-${section}`);
    }
    if (window.location.hash !== `#${section}`) {
      try {
        history.replaceState(null, "", `#${section}`);
      } catch {
        /* ignore */
      }
    }
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  /* ------------------------------- settings -------------------------------- */

  function applySettings(settings, options) {
    const opts = options || {};
    state.settings = settings;

    const toggles = [
      ["setProtection", "protection"],
      ["setBlockMalicious", "blockMalicious"],
      ["setBlockSuspicious", "blockSuspicious"],
      ["setScanOnVisit", "scanOnVisit"],
      ["setDeepOnVisit", "deepScanOnVisit"],
      ["setShowScoreBadge", "showScoreBadge"],
      ["setNotifications", "notifications"],
      ["setPageBanners", "pageBanners"],
      ["setMarkLinks", "markLinks"],
      ["setWarnOnHttpLogin", "warnOnHttpLogin"],
      ["setRedactHistory", "redactHistory"],
    ];
    for (const [id, key] of toggles) {
      $(id).checked = !!settings[key];
    }
    updateMasterUi(settings.protection);

    $("setSuspiciousThreshold").value = String(settings.suspiciousThreshold);
    $("setBlockThreshold").value = String(settings.blockThreshold);
    $("suspiciousValue").textContent = String(settings.suspiciousThreshold);
    $("blockValue").textContent = String(settings.blockThreshold);

    if (!opts.silent) {
      $("setHistoryLimit").value = String(settings.historyLimit);
      $("setCacheTtl").value = String(settings.cacheTtlHours);
    }

    const keys = settings.apiKeys || {};
    if (!opts.silent) {
      $("setUrlhausKey").value = keys.urlhaus || "";
      $("setVirustotalKey").value = keys.virustotal || "";
    }

    const urlhausPill = $("urlhausPill");
    urlhausPill.textContent = keys.urlhaus ? "Configured" : "Not configured";
    urlhausPill.className = `pill${keys.urlhaus ? " safe" : ""}`;
    const vtPill = $("virustotalPill");
    vtPill.textContent = keys.virustotal ? "Configured" : "Not configured";
    vtPill.className = `pill${keys.virustotal ? " safe" : ""}`;

    const anyKey = !!(keys.urlhaus || keys.virustotal);
    $("testDeep").disabled = !anyKey;
    if (!anyKey) $("testDeep").checked = false;
    $("testDeepHint").textContent = anyKey ? "Uses API quota" : "No API keys configured";

    renderAllowlist(settings.allowlist || []);
    $("trustedCount").textContent = String((settings.allowlist || []).length);
  }

  function readThresholds() {
    let suspicious = Number($("setSuspiciousThreshold").value) || 40;
    let block = Number($("setBlockThreshold").value) || 70;
    if (suspicious >= block) {
      if (document.activeElement === $("setSuspiciousThreshold")) {
        block = Math.min(100, suspicious + 5);
        $("setBlockThreshold").value = String(block);
        $("blockValue").textContent = String(block);
      } else {
        suspicious = Math.max(10, block - 5);
        $("setSuspiciousThreshold").value = String(suspicious);
        $("suspiciousValue").textContent = String(suspicious);
      }
    }
    return { block, suspicious };
  }

  function bindSettings() {
    bindToggle("setProtection", "protection");
    bindToggle("setBlockMalicious", "blockMalicious");
    bindToggle("setBlockSuspicious", "blockSuspicious");
    bindToggle("setScanOnVisit", "scanOnVisit");
    bindToggle("setDeepOnVisit", "deepScanOnVisit");
    bindToggle("setShowScoreBadge", "showScoreBadge");
    bindToggle("setNotifications", "notifications");
    bindToggle("setPageBanners", "pageBanners");
    bindToggle("setMarkLinks", "markLinks");
    bindToggle("setWarnOnHttpLogin", "warnOnHttpLogin");
    bindToggle("setRedactHistory", "redactHistory");

    for (const id of ["setSuspiciousThreshold", "setBlockThreshold"]) {
      const slider = $(id);
      slider.addEventListener("input", () => {
        $("suspiciousValue").textContent = $("setSuspiciousThreshold").value;
        $("blockValue").textContent = $("setBlockThreshold").value;
      });
      slider.addEventListener("change", () => {
        const { block, suspicious } = readThresholds();
        scheduleSave({ blockThreshold: block, suspiciousThreshold: suspicious }, { immediate: true });
      });
    }

    for (const [id, key] of [
      ["setHistoryLimit", "historyLimit"],
      ["setCacheTtl", "cacheTtlHours"],
    ]) {
      $(id).addEventListener("change", () => {
        const value = Number($(id).value);
        if (!Number.isFinite(value)) return;
        scheduleSave({ [key]: value }, { immediate: true });
      });
    }

    for (const [id, key] of [
      ["setUrlhausKey", "urlhaus"],
      ["setVirustotalKey", "virustotal"],
    ]) {
      $(id).addEventListener("change", () => {
        const value = $(id).value.trim();
        scheduleSave({ apiKeys: { [key]: value } }, { immediate: true });
        ui.toast(value ? "API key saved" : "API key removed");
      });
    }

    for (const button of document.querySelectorAll(".reveal")) {
      button.addEventListener("click", () => {
        const input = $(button.dataset.target);
        const show = input.type === "password";
        input.type = show ? "text" : "password";
        button.textContent = show ? "Hide" : "Show";
      });
    }
  }

  /* ------------------------------ allowlist -------------------------------- */

  function renderAllowlist(list) {
    const container = $("allowList");
    container.textContent = "";
    $("trustedCount").textContent = String(list.length);
    if (!list.length) {
      const empty = document.createElement("div");
      empty.className = "allow-empty";
      empty.textContent = "No trusted domains yet.";
      container.appendChild(empty);
      return;
    }
    for (const host of list) {
      const row = document.createElement("div");
      row.className = "allow-item";

      const name = document.createElement("span");
      name.className = "mono";
      name.textContent = host;

      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "btn ghost sm";
      remove.textContent = "Remove";
      remove.setAttribute("aria-label", `Remove ${host}`);
      remove.addEventListener("click", async () => {
        remove.disabled = true;
        try {
          await PG.send({ type: "PG_ALLOWLIST_REMOVE", host });
          ui.toast(`${host} is no longer trusted`);
          await reloadSettings();
        } catch (err) {
          remove.disabled = false;
          ui.toast(err.message, true);
        }
      });

      row.appendChild(name);
      row.appendChild(remove);
      container.appendChild(row);
    }
  }

  async function reloadSettings() {
    clearTimeout(state.saveTimer);
    state.pending = {};
    const settings = await PG.send({ type: "PG_SETTINGS_FULL" });
    applySettings(settings);
    return settings;
  }

  function bindAllowlist() {
    $("allowForm").addEventListener("submit", async (event) => {
      event.preventDefault();
      const value = $("allowInput").value.trim();
      if (!value) return;
      try {
        const result = await PG.send({ type: "PG_ALLOWLIST_ADD", host: value });
        $("allowInput").value = "";
        ui.toast(`${result.host} is now trusted`);
        await reloadSettings();
      } catch (err) {
        ui.toast(err.message, true);
      }
    });
  }

  /* ---------------------------- data & privacy ----------------------------- */

  function bindData() {
    $("exportBtn").addEventListener("click", async () => {
      try {
        const payload = await PG.send({ type: "PG_EXPORT" });
        const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
        const link = document.createElement("a");
        link.href = URL.createObjectURL(blob);
        link.download = `phishguard-backup-${new Date().toISOString().slice(0, 10)}.json`;
        link.click();
        setTimeout(() => URL.revokeObjectURL(link.href), 1500);
        ui.toast("Backup exported");
      } catch (err) {
        ui.toast(err.message, true);
      }
    });

    $("importBtn").addEventListener("click", () => $("importFile").click());
    $("importFile").addEventListener("change", async (event) => {
      const file = event.target.files && event.target.files[0];
      event.target.value = "";
      if (!file) return;
      try {
        const text = await file.text();
        const payload = JSON.parse(text);
        if (!window.confirm("Restore this backup? Your current settings and history will be replaced.")) return;
        await PG.send({ type: "PG_IMPORT", payload });
        await reloadSettings();
        ui.toast("Backup restored");
      } catch (err) {
        ui.toast(err.message || "Could not read that backup file", true);
      }
    });

    $("clearHistoryBtn").addEventListener("click", async () => {
      if (!window.confirm("Clear all local scan history?")) return;
      try {
        await PG.send({ type: "PG_HISTORY_CLEAR" });
        ui.toast("History cleared");
      } catch (err) {
        ui.toast(err.message, true);
      }
    });

    $("clearCacheBtn").addEventListener("click", async () => {
      try {
        await PG.send({ type: "PG_CLEAR_CACHE" });
        ui.toast("Cached verdicts cleared");
      } catch (err) {
        ui.toast(err.message, true);
      }
    });

    $("resetAllBtn").addEventListener("click", async () => {
      const confirmed = window.confirm(
        "Reset PhishGuard completely?\n\nThis removes settings, API keys, trusted domains, history and cached verdicts from this browser.",
      );
      if (!confirmed) return;
      try {
        await PG.send({ type: "PG_RESET_ALL" });
        await reloadSettings();
        ui.toast("PhishGuard reset to defaults");
      } catch (err) {
        ui.toast(err.message, true);
      }
    });
  }

  /* -------------------------------- tools --------------------------------- */

  function bindTools() {
    $("testNotifyBtn").addEventListener("click", async () => {
      const label = $("notifyResult");
      try {
        await PG.send({ type: "PG_NOTIFY_TEST" });
        label.textContent = "Test alert sent.";
        label.style.color = "#4ade80";
      } catch (err) {
        label.textContent = err.message;
        label.style.color = "#fca5a5";
      }
      setTimeout(() => {
        label.textContent = "";
      }, 6000);
    });

    $("testForm").addEventListener("submit", async (event) => {
      event.preventDefault();
      const raw = $("testInput").value.trim();
      if (!raw) {
        $("testInput").focus();
        return;
      }
      const button = $("testForm").querySelector("button[type=submit]");
      const container = $("testResult");
      button.disabled = true;
      button.textContent = "Scanning…";
      container.textContent = "";
      try {
        const result = await PG.send({
          type: "PG_SCAN",
          url: raw,
          deep: $("testDeep").checked && !$("testDeep").disabled,
          force: true,
          trigger: "options",
        });
        ui.renderReport(result, container, {
          maxReasons: 10,
          compact: false,
          actions: [
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
          ],
        });
      } catch (err) {
        const error = document.createElement("p");
        error.className = "small";
        error.style.color = "#fca5a5";
        error.textContent = err.message || "Scan failed";
        container.appendChild(error);
      } finally {
        button.disabled = false;
        button.textContent = "Scan";
      }
    });

    $("demoWarningBtn").addEventListener("click", async () => {
      try {
        const result = await PG.send({
          type: "PG_SCAN",
          url: "https://paypal.com.account-verify.example-secure.tk/login",
          deep: false,
          record: false,
          trigger: "demo",
        });
        result.level = result.score >= 70 ? "malicious" : "malicious";
        await PG.send({ type: "PG_OPEN_WARNING", result });
      } catch (err) {
        ui.toast(err.message, true);
      }
    });
  }

  /* -------------------------------- about ---------------------------------- */

  function renderAbout() {
    let version = "2.0.0";
    try {
      version = uiApi.runtime.getManifest().version;
    } catch {
      /* ignore */
    }
    $("aboutVersion").textContent = `Version ${version}`;
    $("versionPill").textContent = `v${version}`;
    $("brandCount").textContent = String(C.BRANDS.length);
    $("tldCount").textContent = String(C.SUSPICIOUS_TLDS.size + C.SHADY_TLDS.size);
    $("trustedCount").textContent = String((state.settings && state.settings.allowlist.length) || 0);

    if (uiApi.commands && uiApi.commands.getAll) {
      U.invoke(uiApi.commands, "getAll")
        .then((commands) => {
          for (const command of commands || []) {
            const shortcut = command.shortcut || "Not set";
            if (command.name === "scan-current-tab") $("shortcutScan").textContent = shortcut;
            if (command.name === "open-console") $("shortcutConsole").textContent = shortcut;
          }
        })
        .catch(() => {});
    }
  }

  /* --------------------------------- boot ---------------------------------- */

  function bindNav() {
    for (const button of document.querySelectorAll(".nav-item")) {
      button.addEventListener("click", () => fill(button.dataset.section));
    }
    window.addEventListener("hashchange", () => {
      const section = window.location.hash.replace("#", "");
      if (section) fill(section);
    });
  }

  function bindHeader() {
    $("openConsoleBtn").addEventListener("click", () => {
      PG.send({ type: "PG_OPEN_APP" }).catch((err) => ui.toast(err.message, true));
    });
  }

  function wireIcons() {
    $("navProtection").appendChild(ui.icon("shield"));
    $("navFeeds").appendChild(ui.icon("activity"));
    $("navAllowlist").appendChild(ui.icon("check"));
    $("navPrivacy").appendChild(ui.icon("lock"));
    $("navTools").appendChild(ui.icon("refresh"));
    $("navAbout").appendChild(ui.icon("shieldAlert"));
    $("feedLockIcon").appendChild(ui.icon("lock"));
  }

  async function boot() {
    wireIcons();
    bindNav();
    bindHeader();
    bindSettings();
    bindAllowlist();
    bindData();
    bindTools();

    const initial = window.location.hash.replace("#", "");
    if (initial && document.getElementById(`section-${initial}`)) fill(initial);

    try {
      const settings = await PG.send({ type: "PG_SETTINGS_FULL" });
      state.loading = false;
      applySettings(settings);
      renderAbout();
      setSaveState("All changes saved");
    } catch (err) {
      state.loading = false;
      setSaveState("Background not responding", "error");
      ui.toast(err.message || "Could not load settings", true);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot, { once: true });
  } else {
    boot();
  }
})();
