/* PhishGuard — optional local API-key seeding for unpacked dev builds */
(function () {
  "use strict";

  const PG = (globalThis.PG = globalThis.PG || {});

  const FILE = "local-keys.json";
  const KEY_PATTERN = /^[A-Za-z0-9._-]{16,200}$/;

  let inFlight = null;

  function sanitizeLocalKeys(raw) {
    const out = { urlhaus: "", virustotal: "" };
    if (!raw || typeof raw !== "object") return out;
    for (const name of ["urlhaus", "virustotal"]) {
      const value = typeof raw[name] === "string" ? raw[name].trim() : "";
      if (KEY_PATTERN.test(value)) out[name] = value;
    }
    return out;
  }

  async function defaultLoader() {
    const api = PG.utils && PG.utils.api;
    if (!api || !api.runtime || typeof api.runtime.getURL !== "function") return null;
    try {
      const res = await fetch(api.runtime.getURL(FILE));
      if (!res || !res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  }

  /**
   * Dev-only convenience: seed API keys from an optional local-keys.json that
   * the build script copies into the unpacked folder. The file is never part
   * of extension source, the zips, or git. Existing stored keys always win.
   */
  function seedLocalKeys(deps) {
    const d = deps || {};
    const useDefaults = !d.getSettings && !d.saveSettings && !d.loadFile;

    // Only dedupe the production path; explicit dependencies always run fresh.
    if (useDefaults && inFlight) return inFlight;

    const run = (async () => {
      const getSettings = d.getSettings || PG.storage.getSettings;
      const saveSettings = d.saveSettings || PG.storage.saveSettings;
      const loadFile = d.loadFile || defaultLoader;

      let settings;
      try {
        settings = await getSettings();
      } catch {
        return { seeded: [], keys: { urlhaus: "", virustotal: "" } };
      }

      const current = (settings && settings.apiKeys) || { urlhaus: "", virustotal: "" };
      let local;
      try {
        local = sanitizeLocalKeys(await loadFile());
      } catch {
        local = { urlhaus: "", virustotal: "" };
      }

      const patch = {};
      if (!current.urlhaus && local.urlhaus) patch.urlhaus = local.urlhaus;
      if (!current.virustotal && local.virustotal) patch.virustotal = local.virustotal;
      if (Object.keys(patch).length === 0) {
        return { seeded: [], keys: { ...current } };
      }

      const next = { ...current, ...patch };
      await saveSettings({ apiKeys: next });
      return { seeded: Object.keys(patch), keys: next };
    })();

    if (useDefaults) {
      inFlight = run.finally(() => {
        inFlight = null;
      });
      return inFlight;
    }
    return run;
  }

  PG.localKeys = { FILE, sanitizeLocalKeys, seedLocalKeys };
})();
