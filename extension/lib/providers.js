/* PhishGuard — threat-intelligence providers (URLhaus + VirusTotal) */
(function () {
  "use strict";

  const PG = (globalThis.PG = globalThis.PG || {});
  const U = PG.utils;

  const URLHAUS_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/";
  const VT_BASE = "https://www.virustotal.com/api/v3";
  const REQUEST_TIMEOUT = 12000;
  const VT_MAX_PER_MINUTE = 2;

  function emptyVt() {
    return {
      ok: false,
      skipped: true,
      found: false,
      malicious: 0,
      suspicious: 0,
      harmless: 0,
      undetected: 0,
      total: 0,
      reputation: null,
      error: null,
    };
  }

  function emptyUrlhaus() {
    return {
      ok: false,
      skipped: true,
      listed: false,
      threat: null,
      tags: [],
      urlStatus: null,
      reference: null,
      dateAdded: null,
      error: null,
    };
  }

  async function fetchWithTimeout(url, options, timeoutMs) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs || REQUEST_TIMEOUT);
    try {
      return await fetch(url, { ...(options || {}), signal: controller.signal });
    } finally {
      clearTimeout(timer);
    }
  }

  async function checkUrlhaus(url, apiKey) {
    const result = emptyUrlhaus();
    if (!apiKey) {
      result.error = "No URLhaus API key configured";
      return result;
    }
    try {
      const body = new URLSearchParams({ url });
      const res = await fetchWithTimeout(URLHAUS_ENDPOINT, {
        method: "POST",
        headers: {
          "Auth-Key": apiKey,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: body.toString(),
      });
      if (!res.ok) {
        result.error = `URLhaus returned HTTP ${res.status}`;
        return result;
      }
      const data = await res.json();
      result.skipped = false;
      result.ok = true;
      if (data && data.query_status === "ok") {
        result.listed = true;
        result.threat = data.threat || null;
        result.tags = Array.isArray(data.tags) ? data.tags.slice(0, 12) : [];
        result.urlStatus = data.url_status || null;
        result.reference = data.urlhaus_reference || null;
        result.dateAdded = data.date_added || null;
      } else if (data && data.query_status && data.query_status !== "no_results") {
        result.error = `URLhaus: ${data.query_status}`;
      }
      return result;
    } catch (err) {
      result.error = err && err.name === "AbortError" ? "URLhaus request timed out" : `URLhaus: ${err.message}`;
      return result;
    }
  }

  async function getVtCallLog() {
    if (!PG.storage) return [];
    const log = await PG.storage.sessionGet("vtCalls");
    return Array.isArray(log) ? log : [];
  }

  async function vtBudget() {
    const log = await getVtCallLog();
    const cutoff = Date.now() - 60000;
    const recent = log.filter((ts) => ts > cutoff);
    if (recent.length >= VT_MAX_PER_MINUTE) {
      const oldest = Math.min(...recent);
      return { allowed: false, waitMs: Math.max(0, 60000 - (Date.now() - oldest)) };
    }
    return { allowed: true, waitMs: 0 };
  }

  async function recordVtCall() {
    if (!PG.storage) return;
    const log = await getVtCallLog();
    const cutoff = Date.now() - 5 * 60000;
    log.push(Date.now());
    await PG.storage.sessionSet("vtCalls", log.filter((ts) => ts > cutoff).slice(-20));
  }

  function statsToResult(stats, extra) {
    const malicious = Number(stats.malicious) || 0;
    const suspicious = Number(stats.suspicious) || 0;
    const harmless = Number(stats.harmless) || 0;
    const undetected = Number(stats.undetected) || 0;
    return {
      ...emptyVt(),
      ...(extra || {}),
      ok: true,
      skipped: false,
      found: true,
      malicious,
      suspicious,
      harmless,
      undetected,
      total: malicious + suspicious + harmless + undetected,
    };
  }

  async function checkVirusTotal(url, apiKey) {
    const result = emptyVt();
    if (!apiKey) {
      result.error = "No VirusTotal API key configured";
      return result;
    }
    try {
      const budget = await vtBudget();
      if (!budget.allowed) {
        result.error = `VirusTotal rate limit — try again in ${Math.ceil(budget.waitMs / 1000)}s`;
        return result;
      }
      await recordVtCall();

      const id = U.base64UrlEncode(url);
      const headers = { "x-apikey": apiKey };
      const lookup = await fetchWithTimeout(`${VT_BASE}/urls/${id}`, { headers });

      if (lookup.ok) {
        const json = await lookup.json();
        const attrs = (json && json.data && json.data.attributes) || {};
        if (attrs.last_analysis_stats) {
          return statsToResult(attrs.last_analysis_stats, {
            reputation: typeof attrs.reputation === "number" ? attrs.reputation : null,
            lastAnalysisDate: attrs.last_analysis_date || null,
            categories: attrs.categories || null,
            cachedLookup: true,
          });
        }
      } else if (lookup.status !== 404) {
        result.error = lookup.status === 429
          ? "VirusTotal quota exceeded (HTTP 429)"
          : `VirusTotal lookup failed (HTTP ${lookup.status})`;
        return result;
      }

      // Unknown URL — submit it for analysis and poll briefly.
      const submit = await fetchWithTimeout(`${VT_BASE}/urls`, {
        method: "POST",
        headers: { ...headers, "Content-Type": "application/x-www-form-urlencoded" },
        body: `url=${encodeURIComponent(url)}`,
      });
      if (!submit.ok) {
        result.ok = true;
        result.skipped = false;
        result.error = submit.status === 429
          ? "VirusTotal quota exceeded (HTTP 429)"
          : `VirusTotal submit failed (HTTP ${submit.status})`;
        return result;
      }
      const submitJson = await submit.json();
      const analysisId = submitJson && submitJson.data && submitJson.data.id;
      if (!analysisId) {
        result.ok = true;
        result.skipped = false;
        result.error = "VirusTotal did not return an analysis id";
        return result;
      }

      for (let attempt = 0; attempt < 3; attempt++) {
        await U.sleep(2200);
        const poll = await fetchWithTimeout(`${VT_BASE}/analyses/${analysisId}`, { headers });
        if (poll.status === 429) {
          result.error = "VirusTotal quota exceeded while waiting for results";
          break;
        }
        if (!poll.ok) continue;
        const pollJson = await poll.json();
        const attrs = (pollJson && pollJson.data && pollJson.data.attributes) || {};
        if (attrs.status === "completed" && attrs.stats) {
          return statsToResult(attrs.stats, { cachedLookup: false });
        }
      }

      result.ok = true;
      result.skipped = false;
      result.error = "Analysis is still running — scan again in a minute for vendor results";
      return result;
    } catch (err) {
      result.error = err && err.name === "AbortError" ? "VirusTotal request timed out" : `VirusTotal: ${err.message}`;
      return result;
    }
  }

  function configured(apiKeys) {
    const keys = apiKeys || {};
    return {
      urlhaus: !!keys.urlhaus,
      virustotal: !!keys.virustotal,
      any: !!(keys.urlhaus || keys.virustotal),
    };
  }

  /** Query every configured provider in parallel. Failures are non-fatal. */
  async function query(url, apiKeys) {
    const keys = apiKeys || {};
    const has = configured(keys);
    const jobs = [];
    jobs.push(has.urlhaus ? checkUrlhaus(url, keys.urlhaus) : Promise.resolve(emptyUrlhaus()));
    jobs.push(has.virustotal ? checkVirusTotal(url, keys.virustotal) : Promise.resolve(emptyVt()));
    const [urlhaus, virustotal] = await Promise.all(jobs);
    return { urlhaus, virustotal, configured: has };
  }

  PG.providers = {
    configured,
    query,
    checkUrlhaus,
    checkVirusTotal,
    vtBudget,
    emptyVt,
    emptyUrlhaus,
  };
})();
