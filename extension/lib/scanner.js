/* PhishGuard — scan orchestration: heuristics + providers + cache + policy */
(function () {
  "use strict";

  const PG = (globalThis.PG = globalThis.PG || {});
  const U = PG.utils;
  const C = PG.constants;

  const FEED_WEIGHTS = {
    urlhaus: 55,
    vtMalicious: 25,
    vtMultiple: 15,
    vtMany: 10,
    vtSuspicious: 8,
  };

  function feedReason(id, label, weight, severity, detail, source) {
    return { id, label, weight, severity, detail, source };
  }

  function dangerousSchemeResult(parsed) {
    return {
      id: U.randomId(),
      url: parsed ? parsed.url : "",
      host: parsed ? parsed.host : "",
      registrable: parsed ? parsed.registrable : "",
      protocol: parsed ? parsed.protocol : "",
      score: 95,
      level: "malicious",
      reasons: [
        feedReason("dangerous-scheme", "Dangerous URL scheme", C.WEIGHTS.dangerousScheme, "high",
          "javascript: and data: URLs can execute code or render fake pages. Never open this.", "heuristic"),
      ],
      sources: { heuristics: { score: 95, reasons: [] }, urlhaus: PG.providers.emptyUrlhaus(), virustotal: PG.providers.emptyVt(), configured: { urlhaus: false, virustotal: false, any: false } },
      deep: false,
      skipped: false,
      trusted: false,
      cached: false,
      scannedAt: Date.now(),
    };
  }

  function combineScores(heuristicScore, reasons, urlhaus, virustotal, settings) {
    let score = heuristicScore;

    if (urlhaus && urlhaus.listed) {
      score += FEED_WEIGHTS.urlhaus;
      const tags = (urlhaus.tags || []).join(", ");
      reasons.push(feedReason(
        "urlhaus-listed",
        "Listed in the URLhaus malware feed",
        FEED_WEIGHTS.urlhaus,
        "high",
        [urlhaus.threat ? `Threat: ${urlhaus.threat}.` : "", tags ? `Tags: ${tags}.` : "", urlhaus.urlStatus ? `Status: ${urlhaus.urlStatus}.` : ""].filter(Boolean).join(" "),
        "urlhaus",
      ));
    }

    if (virustotal && virustotal.total > 0) {
      if (virustotal.malicious > 0) {
        score += FEED_WEIGHTS.vtMalicious;
        reasons.push(feedReason(
          "vt-malicious",
          `${virustotal.malicious} of ${virustotal.total} VirusTotal vendors flagged this URL as malicious`,
          FEED_WEIGHTS.vtMalicious,
          "high",
          "Multiple independent security engines detected malicious content at this address.",
          "virustotal",
        ));
      }
      if (virustotal.malicious >= 4) {
        score += FEED_WEIGHTS.vtMultiple;
        reasons.push(feedReason("vt-multiple", "Multiple vendors agree this is malicious", FEED_WEIGHTS.vtMultiple, "high",
          `${virustotal.malicious} engines flagged the URL.`, "virustotal"));
      }
      if (virustotal.malicious >= 10) {
        score += FEED_WEIGHTS.vtMany;
        reasons.push(feedReason("vt-many", "Strong consensus across VirusTotal vendors", FEED_WEIGHTS.vtMany, "high",
          `${virustotal.malicious} engines flagged the URL.`, "virustotal"));
      }
      if (virustotal.suspicious > 0) {
        score += FEED_WEIGHTS.vtSuspicious;
        reasons.push(feedReason("vt-suspicious", `${virustotal.suspicious} VirusTotal vendors flagged this URL as suspicious`, FEED_WEIGHTS.vtSuspicious, "medium",
          "Suspicious verdicts are weaker than malicious ones but still worth avoiding.", "virustotal"));
      }
    }

    score = U.clamp(Math.round(score), 0, 100);
    const level = U.levelFromScore(score, {
      suspicious: settings.suspiciousThreshold,
      malicious: settings.blockThreshold,
    });
    return { score, level };
  }

  function isFeedFlagged(result) {
    const urlhaus = result && result.sources && result.sources.urlhaus;
    const vt = result && result.sources && result.sources.virustotal;
    return !!(
      (urlhaus && urlhaus.listed) ||
      (vt && vt.malicious >= 3)
    );
  }

  function shouldBlock(result, settings) {
    if (!result || result.skipped) return false;
    if (!settings.protection || !settings.blockMalicious) return false;
    if (result.trusted === "allowlist") return false;
    if (result.sources && result.sources.urlhaus && result.sources.urlhaus.listed) return true;
    if (result.sources && result.sources.virustotal && result.sources.virustotal.malicious >= 3) return true;
    if (result.trusted === "reputation") return false;
    if (result.score >= settings.blockThreshold) return true;
    if (settings.blockSuspicious && result.score >= settings.suspiciousThreshold) return true;
    return false;
  }

  function shouldWarn(result, settings) {
    if (!result || result.skipped || result.trusted === "allowlist") return false;
    if (result.level === "malicious") return true;
    return result.level === "suspicious" && result.score >= settings.suspiciousThreshold;
  }

  function mergeHostVerdict(result, verdict, settings) {
    if (!verdict) return result;
    const extraReasons = Array.isArray(verdict.reasons) ? verdict.reasons : [];
    const known = new Set(result.reasons.map((reason) => reason.id));
    for (const reason of extraReasons) {
      if (!known.has(reason.id)) {
        result.reasons.push({ ...reason, detail: reason.detail || "Previously confirmed for this domain." });
      }
    }
    result.score = Math.max(result.score, Number(verdict.score) || 0);
    result.sources = { ...result.sources, ...(verdict.sources || {}) };
    result.hostVerdict = true;
    result.verdictAt = verdict.ts || 0;
    result.level = U.levelFromScore(result.score, {
      suspicious: settings.suspiciousThreshold,
      malicious: settings.blockThreshold,
    });
    return result;
  }

  /**
   * Scan a URL.
   * @param {string} rawUrl
   * @param {object} [options] { deep, force, trigger, record, settings }
   * @returns {Promise<object>} normalized scan result
   */
  async function scan(rawUrl, options) {
    const opts = options || {};
    const settings = opts.settings || (await PG.storage.getSettings());

    // javascript:/data: links have no hostname, so catch them before parsing.
    const raw = String(rawUrl == null ? "" : rawUrl).trim();
    const dangerousScheme = /^(javascript|data|vbscript|file):/i.exec(raw);
    if (dangerousScheme) {
      return dangerousSchemeResult({
        url: raw,
        host: "",
        registrable: "",
        protocol: `${dangerousScheme[1].toLowerCase()}:`,
      });
    }

    const parsed = U.parseUrl(rawUrl);
    if (!parsed) {
      throw new Error("Enter a valid URL, for example https://example.com");
    }

    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return dangerousSchemeResult(parsed);
    }

    const heuristic = PG.heuristics.analyze(parsed);

    const trusted = await PG.storage.isTrustedDomain(parsed.host);
    const allowlisted = PG.storage.isAllowlisted(parsed.host, settings);
    const trustedKind = allowlisted ? "allowlist" : trusted ? "reputation" : false;

    const base = {
      id: U.randomId(),
      url: parsed.url,
      host: parsed.host,
      registrable: parsed.registrable,
      protocol: parsed.protocol,
      score: heuristic.score,
      level: U.levelFromScore(heuristic.score, {
        suspicious: settings.suspiciousThreshold,
        malicious: settings.blockThreshold,
      }),
      reasons: [...heuristic.reasons],
      sources: {
        heuristics: { score: heuristic.score, reasons: heuristic.reasons, brand: heuristic.brand || null },
        urlhaus: PG.providers.emptyUrlhaus(),
        virustotal: PG.providers.emptyVt(),
        configured: PG.providers.configured(settings.apiKeys),
      },
      deep: false,
      skipped: !!heuristic.skipped,
      note: heuristic.note || null,
      trusted: trustedKind,
      cached: false,
      scannedAt: Date.now(),
      trigger: opts.trigger || "manual",
    };

    // Private / local addresses are never rated or blocked.
    if (heuristic.skipped) {
      base.score = 0;
      base.level = "safe";
      return base;
    }

    // Reuse a recently stored verdict for this domain (from earlier feed scans).
    if (!opts.force) {
      const verdict = await PG.storage.getHostVerdict(parsed.host);
      if (verdict) {
        mergeHostVerdict(base, verdict, settings);
        base.cached = true;
      }
    }

    const providersConfigured = base.sources.configured.any;

    // Deep scan: cached full-URL result first, then live providers.
    if (opts.deep && providersConfigured) {
      let cached = null;
      if (!opts.force) cached = await PG.storage.getCachedScan(parsed.url, settings);

      if (cached) {
        const cachedSources = cached.sources || {};
        const enriched = {
          ...base,
          sources: {
            heuristics: base.sources.heuristics,
            urlhaus: cachedSources.urlhaus || PG.providers.emptyUrlhaus(),
            virustotal: cachedSources.virustotal || PG.providers.emptyVt(),
            configured: base.sources.configured,
          },
          reasons: [...base.reasons],
          deep: true,
          cached: true,
        };
        const merged = combineScores(base.sources.heuristics.score, enriched.reasons, enriched.sources.urlhaus, enriched.sources.virustotal, settings);
        enriched.score = merged.score;
        enriched.level = merged.level;
        return finish(enriched, opts, settings);
      }

      const feeds = await PG.providers.query(parsed.url, settings.apiKeys);
      base.sources.urlhaus = feeds.urlhaus;
      base.sources.virustotal = feeds.virustotal;
      base.deep = true;

      const merged = combineScores(base.sources.heuristics.score, base.reasons, feeds.urlhaus, feeds.virustotal, settings);
      base.score = merged.score;
      base.level = merged.level;

      if (!feeds.urlhaus.listed && feeds.virustotal.total === 0 && !feeds.urlhaus.error && !feeds.virustotal.error) {
        base.reasons.push(feedReason("clean-feeds", "No detections in the configured threat feeds", 0, "info",
          "Not being listed today does not guarantee a site is safe.", "provider"));
      } else if (feeds.urlhaus.error) {
        base.reasons.push(feedReason("urlhaus-error", "URLhaus check unavailable", 0, "info", feeds.urlhaus.error, "provider"));
      } else if (feeds.virustotal.error) {
        base.reasons.push(feedReason("vt-error", "VirusTotal check unavailable", 0, "info", feeds.virustotal.error, "provider"));
      }

      if (isFeedFlagged(base) || base.score >= settings.suspiciousThreshold) {
        await PG.storage.setHostVerdict(parsed.host, base);
      }
      await PG.storage.setCachedScan(parsed.url, base, settings);
    }

    return finish(base, opts, settings);
  }

  async function finish(result, opts, settings) {
    const recordMode = opts.record === undefined ? "always" : opts.record;
    const shouldRecord =
      recordMode === "always" ||
      recordMode === true ||
      (recordMode === "risky" && result.level !== "safe");

    if (shouldRecord) {
      const historyUrl = settings.redactHistory ? U.redactUrl(result.url) : U.stripTrackingParams(result.url);
      await PG.storage.addHistory({
        url: historyUrl,
        host: result.host,
        score: result.score,
        level: result.level,
        reasons: result.reasons.filter((reason) => reason.weight > 0).slice(0, 6),
        sources: {
          urlhaus: result.sources.urlhaus.listed,
          vtMalicious: result.sources.virustotal.malicious,
          vtSuspicious: result.sources.virustotal.suspicious,
        },
        deep: result.deep,
        trigger: result.trigger,
      });
      await PG.storage.bumpStats({
        scans: 1,
        deepScans: result.deep ? 1 : 0,
        lastScanAt: Date.now(),
      });
    }
    return result;
  }

  PG.scanner = {
    scan,
    shouldBlock,
    shouldWarn,
    isFeedFlagged,
    combineScores,
  };
})();
