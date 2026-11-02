/* PhishGuard — offline heuristic URL engine (no network, runs in <5ms) */
(function () {
  "use strict";

  const PG = (globalThis.PG = globalThis.PG || {});
  const U = PG.utils;
  const C = PG.constants;

  function makeReason(id, label, weight, severity, detail) {
    return { id, label, weight, severity, detail, source: "heuristic" };
  }

  function brandMatchesOfficial(brand, host) {
    return brand.domains.some((domain) => host === domain || host.endsWith(`.${domain}`));
  }

  function hasBoundaryToken(tokens, name) {
    return tokens.includes(name);
  }

  function detectBrandImpersonation(parsed) {
    const { host, labels, registrable } = parsed;
    const rootLabels = registrable.split(".");
    const rootMain = rootLabels[0] || "";
    const rootTokens = rootMain.split(/[^a-z0-9]+/).filter(Boolean);
    const subLabels = labels.slice(0, Math.max(0, labels.length - rootLabels.length));
    const lowerHost = host.toLowerCase();

    for (const brand of C.BRANDS) {
      if (brandMatchesOfficial(brand, lowerHost)) continue;
      const name = brand.name;

      const inSubdomain = subLabels.some((label) => label === name || label.split(/[^a-z0-9]+/).includes(name));
      if (inSubdomain) {
        return {
          type: "subdomain",
          brand: name,
          weight: C.WEIGHTS.brandImpersonation,
          label: `“${name}” used in a subdomain of an unrelated site`,
          detail: `The brand name appears in the hostname, but the registered domain is ${registrable}.`,
        };
      }

      if (hasBoundaryToken(rootTokens, name)) {
        return {
          type: "token",
          brand: name,
          weight: C.WEIGHTS.brandImpersonation,
          label: `“${name}” combined with other words in the domain`,
          detail: `Brand names are rarely combined with extra words by the real owner (${registrable}).`,
        };
      }

      const maxDistance = name.length >= 8 ? 2 : 1;
      const distance = U.levenshtein(rootMain, name, maxDistance);
      if (distance > 0 && distance <= maxDistance && Math.abs(rootMain.length - name.length) <= 2) {
        return {
          type: "typo",
          brand: name,
          weight: C.WEIGHTS.typosquat,
          label: `Possible look-alike of “${name}”`,
          detail: `The domain ${registrable} is one or two characters away from the real brand domain.`,
        };
      }

      if (rootMain.includes(name) && C.HOST_KEYWORDS.some((word) => lowerHost.includes(word))) {
        return {
          type: "glued",
          brand: name,
          weight: C.WEIGHTS.brandImpersonation,
          label: `“${name}” glued to a login or security keyword`,
          detail: `The domain mixes a brand with urgency language, a common phishing pattern.`,
        };
      }
    }
    return null;
  }

  function countRedirectTarget(parsed) {
    try {
      const url = new URL(parsed.url);
      const candidates = ["url", "redirect", "redirect_uri", "next", "target", "dest", "destination", "continue", "return", "returnurl", "return_url", "goto", "link"];
      for (const key of candidates) {
        const value = url.searchParams.get(key);
        if (!value) continue;
        let decoded = value;
        try {
          decoded = decodeURIComponent(value);
        } catch {
          /* keep raw */
        }
        const targetHost = U.hostOf(decoded);
        if (targetHost && targetHost !== parsed.host) {
          return { key, targetHost };
        }
      }
    } catch {
      /* ignore */
    }
    return null;
  }

  function analyze(input) {
    const parsed = typeof input === "string" ? U.parseUrl(input) : input;
    if (!parsed) {
      return { parsed: null, score: 0, reasons: [], skipped: false, error: "invalid-url" };
    }

    const reasons = [];
    const { host, labels, registrable, protocol, pathname, search, port, username, password } = parsed;
    const lowerHost = host.toLowerCase();
    const lowerPath = `${pathname}${search}`.toLowerCase();
    const add = (id, label, weight, severity, detail) => {
      if (weight > 0) reasons.push(makeReason(id, label, weight, severity, detail));
    };

    if (U.isLocalHost(host)) {
      return {
        parsed,
        score: 0,
        reasons: [],
        skipped: true,
        note: "Local or private address — not rated.",
      };
    }

    /* ---------------------------- strong signals ---------------------------- */

    if (U.isIp(host)) {
      add("ip-host", "Direct IP address instead of a domain", C.WEIGHTS.ipHost, "high",
        "Phishing kits often host pages on bare IP addresses to avoid domain reputation.");
    }

    if (username || password) {
      add("credentials", "Username or password embedded in the link", C.WEIGHTS.credentials, "high",
        "Everything before the @ is ignored by browsers, so the real destination can be hidden.");
    }

    if (lowerHost.includes("xn--")) {
      add("punycode", "Punycode domain (possible look-alike characters)", C.WEIGHTS.punycode, "high",
        "Punycode can render a foreign alphabet that mimics a well-known brand.");
    }

    const tld = labels[labels.length - 1] || "";
    if (C.SUSPICIOUS_TLDS.has(tld)) {
      add("suspicious-tld", `High-abuse top-level domain (.${tld})`, C.WEIGHTS.suspiciousTld, "medium",
        `.${tld} is frequently used for disposable phishing infrastructure.`);
    } else if (C.SHADY_TLDS.has(tld)) {
      add("shady-tld", `Cheap, frequently abused top-level domain (.${tld})`, C.WEIGHTS.shadyTld, "low",
        `.${tld} registrations are inexpensive and commonly used for scam pages.`);
    }

    const brand = detectBrandImpersonation(parsed);
    if (brand) {
      add("brand-impersonation", brand.label, brand.weight, "high", brand.detail);
    }

    if (lowerHost.includes("xn--") === false && /[\u0400-\u04FF\u0370-\u03FF\u2000-\u206F]/.test(host)) {
      add("mixed-script", "Mixed-script or unusual characters in hostname", 16, "high",
        "Characters from multiple alphabets can disguise a domain.");
    }

    if (C.DOUBLE_EXTENSION_RE.test(pathname)) {
      add("double-extension", "Double file extension", C.WEIGHTS.doubleExtension, "high",
        "A file that looks like a document but actually runs as a program is a classic malware trick.");
    }

    /* ----------------------------- structural ------------------------------ */

    const labelCount = labels.length;
    if (labelCount > 5) {
      add("many-dots", "Unusually deep subdomain chain", C.WEIGHTS.manyLabels + 4, "medium",
        `${labelCount} labels — attackers stack subdomains to look legitimate and evade detection.`);
    } else if (labelCount > 4) {
      add("many-labels", "Many subdomains", C.WEIGHTS.manyLabels, "low",
        "Long subdomain chains are common in phishing URLs.");
    }

    if (port && !["80", "443", "8080", "8443", "3000", "5000", "8000"].includes(port)) {
      add("unusual-port", `Non-standard port :${port}`, C.WEIGHTS.unusualPort, "medium",
        "Legitimate websites rarely serve login pages from unusual ports.");
    }

    if (host.length > 40) {
      add("long-host", "Very long hostname", C.WEIGHTS.longHost, "low",
        "Excessively long hostnames are used to hide the real domain.");
    }

    const rootMain = registrable.split(".")[0] || "";
    const hyphenCount = (rootMain.match(/-/g) || []).length;
    if (hyphenCount >= 3) {
      add("many-hyphens", "Multiple hyphens in the domain", C.WEIGHTS.manyHyphens, "low",
        "Domains with three or more hyphens are disproportionately used for scams.");
    }

    if (rootMain.length >= 16 && /[0-9]/.test(rootMain) && /[a-z]/.test(rootMain) && U.entropy(rootMain) >= 3.4) {
      add("random-label", "Random-looking domain name", C.WEIGHTS.randomLabel, "low",
        "The registered domain looks machine-generated.");
    }

    if (C.URL_SHORTENERS.has(registrable)) {
      add("shortener", "URL shortener hides the final destination", C.WEIGHTS.shortener, "low",
        "Shortened links can lead anywhere — expand and verify before signing in.");
    }

    if (C.DYNAMIC_DNS.has(registrable)) {
      add("dynamic-dns", "Free dynamic DNS provider", C.WEIGHTS.dynamicDns, "medium",
        "Free DNS tunnels let attackers serve pages from throwaway hosts.");
    }

    /* ------------------------------ keywords ------------------------------- */

    const hostHits = C.HOST_KEYWORDS.filter((word) => lowerHost.includes(word));
    if (hostHits.length) {
      add("host-keywords", `Login/urgency keywords in the hostname`, C.WEIGHTS.hostKeywords, "medium",
        `Contains: ${hostHits.slice(0, 4).join(", ")}.`);
      if (hostHits.length >= 2) {
        reasons.push(makeReason("host-keywords-multi", "Multiple phishing keywords in hostname",
          C.WEIGHTS.manyHostKeywords, "medium", `Contains: ${hostHits.slice(0, 6).join(", ")}.`));
      }
    }

    const pathHits = C.PATH_KEYWORDS.filter((word) => lowerPath.includes(word));
    if (pathHits.length) {
      add("path-keywords", "Login or payment language in the path", C.WEIGHTS.pathKeywords, "low",
        `Contains: ${pathHits.slice(0, 4).join(", ")}.`);
    }

    if (protocol === "http:" && pathHits.length && (username || /login|signin|account|password|payment|billing/.test(lowerPath))) {
      add("http-credential-form", "Unencrypted login or payment page", C.WEIGHTS.httpCredentialForm, "high",
        "Credentials entered on an HTTP page travel in clear text.");
    }

    if (protocol === "http:") {
      reasons.push(makeReason("no-https", "Not encrypted (HTTP)", 0, "info",
        "Traffic to this site can be read or modified on the network."));
    }

    /* ------------------------------ obfuscation ---------------------------- */

    if (/(%[0-9a-f]{2}){4,}/i.test(`${pathname}${search}`)) {
      add("encoded-path", "Heavily encoded URL path", C.WEIGHTS.encodedPath, "medium",
        "Heavy percent-encoding is often used to hide a malicious payload or redirect.");
    }

    if (pathname.length > 140) {
      add("long-path", "Unusually long URL path", C.WEIGHTS.longPath, "low",
        "Very long paths are used to push the real domain out of view.");
    }

    const redirect = countRedirectTarget(parsed);
    if (redirect) {
      add("embedded-redirect", "Redirect parameter points to another site", C.WEIGHTS.embeddedRedirect, "medium",
        `The “${redirect.key}” parameter points to ${redirect.targetHost}.`);
    }

    /* --------------------------- combination bonuses ----------------------- */

    const hasBrandSignal = !!brand;
    const aggravating = C.SUSPICIOUS_TLDS.has(tld) || U.isIp(host) || lowerHost.includes("xn--") || labelCount > 4 || hostHits.length > 0 || pathHits.length > 0;
    if (hasBrandSignal && aggravating) {
      reasons.push(makeReason("brand-combo", "Brand impersonation combined with other red flags",
        C.WEIGHTS.brandCombo, "high",
        "Individually these signals are noisy — together they strongly indicate phishing."));
    }

    if (U.isIp(host) && pathHits.length > 0) {
      reasons.push(makeReason("ip-login-combo", "Login or payment path on a bare IP address",
        14, "high",
        "Legitimate services publish a domain name; a login page reached through a raw IP is a strong phishing signal."));
    }

    let score = reasons.reduce((sum, reason) => sum + (reason.weight || 0), 0);
    score = U.clamp(Math.round(score), 0, C.MAX_HEURISTIC_SCORE);

    // Keep the highest-signal reasons first, info reasons last.
    const order = { high: 0, medium: 1, low: 2, info: 3 };
    reasons.sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9) || b.weight - a.weight);

    return {
      parsed,
      score,
      reasons,
      skipped: false,
      brand: brand ? { type: brand.type, name: brand.brand } : null,
    };
  }

  PG.heuristics = { analyze, detectBrandImpersonation };
})();
