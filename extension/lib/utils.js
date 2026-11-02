/* PhishGuard — shared utilities (classic script, works in MV3 worker + pages) */
(function () {
  "use strict";

  const PG = (globalThis.PG = globalThis.PG || {});
  const api = (PG.api = globalThis.browser || globalThis.chrome);

  /**
   * Cross-browser API invocation.
   * Firefox exposes promise-based `browser.*`; Chrome uses callbacks for
   * maximum compatibility across Chromium versions.
   */
  function invoke(area, name, ...args) {
    const fn = area && area[name];
    if (typeof fn !== "function") {
      return Promise.reject(new Error(`API ${name} is unavailable`));
    }
    if (globalThis.browser) {
      try {
        return Promise.resolve(fn.apply(area, args));
      } catch (err) {
        return Promise.reject(err);
      }
    }
    return new Promise((resolve, reject) => {
      let settled = false;
      const done = (value) => {
        if (settled) return;
        settled = true;
        const err = api.runtime && api.runtime.lastError;
        if (err) reject(new Error(err.message));
        else resolve(value);
      };
      let ret;
      try {
        ret = fn.call(area, ...args, done);
      } catch (err) {
        reject(err);
        return;
      }
      if (ret && typeof ret.then === "function") {
        ret.then(done, (err) => {
          if (!settled) reject(err);
        });
      }
    });
  }

  /** Send a message to the background worker and unwrap the envelope. */
  async function send(message) {
    if (!api || !api.runtime) throw new Error("Extension runtime unavailable");
    const res = await invoke(api.runtime, "sendMessage", message);
    if (!res) throw new Error("No response from PhishGuard background service");
    if (res.ok === false) throw new Error(res.error || "Request failed");
    return res.data;
  }

  const MULTI_PART_SUFFIXES = new Set([
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "net.nz", "org.nz",
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "ac.in", "edu.in",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "com.br", "net.br", "org.br",
    "com.mx", "com.ar", "com.co", "com.pe", "com.ve", "com.ec", "com.uy",
    "co.za", "org.za", "net.za", "co.ke", "co.tz", "com.ng",
    "com.sg", "com.my", "com.ph", "com.vn", "com.pk", "com.bd", "com.np", "com.lk",
    "co.id", "or.id", "ac.id", "go.id", "co.th", "in.th", "co.kr", "or.kr",
    "com.tr", "net.tr", "org.tr", "com.sa", "com.ae", "com.qa", "com.kw",
    "com.eg", "com.hk", "com.tw", "com.cn", "net.cn", "org.cn", "gov.cn",
    "co.il", "org.il", "com.ua", "com.pl", "com.ru", "com.es", "com.pt",
    "com.gr", "com.it", "co.at", "or.at", "com.de", "co.hu", "com.ro", "com.cz",
    "com.sk", "com.hr", "com.rs", "com.ba", "com.mk", "com.al", "com.cy", "com.mt",
    "com.co.za", "co.za", "org.uk", "sch.uk", "gov.in", "nic.in", "res.in",
  ]);

  // Hosts that are only ever reachable locally, so never scan/block them.
  const LOCAL_SUFFIXES = [".localhost", ".local", ".internal", ".test", ".example", ".invalid", ".home.arpa"];

  const TRACKER_PARAMS = new Set([
    "fbclid", "gclid", "dclid", "msclkid", "twclid", "igshid", "mc_cid", "mc_eid",
    "_ga", "_gl", "ref", "ref_src", "source", "campaign",
  ]);

  function normalizeInput(raw) {
    let value = String(raw == null ? "" : raw).trim();
    if (!value) return "";
    if (value.startsWith("<") && value.endsWith(">")) value = value.slice(1, -1);
    value = value.replace(/^["']|["']$/g, "");
    if (/^\/\//.test(value)) value = `https:${value}`;
    if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(value)) value = `https://${value}`;
    return value;
  }

  function parseUrl(raw) {
    const normalized = normalizeInput(raw);
    if (!normalized) return null;
    let url;
    try {
      url = new URL(normalized);
    } catch {
      return null;
    }
    if (!url.hostname) return null;
    const host = url.hostname.toLowerCase().replace(/\.$/, "");
    const labels = host.split(".").filter(Boolean);
    return {
      url: url.href,
      protocol: url.protocol,
      host,
      labels,
      registrable: registrableDomain(host),
      port: url.port,
      username: url.username,
      password: url.password,
      pathname: url.pathname || "/",
      search: url.search || "",
      hash: url.hash || "",
    };
  }

  function registrableDomain(host) {
    const labels = String(host).toLowerCase().split(".").filter(Boolean);
    if (labels.length <= 2) return labels.join(".");
    const tail2 = labels.slice(-2).join(".");
    const tail3 = labels.slice(-3).join(".");
    if (MULTI_PART_SUFFIXES.has(tail2) && labels.length >= 3) {
      return tail3;
    }
    // Common hosting suffixes should not make every subdomain look like a new site.
    return tail2;
  }

  function isIPv4(host) {
    const parts = String(host).split(".");
    if (parts.length !== 4) return false;
    return parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
  }

  function isIPv6(host) {
    return typeof host === "string" && host.includes(":") && /^[0-9a-f:.]+$/i.test(host);
  }

  function isIp(host) {
    return isIPv4(host) || isIPv6(host);
  }

  function isPrivateIp(host) {
    if (isIPv4(host)) {
      const [a, b] = host.split(".").map(Number);
      return (
        a === 10 ||
        a === 127 ||
        (a === 169 && b === 254) ||
        (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && b === 168) ||
        (a === 100 && b >= 64 && b <= 127) ||
        a === 0
      );
    }
    if (isIPv6(host)) {
      const h = host.toLowerCase();
      return h === "::1" || h.startsWith("fc") || h.startsWith("fd") || h.startsWith("fe80");
    }
    return false;
  }

  function isLocalHost(host) {
    const h = String(host || "").toLowerCase();
    if (!h) return true;
    if (h === "localhost" || h === "localhost.localdomain") return true;
    if (LOCAL_SUFFIXES.some((suffix) => h === suffix.slice(1) || h.endsWith(suffix))) return true;
    // Only private/link-local IPs are local. Public IP hosts are scannable —
    // phishing kits frequently serve pages straight from a bare address.
    if (isIp(h)) return isPrivateIp(h);
    if (!h.includes(".")) return true;
    return false;
  }

  function isScannableUrl(raw) {
    const parsed = parseUrl(raw);
    if (!parsed) return false;
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  }

  function stripTrackingParams(urlString) {
    try {
      const u = new URL(urlString);
      for (const key of [...u.searchParams.keys()]) {
        if (TRACKER_PARAMS.has(key.toLowerCase()) || key.toLowerCase().startsWith("utm_")) {
          u.searchParams.delete(key);
        }
      }
      return u.href;
    } catch {
      return urlString;
    }
  }

  /** Privacy-preserving URL for local history: no credentials, query or fragment. */
  function redactUrl(raw) {
    const parsed = parseUrl(raw);
    if (!parsed) return String(raw || "").split("?")[0].split("#")[0];
    const segments = parsed.pathname.split("/").filter(Boolean);
    const first = segments[0] ? `/${segments[0]}` : "/";
    let out = `${parsed.protocol}//${parsed.host}${first}`;
    if (segments.length > 1) out += "/…";
    return out;
  }

  function shortUrl(raw, max = 64) {
    const value = String(raw || "");
    if (value.length <= max) return value;
    const head = Math.ceil(max * 0.62);
    const tail = Math.max(6, max - head - 1);
    return `${value.slice(0, head)}…${value.slice(-tail)}`;
  }

  function hostOf(raw) {
    try {
      return new URL(normalizeInput(raw)).hostname.toLowerCase();
    } catch {
      return "";
    }
  }

  function rootDomain(host) {
    return registrableDomain(String(host || "").toLowerCase());
  }

  function clamp(value, min, max) {
    return Math.min(max, Math.max(min, value));
  }

  function randomId() {
    try {
      const bytes = new Uint8Array(8);
      crypto.getRandomValues(bytes);
      return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
    } catch {
      return `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
    }
  }

  async function sha256Hex(value) {
    try {
      const data = new TextEncoder().encode(String(value));
      const digest = await crypto.subtle.digest("SHA-256", data);
      return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
    } catch {
      // FNV-1a fallback (non-cryptographic, cache keys only)
      let h1 = 0x811c9dc5;
      let h2 = 0x01000193;
      for (let i = 0; i < value.length; i++) {
        const c = value.charCodeAt(i);
        h1 = Math.imul(h1 ^ c, 16777619) >>> 0;
        h2 = Math.imul(h2 ^ c, 2246822519) >>> 0;
      }
      return h1.toString(16).padStart(8, "0") + h2.toString(16).padStart(8, "0");
    }
  }

  function escapeHtml(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function escapeAttr(value) {
    return escapeHtml(value).replace(/`/g, "&#96;");
  }

  function timeAgo(timestamp) {
    const ts = typeof timestamp === "number" ? timestamp : Date.parse(timestamp);
    if (!Number.isFinite(ts)) return "unknown";
    const diff = Math.max(0, Date.now() - ts);
    const sec = Math.round(diff / 1000);
    if (sec < 45) return "just now";
    const min = Math.round(sec / 60);
    if (min < 60) return `${min}m ago`;
    const hr = Math.round(min / 60);
    if (hr < 24) return `${hr}h ago`;
    const day = Math.round(hr / 24);
    if (day < 30) return `${day}d ago`;
    return new Date(ts).toLocaleDateString();
  }

  function formatDateTime(timestamp) {
    const ts = typeof timestamp === "number" ? timestamp : Date.parse(timestamp);
    if (!Number.isFinite(ts)) return "";
    return new Date(ts).toLocaleString();
  }

  function levelFromScore(score, thresholds) {
    const t = thresholds || { suspicious: 40, malicious: 70 };
    if (score >= t.malicious) return "malicious";
    if (score >= t.suspicious) return "suspicious";
    return "safe";
  }

  function levelLabel(level) {
    if (level === "malicious") return "Malicious";
    if (level === "suspicious") return "Suspicious";
    return "Safe";
  }

  function levenshtein(a, b, max) {
    const s = String(a || "");
    const t = String(b || "");
    const limit = max == null ? Infinity : max;
    if (s === t) return 0;
    if (Math.abs(s.length - t.length) > limit) return limit + 1;
    const prev = new Array(t.length + 1);
    const curr = new Array(t.length + 1);
    for (let j = 0; j <= t.length; j++) prev[j] = j;
    for (let i = 1; i <= s.length; i++) {
      curr[0] = i;
      let rowMin = curr[0];
      for (let j = 1; j <= t.length; j++) {
        const cost = s[i - 1] === t[j - 1] ? 0 : 1;
        curr[j] = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
        rowMin = Math.min(rowMin, curr[j]);
      }
      if (rowMin > limit) return limit + 1;
      for (let j = 0; j <= t.length; j++) prev[j] = curr[j];
    }
    return prev[t.length];
  }

  /** Shannon entropy in bits per character. */
  function entropy(value) {
    const str = String(value || "");
    if (!str) return 0;
    const counts = new Map();
    for (const ch of str) counts.set(ch, (counts.get(ch) || 0) + 1);
    let result = 0;
    for (const count of counts.values()) {
      const p = count / str.length;
      result -= p * Math.log2(p);
    }
    return result;
  }

  function base64UrlEncode(value) {
    const bytes = new TextEncoder().encode(String(value));
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  function pick(obj, keys) {
    const out = {};
    for (const key of keys) {
      if (obj && Object.prototype.hasOwnProperty.call(obj, key)) out[key] = obj[key];
    }
    return out;
  }

  function isPlainObject(value) {
    return !!value && typeof value === "object" && !Array.isArray(value);
  }

  function safeJsonParse(value, fallback) {
    try {
      const parsed = JSON.parse(value);
      return parsed == null ? fallback : parsed;
    } catch {
      return fallback;
    }
  }

  PG.utils = {
    api,
    invoke,
    send,
    normalizeInput,
    parseUrl,
    registrableDomain,
    rootDomain,
    hostOf,
    isIPv4,
    isIPv6,
    isIp,
    isPrivateIp,
    isLocalHost,
    isScannableUrl,
    stripTrackingParams,
    redactUrl,
    shortUrl,
    clamp,
    randomId,
    sha256Hex,
    escapeHtml,
    escapeAttr,
    timeAgo,
    formatDateTime,
    levelFromScore,
    levelLabel,
    levenshtein,
    entropy,
    base64UrlEncode,
    sleep,
    pick,
    isPlainObject,
    safeJsonParse,
  };

  // Extension pages call PG.send(...) directly. Keep a top-level alias so both
  // PG.send() and PG.utils.send() work (the pages only load this file).
  PG.send = send;
})();
