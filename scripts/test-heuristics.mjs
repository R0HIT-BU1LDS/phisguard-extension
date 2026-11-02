#!/usr/bin/env node
/**
 * Offline heuristic regression tests.
 * Loads the classic extension scripts into a VM with no browser APIs and checks
 * that everyday URLs stay safe while common phishing patterns are flagged.
 *
 * Usage: npm run test:extension  (or: node scripts/test-heuristics.mjs)
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const here = dirname(fileURLToPath(import.meta.url));
const extensionDir = join(here, "..", "extension");

const sandbox = {
  console,
  URL,
  URLSearchParams,
  TextEncoder,
  TextDecoder,
  setTimeout,
  clearTimeout,
  btoa: (value) => Buffer.from(String(value), "binary").toString("base64"),
  atob: (value) => Buffer.from(String(value), "base64").toString("binary"),
};
sandbox.globalThis = sandbox;

const context = vm.createContext(sandbox);

for (const file of ["lib/utils.js", "lib/constants.js", "lib/heuristics.js"]) {
  const code = readFileSync(join(extensionDir, file), "utf8");
  vm.runInContext(code, context, { filename: file });
}

const PG = sandbox.PG;
const U = PG.utils;
const C = PG.constants;
const THRESHOLDS = C.THRESHOLDS;

let failures = 0;
let passes = 0;

function check(name, condition, detail) {
  if (condition) {
    passes += 1;
    console.log(`  ok   ${name}`);
  } else {
    failures += 1;
    console.log(`  FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
}

function scan(url) {
  return PG.heuristics.analyze(url);
}

function levelOf(score) {
  return U.levelFromScore(score, THRESHOLDS);
}

function expectLevel(url, expected, extras) {
  const result = scan(url);
  const level = levelOf(result.score);
  const ok = level === expected;
  check(
    `${url} → ${expected}`,
    ok,
    `got ${level} (score ${result.score}) signals: ${result.reasons.map((r) => r.id).join(", ")}`,
  );
  if (extras && extras.includes) {
    for (const id of extras.includes) {
      check(`  has signal ${id}`, result.reasons.some((r) => r.id === id), result.reasons.map((r) => r.id).join(", "));
    }
  }
  return result;
}

console.log("\nMessaging API contract");
{
  // UI pages call PG.send(...) directly, so the alias must exist at the top level.
  check("PG.send is exposed for UI pages", typeof PG.send === "function");
  check("PG.utils.send is exposed", typeof U.send === "function");
  check("PG.send and PG.utils.send match", PG.send === U.send);
}

console.log("\nURL parsing");
{
  const parsed = U.parseUrl("HTTPS://user:pass@Sub.Example.CO.UK:8443/a/b?x=1#frag");
  check("scheme lowercased", parsed && parsed.protocol === "https:", parsed && parsed.protocol);
  check("hostname lowercased", parsed && parsed.host === "sub.example.co.uk", parsed && parsed.host);
  check("multi-part registrable domain", parsed && parsed.registrable === "example.co.uk", parsed && parsed.registrable);
  check("credentials captured", parsed && parsed.username === "user" && parsed.password === "pass");
  check("bare domain gets https", U.parseUrl("example.com").protocol === "https:");
  check("invalid input rejected", U.parseUrl("http://") === null);
}

console.log("\nLocal / private addresses");
{
  check("localhost is local", U.isLocalHost("localhost") === true);
  check("192.168 private is local", U.isLocalHost("192.168.1.10") === true);
  check("10.x private is local", U.isLocalHost("10.4.5.6") === true);
  check("127 loopback is local", U.isLocalHost("127.0.0.1") === true);
  check("public IPv4 is not local", U.isLocalHost("8.8.8.8") === false);
  check("public IPv6 is not local", U.isLocalHost("2001:4860:4860::8888") === false);
}

console.log("\nRedaction");
{
  check(
    "query and credentials removed",
    U.redactUrl("https://user:pass@example.com/account/reset?token=secret#x") === "https://example.com/account/…",
    U.redactUrl("https://user:pass@example.com/account/reset?token=secret#x"),
  );
}

console.log("\nEveryday sites stay safe");
for (const url of [
  "https://example.com",
  "https://www.google.com/search?q=weather",
  "https://github.com/openai/codex",
  "https://en.wikipedia.org/wiki/Phishing",
  "https://stackoverflow.com/questions/12345",
  "https://www.amazon.in/gp/cart/view.html",
  "https://outlook.office.com/mail/",
  "https://www.irctc.co.in/nget/train-search",
]) {
  expectLevel(url, "safe");
}

console.log("\nPrivate hosts are skipped");
for (const url of ["http://localhost:3000/admin", "http://192.168.1.1/login", "http://127.0.0.1:8080/"]) {
  const result = scan(url);
  check(`${url} skipped`, result.skipped === true && result.score === 0, `skipped=${result.skipped} score=${result.score}`);
}

console.log("\nPhishing patterns are flagged");
expectLevel("https://microsoft.com.login-verify.xyz/account", "malicious", {
  includes: ["brand-impersonation", "suspicious-tld", "host-keywords"],
});
expectLevel("https://paypal.com.account-verify.example-secure.tk/login", "malicious", {
  includes: ["brand-impersonation", "suspicious-tld", "brand-combo"],
});
expectLevel("https://appleid-apple.com.secure-signin.top/verify", "malicious", {
  includes: ["brand-impersonation"],
});
expectLevel("https://paypa1.com/login", "suspicious", { includes: ["brand-impersonation", "brand-combo"] });
expectLevel("http://8.8.8.8/login", "suspicious", { includes: ["ip-host", "ip-login-combo"] });
expectLevel("https://xn--pypal-4ve.com/", "safe", { includes: ["punycode"] });
expectLevel("https://files.example.com/invoice.pdf.exe", "safe", { includes: ["double-extension"] });
expectLevel("https://bit.ly/3xYzAbC", "safe", { includes: ["shortener"] });
expectLevel("https://secure-login.duckdns.org/verify", "suspicious", {
  includes: ["dynamic-dns", "host-keywords"],
});

console.log("\nReason ordering and shape");
{
  const result = scan("https://paypal.com.account-verify.example-secure.tk/login");
  const firstHigh = result.reasons.findIndex((r) => r.severity === "high");
  const firstInfo = result.reasons.findIndex((r) => r.severity === "info");
  check("high severity before info", firstHigh === -1 || firstInfo === -1 || firstHigh < firstInfo);
  check("every reason has id/label/weight", result.reasons.every((r) => r.id && r.label && typeof r.weight === "number"));
  check("score capped at max", result.score <= C.MAX_HEURISTIC_SCORE);
}

console.log("\nTrusted-domain registry integrity");
{
  const duplicates = new Set();
  let duplicateFound = false;
  for (const brand of C.BRANDS) {
    if (duplicates.has(brand.name)) duplicateFound = true;
    duplicates.add(brand.name);
    if (!Array.isArray(brand.domains) || brand.domains.length === 0) {
      duplicateFound = true;
    }
  }
  check("brands have names and domains", !duplicateFound);
  check("thresholds are ordered", THRESHOLDS.suspicious < THRESHOLDS.malicious);
}

console.log("\nBlocking policy (scanner)");
{
  // Load the rest of the pipeline and stub browser storage for Node.
  for (const file of ["lib/providers.js", "lib/scanner.js"]) {
    vm.runInContext(readFileSync(join(extensionDir, file), "utf8"), context, { filename: file });
  }

  const settings = {
    protection: true,
    blockMalicious: true,
    blockSuspicious: false,
    blockThreshold: 70,
    suspiciousThreshold: 40,
    redactHistory: true,
    historyLimit: 50,
    cacheTtlHours: 12,
    apiKeys: { urlhaus: "", virustotal: "" },
    allowlist: [],
  };

  sandbox.PG.storage = {
    getSettings: async () => settings,
    isTrustedDomain: async () => false,
    isAllowlisted: (host, cfg) =>
      (cfg.allowlist || []).some((entry) => host === entry || host.endsWith(`.${entry}`)),
    getHostVerdict: async () => null,
    getCachedScan: async () => null,
    setHostVerdict: async () => {},
    setCachedScan: async () => {},
    addHistory: async () => {},
    bumpStats: async () => {},
  };

  const scanner = sandbox.PG.scanner;
  const opts = { settings, record: false };
  const phishing = "https://paypal.com.account-verify.example-secure.tk/login";

  const malicious = await scanner.scan(phishing, opts);
  check("malicious URL is blocked", scanner.shouldBlock(malicious, settings) === true, `score ${malicious.score}`);
  check("malicious URL is warned about", scanner.shouldWarn(malicious, settings) === true);

  const safe = await scanner.scan("https://example.com", opts);
  check("safe URL is not blocked", scanner.shouldBlock(safe, settings) === false, `score ${safe.score}`);

  const trustedSettings = { ...settings, allowlist: ["example-secure.tk"] };
  const trusted = await scanner.scan(phishing, { settings: trustedSettings, record: false });
  check("allowlisted host is not blocked", scanner.shouldBlock(trusted, trustedSettings) === false);
  check("allowlisted host is not warned about", scanner.shouldWarn(trusted, trustedSettings) === false);

  const suspicious = await scanner.scan("https://paypa1.com/login", opts);
  check("suspicious site is not blocked by default", scanner.shouldBlock(suspicious, settings) === false);
  check(
    "suspicious site is blocked when blockSuspicious is on",
    scanner.shouldBlock(suspicious, { ...settings, blockSuspicious: true }) === true,
  );

  const dangerous = await scanner.scan("javascript:alert(1)", opts);
  check(
    "dangerous scheme result is malicious and blocked",
    dangerous.level === "malicious" && scanner.shouldBlock(dangerous, settings) === true,
  );

  check(
    "disabling protection disables blocking",
    scanner.shouldBlock(malicious, { ...settings, protection: false }) === false,
  );
  check(
    "disabling blockMalicious disables blocking",
    scanner.shouldBlock(malicious, { ...settings, blockMalicious: false }) === false,
  );
}

console.log("\nReport export (deep scan)");
{
  vm.runInContext(readFileSync(join(extensionDir, "shared/report.js"), "utf8"), context, {
    filename: "shared/report.js",
  });
  const ui = sandbox.PG.ui;
  const sample = {
    id: "scan-1",
    url: "https://paypal.com.account-verify.example-secure.tk/login?next=<script>alert(1)</script>",
    host: "paypal.com.account-verify.example-secure.tk",
    registrable: "example-secure.tk",
    protocol: "https:",
    score: 100,
    level: "malicious",
    deep: true,
    trigger: "manual",
    scannedAt: Date.UTC(2026, 0, 2, 3, 4, 5),
    trusted: false,
    cached: false,
    reasons: [
      {
        id: "brand-impersonation",
        label: "Brand impersonation <b>",
        weight: 40,
        severity: "high",
        detail: "Host mentions paypal but is not paypal.com.",
        source: "heuristic",
      },
    ],
    sources: {
      heuristics: { score: 100, reasons: [] },
      urlhaus: {
        ok: true,
        listed: true,
        threat: "malware_download",
        tags: ["elf", "mozi"],
        urlStatus: "online",
        reference: "https://urlhaus.abuse.ch/url/1/",
        dateAdded: "2026-01-01",
        error: null,
      },
      virustotal: {
        ok: true,
        total: 70,
        malicious: 12,
        suspicious: 2,
        harmless: 50,
        reputation: -8,
        error: null,
      },
      configured: { urlhaus: true, virustotal: true, any: true },
    },
  };

  const html = ui.buildReportHtml(sample);
  check("report is a complete HTML document", /^<!doctype html>/i.test(html) && html.includes("</html>"));
  check("report escapes injected markup", !html.includes("<script") && html.includes("&lt;script&gt;"));
  check("report includes the verdict", html.includes("Malicious"));
  check("report includes deep-scan feed data", html.includes("URLhaus") && html.includes("12 malicious"));
  check("report includes risk signals", html.includes("Brand impersonation &lt;b&gt;"));
  check("report has printable styles", html.includes("@media print"));
  check("report notes when feeds were not used", ui.buildReportHtml({ ...sample, deep: false, sources: { ...sample.sources, configured: { any: false } } }).includes("No API keys were configured"));
  check(
    "report filename is host + timestamp",
    /^phishguard-paypal\.com\.account-verify\.example-secure\.tk-\d{8}-\d{4}\.html$/.test(ui.reportFilename(sample)),
  );
}

console.log("\nLocal key seeding (dev builds)");
{
  vm.runInContext(readFileSync(join(extensionDir, "lib/local-keys.js"), "utf8"), context, {
    filename: "lib/local-keys.js",
  });
  const localKeys = sandbox.PG.localKeys;
  const urlhausKey = "a".repeat(48);
  const vtKey = "b".repeat(64);

  let stored = { apiKeys: { urlhaus: "", virustotal: "" } };
  const deps = (file) => ({
    getSettings: async () => ({ ...stored, apiKeys: { ...stored.apiKeys } }),
    saveSettings: async (patch) => {
      stored = { ...stored, ...patch, apiKeys: { ...stored.apiKeys, ...(patch.apiKeys || {}) } };
    },
    loadFile: async () => file,
  });

  const first = await localKeys.seedLocalKeys(deps({ urlhaus: urlhausKey, virustotal: vtKey }));
  check(
    "seeds both missing keys",
    first.seeded.length === 2 && stored.apiKeys.urlhaus === urlhausKey && stored.apiKeys.virustotal === vtKey,
  );

  stored = { apiKeys: { urlhaus: "existing-urlhaus-key-0001", virustotal: "" } };
  const second = await localKeys.seedLocalKeys(deps({ urlhaus: urlhausKey, virustotal: vtKey }));
  check(
    "existing keys win and only the missing one is filled",
    second.seeded.length === 1 &&
      second.seeded[0] === "virustotal" &&
      stored.apiKeys.urlhaus === "existing-urlhaus-key-0001",
  );

  const malformed = localKeys.sanitizeLocalKeys({ urlhaus: "short", virustotal: 42 });
  check("malformed keys are ignored", malformed.urlhaus === "" && malformed.virustotal === "");

  stored = { apiKeys: { urlhaus: "", virustotal: "" } };
  const none = await localKeys.seedLocalKeys(deps(null));
  check("missing local file is a no-op", none.seeded.length === 0 && stored.apiKeys.urlhaus === "");
}

console.log(`\n${passes} passed, ${failures} failed\n`);
process.exit(failures === 0 ? 0 : 1);
