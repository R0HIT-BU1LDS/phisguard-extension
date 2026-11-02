#!/usr/bin/env node
/**
 * Build a one-time PhishGuard settings backup containing your local API keys,
 * so they can be imported through the extension UI instead of being typed.
 *
 * Keys are read from secrets.local.json (gitignored) and written to
 * dist/phishguard-seed-backup.json (also gitignored). Neither file is ever
 * committed, and no key is baked into extension source.
 *
 * Usage: npm run keys:seed
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const secretsPath = join(root, "secrets.local.json");
const outPath = join(root, "dist", "phishguard-seed-backup.json");

if (!existsSync(secretsPath)) {
  console.error(`[seed] Missing secrets.local.json. Copy secrets.example.json and fill in your keys.`);
  process.exit(1);
}

let secrets;
try {
  secrets = JSON.parse(readFileSync(secretsPath, "utf8"));
} catch (err) {
  console.error(`[seed] Could not parse secrets.local.json: ${err.message}`);
  process.exit(1);
}

const urlhaus = typeof secrets.urlhaus === "string" ? secrets.urlhaus.trim() : "";
const virustotal = typeof secrets.virustotal === "string" ? secrets.virustotal.trim() : "";
if (!urlhaus && !virustotal) {
  console.error("[seed] secrets.local.json has no urlhaus or virustotal key.");
  process.exit(1);
}

const payload = {
  exportedAt: new Date().toISOString(),
  app: "PhishGuard",
  schemaVersion: 2,
  data: {
    pg_settings: {
      schemaVersion: 2,
      apiKeys: { urlhaus, virustotal },
    },
  },
};

mkdirSync(join(root, "dist"), { recursive: true });
writeFileSync(outPath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");

const mask = (key) => (key ? `${key.slice(0, 4)}…${key.slice(-4)}` : "not set");
console.log("[seed] Wrote dist/phishguard-seed-backup.json — contains secrets, do not share it.");
console.log(`[seed]   URLhaus:    ${mask(urlhaus)}`);
console.log(`[seed]   VirusTotal: ${mask(virustotal)}`);
console.log("[seed] Import once: PhishGuard settings → Data & privacy → Import backup.");
console.log("[seed] Importing replaces other settings with defaults, so re-check your toggles.");
console.log("[seed] Delete the file after importing if you do not need it again.");
