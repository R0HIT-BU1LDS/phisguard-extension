#!/usr/bin/env node
/**
 * Build installable extension bundles for Chromium and Firefox.
 *
 *   dist/extension-chromium/  → load unpacked in Chrome / Edge / Brave
 *   dist/extension-chromium.zip
 *   dist/extension-firefox/   → load temporary add-on in Firefox
 *   dist/extension-firefox.zip
 *
 * Usage: npm run build:extension
 */
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const source = join(root, "extension");
const dist = join(root, "dist");

const EXCLUDED = new Set(["manifest.firefox.json", "README.md", ".DS_Store"]);

function log(message) {
  console.log(`[build] ${message}`);
}

function ensureSource() {
  for (const file of ["manifest.json", "manifest.firefox.json", "background.js"]) {
    if (!existsSync(join(source, file))) {
      throw new Error(`Missing extension/${file}. Run this script from the repository root.`);
    }
  }
}

function copyBundle(target) {
  rmSync(target, { recursive: true, force: true });
  mkdirSync(target, { recursive: true });
  cpSync(source, target, {
    recursive: true,
    filter: (src) => {
      const name = src.split(/[\\/]/).pop();
      return !EXCLUDED.has(name);
    },
  });
}

function writeManifest(target, manifestName, stripFirefoxManifest) {
  const raw = readFileSync(join(source, manifestName), "utf8");
  const parsed = JSON.parse(raw); // fail fast on malformed manifest
  const targetManifest = join(target, "manifest.json");
  if (manifestName !== "manifest.json") {
    writeFileSync(targetManifest, JSON.stringify(parsed, null, 2) + "\n");
    const original = join(target, manifestName);
    if (stripFirefoxManifest && existsSync(original)) rmSync(original);
  }
  log(`  manifest: ${manifestName} (v${parsed.version}, mv${parsed.manifest_version})`);
}

function zipDirectory(target, zipPath) {
  rmSync(zipPath, { force: true });
  try {
    if (process.platform === "win32") {
      const quotedTarget = target.replace(/'/g, "''");
      const quotedZip = zipPath.replace(/'/g, "''");
      execFileSync(
        "powershell",
        [
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          `$ErrorActionPreference = 'Stop'; Compress-Archive -Path '${quotedTarget}\\*' -DestinationPath '${quotedZip}' -Force`,
        ],
        { stdio: "pipe" },
      );
    } else {
      execFileSync("zip", ["-r", "-q", zipPath, "."], { cwd: target, stdio: "pipe" });
    }
    return true;
  } catch (err) {
    log(`  zip skipped (${err.message.split("\n")[0]})`);
    return false;
  }
}

/**
 * Copy local API keys into the unpacked bundle as local-keys.json so the
 * background can seed them on first run. Called after zipping, so the
 * distributable archives never contain credentials.
 */
function copyLocalKeys(target) {
  const secrets = join(root, "secrets.local.json");
  if (!existsSync(secrets)) return false;
  try {
    const parsed = JSON.parse(readFileSync(secrets, "utf8"));
    const keys = {
      urlhaus: typeof parsed.urlhaus === "string" ? parsed.urlhaus.trim() : "",
      virustotal: typeof parsed.virustotal === "string" ? parsed.virustotal.trim() : "",
    };
    if (!keys.urlhaus && !keys.virustotal) return false;
    writeFileSync(join(target, "local-keys.json"), `${JSON.stringify(keys, null, 2)}\n`, "utf8");
    return true;
  } catch (err) {
    log(`  local keys skipped (${err.message.split("\n")[0]})`);
    return false;
  }
}

function main() {
  ensureSource();
  mkdirSync(dist, { recursive: true });

  const chromium = join(dist, "extension-chromium");
  log("Chromium (Chrome / Edge / Brave)");
  copyBundle(chromium);
  writeManifest(chromium, "manifest.json", true);
  const chromiumZip = `${chromium}.zip`;
  if (zipDirectory(chromium, chromiumZip)) log(`  zip: ${chromiumZip}`);
  if (copyLocalKeys(chromium)) {
    log("  local keys: local-keys.json added to the unpacked folder only (not in the zip)");
  }

  const firefox = join(dist, "extension-firefox");
  log("Firefox");
  copyBundle(firefox);
  writeManifest(firefox, "manifest.firefox.json", true);
  const firefoxZip = `${firefox}.zip`;
  if (zipDirectory(firefox, firefoxZip)) log(`  zip: ${firefoxZip}`);
  if (copyLocalKeys(firefox)) {
    log("  local keys: local-keys.json added to the unpacked folder only (not in the zip)");
  }

  log("Done.");
  log("");
  log("Load in Chrome / Edge / Brave:");
  log(`  1. Open chrome://extensions and enable Developer mode.`);
  log(`  2. "Load unpacked" → ${chromium}`);
  log("");
  log("Load in Firefox:");
  log(`  1. Open about:debugging#/runtime/this-firefox`);
  log(`  2. "Load Temporary Add-on…" → ${join(firefox, "manifest.json")}`);
  log(`  For a permanent install, submit ${firefoxZip} to addons.mozilla.org or use about:config xpinstall.signatures.required=false (Nightly/ESR).`);
}

main();
