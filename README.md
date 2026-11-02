# PhishGuard Extension

An always-on phishing and malware guard for **Chrome, Edge, Brave and Firefox**. It watches real browsing, checks every navigation, and blocks dangerous pages **before they render** — with a full interstitial explaining why.

Plain JavaScript, no bundler, no dependencies. The `extension/` folder is a complete, loadable extension.

---

## Install

### Chrome / Edge / Brave / Opera / Vivaldi

1. Open `chrome://extensions` (`edge://extensions`, `brave://extensions`).
2. Enable **Developer mode**.
3. Click **Load unpacked** and select the `extension/` folder.
4. Pin PhishGuard to the toolbar to see the per-tab risk badge.

Or build packaged copies and load `dist/extension-chromium`:

```bash
npm run build
```

### Firefox

1. Open `about:debugging#/runtime/this-firefox`.
2. **Load Temporary Add-on…**
3. Pick `extension/manifest.firefox.json`.

Temporary add-ons disappear on restart. A permanent install needs signing at [addons.mozilla.org](https://addons.mozilla.org/developers/) — upload `dist/extension-firefox.zip`.

---

## What it does

| Capability | Behaviour |
| --- | --- |
| **Pre-load blocking** | Scans on `onBeforeNavigate`; dangerous navigations are redirected to a local warning page before the site renders. |
| **On-page alerts** | Shadow-DOM banner on suspicious pages with score, top signals and a one-click "Leave site". |
| **Toolbar badge** | Per-tab risk score, colour-coded safe / suspicious / malicious. |
| **Popup** | Current-tab verdict, rescan, quick URL scan, recent activity. |
| **Console** | Full-page scanner, history filters, trusted domains, stats, feed status. |
| **Warning interstitial** | Explains why a site was blocked: signals, sources, rescan, false-positive report, deliberate bypass. |
| **Reports** | Export any scan — including deep-scan feed data — as a printable standalone HTML file, JSON or text. |
| **Context menu / omnibox / shortcuts** | Right-click scans, `pg` + space in the address bar, `Alt+Shift+S` / `Alt+Shift+P`. |

### Blocking actually happens

1. The tab is redirected to `warning/warning.html` (a local page).
2. The scan is stored locally so the interstitial renders instantly.
3. Badge and desktop notification show the score.
4. **Back to safety** returns to the previous page; **Continue anyway** requires an explicit acknowledgement and applies a 10-minute bypass for that host only.

---

## Detection layers

**1. Offline heuristics — always on, no keys, no network.** Brand impersonation, look-alike domains, punycode and mixed scripts, raw IP hosts, high-abuse TLDs, credential/urgency keywords, domain-structure anomalies, obfuscation, URL shorteners, embedded credentials and HTTP login pages. Scores are capped at 80 for heuristics alone so a confirmed feed hit always outranks a noisy rule set. Default bands: safe `< 40`, suspicious `40–69`, malicious `≥ 70`.

**2. URLhaus — optional.** Checks the URL against abuse.ch's malware distribution feed with your free Auth-Key. A listing is treated as confirmed malware.

**3. VirusTotal — optional.** Looks up the URL across 70+ engines. Unknown URLs are submitted and polled briefly. Three or more malicious vendors blocks immediately. The free tier allows roughly 4 lookups/minute, so calls are rate-limited and verdicts cached.

Host verdicts are cached locally: malicious for 7 days, suspicious for 24 hours — repeat visits are instant and consume no quota.

---

## API keys (bring your own)

Keys are **never** included in this repository and are stored only in the browser profile via `chrome.storage.local`.

Get them here:

- URLhaus Auth-Key — <https://auth.abuse.ch/>
- VirusTotal API key — <https://www.virustotal.com/gui/my-apikey>

Add them in **Settings → Threat feeds**. The settings page autosaves; the status pills flip to *Connected*.

For local development you can skip the manual paste:

```bash
copy secrets.example.json secrets.local.json   # then fill in your keys
npm run build                                  # copies them into the unpacked folders only
```

`secrets.local.json`, `local-keys.json` and any exported backup are gitignored and never shipped in the zips. `npm run keys:seed` instead produces `dist/phishguard-seed-backup.json` for **Settings → Data & privacy → Import backup**.

Offline protection works with no keys at all.

---

## Privacy

- No PhishGuard server. Scanning, history and settings stay in the browser profile.
- Offline protection makes **zero** network requests.
- Deep scans send the URL directly to URLhaus and/or VirusTotal, only when a key is configured and a deep scan is requested.
- History redacts URLs by default: scheme, host and the first path segment only.
- The content script never reads page content; it shows the banner and marks links whose hosts are already known-bad.

---

## Permissions

| Permission | Why |
| --- | --- |
| `storage` | Settings, history, cached verdicts, per-tab state. |
| `tabs` | Read the active tab URL; update blocked tab, badge and title. |
| `webNavigation` | Detect navigations before they commit, so blocking is pre-load. |
| `notifications` | Desktop alerts for dangerous sites. |
| `contextMenus` | Right-click scan actions. |
| `alarms` | Periodic cache pruning. |
| `http://*/*`, `https://*/*` | Check any web address and run the banner content script. |

No access to history, bookmarks, downloads or page contents.

---

## Project structure

```text
extension/
├── manifest.json              # Chromium MV3 manifest
├── manifest.firefox.json      # Firefox MV3 manifest (background.scripts)
├── background.js              # Guards, badges, notifications, message router
├── lib/
│   ├── utils.js               # URL parsing, redaction, cross-browser storage/messaging
│   ├── constants.js           # Brands, TLD lists, keywords, weights, thresholds
│   ├── storage.js             # Settings schema, history, cache, per-tab session state
│   ├── heuristics.js          # Offline scoring engine
│   ├── providers.js           # URLhaus + VirusTotal clients
│   ├── scanner.js             # Orchestration, score combination, block/warn policy
│   └── local-keys.js          # Optional dev-build key seeding
├── content/content.js         # Shadow-DOM banner + dangerous-link marking
├── shared/
│   ├── theme.css              # Design tokens and shared components
│   └── report.js              # Report renderer, score ring, export, toast
├── popup/                     # Toolbar popup
├── warning/                   # Blocked-site interstitial
├── app/                       # Full-page console
├── options/                   # Settings page
└── icons/                     # PNG icons

scripts/
├── build-extension.mjs        # Unpacked bundles + zips for both browsers
├── generate-icons.mjs         # Regenerates the shield icons
├── test-heuristics.mjs        # Regression suite
└── make-seed-backup.mjs       # Local, importable key backup
```

---

## Development

```bash
npm run build    # dist/extension-chromium(.zip), dist/extension-firefox(.zip)
npm test         # offline heuristic + policy + messaging regression suite
npm run icons    # regenerate icons
```

After editing `background.js` or anything in `lib/`, click **Reload** on the extension card. After editing content scripts, reload the tab. Page edits (popup / options / warning / app) only need the page reopened.

### Adding a detection rule

1. Add a weight to `WEIGHTS` in `lib/constants.js`.
2. Emit a reason in `lib/heuristics.js` via `makeReason(id, label, weight, severity, detail)`.
3. Add a regression case in `scripts/test-heuristics.mjs`.
4. Run `npm test`.

---

## Troubleshooting

**Nothing is blocked.** Check that protection and "Check every page you open" are enabled. `chrome://` pages, extension pages, local files and localhost are intentionally never scanned. A previously trusted site is skipped — remove it under **Trusted sites**.

**A legitimate site is blocked.** Use **See why** → **Report a false positive** or **Trust this domain**.

**Deep scan is greyed out.** No API key configured. Offline protection is unaffected.

**VirusTotal says "rate limit".** The free API allows about 4 requests/minute. Cached verdicts are reused automatically.

**No notifications on Windows.** Check Focus Assist and the browser's OS notification permission, then use **Test & tools → Send test notification**.

---

## Limitations

- A heuristic and reputation tool, not an antivirus. It cannot inspect page content, JavaScript behaviour or downloads.
- Offline heuristics can flag unusual but legitimate domains; tune thresholds or trust domains.
- Feed coverage depends on URLhaus / VirusTotal freshness.
- Pages already open at install time are scanned on the next navigation or via **Scan page**.

---

## License

MIT. Threat data belongs to abuse.ch (URLhaus) and VirusTotal and is used under their respective terms.
