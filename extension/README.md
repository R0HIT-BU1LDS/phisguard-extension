# PhishGuard — extension source

This folder is the complete extension. Load it directly, or build packaged copies with `npm run build` from the repository root.

- **Chrome / Edge / Brave:** `chrome://extensions` → Developer mode → **Load unpacked** → select this folder.
- **Firefox:** `about:debugging#/runtime/this-firefox` → **Load Temporary Add-on…** → `manifest.firefox.json`.

Full documentation — install, detection layers, settings, API keys, permissions, troubleshooting — lives in the [repository README](../README.md).

## Layout

```text
manifest.json            Chromium MV3 manifest
manifest.firefox.json    Firefox MV3 manifest (background.scripts)
background.js            Navigation guard, badges, notifications, message router
lib/                     utils, constants, storage, heuristics, providers, scanner
content/                 Shadow-DOM banner + dangerous-link marking
shared/                  theme.css, report.js (rendering + export)
popup/ warning/ app/     UI surfaces
options/                 Settings page
icons/                   PNG icons
```

No dependencies, no bundler. Edit files, then reload the extension.
