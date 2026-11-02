/* PhishGuard — on-page alert banner and safe-link marking */
(function () {
  "use strict";

  if (window.top !== window) return;
  if (window.__phishGuardInjected) return;
  window.__phishGuardInjected = true;

  const api = globalThis.browser || globalThis.chrome;
  const isFirefox = !!globalThis.browser;

  const COLORS = {
    malicious: { accent: "#ef4444", soft: "rgba(239,68,68,.14)", text: "#fecaca" },
    suspicious: { accent: "#f59e0b", soft: "rgba(245,158,11,.14)", text: "#fde68a" },
    safe: { accent: "#22c55e", soft: "rgba(34,197,94,.14)", text: "#bbf7d0" },
    info: { accent: "#38bdf8", soft: "rgba(56,189,248,.14)", text: "#bae6fd" },
  };

  const SHIELD_SVG =
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>';

  let root = null;
  let shadow = null;
  let lastResult = null;
  let dismissed = false;
  let linkObserver = null;
  let passwordWarned = false;
  let markTimer = null;

  function send(message) {
    if (isFirefox) {
      return api.runtime.sendMessage(message).catch(() => null);
    }
    return new Promise((resolve) => {
      try {
        api.runtime.sendMessage(message, (response) => {
          if (api.runtime.lastError) resolve(null);
          else resolve(response);
        });
      } catch {
        resolve(null);
      }
    });
  }

  function unwrap(response) {
    if (!response) return null;
    return response.ok === false ? null : response.data;
  }

  function ensureRoot() {
    if (root && root.isConnected) return shadow;
    root = document.createElement("div");
    root.id = "phishguard-root";
    root.style.setProperty("position", "fixed", "important");
    root.style.setProperty("top", "0", "important");
    root.style.setProperty("left", "0", "important");
    root.style.setProperty("right", "0", "important");
    root.style.setProperty("z-index", "2147483647", "important");
    root.style.setProperty("pointer-events", "none", "important");
    shadow = root.attachShadow({ mode: "open" });

    const style = document.createElement("style");
    style.textContent = `
      :host { all: initial; }
      .wrap {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        font-size: 14px; line-height: 1.45; color: #f1f5f9;
        display: flex; align-items: flex-start; gap: 12px;
        margin: 10px auto 0; max-width: 980px; width: calc(100% - 24px);
        padding: 12px 14px; border-radius: 14px;
        background: rgba(10, 16, 32, .94);
        border: 1px solid rgba(255,255,255,.12);
        box-shadow: 0 18px 50px rgba(0,0,0,.55), inset 0 1px 0 rgba(255,255,255,.06);
        backdrop-filter: blur(14px) saturate(140%);
        pointer-events: auto; animation: pg-in .28s cubic-bezier(.2,.8,.2,1);
      }
      .wrap.info { }
      .icon {
        flex: 0 0 auto; width: 34px; height: 34px; border-radius: 10px;
        display: grid; place-items: center; margin-top: 1px;
      }
      .icon svg { width: 19px; height: 19px; }
      .body { flex: 1 1 auto; min-width: 0; }
      .title { font-weight: 650; font-size: 14px; letter-spacing: .1px; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
      .pill {
        font-size: 10px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase;
        padding: 2px 7px; border-radius: 999px; border: 1px solid currentColor; opacity: .95;
      }
      .sub { color: #9fb0cc; font-size: 12px; margin-top: 2px; overflow-wrap: anywhere; }
      .sub b { color: #e2e8f0; font-weight: 600; }
      .reasons { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 7px; }
      .reason {
        font-size: 11px; padding: 3px 8px; border-radius: 999px;
        background: rgba(255,255,255,.06); border: 1px solid rgba(255,255,255,.09);
        color: #cbd5e1; max-width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
      }
      .actions { display: flex; align-items: center; gap: 6px; flex: 0 0 auto; }
      button {
        font: inherit; font-size: 12px; font-weight: 600; cursor: pointer;
        border-radius: 9px; padding: 7px 11px; white-space: nowrap;
        border: 1px solid rgba(255,255,255,.14); background: rgba(255,255,255,.06); color: #e2e8f0;
        transition: background .15s ease, border-color .15s ease, transform .1s ease;
      }
      button:hover { background: rgba(255,255,255,.12); }
      button:active { transform: translateY(1px); }
      button.primary { border-color: transparent; color: #07111f; }
      button.ghost { background: transparent; border-color: transparent; color: #94a3b8; padding: 7px 8px; }
      button.ghost:hover { color: #e2e8f0; background: rgba(255,255,255,.07); }
      .score {
        flex: 0 0 auto; width: 38px; height: 38px; border-radius: 50%;
        display: grid; place-items: center; position: relative; margin-top: 1px;
      }
      .score::after {
        content: ""; position: absolute; inset: 4px; border-radius: 50%;
        background: #0a1020;
      }
      .score span { position: relative; z-index: 1; font-size: 12px; font-weight: 700; }
      @keyframes pg-in { from { opacity: 0; transform: translateY(-12px); } to { opacity: 1; transform: none; } }
      @media (max-width: 640px) {
        .wrap { flex-wrap: wrap; }
        .actions { width: 100%; justify-content: flex-end; }
        .score { display: none; }
      }
    `;
    shadow.appendChild(style);
    (document.documentElement || document.body).appendChild(root);
    return shadow;
  }

  function buildBanner(options) {
    const level = options.level || "suspicious";
    const color = COLORS[level] || COLORS.suspicious;
    const el = ensureRoot();
    el.textContent = "";

    const wrap = document.createElement("div");
    wrap.className = "wrap";
    wrap.setAttribute("role", "alert");
    wrap.style.borderColor = color.accent + "66";

    if (options.score != null) {
      const score = document.createElement("div");
      score.className = "score";
      score.style.background = `conic-gradient(${color.accent} ${Math.max(4, options.score) * 3.6}deg, rgba(255,255,255,.1) 0)`;
      const value = document.createElement("span");
      value.textContent = String(options.score);
      value.style.color = color.accent;
      score.appendChild(value);
      wrap.appendChild(score);
    } else {
      const icon = document.createElement("div");
      icon.className = "icon";
      icon.innerHTML = SHIELD_SVG;
      icon.style.background = color.soft;
      icon.style.border = `1px solid ${color.accent}55`;
      icon.style.color = color.accent;
      wrap.appendChild(icon);
    }

    const body = document.createElement("div");
    body.className = "body";

    const title = document.createElement("div");
    title.className = "title";
    title.appendChild(document.createTextNode(options.title || "PhishGuard warning"));
    if (options.badge) {
      const pill = document.createElement("span");
      pill.className = "pill";
      pill.textContent = options.badge;
      pill.style.color = color.accent;
      pill.style.background = color.soft;
      title.appendChild(pill);
    }
    body.appendChild(title);

    if (options.subtitle) {
      const sub = document.createElement("div");
      sub.className = "sub";
      sub.textContent = options.subtitle;
      body.appendChild(sub);
    }

    if (options.reasons && options.reasons.length) {
      const reasons = document.createElement("div");
      reasons.className = "reasons";
      for (const reason of options.reasons.slice(0, 3)) {
        const chip = document.createElement("span");
        chip.className = "reason";
        chip.textContent = typeof reason === "string" ? reason : reason.label;
        chip.title = typeof reason === "string" ? reason : reason.detail || reason.label;
        reasons.appendChild(chip);
      }
      body.appendChild(reasons);
    }
    wrap.appendChild(body);

    const actions = document.createElement("div");
    actions.className = "actions";

    if (options.primaryLabel) {
      const primary = document.createElement("button");
      primary.className = "primary";
      primary.textContent = options.primaryLabel;
      primary.style.background = color.accent;
      primary.addEventListener("click", () => options.onPrimary && options.onPrimary());
      actions.appendChild(primary);
    }
    if (options.secondaryLabel) {
      const secondary = document.createElement("button");
      secondary.textContent = options.secondaryLabel;
      secondary.addEventListener("click", () => options.onSecondary && options.onSecondary());
      actions.appendChild(secondary);
    }
    const dismiss = document.createElement("button");
    dismiss.className = "ghost";
    dismiss.textContent = "Dismiss";
    dismiss.setAttribute("aria-label", "Dismiss PhishGuard alert");
    dismiss.addEventListener("click", () => {
      dismissed = true;
      removeBanner();
      send({ type: "PG_BANNER_DISMISSED" });
      if (options.onDismiss) options.onDismiss();
    });
    actions.appendChild(dismiss);
    wrap.appendChild(actions);

    el.appendChild(wrap);
  }

  function removeBanner() {
    if (root) root.remove();
    root = null;
    shadow = null;
  }

  async function leaveSite(result) {
    const response = await send({ type: "PG_LEAVE_TO_WARNING", result });
    if (!unwrap(response)) {
      window.location.replace("about:blank");
    }
  }

  function showRiskBanner(result, settings) {
    if (!result || dismissed) return;
    if (result.skipped) return;
    // Sites the user explicitly trusted never get an on-page warning.
    if (result.trusted === "allowlist") return;
    if (result.level === "safe") return;
    if (!settings || !settings.pageBanners) return;

    lastResult = result;
    const malicious = result.level === "malicious";
    const topReasons = (result.reasons || []).filter((r) => r.weight > 0).slice(0, 3);

    buildBanner({
      level: result.level,
      score: result.score,
      title: malicious ? "This site looks dangerous" : "Caution — this site looks suspicious",
      badge: malicious ? "Malicious" : "Suspicious",
      subtitle: `${result.host} scored ${result.score}/100. ${malicious ? "Do not sign in or enter payment details." : "Verify the address before entering any information."}`,
      reasons: topReasons,
      primaryLabel: "Leave site",
      onPrimary: () => leaveSite(result),
      secondaryLabel: "Why?",
      onSecondary: () => send({ type: "PG_OPEN_WARNING", result }),
    });
  }

  function showHttpPasswordBanner() {
    if (passwordWarned) return;
    passwordWarned = true;
    buildBanner({
      level: "info",
      title: "Insecure login form",
      badge: "HTTP",
      subtitle: `${location.hostname} is not encrypted. Anything you type here can be read on the network.`,
      primaryLabel: "Learn more",
      onPrimary: () => send({ type: "PG_OPEN_APP" }),
    });
  }

  /* ----------------------------- safe link marks --------------------------- */

  const marked = new WeakSet();

  function markLinks(badHosts) {
    if (!Array.isArray(badHosts) || badHosts.length === 0) return;
    const byHost = new Map(badHosts.map((entry) => [entry.host, entry]));
    let count = 0;

    const anchors = document.querySelectorAll("a[href]");
    for (const anchor of anchors) {
      if (count++ > 1500) break;
      if (marked.has(anchor)) continue;
      let url;
      try {
        url = new URL(anchor.href, location.href);
      } catch {
        continue;
      }
      if (url.protocol !== "http:" && url.protocol !== "https:") continue;
      if (url.hostname === location.hostname) continue;

      const host = url.hostname.toLowerCase();
      const root = host.split(".").slice(-2).join(".");
      let match = byHost.get(host) || byHost.get(root);
      if (!match) {
        for (const [badHost, entry] of byHost) {
          if (host.endsWith(`.${badHost}`)) {
            match = entry;
            break;
          }
        }
      }
      if (!match) continue;

      marked.add(anchor);
      const color = match.level === "malicious" ? "#ef4444" : "#f59e0b";
      anchor.style.setProperty("outline", `2px dashed ${color}`, "important");
      anchor.style.setProperty("outline-offset", "1px", "important");
      anchor.style.setProperty("border-radius", "3px", "important");
      const existing = anchor.getAttribute("title");
      if (!existing || !existing.includes("PhishGuard")) {
        anchor.setAttribute("title", `${existing ? `${existing} — ` : ""}PhishGuard: ${match.level} link (score ${match.score}/100)`);
      }
      anchor.dataset.phishguard = match.level;
    }
  }

  function startLinkObserver(badHosts) {
    if (!Array.isArray(badHosts) || badHosts.length === 0) return;
    if (linkObserver) return;
    markLinks(badHosts);
    linkObserver = new MutationObserver(() => {
      if (markTimer) return;
      markTimer = setTimeout(() => {
        markTimer = null;
        markLinks(badHosts);
      }, 600);
    });
    linkObserver.observe(document.documentElement, { childList: true, subtree: true });
    setTimeout(() => {
      if (linkObserver) {
        linkObserver.disconnect();
        linkObserver = null;
      }
    }, 120000);
  }

  async function init() {
    if (!/^https?:$/.test(location.protocol)) return;
    const response = await send({ type: "PG_PAGE_STATUS" });
    const data = unwrap(response);
    if (!data) return;

    const settings = data.settings || {};
    if (settings.markLinks) startLinkObserver(data.badHosts);

    if (!settings.protection) return;
    if (settings.pageBanners) {
      setTimeout(() => showRiskBanner(data.result, settings), 500);
    }

    if (settings.warnOnHttpLogin && location.protocol === "http:") {
      const check = () => {
        if (document.querySelector('input[type="password"]')) showHttpPasswordBanner();
      };
      check();
      const observer = new MutationObserver(check);
      observer.observe(document.documentElement, { childList: true, subtree: true });
      setTimeout(() => observer.disconnect(), 15000);
    }
  }

  api.runtime.onMessage.addListener((message) => {
    if (!message) return;
    if (message.type === "PG_SHOW_BANNER" && message.result) {
      send({ type: "PG_PAGE_STATUS" }).then((response) => {
        const data = unwrap(response);
        dismissed = false;
        showRiskBanner(message.result, (data && data.settings) || { pageBanners: true });
      });
    }
  });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init, { once: true });
  } else {
    init();
  }
})();
