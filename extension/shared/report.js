/* PhishGuard — shared result rendering (DOM-only, no innerHTML for untrusted data) */
(function () {
  "use strict";

  const PG = (globalThis.PG = globalThis.PG || {});
  const U = PG.utils;

  const ICONS = {
    shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>',
    shieldAlert: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>',
    activity: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>',
    alert: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>',
    check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>',
    x: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>',
    copy: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>',
    download: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5"/><path d="M12 15V3"/></svg>',
    external: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/></svg>',
    refresh: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 1 1-2.64-6.36"/><path d="M21 3v6h-6"/></svg>',
    trash: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M8 6V4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg>',
    settings: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .34 1.87l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.7 1.7 0 0 0-1.87-.34 1.7 1.7 0 0 0-1 1.55V21a2 2 0 1 1-4 0v-.09a1.7 1.7 0 0 0-1.1-1.55 1.7 1.7 0 0 0-1.88.34l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.7 1.7 0 0 0 4.6 15a1.7 1.7 0 0 0-1.55-1H3a2 2 0 1 1 0-4h.09A1.7 1.7 0 0 0 4.6 8.9a1.7 1.7 0 0 0-.34-1.88l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.7 1.7 0 0 0 9 4.6a1.7 1.7 0 0 0 1-1.55V3a2 2 0 1 1 4 0v.09a1.7 1.7 0 0 0 1 1.55 1.7 1.7 0 0 0 1.87-.34l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.7 1.7 0 0 0 19.4 9v.09a1.7 1.7 0 0 0 1.55 1H21a2 2 0 1 1 0 4h-.09a1.7 1.7 0 0 0-1.51 1z"/></svg>',
    globe: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',
    history: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5"/><path d="M12 7v5l3 2"/></svg>',
    power: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18.36 6.64a9 9 0 1 1-12.73 0"/><path d="M12 2v10"/></svg>',
    key: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/></svg>',
    lock: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
  };

  const LEVEL_COLORS = { safe: "#22c55e", suspicious: "#f59e0b", malicious: "#ef4444" };

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function icon(name, className) {
    const span = document.createElement("span");
    span.className = className || "";
    span.style.display = "inline-flex";
    span.innerHTML = ICONS[name] || ICONS.shield;
    return span;
  }

  function pill(text, tone, iconName) {
    const node = el("span", `pill ${tone || ""}`.trim());
    if (iconName) node.appendChild(icon(iconName));
    node.appendChild(document.createTextNode(text));
    return node;
  }

  function scoreRing(score, level, size) {
    const dim = size || 96;
    const stroke = Math.max(6, Math.round(dim * 0.085));
    const radius = (dim - stroke) / 2;
    const circumference = 2 * Math.PI * radius;
    const color = LEVEL_COLORS[level] || LEVEL_COLORS.safe;

    const wrap = el("div", "score-ring");
    wrap.style.width = `${dim}px`;
    wrap.style.height = `${dim}px`;

    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("width", String(dim));
    svg.setAttribute("height", String(dim));
    svg.setAttribute("aria-hidden", "true");

    const track = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    track.setAttribute("cx", String(dim / 2));
    track.setAttribute("cy", String(dim / 2));
    track.setAttribute("r", String(radius));
    track.setAttribute("fill", "none");
    track.setAttribute("stroke", "rgba(255,255,255,0.08)");
    track.setAttribute("stroke-width", String(stroke));

    const progress = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    progress.setAttribute("cx", String(dim / 2));
    progress.setAttribute("cy", String(dim / 2));
    progress.setAttribute("r", String(radius));
    progress.setAttribute("fill", "none");
    progress.setAttribute("stroke", color);
    progress.setAttribute("stroke-width", String(stroke));
    progress.setAttribute("stroke-linecap", "round");
    progress.setAttribute("stroke-dasharray", String(circumference));
    progress.setAttribute("stroke-dashoffset", String(circumference * (1 - U.clamp(score, 0, 100) / 100)));
    progress.style.transition = "stroke-dashoffset .9s cubic-bezier(.2,.8,.2,1)";

    svg.appendChild(track);
    svg.appendChild(progress);
    wrap.appendChild(svg);

    const value = el("div", "value", String(score));
    value.style.fontSize = `${Math.round(dim * 0.27)}px`;
    value.style.color = color;
    wrap.appendChild(value);

    if (dim >= 80) wrap.appendChild(el("div", "caption", "Risk"));
    return wrap;
  }

  function verdictSentence(result) {
    if (result.skipped) return result.note || "This address is local or private, so it was not rated.";
    if (result.level === "malicious") {
      return "This address matches known phishing or malware patterns. Do not enter credentials, payment details, or download files.";
    }
    if (result.level === "suspicious") {
      return "Several risk signals were found. Verify the address through a trusted channel before continuing.";
    }
    return "No known threats were detected in the sources we checked. Still confirm the address before signing in.";
  }

  function buildSourceCard(name, iconName, big, sub, tone) {
    const card = el("div", "source-card");
    const heading = el("div", "name");
    heading.appendChild(icon(iconName));
    heading.appendChild(document.createTextNode(name));
    card.appendChild(heading);
    const value = el("div", "big", big);
    if (tone) value.style.color = tone;
    card.appendChild(value);
    if (sub) card.appendChild(el("div", "sub", sub));
    return card;
  }

  /**
   * Render a scan result.
   * @param {object} result
   * @param {HTMLElement} container
   * @param {object} [options] { compact, maxReasons, actions: [{label, variant, icon, onClick}] }
   */
  function renderReport(result, container, options) {
    const opts = options || {};
    if (!container) return null;
    container.textContent = "";
    if (!result) return null;

    const wrap = el("div", "report");

    const head = el("div", "report-head");
    head.appendChild(scoreRing(result.score, result.level, opts.compact ? 76 : 96));

    const meta = el("div", "meta");
    meta.appendChild(el("div", "eyebrow", "Verdict"));
    const verdict = el("div", `report-verdict ${result.level}`);
    verdict.appendChild(el("span", "", U.levelLabel(result.level)));
    if (result.trusted === "allowlist") verdict.appendChild(pill("Trusted", "safe", "check"));
    else if (result.trusted === "reputation") verdict.appendChild(pill("Reputable domain", "info"));
    meta.appendChild(verdict);

    const hostLine = el("div", "report-host mono", U.shortUrl(result.url, opts.compact ? 52 : 90));
    hostLine.title = result.url;
    meta.appendChild(hostLine);

    const metaRow = el("div", "row");
    metaRow.style.marginTop = "5px";
    metaRow.appendChild(pill(result.deep ? "Deep scan" : "Offline scan", result.deep ? "info" : "", result.deep ? "activity" : "shield"));
    if (result.cached) metaRow.appendChild(pill("Cached"));
    if (result.hostVerdict) metaRow.appendChild(pill("Known domain", "suspicious"));
    metaRow.appendChild(el("span", "tiny muted", U.timeAgo(result.scannedAt)));
    meta.appendChild(metaRow);
    head.appendChild(meta);
    wrap.appendChild(head);

    wrap.appendChild(el("div", "report-summary", verdictSentence(result)));

    const important = (result.reasons || []).filter((reason) => reason.weight > 0);
    const reasonsSection = el("div", "report-section");
    reasonsSection.appendChild(el("h4", "", important.length ? `Risk signals (${important.length})` : "Risk signals"));
    if (important.length === 0) {
      const clean = el("div", "row");
      clean.appendChild(pill("No signals", "safe", "check"));
      clean.appendChild(el("span", "tiny muted", "Nothing in our offline rules or cached feeds flagged this address."));
      reasonsSection.appendChild(clean);
    } else {
      const list = el("ul", "report-reasons");
      const limit = opts.maxReasons && opts.maxReasons > 0 ? opts.maxReasons : important.length;
      for (const reason of important.slice(0, limit)) {
        const item = el("li");
        const dot = el("span", "dot");
        dot.style.background = LEVEL_COLORS[reason.severity === "high" ? "malicious" : reason.severity === "medium" ? "suspicious" : "safe"];
        item.appendChild(dot);
        const text = el("div", "text");
        text.appendChild(el("div", "label", reason.label));
        if (reason.detail && !opts.compact) text.appendChild(el("div", "detail", reason.detail));
        item.appendChild(text);
        if (reason.weight > 0) item.appendChild(el("span", "weight", `+${reason.weight}`));
        list.appendChild(item);
      }
      reasonsSection.appendChild(list);
    }
    wrap.appendChild(reasonsSection);

    const sources = el("div", "report-section");
    sources.appendChild(el("h4", "", "Sources"));
    const grid = el("div", "report-sources");

    const heurSignals = important.filter((reason) => reason.source === "heuristic").length;
    grid.appendChild(buildSourceCard(
      "On-device rules",
      "shield",
      `${result.sources.heuristics.score}`,
      heurSignals ? `${heurSignals} signal${heurSignals === 1 ? "" : "s"}` : "no signals",
      result.sources.heuristics.score >= 40 ? LEVEL_COLORS.suspicious : LEVEL_COLORS.safe,
    ));

    const urlhaus = result.sources.urlhaus || {};
    let urlhausBig = "Not checked";
    let urlhausSub = "Add an API key";
    let urlhausTone = "";
    if (urlhaus.listed) {
      urlhausBig = "Listed";
      urlhausSub = urlhaus.threat || "In malware feed";
      urlhausTone = LEVEL_COLORS.malicious;
    } else if (urlhaus.ok) {
      urlhausBig = "Clean";
      urlhausSub = "Not in URLhaus";
      urlhausTone = LEVEL_COLORS.safe;
    } else if (urlhaus.error && !urlhaus.skipped) {
      urlhausBig = "Unavailable";
      urlhausSub = urlhaus.error;
    }
    grid.appendChild(buildSourceCard("URLhaus", "shield", urlhausBig, urlhausSub, urlhausTone));

    const vt = result.sources.virustotal || {};
    let vtBig = "Not checked";
    let vtSub = "Add an API key";
    let vtTone = "";
    if (vt.total > 0) {
      vtBig = `${vt.malicious}/${vt.total}`;
      vtSub = `${vt.malicious} malicious · ${vt.suspicious} suspicious`;
      vtTone = vt.malicious > 0 ? LEVEL_COLORS.malicious : LEVEL_COLORS.safe;
    } else if (vt.error && !vt.skipped) {
      vtBig = "Unavailable";
      vtSub = vt.error;
    }
    grid.appendChild(buildSourceCard("VirusTotal", "activity", vtBig, vtSub, vtTone));

    sources.appendChild(grid);
    wrap.appendChild(sources);

    if (opts.actions && opts.actions.length) {
      const actions = el("div", "report-actions");
      for (const action of opts.actions) {
        const button = el("button", `btn ${action.variant || ""} sm`.trim(), action.label);
        button.type = "button";
        if (action.icon) button.prepend(icon(action.icon));
        if (action.title) button.title = action.title;
        button.addEventListener("click", (event) => action.onClick && action.onClick(event, button));
        actions.appendChild(button);
      }
      wrap.appendChild(actions);
    }

    container.appendChild(wrap);
    return wrap;
  }

  function plainTextReport(result) {
    const lines = [
      "PhishGuard Threat Report",
      "========================",
      `URL: ${result.url}`,
      `Host: ${result.host}`,
      `Scanned: ${new Date(result.scannedAt || Date.now()).toISOString()}`,
      `Risk score: ${result.score}/100`,
      `Classification: ${U.levelLabel(result.level)}`,
      `Scan type: ${result.deep ? "deep (threat feeds + offline rules)" : "offline heuristics"}`,
      "",
      "Risk signals:",
    ];
    const reasons = (result.reasons || []).filter((reason) => reason.weight > 0);
    if (reasons.length === 0) lines.push("  - none detected");
    for (const reason of reasons) {
      lines.push(`  - [${reason.severity}] ${reason.label} (+${reason.weight})`);
      if (reason.detail) lines.push(`      ${reason.detail}`);
    }
    lines.push("");
    lines.push(`URLhaus: ${result.sources.urlhaus.listed ? "LISTED" : result.sources.urlhaus.ok ? "not listed" : "not checked"}`);
    if (result.sources.urlhaus.threat) lines.push(`  threat: ${result.sources.urlhaus.threat}`);
    if (result.sources.urlhaus.tags && result.sources.urlhaus.tags.length) lines.push(`  tags: ${result.sources.urlhaus.tags.join(", ")}`);
    const vt = result.sources.virustotal;
    lines.push(`VirusTotal: ${vt.total > 0 ? `${vt.malicious} malicious / ${vt.suspicious} suspicious of ${vt.total}` : "not checked"}`);
    if (vt.error) lines.push(`  note: ${vt.error}`);
    lines.push("");
    lines.push("Generated locally by PhishGuard. Threat data: URLhaus (abuse.ch), VirusTotal.");
    return lines.join("\n");
  }

  function pad2(value) {
    return String(value).padStart(2, "0");
  }

  function reportFilename(result, ext) {
    const host =
      String(result.host || "scan")
        .toLowerCase()
        .replace(/[^a-z0-9.-]+/g, "-")
        .replace(/^-+|-+$/g, "") || "scan";
    const date = new Date(result.scannedAt || Date.now());
    const stamp =
      `${date.getFullYear()}${pad2(date.getMonth() + 1)}${pad2(date.getDate())}` +
      `-${pad2(date.getHours())}${pad2(date.getMinutes())}`;
    return `phishguard-${host}-${stamp}.${ext || "html"}`;
  }

  function advisoryFor(level) {
    if (level === "malicious") {
      return {
        title: "Do not enter any information on this site",
        text: "This address matched strong phishing or malware signals. Close the tab and reach the company through its official website or app instead.",
      };
    }
    if (level === "suspicious") {
      return {
        title: "Verify this site before continuing",
        text: "Some signals looked unusual. Check the spelling of the address and avoid signing in or paying unless you are certain the site is legitimate.",
      };
    }
    return {
      title: "No detections found",
      text: "Nothing in the offline rules or the configured threat feeds matched this address. That does not guarantee the site is safe, so stay alert for unexpected login or payment forms.",
    };
  }

  function reasonRowsHtml(result) {
    const reasons = (result.reasons || []).filter((reason) => reason.weight > 0);
    if (!reasons.length) {
      return '<tr><td colspan="4" class="muted">No risk signals were detected.</td></tr>';
    }
    return reasons
      .map((reason) => {
        const detail = [reason.detail || "", reason.source ? `Source: ${reason.source}.` : ""]
          .filter(Boolean)
          .join(" ");
        return (
          `<tr class="sev-${U.escapeAttr(reason.severity || "info")}">` +
          `<td>${U.escapeHtml(reason.severity || "info")}</td>` +
          `<td class="num">+${Number(reason.weight) || 0}</td>` +
          `<td><strong>${U.escapeHtml(reason.label || reason.id || "Signal")}</strong></td>` +
          `<td>${U.escapeHtml(detail)}</td>` +
          "</tr>"
        );
      })
      .join("");
  }

  function feedData(result) {
    const sources = result.sources || {};
    const urlhaus = sources.urlhaus || {};
    const vt = sources.virustotal || {};
    const configured = sources.configured || {};
    const rows = [];

    let urlhausStatus = "Not checked";
    if (urlhaus.listed) urlhausStatus = "LISTED as malware";
    else if (urlhaus.ok) urlhausStatus = "Not listed";
    else if (urlhaus.error) urlhausStatus = `Unavailable — ${urlhaus.error}`;
    rows.push(["URLhaus", urlhausStatus]);
    if (urlhaus.threat) rows.push(["URLhaus threat", urlhaus.threat]);
    if (urlhaus.tags && urlhaus.tags.length) rows.push(["URLhaus tags", urlhaus.tags.join(", ")]);
    if (urlhaus.urlStatus) rows.push(["URLhaus URL status", urlhaus.urlStatus]);
    if (urlhaus.reference) rows.push(["URLhaus reference", urlhaus.reference]);
    if (urlhaus.dateAdded) rows.push(["URLhaus added", urlhaus.dateAdded]);

    let vtStatus = "Not checked";
    if (vt.total > 0) {
      vtStatus = `${vt.malicious || 0} malicious, ${vt.suspicious || 0} suspicious, ` +
        `${vt.harmless || 0} harmless of ${vt.total} vendors`;
    } else if (vt.error) {
      vtStatus = `Unavailable — ${vt.error}`;
    }
    rows.push(["VirusTotal", vtStatus]);
    if (vt.reputation != null) rows.push(["VirusTotal reputation", String(vt.reputation)]);

    const notes = [];
    if (!configured.any) {
      notes.push(
        "No API keys were configured, so this scan used the offline rules only. Add URLhaus and/or VirusTotal keys in PhishGuard settings to include live threat-feed verdicts in future reports.",
      );
    } else if (!result.deep) {
      notes.push("This was a quick scan. Run a deep scan from the popup or console to add threat-feed data to the report.");
    }
    if (urlhaus.error) notes.push(`URLhaus: ${urlhaus.error}`);
    if (vt.error) notes.push(`VirusTotal: ${vt.error}`);

    return { rows, notes };
  }

  function tableHtml(rows) {
    return rows
      .map(
        ([label, value]) =>
          `<tr><th scope="row">${U.escapeHtml(label)}</th><td>${U.escapeHtml(String(value))}</td></tr>`,
      )
      .join("");
  }

  /**
   * Build a self-contained, printable HTML report for a scan result. All values
   * are escaped, no scripts or remote assets are included.
   */
  function buildReportHtml(result) {
    const level = result.level === "malicious" || result.level === "suspicious" ? result.level : "safe";
    const accent = LEVEL_COLORS[level];
    const advice = advisoryFor(level);
    const scannedAt = U.formatDateTime(result.scannedAt || Date.now());
    const host = result.host || "(no host)";
    const scanType = result.deep ? "Deep scan (offline rules + threat feeds)" : "Offline heuristic scan";
    const feeds = feedData(result);
    const heuristicsScore =
      result.sources && result.sources.heuristics && typeof result.sources.heuristics.score === "number"
        ? result.sources.heuristics.score
        : result.score;

    let version = "2.0.0";
    try {
      version = PG.api.runtime.getManifest().version;
    } catch {
      /* runtime may be unavailable outside an extension page */
    }

    const summaryRows = [
      ["URL", result.url || ""],
      ["Host", host],
      ["Registrable domain", result.registrable || ""],
      ["Protocol", result.protocol || ""],
      ["Scan type", scanType],
      ["Triggered by", result.trigger || "manual"],
      ["Scanned at", scannedAt],
      ["Risk score", `${Number(result.score) || 0}/100 (offline rules scored ${Number(heuristicsScore) || 0})`],
      ["Classification", U.levelLabel(level)],
      ["Feed verdict reused from cache", result.cached ? "Yes" : "No"],
      ["Trust status", result.trusted || "none"],
    ];

    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>PhishGuard report — ${U.escapeHtml(host)}</title>
<style>
  * { box-sizing: border-box; }
  body { margin: 0; padding: 32px 20px; font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif; background: #0b1120; color: #e2e8f0; line-height: 1.55; }
  .sheet { max-width: 880px; margin: 0 auto; }
  header { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; padding-bottom: 16px; border-bottom: 1px solid #1e293b; }
  h1 { font-size: 20px; margin: 0 0 4px; letter-spacing: -0.01em; }
  h2 { font-size: 14px; margin: 0 0 10px; text-transform: uppercase; letter-spacing: 0.08em; color: #94a3b8; }
  p { margin: 0; }
  .muted { color: #94a3b8; }
  .small { font-size: 12px; }
  .verdict { flex: none; padding: 6px 14px; border-radius: 999px; font-size: 13px; font-weight: 600; color: #0b1120; background: ${accent}; }
  .hero { display: flex; align-items: center; gap: 20px; margin: 24px 0; padding: 20px; border: 1px solid #1e293b; border-left: 4px solid ${accent}; border-radius: 12px; background: #0f172a; }
  .score { flex: none; text-align: center; }
  .score strong { display: block; font-size: 34px; line-height: 1; color: ${accent}; }
  .score span { font-size: 12px; color: #94a3b8; }
  .url { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 13px; word-break: break-all; margin-bottom: 6px; }
  section { margin: 24px 0; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #1e293b; vertical-align: top; }
  thead th { color: #94a3b8; font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; }
  tbody th { width: 32%; color: #cbd5e1; font-weight: 500; }
  td.num { text-align: right; white-space: nowrap; font-variant-numeric: tabular-nums; }
  .sev-high td:first-child { color: #f87171; font-weight: 600; }
  .sev-medium td:first-child { color: #fbbf24; font-weight: 600; }
  .note { margin-top: 10px; padding: 10px 12px; border-radius: 8px; background: #111c33; border: 1px solid #1e293b; font-size: 12px; color: #cbd5e1; }
  details { margin-top: 12px; }
  summary { cursor: pointer; font-size: 13px; color: #94a3b8; }
  pre { margin: 10px 0 0; padding: 14px; overflow: auto; border-radius: 8px; background: #0f172a; border: 1px solid #1e293b; font-size: 11px; line-height: 1.5; }
  footer { margin-top: 28px; padding-top: 14px; border-top: 1px solid #1e293b; font-size: 11px; color: #94a3b8; }
  @media print {
    body { background: #fff; color: #111827; padding: 0; }
    .hero, section, footer { border-color: #d1d5db; }
    .hero { background: #f9fafb; }
    .muted, h2, thead th, footer, summary, .score span { color: #4b5563; }
    tbody th { color: #111827; }
    th, td { border-bottom: 1px solid #e5e7eb; }
    .note, pre { background: #f9fafb; border-color: #e5e7eb; color: #111827; }
    .verdict { color: #fff; background: ${accent}; }
  }
</style>
</head>
<body>
<div class="sheet">
  <header>
    <div>
      <h1>PhishGuard Threat Report</h1>
      <p class="muted small">${U.escapeHtml(scannedAt)} · PhishGuard ${U.escapeHtml(version)} · generated locally</p>
    </div>
    <span class="verdict">${U.escapeHtml(U.levelLabel(level))}</span>
  </header>

  <div class="hero">
    <div class="score"><strong>${Number(result.score) || 0}</strong><span>out of 100</span></div>
    <div>
      <p class="url">${U.escapeHtml(result.url || "")}</p>
      <p class="small muted"><strong>${U.escapeHtml(advice.title)}.</strong> ${U.escapeHtml(advice.text)}</p>
    </div>
  </div>

  <section>
    <h2>Scan summary</h2>
    <table><tbody>${tableHtml(summaryRows)}</tbody></table>
  </section>

  <section>
    <h2>Risk signals</h2>
    <table>
      <thead><tr><th>Severity</th><th class="num">Weight</th><th>Signal</th><th>Detail</th></tr></thead>
      <tbody>${reasonRowsHtml(result)}</tbody>
    </table>
  </section>

  <section>
    <h2>Threat intelligence</h2>
    <table><tbody>${tableHtml(feeds.rows)}</tbody></table>
    ${feeds.notes.map((note) => `<p class="note">${U.escapeHtml(note)}</p>`).join("")}
  </section>

  <section>
    <h2>Recommended action</h2>
    <table><tbody>${tableHtml([
      ["What to do", advice.title],
      ["Why", advice.text],
    ])}</tbody></table>
  </section>

  <section>
    <h2>Machine-readable data</h2>
    <details>
      <summary>Show full JSON result</summary>
      <pre>${U.escapeHtml(JSON.stringify(result, null, 2))}</pre>
    </details>
  </section>

  <footer>
    Generated by PhishGuard ${U.escapeHtml(version)}. Detection ran on this device; no browsing data was uploaded.
    Threat feed data, when shown, comes from URLhaus (abuse.ch) and VirusTotal. Use your browser's Print option to save this page as PDF.
  </footer>
</div>
</body>
</html>`;
  }

  function downloadBlob(filename, mime, text) {
    const blob = new Blob([text], { type: mime });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    link.rel = "noopener";
    link.style.display = "none";
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 15000);
    return filename;
  }

  /**
   * Save a scan report. `format` is "html" (default, printable), "json" or "txt".
   */
  function downloadReport(result, format) {
    if (!result) throw new Error("No scan result to export");
    if (format === "json") {
      return downloadBlob(reportFilename(result, "json"), "application/json", JSON.stringify(result, null, 2));
    }
    if (format === "txt") {
      return downloadBlob(reportFilename(result, "txt"), "text/plain;charset=utf-8", plainTextReport(result));
    }
    return downloadBlob(reportFilename(result, "html"), "text/html;charset=utf-8", buildReportHtml(result));
  }

  let toastTimer = 0;
  function toast(message, isError) {
    let node = document.querySelector(".toast");
    if (!node) {
      node = el("div", "toast");
      node.setAttribute("role", "status");
      document.body.appendChild(node);
    }
    node.textContent = message;
    node.classList.toggle("error", !!isError);
    node.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => node.classList.remove("show"), 3200);
  }

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      try {
        const area = document.createElement("textarea");
        area.value = text;
        area.style.position = "fixed";
        area.style.opacity = "0";
        document.body.appendChild(area);
        area.select();
        const ok = document.execCommand("copy");
        area.remove();
        return ok;
      } catch {
        return false;
      }
    }
  }

  PG.ui = {
    ICONS,
    LEVEL_COLORS,
    el,
    icon,
    pill,
    scoreRing,
    renderReport,
    verdictSentence,
    plainTextReport,
    buildReportHtml,
    reportFilename,
    downloadReport,
    toast,
    copyText,
  };
})();
