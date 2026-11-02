/* PhishGuard — warning interstitial */
(function () {
  "use strict";

  const PG = globalThis.PG;
  const U = PG.utils;
  const ui = PG.ui;
  const api = U.api;

  const params = new URLSearchParams(window.location.search);
  const scanId = params.get("id");
  const rawUrl = params.get("u");

  let result = null;
  let tabId = null;

  const $ = (id) => document.getElementById(id);

  /**
   * Messages sent from an extension page do not carry sender.tab, so look up
   * the tab hosting this interstitial and pass its id with tab actions.
   */
  async function ownTabId() {
    if (tabId != null) return tabId;
    try {
      const tab = await U.invoke(api.tabs, "getCurrent");
      if (tab && tab.id != null) tabId = tab.id;
    } catch {
      /* ignore — the background will fall back to a new tab */
    }
    return tabId;
  }

  function levelClass(level) {
    document.body.classList.remove("safe", "suspicious", "malicious");
    document.body.classList.add(level === "safe" ? "safe" : level === "suspicious" ? "suspicious" : "malicious");
  }

  function setText(id, text) {
    const node = $(id);
    if (node) node.textContent = text;
  }

  function showError(message) {
    $("loadingState").classList.add("hidden");
    $("content").classList.add("hidden");
    $("errorState").classList.remove("hidden");
    setText("errorText", message || "The report could not be loaded.");
  }

  async function load() {
    $("errorState").classList.add("hidden");
    $("content").classList.add("hidden");
    $("loadingState").classList.remove("hidden");

    let scan = null;
    try {
      if (scanId) {
        scan = await PG.send({ type: "PG_GET_SCAN", id: scanId });
      }
      if (!scan && rawUrl) {
        scan = await PG.send({
          type: "PG_SCAN",
          url: rawUrl,
          deep: false,
          record: false,
          trigger: "warning",
        });
      }
    } catch (err) {
      showError(err.message);
      return;
    }

    if (!scan) {
      showError("This report expired. Open the link again from the PhishGuard popup or console.");
      return;
    }

    result = scan;
    render(scan);
  }

  function adviceFor(level) {
    if (level === "safe") {
      return {
        title: "No threats detected in the sources we checked",
        text: "This report was opened from a previous alert, or the site has since been cleared. Continue only if you trust the sender of the link.",
        items: [
          "Confirm the address in the browser bar matches the site you intended to visit.",
          "Never enter a password you did not expect to need.",
        ],
      };
    }
    if (level === "suspicious") {
      return {
        title: "Verify this site before you continue",
        text: "Some risk signals matched phishing patterns, but nothing confirmed malware. Attackers often rely on you not checking the address.",
        items: [
          "Reach the site through a bookmark or by typing the official address yourself.",
          "Contact the organization using a phone number from your own records — not the one on this page.",
          "Do not enter passwords, card numbers, or one-time codes on a page you reached from an unexpected link.",
        ],
      };
    }
    return {
      title: "Do not continue to this site",
      text: "This address matched known phishing or malware indicators. Visiting it could expose your accounts, credentials, or device.",
      items: [
        "Do not sign in, pay, or download anything from this site.",
        "If you already entered a password, change it now and turn on two-factor authentication.",
        "Report the message or link to your IT team, bank, or the brand being impersonated.",
        "Use PhishGuard's console to review the signals and keep a copy of this report.",
      ],
    };
  }

  function render(scan) {
    const level = scan.level === "safe" ? "safe" : scan.level === "suspicious" ? "suspicious" : "malicious";
    levelClass(level);

    $("loadingState").classList.add("hidden");
    $("errorState").classList.add("hidden");
    $("content").classList.remove("hidden");

    const malicious = level === "malicious";
    const suspicious = level === "suspicious";

    setText("eyebrow", malicious ? "Threat detected" : suspicious ? "Caution advised" : "No threats detected");
    setText(
      "headline",
      malicious ? "This site may be dangerous" : suspicious ? "This site looks suspicious" : "This site looks clear now",
    );
    setText("host", scan.host || "Unknown host");
    setText("urlText", U.shortUrl(scan.url, 110));
    $("urlText").title = scan.url;

    const scanType = $("scanType");
    scanType.textContent = scan.deep ? "Deep scan" : "Offline scan";
    scanType.className = `pill ${malicious ? "malicious" : suspicious ? "suspicious" : "safe"}`;

    $("heroIcon").textContent = "";
    $("heroIcon").appendChild(ui.icon(malicious ? "shieldAlert" : "shield"));

    $("scoreHolder").textContent = "";
    $("scoreHolder").appendChild(ui.scoreRing(scan.score, level, 104));

    const banner = $("statusBanner");
    banner.className = "status-banner";
    banner.textContent = "";
    const marker = document.createElement("span");
    marker.className = "marker";
    banner.appendChild(marker);
    const bannerText = document.createElement("span");
    bannerText.textContent = malicious
      ? `Blocked before it loaded. Risk score ${scan.score}/100 — a high score is a strong indication of phishing or malware.`
      : suspicious
        ? `Risk score ${scan.score}/100. Treat this page with caution and verify the address.`
        : `Risk score ${scan.score}/100. No detections in the sources we checked.`;
    banner.appendChild(bannerText);

    const advice = adviceFor(level);
    setText("adviceTitle", advice.title);
    setText("adviceText", advice.text);
    const list = $("adviceList");
    list.textContent = "";
    for (const item of advice.items) {
      const li = document.createElement("li");
      li.textContent = item;
      list.appendChild(li);
    }

    ui.renderReport(scan, $("report"), { maxReasons: 12, actions: [] });
    setText("timestamp", U.formatDateTime(scan.scannedAt));

    configureActions(scan, level);
    document.title = malicious ? "Blocked by PhishGuard" : suspicious ? "Warning from PhishGuard" : "PhishGuard — clear";
  }

  function configureActions(scan, level) {
    const backBtn = $("backBtn");
    const proceedBtn = $("proceedBtn");
    const trustBtn = $("trustBtn");
    const reportBtn = $("reportBtn");
    const proceedPanel = $("proceedPanel");

    backBtn.textContent = level === "safe" ? "Close this tab" : "Back to safety";
    backBtn.onclick = () => backToSafety();

    proceedPanel.classList.add("hidden");
    $("riskAck").checked = false;
    $("continueBtn").disabled = true;

    if (level === "safe") {
      proceedBtn.className = "btn primary";
      proceedBtn.textContent = "Continue to site";
      proceedBtn.onclick = () => proceedTo(scan);
      trustBtn.classList.add("hidden");
      reportBtn.classList.add("hidden");
    } else {
      proceedBtn.className = "btn ghost danger-text";
      proceedBtn.classList.remove("hidden");
      proceedBtn.textContent = "Continue anyway";
      proceedBtn.onclick = () => proceedPanel.classList.toggle("hidden");
      trustBtn.classList.remove("hidden");
      reportBtn.classList.remove("hidden");
      trustBtn.onclick = () => trustSite(scan);
      reportBtn.onclick = () => reportFalsePositive(scan);
    }

    $("backBtn").onclick = () => backToSafety(scan);
    $("detailsBtn").onclick = () => $("reportSection").scrollIntoView({ behavior: "smooth", block: "start" });
    $("continueBtn").onclick = () => proceedTo(scan);
    $("riskAck").onchange = () => {
      $("continueBtn").disabled = !$("riskAck").checked;
    };
    $("cancelProceed").onclick = () => proceedPanel.classList.add("hidden");
    $("trustBtn").onclick = () => trustSite(scan);
    $("reportBtn").onclick = () => reportFalsePositive(scan);
    $("consoleBtn").onclick = () => {
      PG.send({ type: "PG_OPEN_APP", url: scan.url }).catch((err) => ui.toast(err.message, true));
    };
    $("copyBtn").onclick = async () => {
      const ok = await ui.copyText(ui.plainTextReport(scan));
      ui.toast(ok ? "Report copied" : "Could not copy report", !ok);
    };
    $("downloadBtn").onclick = () => {
      try {
        const name = ui.downloadReport(scan, "html");
        ui.toast(`Report saved as ${name}`);
      } catch (err) {
        ui.toast(err.message || "Could not save report", true);
      }
    };
    $("rescanBtn").onclick = () => rescan(scan);
  }

  async function rescan(scan) {
    const button = $("rescanBtn");
    button.disabled = true;
    button.textContent = "Scanning…";
    try {
      const fresh = await PG.send({
        type: "PG_SCAN",
        url: scan.url,
        deep: true,
        force: true,
        record: false,
        trigger: "warning",
      });
      result = fresh;
      render(fresh);
      ui.toast("Report refreshed");
    } catch (err) {
      ui.toast(err.message, true);
    } finally {
      button.disabled = false;
      button.textContent = "Re-scan";
    }
  }

  async function proceedTo(scan) {
    try {
      await PG.send({ type: "PG_PROCEED", url: scan.url, tabId: await ownTabId() });
    } catch (err) {
      ui.toast(err.message, true);
    }
  }

  async function backToSafety(scan) {
    try {
      await PG.send({
        type: "PG_BACK_TO_SAFETY",
        tabId: await ownTabId(),
        previousUrl: (result && result.previousUrl) || (scan && scan.previousUrl) || "",
      });
    } catch {
      window.close();
    }
  }

  async function trustSite(scan) {
    const host = scan.host || U.hostOf(scan.url);
    const confirmed = window.confirm(
      `Trust ${host}?\n\nPhishGuard will skip automatic blocking for this domain. Only do this if you are certain the site is legitimate.`,
    );
    if (!confirmed) return;
    try {
      await PG.send({ type: "PG_TRUST", url: scan.url, tabId: await ownTabId(), proceed: true, clearVerdict: true });
    } catch (err) {
      ui.toast(err.message, true);
    }
  }

  async function reportFalsePositive(scan) {
    const host = scan.host || U.hostOf(scan.url);
    const confirmed = window.confirm(
      `Report ${host} as a false positive?\n\nThis adds the domain to your trusted list and stores the report locally.`,
    );
    if (!confirmed) return;
    try {
      await PG.send({ type: "PG_REPORT_FALSE_POSITIVE", url: scan.url });
      ui.toast("Marked as a false positive. The domain is now trusted.");
      setTimeout(() => backToSafety(), 900);
    } catch (err) {
      ui.toast(err.message, true);
    }
  }

  $("retryBtn").onclick = () => load();
  $("closeErrorBtn").onclick = async () => {
    try {
      const tab = await U.invoke(api.tabs, "getCurrent");
      if (tab) await U.invoke(api.tabs, "remove", tab.id);
      else window.close();
    } catch {
      window.close();
    }
  };

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      event.preventDefault();
      backToSafety();
    }
  });

  load();
})();
