/* PhishGuard — detection constants and brand registry */
(function () {
  "use strict";

  const PG = (globalThis.PG = globalThis.PG || {});

  /**
   * Brands that are frequently impersonated. `domains` lists the only
   * registrable suffixes we consider legitimate for that brand.
   */
  const BRANDS = [
    { name: "paypal", domains: ["paypal.com", "paypal.me", "paypalobjects.com", "paypal-community.com"] },
    { name: "microsoft", domains: ["microsoft.com", "microsoftonline.com", "microsoft365.com", "live.com", "office.com", "office365.com", "outlook.com", "onedrive.com", "sharepoint.com", "azure.com", "xbox.com", "skype.com", "msn.com", "bing.com", "windows.com", "visualstudio.com", "nuget.org"] },
    { name: "google", domains: ["google.com", "googleapis.com", "googleusercontent.com", "googlevideo.com", "gstatic.com", "youtube.com", "youtu.be", "gmail.com", "goo.gl", "android.com", "chrome.com", "withgoogle.com", "google.co.uk", "google.in"] },
    { name: "apple", domains: ["apple.com", "icloud.com", "me.com", "apple.co", "applemusic.com"] },
    { name: "amazon", domains: ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.ca", "amazon.com.au", "amazon.co.jp", "amazonaws.com", "primevideo.com", "audible.com"] },
    { name: "facebook", domains: ["facebook.com", "fb.com", "fb.me", "messenger.com"] },
    { name: "meta", domains: ["meta.com", "facebook.com", "instagram.com", "whatsapp.com", "fb.com"] },
    { name: "instagram", domains: ["instagram.com", "instagr.am", "cdninstagram.com"] },
    { name: "whatsapp", domains: ["whatsapp.com", "wa.me", "whatsapp.net"] },
    { name: "telegram", domains: ["telegram.org", "t.me", "telegram.me"] },
    { name: "discord", domains: ["discord.com", "discord.gg", "discordapp.com", "discordapp.net"] },
    { name: "netflix", domains: ["netflix.com", "nflxvideo.net", "nflximg.net"] },
    { name: "spotify", domains: ["spotify.com", "spotify.link", "scdn.co"] },
    { name: "docusign", domains: ["docusign.com", "docusign.net"] },
    { name: "dropbox", domains: ["dropbox.com", "dropboxusercontent.com", "dropboxstatic.com"] },
    { name: "adobe", domains: ["adobe.com", "adobelogin.com", "adobe.io"] },
    { name: "steam", domains: ["steampowered.com", "steamcommunity.com", "steamstatic.com"] },
    { name: "epicgames", domains: ["epicgames.com", "epicgames.dev", "unrealengine.com"] },
    { name: "roblox", domains: ["roblox.com", "rbxcdn.com", "roblox.qq.com"] },
    { name: "playstation", domains: ["playstation.com", "sony.com", "sonyentertainmentnetwork.com"] },
    { name: "nintendo", domains: ["nintendo.com", "nintendo.net", "nintendo.co.jp"] },
    { name: "twitch", domains: ["twitch.tv", "ttvnw.net", "jtvnw.net"] },
    { name: "reddit", domains: ["reddit.com", "redd.it", "redditmedia.com", "redditstatic.com"] },
    { name: "pinterest", domains: ["pinterest.com", "pinimg.com", "pin.it"] },
    { name: "snapchat", domains: ["snapchat.com", "snap.com", "sc-static.net"] },
    { name: "tiktok", domains: ["tiktok.com", "tiktokv.com", "byteoversea.com", "musical.ly"] },
    { name: "linkedin", domains: ["linkedin.com", "licdn.com", "lnkd.in"] },
    { name: "github", domains: ["github.com", "githubusercontent.com", "githubassets.com", "github.io", "github.dev"] },
    { name: "gitlab", domains: ["gitlab.com", "gitlab.io"] },
    { name: "slack", domains: ["slack.com", "slack-edge.com", "slack-files.com"] },
    { name: "zoom", domains: ["zoom.us", "zoom.com", "zoomgov.com"] },
    { name: "notion", domains: ["notion.so", "notion.site", "notion.com"] },
    { name: "figma", domains: ["figma.com", "figstatic.com"] },
    { name: "canva", domains: ["canva.com", "canva.site", "canvausercontent.com"] },
    { name: "booking", domains: ["booking.com", "booking.holdings"] },
    { name: "airbnb", domains: ["airbnb.com", "airbnb.com.br", "airbnb.co.uk"] },
    { name: "uber", domains: ["uber.com", "ubercms.com"] },
    { name: "lyft", domains: ["lyft.com", "lyft.net"] },
    { name: "doordash", domains: ["doordash.com", "doordash.news"] },
    { name: "walmart", domains: ["walmart.com", "walmart.ca", "walmartapis.com"] },
    { name: "target", domains: ["target.com", "targetimg1.com"] },
    { name: "bestbuy", domains: ["bestbuy.com", "bestbuyservices.com"] },
    { name: "ebay", domains: ["ebay.com", "ebay.co.uk", "ebay.in", "ebayimg.com", "ebaystatic.com"] },
    { name: "aliexpress", domains: ["aliexpress.com", "aliexpress.ru", "alicdn.com"] },
    { name: "alibaba", domains: ["alibaba.com", "alibabacloud.com", "aliyun.com"] },
    { name: "shopify", domains: ["shopify.com", "myshopify.com", "shopifycdn.com"] },
    { name: "stripe", domains: ["stripe.com", "stripe.network", "stripe.dev"] },
    { name: "cloudflare", domains: ["cloudflare.com", "cloudflare.net", "cloudflare-dns.com", "workers.dev"] },
    { name: "godaddy", domains: ["godaddy.com", "secureserver.net"] },
    { name: "namecheap", domains: ["namecheap.com", "namecheap.net"] },
    { name: "yahoo", domains: ["yahoo.com", "yimg.com", "yahoo.co.jp", "yahoo.in"] },
    { name: "protonmail", domains: ["proton.me", "protonmail.com", "protonmail.ch", "protonvpn.com"] },
    { name: "coinbase", domains: ["coinbase.com", "coinbase.com.br", "cbhq.net"] },
    { name: "binance", domains: ["binance.com", "binance.us", "bnbstatic.com"] },
    { name: "metamask", domains: ["metamask.io", "metamask.app"] },
    { name: "trustwallet", domains: ["trustwallet.com", "trustwallet.org"] },
    { name: "kraken", domains: ["kraken.com", "krakenfx.com"] },
    { name: "revolut", domains: ["revolut.com", "revolut.codes", "revolutpays.com"] },
    { name: "cashapp", domains: ["cash.app", "squareup.com", "square.com"] },
    { name: "venmo", domains: ["venmo.com", "venmo.net"] },
    { name: "zelle", domains: ["zellepay.com", "zelle.com"] },
    { name: "chase", domains: ["chase.com", "jpmorgan.com", "jpmorganchase.com"] },
    { name: "bankofamerica", domains: ["bankofamerica.com", "bofa.com", "ml.com"] },
    { name: "wellsfargo", domains: ["wellsfargo.com", "wf.com"] },
    { name: "citibank", domains: ["citibank.com", "citi.com", "citigroup.com"] },
    { name: "hsbc", domains: ["hsbc.com", "hsbc.co.uk", "hsbc.net"] },
    { name: "barclays", domains: ["barclays.co.uk", "barclays.com", "barclaycard.co.uk"] },
    { name: "santander", domains: ["santander.com", "santander.co.uk", "santanderbank.com"] },
    { name: "hdfc", domains: ["hdfcbank.com", "hdfc.com", "hdfclife.com"] },
    { name: "icici", domains: ["icicibank.com", "icicibank.co.in", "icicidirect.com"] },
    { name: "axis", domains: ["axisbank.com", "axisbank.co.in"] },
    { name: "sbi", domains: ["onlinesbi.sbi", "onlinesbi.com", "sbi.co.in", "sbicard.com"] },
    { name: "paytm", domains: ["paytm.com", "paytmbank.com", "paytm.in"] },
    { name: "phonepe", domains: ["phonepe.com", "phonepe.in"] },
    { name: "aadhaar", domains: ["uidai.gov.in", "aadhaar.uidai.gov.in", "myaadhaar.uidai.gov.in"] },
    { name: "irs", domains: ["irs.gov", "irs.com"] },
    { name: "usps", domains: ["usps.com", "usps.gov", "uspsmail.com"] },
    { name: "dhl", domains: ["dhl.com", "dhl.de", "dhlparcel.co.uk"] },
    { name: "fedex", domains: ["fedex.com", "fedex.co.uk", "fedex.com.br"] },
    { name: "ups", domains: ["ups.com", "upsc.com", "ups.dev"] },
    { name: "royalmail", domains: ["royalmail.com", "royalmailgroup.com"] },
    { name: "flipkart", domains: ["flipkart.com", "flipkart.net", "fkrt.it"] },
    { name: "myntra", domains: ["myntra.com", "myntassets.com"] },
    { name: "swiggy", domains: ["swiggy.in", "swiggy.com", "swiggy.in"] },
    { name: "zomato", domains: ["zomato.com", "zomato.in"] },
    { name: "irctc", domains: ["irctc.co.in", "irctc.com", "indianrail.gov.in"] },
    { name: "airtel", domains: ["airtel.in", "airtel.com", "airtel.co.in"] },
    { name: "jio", domains: ["jio.com", "jio.in", "jiomart.com"] },
    { name: "wordpress", domains: ["wordpress.com", "wordpress.org", "wp.com"] },
    { name: "wix", domains: ["wix.com", "wixsite.com", "wixstatic.com"] },
    { name: "squarespace", domains: ["squarespace.com", "sqsp.net"] },
    { name: "webflow", domains: ["webflow.com", "webflow.io"] },
    { name: "etsy", domains: ["etsy.com", "etsystatic.com"] },
    { name: "openai", domains: ["openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com"] },
    { name: "anthropic", domains: ["anthropic.com", "claude.ai", "claude.com"] },
  ];

  const SUSPICIOUS_TLDS = new Set([
    "zip", "mov", "top", "xyz", "click", "link", "tk", "ml", "ga", "cf", "gq",
    "work", "rest", "cam", "sbs", "buzz", "monster", "lol", "icu", "cfd", "su",
    "pw", "ws", "bar", "boats", "casa", "cyou", "download", "fit", "hair", "host",
    "makeup", "mom", "quest", "skin", "autos", "beauty", "bond", "christmas",
    "dance", "date", "faith", "gift", "life", "lifestyle", "love", "men", "party",
    "review", "science", "stream", "study", "trade", "win", "work", "yachts",
  ]);

  const SHADY_TLDS = new Set([
    "online", "site", "info", "biz", "shop", "live", "fun", "club", "vip", "pro",
    "store", "space", "website", "press", "today", "email", "sale", "support",
  ]);

  const URL_SHORTENERS = new Set([
    "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy", "tiny.cc",
    "s.id", "lnkd.in", "t.ly", "v.gd", "qr.ae", "adf.ly", "shrtco.de", "short.io",
    "bl.ink", "urlz.fr", "clck.ru", "tiny.one", "surl.li", "trib.al", "dlvr.it",
    "ift.tt", "u.to", "x.co", "j.mp", "v.ht", "po.st", "snip.ly",
  ]);

  const DYNAMIC_DNS = new Set([
    "duckdns.org", "no-ip.com", "noip.com", "ddns.net", "hopto.org", "zapto.org",
    "sytes.net", "dyndns.org", "dynu.net", "ngrok.io", "ngrok-free.app",
    "ngrok.app", "trycloudflare.com", "serveo.net", "localhost.run", "loca.lt",
    "pagekite.me", "telebit.io", "bore.pub", "tunnelto.dev", "pinggy.io",
  ]);

  const HOST_KEYWORDS = [
    "login", "log-in", "signin", "sign-in", "secure", "account", "update",
    "verify", "verification", "confirm", "password", "passwd", "billing",
    "payment", "invoice", "wallet", "recover", "recovery", "unlock", "suspend",
    "alert", "support", "helpdesk", "banking", "kyc", "aadhaar", "pan-card",
    "refund", "delivery", "tracking", "customs", "bonus", "giveaway", "prize",
    "claim", "seed", "privatekey", "connect", "validation", "authenticate",
    "webscr", "security-check", "id-verify", "customer-care",
  ];

  const PATH_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "account", "update",
    "password", "billing", "payment", "invoice", "wallet", "recovery", "unlock",
    "confirm", "secure", "bonus", "claim", "prize", "kyc", "refund",
  ];

  const DOUBLE_EXTENSION_RE =
    /\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|csv|html?|zip|rar|7z|mp4|mp3|svg|xml|json|apk|dmg|iso)\.(?:exe|scr|bat|cmd|com|pif|vbs|vbe|js|jse|wsf|wsh|hta|msi|jar|apk|ps1|sh|lnk|py|rb|pl|reg|cpl|dll|sys)$/i;

  /** Heuristic scores per signal (documented in extension/README.md). */
  const WEIGHTS = {
    dangerousScheme: 95,
    privateIpNote: 0,
    ipHost: 26,
    credentials: 22,
    punycode: 18,
    suspiciousTld: 14,
    shadyTld: 5,
    manyLabels: 8,
    brandImpersonation: 34,
    brandCombo: 20,
    typosquat: 26,
    shortener: 8,
    unusualPort: 10,
    longHost: 6,
    manyHyphens: 8,
    randomLabel: 10,
    hostKeywords: 12,
    manyHostKeywords: 6,
    pathKeywords: 4,
    httpCredentialForm: 10,
    encodedPath: 8,
    doubleExtension: 22,
    dynamicDns: 18,
    longPath: 4,
    embeddedRedirect: 10,
    manyDots: 6,
    base64Path: 8,
  };

  const MAX_HEURISTIC_SCORE = 80;

  /** Reputable domains we never block on heuristics alone (feeds still apply). */
  const TRUSTED_DOMAINS = new Set([
    "google.com", "youtube.com", "microsoft.com", "apple.com", "amazon.com",
    "github.com", "gitlab.com", "cloudflare.com", "wikipedia.org", "mozilla.org",
    "facebook.com", "instagram.com", "whatsapp.com", "linkedin.com", "netflix.com",
    "x.com", "twitter.com", "openai.com", "anthropic.com", "stackoverflow.com",
    "reddit.com", "npmjs.com", "wordpress.org",
    "microsoftonline.com", "office.com", "live.com", "outlook.com", "bing.com",
    "yahoo.com", "paypal.com", "stripe.com", "shopify.com", "salesforce.com",
    "adobe.com", "dropbox.com", "slack.com", "zoom.us", "notion.so", "figma.com",
    "canva.com", "spotify.com", "twitch.tv", "discord.com", "telegram.org",
    "signal.org", "proton.me", "w3.org", "ietf.org", "archive.org",
    "debian.org", "ubuntu.com", "python.org",
    "nodejs.org", "rust-lang.org", "golang.org", "docker.com", "kubernetes.io",
  ]);

  const THRESHOLDS = { suspicious: 40, malicious: 70 };

  PG.constants = {
    BRANDS,
    SUSPICIOUS_TLDS,
    SHADY_TLDS,
    URL_SHORTENERS,
    DYNAMIC_DNS,
    HOST_KEYWORDS,
    PATH_KEYWORDS,
    DOUBLE_EXTENSION_RE,
    WEIGHTS,
    MAX_HEURISTIC_SCORE,
    TRUSTED_DOMAINS,
    THRESHOLDS,
    LEVELS: ["safe", "suspicious", "malicious"],
  };
})();
