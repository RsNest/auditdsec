/* Reports the panel's own errors to the server's log (frontend.jsonl), so a
 * failure that exists only in a browser reaches the same place as every other
 * log. Rules:
 *  - it sends text only: no page content, no form values, no storage, no cookies;
 *  - the server cleans and limits what it receives; this side limits too:
 *    a short queue, identical errors counted instead of resent, three tries
 *    with growing pauses, then the report is dropped;
 *  - it only reports while signed in, with the same token and marker header as
 *    every other call, and never reports its own failures;
 *  - it has no access to the file system or Docker: it is a POST to the panel. */
(function () {
  "use strict";

  var MAX_QUEUE = 20;
  var PAUSES = [5000, 15000, 45000];
  var queue = [];
  var sending = false;
  var provider = { token: function () { return null; }, build: function () { return ""; } };

  function hex(n) {
    var out = "";
    try {
      var a = new Uint8Array(n);
      crypto.getRandomValues(a);
      for (var i = 0; i < a.length; i++) { out += ("0" + a[i].toString(16)).slice(-2); }
    } catch (e) {
      for (var j = 0; j < n * 2; j++) { out += Math.floor(Math.random() * 16).toString(16); }
    }
    return out;
  }

  /* A request ID the server will keep: 32 lower-case hex characters. */
  function requestId() { return hex(16); }

  function clip(s, n) { s = String(s == null ? "" : s); return s.length > n ? s.slice(0, n) : s; }

  /* Addresses of pages can carry filters or addresses: only the path is sent. */
  function noQuery(s) { s = String(s || ""); var i = s.indexOf("?"); return i >= 0 ? s.slice(0, i) : s; }

  function report(kind, message, extra) {
    extra = extra || {};
    var item = {
      kind: kind,
      message: clip(message, 500),
      stack: clip(extra.stack, 2000),
      source: clip(noQuery(extra.source), 300),
      line: extra.line | 0,
      col: extra.col | 0,
      route: clip(noQuery(location.hash || location.pathname), 200),
      build: clip(provider.build(), 40),
      user_agent: clip(navigator.userAgent, 200),
      client_time: new Date().toISOString(),
      request_id: extra.requestId || "",
      status: extra.status | 0,
      count: 1
    };
    var key = item.kind + "|" + item.message + "|" + item.source + "|" + item.line;
    for (var i = 0; i < queue.length; i++) {
      if (queue[i].key === key) { queue[i].item.count++; return; }
    }
    if (queue.length >= MAX_QUEUE) { return; }
    queue.push({ key: key, item: item, tries: 0 });
    pump();
  }

  function pump() {
    if (sending || !queue.length) { return; }
    var token = provider.token();
    if (!token) { return; }
    sending = true;
    var entry = queue[0];
    var done = function (ok, retry) {
      sending = false;
      if (ok || entry.tries >= PAUSES.length || !retry) {
        queue.shift();
        setTimeout(pump, 0);
        return;
      }
      var pause = PAUSES[entry.tries++];
      setTimeout(pump, pause);
    };
    try {
      fetch("/api/v1/client-log", {
        method: "POST", cache: "no-store", keepalive: true,
        headers: { "Content-Type": "application/json", "X-Requested-With": "auditdsec", Authorization: "Bearer " + token },
        body: JSON.stringify(entry.item)
      }).then(function (res) {
        // 401/403: the session is gone; 400/413: retrying the same text would
        // fail the same way. 429 and server errors are worth another try.
        done(res.ok, res.status === 429 || res.status >= 500);
      }, function () { done(false, true); });
    } catch (e) {
      done(false, false);
    }
  }

  window.addEventListener("error", function (ev) {
    var t = ev.target;
    if (t && t !== window && (t.src || t.href)) {
      report("resource", "failed to load " + noQuery(t.src || t.href), { source: t.src || t.href });
      return;
    }
    report("error", ev.message || "error", {
      source: ev.filename, line: ev.lineno, col: ev.colno,
      stack: ev.error && ev.error.stack
    });
  }, true);

  window.addEventListener("unhandledrejection", function (ev) {
    var r = ev.reason;
    report("unhandledrejection", (r && r.message) || String(r), { stack: r && r.stack });
  });

  window.AUDITDSEC_REPORT = {
    report: report,
    requestId: requestId,
    /* The panel gives it the token and the build it is running. */
    provide: function (p) { for (var k in p) { if (typeof p[k] === "function") { provider[k] = p[k]; } } },
    flush: pump
  };
})();
