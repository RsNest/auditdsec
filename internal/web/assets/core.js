/* auditdsec panel: state, data access, formatting and small shared helpers.
   Plain scripts on purpose — no bundler, no modules — so the page also opens
   straight from disk. Values that come from the audit log are attacker
   controlled, so they only ever reach the DOM as text nodes. */
(function () {
  "use strict";

  var API = "/api/v1";
  var NS = "http://www.w3.org/2000/svg";
  var KINDS = [
    "ssh_login_ok", "ssh_login_fail", "auth_ok", "auth_fail", "login_after_bruteforce", "sudo",
    "user_change", "authorized_keys_change", "persistence", "config_change",
    "log_tamper", "suspicious_exec", "auditd_stopped", "panel_cert"
  ];
  var KIND_SEV = {
    ssh_login_ok: "info", ssh_login_fail: "warn", auth_ok: "info", auth_fail: "warn", login_after_bruteforce: "critical",
    sudo: "info", user_change: "warn", authorized_keys_change: "critical",
    persistence: "critical", config_change: "warn", log_tamper: "critical",
    suspicious_exec: "warn", auditd_stopped: "critical", panel_cert: "warn"
  };
  var SEVS = ["info", "warn", "critical"];
  var SEV_RANK = { info: 0, warn: 1, critical: 2 };

  /* ---------------- storage, tolerant of private mode ---------------- */

  function get(store, key) {
    try { return window[store].getItem(key); } catch (e) { return null; }
  }
  function put(store, key, value) {
    try {
      if (value === null) { window[store].removeItem(key); }
      else { window[store].setItem(key, value); }
    } catch (e) { /* storage unavailable: the panel still works */ }
  }

  /* ---------------- state ---------------- */

  var params = new URLSearchParams(location.search);
  var mock = params.get("mock") === "1" || location.protocol === "file:";

  function pick(value, allowed) { return allowed.indexOf(value) >= 0 ? value : null; }

  var state = {
    mock: mock,
    lang: pick(params.get("lang"), ["ru", "en"]) || pick(get("localStorage", "ads.lang"), ["ru", "en"]) ||
      ((navigator.language || "ru").toLowerCase().indexOf("ru") === 0 ? "ru" : "en"),
    /* ?theme= renders one theme on demand, for screenshots and kiosks. */
    theme: pick(params.get("theme"), ["dark", "light"]) || pick(get("localStorage", "ads.theme"), ["dark", "light"]) || "dark",
    token: get("sessionStorage", "ads.token"),
    status: null,
    offline: false,
    reduced: !!(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches),
    announced: null
  };
  var hooks = { unauthorized: null };

  /* ---------------- i18n ---------------- */

  var CATALOGS = window.AUDITDSEC_I18N || { ru: {}, en: {} };

  function t(key, vars) {
    var s = (CATALOGS[state.lang] || {})[key];
    if (s === undefined) { s = (CATALOGS.ru || {})[key]; }
    if (s === undefined) { return key; }
    if (!vars) { return s; }
    return s.replace(/{(\w+)}/g, function (m, name) {
      return vars[name] === undefined || vars[name] === null ? m : String(vars[name]);
    });
  }

  /* ---------------- formatting ---------------- */

  function num(n) {
    if (n === null || n === undefined) { return "—"; }
    try { return new Intl.NumberFormat(state.lang).format(n); } catch (e) { return String(n); }
  }
  function parseTime(iso) {
    if (!iso) { return null; }
    var d = new Date(iso);
    return isNaN(d.getTime()) ? null : d;
  }
  function fmt(iso, opts, fallback) {
    var d = parseTime(iso);
    if (!d) { return t("common.never"); }
    try { return new Intl.DateTimeFormat(state.lang, opts).format(d); } catch (e) { return fallback(d); }
  }
  function dateTime(iso) {
    return fmt(iso, { dateStyle: "medium", timeStyle: "short" }, function (d) { return d.toISOString(); });
  }
  function clock(iso) {
    return fmt(iso, { hour: "2-digit", minute: "2-digit", second: "2-digit" }, function (d) { return d.toISOString().slice(11, 19); });
  }
  function hourLabel(iso) {
    return fmt(iso, { hour: "2-digit", minute: "2-digit", hour12: false }, function (d) { return d.toISOString().slice(11, 16); });
  }
  function relative(iso) {
    var d = parseTime(iso);
    if (!d) { return t("common.never"); }
    var secs = Math.round((d.getTime() - Date.now()) / 1000);
    if (Math.abs(secs) < 45) { return t("common.just_now"); }
    var units = [["day", 86400], ["hour", 3600], ["minute", 60], ["second", 1]];
    try {
      var rtf = new Intl.RelativeTimeFormat(state.lang, { numeric: "auto" });
      for (var i = 0; i < units.length; i++) {
        if (Math.abs(secs) >= units[i][1] || i === units.length - 1) {
          return rtf.format(Math.round(secs / units[i][1]), units[i][0]);
        }
      }
    } catch (e) { /* fall through */ }
    return dateTime(iso);
  }
  function duration(seconds) {
    if (seconds === null || seconds === undefined) { return t("common.unknown"); }
    var s = Math.max(0, Math.floor(seconds));
    var d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
    if (d > 0) { return t("unit.d", { n: d }) + " " + t("unit.h", { n: h }); }
    if (h > 0) { return t("unit.h", { n: h }) + " " + t("unit.m", { n: m }); }
    if (m > 0) { return t("unit.m", { n: m }); }
    return t("unit.s", { n: s });
  }
  function until(iso, permanent) {
    return permanent || !iso ? t("bans.permanent") : dateTime(iso);
  }

  /* ---------------- DOM helpers ---------------- */

  function el(tag, props, kids) {
    var node = document.createElement(tag);
    if (props) {
      for (var key in props) {
        if (!Object.prototype.hasOwnProperty.call(props, key)) { continue; }
        var v = props[key];
        if (v === null || v === undefined || v === false) { continue; }
        if (key === "class") { node.className = v; }
        else if (key === "text") { node.textContent = String(v); }
        else if (key === "value") { node.value = v; }
        else if (key.slice(0, 2) === "on") { node.addEventListener(key.slice(2), v); }
        else if (key === "dataset") { for (var d in v) { if (v[d] !== null && v[d] !== undefined) { node.dataset[d] = v[d]; } } }
        else { node.setAttribute(key, v === true ? "" : String(v)); }
      }
    }
    add(node, kids);
    return node;
  }
  function add(node, kids) {
    if (kids === null || kids === undefined || kids === false) { return node; }
    if (!Array.isArray(kids)) { kids = [kids]; }
    for (var i = 0; i < kids.length; i++) {
      var k = kids[i];
      if (k === null || k === undefined || k === false) { continue; }
      node.appendChild(typeof k === "object" ? k : document.createTextNode(String(k)));
    }
    return node;
  }
  function clear(node) { while (node.firstChild) { node.removeChild(node.firstChild); } return node; }
  function $(sel, root) { return (root || document).querySelector(sel); }
  function sv(tag, attrs, text) {
    var n = document.createElementNS(NS, tag);
    if (attrs) { for (var k in attrs) { n.setAttribute(k, attrs[k]); } }
    if (text !== undefined && text !== null) { n.textContent = text; }
    return n;
  }
  function clamp(x, lo, hi) { return Math.min(hi, Math.max(lo, x)); }
  function easeOut(x) { return 1 - Math.pow(1 - x, 3); }
  function debounce(fn, ms) {
    var timer = null;
    return function () { if (timer) { clearTimeout(timer); } timer = setTimeout(fn, ms); };
  }

  /* ---------------- addresses ---------------- */

  function isIPv4(s) {
    var p = s.split(".");
    if (p.length !== 4) { return false; }
    for (var i = 0; i < 4; i++) {
      if (!/^\d{1,3}$/.test(p[i]) || Number(p[i]) > 255) { return false; }
      if (p[i].length > 1 && p[i][0] === "0") { return false; }
    }
    return true;
  }
  function isIPv6(s) {
    if (s.indexOf(":") < 0) { return false; }
    var halves = s.split("::");
    if (halves.length > 2) { return false; }
    var groups = [];
    for (var h = 0; h < halves.length; h++) {
      if (halves[h] === "") { continue; }
      var parts = halves[h].split(":");
      for (var i = 0; i < parts.length; i++) {
        if (parts[i].indexOf(".") >= 0) {
          if (i !== parts.length - 1 || !isIPv4(parts[i])) { return false; }
          groups.push("0", "0");
          continue;
        }
        if (!/^[0-9a-fA-F]{1,4}$/.test(parts[i])) { return false; }
        groups.push(parts[i]);
      }
    }
    return halves.length === 2 ? groups.length <= 7 : groups.length === 8;
  }
  function isIP(s) { return isIPv4(s) || isIPv6(s); }

  /* Mirrors the agent: an address the kernel could never usefully ban is not
     offered for banning in the first place. */
  function bannable(s) {
    if (!s || !isIP(s)) { return false; }
    if (isIPv4(s)) {
      var o = s.split(".").map(Number);
      if (o[0] === 0 || o[0] === 127 || o[0] === 10 || o[0] >= 224) { return false; }
      if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) { return false; }
      if (o[0] === 192 && o[1] === 168) { return false; }
      if (o[0] === 169 && o[1] === 254) { return false; }
      return true;
    }
    var low = s.toLowerCase();
    if (low === "::" || low === "::1") { return false; }
    return !(/^fe[89ab]/.test(low) || /^f[cd]/.test(low) || /^ff/.test(low));
  }

  /* ---------------- data access ---------------- */

  function fail(code, message) {
    var e = new Error(message || code);
    e.code = code;
    return e;
  }

  function setOffline(off) {
    if (state.offline === off) { return; }
    state.offline = off;
    var node = $("#offline");
    clear(node);
    if (off) { add(node, [el("span", { class: "dot", dataset: { sev: "critical" } }), el("span", { text: t("err.offline") })]); }
    node.hidden = !off;
  }

  function request(method, path, body) {
    if (state.mock && window.AUDITDSEC_MOCK) {
      return window.AUDITDSEC_MOCK.handle(method, path, body).then(function (data) {
        setOffline(false);
        return data;
      });
    }
    var headers = { Accept: "application/json" };
    if (state.token) { headers.Authorization = "Bearer " + state.token; }
    if (method !== "GET") {
      headers["X-Requested-With"] = "auditdsec";
      if (body) { headers["Content-Type"] = "application/json"; }
    }
    return fetch(API + path, {
      method: method, headers: headers, cache: "no-store",
      body: body ? JSON.stringify(body) : undefined
    }).then(function (res) {
      setOffline(false);
      if (res.status === 401 || res.status === 403) {
        if (path === "/login") { throw fail("bad_credentials", t("login.error")); }
        state.token = null;
        put("sessionStorage", "ads.token", null);
        if (hooks.unauthorized) { hooks.unauthorized(); }
        throw fail("unauthorized", t("err.unauthorized"));
      }
      if (res.status === 429) { throw fail("throttled", t("login.throttled")); }
      if (res.status === 204) { return null; }
      return res.text().then(function (raw) {
        var data = null;
        if (raw) { try { data = JSON.parse(raw); } catch (e) { data = null; } }
        if (!res.ok) {
          var failure = fail((data && data.error) || String(res.status), (data && data.message) || t("err.generic"));
          failure.reasons = (data && data.reasons) || [];
          throw failure;
        }
        return data;
      });
    }, function () {
      setOffline(true);
      throw fail("offline", t("err.offline"));
    });
  }

  var api = {
    login: function (login, password) { return request("POST", "/login", { login: login, password: password }); },
    setupComplete: function (p) { return request("POST", "/setup/complete", p); },
    status: function () { return request("GET", "/status"); },
    events: function (query) { return request("GET", "/events" + (query ? "?" + query : "")); },
    explain: function (kind) { return request("GET", "/explain/" + kind + "?lang=" + state.lang); },
    bans: function () { return request("GET", "/bans"); },
    suspects: function () { return request("GET", "/suspects"); },
    ban: function (payload) { return request("POST", "/bans", payload); },
    unban: function (ip) { return request("DELETE", "/bans/" + encodeURIComponent(ip)); },
    allowlist: function () { return request("GET", "/allowlist"); },
    allow: function (ip) { return request("POST", "/allowlist", { ip: ip }); },
    unallow: function (ip) { return request("DELETE", "/allowlist/" + encodeURIComponent(ip)); },
    mute: function (hours) { return request("POST", "/mute", { hours: hours }); },
    unmute: function () { return request("DELETE", "/mute"); },
    config: function () { return request("GET", "/config"); },
    telegram: function () { return request("GET", "/settings/telegram"); },
    telegramAction: function (operation, draft) { return request(operation === "save" ? "PUT" : "POST", "/settings/telegram" + (operation === "save" ? "" : "/" + operation), draft); },
    diagnostics: function () { return request("GET", "/diagnostics"); }
  };

  /* Explanations never change while the agent runs: one fetch per kind. */
  var explainCache = {};
  function explain(kind) {
    var key = state.lang + ":" + kind;
    if (explainCache[key]) { return explainCache[key]; }
    explainCache[key] = api.explain(kind).then(function (data) {
      if (!data) { return null; }
      if (data.what || data.risk || data.todo) {
        return { what: data.what || "", risk: data.risk || "", todo: data.todo || "" };
      }
      if (typeof data.text === "string") {
        var lines = data.text.split("\n").map(function (line) {
          var at = line.indexOf(": ");
          return at > 0 && at < 40 ? line.slice(at + 2) : line;
        });
        return { what: lines[0] || "", risk: lines[1] || "", todo: lines[2] || "" };
      }
      return null;
    }, function () { return null; });
    return explainCache[key];
  }
  function resetExplain() { explainCache = {}; }

  /* ---------------- status level ---------------- */

  function level(status) {
    if (!status) { return "ok"; }
    if (status.auditd && status.auditd.healthy === false) { return "down"; }
    var c = status.counters || {};
    if (c.critical_24h > 0) { return "crit"; }
    if (c.warn_24h > 0) { return "warn"; }
    return "ok";
  }
  function loadStatus() {
    return api.status().then(function (data) { state.status = data; return data; }, function () { return state.status; });
  }

  /* ---------------- toasts and dialogs ---------------- */

  function toast(message, tone) {
    var node = el("div", { class: "toast", role: "status", dataset: { tone: tone || "info" }, text: message });
    $("#toasts").appendChild(node);
    setTimeout(function () { if (node.parentNode) { node.parentNode.removeChild(node); } }, 5000);
  }

  function confirmAction(message, label, tone) {
    var dlg = $("#dialog");
    clear(dlg);
    return new Promise(function (resolve) {
      var done = false;
      function finish(ok) {
        if (done) { return; }
        done = true;
        dlg.removeEventListener("close", onClose);
        if (dlg.open) { dlg.close(); }
        resolve(ok);
      }
      function onClose() { finish(false); }
      dlg.addEventListener("close", onClose);
      var ok = el("button", {
        class: "pill " + (tone === "danger" ? "pill-danger" : "pill-solid"), type: "button",
        text: label || t("common.confirm"), onclick: function () { finish(true); }
      });
      add(dlg, el("div", { class: "dlg" }, [
        el("p", { text: message }),
        el("div", { class: "btns" }, [
          el("button", { class: "pill pill-quiet", type: "button", text: t("common.cancel"), onclick: function () { finish(false); } }),
          ok
        ])
      ]));
      if (typeof dlg.showModal === "function") { dlg.showModal(); } else { finish(window.confirm(message)); }
      ok.focus();
    });
  }

  function announceCritical(events) {
    if (!events || !events.length) { return; }
    var top = null;
    for (var i = 0; i < events.length; i++) {
      if (events[i].severity === "critical") { top = events[i]; break; }
    }
    if (!top || state.announced === top.id) { return; }
    var first = state.announced === null;
    state.announced = top.id;
    if (!first) { $("#live").textContent = t("ev.announce", { summary: top.summary || t("kind." + top.kind) }); }
  }

  window.ADS = {
    KINDS: KINDS, KIND_SEV: KIND_SEV, SEVS: SEVS, SEV_RANK: SEV_RANK, NS: NS,
    state: state, hooks: hooks, api: api, explain: explain, resetExplain: resetExplain,
    get: get, put: put, params: params,
    t: t, num: num, dateTime: dateTime, clock: clock, hourLabel: hourLabel,
    relative: relative, duration: duration, until: until, parseTime: parseTime,
    el: el, add: add, clear: clear, $: $, sv: sv, clamp: clamp, easeOut: easeOut, debounce: debounce,
    isIP: isIP, bannable: bannable, level: level, loadStatus: loadStatus,
    toast: toast, confirmAction: confirmAction, announceCritical: announceCritical, setOffline: setOffline
  };
})();
