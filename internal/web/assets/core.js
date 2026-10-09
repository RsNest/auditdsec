/* auditdsec panel: shell, data access, formatting and shared widgets.
   Plain ES5-flavoured script on purpose: no bundler, no modules, so the file
   also opens straight from disk. Values that come from the audit log are
   attacker-controlled, so they only ever reach the DOM as text nodes. */
(function () {
  "use strict";

  var API = "/api/v1";
  var SVG_NS = "http://www.w3.org/2000/svg";
  var KINDS = [
    "ssh_login_ok", "ssh_login_fail", "login_after_bruteforce", "sudo",
    "user_change", "authorized_keys_change", "persistence", "config_change",
    "log_tamper", "suspicious_exec", "auditd_stopped"
  ];
  var SEVS = ["info", "warn", "critical"];

  /* ---------------- storage, tolerant of private mode ---------------- */

  function get(store, key) {
    try { return window[store].getItem(key); } catch (e) { return null; }
  }
  function set(store, key, value) {
    try {
      if (value === null) { window[store].removeItem(key); }
      else { window[store].setItem(key, value); }
    } catch (e) { /* storage unavailable: the panel still works */ }
  }

  /* ---------------- state ---------------- */

  var params = new URLSearchParams(location.search);
  var mock = params.get("mock") === "1" || location.protocol === "file:";

  function initialLang() {
    var forced = params.get("lang");
    if (forced === "ru" || forced === "en") { return forced; }
    var saved = get("localStorage", "ads.lang");
    if (saved === "ru" || saved === "en") { return saved; }
    var nav = (navigator.language || "ru").toLowerCase();
    return nav.indexOf("ru") === 0 ? "ru" : "en";
  }

  /* ?theme= is not a setting, only a way to render one theme on demand, for
     screenshots and for a kiosk that should not follow the host machine. */
  var forcedTheme = params.get("theme");
  if (forcedTheme !== "dark" && forcedTheme !== "light") { forcedTheme = null; }

  var state = {
    mock: mock,
    lang: initialLang(),
    theme: forcedTheme || get("localStorage", "ads.theme"),
    density: get("localStorage", "ads.density"),
    token: get("sessionStorage", "ads.token"),
    status: null,
    offline: false,
    route: "",
    view: null,
    announced: null
  };

  /* ---------------- i18n ---------------- */

  var CATALOGS = window.AUDITDSEC_I18N || { ru: {}, en: {} };

  function t(key, vars) {
    var table = CATALOGS[state.lang] || {};
    var s = table[key];
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
  function dateTime(iso) {
    var d = parseTime(iso);
    if (!d) { return t("common.never"); }
    try {
      return new Intl.DateTimeFormat(state.lang, { dateStyle: "medium", timeStyle: "short" }).format(d);
    } catch (e) { return d.toISOString(); }
  }
  function clock(iso) {
    var d = parseTime(iso);
    if (!d) { return "--:--:--"; }
    try {
      return new Intl.DateTimeFormat(state.lang, { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(d);
    } catch (e) { return d.toISOString().slice(11, 19); }
  }
  function hourLabel(iso) {
    var d = parseTime(iso);
    if (!d) { return "--"; }
    try {
      return new Intl.DateTimeFormat(state.lang, { hour: "2-digit", minute: "2-digit" }).format(d);
    } catch (e) { return d.toISOString().slice(11, 16); }
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
    if (permanent || !iso) { return t("bans.permanent"); }
    return dateTime(iso);
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
        else if (key === "dataset") { for (var d in v) { node.dataset[d] = v[d]; } }
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
  function $(sel) { return document.querySelector(sel); }

  /* ---------------- icons (static markup only) ---------------- */

  var ICONS = {
    shield: '<path d="M12 21.5s7.5-3.4 7.5-9.6V5.4L12 2.6 4.5 5.4v6.5c0 6.2 7.5 9.6 7.5 9.6Z"/><path d="m8.8 12 2.4 2.4 4-4.6"/>',
    shieldAlert: '<path d="M12 21.5s7.5-3.4 7.5-9.6V5.4L12 2.6 4.5 5.4v6.5c0 6.2 7.5 9.6 7.5 9.6Z"/><path d="M12 8v4"/><path d="M12 15.5h.01"/>',
    shieldOff: '<path d="M12 21.5s7.5-3.4 7.5-9.6V5.4L12 2.6 4.5 5.4v6.5c0 6.2 7.5 9.6 7.5 9.6Z"/><path d="m4.5 4 15 16"/>',
    check: '<path d="m5 13 4 4L19 7"/>',
    checkCircle: '<circle cx="12" cy="12" r="9"/><path d="m8.5 12 2.5 2.5 4.5-5"/>',
    xCircle: '<circle cx="12" cy="12" r="9"/><path d="m9 9 6 6"/><path d="m15 9-6 6"/>',
    alertTriangle: '<path d="M10.3 4.3 2.8 17.5A2 2 0 0 0 4.5 20.5h15a2 2 0 0 0 1.7-3L13.7 4.3a2 2 0 0 0-3.4 0Z"/><path d="M12 9v4"/><path d="M12 16.5h.01"/>',
    alertOctagon: '<path d="M8.6 3h6.8L21 8.6v6.8L15.4 21H8.6L3 15.4V8.6Z"/><path d="M12 8v4.5"/><path d="M12 16h.01"/>',
    info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5"/><path d="M12 8h.01"/>',
    activity: '<path d="M22 12h-4l-3 8L9 4l-3 8H2"/>',
    dashboard: '<rect x="3" y="3" width="8" height="8" rx="1.5"/><rect x="13" y="3" width="8" height="5" rx="1.5"/><rect x="13" y="10" width="8" height="11" rx="1.5"/><rect x="3" y="13" width="8" height="8" rx="1.5"/>',
    list: '<path d="M8 6h13"/><path d="M8 12h13"/><path d="M8 18h13"/><path d="M3.5 6h.01"/><path d="M3.5 12h.01"/><path d="M3.5 18h.01"/>',
    bell: '<path d="M18 9a6 6 0 1 0-12 0c0 5-2 6-2 6h16s-2-1-2-6"/><path d="M10.4 19a2 2 0 0 0 3.2 0"/>',
    bellOff: '<path d="M18 9a6 6 0 0 0-9-5.2"/><path d="M6.1 6.5A6 6 0 0 0 6 9c0 5-2 6-2 6h13"/><path d="m3 3 18 18"/>',
    server: '<rect x="3" y="4" width="18" height="6" rx="2"/><rect x="3" y="14" width="18" height="6" rx="2"/><path d="M7 7h.01"/><path d="M7 17h.01"/>',
    login: '<path d="M14 3h5a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-5"/><path d="m10 8 4 4-4 4"/><path d="M3 12h11"/>',
    crown: '<path d="M4 18.5h16"/><path d="m4 18.5 1-9.5 4 4 3-6.5 3 6.5 4-4 1 9.5"/>',
    userX: '<circle cx="9.5" cy="8" r="3.5"/><path d="M3 20a6.5 6.5 0 0 1 13 0"/><path d="m18 6 4 4"/><path d="m22 6-4 4"/>',
    key: '<circle cx="8" cy="15.5" r="3.5"/><path d="m10.6 13 7.4-7.4"/><path d="m15.5 5.5 2.5 2.5"/><path d="m18.5 8.5 2-2"/>',
    timer: '<circle cx="12" cy="13.5" r="7.5"/><path d="M12 10v3.5l2.5 1.5"/><path d="M9 2.5h6"/>',
    sliders: '<path d="M4 7h9"/><path d="M19 7h1"/><path d="M4 17h3"/><path d="M13 17h7"/><circle cx="16" cy="7" r="2.2"/><circle cx="10" cy="17" r="2.2"/>',
    trash: '<path d="M4 7h16"/><path d="M9.5 7V4.5h5V7"/><path d="m6.5 7 1 13h9l1-13"/>',
    terminal: '<rect x="2.5" y="3.5" width="19" height="17" rx="2.5"/><path d="m6.5 9 3 3-3 3"/><path d="M12.5 15h5"/>',
    power: '<path d="M12 3v8.5"/><path d="M7.3 6.8a7 7 0 1 0 9.4 0"/>',
    clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7.5V12l3 2"/>',
    search: '<circle cx="11" cy="11" r="7"/><path d="m16.5 16.5 4 4"/>',
    refresh: '<path d="M3.5 12a8.5 8.5 0 0 1 14.4-6.1"/><path d="M18.5 3v4h-4"/><path d="M20.5 12a8.5 8.5 0 0 1-14.4 6.1"/><path d="M5.5 21v-4h4"/>',
    plus: '<path d="M12 5v14"/><path d="M5 12h14"/>',
    chevron: '<path d="m6 9 6 6 6-6"/>',
    moon: '<path d="M20 14.5A8.5 8.5 0 0 1 9.5 4 8.5 8.5 0 1 0 20 14.5Z"/>',
    sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m5 5 1.5 1.5"/><path d="M17.5 17.5 19 19"/><path d="M19 5l-1.5 1.5"/><path d="M6.5 17.5 5 19"/>',
    globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a14 14 0 0 1 0 18"/><path d="M12 3a14 14 0 0 0 0 18"/>',
    rows: '<rect x="3" y="4" width="18" height="6" rx="1.5"/><rect x="3" y="14" width="18" height="6" rx="1.5"/>',
    copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h8"/>',
    offline: '<path d="m3 3 18 18"/><path d="M8.5 16.4a5 5 0 0 1 7 0"/><path d="M5 12.8a9.5 9.5 0 0 1 3-2"/><path d="M19 12.8a9.5 9.5 0 0 0-5-2.5"/><path d="M12 20h.01"/>',
    clipboard: '<path d="M9 4.5h6V7H9z"/><path d="M8.6 5.5H6.5a2 2 0 0 0-2 2V19a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2V7.5a2 2 0 0 0-2-2h-2.1"/><path d="m9.3 13 2 2 3.9-4"/>',
    logout: '<path d="M10 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h5"/><path d="m16 8 4 4-4 4"/><path d="M20 12H9"/>',
    dot: '<circle cx="12" cy="12" r="2.5"/>'
  };

  var KIND_ICON = {
    ssh_login_ok: "login",
    ssh_login_fail: "xCircle",
    login_after_bruteforce: "shieldAlert",
    sudo: "crown",
    user_change: "userX",
    authorized_keys_change: "key",
    persistence: "timer",
    config_change: "sliders",
    log_tamper: "trash",
    suspicious_exec: "terminal",
    auditd_stopped: "power"
  };
  var SEV_ICON = { info: "info", warn: "alertTriangle", critical: "alertOctagon" };

  function icon(name, cls) {
    var svg = document.createElementNS(SVG_NS, "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "1.8");
    svg.setAttribute("stroke-linecap", "round");
    svg.setAttribute("stroke-linejoin", "round");
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("focusable", "false");
    svg.setAttribute("class", "ic" + (cls ? " " + cls : ""));
    svg.innerHTML = ICONS[name] || ICONS.dot;
    return svg;
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

  /* Mirrors the agent: an address the kernel would never let us ban usefully
     is not offered for banning in the first place. */
  function bannable(s) {
    if (!s || !isIP(s)) { return false; }
    if (isIPv4(s)) {
      var o = s.split(".").map(Number);
      if (o[0] === 0 || o[0] === 127 || o[0] === 10) { return false; }
      if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) { return false; }
      if (o[0] === 192 && o[1] === 168) { return false; }
      if (o[0] === 169 && o[1] === 254) { return false; }
      if (o[0] >= 224) { return false; }
      return true;
    }
    var low = s.toLowerCase();
    if (low === "::" || low === "::1") { return false; }
    if (/^fe[89ab]/.test(low) || /^f[cd]/.test(low) || /^ff/.test(low)) { return false; }
    return true;
  }

  /* ---------------- data access ---------------- */

  function fail(code, message) {
    var e = new Error(message || code);
    e.code = code;
    return e;
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
      method: method,
      headers: headers,
      cache: "no-store",
      body: body ? JSON.stringify(body) : undefined
    }).then(function (res) {
      setOffline(false);
      if (res.status === 401) {
        state.token = null;
        set("sessionStorage", "ads.token", null);
        gate(true);
        throw fail("unauthorized", t("err.unauthorized"));
      }
      if (res.status === 204) { return null; }
      return res.text().then(function (raw) {
        var data = null;
        if (raw) { try { data = JSON.parse(raw); } catch (e) { data = null; } }
        if (!res.ok) {
          throw fail((data && data.error) || String(res.status),
            (data && data.message) || t("err.generic"));
        }
        return data;
      });
    }, function () {
      setOffline(true);
      throw fail("offline", t("err.offline"));
    });
  }

  var api = {
    status: function () { return request("GET", "/status"); },
    events: function (query) { return request("GET", "/events" + (query ? "?" + query : "")); },
    explain: function (kind) { return request("GET", "/explain/" + kind + "?lang=" + state.lang); },
    bans: function () { return request("GET", "/bans"); },
    ban: function (payload) { return request("POST", "/bans", payload); },
    unban: function (ip) { return request("DELETE", "/bans/" + encodeURIComponent(ip)); },
    allowlist: function () { return request("GET", "/allowlist"); },
    allow: function (ip) { return request("POST", "/allowlist", { ip: ip }); },
    unallow: function (ip) { return request("DELETE", "/allowlist/" + encodeURIComponent(ip)); },
    mute: function (hours) { return request("POST", "/mute", { hours: hours }); },
    unmute: function () { return request("DELETE", "/mute"); },
    config: function () { return request("GET", "/config"); },
    diagnostics: function () { return request("GET", "/diagnostics"); }
  };

  /* Explanations never change while the agent runs, so one fetch per kind. */
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

  /* ---------------- chrome: toasts, dialogs, offline ---------------- */

  function toast(message, tone) {
    var host = $("#toasts");
    var node = el("div", { class: "toast", role: "status", dataset: { tone: tone || "info" }, text: message });
    host.appendChild(node);
    setTimeout(function () {
      if (node.parentNode) { node.parentNode.removeChild(node); }
    }, 5000);
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
        class: "btn " + (tone === "danger" ? "btn-danger" : "btn-primary"),
        type: "button", text: label || t("common.confirm"),
        onclick: function () { finish(true); }
      });
      add(dlg, el("div", { class: "dlg" }, [
        el("p", { text: message }),
        el("div", { class: "actions" }, [
          el("button", {
            class: "btn", type: "button", text: t("common.cancel"),
            onclick: function () { finish(false); }
          }),
          ok
        ])
      ]));
      if (typeof dlg.showModal === "function") { dlg.showModal(); } else { finish(window.confirm(message)); }
      ok.focus();
    });
  }

  function setOffline(off) {
    if (state.offline === off) { return; }
    state.offline = off;
    $("#offline").hidden = !off;
  }

  /* ---------------- shared widgets ---------------- */

  function severity(sev) {
    return el("span", { class: "sev", dataset: { sev: sev } }, [
      icon(SEV_ICON[sev] || "info"),
      el("span", { text: t("sev." + sev) })
    ]);
  }

  function statCard(label, value, opts) {
    opts = opts || {};
    return el("div", { class: "stat", dataset: opts.tone ? { tone: opts.tone } : null }, [
      el("div", { class: "stat-top" }, [
        el("span", { class: "label", text: label }),
        icon(opts.icon || "activity")
      ]),
      el("b", { text: value }),
      opts.note ? el("small", { text: opts.note }) : null
    ]);
  }

  function card(title, body, opts) {
    opts = opts || {};
    var head = title ? el("header", null, [
      opts.icon ? icon(opts.icon) : null,
      el("h2", { text: title }),
      opts.aside || null
    ]) : null;
    return el("section", { class: "card" }, [
      head,
      el("div", { class: "card-body" + (opts.flush ? " flush" : "") }, body)
    ]);
  }

  function empty(message) {
    return el("div", { class: "empty" }, [icon("search"), el("div", { text: message })]);
  }

  function skeleton() {
    return el("div", { class: "skel" }, [el("i"), el("i"), el("i")]);
  }

  function field(label, control) {
    var id = "f" + Math.random().toString(36).slice(2, 8);
    control.id = id;
    return el("div", { class: "field" }, [
      el("label", { class: "label", for: id, text: label }),
      control
    ]);
  }

  function select(options, value, onchange) {
    var node = el("select", { class: "select", onchange: onchange });
    options.forEach(function (opt) {
      add(node, el("option", { value: opt.value, text: opt.label, selected: opt.value === value }));
    });
    return node;
  }

  function copyButton(text) {
    var btn = el("button", {
      class: "btn-link", type: "button", text: t("common.copy"),
      onclick: function () {
        var done = function () { btn.textContent = t("common.copied"); };
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(done, function () { });
        } else { done(); }
      }
    });
    return btn;
  }

  /* ---------------- header and navigation ---------------- */

  var NAV = [
    { route: "", key: "nav.overview", icon: "dashboard" },
    { route: "events", key: "nav.events", icon: "list" },
    { route: "bans", key: "nav.bans", icon: "shieldOff" },
    { route: "policy", key: "nav.policy", icon: "bell" },
    { route: "diag", key: "nav.diag", icon: "activity", divider: true },
    { route: "setup", key: "nav.setup", icon: "clipboard" }
  ];

  function translateStatic() {
    var nodes = document.querySelectorAll("[data-i18n]");
    for (var i = 0; i < nodes.length; i++) { nodes[i].textContent = t(nodes[i].dataset.i18n); }
    var attrs = document.querySelectorAll("[data-i18n-attr]");
    for (var j = 0; j < attrs.length; j++) {
      var spec = String(attrs[j].dataset.i18nAttr).split(":");
      if (spec.length === 2) { attrs[j].setAttribute(spec[0], t(spec[1])); }
    }
  }

  function buildChrome() {
    var bar = clear($("#bar"));
    add(bar, [
      el("a", { class: "brand", href: "#/", "aria-label": t("app.title") }, [icon("shield"), el("span", { text: "auditdsec" })]),
      el("span", { class: "host", id: "host" }),
      el("span", { class: "bar-spacer" }),
      el("div", { class: "bar-tools" }, [
        el("span", { class: "dot", id: "statusdot", role: "img", "aria-label": "" }),
        el("button", {
          class: "btn btn-icon btn-ghost", type: "button", id: "themebtn",
          title: t("hdr.theme"), "aria-label": t("hdr.theme"),
          onclick: toggleTheme
        }, icon(effectiveTheme() === "dark" ? "sun" : "moon")),
        el("div", { class: "switch", role: "group", "aria-label": t("hdr.density") }, [
          densityButton("simple", "hdr.density.simple"),
          densityButton("detailed", "hdr.density.detailed")
        ]),
        el("button", {
          class: "btn btn-icon btn-ghost", type: "button",
          title: t("hdr.lang"), "aria-label": t("hdr.lang"),
          onclick: toggleLang
        }, [icon("globe"), el("span", { text: state.lang === "ru" ? "RU" : "EN" })]),
        state.token ? el("button", {
          class: "btn btn-icon btn-ghost", type: "button",
          title: t("login.logout"), "aria-label": t("login.logout"),
          onclick: function () {
            state.token = null;
            set("sessionStorage", "ads.token", null);
            buildChrome();
            gate(true);
          }
        }, icon("logout")) : null
      ])
    ]);

    var nav = clear($("#nav"));
    NAV.forEach(function (item) {
      if (item.divider) { add(nav, el("hr")); }
      add(nav, el("a", {
        href: "#/" + item.route,
        dataset: { route: item.route }
      }, [icon(item.icon), el("span", { text: t(item.key) })]));
    });
  }

  function densityButton(value, key) {
    return el("button", {
      type: "button", text: t(key),
      "aria-pressed": state.density === value ? "true" : "false",
      onclick: function () { setDensity(value); }
    });
  }

  function effectiveTheme() {
    if (state.theme === "light" || state.theme === "dark") { return state.theme; }
    try {
      return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
    } catch (e) { return "dark"; }
  }
  function applyTheme() {
    if (state.theme) { document.documentElement.setAttribute("data-theme", state.theme); }
    else { document.documentElement.removeAttribute("data-theme"); }
  }
  function toggleTheme() {
    state.theme = effectiveTheme() === "dark" ? "light" : "dark";
    set("localStorage", "ads.theme", state.theme);
    applyTheme();
    buildChrome();
    paintStatus();
  }
  function setDensity(value) {
    state.density = value;
    set("localStorage", "ads.density", value);
    document.documentElement.setAttribute("data-density", value);
    buildChrome();
    paintStatus();
  }
  function toggleLang() {
    state.lang = state.lang === "ru" ? "en" : "ru";
    set("localStorage", "ads.lang", state.lang);
    document.documentElement.lang = state.lang;
    explainCache = {};
    translateStatic();
    buildChrome();
    paintStatus();
    renderRoute(true);
  }

  /* ---------------- status level ---------------- */

  function level(status) {
    if (!status) { return "unknown"; }
    if (status.auditd && status.auditd.healthy === false) { return "crit"; }
    var c = status.counters || {};
    if (c.critical_24h > 0) { return "crit"; }
    if (c.warn_24h > 0) { return "warn"; }
    return "ok";
  }

  function paintStatus() {
    var s = state.status;
    var host = $("#host");
    clear(host);
    if (s) {
      add(host, [icon("server"), el("span", { text: s.host || t("common.unknown") })]);
      if (s.profile) { add(host, el("span", { class: "muted", text: " · " + t("hdr.profile", { profile: s.profile }) })); }
    }
    var lv = level(s);
    var dot = $("#statusdot");
    dot.dataset.level = lv === "unknown" ? "" : lv;
    var titleKey = lv === "crit" ? "status.crit.title" : lv === "warn" ? "status.warn.title" : "status.ok.title";
    dot.setAttribute("aria-label", t("hdr.status", { state: t(titleKey) }));
    document.title = (lv === "crit" ? "(!) " : "") + "auditdsec" + (s && s.host ? " · " + s.host : "");
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
    if (first) { return; }
    $("#live").textContent = t("ev.announce", { summary: top.summary || t("kind." + top.kind) });
  }

  /* ---------------- routing ---------------- */

  var routes = {};

  function currentRoute() {
    var hash = location.hash.replace(/^#\/?/, "");
    var name = hash.split("?")[0].replace(/\/$/, "");
    return routes[name] ? name : (name === "" ? "" : "");
  }

  function renderRoute(force) {
    var name = currentRoute();
    if (!force && name === state.route && state.view) { return; }
    state.route = name;
    var main = clear($("#main"));
    var links = $("#nav").querySelectorAll("a");
    for (var i = 0; i < links.length; i++) {
      if (links[i].dataset.route === name) { links[i].setAttribute("aria-current", "page"); }
      else { links[i].removeAttribute("aria-current"); }
    }
    state.view = routes[name] ? routes[name](main) : null;
    main.focus({ preventScroll: true });
  }

  /* ---------------- refresh loop ---------------- */

  function loadStatus() {
    return api.status().then(function (data) {
      state.status = data;
      paintStatus();
      return data;
    }, function () { return null; });
  }

  function tick() {
    if (document.visibilityState !== "visible") { return; }
    loadStatus().then(function () {
      if (state.view && typeof state.view.poll === "function") { state.view.poll(); }
    });
  }

  /* ---------------- access gate ---------------- */

  function gate(show) {
    $("#gate").hidden = !show;
    $("#shell").hidden = show;
    if (show) {
      var input = $("#gate-token");
      if (input) { input.focus(); }
    }
  }

  function buildGate() {
    var host = clear($("#gate"));
    var input = el("input", {
      class: "input", type: "password", id: "gate-token",
      autocomplete: "current-password", required: true, name: "token"
    });
    var error = el("p", { class: "err", hidden: true });
    var form = el("form", {
      onsubmit: function (ev) {
        ev.preventDefault();
        var value = input.value.trim();
        if (!value) { return; }
        state.token = value;
        api.status().then(function (data) {
          set("sessionStorage", "ads.token", value);
          state.status = data;
          error.hidden = true;
          gate(false);
          paintStatus();
          renderRoute(true);
        }, function () {
          state.token = null;
          error.textContent = t("login.error");
          error.hidden = false;
          input.select();
        });
      }
    }, [
      el("div", { class: "brand" }, [icon("shield"), el("span", { text: "auditdsec" })]),
      el("p", { text: t("login.sub") }),
      field(t("login.token"), input),
      error,
      el("button", { class: "btn btn-primary", type: "submit", text: t("login.submit") })
    ]);
    add(host, form);
  }

  /* ---------------- mock strip ---------------- */

  function buildMockStrip() {
    var strip = $("#strip");
    strip.hidden = false;
    clear(strip);
    var scenario = window.AUDITDSEC_MOCK ? window.AUDITDSEC_MOCK.scenario : "alert";
    var picker = select([
        { value: "quiet", label: t("mock.sc.quiet") },
        { value: "warn", label: t("mock.sc.warn") },
        { value: "alert", label: t("mock.sc.alert") },
        { value: "degraded", label: t("mock.sc.degraded") }
      ], scenario, function (ev) {
        window.AUDITDSEC_MOCK.setScenario(ev.target.value);
        state.announced = null;
        loadStatus().then(function () { renderRoute(true); });
      });
    picker.id = "mock-sc";
    add(strip, [
      el("b", { text: t("mock.label") }),
      el("label", { class: "label", for: "mock-sc", text: t("mock.scenario") }),
      picker
    ]);
  }

  /* ---------------- boot ---------------- */

  function boot() {
    if (!state.density) { state.density = "simple"; }
    document.documentElement.setAttribute("data-density", state.density);
    document.documentElement.lang = state.lang;
    applyTheme();
    translateStatic();
    buildChrome();
    buildGate();

    var offline = clear($("#offline"));
    add(offline, el("div", { class: "notice tone-crit" }, [
      icon("offline"),
      el("div", null, [
        el("h3", { text: t("offline.title") }),
        el("p", { text: t("offline.body") })
      ]),
      el("button", { class: "btn btn-sm", type: "button", text: t("common.retry"), onclick: tick })
    ]));
    $("#offline").hidden = true;

    window.addEventListener("hashchange", function () { renderRoute(false); });
    document.addEventListener("keydown", function (ev) {
      if (ev.key === "/" && !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName)) {
        var search = document.getElementById("ev-search");
        if (search) { ev.preventDefault(); search.focus(); }
      }
    });
    document.addEventListener("visibilitychange", function () {
      if (document.visibilityState === "visible") { tick(); }
    });

    loadStatus().then(function (data) {
      if (!data && !state.mock && !state.token && !state.offline) { return; }
      if (state.status && state.status.profile === "pro" && !get("localStorage", "ads.density")) {
        setDensity("detailed");
      }
      gate(false);
      renderRoute(true);
    });
    setInterval(tick, 10000);
  }

  function start() {
    if (state.mock) {
      if (window.AUDITDSEC_MOCK) {
        var preset = params.get("scenario");
        if (preset) { window.AUDITDSEC_MOCK.setScenario(preset); }
        buildMockStrip();
        boot();
        return;
      }
      var s = document.createElement("script");
      s.src = "dev/mock.js";
      s.onload = function () {
        if (window.AUDITDSEC_MOCK) {
          var want = params.get("scenario");
          if (want) { window.AUDITDSEC_MOCK.setScenario(want); }
          buildMockStrip();
        }
        boot();
      };
      s.onerror = function () { state.mock = false; boot(); };
      document.head.appendChild(s);
      return;
    }
    boot();
  }

  window.ADS = {
    KINDS: KINDS, SEVS: SEVS, state: state, api: api, explain: explain,
    t: t, num: num, dateTime: dateTime, clock: clock, hourLabel: hourLabel,
    relative: relative, duration: duration, until: until,
    el: el, add: add, clear: clear, icon: icon, KIND_ICON: KIND_ICON, SEV_ICON: SEV_ICON,
    severity: severity, statCard: statCard, card: card, empty: empty, skeleton: skeleton,
    field: field, select: select, copyButton: copyButton, toast: toast,
    confirmAction: confirmAction, isIP: isIP, bannable: bannable, level: level,
    announceCritical: announceCritical, loadStatus: loadStatus, tick: tick,
    routes: routes, renderRoute: renderRoute, SVG_NS: SVG_NS, start: start
  };
})();
