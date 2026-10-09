/* auditdsec panel: the sign-in form, the page itself and the scroll engine.
   Everything the portal hero does is a function of scroll position, so it
   plays backwards when the reader scrolls back up; entry reveals elsewhere
   fire once and stay. */
(function () {
  "use strict";

  var A = window.ADS;
  var el = A.el, add = A.add, clear = A.clear, t = A.t, $ = A.$, sv = A.sv;
  var S = A.state;

  var R = {};
  var model = { status: null, events: [], bans: [], allow: [], cfg: null, diag: null };
  var deck = null, journal = null, engine = null, poll = null, observer = null, uid = 0;

  function errText(e) {
    if (!e) { return t("err.generic"); }
    if (e.code === "allowlisted") { return t("err.allowlisted"); }
    if (e.code === "offline") { return t("err.offline"); }
    return e.message || t("err.generic");
  }
  function logo(cls) { return el("span", { class: cls || "wm" }, ["auditdsec", el("i", { text: "." })]); }
  function fieldOf(label, control) {
    var id = "f" + (++uid);
    control.id = id;
    return el("div", { class: "fld" }, [el("label", { class: "lbl", for: id, text: label }), control]);
  }
  function go(id) {
    var node = document.getElementById(id);
    if (node) { node.scrollIntoView({ behavior: S.reduced ? "auto" : "smooth", block: "start" }); }
  }
  function tone(lv) { return lv === "down" ? "crit" : lv; }

  /* ---------------- actions the deck, journal and tables share ---------------- */

  var actions = {
    ban: function (ip, duration, reason) {
      if (!A.bannable(ip)) { A.toast(t("err.private_ip"), "err"); return; }
      A.confirmAction(t("bans.form.confirm", { ip: ip, duration: t("bans.dur." + duration) }), t("bans.form.submit"), "danger")
        .then(function (ok) {
          if (!ok) { return; }
          A.api.ban({ ip: ip, duration: duration, reason: reason || "panel" }).then(function () {
            A.toast(t("bans.form.done", { ip: ip }), "ok");
            refresh();
          }, function (e) { A.toast(errText(e), "err"); });
        });
    },
    trust: function (ip) {
      A.api.allow(ip).then(function () { A.toast(t("allow.form.done", { ip: ip }), "ok"); refresh(); },
        function (e) { A.toast(errText(e), "err"); });
    },
    mute: function (hours) {
      A.api.mute(hours).then(function (res) {
        A.toast(t("policy.mute.done", { until: A.dateTime(res && res.muted_until) }), "ok");
        refresh();
      }, function (e) { A.toast(errText(e), "err"); });
    }
  };

  /* ---------------- sign-in: the form and nothing else ---------------- */

  function showGate() {
    stopAll();
    $("#shell").hidden = true;
    $("#demo").hidden = true;
    var host = clear($("#gate"));
    host.hidden = false;

    var user = el("input", { class: "in", type: "text", name: "username", autocomplete: "username", autocapitalize: "none", spellcheck: "false", required: true });
    var pass = el("input", { class: "in", type: "password", name: "password", autocomplete: "current-password", required: true });
    var err = el("p", { class: "err", role: "alert", hidden: true });
    var submit = el("button", { class: "pill pill-solid", type: "submit", text: t("login.submit") });

    var form = el("form", {
      class: "gate-form",
      onsubmit: function (ev) {
        ev.preventDefault();
        var login = user.value.trim();
        if (!login || !pass.value) { return; }
        submit.disabled = true;
        submit.textContent = t("login.busy");
        err.hidden = true;
        A.api.login(login, pass.value).then(function (res) {
          if (!res || !res.token) { throw new Error("no token"); }
          S.token = res.token;
          A.put("sessionStorage", "ads.token", res.token);
          pass.value = "";
          showShell();
        }, function (e) {
          err.textContent = e.code === "throttled" ? t("login.throttled") : e.code === "offline" ? t("err.offline") : t("login.error");
          err.hidden = false;
          submit.disabled = false;
          submit.textContent = t("login.submit");
          pass.select();
        });
      }
    }, [logo("wm"), fieldOf(t("login.user"), user), fieldOf(t("login.pass"), pass), err, submit]);

    add(host, form);
    user.focus();
  }

  function signOut() {
    S.token = null;
    A.put("sessionStorage", "ads.token", null);
    showGate();
    window.scrollTo(0, 0);
  }

  /* ---------------- the bar ---------------- */

  var SECTIONS = [["overview", "nav.overview"], ["events", "nav.events"], ["addresses", "nav.addresses"], ["alerts", "nav.alerts"], ["system", "nav.system"]];

  function setLang() {
    S.lang = S.lang === "ru" ? "en" : "ru";
    A.put("localStorage", "ads.lang", S.lang);
    document.documentElement.lang = S.lang;
    A.resetExplain();
    $("#skip").textContent = t("a11y.skip");
    rebuild();
  }
  function setTheme() {
    S.theme = S.theme === "dark" ? "light" : "dark";
    A.put("localStorage", "ads.theme", S.theme);
    document.documentElement.setAttribute("data-theme", S.theme);
    buildBar();
  }

  function buildBar() {
    var bar = clear($("#bar"));
    var sheet = $("#sheet");
    if (sheet) { sheet.parentNode.removeChild(sheet); }
    var menu = el("button", {
      class: "lnk menu-btn", type: "button", "aria-expanded": "false", text: t("nav.menu"),
      onclick: function () { toggleSheet(menu); }
    });
    add(bar, [
      el("a", { class: "wm", href: "#top", onclick: function (e) { e.preventDefault(); window.scrollTo({ top: 0, behavior: S.reduced ? "auto" : "smooth" }); } },
        ["auditdsec", el("i", { text: "." })]),
      el("nav", { class: "links", "aria-label": t("a11y.nav") }, SECTIONS.map(function (s) {
        return el("a", { class: "lnk", href: "#" + s[0], dataset: { sec: s[0] }, text: t(s[1]) });
      })),
      el("div", { class: "bar-right" }, [
        el("button", { class: "lnk hide-s", type: "button", "aria-label": t("nav.lang"), title: t("nav.lang"), text: S.lang === "ru" ? "EN" : "RU", onclick: setLang }),
        el("button", { class: "lnk hide-s", type: "button", text: S.theme === "dark" ? t("nav.theme.light") : t("nav.theme.dark"), onclick: setTheme }),
        menu,
        el("button", { class: "pill pill-sm", type: "button", text: t("nav.signout"), onclick: signOut })
      ])
    ]);
  }

  function toggleSheet(btn) {
    var open = $("#sheet");
    if (open) { open.parentNode.removeChild(open); btn.setAttribute("aria-expanded", "false"); return; }
    var close = function () { var s = $("#sheet"); if (s) { s.parentNode.removeChild(s); } btn.setAttribute("aria-expanded", "false"); };
    var items = SECTIONS.map(function (s) {
      return el("a", { class: "lnk", href: "#" + s[0], text: t(s[1]), onclick: close });
    });
    items.push(el("button", { class: "lnk", type: "button", text: S.lang === "ru" ? "English" : "Русский", onclick: function () { close(); setLang(); } }));
    items.push(el("button", { class: "lnk", type: "button", text: S.theme === "dark" ? t("nav.theme.light") : t("nav.theme.dark"), onclick: function () { close(); setTheme(); } }));
    $("#shell").appendChild(el("div", { class: "sheet", id: "sheet" }, items));
    btn.setAttribute("aria-expanded", "true");
  }

  /* ---------------- the page ---------------- */

  function section(id, cls, kids) { return el("section", { id: id, class: cls }, kids); }
  function head(label, title, extra) {
    return el("div", { class: "sec-head" }, [
      el("span", { class: "lbl rv", text: label }),
      el("h2", { class: "sec-h rv", text: title }),
      extra || null
    ]);
  }

  function buildMain() {
    var main = clear($("#main"));
    R = {};

    /* portal hero */
    R.hero = el("section", { id: "top", class: "hero" + (S.reduced ? " still" : "") },
      el("div", { class: "stage" }, [
        R.hImg = el("div", { class: "h-img", "aria-hidden": "true" }),
        R.hWash = el("div", { class: "h-wash", "aria-hidden": "true" }),
        el("div", { class: "h-veil", "aria-hidden": "true" }),
        R.dotA = el("div", { class: "h-dot a", "aria-hidden": "true" }),
        R.dotB = el("div", { class: "h-dot b", "aria-hidden": "true" }),
        R.panL = el("div", { class: "panel panel-l", "aria-hidden": "true" }),
        R.panR = el("div", { class: "panel panel-r", "aria-hidden": "true" }),
        R.title = el("h1", { class: "h-title", "aria-label": "auditdsec" }, [
          R.t1 = el("span", { text: "audit", "aria-hidden": "true" }),
          R.t2 = el("span", { "aria-hidden": "true" }, ["dsec", el("i", { text: "." })])
        ]),
        R.hTL = el("div", { class: "h-meta h-tl" }),
        R.hTR = el("div", { class: "h-meta h-tr" }),
        R.hBR = el("div", { class: "h-meta h-br", text: t("hero.scroll") + " ↓" }),
        R.hStatus = el("div", { class: "h-status" }, [
          el("span", { class: "h-meta", text: t("hero.status") }),
          R.hStatusB = el("b"),
          R.hSub = el("p", { class: "h-sub" })
        ])
      ]));

    /* statement fold */
    R.fold = section("overview", "fold", [
      R.dial = el("div", { class: "dial", "aria-hidden": "true" }),
      el("span", { class: "lbl rv", text: t("stmt.label") }),
      R.stmt = el("h2", { class: "stmt rv" }),
      R.numeral = el("div", { class: "numeral rv", "aria-hidden": "true" }),
      R.facts = el("div", { class: "facts rv" }),
      R.notes = el("div", { class: "rv" }),
      R.chart = el("div", { class: "chart-wrap rv" })
    ]);
    drawDial(R.dial);

    /* the deck */
    var deckHost = el("div", { class: "deck-wrap rv" });
    R.events = section("events", "split", [
      el("div", { class: "head" }, [
        el("span", { class: "lbl rv", text: t("deck.label") }),
        el("h2", { class: "rv", text: t("deck.title") }),
        el("p", { class: "rv", text: t("deck.lede") }),
        el("div", { class: "btns rv" }, [
          el("button", { class: "pill pill-solid", type: "button", text: t("deck.btn.journal"), onclick: function () { go("journal"); } }),
          el("button", { class: "pill", type: "button", text: t("deck.btn.critical"), onclick: function () { journal.setSeverity("critical"); go("journal"); } })
        ])
      ]),
      deckHost
    ]);
    deck = new A.feed.Deck(deckHost, actions);

    /* the journal */
    var jHost = el("div", { class: "rv" });
    R.journal = section("journal", "sec", [head(t("journal.label"), t("journal.title")), jHost]);
    journal = new A.feed.Journal(jHost, actions);

    /* the roster */
    R.roster = el("div", { class: "roster rv" });
    R.rosterSec = section("kinds", "sec", [head(t("roster.label"), t("roster.title"), el("p", { class: "callout rv", text: t("roster.hint") })), R.roster]);

    /* addresses */
    R.bansTbl = el("div");
    R.allowTbl = el("div");
    R.addr = section("addresses", "sec", [
      head(t("addr.label"), t("addr.title"), el("p", { class: "callout rv", text: t("allow.note") })),
      el("div", { class: "tbl-wrap rv" }, [el("h3", { class: "sub-h", text: t("bans.title") }), R.bansTbl, banForm()]),
      el("div", { class: "tbl-wrap rv" }, [el("h3", { class: "sub-h", text: t("addr.allow.title") }), R.allowTbl, allowForm()])
    ]);

    /* alerts */
    R.alerts = el("div", { class: "tbl-wrap rv" });
    R.alertSec = section("alerts", "sec", [head(t("alerts.label"), t("alerts.title")), R.alerts]);

    /* system */
    R.sysKv = el("div", { class: "kvs" });
    R.sysNote = el("p", { class: "callout", text: "" });
    R.checks = el("div", { class: "checks" });
    R.confPre = el("pre");
    R.system = section("system", "sec", [
      head(t("sys.label"), t("sys.title")),
      el("div", { class: "tbl-wrap rv" }, [R.sysKv, el("div", { class: "callout" }, [el("b", { text: t("diag.debug.title") + ". " }), t("diag.debug.body")])]),
      el("div", { class: "tbl-wrap rv" }, [el("h3", { class: "sub-h", text: t("setup.label") }), R.checks]),
      el("details", { class: "conf rv" }, [
        el("summary", null, [el("span", { class: "lbl", text: t("diag.config") })]),
        el("p", { class: "callout", text: t("diag.config.note") }),
        R.confPre
      ])
    ]);

    /* close */
    R.fine = el("p");
    R.close = el("footer", { id: "close", class: "close" }, [
      el("h2", { class: "rv", text: t("close.title") }),
      el("div", { class: "close-row rv" }, [
        R.fine,
        el("div", { class: "btns" }, [
          el("button", { class: "pill", type: "button", text: t("close.top"), onclick: function () { window.scrollTo({ top: 0, behavior: S.reduced ? "auto" : "smooth" }); } }),
          el("button", { class: "pill pill-solid", type: "button", text: t("nav.signout"), onclick: signOut })
        ])
      ]),
      el("div", { class: "foot" }, [el("span", { text: "MIT" }), el("span", { text: "github.com/RsNest/auditdsec" })]),
      R.bigWm = el("div", { class: "big-wm", "aria-hidden": "true" }, ["auditdsec", el("i", { text: "." })])
    ]);

    add(main, [R.hero, R.fold, R.events, R.journal, R.rosterSec, R.addr, R.alertSec, R.system, R.close]);
    setupReveals();
  }

  /* ---------------- forms ---------------- */

  function banForm() {
    var ip = el("input", { class: "in", type: "text", placeholder: t("bans.form.ip.ph"), autocomplete: "off", spellcheck: "false" });
    var reason = el("input", { class: "in", type: "text", placeholder: t("bans.form.reason.ph"), autocomplete: "off" });
    var dur = el("select", { class: "sel" }, ["24h", "1h", "30d", "permanent"].map(function (d) { return el("option", { value: d, text: t("bans.dur." + d) }); }));
    var err = el("p", { class: "err", role: "alert", hidden: true });
    function invalid(msg) { err.textContent = msg; err.hidden = false; ip.setAttribute("aria-invalid", "true"); ip.focus(); }
    return el("form", {
      onsubmit: function (ev) {
        ev.preventDefault();
        var value = ip.value.trim();
        if (!A.isIP(value)) { return invalid(t("err.bad_ip")); }
        if (!A.bannable(value)) { return invalid(t("err.private_ip")); }
        err.hidden = true; ip.removeAttribute("aria-invalid");
        A.confirmAction(t("bans.form.confirm", { ip: value, duration: t("bans.dur." + dur.value) }), t("bans.form.submit"), "danger").then(function (ok) {
          if (!ok) { return; }
          A.api.ban({ ip: value, duration: dur.value, reason: reason.value.trim() || "manual" }).then(function () {
            A.toast(t("bans.form.done", { ip: value }), "ok");
            ip.value = ""; reason.value = "";
            refresh();
          }, function (e) { invalid(errText(e)); });
        });
      }
    }, [
      el("h3", { class: "lbl", text: t("bans.form.title") }),
      el("div", { class: "form-row" }, [
        fieldOf(t("bans.form.ip"), ip), fieldOf(t("bans.form.reason"), reason), fieldOf(t("bans.form.duration"), dur),
        el("button", { class: "pill pill-danger", type: "submit", text: t("bans.form.submit") })
      ]),
      err
    ]);
  }

  function allowForm() {
    var ip = el("input", { class: "in", type: "text", placeholder: t("bans.form.ip.ph"), autocomplete: "off", spellcheck: "false" });
    var err = el("p", { class: "err", role: "alert", hidden: true });
    return el("form", {
      onsubmit: function (ev) {
        ev.preventDefault();
        var value = ip.value.trim();
        if (!A.isIP(value)) { err.textContent = t("err.bad_ip"); err.hidden = false; ip.setAttribute("aria-invalid", "true"); return; }
        err.hidden = true; ip.removeAttribute("aria-invalid");
        A.api.allow(value).then(function () {
          A.toast(t("allow.form.done", { ip: value }), "ok");
          ip.value = "";
          refresh();
        }, function (e) { err.textContent = errText(e); err.hidden = false; });
      }
    }, [
      el("div", { class: "form-row" }, [
        fieldOf(t("allow.col.ip"), ip),
        el("button", { class: "pill", type: "submit", text: t("allow.form.submit") })
      ]),
      err
    ]);
  }

  /* ---------------- painting ---------------- */

  var INK = "#EDE7DC", AMBER = "#E8913C", TEAL = "#5FB0B8", RED = "#E5604D";

  function drawField(host, hourly) {
    clear(host);
    var svg = sv("svg", { viewBox: "0 0 1000 1000", preserveAspectRatio: "xMidYMid slice" });
    var seed = 11;
    function rnd() { seed = (seed * 16807) % 2147483647; return seed / 2147483647; }

    var logs = sv("g", { transform: "rotate(-7 500 500)" });
    for (var i = 0; i < 96; i++) {
      var accent = i % 17 === 0 ? AMBER : i % 23 === 0 ? TEAL : INK;
      logs.appendChild(sv("rect", {
        x: Math.round(rnd() * 880 - 60), y: i * 11 + Math.round(rnd() * 5), width: Math.round(40 + rnd() * 280), height: 1.2,
        fill: accent, opacity: (accent === INK ? 0.05 + rnd() * 0.1 : 0.55).toFixed(2)
      }));
    }
    svg.appendChild(logs);

    [150, 250, 350, 450].forEach(function (r) {
      svg.appendChild(sv("circle", { cx: 500, cy: 500, r: r, fill: "none", stroke: INK, "stroke-opacity": 0.12, "stroke-width": 1 }));
    });

    var data = (hourly || []).slice(-24);
    var max = 1;
    data.forEach(function (h) { max = Math.max(max, (h.info || 0) + (h.warn || 0) + (h.critical || 0)); });
    data.forEach(function (h, idx) {
      var total = (h.info || 0) + (h.warn || 0) + (h.critical || 0);
      var a = (-90 + idx * 15) * Math.PI / 180;
      var inner = 130, len = total ? 24 + 290 * (total / max) : 7;
      var color = h.critical ? RED : h.warn ? AMBER : INK;
      svg.appendChild(sv("line", {
        x1: (500 + Math.cos(a) * inner).toFixed(1), y1: (500 + Math.sin(a) * inner).toFixed(1),
        x2: (500 + Math.cos(a) * (inner + len)).toFixed(1), y2: (500 + Math.sin(a) * (inner + len)).toFixed(1),
        stroke: color, "stroke-width": total ? 5 : 2, "stroke-linecap": "round", "stroke-opacity": total ? 0.95 : 0.3
      }));
      if (idx % 6 === 0) {
        svg.appendChild(sv("text", {
          x: (500 + Math.cos(a) * 482).toFixed(1), y: (500 + Math.sin(a) * 482 + 4).toFixed(1), "text-anchor": "middle",
          fill: INK, "fill-opacity": 0.4, "font-size": 13, "font-family": "ui-monospace,monospace"
        }, A.hourLabel(h.hour)));
      }
    });
    svg.appendChild(sv("circle", { cx: 500, cy: 500, r: 4, fill: TEAL }));
    host.appendChild(svg);
  }

  function drawDial(host) {
    var svg = sv("svg", { viewBox: "0 0 100 100" });
    for (var i = 0; i < 60; i++) {
      var a = i * 6 * Math.PI / 180, long = i % 5 === 0;
      svg.appendChild(sv("line", {
        x1: (50 + Math.cos(a) * (long ? 41 : 44)).toFixed(2), y1: (50 + Math.sin(a) * (long ? 41 : 44)).toFixed(2),
        x2: (50 + Math.cos(a) * 48).toFixed(2), y2: (50 + Math.sin(a) * 48).toFixed(2),
        stroke: "currentColor", "stroke-width": long ? 0.5 : 0.25, "stroke-opacity": long ? 0.9 : 0.5
      }));
    }
    svg.appendChild(sv("circle", { cx: 50, cy: 50, r: 30, fill: "none", stroke: "currentColor", "stroke-opacity": 0.35, "stroke-width": 0.25 }));
    svg.appendChild(sv("circle", { cx: 50, cy: 50, r: 16, fill: "none", stroke: "currentColor", "stroke-opacity": 0.25, "stroke-width": 0.25 }));
    svg.appendChild(sv("line", { x1: 50, y1: 50, x2: 50, y2: 6, stroke: AMBER, "stroke-width": 0.5 }));
    svg.appendChild(sv("circle", { cx: 50, cy: 6, r: 1.1, fill: AMBER }));
    host.style.color = "var(--ink)";
    host.appendChild(svg);
  }

  function paintHero() {
    var s = model.status;
    if (!s || !R.hero) { return; }
    var lv = A.level(s);
    clear(R.hTL);
    add(R.hTL, [el("i", { class: "dot", dataset: { lv: tone(lv) } }), el("span", { text: t("hero.host") + " · " + (s.host || t("common.unknown")) })]);
    R.hTR.textContent = t("hero.profile", { profile: s.profile || "—", version: s.version || "—" });
    R.hStatus.dataset.lv = tone(lv);
    R.hStatusB.textContent = t("status." + lv);
    R.hSub.textContent = t("hero.updated", { time: A.clock(new Date().toISOString()) });
    drawField(R.hImg, s.hourly);
    update();
  }

  function note(dotAttrs, strong, body) {
    return el("div", { class: "note" }, [
      el("i", { class: "dot", dataset: dotAttrs }),
      el("p", null, [strong ? el("b", { text: strong + " " }) : null, body])
    ]);
  }

  function hourlyChart(hourly) {
    var data = (hourly || []).slice(-24);
    var W = 960, H = 150, BASE = 124, TOP = 14;
    var svg = sv("svg", { viewBox: "0 0 " + W + " " + H, class: "chart", role: "img", "aria-label": t("chart.title") });
    var max = 1;
    data.forEach(function (h) { max = Math.max(max, (h.info || 0) + (h.warn || 0) + (h.critical || 0)); });
    svg.appendChild(sv("line", { x1: 0, y1: BASE + 0.5, x2: W, y2: BASE + 0.5 }));
    svg.appendChild(sv("line", { x1: 0, y1: TOP + 0.5, x2: W, y2: TOP + 0.5 }));
    svg.appendChild(sv("text", { x: 0, y: TOP - 4 }, String(max)));
    var slot = W / Math.max(1, data.length), bw = Math.min(7, slot * 0.4);
    data.forEach(function (h, i) {
      var info = h.info || 0, warn = h.warn || 0, crit = h.critical || 0, total = info + warn + crit;
      var x = i * slot + (slot - bw) / 2;
      var g = sv("g");
      g.appendChild(sv("title", null, t("chart.tip", { hour: A.hourLabel(h.hour), info: info, warn: warn, critical: crit })));
      if (!total) { g.appendChild(sv("rect", { x: x, y: BASE - 2, width: bw, height: 2, class: "b-zero" })); }
      else {
        var y = BASE;
        [["b-info", info], ["b-warn", warn], ["b-crit", crit]].forEach(function (part) {
          if (!part[1]) { return; }
          var hg = Math.max(2, (part[1] / max) * (BASE - TOP));
          y -= hg;
          g.appendChild(sv("rect", { x: x, y: y, width: bw, height: hg, class: part[0] }));
        });
      }
      if (i % 4 === 0) { g.appendChild(sv("text", { x: i * slot + slot / 2, y: BASE + 17, "text-anchor": "middle" }, A.hourLabel(h.hour))); }
      svg.appendChild(g);
    });
    return svg;
  }

  function paintFold() {
    var s = model.status;
    if (!s || !R.fold) { return; }
    var lv = A.level(s), c = s.counters || {}, ban = s.ban || {};
    var count = lv === "crit" ? c.critical_24h : c.warn_24h;
    clear(R.stmt);
    R.stmt.dataset.lv = tone(lv);
    add(R.stmt, [
      t("stmt." + lv + ".lead", { host: s.host || "", events: A.num(c.events_24h) }),
      el("mark", { text: t("stmt." + lv + ".mark", { count: A.num(count) }) })
    ]);
    R.numeral.textContent = A.num(c.events_24h).replace(/\s/g, "");

    clear(R.facts);
    [
      ["fact.events", A.num(c.events_24h), null],
      ["fact.critical", A.num(c.critical_24h), c.critical_24h > 0 ? "crit" : null],
      ["fact.warn", A.num(c.warn_24h), c.warn_24h > 0 ? "warn" : null],
      ["fact.bans", A.num(s.bans_active), null],
      ["fact.allow", A.num(s.allowlist_count), null],
      ["fact.uptime", A.duration(s.uptime_seconds), null],
      ["fact.alerts", A.num(c.alerts_sent), null]
    ].forEach(function (f) {
      add(R.facts, el("div", { dataset: { tone: f[2] } }, [el("span", { class: "lbl", text: t(f[0]) }), el("b", { text: f[1] })]));
    });

    clear(R.notes);
    if (lv === "down") {
      add(R.notes, note({ lv: "crit" }, t("note.audit") + ".", t("health.stale", { time: A.dateTime(s.auditd && s.auditd.last_write) })));
    }
    if (!ban.enforcing) {
      add(R.notes, note({ sev: "warn" }, t("enforce.title") + ".", t("enforce.body") + " " + t("enforce.howto")));
    } else if (ban.dry_run) {
      add(R.notes, note({ sev: "warn" }, t("note.bans") + ".", t("enforce.dry_run")));
    }

    clear(R.chart);
    add(R.chart, [
      el("span", { class: "lbl", text: t("chart.title") + " — " + t("chart.cap") }),
      hourlyChart(s.hourly),
      el("div", { class: "legend" }, A.SEVS.map(function (sev) {
        return el("span", { dataset: { sev: sev } }, [el("i", { class: "dot" }), el("span", { text: t("sev." + sev) })]);
      }))
    ]);
  }

  function countsByKind() {
    var s = model.status || {};
    if (s.by_kind) { return s.by_kind; }
    var out = {};
    model.events.forEach(function (e) { out[e.kind] = (out[e.kind] || 0) + 1; });
    return out;
  }

  function paintRoster() {
    if (!R.roster) { return; }
    var counts = countsByKind();
    var kinds = A.KINDS.slice().sort(function (a, b) {
      return (counts[b] || 0) - (counts[a] || 0) || A.KINDS.indexOf(a) - A.KINDS.indexOf(b);
    });
    clear(R.roster);
    kinds.forEach(function (k) {
      var n = counts[k] || 0;
      add(R.roster, el("button", {
        class: "r-row", type: "button", dataset: { sev: A.KIND_SEV[k], zero: n ? "false" : "true" },
        onclick: function () { journal.setKind(k); go("journal"); }
      }, [
        el("span", { class: "k", text: t("sev." + A.KIND_SEV[k]) }),
        el("span", { class: "n", text: t("kind." + k) }),
        el("span", { class: "c", text: A.num(n) })
      ]));
    });
  }

  function cell(label, kids) { return el("td", { dataset: { label: label } }, kids); }

  function paintBans() {
    if (!R.bansTbl) { return; }
    clear(R.bansTbl);
    if (!model.bans.length) { add(R.bansTbl, el("div", { class: "tbl-empty", text: t("bans.empty") })); return; }
    add(R.bansTbl, el("table", { class: "tbl" }, [
      el("thead", null, el("tr", null, [
        el("th", { text: t("bans.col.ip") }), el("th", { text: t("bans.col.reason") }), el("th", { text: t("bans.col.until") }),
        el("th", { text: t("bans.col.repeat") }), el("th", { text: t("bans.col.state") }), el("th", { class: "r" })
      ])),
      el("tbody", null, model.bans.map(function (b) {
        return el("tr", null, [
          el("td", { text: b.ip }),
          cell(t("bans.col.reason"), [b.reason || "—", el("small", { text: t("bans.source." + (b.source || "auto")) + " · " + A.relative(b.created) })]),
          cell(t("bans.col.until"), A.until(b.until, b.permanent)),
          cell(t("bans.col.repeat"), A.num(b.repeat_count || 1)),
          cell(t("bans.col.state"), el("span", { class: "state", dataset: b.applied ? { lv: "ok" } : { sev: "warn" } },
            [el("i", { class: "dot" }), el("span", { text: b.applied ? t("bans.state.applied") : t("bans.state.recorded") })])),
          el("td", { class: "r" }, el("button", {
            class: "pill pill-quiet pill-sm", type: "button", text: t("bans.unban"),
            onclick: function () {
              A.confirmAction(t("bans.unban.confirm", { ip: b.ip }), t("bans.unban"), "danger").then(function (ok) {
                if (!ok) { return; }
                A.api.unban(b.ip).then(function () { A.toast(t("bans.unban.done", { ip: b.ip }), "ok"); refresh(); },
                  function (e) { A.toast(errText(e), "err"); });
              });
            }
          }))
        ]);
      }))
    ]));
  }

  function paintAllow() {
    if (!R.allowTbl) { return; }
    clear(R.allowTbl);
    if (!model.allow.length) { add(R.allowTbl, el("div", { class: "tbl-empty", text: t("allow.empty") })); return; }
    add(R.allowTbl, el("table", { class: "tbl" }, [
      el("thead", null, el("tr", null, [el("th", { text: t("allow.col.ip") }), el("th", { text: t("allow.col.source") }), el("th", { text: t("allow.col.added") }), el("th", { class: "r" })])),
      el("tbody", null, model.allow.map(function (a) {
        return el("tr", null, [
          el("td", { text: a.ip }),
          cell(t("allow.col.source"), t("allow.source." + (a.source || "manual"))),
          cell(t("allow.col.added"), A.dateTime(a.added)),
          el("td", { class: "r" }, el("button", {
            class: "pill pill-quiet pill-sm", type: "button", text: t("allow.remove"),
            onclick: function () {
              A.confirmAction(t("allow.remove.confirm", { ip: a.ip }), t("allow.remove"), "danger").then(function (ok) {
                if (!ok) { return; }
                A.api.unallow(a.ip).then(function () { A.toast(t("allow.remove.done", { ip: a.ip }), "ok"); refresh(); },
                  function (e) { A.toast(errText(e), "err"); });
              });
            }
          }))
        ]);
      }))
    ]));
  }

  function kvRow(label, value) { return el("div", null, [el("span", { class: "lbl", text: label }), el("b", { text: value })]); }

  function paintAlerts() {
    if (!R.alerts) { return; }
    var s = model.status || {}, tg = (model.cfg && model.cfg.telegram) || {};
    clear(R.alerts);
    var buttons = [];
    if (s.muted_until) {
      buttons.push(el("button", {
        class: "pill pill-solid", type: "button", text: t("policy.unmute"),
        onclick: function () {
          A.api.unmute().then(function () { A.toast(t("policy.unmute.done"), "ok"); refresh(); }, function (e) { A.toast(errText(e), "err"); });
        }
      }));
    } else {
      [1, 8, 24].forEach(function (h) {
        buttons.push(el("button", { class: "pill", type: "button", text: t("policy.mute.btn", { hours: h }), onclick: function () { actions.mute(h); } }));
      });
    }
    add(R.alerts, [
      el("div", { class: "kvs" }, [
        kvRow(t("policy.min_sev"), tg.min_severity ? t("sev." + tg.min_severity) : t("common.unknown")),
        kvRow(t("policy.quiet"), tg.quiet_hours ? String(tg.quiet_hours) : t("policy.quiet.off")),
        kvRow(t("policy.dedup"), tg.dedup_window || t("common.unknown")),
        kvRow(t("policy.rate"), tg.rate_per_minute ? t("policy.rate.value", { n: tg.rate_per_minute }) : t("common.unknown")),
        kvRow(t("policy.mute"), s.muted_until ? t("policy.mute.on", { until: A.dateTime(s.muted_until) }) : t("policy.mute.off"))
      ]),
      el("p", { class: "callout", text: t("policy.readonly") + " " + t("policy.critical_note") }),
      el("div", { class: "btns" }, buttons)
    ]);
  }

  function checkRow(ok, key) {
    return el("div", { class: "check" }, [
      el("i", { class: "dot", dataset: ok ? { lv: "ok" } : { sev: "warn" } }),
      el("div", null, [el("b", { text: t("setup." + key) }), el("p", { text: ok ? t("setup.ok") : t("setup." + key + ".fix") })])
    ]);
  }

  function paintSystem() {
    if (!R.sysKv) { return; }
    var s = model.status || {}, d = model.diag || {}, c = d.counters || s.counters || {};
    clear(R.sysKv);
    [
      [t("diag.debug"), (d.debug !== undefined ? d.debug : s.debug) ? t("common.on") : t("common.off")],
      [t("diag.level"), d.log_level || s.log_level || t("common.unknown")],
      [t("diag.detector"), d.detector || t("common.none")],
      [t("diag.banner"), d.banner || (s.ban && s.ban.backend) || t("common.none")],
      [t("diag.audit_log"), d.audit_log || t("common.unknown")],
      [t("diag.offset"), d.offset !== undefined ? A.num(d.offset) : t("common.unknown")],
      [t("diag.events"), A.num(c.events_total !== undefined ? c.events_total : c.events_24h)],
      [t("diag.alerts"), A.num(c.alerts_sent)],
      [t("diag.skipped"), A.num(c.lines_skipped)],
      [t("diag.ratelimited"), A.num(c.rate_limited)]
    ].forEach(function (r) { add(R.sysKv, kvRow(r[0], r[1])); });

    var tg = (model.cfg && model.cfg.telegram) || {};
    clear(R.checks);
    add(R.checks, [
      checkRow(!(s.auditd && s.auditd.healthy === false), "auditd"),
      checkRow(!!(tg.token && tg.chat_ids && tg.chat_ids.length), "telegram"),
      checkRow(s.rules_loaded !== undefined ? !!s.rules_loaded : !!(s.counters && s.counters.events_24h > 0), "rules"),
      checkRow(!!(s.ban && s.ban.enforcing), "bans")
    ]);
    R.confPre.textContent = model.cfg ? JSON.stringify(model.cfg, null, 2) : t("common.unknown");
  }

  function paintClose() {
    var s = model.status || {};
    if (R.fine) { R.fine.textContent = t("close.fine", { version: s.version || "—", host: s.host || "—" }); }
  }

  function paintDeck(force) {
    if (!deck) { return; }
    var ranked = model.events.slice().sort(function (a, b) {
      return (A.SEV_RANK[b.severity] - A.SEV_RANK[a.severity]) || (a.time < b.time ? 1 : -1);
    });
    var pickd = [], seen = {};
    ranked.forEach(function (e) {
      var key = e.kind + "|" + (e.src_ip || e.user || "");
      if (pickd.length < 7 && !seen[key]) { seen[key] = true; pickd.push(e); }
    });
    ranked.forEach(function (e) { if (pickd.length < 7 && pickd.indexOf(e) < 0) { pickd.push(e); } });
    var sig = pickd.map(function (e) { return e.id; }).join(",");
    if (force || sig !== deck.signature()) { deck.set(pickd); }
  }

  function paintAll() {
    model.status = S.status;
    paintHero(); paintFold(); paintRoster(); paintBans(); paintAllow(); paintAlerts(); paintSystem(); paintClose();
    paintDeck(false);
  }

  /* ---------------- data ---------------- */

  function loadAll() {
    return A.loadStatus().then(function () {
      var since = new Date(Date.now() - 86400e3).toISOString();
      return Promise.all([
        A.api.events("limit=200&since=" + encodeURIComponent(since)).then(function (p) { model.events = (p && p.items) || []; A.announceCritical(model.events); }, function () { }),
        A.api.bans().then(function (v) { model.bans = v || []; }, function () { }),
        A.api.allowlist().then(function (v) { model.allow = v || []; }, function () { }),
        A.api.config().then(function (v) { model.cfg = v; }, function () { }),
        A.api.diagnostics().then(function (v) { model.diag = v; }, function () { })
      ]);
    }).then(paintAll);
  }

  function refresh() {
    return loadAll().then(function () { if (journal) { journal.refresh(); } });
  }

  function startPoll() {
    stopPoll();
    poll = setInterval(function () { if (document.visibilityState === "visible") { refresh(); } }, 10000);
  }
  function stopPoll() { if (poll) { clearInterval(poll); poll = null; } }

  /* ---------------- scroll engine ---------------- */

  function update() {
    if (!R.hero) { return; }
    var y = window.scrollY, vh = window.innerHeight, vw = window.innerWidth;

    if (!S.reduced) {
      var range = R.hero.offsetHeight - vh;
      var p = A.clamp(range > 0 ? y / range : 1, 0, 1);
      var q = A.easeOut(A.clamp(p / 0.7, 0, 1));
      R.panL.style.transform = "translate3d(" + (-q * 104) + "%,0,0)";
      R.panR.style.transform = "translate3d(" + q * 104 + "%,0,0)";
      R.hImg.style.transform = "scale(" + (1.14 - 0.14 * q) + ")";
      R.hWash.style.opacity = String(0.34 * q);
      var dx = q * vw * 0.36, dy = q * vh * 0.32;
      R.dotA.style.transform = "translate3d(" + -dx + "px," + -dy + "px,0)";
      R.dotB.style.transform = "translate3d(" + dx + "px," + dy + "px,0)";
      /* The title opens: it grows and tightens at the same time, and its
         halves part by about half their own width. */
      var g = A.easeOut(p);
      R.title.style.transform = "scale(" + (1 + 0.28 * g) + ")";
      R.title.style.letterSpacing = (-0.02 - 0.05 * g) + "em";
      R.t1.style.transform = "translate3d(" + -0.5 * R.t1.offsetWidth * g + "px,0,0)";
      R.t2.style.transform = "translate3d(" + 0.5 * R.t2.offsetWidth * g + "px,0,0)";
      var so = A.clamp((p - 0.45) / 0.3, 0, 1);
      R.hStatus.style.opacity = String(so);
      R.hStatus.style.transform = "translateY(" + (1 - so) * 16 + "px)";
      R.hBR.style.opacity = String(1 - A.clamp(p * 4, 0, 1));
    }

    if (R.dial && R.fold) {
      var r = R.fold.getBoundingClientRect();
      var prog = (vh - r.top) / (vh + r.height);
      R.dial.style.transform = "translate3d(0," + (prog - 0.5) * -120 + "px,0) rotate(" + prog * 140 + "deg)";
    }

    var current = "";
    [["overview", "overview"], ["events", "events"], ["journal", "events"], ["kinds", "events"], ["addresses", "addresses"], ["alerts", "alerts"], ["system", "system"]].forEach(function (pair) {
      var node = document.getElementById(pair[0]);
      if (node && node.getBoundingClientRect().top <= vh * 0.4) { current = pair[1]; }
    });
    Array.prototype.forEach.call(document.querySelectorAll(".bar .lnk[data-sec]"), function (a) {
      if (a.dataset.sec === current) { a.setAttribute("aria-current", "true"); } else { a.removeAttribute("aria-current"); }
    });
  }

  /* The closing wordmark spans the page exactly, whatever the font ends up
     measuring: it is sized from its own width, then translated down so the
     page edge crops it. */
  function fitWordmark() {
    var w = R.bigWm;
    if (!w || !R.close) { return; }
    var target = R.close.clientWidth;
    w.style.fontSize = "100px";
    var natural = w.scrollWidth;
    if (natural > 0 && target > 0) { w.style.fontSize = (100 * target / natural * 0.985).toFixed(1) + "px"; }
  }

  function startEngine() {
    stopEngine();
    var ticking = false;
    function onScroll() {
      if (ticking) { return; }
      ticking = true;
      requestAnimationFrame(function () { ticking = false; fitWordmark(); update(); });
    }
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onScroll);
    engine = function () {
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("resize", onScroll);
    };
    fitWordmark();
    if (document.fonts && document.fonts.ready) { document.fonts.ready.then(function () { fitWordmark(); update(); }); }
    update();
  }
  function stopEngine() { if (engine) { engine(); engine = null; } }

  function setupReveals() {
    if (observer) { observer.disconnect(); observer = null; }
    var root = document.documentElement;
    if (S.reduced || !("IntersectionObserver" in window)) { root.classList.remove("reveal-on"); return; }
    root.classList.add("reveal-on");
    observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (en.isIntersecting) { en.target.classList.add("shown"); observer.unobserve(en.target); }
      });
    }, { rootMargin: "0px 0px -8% 0px" });
    Array.prototype.forEach.call(document.querySelectorAll(".rv"), function (n) { observer.observe(n); });
  }

  /* ---------------- lifecycle ---------------- */

  function stopAll() {
    stopPoll(); stopEngine();
    if (observer) { observer.disconnect(); observer = null; }
    document.documentElement.classList.remove("reveal-on");
    var sheet = $("#sheet");
    if (sheet) { sheet.parentNode.removeChild(sheet); }
    clear($("#main"));
    R = {}; deck = null; journal = null;
    model = { status: null, events: [], bans: [], allow: [], cfg: null, diag: null };
    S.status = null;
  }

  function rebuild() {
    stopEngine();
    buildBar(); buildMain(); setupDemo();
    paintAll();
    journal.reload();
    startEngine();
  }

  function setupDemo() {
    var host = $("#demo");
    if (!S.mock || !window.AUDITDSEC_MOCK) { host.hidden = true; return; }
    clear(host);
    var sel = el("select", { class: "sel", "aria-label": t("mock.scenario"), onchange: function (e) {
      window.AUDITDSEC_MOCK.setScenario(e.target.value);
      S.announced = null;
      loadAll().then(function () { paintDeck(true); journal.reload(); });
    } }, [["quiet", "mock.sc.quiet"], ["warn", "mock.sc.warn"], ["alert", "mock.sc.alert"], ["degraded", "mock.sc.degraded"]].map(function (o) {
      return el("option", { value: o[0], text: t(o[1]), selected: o[0] === window.AUDITDSEC_MOCK.scenario });
    }));
    add(host, [el("span", { class: "lbl", text: t("mock.label") }), sel]);
    host.hidden = false;
  }

  function showShell() {
    stopAll();
    $("#gate").hidden = true;
    clear($("#gate"));
    $("#shell").hidden = false;
    A.hooks.unauthorized = showGate;
    window.scrollTo(0, 0);
    buildBar(); buildMain(); setupDemo();
    startEngine();
    loadAll().then(function () { journal.reload(); startPoll(); });
  }

  function boot() {
    document.documentElement.lang = S.lang;
    document.documentElement.setAttribute("data-theme", S.theme);
    $("#skip").textContent = t("a11y.skip");
    A.hooks.unauthorized = showGate;
    if (S.token) {
      A.api.status().then(function (st) { S.status = st; showShell(); }, function () { showGate(); });
    } else { showGate(); }
  }

  function start() {
    if (S.mock && !window.AUDITDSEC_MOCK) {
      var s = document.createElement("script");
      s.src = "dev/mock.js";
      s.onload = function () {
        var want = A.params.get("scenario");
        if (want && window.AUDITDSEC_MOCK) { window.AUDITDSEC_MOCK.setScenario(want); }
        boot();
      };
      s.onerror = function () { S.mock = false; boot(); };
      document.head.appendChild(s);
      return;
    }
    if (S.mock && window.AUDITDSEC_MOCK) {
      var preset = A.params.get("scenario");
      if (preset) { window.AUDITDSEC_MOCK.setScenario(preset); }
    }
    boot();
  }

  start();
})();
