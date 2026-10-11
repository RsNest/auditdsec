/* auditdsec workspace: hash routes, operational overview and existing actions.
   Pages keep their forms and filters when navigating; log values are text only. */
(function () {
  "use strict";

  var A = window.ADS;
  var el = A.el, add = A.add, clear = A.clear, t = A.t, $ = A.$, sv = A.sv;
  var S = A.state;

  var R = {};
  var model = { status: null, events: [], incidents: [], exceptions: [], bans: [], allow: [], suspects: null, cfg: null, diag: null };
  var pendingBans = Object.create(null), modelRevision = 0;
  var journal = null, poll = null, uid = 0, route = "overview", incidentFilter = "open";

  function errText(e) {
    if (!e) { return t("err.generic"); }
    if (e.code === "allowlisted") { return t("err.allowlisted"); }
    if (e.code === "offline") { return t("err.offline"); }
    if (e.code === "firewall") { return t("bans.form.failed"); }
    return e.message || t("err.generic");
  }
  function logo(cls) { return el("span", { class: cls || "wm" }, ["auditdsec", el("i", { text: "." })]); }
  function fieldOf(label, control) {
    var id = "f" + (++uid);
    control.id = id;
    return el("div", { class: "fld" }, [el("label", { class: "lbl", for: id, text: label }), control]);
  }
  function go(id) {
    var aliases = { top: "overview", journal: "events", kinds: "events", access: "settings", alerts: "settings" };
    var target = aliases[id] || id;
    if (location.hash === "#" + target) { navigate(); }
    else { location.hash = target; }
    if (id === "access" || id === "alerts") { setSettingsTab(id); }
  }

  function tone(lv) { return lv === "down" ? "crit" : lv; }

  /* ---------------- actions the deck, journal and tables share ---------------- */

  var actions = {
    isBlocked: function (ip) { return A.feed.blocked(ip, model.bans); },
    canBan: function (ip) { return !pendingBans[ip] && !actions.isBlocked(ip) && !A.feed.protectedIP(ip, model.allow); },
    ban: function (ip, duration, reason) {
      if (!A.bannable(ip)) { A.toast(t("err.private_ip"), "err"); return Promise.resolve(false); }
      if (!actions.canBan(ip)) { return Promise.resolve(false); }
      var session = S.token;
      pendingBans[ip] = session;
      syncBanButtons();
      return A.confirmAction(t("bans.form.confirm", { ip: ip, duration: t("bans.dur." + duration) }), t("bans.form.submit"), "danger")
        .then(function (ok) {
          if (!ok || S.token !== session) { return false; }
          return A.api.ban({ ip: ip, duration: duration, reason: reason || "panel" }).then(function (b) {
            if (S.token !== session) { return false; }
            modelRevision++;
            model.bans = model.bans.filter(function (old) { return old.ip !== b.ip; }).concat([b]);
            // Repaint before polling: ordinary cards for a blocked IP disappear now.
            paintAll();

            A.toast(t(b.applied ? "bans.form.done" : "bans.form.recorded", { ip: b.ip }), b.applied ? "ok" : "warn");
            refresh();
            return !!b.applied;
          });
        }).catch(function (e) {
          if (S.token === session) { A.toast(errText(e), "err"); refresh(); }
          return false;
        }).finally(function () {
          if (pendingBans[ip] === session) { delete pendingBans[ip]; }
          syncBanButtons();
        });
    },
    trust: function (ip) {
      A.api.allow(ip).then(function (a) {
        modelRevision++;
        model.allow = model.allow.filter(function (old) { return old.ip !== a.ip; }).concat([a]);
        paintAll(); A.toast(t("allow.form.done", { ip: ip }), "ok"); refresh();
      },
        function (e) { A.toast(errText(e), "err"); });
    },
    exception: function (ev) { R.excForm.prefill(ev); go("exceptions"); },
    mute: function (hours) {
      A.api.mute(hours).then(function (res) {
        A.toast(t("policy.mute.done", { until: A.dateTime(res && res.muted_until) }), "ok");
        refresh();
      }, function (e) { A.toast(errText(e), "err"); });
    }
  };

  function syncBanButtons() {
    Array.prototype.forEach.call(document.querySelectorAll("[data-ban-ip]"), function (b) {
      var ip = b.dataset.banIp;
      b.disabled = !actions.canBan(ip);
      b.textContent = pendingBans[ip] ? t("bans.form.busy") :
        actions.isBlocked(ip) ? t("bans.state.applied") : t("ev.act.ban", { ip: ip });
    });
  }

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
          if (res.setup) {
            /* admin / admin: this is a setup session. It reaches the setup
               screen and nothing else (the server enforces that), and it is
               kept in memory only: a reload starts from the sign-in again. */
            S.token = res.token;
            pass.value = "";
            showSetup();
            return;
          }
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

  /* ---------------- first sign-in: replace admin / admin ---------------- */

  var COMMON = { admin: 1, password: 1, qwerty: 1, "12345678": 1 };

  function passwordFacts(pw, login) {
    var len = Array.from(pw).length;
    var lower = pw !== pw.toUpperCase();
    var upper = pw !== pw.toLowerCase();
    var low = pw.toLowerCase();
    return {
      len: len >= 8 && len <= 128, lower: lower, upper: upper,
      notDefault: low !== "admin" && !COMMON[low] && low !== String(login || "").toLowerCase(),
      digit: /[0-9]/.test(pw), symbol: /[^\p{L}\p{N}]/u.test(pw), length: len
    };
  }
  /* 0 below the minimum, 1 the minimum but weak, 2 better, 3 strong. The
     minimum is a floor, not a proof of strength, and the text says so. */
  function strengthOf(f) {
    if (!(f.len && f.lower && f.upper && f.notDefault)) { return 0; }
    var extra = (f.length >= 12 ? 1 : 0) + (f.digit ? 1 : 0) + (f.symbol ? 1 : 0) + (f.length >= 16 ? 1 : 0);
    return extra <= 1 ? 1 : extra === 2 ? 2 : 3;
  }

  function showSetup() {
    stopAll();
    $("#shell").hidden = true;
    var host = clear($("#gate"));
    host.hidden = false;

    var user = el("input", { class: "in", type: "text", name: "username", value: "admin", autocomplete: "username", autocapitalize: "none", spellcheck: "false", maxlength: "64", required: true });
    var keep = el("input", { type: "checkbox", id: "keepadmin" });
    var keepRow = el("label", { class: "tick", for: "keepadmin", hidden: true }, [keep, el("span", { text: t("setup.keep") })]);
    var pass = el("input", { class: "in", type: "password", name: "new-password", autocomplete: "new-password", maxlength: "128", required: true });
    var again = el("input", { class: "in", type: "password", name: "new-password-again", autocomplete: "new-password", maxlength: "128", required: true });
    var toggle = el("button", { class: "lnk", type: "button", "aria-pressed": "false", text: t("setup.show") });
    var rules = el("ul", { class: "rules", "aria-live": "polite" });
    var meter = el("p", { class: "hint", role: "status" });
    var err = el("p", { class: "err", role: "alert", hidden: true });
    var submit = el("button", { class: "pill pill-solid", type: "submit", text: t("setup.submit") });

    toggle.onclick = function () {
      var shown = pass.type === "password";
      pass.type = again.type = shown ? "text" : "password";
      toggle.textContent = shown ? t("setup.hide") : t("setup.show");
      toggle.setAttribute("aria-pressed", shown ? "true" : "false");
    };

    function evaluate() {
      var login = user.value.trim();
      var f = passwordFacts(pass.value, login);
      keepRow.hidden = login.toLowerCase() !== "admin";
      if (keepRow.hidden) { keep.checked = false; }
      var list = [
        [f.len, t("setup.rule.len")], [f.lower, t("setup.rule.lower")], [f.upper, t("setup.rule.upper")],
        [f.notDefault, t("setup.rule.notdefault")], [pass.value !== "" && pass.value === again.value, t("setup.rule.same")]
      ];
      clear(rules);
      list.forEach(function (r) { add(rules, el("li", { class: r[0] ? "yes" : "no", text: (r[0] ? "✓ " : "• ") + r[1] })); });
      var lvl = pass.value ? strengthOf(f) : -1;
      meter.textContent = lvl < 0 ? "" : t("setup.strength." + lvl);
      return list.every(function (r) { return r[0]; });
    }
    [user, pass, again].forEach(function (n) { n.addEventListener("input", evaluate); });

    var form = el("form", {
      class: "gate-form",
      onsubmit: function (ev) {
        ev.preventDefault();
        err.hidden = true;
        var login = user.value.trim();
        if (!evaluate() || !login) { err.textContent = t("setup.fix"); err.hidden = false; return; }
        if (login.toLowerCase() === "admin" && !keep.checked) { err.textContent = t("reason.login_admin_unconfirmed"); err.hidden = false; return; }
        submit.disabled = true;
        A.api.setupComplete({ login: login, password: pass.value, password_confirm: again.value, keep_admin_confirmed: keep.checked }).then(function () {
          S.token = null;
          A.put("sessionStorage", "ads.token", null);
          pass.value = again.value = "";
          showGate();
          var f0 = $("#gate").firstChild;
          f0.insertBefore(el("p", { class: "ok", role: "status", text: t("setup.done") }), f0.firstChild.nextSibling);
        }, function (e) {
          var why = (e.reasons || []).map(function (r) { return t("reason." + r); }).filter(Boolean);
          err.textContent = e.code === "throttled" ? t("login.throttled") : e.code === "offline" ? t("err.offline") :
            why.length ? why.join(" ") : e.code === "unauthorized" ? t("setup.expired") : t("setup.failed");
          err.hidden = false;
          submit.disabled = false;
        });
      }
    }, [logo("wm"), el("p", { class: "hint", text: t("setup.intro") }),
      fieldOf(t("setup.login"), user), keepRow,
      fieldOf(t("setup.pass"), pass), fieldOf(t("setup.again"), again),
      toggle, rules, meter, err, submit]);

    add(host, form);
    evaluate();
    user.select();
    user.focus();
  }

  function signOut() {
    A.api.logout().catch(function () {});
    A.Updates.reset();
    S.token = null;
    A.put("sessionStorage", "ads.token", null);
    showGate();
    window.scrollTo(0, 0);
  }

  /* ---------------- workspace and navigation ---------------- */

  var SECTIONS = [["overview", "nav.overview", "grid"], ["events", "nav.events", "list"],
    ["incidents", "nav.incidents", "layers"], ["addresses", "ui.blocks", "shield"],
    ["exceptions", "nav.exceptions", "filter"], ["system", "ui.diagnostics", "activity"],
    ["settings", "ui.settings", "settings"], ["updates", "ui.updates", "download"]];

  function icon(name) {
    var paths = {
      grid: ["M3 3h7v7H3z", "M14 3h7v7h-7z", "M3 14h7v7H3z", "M14 14h7v7h-7z"],
      list: ["M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"],
      layers: ["m12 3 10 5-10 5L2 8z", "m2 12 10 5 10-5M2 16l10 5 10-5"],
      shield: ["M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z", "m8 12 3 3 5-6"],
      filter: ["M3 4h18l-7 8v7l-4 2v-9Z"],
      activity: ["M2 12h5l3-8 4 16 3-8h5"],
      settings: ["M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8Z", "M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M5 19l2-2M17 7l2-2"],
      download: ["M12 3v12m-5-5 5 5 5-5", "M4 16v5h16v-5"],
      menu: ["M4 6h16M4 12h16M4 18h16"], refresh: ["M20 7v5h-5M4 17v-5h5", "M6 7a7 7 0 0 1 12-2l2 2M18 17a7 7 0 0 1-12 2l-2-2"]
    };
    var node = sv("svg", { viewBox: "0 0 24 24", class: "icon", fill: "none", stroke: "currentColor", "stroke-width": 1.6, "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true" });
    (paths[name] || paths.grid).forEach(function (d) { node.appendChild(sv("path", { d: d })); });
    return node;
  }
  function setLang() {
    S.lang = S.lang === "ru" ? "en" : "ru";
    A.put("localStorage", "ads.lang", S.lang); document.documentElement.lang = S.lang;
    A.resetExplain(); $("#skip").textContent = t("a11y.skip"); rebuild();
  }
  function setTheme() {
    S.theme = S.theme === "dark" ? "light" : "dark";
    A.put("localStorage", "ads.theme", S.theme);
    document.documentElement.setAttribute("data-theme", S.theme); buildBar(); navigate(false);
  }
  function syncNav() {
    var open = $("#shell").classList.contains("nav-open");
    $("#sidebar").inert = window.matchMedia("(max-width: 900px)").matches && !open;
    var menu = $(".menu-btn"); if (menu) { menu.setAttribute("aria-expanded", String(open)); }
  }
  function buildBar() {
    var side = clear($("#sidebar")), bar = clear($("#bar"));
    add(side, [el("a", { class: "brand", href: "#overview" }, [el("span", { class: "brand-icon" }, icon("shield")), logo()]),
      el("p", { class: "nav-label", text: t("ui.workspace") }),
      el("nav", { class: "side-links", "aria-label": t("a11y.nav") }, SECTIONS.map(function (s) {
        if (s[0] === "updates") {
          var b = A.Updates.button("side-link"); add(b, icon(s[2])); b.dataset.sec = "updates"; return b;
        }
        return el("a", { class: "side-link", href: "#" + s[0], dataset: { sec: s[0] } }, [icon(s[2]), el("span", { text: t(s[1]) })]);
      })),
      el("div", { class: "sidebar-foot" }, [R.sideHost = el("span", { class: "mono" }), el("a", { href: "https://github.com/RsNest/auditdsec", target: "_blank", rel: "noopener noreferrer", text: "GitHub ↗" })])]);
    var account = el("details", { class: "account-menu" }, [el("summary", { "aria-label": t("ui.account") }, [el("span", { class: "avatar", text: "A" }), el("span", { class: "account-label", text: t("ui.account") }), "⌄"]),
      el("div", { class: "account-options" }, [
        el("button", { type: "button", text: S.lang === "ru" ? "English" : "Русский", onclick: setLang }),
        el("button", { type: "button", text: S.theme === "dark" ? t("nav.theme.light") : t("nav.theme.dark"), onclick: setTheme }),
        el("button", { type: "button", text: t("nav.signout"), onclick: signOut })])]);
    add(bar, [el("div", { class: "bar-title" }, [el("button", { class: "menu-btn icon-btn", type: "button", "aria-label": t("nav.menu"), "aria-controls": "sidebar", "aria-expanded": "false", onclick: function (e) {
      $("#shell").classList.toggle("nav-open"); syncNav();
    } }, icon("menu")), R.pageTitle = el("span", { class: "bar-page" })]),
      el("div", { class: "bar-right" }, [R.headerStatus = el("span", { class: "health-badge" }), account])]);
    syncNav(); paintHero();
  }
  function navigate(focus) {
    var aliases = { top: "overview", journal: "events", kinds: "events", access: "settings", alerts: "settings" };
    var id = location.hash.slice(1) || "overview";
    if (id === "alerts" || id === "access") { setSettingsTab(id); }
    id = aliases[id] || id;
    route = SECTIONS.some(function (s) { return s[0] === id; }) ? id : "overview";
    Array.prototype.forEach.call($("#main").children, function (n) { n.hidden = n.id !== route; });
    Array.prototype.forEach.call(document.querySelectorAll("[data-sec]"), function (n) {
      if (n.dataset.sec === route) { n.setAttribute("aria-current", "page"); } else { n.removeAttribute("aria-current"); }
    });
    var label = SECTIONS.filter(function (s) { return s[0] === route; })[0][1];
    if (R.pageTitle) { R.pageTitle.textContent = t(label); }
    document.title = t(label) + " · auditdsec";
    $("#shell").classList.remove("nav-open");
    syncNav();
    if (focus !== false) { window.scrollTo(0, 0); $("#main").focus({ preventScroll: true }); }
    if (route === "events" && journal) { journal.refresh(); }
  }
  window.addEventListener("hashchange", function () { if (!$("#shell").hidden) { navigate(); } });
  window.addEventListener("resize", syncNav);
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && $("#shell").classList.contains("nav-open")) { $("#shell").classList.remove("nav-open"); syncNav(); var m = $(".menu-btn"); if (m) { m.focus(); } }
  });
  document.addEventListener("click", function (e) {
    if ($("#shell").classList.contains("nav-open") && !e.target.closest("#sidebar, .menu-btn")) {
      $("#shell").classList.remove("nav-open"); syncNav();
    }
    var account = $(".account-menu"); if (account && !account.contains(e.target)) { account.open = false; }
  });
  A.navigate = go;
  A.icon = icon;

  function section(id, cls, kids) { return el("section", { id: id, class: "page " + cls, hidden: true }, kids); }
  function head(label, title, extra) {
    return el("div", { class: "page-head" }, [el("div", null, [el("span", { class: "eyebrow", text: label }), el("h1", { text: title })]), extra || null]);
  }
  function card(title, kids, action) {
    return el("div", { class: "card" }, [el("div", { class: "card-head" }, [el("h2", { text: title }), action || null]), el("div", { class: "card-body" }, kids)]);
  }
  function setSettingsTab(id) {
    Array.prototype.forEach.call(document.querySelectorAll(".settings-pane"), function (n) { n.hidden = n.id !== id; });
    Array.prototype.forEach.call(document.querySelectorAll(".settings-tab"), function (n) { n.setAttribute("aria-selected", String(n.dataset.tab === id)); });
  }
  function buildMain() {
    var main = clear($("#main"));
    var barRefs = { sideHost: R.sideHost, pageTitle: R.pageTitle, headerStatus: R.headerStatus };
    R = barRefs;
    R.stmt = el("p", { class: "overview-sub" }); R.facts = el("div", { class: "metrics" });
    R.notes = el("div", { class: "overview-notices" }); R.chart = el("div", { class: "chart-wrap" });
    R.recent = el("div", { class: "recent-events" }); R.health = el("div", { class: "health-list" });
    R.fold = section("overview", "", [head(t("ui.workspace"), t("ui.overview.title"), el("button", { class: "pill pill-quiet", type: "button", onclick: function () { go("events"); }, text: t("ui.all_events") })),
      R.stmt, R.notes, R.facts, el("div", { class: "overview-grid" }, [
        card(t("chart.title"), R.chart), card(t("ui.health"), R.health),
        card(t("ui.latest_events"), R.recent, el("button", { class: "lnk", type: "button", text: t("ui.all_events") + " →", onclick: function () { go("events"); } }))])]);
    var jHost = el("div", { class: "card journal-card" });
    R.roster = el("div", { class: "roster" });
    R.journal = section("events", "", [head(t("journal.label"), t("journal.title")), jHost,
      el("details", { class: "card roster-card" }, [el("summary", { text: t("roster.title") }), R.roster])]);
    journal = new A.feed.Journal(jHost, actions);
    R.incTbl = el("div", { class: "card table-card" });
    var incFilter = el("select", { class: "sel", onchange: function (e) { incidentFilter = e.target.value; modelRevision++; refresh(); } }, ["open", "all", "new", "acknowledged", "resolved"].map(function (s) {
      return el("option", { value: s, selected: s === incidentFilter, text: t("inc.state." + s) });
    }));
    R.incSec = section("incidents", "", [head(t("inc.label"), t("inc.title"), fieldOf(t("inc.filter"), incFilter)), el("p", { class: "page-lede", text: t("inc.lede") }), R.incTbl]);
    R.excTbl = el("div", { class: "card table-card" }); R.excForm = excForm();
    R.excSec = section("exceptions", "", [head(t("exc.label"), t("exc.title")), el("p", { class: "page-lede", text: t("exc.lede") }),
      R.excTbl, card(t("exc.form.title"), R.excForm.node)]);
    R.bansTbl = el("div"); R.allowTbl = el("div"); R.suspectsTbl = el("div"); R.suspectsNote = el("p", { class: "callout" });
    R.addr = section("addresses", "", [head(t("addr.label"), t("ui.blocks")), el("p", { class: "page-lede", text: t("allow.note") }),
      card(t("suspects.title"), [R.suspectsNote, R.suspectsTbl]), card(t("bans.title"), [R.bansTbl, el("details", { class: "form-disclosure" }, [el("summary", { text: t("bans.form.title") }), banForm()])]),
      card(t("addr.allow.title"), [R.allowTbl, allowForm()])]);
    R.accessHost = el("div", { class: "card-body" });
    var accessPane = el("div", { id: "access", class: "settings-pane card", role: "tabpanel" }, R.accessHost);
    A.Access.mount(R.accessHost);
    R.alerts = el("div", { class: "card card-body" }); R.telegram = el("div", { class: "card card-body" });
    var alertsPane = el("div", { id: "alerts", class: "settings-pane", role: "tabpanel", hidden: true }, [R.telegram, R.alerts]);
    var tabs = el("div", { class: "settings-nav", role: "tablist", "aria-label": t("ui.settings") }, [["access", "nav.access"], ["alerts", "nav.alerts"]].map(function (p) {
      return el("button", { class: "settings-tab", type: "button", role: "tab", dataset: { tab: p[0] }, "aria-controls": p[0], "aria-selected": String(p[0] === "access"), text: t(p[1]), onclick: function () { setSettingsTab(p[0]); } });
    }));
    R.settings = section("settings", "", [head(t("ui.workspace"), t("ui.settings")), el("div", { class: "settings-layout" }, [tabs, el("div", { class: "settings-content" }, [accessPane, alertsPane])])]);
    R.sysKv = el("div", { class: "kvs" }); R.checks = el("div", { class: "checks" }); R.confPre = el("pre");
    R.system = section("system", "", [head(t("sys.label"), t("ui.diagnostics")),
      card(t("setup.label"), R.checks), card(t("ui.runtime"), [R.sysKv, el("p", { class: "callout", text: t("diag.debug.body") })]),
      el("details", { class: "conf card" }, [el("summary", { text: t("diag.config") }), el("div", { class: "card-body" }, [el("p", { class: "callout", text: t("diag.config.note") }), R.confPre])])]);
    R.updatesHost = el("div");
    R.updates = section("updates", "updates-page", [head(t("ui.workspace"), t("ui.updates")), R.updatesHost]);
    A.Updates.mount(R.updatesHost);
    add(main, [R.fold, R.journal, R.incSec, R.addr, R.excSec, R.system, R.settings, R.updates]);
    navigate(false);
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
        var button = ev.target.querySelector("[type=submit]");
        if (button.disabled) { return; }
        button.disabled = true;
        actions.ban(value, dur.value, reason.value.trim() || "manual").then(function (applied) {
          if (applied) { ip.value = ""; reason.value = ""; }
        }).finally(function () { button.disabled = false; });
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

  function paintHero() {
    var s = model.status || S.status;
    if (!s) { return; }
    S.version = s.version;
    if (R.sideHost) { R.sideHost.textContent = s.host || t("common.unknown"); }
    if (R.headerStatus) {
      clear(R.headerStatus);
      add(R.headerStatus, [el("i", { class: "dot", dataset: { lv: tone(A.level(s)) } }), el("span", { text: t("status." + A.level(s)) })]);
    }
  }

  function note(dotAttrs, strong, body) {
    return el("div", { class: "note" }, [
      el("i", { class: "dot", dataset: dotAttrs }),
      el("p", null, [strong ? el("b", { text: strong + " " }) : null, body])
    ]);
  }

  function hourlyChart(hourly) {
    var data = (hourly || []).slice(-24);
    var W = 720, H = 220, BASE = 178, TOP = 20;
    var svg = sv("svg", { viewBox: "0 0 " + W + " " + H, class: "chart", role: "img", "aria-label": t("chart.title") });
    var max = 1;
    data.forEach(function (h) { max = Math.max(max, (h.info || 0) + (h.warn || 0) + (h.critical || 0)); });
    svg.appendChild(sv("line", { x1: 0, y1: BASE + 0.5, x2: W, y2: BASE + 0.5 }));
    svg.appendChild(sv("line", { x1: 0, y1: TOP + 0.5, x2: W, y2: TOP + 0.5 }));
    svg.appendChild(sv("text", { x: 0, y: TOP - 4 }, String(max)));
    var slot = W / Math.max(1, data.length), bw = Math.min(14, slot * 0.4);
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
    var c = s.counters || {}, ban = s.ban || {}, lv = A.level(s);
    R.stmt.textContent = (s.host || t("common.unknown")) + " · " + t("ui.overview.subtitle");
    clear(R.facts);
    [["fact.events", c.events_24h, "list", ""], ["fact.critical", c.critical_24h, "activity", "critical"],
      ["fact.warn", c.warn_24h, "filter", "warn"], ["fact.bans", s.bans_active, "shield", ""]].forEach(function (f) {
      add(R.facts, el("div", { class: "metric card", dataset: { sev: f[3] } }, [el("div", { class: "metric-top" }, [el("span", { text: t(f[0]) }), icon(f[2])]),
        el("b", { class: "metric-value", text: A.num(f[1]) }), el("span", { class: "metric-caption", text: f[0] === "fact.bans" ? t("ui.active_now") : t("ev.period.24h") })]));
    });
    clear(R.notes);
    if (lv === "down") { add(R.notes, note({ lv: "crit" }, t("note.audit"), t("health.stale", { time: A.dateTime(s.auditd && s.auditd.last_write) }))); }
    if (!ban.enforcing || ban.dry_run) { add(R.notes, note({ sev: "warn" }, t("enforce.title"), ban.dry_run ? t("enforce.dry_run") : t("enforce.body"))); }
    clear(R.chart);
    add(R.chart, [hourlyChart(s.hourly), el("div", { class: "legend" }, A.SEVS.map(function (sev) {
      return el("span", { dataset: { sev: sev } }, [el("i", { class: "dot" }), t("sev." + sev)]);
    }))]);
    clear(R.health);
    add(R.health, [checkRow(!(s.auditd && s.auditd.healthy === false), "auditd"),
      checkRow(!!(model.telegram && model.telegram.status === "connected"), "telegram"),
      el("div", { class: "health-fact" }, [el("span", { text: t("fact.uptime") }), el("b", { text: A.duration(s.uptime_seconds) })]),
      el("div", { class: "health-fact" }, [el("span", { text: t("ui.profile") }), el("b", { text: s.profile || "—" })])]);
    clear(R.recent);
    var events = model.events.slice(0, 5);
    if (!events.length) { add(R.recent, el("div", { class: "empty", text: t("ev.empty") })); }
    events.forEach(function (ev) { add(R.recent, A.feed.row(ev, actions)); });
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

  function paintSuspects() {
    if (!R.suspectsTbl) { return; }
    clear(R.suspectsTbl);
    var page = model.suspects;
    if (!page || model.suspectsError) {
      R.suspectsNote.textContent = t("suspects.unavailable");
      if (!page) { return; }
    } else {
      R.suspectsNote.textContent = t(page.auto_enforcing ? "suspects.policy" : "suspects.disabled", {
        count: page.threshold, minutes: Math.round(page.window_seconds / 60)
      }) + (page.truncated ? " " + t("suspects.truncated") : "");
    }
    var items = page.items.filter(function (s) {
      return !actions.isBlocked(s.ip) && !A.feed.protectedIP(s.ip, model.allow);
    });
    if (!items.length) { add(R.suspectsTbl, el("div", { class: "tbl-empty", text: t("suspects.empty") })); return; }
    add(R.suspectsTbl, el("table", { class: "tbl" }, [
      el("thead", null, el("tr", null, [
        el("th", { text: t("bans.col.ip") }), el("th", { text: t("suspects.count") }),
        el("th", { text: t("suspects.last") }), el("th", { text: t("bans.col.state") }), el("th", { class: "r" })
      ])),
      el("tbody", null, items.map(function (s) {
        return el("tr", null, [
          el("td", { class: "mono", text: s.ip }), cell(t("suspects.count"), A.num(s.attempts)),
          cell(t("suspects.last"), A.relative(s.last)),
          cell(t("bans.col.state"), t(s.state === "needs_attention" ? "suspects.attention" : "suspects.review")),
          el("td", { class: "r" }, [
            A.feed.banButton(s.event, actions),
            el("button", { class: "pill pill-quiet pill-sm", type: "button", text: t("ev.act.trust"),
              onclick: function () { actions.trust(s.ip); } })
          ])
        ]);
      }))
    ]));
  }

  function paintIncidents() {
    if (!R.incTbl) { return; }
    clear(R.incTbl);
    if (!model.incidents.length) { add(R.incTbl, el("div", { class: "tbl-empty", text: t("inc.empty") })); return; }
    var act = function (id, action) {
      A.api.incidentAction(id, action).then(function () { A.feed.closeDetail(); A.toast(t("inc.state." + (action === "ack" ? "acknowledged" : action === "resolve" ? "resolved" : "new")), "ok"); refresh(); },
        function (e) { A.toast(errText(e), "err"); });
    };
    var btn = function (i, name, action) { return el("button", { class: "pill pill-quiet pill-sm", type: "button", text: t("inc.act." + name), onclick: function () { act(i.id, action); } }); };
    function openIncident(i) {
      var dlg = A.feed.showDetail(i.reason, el("p", { class: "callout", text: t("common.loading") }));
      A.api.incident(i.id).then(function (full) {
        if (!dlg.isConnected) { return; }
        var body = clear(dlg.querySelector(".drawer-body"));
        add(body, [
          el("div", { class: "facts-inline" }, [
            kvRow(t("inc.col.sev"), t("sev." + full.severity)), kvRow(t("inc.col.state"), t("inc.state." + full.state)),
            kvRow(t("ev.ip"), full.src_ip || "—"), kvRow(t("inc.col.events"), A.num(full.total))
          ]),
          el("h3", { text: t("nav.events") }),
          el("ol", { class: "incident-timeline" }, (full.events || []).map(function (e) {
            return el("li", null, [el("span", { class: "lbl", text: A.dateTime(e.time) }),
              el("p", { text: t("kind." + e.kind) + (e.user ? " · " + e.user : "") }), A.feed.sevTag(e.severity)]);
          })),
          el("div", { class: "btns" }, [
            full.state === "new" ? btn(full, "acknowledged", "ack") : null,
            full.state !== "resolved" ? btn(full, "resolved", "resolve") : btn(full, "new", "reopen")
          ])
        ]);
      }, function (e) { if (dlg.isConnected) { var b = clear(dlg.querySelector(".drawer-body")); add(b, el("p", { class: "err", text: errText(e) })); } });
    }
    add(R.incTbl, el("table", { class: "tbl" }, [
      el("thead", null, el("tr", null, [el("th", { text: t("inc.col.reason") }), el("th", { text: t("inc.col.sev") }), el("th", { text: t("inc.col.state") }), el("th", { text: t("inc.col.events") }), el("th", { class: "r" })])),
      el("tbody", null, model.incidents.map(function (i) {
        var kinds = Object.keys(i.kinds || {}).map(function (k) { return t("kind." + k) + " ×" + i.kinds[k]; }).join(" · ");
        return el("tr", null, [
          cell(t("inc.col.reason"), [el("button", { class: "lnk", type: "button", "aria-haspopup": "dialog", text: i.reason, onclick: function () { openIncident(i); } }), el("small", { text: A.relative(i.last_seen) + (kinds ? " · " + kinds : "") + ((i.bans || []).length ? " · " + t("inc.bans") + " " + i.bans.join(", ") : "") })]),
          cell(t("inc.col.sev"), A.feed.sevTag(i.severity)),
          cell(t("inc.col.state"), t("inc.state." + i.state)),
          cell(t("inc.col.events"), A.num(i.total)),
          el("td", { class: "r" }, [
            i.state === "new" ? btn(i, "acknowledged", "ack") : null,
            i.state !== "resolved" ? btn(i, "resolved", "resolve") : btn(i, "new", "reopen")
          ])
        ]);
      }))
    ]));
  }

  function excForm() {
    var kind = el("select", { class: "sel" }, A.KINDS.map(function (k) { return el("option", { value: k, text: t("kind." + k) }); }));
    var inp = function () { return el("input", { class: "in", type: "text", autocomplete: "off", spellcheck: "false" }); };
    var user = inp(), ip = inp(), path = inp(), cmd = inp(), reason = inp();
    var hours = el("select", { class: "sel" }, ["24", "168", "720", "2160"].map(function (h) { return el("option", { value: h, text: t("exc.dur." + h) }); }));
    var err = el("p", { class: "err", role: "alert", hidden: true });
    var node = el("form", {
      onsubmit: function (e) {
        e.preventDefault();
        var p = { kind: kind.value, user: user.value.trim(), src_ip: ip.value.trim(), path_prefix: path.value.trim(), cmd_prefix: cmd.value.trim(), reason: reason.value.trim(), hours: parseInt(hours.value, 10) };
        if (!p.user && !p.src_ip && !p.path_prefix && !p.cmd_prefix) { err.textContent = t("exc.form.need"); err.hidden = false; return; }
        err.hidden = true;
        A.api.addException(p).then(function (x) {
          A.toast(t("exc.form.done", { id: x.id }), "ok");
          user.value = ip.value = path.value = cmd.value = reason.value = "";
          refresh();
        }, function (er) { err.textContent = errText(er); err.hidden = false; });
      }
    }, [
      el("h3", { class: "lbl", text: t("exc.form.title") }),
      el("div", { class: "form-row" }, [
        fieldOf(t("exc.form.kind"), kind), fieldOf(t("exc.form.user"), user), fieldOf(t("exc.form.ip"), ip),
        fieldOf(t("exc.form.path"), path), fieldOf(t("exc.form.cmd"), cmd), fieldOf(t("exc.form.reason"), reason), fieldOf(t("exc.form.hours"), hours),
        el("button", { class: "pill pill-solid", type: "submit", text: t("exc.form.submit") })
      ]),
      err
    ]);
    return {
      node: node,
      prefill: function (ev) {
        kind.value = ev.kind; user.value = ev.user || ""; ip.value = ev.src_ip || "";
        path.value = (ev.args && ev.args.path) || ""; cmd.value = (ev.args && ev.args.cmd) || ""; reason.focus();
      }
    };
  }

  function paintExceptions() {
    if (!R.excTbl) { return; }
    clear(R.excTbl);
    if (!model.exceptions.length) { add(R.excTbl, el("div", { class: "tbl-empty", text: t("exc.empty") })); return; }
    add(R.excTbl, el("table", { class: "tbl" }, [
      el("thead", null, el("tr", null, [el("th", { text: t("exc.col.rule") }), el("th", { text: t("exc.col.until") }), el("th", { text: t("exc.col.hits") }), el("th", { class: "r" })])),
      el("tbody", null, model.exceptions.map(function (x) {
        var what = [t("kind." + x.kind)].concat([x.user, x.login_user, x.src_ip, x.path_prefix && x.path_prefix + "…", x.cmd_prefix && x.cmd_prefix + "…", x.exe].filter(Boolean)).join(" · ");
        return el("tr", null, [
          cell(t("exc.col.rule"), [what, el("small", { text: x.reason + " · " + x.created_by })]),
          cell(t("exc.col.until"), A.dateTime(x.expires_at)),
          cell(t("exc.col.hits"), A.num(x.hits || 0)),
          el("td", { class: "r" }, el("button", {
            class: "pill pill-quiet pill-sm", type: "button", text: t("exc.remove"),
            onclick: function () {
              A.confirmAction(t("exc.remove.confirm", { id: x.id }), t("exc.remove"), "danger").then(function (ok) {
                if (ok) { A.api.removeException(x.id).then(refresh, function (e) { A.toast(errText(e), "err"); }); }
              });
            }
          }))
        ]);
      }))
    ]));
  }

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
                A.api.unban(b.ip).then(function () {
                  modelRevision++;
                  model.bans = model.bans.filter(function (old) { return old.ip !== b.ip; });
                  paintAll(); A.toast(t("bans.unban.done", { ip: b.ip }), "ok"); refresh();
                },
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
	  [t("diag.source"), d.source_status || t("common.unknown")],
      [t("diag.events"), A.num(c.events_total !== undefined ? c.events_total : c.events_24h)],
      [t("diag.alerts"), A.num(c.alerts_sent)],
      [t("diag.skipped"), A.num(c.lines_skipped)],
      [t("diag.ratelimited"), A.num(c.rate_limited)]
    ].forEach(function (r) { add(R.sysKv, kvRow(r[0], r[1])); });

    if (c.delivery) {
      ["pending", "critical_pending", "queued", "suppressed", "grouped", "retries", "failed", "cancelled", "overflow"].forEach(function (key) {
        add(R.sysKv, kvRow(t("delivery." + key), A.num(c.delivery[key])));
      });
    }

    var tg = (model.cfg && model.cfg.telegram) || {};
    clear(R.checks);
    add(R.checks, [
      checkRow(!(s.auditd && s.auditd.healthy === false), "auditd"),
      checkRow(!!(model.telegram && model.telegram.status === "connected"), "telegram"),
      checkRow(s.rules_loaded !== undefined ? !!s.rules_loaded : !!(s.counters && s.counters.events_24h > 0), "rules"),
      checkRow(!!(s.ban && s.ban.enforcing), "bans")
    ]);
    R.confPre.textContent = model.cfg ? JSON.stringify(model.cfg, null, 2) : t("common.unknown");
  }



  function paintAll() {
    model.status = S.status;
    if (R.telegram) { A.Telegram.paint(R.telegram, model.telegram); }
    paintHero(); paintFold(); paintRoster(); paintSuspects(); paintIncidents(); paintExceptions(); paintBans(); paintAllow(); paintAlerts(); paintSystem();
    syncBanButtons();
  }

  /* ---------------- data ---------------- */

  function loadAll() {
    var revision = modelRevision, session = S.token;
    function current() { return revision === modelRevision && session === S.token; }
    return A.loadStatus().then(function () {
      if (!current()) { return; }
      var since = new Date(Date.now() - 86400e3).toISOString();
      return Promise.all([
        A.api.events("limit=200&since=" + encodeURIComponent(since)).then(function (p) { if (current()) { model.events = (p && p.items) || []; A.announceCritical(model.events); } }, function () { }),
        A.api.bans().then(function (v) { if (current()) { model.bans = v || []; } }, function () { }),
        A.api.incidents(incidentFilter).then(function (v) { if (current()) { model.incidents = (v && v.items) || []; } }, function () { }),
        A.api.update().then(function (v) { if (current()) { A.Updates.set(v); } }, function () { }),
        A.api.access().then(function (v) { if (current()) { A.Access.update(v); } }, function () { }),
        A.api.exceptions().then(function (v) { if (current()) { model.exceptions = (v && v.items) || []; } }, function () { }),
        A.api.allowlist().then(function (v) { if (current()) { model.allow = v || []; } }, function () { }),
        A.api.suspects().then(function (v) { if (current()) { model.suspects = v; model.suspectsError = false; } },
          function () { if (current()) { model.suspectsError = true; } }),
        A.api.config().then(function (v) { if (current()) { model.cfg = v; } }, function () { }),
        A.api.telegram().then(function (v) { if (current()) { model.telegram = v; } }, function () { }),
        A.api.diagnostics().then(function (v) { if (current()) { model.diag = v; } }, function () { })
      ]);
    }).then(function () { if (current()) { paintAll(); } });
  }

  function refresh() {
    return loadAll().then(function () { if (journal) { journal.refresh(); } });
  }

  function startPoll() {
    stopPoll();
    poll = setInterval(function () { if (document.visibilityState === "visible") { refresh(); } }, 10000);
  }
  function stopPoll() { if (poll) { clearInterval(poll); poll = null; } }



  /* ---------------- lifecycle ---------------- */

  function stopAll() {
    modelRevision++;
    pendingBans = Object.create(null);
    A.Telegram.close();
    stopPoll();
    A.Updates.unmount();
    A.Access.unmount();
    A.feed.closeDetail();
    var sheet = $("#sheet");
    if (sheet) { sheet.parentNode.removeChild(sheet); }
    clear($("#main"));
    R = {}; journal = null;
    model = { status: null, events: [], incidents: [], exceptions: [], bans: [], allow: [], suspects: null, cfg: null, diag: null };
    S.status = null;
  }

  function rebuild() {
    modelRevision++;
    A.Updates.unmount(); A.Access.unmount(); A.feed.closeDetail();
    buildBar(); buildMain(); setupDemo();
    paintAll();
    journal.reload();
    loadAll();
  }

  function setupDemo() {
    var host = $("#demo");
    if (!S.mock || !window.AUDITDSEC_MOCK) { host.hidden = true; return; }
    clear(host);
    var sel = el("select", { class: "sel", "aria-label": t("mock.scenario"), onchange: function (e) {
      window.AUDITDSEC_MOCK.setScenario(e.target.value);
      S.announced = null;
      loadAll().then(function () { journal.reload(); });
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
