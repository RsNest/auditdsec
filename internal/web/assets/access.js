/* How the panel is reached: current address and certificate, and the wizard that
   changes it. The wizard only asks; the change itself is made by the installer
   through the local control service, and without it only the command is shown. */
(function () {
  "use strict";
  var A = window.ADS, el = A.el, add = A.add, clear = A.clear, t = A.t;
  var ui = null, polling = null;

  function row(label, value) {
    return el("div", null, [el("span", { class: "lbl", text: label }), el("span", { class: "mono", text: value || t("common.unknown") })]);
  }
  function copyCmd(cmd) {
    return el("div", { class: "raw" }, [
      el("div", { class: "raw-head" }, [el("span", { class: "lbl", text: t("acc.command") }), el("button", {
        class: "lnk", type: "button", text: t("common.copy"),
        onclick: function () { if (navigator.clipboard && navigator.clipboard.writeText) { navigator.clipboard.writeText(cmd); } A.toast(t("common.copied"), "ok"); }
      })]),
      el("code", { text: cmd })
    ]);
  }
  /* Everything below is shown with textContent only: addresses, notes and
     errors come from DNS and from the installer. */
  function checkLine(c) {
    return el("li", { class: "chk", dataset: { s: c.status } }, [el("b", { text: t("acc.status." + c.status) + " " }), c.text]);
  }

  function status(s) {
    var c = (s && s.current) || {};
    var host = ui.status;
    clear(host);
    add(host, [
      row(t("acc.link"), c.url), row(t("acc.mode"), c.mode ? t("acc.mode." + c.mode) : ""), row(t("acc.site"), c.site),
      row(t("acc.issuer"), c.issuer), row(t("acc.until"), c.not_after), row(t("acc.renewal"), c.renewal),
      row(t("acc.running"), c.running)
    ]);
    if (c.source === "agent") { add(host, el("p", { class: "callout", text: t("acc.partial") })); }
    var ctl = s && s.control;
    ui.control.textContent = ctl && ctl.available ? t("acc.ctl.ok") : t("acc.ctl.none");
    ui.control.dataset.ok = ctl && ctl.available ? "1" : "0";
    ui.available = !!(ctl && ctl.available);
    if (s && s.draft && !ui.touched) { fill(s.draft); }
    if (s && s.last_task && !polling && ui.shownTask !== s.last_task.id) { track(s.last_task); }
  }

  function fill(d) {
    ui.action.value = d.action || "domain"; ui.site.value = d.site || ""; ui.email.value = d.email || ""; ui.port.value = d.https_port || "auto";
    toggle();
  }
  function toggle() {
    var dom = ui.action.value === "domain", ip = ui.action.value === "ip";
    ui.siteF.hidden = !(dom || ip); ui.emailF.hidden = !(dom || ip); ui.portF.hidden = !(dom || ip);
  }
  function params() {
    var p = { action: ui.action.value };
    if (!ui.siteF.hidden && ui.site.value.trim()) { p.site = ui.site.value.trim(); }
    if (!ui.emailF.hidden && ui.email.value.trim()) { p.email = ui.email.value.trim(); }
    if (!ui.portF.hidden && ui.port.value.trim() && ui.port.value.trim() !== "auto") { p.https_port = ui.port.value.trim(); }
    return p;
  }

  function checkNow() {
    var p = params();
    clear(ui.result); ui.touched = true;
    add(ui.result, el("p", { class: "callout", text: t("acc.checking") }));
    A.api.accessCheck(p).then(function (r) { show(p, r); }, function (e) {
      clear(ui.result); add(ui.result, el("p", { class: "err", text: e.message || t("err.generic") }));
    });
  }

  function show(p, r) {
    clear(ui.result);
    var pre = r.preflight, plan = r.plan, kids = [];
    if (pre) {
      var recs = pre.records || [];
      kids.push(el("h4", { class: "lbl", text: t("acc.dns.title") }));
      kids.push(el("p", { class: "callout", text: t("acc.dns.how") }));
      kids.push(recs.length ? el("table", { class: "tbl" }, [el("tbody", null, recs.map(function (x) {
        return el("tr", null, [el("td", { text: x.type }), el("td", { text: x.name }), el("td", { text: x.value })]);
      }))]) : el("p", { class: "err", text: t("acc.dns.noaddr") }));
      kids.push(el("p", { text: t("acc.dns.found") + " A: " + ((pre.a || []).join(", ") || "—") + " · AAAA: " + ((pre.aaaa || []).join(", ") || "—") }));
      kids.push(el("ul", { class: "chks" }, (pre.checks || []).map(checkLine)));
      (pre.problems || []).forEach(function (x) { kids.push(el("p", { class: "err", text: x })); });
      kids.push(el("p", { class: "callout", text: t("acc.dns.notguarantee") }));
    }
    kids.push(el("h4", { class: "lbl", text: t("acc.plan.title") }));
    kids.push(el("ul", null, (plan.changes || []).map(function (c) { return el("li", { text: c.what + (c.from ? ": " + c.from : "") + (c.to ? " → " + c.to : "") }); })));
    kids.push(el("p", { text: t("acc.plan.kept") + ": " + (plan.kept || []).join(", ") }));
    kids.push(el("p", { class: "callout", text: plan.interruption }));
    kids.push(el("p", { class: "callout", text: plan.rollback }));
    var blocked = pre && !pre.dns_ok;
    if (blocked) { kids.push(el("p", { class: "err", text: t("acc.blocked") })); }
    if (ui.available) {
      var ok = el("input", { type: "checkbox" });
      var go = el("button", { class: "pill pill-solid", type: "button", text: t("acc.apply"), disabled: true, onclick: function () { apply(p, plan); } });
      ok.addEventListener("change", function () { go.disabled = !ok.checked || !!blocked; });
      kids.push(el("label", { class: "tg-check" }, [ok, el("span", { text: t("acc.confirm") })]), go);
    } else {
      kids.push(el("p", { class: "callout", text: t("acc.manual") }), copyCmd(plan.command));
    }
    kids.push(el("button", { class: "pill pill-quiet", type: "button", text: t("acc.draft.save"), onclick: function () {
      A.api.accessDraft(p).then(function () { A.toast(t("acc.draft.saved"), "ok"); }, function (e) { A.toast(e.message || t("err.generic"), "err"); });
    } }));
    add(ui.result, kids);
  }

  function apply(p, plan) {
    var body = Object.assign({}, p, { plan_id: plan.plan_id, confirm: true });
    A.api.accessApply(body).then(function (task) { track(task); }, function (e) {
      clear(ui.progress); add(ui.progress, el("p", { class: "err", text: e.message || t("err.generic") }));
      if (e.data && e.data.command) { add(ui.progress, copyCmd(e.data.command)); }
    });
  }

  function paintTask(task) {
    clear(ui.progress);
    var done = !(task.state === "queued" || task.state === "running");
    var kids = [el("p", { class: "lbl", text: t("acc.task") + ": " + t("acc.state." + task.state) + (task.stage ? " · " + t("acc.stage." + task.stage) : "") })];
    kids.push(el("ol", null, (task.events || []).filter(function (e) { return e.kind === "stage"; }).map(function (e) {
      return el("li", { text: t("acc.stage." + e.code) });
    })));
    if (task.state === "succeeded") {
      var u = task.params && task.params.action === "domain" ? "https://" + task.params.site + (task.params.https_port && task.params.https_port !== "443" ? ":" + task.params.https_port : "") : "";
      kids.push(el("p", { class: "callout", text: t("acc.done") }));
      if (u) { kids.push(el("a", { class: "pill pill-solid", href: u, rel: "noopener", text: t("acc.open") })); }
    } else if (done) {
      kids.push(el("p", { class: "err", text: t("acc.fail." + (task.state === "rolled_back" ? "rolled_back" : task.state === "interrupted" ? "interrupted" : "failed")) }));
      if (task.cause) { kids.push(el("p", { text: task.cause })); }
      if (task.fix) { kids.push(el("p", { class: "callout", text: t("acc.fix") + ": " + task.fix })); }
      if (task.code) { kids.push(el("p", { class: "mono", text: task.code })); }
      if (task.trace_id) { kids.push(el("p", { class: "mono", text: t("acc.trace") + ": " + task.trace_id })); }
    } else {
      kids.push(el("p", { class: "callout", text: t("acc.wait") }));
    }
    add(ui.progress, kids);
    return done;
  }

  /* The change can interrupt the panel itself (it restarts behind its proxy), so
     a failed poll is expected and retried; the state lives in the control service. */
  function track(task) {
    ui.shownTask = task.id;
    if (polling) { clearInterval(polling); polling = null; }
    if (paintTask(task)) { return; }
    var misses = 0;
    polling = setInterval(function () {
      A.api.accessTask(task.id).then(function (x) {
        misses = 0;
        if (paintTask(x)) { clearInterval(polling); polling = null; }
      }, function () {
        misses++;
        if (misses === 3) { add(ui.progress, el("p", { class: "callout", text: t("acc.reconnect") })); }
      });
    }, 2500);
  }

  function mount(host) {
    ui = { available: false, touched: false, shownTask: "" };
    ui.action = el("select", { class: "sel", onchange: toggle }, ["domain", "ip", "tunnel", "update", "check"].map(function (a) { return el("option", { value: a, text: t("acc.action." + a) }); }));
    ui.site = el("input", { class: "in", type: "text", autocomplete: "off", spellcheck: "false", placeholder: "panel.example.com" });
    ui.email = el("input", { class: "in", type: "text", autocomplete: "off", placeholder: "me@example.com" });
    ui.port = el("input", { class: "in", type: "text", value: "auto", autocomplete: "off" });
    function f(label, c) { return el("label", { class: "fld" }, [el("span", { class: "lbl", text: label }), c]); }
    ui.siteF = f(t("acc.f.site"), ui.site); ui.emailF = f(t("acc.f.email"), ui.email); ui.portF = f(t("acc.f.port"), ui.port);
    ui.status = el("div", { class: "facts-inline" });
    ui.control = el("p", { class: "callout" });
    ui.result = el("div"); ui.progress = el("div", { "aria-live": "polite" });
    add(host, [
      el("h3", { class: "sub-h", text: t("acc.current") }), ui.status, ui.control,
      el("h3", { class: "sub-h", text: t("acc.wizard") }), el("p", { class: "callout", text: t("acc.lede") }),
      el("div", { class: "form-row" }, [f(t("acc.f.action"), ui.action), ui.siteF, ui.emailF, ui.portF,
        el("button", { class: "pill pill-solid", type: "button", text: t("acc.check"), onclick: checkNow })]),
      ui.result, ui.progress
    ]);
    toggle();
  }

  A.Access = { mount: mount, update: function (s) { if (ui) { status(s); } }, params: function () { return ui ? params() : null; } };
})();
