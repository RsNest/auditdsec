/* Updates are a page. The control service owns the operation across restarts.
   No published text is interpreted as HTML, a URL or an executable command. */
(function () {
  "use strict";
  var A = window.ADS, el = A.el, add = A.add, clear = A.clear, t = A.t;
  var view = null, host = null, buttons = [], timer = null, task = null, busy = false;
  var signature = "", generation = 0, reconnect = false, verifying = false, target = "", started = 0;
  var TASK_KEY = "ads.update.task";

  function pending() { return !!(view && view.pending); }
  function active() { return task && (task.state === "running" || task.state === "queued"); }
  function stateText(v) {
    if (!v) { return t("upd.state.checking"); }
    var keys = { checking: "checking", up_to_date: "current", available: "available", unavailable: "unavailable",
      unknown_installed: "unknown", unsupported_arch: "arch", incomplete: "incomplete", disabled: "disabled" };
    return t("upd.state." + (keys[v.state] || "never"));
  }
  function shortVersion(v) {
    if (!v || !v.version) { return t("common.unknown"); }
    return v.version.split("+")[0] + (/dev/.test(v.version) && v.commit ? " · " + v.commit.slice(0, 7) : "");
  }
  function paintButtons() {
    buttons = buttons.filter(function (b) { return b.isConnected; });
    buttons.forEach(function (b) { b.querySelector(".upd-dot").hidden = !pending(); b.title = pending() ? t("upd.new") : t("ui.updates"); });
  }
  function button(cls) {
    var b = el("button", { class: cls, type: "button", onclick: function () { A.navigate("updates"); } },
      [el("span", { text: t("ui.updates") }), el("i", { class: "upd-dot", "aria-hidden": "true", hidden: !pending() })]);
    buttons.push(b); return b;
  }
  function release(c) {
    var kids = [el("h3", { text: c.title }), el("time", { datetime: c.date, text: c.date })];
    ["added", "fixed", "changed", "actions"].forEach(function (k) {
      if (c[k] && c[k].length) { kids.push(el("div", { class: "release-group" }, [
        el("span", { class: "lbl", text: t("upd." + k) }), el("ul", null, c[k].map(function (s) { return el("li", { text: s }); }))])); }
    });
    return el("article", { class: "release-entry" }, kids);
  }
  function manual() {
    return el("details", { class: "card update-details", dataset: { preserve: "manual" } }, [
      el("summary", { text: t("ui.update.manual") }), el("p", { class: "callout", text: t("upd.how.note") }),
      el("div", { class: "raw" }, el("code", { text: "sudo ./install.sh --action update" }))
    ]);
  }
  function operation() {
    if (!task) { return null; }
    var text = reconnect ? t("ui.update.reconnect") : verifying ? t("ui.update.verify") :
      active() ? t("ui.update.installing") : task.state === "succeeded" ? t("ui.update.success") :
      task.state === "rolled_back" ? t("ui.update.rolled_back") : t("ui.update.failed");
    var stages = ["source", "image", "apply", "verify"];
    var at = { start: 0, source: 0, preflight: 0, image: 1, dns: 1, challenge: 1, apply: 2, verify: 3, rollback: 3 }[task.stage];
    if (at === undefined) { at = 0; }
    var success = task.state === "succeeded" && !verifying;
    var bad = !active() && !success && !verifying;
    return el("div", { class: "card update-progress" }, [
      el("h2", { text: t("ui.update.progress") }),
      el("p", { role: "status", "aria-live": "polite", class: bad ? "err" : "", text: text }),
      el("ol", { class: "update-steps" }, stages.map(function (s, i) {
        var state = success || i < at ? "done" : i === at ? (bad ? "failed" : "live") : "pending";
        return el("li", { class: "update-step", dataset: { state: state } }, [
          el("span", { class: "step-mark", "aria-hidden": "true", text: state === "done" ? "✓" : String(i + 1) }),
          el("span", { text: t("ui.update.stage." + s) })
        ]);
      })),
      task.cause ? el("p", { class: "err", text: task.cause }) : null,
      task.fix ? el("p", { class: "callout", text: task.fix }) : null,
      el("details", { class: "update-details", dataset: { preserve: "log" } }, [
        el("summary", { text: t("ui.update.logs") }),
        el("p", { class: "mono", text: "Trace ID: " + (task.trace_id || task.id) }),
        el("pre", { text: (task.events || []).map(function (e) { return (e.at || "") + " · " + (e.text || e.code || e.state); }).join("\n") + (task.log_tail ? "\n\n" + task.log_tail : "") })
      ])
    ]);
  }
  function paint(force) {
    paintButtons();
    if (!host || !host.isConnected) { return; }
    var sig = JSON.stringify([view, task, busy, reconnect, verifying, A.state.lang]);
    if (!force && sig === signature) { return; }
    signature = sig;
    var opened = Array.prototype.map.call(host.querySelectorAll("details[open][data-preserve]"), function (n) { return n.dataset.preserve; });
    var focused = host.contains(document.activeElement) && document.activeElement.dataset.focus;
    clear(host);
    var v = view || {}, inst = v.installed || {}, irreversible = v.requires && v.requires.migration === "irreversible";
    var can = pending() && v.state === "available" && v.control && v.control.available && !irreversible && !busy && !active() && !verifying;
    var primary = pending() ? el("button", { class: "pill pill-solid", type: "button", disabled: !can, dataset: { focus: "apply" },
      text: busy || active() || verifying ? t("ui.update.installing") : t("ui.update.install"), onclick: apply }) : null;
    add(host, el("div", { class: "card" }, [
      el("div", { class: "update-summary" }, [
        el("div", null, [el("div", { class: "update-heading" }, [el("span", { class: "update-icon" }, A.icon("download")), el("h2", { text: stateText(view) })]),
          el("p", { class: "callout", text: t("ui.update.description") }),
          el("div", { class: "version-pair" }, [el("div", null, [el("span", { class: "lbl", text: t("upd.installed") }), el("b", { text: shortVersion(inst), title: inst.version || "" })]),
            pending() && v.latest ? el("span", { class: "version-arrow", "aria-hidden": "true", text: "→" }) : null,
            pending() && v.latest ? el("div", null, [el("span", { class: "lbl", text: t("upd.available") }), el("b", { text: shortVersion(v.latest), title: v.latest.version })]) : null])]),
        el("div", { class: "update-actions" }, [primary, pending() ? el("p", { text: t("ui.update.pause") }) : null])
      ]),
      el("div", { class: "update-meta" }, [
        el("span", { text: t("ui.update.last", { time: v.last_checked ? A.relative(v.last_checked) : t("upd.never") }) }),
        v.state !== "disabled" ? el("span", { text: t("ui.update.auto") }) : null,
        el("button", { class: "lnk", type: "button", dataset: { focus: "check" }, disabled: busy || active() || v.state === "checking", text: t("upd.check"), onclick: check })
      ])
    ]));
    if (pending() && !(v.control && v.control.available)) {
      add(host, el("div", { class: "card card-body" }, [el("p", { class: "callout", text: t("ui.update.control") }), el("code", { text: t("ui.update.enable") })]));
    }
    if (irreversible) { add(host, el("p", { class: "callout", text: t("ui.update.irreversible") })); }
    if (v.state === "unavailable") { add(host, el("p", { class: "err", text: t("upd.err") + (v.error ? ": " + v.error : "") })); }
    if (v.message) { add(host, el("p", { class: "callout", text: v.message })); }
    add(host, operation());
    add(host, el("details", { class: "card update-details", dataset: { preserve: "technical" } }, [
      el("summary", { text: t("ui.update.details") }),
      el("div", { class: "facts-inline" }, [
        [t("upd.installed"), (inst.version || "—") + " · " + (inst.commit || "—")],
        [t("upd.available"), v.latest ? v.latest.version + " · " + v.latest.commit : "—"],
        [t("upd.channel"), v.channel ? t("upd.channel." + v.channel) : "—"],
        [t("upd.published"), v.latest ? A.dateTime(v.latest.published) : "—"]
      ].map(function (f) { return el("div", null, [el("span", { class: "lbl", text: f[0] }), el("span", { class: "mono", text: f[1] })]); }))
    ]));
    add(host, el("h2", { text: t("ui.update.changes") }));
    var changes = v.changes || [];
    var releases = el("div", { class: "release-list" });
    changes.slice(0, 2).forEach(function (c) { add(releases, el("div", { class: "card" }, release(c))); });
    if (changes.length > 2) { add(releases, el("details", { class: "card release-more", dataset: { preserve: "more" } }, [
      el("summary", { text: t("ui.update.previous") + " · " + (changes.length - 2) }), changes.slice(2).map(release)
    ])); }
    if (!changes.length) { add(releases, el("div", { class: "card empty", text: t("ui.update.none") })); }
    add(host, releases);
    if (v.breaking && v.breaking.length) { add(host, el("div", { class: "card update-conditions" }, [
      el("h3", { text: t("upd.conditions") }), el("ul", null, v.breaking.map(function (s) { return el("li", { text: s }); }))
    ])); }
    add(host, manual());
    opened.forEach(function (id) { var n = host.querySelector('details[data-preserve="' + id + '"]'); if (n) { n.open = true; } });
    if (focused) { var f = host.querySelector('[data-focus="' + focused + '"]'); if (f) { f.focus({ preventScroll: true }); } }
  }
  function check() {
    var gen = generation; busy = true; paint();
    A.api.updateCheck().then(function (v) { if (gen === generation) { view = v; refreshCheck(6, gen); } }, function (e) {
      if (gen === generation) { A.toast(e.code === "throttled" ? t("upd.toofast") : e.message || t("err.generic"), "warn"); }
    }).finally(function () { if (gen === generation) { busy = false; paint(); } });
  }
  function refreshCheck(n, gen) {
    if (!n || gen !== generation) { return; }
    setTimeout(function () { if (gen !== generation) { return; } A.api.update().then(function (v) { if (gen !== generation) { return; } set(v); if (v.state === "checking") { refreshCheck(n - 1, gen); } }, function () {}); }, 1500);
  }
  function saveTask() { A.put("sessionStorage", TASK_KEY, JSON.stringify({ id: task.id, commit: target, started: started })); }
  function apply() {
    if (busy || active() || !view || !view.latest) { return; }
    target = view.latest.commit; busy = true; paint();
    var gen = generation;
    A.api.updateApply(target).then(function (v) {
      if (gen !== generation) { return; }
      task = v; started = Date.now(); saveTask(); track();
    }, function (e) { if (gen === generation) { A.toast(e.message || t("err.generic"), "err"); } }).finally(function () {
      if (gen === generation) { busy = false; paint(); }
    });
  }
  function track() {
    if (timer) { clearTimeout(timer); }
    var gen = generation;
    if (!task) { return; }
    timer = setTimeout(function () {
      if (gen !== generation || !A.state.token) { return; }
      A.api.updateTask(task.id).then(function (v) {
        if (gen !== generation) { return; }
        task = v; reconnect = false;
        if (active()) { paint(); track(); return; }
        if (task.state === "succeeded") {
          verifying = true; paint();
          A.api.update().then(function (v) {
            if (gen !== generation) { return; }
            view = v; verifying = false;
            if (!v.installed || v.installed.commit !== target) {
              task = Object.assign({}, task, { state: "failed", cause: t("ui.update.mismatch") });
            }
            A.put("sessionStorage", TASK_KEY, null); paint();
            // Once the new agent confirms its exact commit, load its assets.
            if (task.state === "succeeded" && !A.state.mock) {
              setTimeout(function () { if (gen === generation && A.state.token) { location.reload(); } }, 1200);
            }
          }, function () { if (gen === generation) { retry(); } });
        } else { A.put("sessionStorage", TASK_KEY, null); paint(); }
      }, function () {
        if (gen !== generation) { return; }
        retry();
      });
    }, 2000);
  }
  function retry() {
    reconnect = true; paint();
    if (Date.now() - started < 30 * 60 * 1000) { track(); }
    else { reconnect = false; verifying = false; task = Object.assign({}, task, { state: "interrupted", cause: t("ui.update.timeout") }); paint(); }
  }
  function set(v) {
    view = v;
    if (!task && v.task && !(v.task.state === "succeeded" && (!v.installed || v.installed.commit !== v.task.params.commit))) {
      task = v.task; target = task.params.commit || ""; started = Date.parse(task.started) || Date.now();
      if (active()) { saveTask(); track(); }
    }
    paint();
  }
  function mount(node) {
    host = node; signature = "";
    var saved = A.get("sessionStorage", TASK_KEY);
    if (saved && !task) { try { var s = JSON.parse(saved); task = { id: s.id, state: "running" }; target = s.commit; started = s.started; } catch (e) { A.put("sessionStorage", TASK_KEY, null); } }
    paint(true); if (active()) { track(); }
  }
  function unmount() { generation++; if (timer) { clearTimeout(timer); } timer = null; host = null; buttons = []; busy = false; }
  function reset() { unmount(); task = null; view = null; verifying = false; reconnect = false; A.put("sessionStorage", TASK_KEY, null); }
  A.Updates = { button: button, set: set, pending: pending, stateText: stateText, mount: mount, unmount: unmount, reset: reset, open: function () { A.navigate("updates"); } };
})();
