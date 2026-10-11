/* Version and updates: a permanent button in the bar, a quiet indicator when a
   newer version is known, and a dialog with what is installed, what is
   available, what changed and how to update. The panel only reports; the update
   itself is made by ./install.sh on the server. Texts that come from the
   published notes are set with textContent only. */
(function () {
  "use strict";
  var A = window.ADS, el = A.el, add = A.add, clear = A.clear, t = A.t;
  var view = null, dialog = null, buttons = [];

  function pending() { return !!(view && view.pending); }

  /* The text of the state line. A failed check is never "up to date". */
  function stateText(v) {
    if (!v) { return t("upd.state.checking"); }
    switch (v.state) {
      case "checking": return t("upd.state.checking");
      case "up_to_date": return t("upd.state.current");
      case "available": return t("upd.state.available");
      case "unavailable": return t("upd.state.unavailable");
      case "unknown_installed": return t("upd.state.unknown");
      case "unsupported_arch": return t("upd.state.arch");
      case "incomplete": return t("upd.state.incomplete");
      case "disabled": return t("upd.state.disabled");
      default: return t("upd.state.never");
    }
  }

  function when(iso) { return iso ? A.dateTime(iso) : ""; }

  function paintButtons() {
    buttons.forEach(function (b) {
      if (!b.isConnected) { return; }
      b.dataset.pending = pending() ? "1" : "0";
      b.title = pending() ? t("upd.new") : t("upd.title");
      var dot = b.querySelector(".upd-dot");
      if (dot) { dot.hidden = !pending(); }
      var tag = b.querySelector(".upd-tag");
      if (tag) { tag.hidden = !pending(); tag.textContent = t("upd.new"); }
    });
  }

  function button(cls) {
    var b = el("button", { class: cls || "lnk", type: "button", onclick: open }, [
      el("span", { text: t("upd.title") }),
      el("i", { class: "upd-dot", "aria-hidden": "true", hidden: true }),
      el("span", { class: "upd-tag", hidden: true })
    ]);
    buttons.push(b);
    paintButtons();
    return b;
  }

  function list(title, items) {
    if (!items || !items.length) { return null; }
    return el("div", null, [el("span", { class: "lbl", text: title }),
      el("ul", null, items.map(function (s) { return el("li", { text: s }); }))]);
  }

  function copy(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) { navigator.clipboard.writeText(text).then(function () { }, function () { }); }
    A.toast(t("common.copied"), "ok");
  }

  function body() {
    var v = view, kids = [];
    kids.push(el("p", { class: "callout", role: "status", "aria-live": "polite", dataset: { state: v ? v.state : "checking" }, text: stateText(v) }));
    if (!v) { return kids; }
    var inst = v.installed || {};
    var facts = [[t("upd.installed"), (inst.version || t("common.unknown")) + (inst.commit && inst.commit !== "none" ? " · " + inst.commit.slice(0, 12) : "")]];
    if (v.latest && (v.state !== "up_to_date")) {
      facts.push([t("upd.available"), v.latest.version + " · " + v.latest.commit.slice(0, 12)]);
      if (v.latest.published) { facts.push([t("upd.published"), when(v.latest.published)]); }
    }
    facts.push([t("upd.channel"), t("upd.channel." + v.channel)]);
    facts.push([t("upd.lastok"), v.last_success ? when(v.last_success) : t("upd.never")]);
    if (v.last_checked && (!v.last_success || v.last_checked !== v.last_success)) { facts.push([t("upd.lastcheck"), when(v.last_checked)]); }
    kids.push(el("div", { class: "facts-inline" }, facts.map(function (f) {
      return el("div", null, [el("span", { class: "lbl", text: f[0] }), el("span", { class: "mono", text: f[1] })]);
    })));
    if (v.state === "unavailable") {
      kids.push(el("p", { class: "err", text: t("upd.err") + (v.error ? ": " + v.error : "") }));
      if (v.pending) { kids.push(el("p", { class: "callout", text: t("upd.stale") })); }
    }
    if (v.message) { kids.push(el("p", { class: "callout", text: v.message })); }
    if (v.pending) {
      if (v.truncated) { kids.push(el("p", { class: "callout", text: t("upd.truncated") })); }
      (v.changes || []).forEach(function (c) {
        kids.push(el("div", { class: "upd-change" }, [
          el("h4", { class: "sub-h", text: c.title }),
          list(t("upd.added"), c.added), list(t("upd.fixed"), c.fixed), list(t("upd.changed"), c.changed), list(t("upd.actions"), c.actions)
        ]));
      });
      var conds = [];
      (v.breaking || []).forEach(function (b) { conds.push(b); });
      if (v.requires && v.requires.installer_update) { conds.push(t("upd.cond.installer")); }
      if (v.requires && v.requires.migration === "reversible") { conds.push(t("upd.cond.migration")); }
      if (v.requires && v.requires.migration === "irreversible") { conds.push(t("upd.cond.irreversible")); }
      conds.push(t("upd.cond.pause"));
      kids.push(el("div", { class: "upd-cond" }, [el("span", { class: "lbl", text: t("upd.conditions") }),
        el("ul", null, conds.map(function (s) { return el("li", { text: s }); }))]));
    }
    return kids;
  }

  function howTo() {
    var cmd = (view && view.command) || "./install.sh";
    var item = (view && view.menu_item) || t("upd.menuitem");
    return el("div", { class: "upd-how" }, [
      el("h4", { class: "sub-h", text: t("upd.how") }),
      el("ol", null, [
        el("li", { text: t("upd.how.1") }),
        el("li", { text: t("upd.how.2") }),
        el("li", { text: t("upd.how.3") + " «" + item + "»" }),
        el("li", { text: t("upd.how.4") }),
        el("li", { text: t("upd.how.5") })
      ]),
      el("div", { class: "raw" }, [
        el("div", { class: "raw-head" }, [el("span", { class: "lbl", text: t("acc.command") }),
          el("button", { class: "lnk", type: "button", text: t("upd.copy"), onclick: function () { copy(cmd); } })]),
        el("code", { text: cmd })
      ]),
      el("p", { class: "callout", text: t("upd.how.note") })
    ]);
  }

  function paintDialog() {
    if (!dialog) { return; }
    var host = dialog.querySelector(".upd-body");
    clear(host);
    add(host, body());
  }

  function check() {
    var btn = dialog && dialog.querySelector(".upd-check");
    if (btn) { btn.disabled = true; }
    A.api.updateCheck().then(function (v) { view = v; paintButtons(); paintDialog(); poll(5); },
      function (e) {
        if (e && e.data && e.data.state) { view = e.data; paintButtons(); paintDialog(); }
        A.toast(e && e.code === "throttled" ? t("upd.toofast") : ((e && e.message) || t("err.generic")), "warn");
      }).then(function () { if (btn) { btn.disabled = false; } });
  }

  /* After the button the check runs in the background: look a few times. */
  function poll(n) {
    if (n <= 0 || !dialog) { return; }
    setTimeout(function () {
      A.api.update().then(function (v) {
        view = v; paintButtons(); paintDialog();
        if (v.state === "checking" || (v.state === "never")) { poll(n - 1); }
      }, function () { });
    }, 1500);
  }

  function open() {
    if (dialog) { return; }
    var trigger = document.activeElement;
    var dlg = el("dialog", { class: "tg-dialog", "aria-labelledby": "upd-heading" });
    dialog = dlg;
    var how = null;
    var toggleHow = el("button", { class: "pill pill-solid", type: "button", text: t("upd.how.btn"), onclick: function () {
      if (how) { how.remove(); how = null; toggleHow.textContent = t("upd.how.btn"); return; }
      how = howTo(); dlg.querySelector(".upd-how-host").appendChild(how); toggleHow.textContent = t("upd.how.hide");
    } });
    add(dlg, el("div", { class: "tg-form" }, [
      el("h3", { id: "upd-heading", class: "sub-h", text: t("upd.title") }),
      el("div", { class: "upd-body" }),
      el("div", { class: "upd-how-host" }),
      el("div", { class: "btns" }, [
        toggleHow,
        el("button", { class: "pill upd-check", type: "button", text: t("upd.check"), onclick: check }),
        el("button", { class: "pill pill-quiet", type: "button", text: t("common.close"), onclick: function () { dlg.close(); } })
      ])
    ]));
    dlg.addEventListener("close", function () {
      clear(dlg); dlg.remove(); dialog = null;
      if (trigger && trigger.isConnected) { trigger.focus(); }
    }, { once: true });
    add(document.body, dlg);
    paintDialog();
    dlg.showModal();
    A.api.update().then(function (v) { view = v; paintButtons(); paintDialog(); }, function () { });
  }

  A.Updates = {
    button: button,
    set: function (v) { view = v; paintButtons(); paintDialog(); },
    pending: pending,
    stateText: stateText,
    open: open
  };
})();
