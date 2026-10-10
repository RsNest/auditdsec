/* Telegram drafts stay in this dialog; the saved token never reaches the UI. */
(function () {
  "use strict";
  var A = window.ADS, el = A.el, add = A.add, t = A.t, dialog = null;
  function check(control, text) { return el("label", { class: "tg-check" }, [control, el("span", { text: text })]); }
  function field(text, control) {
    return el("label", { class: "fld" }, [el("span", { class: "lbl", text: text }), control]);
  }
  function close() { if (dialog) { dialog.close(); } }
  function open() {
    if (dialog) { return; }
    A.api.telegram().then(function (saved) {
      if (dialog || !A.state.token) { return; }
      var trigger = document.activeElement, busy = false;
      var dlg = el("dialog", { class: "tg-dialog", "aria-labelledby": "tg-heading" });
      dialog = dlg;
      var token = el("input", { class: "in", type: "password", autocomplete: "new-password", spellcheck: "false", maxlength: 256, placeholder: saved.has_token ? t("tg.token.saved") : "123456:..." });
      var ids = el("input", { class: "in", type: "text", value: saved.chat_ids.join(", "), autocomplete: "off", spellcheck: "false", placeholder: "123456789, -1001234567890" });
      var enabled = el("input", { type: "checkbox", checked: saved.enabled });
      var bans = el("input", { type: "checkbox", checked: saved.bans });
      var startup = el("input", { type: "checkbox", checked: saved.startup_notice });
      var severity = el("select", { class: "sel" }, A.SEVS.map(function (v) { return el("option", { value: v, selected: saved.min_severity === v, text: t("sev." + v) }); }));
      var from = el("input", { class: "in", type: "time", value: saved.quiet_from });
      var to = el("input", { class: "in", type: "time", value: saved.quiet_to });
      var rate = el("input", { class: "in", type: "number", min: 1, max: 1000, step: 1, required: true, value: saved.rate_per_minute });
      var message = el("p", { class: "callout", role: "status", "aria-live": "polite" });
      var categories = [], buttons = [];
      var kindFields = el("fieldset", { class: "tg-kinds" }, [el("legend", { class: "lbl", text: t("tg.categories") })]);
      saved.available_kinds.forEach(function (kind) {
        var input = el("input", { type: "checkbox", checked: saved.kinds.indexOf(kind) >= 0 });
        categories.push({ kind: kind, input: input }); add(kindFields, check(input, t("kind." + kind)));
      });
      function draft() {
        var values = ids.value.trim() ? ids.value.trim().split(/[\s,;]+/) : [];
        var chatIDs = values.map(function (v) {
          if (!/^-?[0-9]+$/.test(v) || !Number.isSafeInteger(Number(v)) || Number(v) === 0) { throw new Error(t("tg.ids.invalid")); }
          return Number(v);
        });
        return { enabled: enabled.checked, token: token.value.trim(), chat_ids: chatIDs,
          kinds: categories.filter(function (v) { return v.input.checked; }).map(function (v) { return v.kind; }),
          min_severity: severity.value, quiet_from: from.value, quiet_to: to.value,
          rate_per_minute: Number(rate.value), bans: bans.checked, startup_notice: startup.checked };
      }
      var form, controls;
      function perform(operation) {
        if (busy || !form.reportValidity()) { return; }
        var payload;
        try { payload = draft(); } catch (e) { message.textContent = e.message; return; }
        busy = true; controls.disabled = true;
        buttons.forEach(function (b) { b.disabled = true; }); message.textContent = t("tg.busy");
        A.api.telegramAction(operation, payload).then(function (view) {
          payload.token = "";
          if (!dlg.isConnected) { return; }
          message.textContent = t("tg.done." + operation) + (view.bot_username ? " @" + view.bot_username : "");
          if (operation === "save") {
            token.value = ""; token.type = "password"; show.textContent = t("tg.show"); show.setAttribute("aria-pressed", "false");
            token.placeholder = view.has_token ? t("tg.token.saved") : "123456:...";
          }
        }, function (e) { payload.token = ""; if (dlg.isConnected) { message.textContent = e.message || t("err.generic"); } }).then(function () {
          busy = false; controls.disabled = false; buttons.forEach(function (b) { b.disabled = false; });
        });
      }
      function button(operation) {
        var b = el("button", { type: "button", class: "pill" + (operation === "save" ? " pill-solid" : ""), text: t("tg." + operation), onclick: function () { perform(operation); } });
        buttons.push(b); return b;
      }
      var show = el("button", { type: "button", class: "pill pill-quiet", "aria-pressed": "false", text: t("tg.show"), onclick: function () {
        var visible = token.type === "password"; token.type = visible ? "text" : "password";
        show.textContent = t(visible ? "tg.hide" : "tg.show"); show.setAttribute("aria-pressed", String(visible));
      } });
      controls = el("fieldset", { class: "tg-controls" }, [check(enabled, t("tg.enabled")), field(t("tg.token"), token), show,
        field(t("tg.ids"), ids), kindFields, check(bans, t("tg.bans")), check(startup, t("tg.startup")),
        el("div", { class: "form-row" }, [field(t("policy.min_sev"), severity), field(t("policy.rate"), rate)]),
        el("div", { class: "form-row" }, [field(t("tg.quiet.from"), from), field(t("tg.quiet.to"), to)])]);
      form = el("form", { class: "dlg", onsubmit: function (ev) { ev.preventDefault(); perform("save"); } }, [
        el("h2", { id: "tg-heading", text: t("tg.title") }), el("p", { class: "callout", text: t("tg.help") }), controls,
        el("p", { class: "callout", text: t("tg.policy.note") }), message,
        el("div", { class: "btns" }, [button("verify"), button("test"), button("save"), el("button", { class: "pill pill-quiet", type: "button", text: t("common.cancel"), onclick: function () { dlg.close(); } })])
      ]);
      dlg.addEventListener("close", function () {
        token.value = ""; A.clear(dlg); dlg.remove(); dialog = null;
        if (trigger && trigger.isConnected) { trigger.focus(); }
      }, { once: true });
      add(dlg, form); add(document.body, dlg); dlg.showModal(); token.focus();
    }, function (e) { A.toast(e.message || t("err.generic"), "err"); });
  }
  function paint(host, tg) {
    A.clear(host);
    add(host, [el("h3", { class: "sub-h", text: t("tg.title") }),
      el("p", { class: "callout", text: tg ? t("tg.status." + tg.status) + (tg.bot_username ? " @" + tg.bot_username : "") : t("common.unknown") }),
      el("p", { class: "callout", text: tg && tg.last_delivery && tg.last_delivery.indexOf("0001-") !== 0 ? t("tg.last") + " " + A.dateTime(tg.last_delivery) : t("tg.not.delivered") }),
      el("button", { class: "pill pill-solid", type: "button", text: t("tg.configure"), disabled: A.state.mock, onclick: open })]);
    if (tg && tg.last_error) { add(host, el("p", { class: "err", text: t("tg.error." + tg.last_error) })); }
  }
  A.Telegram = { paint: paint, close: close };
})();
