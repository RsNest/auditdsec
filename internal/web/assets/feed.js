/* auditdsec panel: the throwable deck of events and the full journal.
   Both show text taken from the audit log, so it is only ever set through
   textContent. Actions are handed in by the caller, which owns the API. */
(function () {
  "use strict";

  var A = window.ADS;
  var el = A.el, add = A.add, clear = A.clear, t = A.t;

  function sevTag(sev) {
    return el("span", { class: "sevtag", dataset: { sev: sev } }, [
      el("i", { class: "dot" }), el("span", { text: t("sev." + sev) })
    ]);
  }

  /* ---------------- the deck ---------------- */

  function blocked(ip, bans) {
    return (bans || []).some(function (b) {
      return b.ip === ip && b.applied && (b.permanent || Date.parse(b.until) > Date.now());
    });
  }

  function protectedIP(ip, allow) {
    return (allow || []).some(function (a) { return a.ip === ip; });
  }

  function deckSignature(list) {
    return list.map(function (e) { return e.id + ":" + (e.attempts || "") + ":" + (e.review_state || ""); }).join(",");
  }

  function selectDeck(events, suspects, bans, allow) {
    var candidates = (events || []).filter(function (ev) {
      // Failures use the per-address review queue, not the last 200 raw rows.
      if (suspects && ev.kind === "ssh_login_fail") { return false; }
      return !ev.src_ip || ev.severity === "critical" ||
        (!blocked(ev.src_ip, bans) && !protectedIP(ev.src_ip, allow));
    });
    (suspects && suspects.items || []).forEach(function (s) {
      if (blocked(s.ip, bans) || protectedIP(s.ip, allow)) { return; }
      var ev = Object.assign({}, s.event, { attempts: s.attempts, review_state: s.state });
      candidates.push(ev);
    });
    candidates.sort(function (a, b) {
      return (A.SEV_RANK[b.severity] - A.SEV_RANK[a.severity]) ||
        (Number(b.review_state === "needs_attention") - Number(a.review_state === "needs_attention")) ||
        ((a.attempts || 0) - (b.attempts || 0)) || (a.time < b.time ? 1 : -1);
    });
    var seen = Object.create(null), selected = [];
    candidates.forEach(function (ev) {
      var key = ev.kind === "ssh_login_fail" ? "failure:" + ev.src_ip : ev.kind + "|" + (ev.src_ip || ev.user || "");
      if (selected.length < 7 && !seen[key]) { seen[key] = true; selected.push(ev); }
    });
    return selected;
  }

  function banButton(ev, actions) {
    var b = el("button", {
      class: "pill pill-danger pill-sm", type: "button", dataset: { banIp: ev.src_ip },
      disabled: !actions.canBan(ev.src_ip),
      text: actions.isBlocked(ev.src_ip) ? t("bans.state.applied") : t("ev.act.ban", { ip: ev.src_ip }),
      onclick: function () { actions.ban(ev.src_ip, "24h", "panel: " + ev.kind); }
    });
    return b;
  }

  function pose(rank) {
    var dir = rank % 2 ? 1 : -1;
    return "translate(" + rank * 14 + "px," + -rank * 11 + "px) scale(" + (1 - rank * 0.045) + ") rotate(" + dir * rank * 1.5 + "deg)";
  }

  function Deck(host, actions) {
    var items = [], nodes = [], order = [], pos = 0, busy = false, drag = null, generation = 0;
    var stage = el("div", { class: "deck", tabindex: "0", role: "group", "aria-label": t("deck.aria") });
    var dots = el("div", { class: "dots", "aria-hidden": "true" });
    var hint = el("p", { class: "hint", text: t("deck.hint") });
    var live = el("span", { class: "sr", role: "status", "aria-live": "polite" });
    add(host, [stage, dots, hint, live]);

    function card(ev) {
      var buttons = [];
      if (ev.src_ip && A.bannable(ev.src_ip)) {
        buttons.push(banButton(ev, actions));
      }
      if (ev.src_ip) {
        buttons.push(el("button", {
          class: "pill pill-quiet pill-sm", type: "button", text: t("ev.act.trust"),
          onclick: function () { actions.trust(ev.src_ip); }
        }));
      }
      return el("article", { class: "dcard", dataset: { sev: ev.severity } }, [
        el("div", { class: "dc-top" }, [sevTag(ev.severity), el("span", { class: "lbl", text: A.relative(ev.time) })]),
        el("div", null, [
          el("h3", { class: "dc-title", text: ev.summary || t("kind." + ev.kind) }),
          el("p", { class: "dc-kind", text: ev.attempts ? t("suspects.attempts", { count: ev.attempts }) : t("kind." + ev.kind) }),
          ev.review_state === "needs_attention" ? el("p", { class: "err", text: t("suspects.attention") }) : null
        ]),
        el("div", { class: "dc-foot" }, [
          el("div", { class: "dc-meta" }, [
            ev.src_ip ? el("span", { class: "mono", text: ev.src_ip }) : null,
            ev.user ? el("span", { text: ev.user }) : null
          ]),
          el("div", { class: "dc-actions" }, buttons)
        ])
      ]);
    }

    function layout(snapIdx) {
      order.forEach(function (idx, rank) {
        var node = nodes[idx];
        if (idx === snapIdx) { node.classList.add("snap"); }
        node.classList.remove("drag");
        var visible = rank <= 4;
        node.style.transform = pose(Math.min(rank, 4));
        node.style.opacity = visible ? "1" : "0";
        node.style.zIndex = String(100 - rank);
        node.style.pointerEvents = rank === 0 ? "auto" : "none";
        node.setAttribute("aria-hidden", rank === 0 ? "false" : "true");
        if (idx === snapIdx) {
          void node.offsetWidth;
          node.classList.remove("snap");
        }
      });
      Array.prototype.forEach.call(dots.children, function (d, i) { d.className = i === pos ? "on" : ""; });
      live.textContent = items.length ? t("deck.pos", { n: pos + 1, total: items.length }) : "";
    }

    function toss(dir) {
      if (busy || order.length < 2) { return; }
      busy = true;
      var version = generation;
      var idx = order[0], node = nodes[idx];
      node.classList.remove("drag");
      node.style.transform = "translate(" + dir * stage.offsetWidth * 1.15 + "px,-30px) rotate(" + dir * 22 + "deg)";
      node.style.opacity = "0";
      setTimeout(function () {
        if (version !== generation) { return; }
        order.push(order.shift());
        pos = (pos + 1) % items.length;
        layout(idx);
        busy = false;
      }, 380);
    }

    function bringBack() {
      if (busy || order.length < 2) { return; }
      busy = true;
      var version = generation;
      var idx = order.pop(), node = nodes[idx];
      node.classList.add("snap");
      node.style.transform = "translate(" + -stage.offsetWidth * 1.15 + "px,-30px) rotate(-22deg)";
      node.style.opacity = "0";
      void node.offsetWidth;
      node.classList.remove("snap");
      order.unshift(idx);
      pos = (pos - 1 + items.length) % items.length;
      requestAnimationFrame(function () { if (version === generation) { layout(); busy = false; } });
    }

    stage.addEventListener("pointerdown", function (e) {
      if (busy || !order.length || (e.pointerType === "mouse" && e.button !== 0)) { return; }
      if (e.target.closest("button, a")) { return; }
      var node = nodes[order[0]];
      if (!node || !node.contains(e.target)) { return; }
      drag = { id: e.pointerId, x: e.clientX, y: e.clientY, dx: 0, node: node };
      try { stage.setPointerCapture(e.pointerId); } catch (err) { /* capture is a nicety */ }
      node.classList.add("drag");
    });
    stage.addEventListener("pointermove", function (e) {
      if (!drag || e.pointerId !== drag.id) { return; }
      drag.dx = e.clientX - drag.x;
      var dy = (e.clientY - drag.y) * 0.25;
      drag.node.style.transform = "translate(" + drag.dx + "px," + dy + "px) rotate(" + drag.dx * 0.05 + "deg) scale(1.02)";
    });
    function release(e, thrown) {
      if (!drag || e.pointerId !== drag.id) { return; }
      var d = drag;
      drag = null;
      d.node.classList.remove("drag");
      try { stage.releasePointerCapture(e.pointerId); } catch (err) { /* already released */ }
      if (thrown && Math.abs(d.dx) > stage.offsetWidth * 0.1 && order.length > 1) { toss(d.dx > 0 ? 1 : -1); }
      else { layout(); }
    }
    stage.addEventListener("pointerup", function (e) { release(e, true); });
    stage.addEventListener("pointercancel", function (e) { release(e, false); });
    stage.addEventListener("keydown", function (e) {
      if (e.key === "ArrowRight") { e.preventDefault(); toss(1); }
      else if (e.key === "ArrowLeft") { e.preventDefault(); bringBack(); }
    });

    function set(list) {
      generation++;
      var hadFocus = stage.contains(document.activeElement);
      items = list || [];
      clear(stage); clear(dots);
      nodes = []; order = []; pos = 0; busy = false; drag = null;
      hint.hidden = items.length < 2;
      if (hadFocus) { stage.focus({ preventScroll: true }); }
      if (!items.length) {
        add(stage, el("div", { class: "deck-empty", text: t("deck.empty") }));
        return;
      }
      items.forEach(function (ev, i) {
        var node = card(ev);
        nodes.push(node); order.push(i);
        stage.appendChild(node);
        if (i < 9) { dots.appendChild(el("i")); }
      });
      layout();
    }

    function advanceFromIP(ip) {
      if (!order.length || items[order[0]].src_ip !== ip) { return; }
      var next = order.findIndex(function (idx) { return items[idx].src_ip !== ip; });
      if (next < 1) { return; }
      // Critical evidence remains in the deck, but a successful ban still
      // moves the operator to the next address instead of keeping that card.
      generation++; busy = false; drag = null;
      order = order.slice(next).concat(order.slice(0, next));
      pos = (pos + next) % items.length;
      layout();
    }

    return { set: set, advanceFromIP: advanceFromIP, signature: function () { return deckSignature(items); } };
  }

  /* ---------------- journal rows ---------------- */

  function detail(ev, actions) {
    var explainBox = el("div", { class: "explain" }, el("p", { class: "callout", text: t("ev.detail.pending") }));
    A.explain(ev.kind).then(function (data) {
      clear(explainBox);
      if (!data || (!data.what && !data.risk && !data.todo)) {
        add(explainBox, el("p", { class: "callout", text: t("ev.detail.missing") }));
        return;
      }
      [["ev.detail.what", data.what], ["ev.detail.risk", data.risk], ["ev.detail.todo", data.todo]].forEach(function (pair) {
        add(explainBox, el("div", null, [el("span", { class: "lbl", text: t(pair[0]) }), el("p", { text: pair[1] || "—" })]));
      });
    });

    var buttons = [];
    if (ev.src_ip && A.bannable(ev.src_ip)) {
      buttons.push(banButton(ev, actions));
    }
    if (ev.src_ip) {
      buttons.push(el("button", { class: "pill pill-quiet pill-sm", type: "button", text: t("ev.act.trust"), onclick: function () { actions.trust(ev.src_ip); } }));
    }
    buttons.push(el("button", { class: "pill pill-quiet pill-sm", type: "button", text: t("ev.act.mute"), onclick: function () { actions.mute(24); } }));

    var facts = [[t("ev.time"), A.dateTime(ev.time)]];
    if (ev.user) { facts.push([t("ev.user"), ev.user]); }
    if (ev.src_ip) { facts.push([t("ev.ip"), ev.src_ip]); }
    if (ev.args) {
      Object.keys(ev.args).forEach(function (k) {
        if (k !== "user" && k !== "ip") { facts.push([k, String(ev.args[k])]); }
      });
    }

    return el("div", { class: "jdetail" }, [
      explainBox,
      el("div", { class: "facts-inline" }, facts.map(function (f) {
        return el("div", null, [el("span", { class: "lbl", text: f[0] }), el("span", { class: "mono", text: f[1] })]);
      })),
      contextBlock(ev),
      ev.raw ? el("div", { class: "raw" }, [
        el("div", { class: "raw-head" }, [el("span", { class: "lbl", text: t("ev.detail.raw") }), copyButton(ev.raw)]),
        el("code", { text: ev.raw })
      ]) : null,
      el("div", { class: "btns" }, buttons)
    ]);
  }

  /* Who did it, as logged in and as run, plus the session; unknown stays unknown. */
  function contextRows(ev) {
    var c = ev.context;
    if (!c) { return []; }
    var who = function (name, uid) { return name || (uid ? "uid " + uid : ""); };
    var rows = [];
    var login = who(c.login_user, c.login_uid);
    var eff = who(c.effective_user, c.effective_uid);
    if (login) { rows.push([t("ev.ctx.login"), login]); }
    if (eff) { rows.push([t("ev.ctx.effective"), eff]); }
    var s = c.session;
    if (s) {
      var where = s.addr ? s.addr + (s.port ? ":" + s.port : "") : t("ev.ctx.unknown");
      var note = s.confidence === "observed" ? t("ev.ctx.observed")
        : s.confidence === "correlated" ? t("ev.ctx.correlated") : (s.note || "");
      rows.push([t("ev.ctx.session"), where + (note ? " — " + note : "") + (s.ended ? " (" + t("ev.ctx.ended") + ")" : "")]);
    }
    if (c.session_id) { rows.push([t("ev.ctx.session_id"), c.session_id]); }
    var proc = [c.exe, c.pid && "pid " + c.pid, c.ppid && "ppid " + c.ppid].filter(Boolean).join(" · ");
    if (proc) { rows.push([t("ev.ctx.process"), proc]); }
    if (c.command) { rows.push([t("ev.ctx.command"), c.command]); }
    return rows;
  }

  function contextBlock(ev) {
    var rows = contextRows(ev);
    if (!rows.length) { return null; }
    return el("div", { class: "facts-inline ctx" }, [el("span", { class: "lbl", text: t("ev.ctx.title") })].concat(rows.map(function (r) {
      return el("div", null, [el("span", { class: "lbl", text: r[0] }), el("span", { class: "mono", text: r[1] })]);
    })));
  }

  function copyButton(text) {
    var b = el("button", {
      class: "lnk", type: "button", text: t("common.copy"),
      onclick: function () {
        var done = function () { b.textContent = t("common.copied"); };
        if (navigator.clipboard && navigator.clipboard.writeText) { navigator.clipboard.writeText(text).then(done, function () { }); }
        else { done(); }
      }
    });
    return b;
  }

  function row(ev, actions) {
    var wrap = el("div");
    var open = null;
    var btn = el("button", { class: "jrow", type: "button", "aria-expanded": "false" }, [
      el("span", { class: "t", text: A.clock(ev.time) }),
      sevTag(ev.severity),
      el("span", { class: "s", text: ev.summary || t("kind." + ev.kind) }),
      el("span", { class: "ip", text: ev.src_ip || "" }),
      el("span", { class: "chev", "aria-hidden": "true", text: "⌄" })
    ]);
    btn.addEventListener("click", function () {
      var isOpen = btn.getAttribute("aria-expanded") === "true";
      btn.setAttribute("aria-expanded", isOpen ? "false" : "true");
      if (isOpen) { if (open) { wrap.removeChild(open); open = null; } return; }
      open = detail(ev, actions);
      wrap.appendChild(open);
    });
    add(wrap, btn);
    return wrap;
  }

  /* ---------------- the journal ---------------- */

  function Journal(host, actions) {
    var f = { severity: "", kind: "", ip: "", user: "", q: "", period: "24h" };
    var items = [], next = null, loading = false;

    var ipIn = el("input", { class: "in", type: "text", placeholder: "203.0.113.7", autocomplete: "off", spellcheck: "false" });
    var userIn = el("input", { class: "in", type: "text", placeholder: "root", autocomplete: "off", spellcheck: "false" });
    var searchIn = el("input", { class: "in", type: "search", id: "ev-search", placeholder: t("ev.search.ph"), autocomplete: "off" });
    var changed = A.debounce(function () { f.ip = ipIn.value.trim(); f.user = userIn.value.trim(); f.q = searchIn.value.trim(); reset(); }, 350);
    [ipIn, userIn, searchIn].forEach(function (n) { n.addEventListener("input", changed); });

    var chips = el("div", { class: "chips" }, [""].concat(A.SEVS).map(function (s) {
      return el("button", {
        class: "lnk", type: "button", dataset: { sev: s }, text: s ? t("sev." + s) : t("sev.any"),
        "aria-pressed": s === "" ? "true" : "false",
        onclick: function () { setSeverity(s); }
      });
    }));
    var kindSel = A.el("select", { class: "sel", onchange: function (e) { f.kind = e.target.value; reset(); } },
      [{ v: "", l: t("kind.any") }].concat(A.KINDS.map(function (k) { return { v: k, l: t("kind." + k) }; })).map(function (o) {
        return el("option", { value: o.v, text: o.l });
      }));
    var periodSel = el("select", { class: "sel", onchange: function (e) { f.period = e.target.value; reset(); } },
      ["1h", "24h", "7d", "all"].map(function (p) { return el("option", { value: p, text: t("ev.period." + p), selected: p === f.period }); }));

    function fld(label, control) {
      return el("div", { class: "fld" }, [el("label", { class: "lbl", text: label }), control]);
    }
    var count = el("span", { class: "count" });
    var list = el("div", { class: "jlist" });
    var more = el("button", { class: "pill", type: "button", text: t("ev.loadmore"), hidden: true, onclick: function () { load(true); } });

    add(host, [
      el("div", { class: "filters" }, [
        el("div", { class: "fld wide" }, [el("span", { class: "lbl", text: t("ev.sev") }), chips]),
        fld(t("ev.kind"), kindSel), fld(t("ev.period"), periodSel),
        fld(t("ev.ip"), ipIn), fld(t("ev.user"), userIn), fld(t("ev.search"), searchIn),
        el("div", { class: "fld" }, [
          count,
          el("button", { class: "lnk", type: "button", text: t("ev.reset"), onclick: resetFilters })
        ])
      ]),
      list,
      el("div", { class: "btns" }, more)
    ]);

    function setSeverity(s) {
      f.severity = s;
      Array.prototype.forEach.call(chips.children, function (c) { c.setAttribute("aria-pressed", c.dataset.sev === s ? "true" : "false"); });
      reset();
    }
    function resetFilters() {
      f = { severity: "", kind: "", ip: "", user: "", q: "", period: "24h" };
      ipIn.value = ""; userIn.value = ""; searchIn.value = ""; kindSel.value = ""; periodSel.value = "24h";
      setSeverity("");
    }

    function query(cursor) {
      var p = ["limit=50"];
      ["severity", "kind", "ip", "user", "q"].forEach(function (k) { if (f[k]) { p.push(k + "=" + encodeURIComponent(f[k])); } });
      if (f.period !== "all") {
        var ms = f.period === "1h" ? 3600e3 : f.period === "7d" ? 7 * 86400e3 : 86400e3;
        p.push("since=" + encodeURIComponent(new Date(Date.now() - ms).toISOString()));
      }
      if (cursor) { p.push("before=" + encodeURIComponent(cursor)); }
      return p.join("&");
    }

    function paint() {
      clear(list);
      if (!items.length) { add(list, el("div", { class: "empty", text: loading ? t("common.loading") : t("ev.empty") })); }
      else { items.forEach(function (ev) { add(list, row(ev, actions)); }); }
      count.textContent = t("ev.count", { count: A.num(items.length) });
      more.hidden = !next;
    }

    function load(append) {
      loading = true;
      return A.api.events(query(append ? next : null)).then(function (page) {
        loading = false;
        var batch = (page && page.items) || [];
        items = append ? items.concat(batch) : batch;
        next = (page && page.next) || null;
        A.announceCritical(items);
        paint();
      }, function (e) {
        loading = false;
        paint();
        if (e.code !== "offline") { A.toast(e.message || t("err.generic"), "err"); }
      });
    }
    function reset() { items = []; next = null; paint(); return load(false); }

    paint();
    return {
      reload: reset,
      refresh: function () { if (!next && !list.querySelector("[aria-expanded=true]") && document.activeElement.tagName !== "INPUT") { return load(false); } },
      setKind: function (k) { f.kind = k; kindSel.value = k; return reset(); },
      setSeverity: setSeverity
    };
  }

  window.ADS.feed = { contextRows: contextRows, Deck: Deck, Journal: Journal, row: row, sevTag: sevTag,
    selectDeck: selectDeck, deckSignature: deckSignature, blocked: blocked, protectedIP: protectedIP, banButton: banButton };
})();
