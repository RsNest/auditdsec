/* auditdsec panel views. Each view renders into <main> and may return
   { poll, reload } so the 10-second refresh and post-action reloads find it. */
(function () {
  "use strict";

  var A = window.ADS;
  var el = A.el, add = A.add, clear = A.clear, icon = A.icon, t = A.t;
  var card = A.card, empty = A.empty, skeleton = A.skeleton, field = A.field;
  var NS = A.SVG_NS;

  function sv(tag, attrs, text) {
    var n = document.createElementNS(NS, tag);
    if (attrs) { for (var k in attrs) { n.setAttribute(k, attrs[k]); } }
    if (text !== undefined && text !== null) { n.textContent = text; }
    return n;
  }

  function reloadCurrent() {
    A.loadStatus();
    var v = A.state.view;
    if (v && typeof v.reload === "function") { v.reload(); }
  }

  function mapError(e) {
    if (!e) { return t("err.generic"); }
    if (e.code === "allowlisted") { return t("err.allowlisted"); }
    if (e.code === "offline") { return t("err.offline"); }
    return e.message || t("err.generic");
  }

  /* ---------------- actions shared by several views ---------------- */

  function banAddress(ip, duration, reason) {
    if (!A.bannable(ip)) { A.toast(t("err.private_ip"), "err"); return; }
    A.confirmAction(
      t("bans.form.confirm", { ip: ip, duration: t("bans.dur." + duration) }),
      t("bans.form.submit"), "danger"
    ).then(function (ok) {
      if (!ok) { return; }
      A.api.ban({ ip: ip, duration: duration, reason: reason || "panel" }).then(function () {
        A.toast(t("bans.form.done", { ip: ip }), "ok");
        reloadCurrent();
      }, function (e) { A.toast(mapError(e), "err"); });
    });
  }

  function allowAddress(ip) {
    A.api.allow(ip).then(function () {
      A.toast(t("allow.form.done", { ip: ip }), "ok");
      reloadCurrent();
    }, function (e) { A.toast(mapError(e), "err"); });
  }

  function muteAlerts(hours) {
    A.api.mute(hours).then(function (res) {
      A.toast(t("policy.mute.done", { until: A.dateTime(res && res.muted_until) }), "ok");
      reloadCurrent();
    }, function (e) { A.toast(mapError(e), "err"); });
  }

  /* ---------------- event row ---------------- */

  function eventRow(ev) {
    var wrap = el("div");
    var detail = null;

    var btn = el("button", { class: "row", type: "button", "aria-expanded": "false" }, [
      el("div", { class: "row-main" }, [
        el("div", { class: "row-icon", dataset: { sev: ev.severity } }, icon(A.KIND_ICON[ev.kind] || "info")),
        el("div", { class: "row-body" }, [
          el("div", { class: "row-meta" }, [
            el("span", { class: "time", text: A.clock(ev.time) }),
            A.severity(ev.severity),
            el("span", { class: "tag", text: t("kind." + ev.kind) })
          ]),
          el("div", { class: "row-text", text: ev.summary || t("kind." + ev.kind) })
        ]),
        el("div", { class: "row-side" }, [
          ev.src_ip ? el("span", { class: "mono", text: ev.src_ip }) : null,
          ev.user ? el("small", { text: ev.user }) : null
        ]),
        icon("chevron", "row-chev")
      ])
    ]);

    btn.addEventListener("click", function () {
      var open = btn.getAttribute("aria-expanded") === "true";
      btn.setAttribute("aria-expanded", open ? "false" : "true");
      if (open) {
        if (detail) { wrap.removeChild(detail); detail = null; }
        return;
      }
      detail = buildDetail(ev);
      wrap.appendChild(detail);
    });

    add(wrap, btn);
    return wrap;
  }

  function buildDetail(ev) {
    var explain = el("div", { class: "explain" }, el("p", { class: "muted", text: t("ev.detail.pending") }));
    A.explain(ev.kind).then(function (data) {
      clear(explain);
      if (!data || (!data.what && !data.risk && !data.todo)) {
        add(explain, el("p", { class: "muted", text: t("ev.detail.missing") }));
        return;
      }
      [["ev.detail.what", data.what], ["ev.detail.risk", data.risk], ["ev.detail.todo", data.todo]]
        .forEach(function (pair) {
          add(explain, el("div", null, [
            el("h4", { class: "label", text: t(pair[0]) }),
            el("p", { text: pair[1] || "—" })
          ]));
        });
    });

    var actions = [];
    if (ev.src_ip) {
      if (A.bannable(ev.src_ip)) {
        actions.push(el("button", {
          class: "btn btn-danger btn-sm", type: "button",
          text: t("ev.act.ban", { ip: ev.src_ip }),
          onclick: function () { banAddress(ev.src_ip, "24h", "panel: " + ev.kind); }
        }));
      }
      actions.push(el("button", {
        class: "btn btn-sm", type: "button", text: t("ev.act.trust"),
        onclick: function () { allowAddress(ev.src_ip); }
      }));
    }
    actions.push(el("button", {
      class: "btn btn-sm", type: "button", text: t("ev.act.mute"),
      onclick: function () { muteAlerts(24); }
    }));

    var facts = [];
    if (ev.user) { facts.push(["ev.user", ev.user]); }
    if (ev.src_ip) { facts.push(["ev.ip", ev.src_ip]); }
    if (ev.args) {
      Object.keys(ev.args).forEach(function (k) {
        if (k === "user" || k === "ip") { return; }
        facts.push([null, null, k, ev.args[k]]);
      });
    }

    return el("div", { class: "detail" }, [
      explain,
      el("div", { class: "kv" }, [
        el("div", null, [
          el("span", { class: "label", text: t("ev.time") }),
          el("b", { text: A.dateTime(ev.time) })
        ])
      ].concat(facts.map(function (f) {
        return el("div", null, [
          el("span", { class: "label", text: f[0] ? t(f[0]) : f[2] }),
          el("b", { class: "mono", text: f[0] ? f[1] : String(f[3]) })
        ]);
      }))),
      ev.raw ? el("div", { class: "raw" }, [
        el("div", { class: "raw-head" }, [
          el("span", { class: "label", text: t("ev.detail.raw") }),
          A.copyButton(ev.raw)
        ]),
        el("code", { text: ev.raw })
      ]) : null,
      el("div", { class: "actions" }, actions)
    ]);
  }

  /* ---------------- hourly chart ---------------- */

  function hourlyChart(hourly) {
    var data = (hourly || []).slice(-24);
    if (!data.length) { return empty(t("chart.empty")); }

    var W = 720, H = 150, BASE = 120, TOP = 12;
    var svg = sv("svg", { viewBox: "0 0 " + W + " " + H, class: "chart", role: "img" });
    svg.setAttribute("aria-label", t("chart.title"));

    var max = 1;
    data.forEach(function (h) {
      max = Math.max(max, (h.info || 0) + (h.warn || 0) + (h.critical || 0));
    });
    svg.appendChild(sv("line", { x1: 0, y1: BASE + .5, x2: W, y2: BASE + .5, class: "grid-line" }));
    svg.appendChild(sv("line", { x1: 0, y1: TOP + .5, x2: W, y2: TOP + .5, class: "grid-line" }));
    svg.appendChild(sv("text", { x: 2, y: TOP - 3 }, String(max)));

    var slot = W / data.length;
    var bw = Math.min(22, slot * .62);

    data.forEach(function (h, i) {
      var info = h.info || 0, warn = h.warn || 0, crit = h.critical || 0;
      var total = info + warn + crit;
      var x = i * slot + (slot - bw) / 2;
      var g = sv("g");
      g.appendChild(sv("title", null, t("chart.tip", {
        hour: A.hourLabel(h.hour), info: info, warn: warn, critical: crit
      })));
      if (total === 0) {
        g.appendChild(sv("rect", { x: x, y: BASE - 2, width: bw, height: 2, rx: 1, class: "bar-zero" }));
      } else {
        var y = BASE;
        [["bar-info", info], ["bar-warn", warn], ["bar-crit", crit]].forEach(function (part) {
          if (!part[1]) { return; }
          var hgt = Math.max(2, (part[1] / max) * (BASE - TOP));
          y -= hgt;
          g.appendChild(sv("rect", { x: x, y: y, width: bw, height: hgt, rx: 2, class: part[0] }));
        });
      }
      if (i % 4 === 0) {
        g.appendChild(sv("text", { x: i * slot + slot / 2, y: BASE + 16, "text-anchor": "middle" },
          A.hourLabel(h.hour)));
      }
      svg.appendChild(g);
    });

    return el("div", null, [
      svg,
      el("div", { class: "legend" }, A.SEVS.map(function (s) {
        var swatch = el("i");
        swatch.style.background = "var(--" + (s === "critical" ? "crit" : s) + ")";
        return el("span", null, [swatch, el("span", { text: t("sev." + s) })]);
      }))
    ]);
  }

  /* ---------------- overview ---------------- */

  function statusBanner(status) {
    var lv = A.level(status);
    var down = status && status.auditd && status.auditd.healthy === false;
    var counters = (status && status.counters) || {};
    var titleKey, subKey, vars = {}, ico;
    if (down) {
      titleKey = "status.down.title"; subKey = "status.down.sub"; ico = "power";
    } else if (lv === "crit") {
      titleKey = "status.crit.title"; subKey = "status.crit.sub"; ico = "alertOctagon";
      vars.count = A.num(counters.critical_24h);
    } else if (lv === "warn") {
      titleKey = "status.warn.title"; subKey = "status.warn.sub"; ico = "alertTriangle";
      vars.count = A.num(counters.warn_24h);
    } else {
      titleKey = "status.ok.title"; subKey = "status.ok.sub"; ico = "checkCircle";
    }
    return el("div", { class: "banner tone-" + (lv === "unknown" ? "ok" : lv) }, [
      icon(ico),
      el("div", null, [
        el("h1", { text: t(titleKey) }),
        el("p", { text: t(subKey, vars) }),
        status ? el("p", {
          text: t("status.meta", {
            host: status.host || t("common.unknown"),
            time: status.auditd && status.auditd.last_write ? A.relative(status.auditd.last_write) : t("common.never")
          })
        }) : null
      ])
    ]);
  }

  A.routes[""] = function (main) {
    var box = el("div", { class: "view" });
    add(main, box);

    function paint(status, events) {
      clear(box);
      if (!status) { add(box, skeleton()); return; }
      var c = status.counters || {};
      var ban = status.ban || {};
      var down = status.auditd && status.auditd.healthy === false;

      add(box, statusBanner(status));

      if (down) {
        add(box, el("div", { class: "notice tone-crit" }, [
          icon("power"),
          el("div", null, [
            el("h3", { text: t("health.title") }),
            el("p", { text: t("health.stale") }),
            el("p", { class: "muted" }, [
              el("span", { text: t("health.last_write") + ": " }),
              el("span", { text: A.dateTime(status.auditd && status.auditd.last_write) }),
              el("span", { text: " · " }),
              el("code", { text: "systemctl status auditd" })
            ])
          ])
        ]));
      }
      if (!ban.enforcing) {
        add(box, el("div", { class: "notice tone-warn" }, [
          icon("shieldOff"),
          el("div", null, [
            el("h3", { text: t("enforce.title") }),
            el("p", { text: t("enforce.body") }),
            el("p", { class: "muted", text: t("enforce.howto") })
          ])
        ]));
      } else if (ban.dry_run) {
        add(box, el("div", { class: "notice tone-warn" }, [
          icon("info"),
          el("div", null, [el("h3", { text: t("enforce.title") }), el("p", { text: t("enforce.dry_run") })])
        ]));
      }

      add(box, el("div", { class: "stats" }, [
        A.statCard(t("card.events24"), A.num(c.events_24h), { icon: "activity" }),
        A.statCard(t("card.critical24"), A.num(c.critical_24h), {
          icon: "alertOctagon", tone: c.critical_24h > 0 ? "crit" : null
        }),
        A.statCard(t("card.warn24"), A.num(c.warn_24h), {
          icon: "alertTriangle", tone: c.warn_24h > 0 ? "warn" : null
        }),
        A.statCard(t("card.bans"), A.num(status.bans_active), { icon: "shieldOff" }),
        A.statCard(t("card.allowlist"), A.num(status.allowlist_count), { icon: "shield" }),
        A.statCard(t("card.uptime"), A.duration(status.uptime_seconds), {
          icon: "clock", note: status.version ? "v" + status.version : null
        })
      ]));

      add(box, card(t("chart.title"), hourlyChart(status.hourly), { icon: "activity" }));

      var rows;
      if (!events) { rows = skeleton(); }
      else if (!events.length) { rows = empty(t("ev.empty")); }
      else {
        rows = el("div", { class: "rows" });
        events.slice(0, 8).forEach(function (ev) { add(rows, eventRow(ev)); });
      }
      add(box, card(t("recent.title"), rows, {
        icon: "list", flush: true,
        aside: el("a", { href: "#/events", text: t("recent.all") })
      }));
    }

    function load() {
      var status = A.state.status;
      A.api.events("limit=8").then(function (page) {
        var items = (page && page.items) || [];
        A.announceCritical(items);
        paint(status, items);
      }, function () { paint(status, []); });
    }

    paint(A.state.status, null);
    load();
    return { poll: load, reload: load };
  };

  /* ---------------- events ---------------- */

  A.routes.events = function (main) {
    var filters = { severity: "", kind: "", ip: "", user: "", q: "", period: "24h" };
    var items = [], next = null, loading = false;

    var head = el("div", { class: "view-head" }, [
      el("h1", { text: t("ev.title") }),
      el("button", {
        class: "btn btn-sm", type: "button", onclick: function () { reset(false); }
      }, [icon("refresh"), el("span", { text: t("common.refresh") })])
    ]);

    var search = el("input", {
      class: "input", type: "search", id: "ev-search",
      placeholder: t("ev.search.ph"), value: filters.q
    });
    search.addEventListener("input", debounce(function () { filters.q = search.value.trim(); reset(false); }, 350));

    var ipInput = el("input", { class: "input", type: "text", placeholder: "203.0.113.7" });
    ipInput.addEventListener("input", debounce(function () { filters.ip = ipInput.value.trim(); reset(false); }, 350));
    var userInput = el("input", { class: "input", type: "text", placeholder: "root" });
    userInput.addEventListener("input", debounce(function () { filters.user = userInput.value.trim(); reset(false); }, 350));

    var sevChips = el("div", { class: "chips" }, [""].concat(A.SEVS).map(function (s) {
      return el("button", {
        class: "chip", type: "button",
        "aria-pressed": filters.severity === s ? "true" : "false",
        onclick: function (ev) {
          filters.severity = s;
          var all = sevChips.querySelectorAll(".chip");
          for (var i = 0; i < all.length; i++) { all[i].setAttribute("aria-pressed", "false"); }
          ev.currentTarget.setAttribute("aria-pressed", "true");
          reset(false);
        }
      }, s ? [icon(A.SEV_ICON[s]), el("span", { text: t("sev." + s) })] : el("span", { text: t("sev.any") }));
    }));

    var kindSelect = A.select(
      [{ value: "", label: t("kind.any") }].concat(A.KINDS.map(function (k) {
        return { value: k, label: t("kind." + k) };
      })),
      filters.kind,
      function (ev) { filters.kind = ev.target.value; reset(false); }
    );

    var periodSelect = A.select(
      [
        { value: "1h", label: t("ev.period.1h") },
        { value: "24h", label: t("ev.period.24h") },
        { value: "7d", label: t("ev.period.7d") },
        { value: "all", label: t("ev.period.all") }
      ],
      filters.period,
      function (ev) { filters.period = ev.target.value; reset(false); }
    );

    var filterCard = card(t("ev.filters"), el("div", { class: "filters" }, [
      el("div", { class: "field wide" }, [
        el("span", { class: "label", text: t("ev.sev") }),
        sevChips
      ]),
      field(t("ev.kind"), kindSelect),
      field(t("ev.period"), periodSelect),
      field(t("ev.ip"), ipInput),
      field(t("ev.user"), userInput),
      el("div", { class: "field wide" }, [
        el("label", { class: "label", for: "ev-search", text: t("ev.search") }),
        search
      ]),
      el("div", { class: "field" }, el("button", {
        class: "btn", type: "button", text: t("ev.reset"),
        onclick: function () {
          filters = { severity: "", kind: "", ip: "", user: "", q: "", period: "24h" };
          search.value = ""; ipInput.value = ""; userInput.value = "";
          kindSelect.value = ""; periodSelect.value = "24h";
          var all = sevChips.querySelectorAll(".chip");
          for (var i = 0; i < all.length; i++) { all[i].setAttribute("aria-pressed", i === 0 ? "true" : "false"); }
          reset(false);
        }
      }))
    ]), { icon: "search" });

    var rows = el("div", { class: "rows" });
    var count = el("span", { class: "muted" });
    var more = el("button", {
      class: "btn", type: "button", text: t("ev.loadmore"), hidden: true,
      onclick: function () { load(true); }
    });
    var listCard = card(t("ev.title"), rows, { icon: "list", flush: true, aside: count });
    var footer = el("div", { class: "actions" }, more);

    add(main, el("div", { class: "view" }, [head, filterCard, listCard, footer]));

    function query(cursor) {
      var parts = ["limit=50"];
      if (filters.severity) { parts.push("severity=" + encodeURIComponent(filters.severity)); }
      if (filters.kind) { parts.push("kind=" + encodeURIComponent(filters.kind)); }
      if (filters.ip) { parts.push("ip=" + encodeURIComponent(filters.ip)); }
      if (filters.user) { parts.push("user=" + encodeURIComponent(filters.user)); }
      if (filters.q) { parts.push("q=" + encodeURIComponent(filters.q)); }
      if (filters.period !== "all") {
        var ms = filters.period === "1h" ? 3600e3 : filters.period === "7d" ? 7 * 86400e3 : 86400e3;
        parts.push("since=" + encodeURIComponent(new Date(Date.now() - ms).toISOString()));
      }
      if (cursor) { parts.push("before=" + encodeURIComponent(cursor)); }
      return parts.join("&");
    }

    function paint() {
      clear(rows);
      if (!items.length) {
        add(rows, loading ? skeleton() : empty(t("ev.empty")));
      } else {
        items.forEach(function (ev) { add(rows, eventRow(ev)); });
      }
      count.textContent = t("ev.count", { count: A.num(items.length) });
      more.hidden = !next;
    }

    function load(append) {
      loading = true;
      if (!append) { paint(); }
      A.api.events(query(append ? next : null)).then(function (page) {
        loading = false;
        var batch = (page && page.items) || [];
        items = append ? items.concat(batch) : batch;
        next = (page && page.next) || null;
        A.announceCritical(items);
        paint();
      }, function (e) {
        loading = false;
        paint();
        if (e.code !== "offline") { A.toast(mapError(e), "err"); }
      });
    }

    function reset() { items = []; next = null; load(false); }

    reset();
    return { poll: function () { if (!next) { load(false); } }, reload: reset };
  };

  function debounce(fn, ms) {
    var timer = null;
    return function () {
      if (timer) { clearTimeout(timer); }
      timer = setTimeout(fn, ms);
    };
  }

  /* ---------------- bans and allowlist ---------------- */

  A.routes.bans = function (main) {
    var tab = "bans";
    var body = el("div");
    var tabs = el("div", { class: "tabs", role: "tablist" }, [
      tabButton("bans", "bans.tab"),
      tabButton("allow", "allow.tab")
    ]);

    function tabButton(name, key) {
      return el("button", {
        type: "button", role: "tab", text: t(key), dataset: { tab: name },
        "aria-selected": tab === name ? "true" : "false",
        onclick: function () {
          tab = name;
          var all = tabs.querySelectorAll("button");
          for (var i = 0; i < all.length; i++) {
            all[i].setAttribute("aria-selected", all[i].dataset.tab === name ? "true" : "false");
          }
          load();
        }
      });
    }

    add(main, el("div", { class: "view" }, [
      el("div", { class: "view-head" }, [
        el("h1", { text: t("nav.bans") }),
        el("button", { class: "btn btn-sm", type: "button", onclick: function () { load(); } },
          [icon("refresh"), el("span", { text: t("common.refresh") })])
      ]),
      el("div", { class: "notice tone-info" }, [
        icon("shield"),
        el("div", null, [el("p", { text: t("allow.note") })])
      ]),
      tabs,
      body
    ]));

    function load() {
      clear(body);
      add(body, skeleton());
      if (tab === "bans") {
        A.api.bans().then(function (list) { clear(body); add(body, bansPane(list || [])); },
          function (e) { clear(body); add(body, empty(mapError(e))); });
      } else {
        A.api.allowlist().then(function (list) { clear(body); add(body, allowPane(list || [])); },
          function (e) { clear(body); add(body, empty(mapError(e))); });
      }
    }

    function bansPane(list) {
      var table;
      if (!list.length) { table = empty(t("bans.empty")); }
      else {
        table = el("div", { class: "scroll-x" }, el("table", null, [
          el("thead", null, el("tr", null, [
            el("th", { text: t("bans.col.ip") }),
            el("th", { text: t("bans.col.reason") }),
            el("th", { text: t("bans.col.until") }),
            el("th", { text: t("bans.col.repeat") }),
            el("th", { text: t("bans.col.state") }),
            el("th", { class: "right" })
          ])),
          el("tbody", null, list.map(function (b) {
            return el("tr", null, [
              el("td", null, el("span", { class: "mono", text: b.ip })),
              el("td", null, [
                el("div", { text: b.reason || "—" }),
                el("small", { class: "muted", text: t("bans.source." + (b.source || "auto")) + " · " + A.relative(b.created) })
              ]),
              el("td", { class: "nowrap", text: A.until(b.until, b.permanent) }),
              el("td", { text: A.num(b.repeat_count || 1) }),
              el("td", null, el("span", {
                class: "pill", dataset: { tone: b.applied ? "ok" : "warn" }
              }, [
                icon(b.applied ? "check" : "info"),
                el("span", { text: b.applied ? t("bans.state.applied") : t("bans.state.recorded") })
              ])),
              el("td", { class: "right" }, el("button", {
                class: "btn btn-sm", type: "button", text: t("bans.unban"),
                onclick: function () {
                  A.confirmAction(t("bans.unban.confirm", { ip: b.ip }), t("bans.unban"), "danger")
                    .then(function (ok) {
                      if (!ok) { return; }
                      A.api.unban(b.ip).then(function () {
                        A.toast(t("bans.unban.done", { ip: b.ip }), "ok");
                        A.loadStatus(); load();
                      }, function (e) { A.toast(mapError(e), "err"); });
                    });
                }
              }))
            ]);
          }))
        ]));
      }
      return el("div", { class: "view" }, [
        card(t("bans.title"), table, { icon: "shieldOff", flush: true }),
        banForm()
      ]);
    }

    function banForm() {
      var ip = el("input", { class: "input", type: "text", placeholder: t("bans.form.ip.ph"), required: true });
      var reason = el("input", { class: "input", type: "text", placeholder: t("bans.form.reason.ph") });
      var dur = A.select([
        { value: "1h", label: t("bans.dur.1h") },
        { value: "24h", label: t("bans.dur.24h") },
        { value: "30d", label: t("bans.dur.30d") },
        { value: "permanent", label: t("bans.dur.permanent") }
      ], "24h");
      var err = el("p", { class: "err", hidden: true });

      var form = el("form", {
        onsubmit: function (ev) {
          ev.preventDefault();
          var value = ip.value.trim();
          if (!A.isIP(value)) { return invalid(t("err.bad_ip")); }
          if (!A.bannable(value)) { return invalid(t("err.private_ip")); }
          err.hidden = true;
          ip.removeAttribute("aria-invalid");
          A.confirmAction(
            t("bans.form.confirm", { ip: value, duration: t("bans.dur." + dur.value) }),
            t("bans.form.submit"), "danger"
          ).then(function (ok) {
            if (!ok) { return; }
            A.api.ban({ ip: value, duration: dur.value, reason: reason.value.trim() || "manual" })
              .then(function () {
                A.toast(t("bans.form.done", { ip: value }), "ok");
                ip.value = ""; reason.value = "";
                A.loadStatus(); load();
              }, function (e) { invalid(mapError(e)); });
          });
        }
      }, [
        el("div", { class: "filters" }, [
          field(t("bans.form.ip"), ip),
          field(t("bans.form.reason"), reason),
          field(t("bans.form.duration"), dur)
        ]),
        err,
        el("div", { class: "actions" }, el("button", {
          class: "btn btn-danger", type: "submit", text: t("bans.form.submit")
        }))
      ]);

      function invalid(message) {
        err.textContent = message;
        err.hidden = false;
        ip.setAttribute("aria-invalid", "true");
        ip.focus();
      }

      return card(t("bans.form.title"), form, { icon: "plus" });
    }

    function allowPane(list) {
      var table;
      if (!list.length) { table = empty(t("allow.empty")); }
      else {
        table = el("div", { class: "scroll-x" }, el("table", null, [
          el("thead", null, el("tr", null, [
            el("th", { text: t("allow.col.ip") }),
            el("th", { text: t("allow.col.source") }),
            el("th", { text: t("allow.col.added") }),
            el("th", { class: "right" })
          ])),
          el("tbody", null, list.map(function (a) {
            return el("tr", null, [
              el("td", null, el("span", { class: "mono", text: a.ip })),
              el("td", { text: t("allow.source." + (a.source || "manual")) }),
              el("td", { class: "nowrap", text: A.dateTime(a.added) }),
              el("td", { class: "right" }, el("button", {
                class: "btn btn-sm", type: "button", text: t("allow.remove"),
                onclick: function () {
                  A.confirmAction(t("allow.remove.confirm", { ip: a.ip }), t("allow.remove"), "danger")
                    .then(function (ok) {
                      if (!ok) { return; }
                      A.api.unallow(a.ip).then(function () {
                        A.toast(t("allow.remove.done", { ip: a.ip }), "ok");
                        A.loadStatus(); load();
                      }, function (e) { A.toast(mapError(e), "err"); });
                    });
                }
              }))
            ]);
          }))
        ]));
      }

      var ip = el("input", { class: "input", type: "text", placeholder: t("bans.form.ip.ph"), required: true });
      var err = el("p", { class: "err", hidden: true });
      var form = el("form", {
        onsubmit: function (ev) {
          ev.preventDefault();
          var value = ip.value.trim();
          if (!A.isIP(value)) {
            err.textContent = t("err.bad_ip"); err.hidden = false;
            ip.setAttribute("aria-invalid", "true");
            return;
          }
          err.hidden = true;
          ip.removeAttribute("aria-invalid");
          A.api.allow(value).then(function () {
            A.toast(t("allow.form.done", { ip: value }), "ok");
            ip.value = ""; A.loadStatus(); load();
          }, function (e) { err.textContent = mapError(e); err.hidden = false; });
        }
      }, [
        el("div", { class: "filters" }, [field(t("allow.col.ip"), ip)]),
        err,
        el("div", { class: "actions" }, el("button", {
          class: "btn btn-primary", type: "submit", text: t("allow.form.submit")
        }))
      ]);

      return el("div", { class: "view" }, [
        card(t("allow.title"), table, { icon: "shield", flush: true }),
        card(t("allow.form.submit"), form, { icon: "plus" })
      ]);
    }

    load();
    return { reload: load };
  };

  /* ---------------- alert policy ---------------- */

  A.routes.policy = function (main) {
    var box = el("div", { class: "view" });
    add(main, box);

    function quietLabel(tg) {
      if (!tg || tg.quiet_hours === undefined || tg.quiet_hours === null || tg.quiet_hours === "") {
        return t("policy.quiet.off");
      }
      return String(tg.quiet_hours);
    }

    function paint(cfg) {
      clear(box);
      var status = A.state.status || {};
      var tg = (cfg && cfg.telegram) || {};

      add(box, el("div", { class: "view-head" }, el("h1", { text: t("policy.title") })));

      add(box, card(t("policy.current"), [
        el("div", { class: "kv" }, [
          kv(t("policy.min_sev"), tg.min_severity ? t("sev." + tg.min_severity) : t("common.unknown")),
          kv(t("policy.quiet"), quietLabel(tg)),
          kv(t("policy.dedup"), tg.dedup_window || t("common.unknown")),
          kv(t("policy.rate"), tg.rate_per_minute ? t("policy.rate.value", { n: tg.rate_per_minute }) : t("common.unknown")),
          kv(t("policy.mute"), status.muted_until
            ? t("policy.mute.on", { until: A.dateTime(status.muted_until) })
            : t("policy.mute.off"))
        ]),
        el("p", { class: "muted", text: t("policy.readonly") })
      ], { icon: "bell" }));

      add(box, el("div", { class: "notice tone-info" }, [
        icon("info"),
        el("div", null, el("p", { text: t("policy.critical_note") }))
      ]));

      var controls = [];
      if (status.muted_until) {
        controls.push(el("button", {
          class: "btn btn-primary", type: "button", text: t("policy.unmute"),
          onclick: function () {
            A.api.unmute().then(function () {
              A.toast(t("policy.unmute.done"), "ok");
              A.loadStatus().then(function () { paint(cfg); });
            }, function (e) { A.toast(mapError(e), "err"); });
          }
        }));
      } else {
        [1, 8, 24].forEach(function (h) {
          controls.push(el("button", {
            class: "btn", type: "button", text: t("policy.mute.btn", { hours: h }),
            onclick: function () {
              A.api.mute(h).then(function (res) {
                A.toast(t("policy.mute.done", { until: A.dateTime(res && res.muted_until) }), "ok");
                A.loadStatus().then(function () { paint(cfg); });
              }, function (e) { A.toast(mapError(e), "err"); });
            }
          }));
        });
      }
      add(box, card(t("policy.mute"), el("div", { class: "actions" }, controls), { icon: "bellOff" }));
    }

    add(box, skeleton());
    A.api.config().then(function (cfg) { paint(cfg); }, function () { paint(null); });
    return { reload: function () { A.api.config().then(paint, function () { paint(null); }); } };
  };

  function kv(label, value) {
    return el("div", null, [
      el("span", { class: "label", text: label }),
      el("b", { text: value })
    ]);
  }

  /* ---------------- diagnostics ---------------- */

  A.routes.diag = function (main) {
    var box = el("div", { class: "view" });
    add(main, box);

    function paint(diag, cfg) {
      clear(box);
      var status = A.state.status || {};
      var c = (diag && diag.counters) || status.counters || {};

      add(box, el("div", { class: "view-head" }, [
        el("h1", { text: t("diag.title") }),
        el("button", { class: "btn btn-sm", type: "button", onclick: load },
          [icon("refresh"), el("span", { text: t("common.refresh") })])
      ]));

      add(box, card(t("diag.state"), el("div", { class: "kv" }, [
        kv(t("diag.debug"), (diag && diag.debug) || status.debug ? t("common.on") : t("common.off")),
        kv(t("diag.level"), (diag && diag.log_level) || status.log_level || t("common.unknown")),
        kv(t("diag.detector"), (diag && diag.detector) || t("common.none")),
        kv(t("diag.banner"), (diag && diag.banner) || (status.ban && status.ban.backend) || t("common.none")),
        kv(t("diag.audit_log"), (diag && diag.audit_log) || t("common.unknown")),
        kv(t("diag.offset"), diag && diag.offset !== undefined ? A.num(diag.offset) : t("common.unknown"))
      ]), { icon: "activity" }));

      add(box, card(t("diag.counters"), el("div", { class: "stats" }, [
        A.statCard(t("diag.events"), A.num(c.events_total !== undefined ? c.events_total : c.events_24h), { icon: "activity" }),
        A.statCard(t("diag.alerts"), A.num(c.alerts_sent), { icon: "bell" }),
        A.statCard(t("diag.skipped"), A.num(c.lines_skipped), { icon: "list" }),
        A.statCard(t("diag.ratelimited"), A.num(c.rate_limited), { icon: "bellOff" })
      ]), { icon: "dashboard" }));

      add(box, el("div", { class: "notice tone-info" }, [
        icon("info"),
        el("div", null, [
          el("h3", { text: t("diag.debug.title") }),
          el("p", { text: t("diag.debug.body") })
        ])
      ]));

      add(box, card(t("diag.config"), [
        el("p", { class: "muted", text: t("diag.config.note") }),
        el("pre", { class: "conf", text: cfg ? JSON.stringify(cfg, null, 2) : t("common.unknown") })
      ], { icon: "sliders" }));
    }

    function load() {
      clear(box);
      add(box, skeleton());
      Promise.all([
        A.api.diagnostics().then(null, function () { return null; }),
        A.api.config().then(null, function () { return null; })
      ]).then(function (res) { paint(res[0], res[1]); });
    }

    load();
    return { reload: load };
  };

  /* ---------------- setup check ---------------- */

  A.routes.setup = function (main) {
    var box = el("div", { class: "view" });
    add(main, box);

    function check(ok, titleKey, fixKey) {
      return el("div", { class: "check", dataset: { ok: ok ? "true" : "false" } }, [
        icon(ok ? "checkCircle" : "alertTriangle"),
        el("div", null, [
          el("h3", { text: t(titleKey) }),
          el("p", { text: ok ? t("setup.ok") : t(fixKey) })
        ])
      ]);
    }

    function paint(cfg) {
      clear(box);
      var status = A.state.status || {};
      var tg = (cfg && cfg.telegram) || {};
      var auditd = !(status.auditd && status.auditd.healthy === false);
      var telegram = !!(tg.token && tg.chat_ids && tg.chat_ids.length);
      var rules = status.rules_loaded !== undefined
        ? !!status.rules_loaded
        : !!(status.counters && status.counters.events_24h > 0);
      var bans = !!(status.ban && status.ban.enforcing);

      add(box, el("div", { class: "view-head" }, el("h1", { text: t("setup.title") })));
      add(box, card(null, el("div", { class: "check-list" }, [
        check(auditd, "setup.auditd", "setup.auditd.fix"),
        check(telegram, "setup.telegram", "setup.telegram.fix"),
        check(rules, "setup.rules", "setup.rules.fix"),
        check(bans, "setup.bans", "setup.bans.fix")
      ]), { icon: "clipboard" }));
    }

    add(box, skeleton());
    A.api.config().then(paint, function () { paint(null); });
    return { reload: function () { A.api.config().then(paint, function () { paint(null); }); } };
  };

  A.start();
})();
