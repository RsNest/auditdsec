# auditdsec — architecture

Lightweight Go agent: reads the Linux auditd log, turns raw records into human-readable
security events, sends them to Telegram, and (from v0.2) detects brute force and bans
attackers. Target users: ordinary VPS owners (profile `simple`) and admins of 5–10 hosts
(profile `pro`). One binary, different presets. Docker is the primary install, a static
binary the fallback.

## Constraints

- Go 1.24, one static binary (`CGO_ENABLED=0`), ~7 MB, tens of MB of RAM.
- **No external dependencies — standard library only.** This started as a build
  constraint (the egress policy of the build environment reaches `github.com` only, so
  `proxy.golang.org`, `gopkg.in`, `modernc.org` and `golang.org/x` are unreachable) and
  turned out to fit the product: nothing to audit but our own code, no supply chain, a
  tiny image. The three things a library would have provided are implemented here:
  - polling instead of `fsnotify` — one `stat` per second, and it behaves the same on
    bind mounts and network filesystems, where inotify is unreliable;
  - `internal/logging` instead of `lumberjack` — size-based rotation with N backups;
  - day-partitioned JSONL instead of SQLite — see **Storage**.
  When the module proxy is available, `internal/store` is the seam to put SQLite behind,
  and `internal/config/yaml.go` can be replaced by `yaml.v3` without invalidating a
  single existing config file, because the parser accepts a strict subset of YAML.
- auditd stays on the host; the container mounts `/var/log/audit` read-only and needs no
  capabilities. Bans are applied by a CrowdSec bouncer or, optionally, by a profile with
  `NET_ADMIN` — never by the default container.
- UI language: Russian primary, English complete alongside it, enforced by a test.

## Pipeline

```
source → parse → semantic → ┬→ store
                            └→ notify
```

- `source` (**internal/source**) follows `audit.log`: polls, notices rotation (inode
  change) and truncation (size below the offset, or a changed file head), persists the
  offset of the last complete line so a restart neither loses nor repeats events, and
  waits patiently while the file does not exist.
- `parse` (**internal/parse**) splits a line into fields (quoted values, the nested
  `msg='...'` of USER_* records, hex-encoded commands) and groups records by audit
  serial. An event closes on its `EOE` record, when a different serial appears, or after
  an idle timeout.
- `semantic` (**internal/semantic**) maps records to a `model.Event`: kind, severity,
  user, source address, and the arguments the i18n template needs. This is the only
  package that knows auditd's vocabulary, and the only one that decides severity.
- `store` (**internal/store**) appends to a JSONL file per UTC day and keeps a small
  in-memory ring for `/last`.
- `notify` (**internal/notify/telegram**) applies the alert policy and talks to the API.

All stages pass `model.Event`. After an event is delivered it goes to `detect`, whose
`Result` carries two things: ban decisions for `action`, and events the detector derived
itself. A derived event is delivered but never fed back, so one cannot trigger another.

## Storage

Events: `state_dir/events/YYYY-MM-DD.jsonl`. Retention is deleting old files; the data
stays readable with `grep` and `jq`, which matters for a tool whose job is explaining
what happened. State that must be read back — allowlist, bans, mute deadline, the
Telegram update offset — lives in `state_dir/state.json`, written atomically
(temp file plus rename). A half-written last line after a crash is skipped on read.

Not SQLite, for now: the workload is append-only with a daily scan, which a file does
well, and it keeps the dependency count at zero. The `store` API is narrow on purpose so
the backend can change.

## Alert policy

In order: severity threshold → mute → quiet hours → dedup → rate limit. Critical events
skip mute and quiet hours, which is the whole point of the agent. Identical events inside
`dedup_window` become one message plus a trailing count, so 47 failed logins are one
alert and "46 more", not 47 messages. The rate limiter is a token bucket, so a storm
cannot get the bot throttled by Telegram itself.

## Detection

`detect.BruteForce` counts failed logins per source address in a sliding window. The
event's own timestamp is the clock rather than `time.Now()`, so replaying a log produces
exactly the same decisions as watching it live — which is what makes the thresholds
testable at all.

It emits two different things. A ban decision, when the failure count reaches the
threshold; and a derived `login_after_bruteforce` event, when a login succeeds from an
address that has just failed many times. The second is the signal that matters most and
it exists nowhere in the audit log: it is a pattern across records, not a record.

After a decision the counter resets, and another ban for the same address is held off for
one window, so a burst cannot re-ban on every packet. Tracked addresses are capped and
evicted least-recently-seen first, so a spray from thousands of sources cannot grow the
agent's memory.

## Bans

`action.Banner` is the interface; `action.Nftables` the implementation. Everything lives
in the agent's own `inet auditdsec` table with two timeout-flagged sets and a drop rule at
priority -10, so the host's own firewall — ufw, firewalld, Docker's chains — is never
edited, and uninstalling is one `nft delete table` away.

The table is recreated at startup and the store's active bans are pushed back into it.
That makes the store the source of truth instead of whatever survived a reboot, at the
cost of a short window during a restart where nothing is blocked.

Three decisions worth keeping:

- **The ladder starts at an hour** (1h → 1d → 30d → permanent, by repeat count).
  Addresses are shared and recycled, so a permanent ban on a first offence would make
  the agent more harmful than the attack it answers.
- **A decision whose window has already closed is skipped**, quietly. Reading an audit log
  written before the agent started would otherwise flood the chat and block addresses over
  attacks that ended days ago — exactly what `read_from_start` does on a first run.
- **The default backend is `none`.** The container the agent normally runs in holds no
  capabilities and cannot touch netfilter, so decisions are recorded and reported but not
  applied, and the agent says so at startup. Enforcement is opt-in through
  `deploy/compose.enforce.yml`, which adds `NET_ADMIN`, the host network namespace and an
  image that actually contains `nft`.

`DryRun` logs the exact command instead of running it, because the failure mode of this
whole feature is locking the owner out of their own server.

## Safety rules

- Three independent barriers stop the agent locking its owner out: the allowlist beats a
  ban (enforced inside `store.RecordBan`, so neither the detector nor a chat button can
  bypass it, and allowlisting lifts an existing ban in the firewall too); the source of
  the first successful login after startup is allowlisted automatically, because that is
  almost always the person installing the agent; and private, loopback and link-local
  addresses are never bannable, since that is how a host reaches its own network.
- Permanent bans are reserved for repeat offenders, counted in `Ban.Count`.
- Secrets are masked in command lines before they are sent or stored, including by
  replacing the hex form of a sudo command in the retained evidence — hex is trivially
  reversible, so storing it would store the password.
- The bot token never reaches a log or an error string.
- The bot answers only allowlisted chat ids and refuses to start without that list.
- Values taken from the log are HTML-escaped before they reach a message, so a file path
  cannot forge markup.

## Layout

```
cmd/auditdsec/            entrypoint: run, check-config, explain, version
internal/model/           Event, Kind, Severity, dedup key
internal/parse/           audit record parser and event assembler
internal/source/          rotation-aware log tailer
internal/semantic/        auditd → human event, severity rules, audit key names
internal/detect/          brute-force detector, escalation ladder
internal/action/          Banner interface, nftables implementation, no-op
internal/notify/telegram/ API client, alert policy, bot commands, rendering
internal/store/           JSONL events, state, retention, allowlist, bans
internal/config/          YAML subset parser, profile presets, env overrides
internal/i18n/            ru and en catalogs
internal/logging/         JSON log with size-based rotation
internal/redact/          secret masking
internal/pipeline/        wiring, heartbeat, retention purge
deploy/                   Dockerfile, audit rules, systemd unit, helper script
```

## Profiles

`simple`: audit rules at the standard level, alerts from `warn` (so routine sudo is
recorded but does not page anyone), 14 days of retention, 10 messages a minute, a 10
minute dedup window, heartbeat at 6 hours.

`pro`: alerts from `info`, 90 days, 30 messages a minute, a 5 minute dedup window,
heartbeat at 2 hours, and a tighter brute-force threshold (5 failures in 5 minutes
against 10 in 10). v0.4 adds what the profile is really for: several hosts in one chat, Prometheus
metrics, alert routing.

## Heartbeat

The failure that matters most is silence: an attacker who stops auditd leaves no events,
and the agent would otherwise look calm. Every `heartbeat.check_every` the pipeline stats
the audit log and reports a critical `auditd_stopped` event when the file is unreadable or
has not been written for longer than `heartbeat.stale_after`, with a cooldown so it says
it once rather than every minute. A hard signal — auditd's own `DAEMON_END` record — is
handled by `semantic` like any other event.

## Debug mode

One switch, three equivalent ways to set it: `AUDITDSEC_DEBUG=1`, `debug: true`, or
`run -debug` (the flag wins, and only when actually passed, so `-debug=false` cannot
silently override a file that asked for it). Turning it on also forces `log.level` to
debug, because the two were never useful apart.

What it adds is a trail for one question — *why did no alert arrive* — so each stage
reports its own refusal:

- `pipeline` logs every line read, through `redact.AuditLine` so a hex-encoded command
  is decoded, masked and written back readable instead of being copied verbatim;
- `semantic.MapVerbose` returns the reason a record was dropped, and an unknown audit key
  lists the keys the build does know, because a rules file that disagrees with the binary
  is the usual cause;
- `telegram` logs a verdict per event (sent, grouped, held) with the reason, covering the
  severity threshold, mute, quiet hours, the dedup window and the rate limit;
- counters print every 30 seconds, which tells a quiet agent from a stuck one.

The `/debug` bot command reports the live state and, deliberately, how to switch the mode
on and off: a diagnostic the user cannot enable is useless. Its pipeline-side lines arrive
through `Client.SetDiag`, a setter rather than an option because the pipeline is built
after the client it reports to.

## Roadmap

- **v0.1** (done): parser, 10 event kinds, Telegram alerts with buttons and commands,
  allowlist, storage with retention, heartbeat, i18n, Docker, systemd.
- **v0.2** (done): sliding-window brute-force detector, the `login_after_bruteforce`
  signal, nftables Banner with escalation and a dry-run mode, automatic allowlisting of
  the owner's address, debug mode.
- **v0.3**: CrowdSec both ways (events to LAPI, decisions to Telegram), hardening score,
  learning mode and "first time from this country" alerts, an ipset backend for hosts
  still on iptables.
- **v0.4**: pro profile in full — multi-host, metrics, routing, `auditdsec query`.
