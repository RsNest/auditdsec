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

All stages pass `model.Event`. `action.Banner` and `detect.Detector` are interfaces with
no implementation yet, so v0.2 plugs in without reshaping the pipeline.

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

## Safety rules

- The allowlist always beats a ban, enforced in `store.RecordBan` so no caller can
  bypass it. Allowlisting an address lifts an existing ban. This is what keeps an owner
  on a dynamic address from locking themselves out.
- Permanent bans are reserved for repeat offenders; the ladder is 1h → 24h → 30d →
  permanent, and the counter for it is already stored (`Ban.Count`).
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
internal/detect/          Detector interface (brute force: v0.2)
internal/action/          Banner interface + no-op (nftables: v0.2, CrowdSec: v0.3)
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

`pro`: alerts from `info`, 90 days, 30 messages a minute, a 5 minute window, heartbeat at
2 hours. v0.4 adds what the profile is really for: several hosts in one chat, Prometheus
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
- **v0.2**: sliding-window brute-force detector, nftables/ipset Banner, ban escalation,
  automatic allowlisting of the owner's address on the first key login.
- **v0.3**: CrowdSec both ways (events to LAPI, decisions to Telegram), hardening score,
  learning mode and "first time from this country" alerts.
- **v0.4**: pro profile in full — multi-host, metrics, routing, `auditdsec query`.
