# auditdsec — architecture

Lightweight Go agent: reads the Linux auditd log, turns raw records into human-readable
security events, sends them to Telegram, and (from v0.2) detects brute force and bans
attackers. Target user: the owner of a VPS. One product: one binary, one install path,
one panel; the old `simple` / `pro` profiles survive only as presets of starting values
(see **Configuration and migration**). Docker is the primary install, a static binary the
fallback.

This document keeps two things apart: what is **implemented** (the sections up to
**Roadmap**) and the **target architecture** that the next stages build towards, marked as
not implemented. Where the implementation has a known defect, it says so in place.

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
  capabilities. Bans are applied, optionally, by the enforce overlay with `NET_ADMIN` —
  never by the default container. CrowdSec exists only as settings; there is no LAPI
  client yet.
- UI language: Russian primary, English complete alongside it, enforced by a test.

## Pipeline

```
source → parse → semantic → ┬→ store
                            └→ notify
```

- `source` (**internal/source**) follows `audit.log`: polls, notices rotation (inode
  change) and truncation (size below the offset, or a changed file head), persists the
  offset of the last complete line, and waits patiently while the file does not exist.
  A restart of a running agent resumes at that offset; the cases where this loses lines
  are listed under the known defects below.
- `parse` (**internal/parse**) splits a line into fields (quoted values, the nested
  `msg='...'` of USER_* records, hex-encoded commands) and groups records by audit
  serial. An event closes on its `EOE` record, when a different serial appears (a known
  defect, below), or after an idle timeout.
- `semantic` (**internal/semantic**) maps records to a `model.Event`: kind, severity,
  user, source address, and the arguments the i18n template needs. This is the only
  package that knows auditd's vocabulary, and the only one that decides severity.
- `store` (**internal/store**) appends to a JSONL file per UTC day and keeps a small
  in-memory ring for `/last`.
- `notify` (**internal/notify/telegram**) applies the alert policy and talks to the API.

All stages pass `model.Event`. After an event is delivered it goes to `detect`, whose
`Result` carries two things: ban decisions for `action`, and events the detector derived
itself. A derived event is delivered but never fed back, so one cannot trigger another.

Durable boundaries today: the source offset (`tail.json`), the day files of events and
`state.json`. Everything between them — the line channel, the assembler, the alert policy,
the detector — is memory only.

**Known defects, fixed in stage 1** (see **Target architecture**; nothing below is claimed
as solved):

- the assembler closes every other open event when a record with another serial arrives,
  so interleaved records (`SYSCALL(A) SYSCALL(B) PATH(A) EOE(A) ...`) are split;
- the cursor is a bare offset: a file rotated while the agent was stopped is read from the
  old offset, and the offset is saved once lines reach a channel, before the event is
  assembled and stored — a crash in between loses those lines;
- delivery is synchronous: a slow Telegram delays detection and reading; one rate limit
  covers critical and routine alerts; a dedup group is recorded before the send succeeds;
- the brute-force tracker clears its failure history on a ban, so a successful login right
  after the ban threshold is not correlated;
- `PROCTITLE` and other encodings of a command line are not all masked before storage;
- bans: addresses are compared as strings, an allowlist entry can remove a ban the firewall
  failed to lift, and `Applied` is not the observed firewall state.

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
cmd/auditdsec/            entrypoint: run, check-config, explain, version, hash-password,
                          reset-credentials, net-check, port-plan, port-check,
                          probe-listen, remote-check, check-site
cmd/auditdsec-probe/      RemoteProbe service, run on another machine
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
internal/api/             panel HTTP API, sessions, first-time setup, password policy
internal/web/             embedded panel assets
internal/netcheck/        DNS check, port binding and plan, nonce listener, RemoteProbe
deploy/                   Dockerfile, audit rules, systemd unit, Caddy and certbot overlays
install.sh                the installer (see Panel publication)
scripts/e2e/stage0/       the installer stand: Pebble, CoreDNS, RemoteProbe behind a firewall
```

## Profiles

Deprecated as a choice (see **Configuration and migration**); the presets are:

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

## Panel publication

Implemented in stage 0.

```
                 internet
                    │
   ┌────────────────┼──────────────────────────────── VPS ─────────────┐
   │   :PANEL_HTTPS_PORT (443 or chosen)      :80 (HTTP-01)            │
   │                    │                       │                      │
   │              Caddy (TLS)  ◄── reload ── certbot (IP mode only)    │
   │       admin API 127.0.0.1:2019             │ /certs volume        │
   │                    │ plain HTTP            │                      │
   │          agent 127.0.0.1:PANEL_UPSTREAM_PORT (9477)               │
   └───────────────────────────────────────────────────────────────────┘
        ▲ install time only: temporary nonce listener on the candidate port
        │
   RemoteProbe (cmd/auditdsec-probe) on ANOTHER machine, run by the owner
```

- The agent never publishes a port: it listens on loopback, plain HTTP, and refuses a
  public or wildcard address. Caddy is the only listener on a public port. HTTP/3 is off,
  so no UDP port is needed. Caddy's admin API stays on loopback.
- **Domain:** Caddy obtains and renews the certificate (HTTP-01 on 80, or TLS-ALPN-01
  when the panel itself is on 443). **IP:** a pinned certbot obtains a `shortlived`
  certificate over HTTP-01 on 80 (the only challenge an address can use) and Caddy loads
  the files; a loop renews it and checks every minute that the panel port serves the
  file on disk.
- `./install.sh` decides and checks, in this order: preflight → domain or IP → public DNS
  (`auditdsec net-check`: several resolvers, A and AAAA apart, CNAME followed; every
  record must lead here) → port (`port-plan`, `port-check` binds v4 and v6, then
  `probe-listen` serves a random nonce and `remote-check` asks the RemoteProbe provider to
  fetch it) → challenge port → write `.env` → start → local checks → `remote-check -kind
  tls` against the started panel with certificate verification → summary.
- Local reachability proves nothing about the internet, so "published" requires the
  outside check with a production certificate. A missing provider is
  `external_check_unavailable`, never "closed". Each failure has a code and an exit status.
- Rollback: before anything starts, a failure leaves the machine as it was (the temporary
  listener is removed; the installation's own proxy, stopped for the port checks, is
  started again). After a start that fails, the last verified `.env` comes back and the
  failed one is kept as `.env.failed`. Volumes — events, credentials, certificates — are
  never removed by the installer.
- Not supported, and reported as such: a CDN or load balancer in front of the name (the
  check wants DNS-only records), DNS-01, routing the challenge through another web server
  on port 80. The installer never stops another program, disables a firewall, or adds a
  firewall rule.

### RemoteProbe

`internal/netcheck/probe.go` holds the contract (request, results), the checker, the HTTP
service and the client; `docs/PANEL.md` documents it. The service is built not to become
an open scanner: bearer token, global and per-target rate limits, a cap on concurrent
checks, no private / loopback / link-local / metadata targets (checked before dialling
and again on the socket), a host name only if it resolves to the very address being
tested, a connection to the literal address, no redirects, plain HTTP only on loopback.

## First-time setup

Implemented in stage 0. `internal/api/bootstrap.go`, `policy.go`.

- No credentials → state `bootstrap`: only `admin` / `admin` is accepted, and it yields a
  15-minute *setup* session that every other endpoint refuses (server side).
- `POST /api/v1/setup/complete` validates login and password on the server (the browser
  holds a copy of the rules for convenience only), serialises concurrent attempts, writes
  `panel-credentials.json` (login, PBKDF2-SHA256 hash, `bootstrap_completed`) atomically —
  temp file, fsync, rename, fsync of the directory — then the `panel-setup-done` marker,
  then switches the in-memory credentials and revokes every session.
- Crash between the write and the HTTP answer: the file on disk is the truth; admin /
  admin no longer works after restart, the new pair does.
- After completion nothing returns to `admin` / `admin`. Credentials missing or damaged
  with the marker present → state `locked`, sign-in stops with a diagnosis; the way out is
  local: `auditdsec reset-credentials -yes`. A state directory that cannot be written at
  start → `locked` as well, so no setup is offered whose result would be lost.
- An older installation's `web.password_hash` / `AUDITDSEC_WEB_PASSWORD_HASH` is copied
  into the managed file at the first start and then the file wins; `.env` cannot undo a
  change made in the panel.

## Privilege model

| Component | Runs as | Capabilities | Network |
|---|---|---|---|
| agent (default) | root in a `scratch` image, read-only rootfs | none | host namespace in panel modes, loopback listener only |
| agent (enforce overlay) | root | `NET_ADMIN` | host |
| Caddy | image default | `NET_BIND_SERVICE` only | host |
| certbot | image default | `NET_BIND_SERVICE` only | host, binds 80 during challenges |
| installer | root or docker group on the host | — | runs the agent image for checks with `--network host` |
| RemoteProbe | unprivileged, another machine | — | outbound to the tested endpoint only |

The panel never gains firewall rights: a ban requested in the panel goes through the
agent, and is applied only when the enforce overlay gave the agent `NET_ADMIN`.

## Threat assumptions

- Root on the VPS is trusted; an attacker with root can stop the agent, edit its state
  and its credentials. The agent is evidence and alerting, not a sandbox.
- The panel faces the internet. Its first sign-in pair is public knowledge, so the window
  between installation and the owner's first sign-in is a real exposure; the installer
  says so and the setup session can do nothing but set credentials.
- The RemoteProbe provider is trusted with which address and port are tested, never with
  a panel secret: it is sent a nonce or reads the public setup state.
- DNS answers from public resolvers can disagree during propagation; the check reports
  that rather than guessing.

## Configuration and migration

- `schema_version: 1` is written by new files; a file without it is read unchanged
  (every newer key has a safe default). A file for a newer version is refused.
- `web.listen` → `web.upstream_listen` (same setting; both are read). New:
  `web.public_https_port`, which must agree with the port in `web.public_url`.
- `.env`: `PANEL_PORT` was always the upstream and becomes `PANEL_UPSTREAM_PORT` on the
  next installer run; `PANEL_HTTPS_PORT`, `PANEL_SITE_ADDR`, `PANEL_PUBLIC_URL` and the
  `PANEL_PROBE_*` keys are new. An installation from before the port was a choice is
  treated as being on 443. `--port` keeps its old meaning under the name
  `--upstream-port`.
- `profile: simple|pro` is a preset of starting values; explicit keys win. The installer
  no longer asks for one. The release version (`auditdsec version`) is independent of it.
- Panel credentials: see **First-time setup**.

## Limits

| What | Limit |
|---|---|
| agent container memory | 64 MiB (`mem_limit`), 64 pids |
| Caddy / certbot containers | 128 MiB / 256 MiB |
| API request body | 4 KiB; RemoteProbe request 2 KiB, answer read 8 KiB |
| panel sessions | 16 at once; setup session 15 minutes |
| sign-in | 5 failures per address per 10 minutes; 30 wrong first sign-ins overall per window |
| automatic port choice | 443 + up to 16 random ports from 20000–29999 (`PANEL_PORT_RANGE_LO/HI`) |
| DNS check | 3 resolvers, up to 3 rounds 5 s apart, 2 minutes in all |
| temporary nonce listener | 3 minutes at most |

Stage 1 adds budgets for pending audit records, event size, tracker memory and the
outbox; they are not enforced today beyond what the current code does.

## Target architecture

**Not implemented.** This is what stage 1 and later build towards; nothing here is
claimed by the code above.

```text
audit.log / optional journald
        ↓
source + identity-aware cursor (device, inode, generation, offset)
        ↓
record parser → sanitizer → recoverable assembly (many open events, size and count caps)
        ↓
normalized events with stable IDs
        ↓
durable journal / EventStore  ← the source cursor is confirmed only up to here
        ├── detectors → incident correlation
        ├── notification policy → durable outbox → channel workers
        └── decision service → desired state → reconciler → enforcer

Telegram / Web API / CLI
        ├── query the same event, incident and delivery state
        └── invoke the same policy and decision services
```

Chosen recovery model (stage 1): **replay with a held cursor**. The cursor is not advanced
past the earliest event that is still open or not yet in the store; after a crash the
lines after it are read again and duplicates are dropped by the event's stable ID, so a
repeat creates no new decision and no new delivery job. This is at-least-once with
deduplication, not exactly-once.

Entities:

- `Event`: schema version, stable ID, host and source identity, occurred/observed time,
  kind, severity, actor, effective UID, session, process, source IP, redacted evidence,
  `complete` and `incomplete_reason`.
- `Incident`: ID, related event IDs, correlation reason, severity, first/last seen,
  new / acknowledged / resolved, response actions.
- `DeliveryJob`: event or incident, channel, destination, priority, status, attempts,
  next attempt, last error, created / delivered.
- `Decision`: origin, IP or prefix (canonical `netip`), reason, evidence IDs, desired and
  observed state (`pending`, `applied`, `failed`, `dry_run`, `unknown`, `expired`), expiry,
  executor.
- `OperatorAction`: who, when, through which interface, what (allow, ban, unban, ack,
  suppress) and the result.

Interfaces only where there are already two clients, a retry or two implementations:
`Source`, `EventStore`, `Detector`, `NotificationChannel`, `DecisionService`, `Enforcer`,
`HealthProvider`.

## Roadmap

- **v0.1** (done): parser, 10 event kinds, Telegram alerts with buttons and commands,
  allowlist, storage with retention, heartbeat, i18n, Docker, systemd.
- **v0.2** (done): sliding-window brute-force detector, the `login_after_bruteforce`
  signal, nftables Banner with escalation and a dry-run mode, automatic allowlisting of
  the owner's address, debug mode.
- **Stage 0** (done, branch `wip/acme-staging-production`): public HTTPS panel on a domain
  or IP and a chosen port, DNS / port / certificate checks from outside, installer error
  codes, mandatory first-time setup from `admin` / `admin`.
- **Stage 1** (next), in this order:
  1. assembler: many open events keyed by source, timestamp and serial; close on EOE or
     timeout; caps with an `incomplete` event instead of silent loss; PATH chosen by
     `item` / `nametype`;
  2. cursor with file identity and replay with a held cursor; stable event IDs;
  3. durable outbox and channel workers; critical with a protected share; real counters;
  4. brute-force: correlation history kept apart from the ban cooldown;
  5. one sanitizer before storage, logs, API and messages (PROCTITLE, EXECVE argv);
  6. `DecisionService`: canonical addresses, desired vs observed state, reconciler,
     nftables timeout refresh; first-login auto-allowlist off for new installations;
  7. audit rules and health: SSH vs other auth, log tampering only for truncate / unlink
     / rename, mandatory audit keys checked, `audit_unavailable` vs `audit_silent`.
- **Stage 2**: `auditdsec doctor`, SSH session context from journald, scoped exceptions and
  incident handling, file-change details (FIM), saved filters, export, Telegram roles.
- **Stage 3**: CrowdSec adapter, webhook / ntfy, `/metrics`, external heartbeat, CI.
- **Stage 4**: multi-host, learning mode, hardening report, an indexed store when the load
  calls for it, declarative detection rules.
