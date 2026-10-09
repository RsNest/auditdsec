# auditdsec — architecture

Lightweight Go agent: reads Linux auditd log, turns raw records into human-readable security events,
sends them to Telegram, detects brute force and bans attackers (own detector + CrowdSec).
Target: ordinary VPS owners (profile `simple`) and admins of 5–10 hosts (profile `pro`).
Same binary, different config presets. Docker is the primary install, a static binary is the fallback.

## Constraints
- Go 1.24, single static binary (CGO_ENABLED=0), ~15–30 MB RAM.
- Prefer stdlib. Allowed deps: `gopkg.in/yaml.v3`, `modernc.org/sqlite`, `github.com/fsnotify/fsnotify`, `gopkg.in/natefinch/lumberjack.v2`. Telegram via plain net/http (no heavy SDK).
- auditd stays on the host. Container mounts `/var/log/audit:ro`. Container never needs NET_ADMIN in the default setup.
- Own logs: JSON, rotated with lumberjack. Docker: `read_only`, `mem_limit: 64m`, `cap_drop: ALL`, json-file log driver with max-size/max-file.
- UI language: Russian primary, English secondary (i18n from day one, `internal/i18n`).

## Pipeline
`source (tail audit.log) -> parse (assemble multi-line events) -> semantic (human Event + severity)
 -> detect (sliding windows, baseline) -> action (ban) / notify (telegram) / store (sqlite)`

All stages communicate through the normalized `model.Event`. Sources, detectors, actions and notifiers
are Go interfaces so profiles simply enable different sets.

## Layout
```
cmd/auditdsec/main.go        entrypoint, subcommands: run, version, explain, check-config
internal/model/              Event, Severity, Kind
internal/source/             file tailer (inotify via fsnotify, rotation-aware, offset persisted)
internal/parse/              audit record parser + event assembler (msg=audit(ts:serial))
internal/semantic/           rules: raw audit events -> model.Event (ssh login, sudo, user add, authorized_keys change, persistence, log tamper)
internal/detect/             brute-force sliding window per IP, "success after N failures"
internal/action/             Banner interface: nft/ipset implementation (optional), CrowdSec LAPI client (later)
internal/notify/telegram/    sender, dedup/grouping, inline buttons, commands, chat_id allowlist
internal/store/              sqlite, retention, allowlist table, ban table
internal/i18n/               ru/en message catalogs
internal/config/             yaml config + profile presets (simple|pro)
internal/redact/             mask secrets in command lines
deploy/                      Dockerfile, docker-compose.yml, auditdsec.rules (audit rules by level), systemd unit
docs/
```

## Profiles
- simple: audit rules level `standard`, only important alerts + daily digest, own brute-force detector with ban
  escalation (1h -> 1d -> 30d -> permanent after 3 repeats), auto-allowlist of owner IP on first successful key login,
  learning mode 3 days, quiet hours, CrowdSec optional.
- pro: yaml config, level `paranoid`, CrowdSec both modes (push events/alerts to LAPI, pull decisions to Telegram),
  routing rules (telegram/ntfy/webhook), multi-host (host name + tags in every message), Prometheus /metrics,
  healthcheck pings, configurable thresholds.

## Core (always on)
Audit parser, heartbeat + alert if auditd/agent stops, secret redaction, chat_id allowlist, log rotation.

## Safety rules for bans
Never ban an allowlisted IP, private/loopback ranges, or the IP of a currently active owner session.
Permanent only after repeated offences. All bans reversible from Telegram (/unban) and CLI.

## Roadmap
- v0.1 (MVP): parser, semantic A1–A4 (ssh login, sudo, user/account changes, authorized_keys), Telegram alerts with
  buttons ("ban IP", "it's me", "mute 24h"), allowlist, sqlite, i18n, Docker, README.
- v0.2: brute-force detector + ban escalation (nft/ipset), audit rules profiles, auto-allowlist.
- v0.3: CrowdSec C1/C2, hardening score (/score), learning mode.
- v0.4: pro profile: multi-host, metrics, routing, CLI explain/query.
