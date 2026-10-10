# auditdsec doctor

`auditdsec doctor [-config FILE] [-rules PATHS]` tells the owner, in the configured
language (ru/en), what works, what is broken and how to fix it. It exits non-zero only when
something is **FAIL**, so it can be used in scripts.

It is read-only. It never changes the firewall, the audit rules or the state, never sends a
Telegram message and never opens a port. The only write is a short-lived probe file in the
state directory to learn whether it is writable. It is safe to run while the agent is running:
the notification queue is inspected on a temporary copy, and `state.json` is only read.

| Area | What is checked | FAIL | WARN |
|---|---|---|---|
| State directory | exists, writable | not a directory / not writable | – |
| Audit log | `internal/auditlog` state | `audit_unavailable` (missing, unreadable) | `audit_silent` (not written for `heartbeat.stale_after`; may be a quiet host) |
| Audit rules | required keys in `/etc/audit/rules.d`, `/etc/audit/audit.rules` (or `-rules`) | a required key is missing | rule files unreadable; INFO when invisible (container) |
| Firewall | backend, dry run, `nft` present, `nft list table inet <table>` | `nft` missing | table not readable (no privilege / not created yet); INFO for backend `none` and dry run |
| Ban decisions and detection | bans by observed state, unconfirmed unblocks, owed notices, detector enabled, detection backlog | `state.json` damaged | failed/pending bans, unconfirmed unblocks, detector disabled |
| Notification queue | Telegram configured, queue pending/failed/overflow | queue file damaged | permanent failures (last reason shown), overflow |
| SSH session context | journal readable for the optional enrichment | – | journal unreadable (INFO when journalctl is absent or the option is off) |
| Web panel | answers on `web.listen`, first-login setup, `public_url` scheme | nothing answers | `public_url` not HTTPS |

Each finding has a *what* line and, when action is needed, a *fix* line with the command or
setting to use. A dry run or `ban.backend: none` is always reported as "nothing is blocked".

## What it does not check

- That the kernel really delivers events: `sudo true` and watching for a new line shows it.
- `auditctl -l` (what is loaded in the kernel); only the rule files are read. Run
  `auditdsec check-rules` and `auditctl -l` on the host.
- That Telegram accepts a message or that the panel certificate is valid from the outside;
  no network call leaves the machine. Use the panel's test message.
- Inside a container the host's rule files and `nft` are usually not visible; the corresponding
  findings say so instead of failing.

Verification: `internal/doctor` tests use fake commands, a fake HTTP probe and temporary
directories; they assert the levels, the fix texts, that no non-read-only command runs and
that no file other than the probe is touched. Not run against a real auditd or nftables.
