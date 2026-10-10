# Durable notification delivery

Stage 1.3 applies to automatic event alerts, automatic ban/first-login notices and startup
notices. Interactive bot replies and the settings page's explicit test message remain
immediate operations. The supported channel is Telegram; the queue's `Sender` interface
separates policy and provider calls for future channel adapters.

## Persistence and recovery

Each new event is synced together with its immutable `notification_plan` in the daily
JSONL journal. The plan contains one request body per recipient, priority and a credential
fingerprint. It contains no bot token. A journal record without a plan is legacy history:
import advances the receipt without sending an old event under newly configured settings.

`<state_dir>/outbox/outbox.wal` stores atomic transactions with queue changes, retry
deadlines, grouping windows/counts, outcomes and per-day journal byte receipts. Imports
commit all admitted jobs and the receipt together. Completed job bodies are removed;
receipts prevent their recreation. A restart streams the unimported journal tail before
source processing starts. Ban and startup notices use journal rows with no UI event kind.
Old receipt entries are removed only after their journal files are removed by retention.

The WAL is synced after every transaction and compacted through a synced temporary file,
atomic rename and directory sync on Linux. An incomplete final WAL row is truncated;
invalid committed rows fail closed. An initialized WAL that is missing or empty fails
closed, using `<state_dir>/.outbox.initialized` as the independent initialization marker.
Keep the journal, WAL, initialization markers and source cursor in the same backup/state
volume. Run one agent per state volume. Do not delete the WAL or marker to fix an error:
restore a matching backup and investigate the failed write or lost state.

A provider call happens after its attempt has been saved. Its acknowledgment then removes
the pending job and increments `delivered` in one transaction. If Telegram accepts a
request and the process dies before persisting the acknowledgment, that recipient can
receive it again. Telegram `sendMessage` has no client idempotency key: the guarantee is
**at least once**, not exactly once. A provider acknowledgment is not a read receipt.

Notification intent persistence does not make detection/firewall changes transactional.
A crash between a ban decision and journaling its notice can still lose that notice;
the stage 1.6 decision service/reconciler must close that separate gap.

## Admission and delivery

| Resource | Default behavior |
|---|---|
| Pending jobs | 2048; 512 reserved from routine traffic for critical jobs |
| Payload bytes | 16 MiB including grouping payloads; 4 MiB reserved for critical traffic |
| One recipient request body | 32 KiB; rendered Telegram text bounded before admission |
| Group windows | At most 512; at most 24 hours per window |
| Workers | One routine and one critical worker; provider calls capped at 20 seconds |
| Job lifetime | Seven days, then an explicit terminal failure |
| WAL transaction / snapshot | At most 24 MiB; compaction threshold 8 MiB |
| Recent terminal failures | Last 100 records; full message evidence remains in the journal |
| Retained daily receipts | At most 4096; retention prunes removed journal generations |

Routine overflow is explicitly counted; the journal event is retained but that notification
is not admitted. Critical overflow holds journal intake and the source cursor while workers
drain. A prolonged provider outage can therefore eventually pause event processing when
the critical reserve is exhausted. No finite queue can promise unlimited lossless delivery.

Rate budgets are shared by a bot route and all its recipients, not multiplied per chat.
About 20% of refill capacity is protected for critical traffic, which may also borrow
routine capacity. Buckets allow a startup burst; each share holds at least one token at
very small configured rates. Rate admission delays the job rather than discarding it.
Telegram 429 cooldowns are shared by the route's workers; per-job `retry_after` deadlines
are persisted. Retryable transport failures and server errors use exponential backoff
with stable per-job jitter. Other permanent 4xx rejections are terminal and inspectable.

Grouping starts only after the first successful send for that route/recipient/evidence
key. Failed attempts cannot swallow successors. Repeat counts and the final summary are
saved in the WAL; a summary becomes its own retryable job. If grouping storage is full,
delivery proceeds without opening another window. Summary admission follows the same
priority/overflow rules as other jobs.

Severity, category, mute and quiet-hours decisions are recorded when the plan is created.
They are rechecked before sending. Critical event alerts bypass mute and quiet hours;
explicit category disabling still applies. Disabling the channel, rotating its token or
removing a recipient cancels stale jobs. A saved job is never sent with replacement
credentials. Settings updates drain requests already in flight before activating changes.

These are notification payload/state bounds, not a total process memory guarantee. WAL
serialization, event assembly and existing whole-day store scans require additional memory.
External modifications/restoration of journal files without matching WAL receipts are
unsupported; truncated journals behind a receipt fail closed.

## Counters and API

`GET /api/v1/deliveries` requires a full panel session. It returns current queue stats and
safe terminal failure labels. The same stats are under `counters.delivery` in status and
diagnostics, and visible in the System panel.

- `queued`: admitted per-recipient jobs, including grouping summaries and automatic notices.
- `delivered`: jobs acknowledged by the provider and durably completed.
- `suppressed`: event/notice plans held by policy before admission, counted once per plan.
- `grouped`: recipient jobs folded into an acknowledged grouping window.
- `deferred`: rate-admission postponements; one job can be deferred more than once.
- `retries`: retry schedules after an unsuccessful provider request.
- `failed`: terminal provider rejections or expired jobs.
- `cancelled`: jobs invalidated by current policy or changed routes.
- `overflow`: recipient jobs/summaries not admitted because routine capacity was exhausted.
- `pending`, `critical_pending`, `in_flight`, `payload_bytes`: current occupancy.

Outcome counters survive restart. `alerts_sent` is a compatibility name for `delivered`;
`rate_limited` is a compatibility name for `deferred`. They do not count policy no-ops as
successful sends. These measures count different units (plans, recipient jobs and attempts)
and should not be added together as though each were an event count.
