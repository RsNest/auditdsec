"use strict";

// Exercise the selection policy without a browser or privileged stand.
const assert = require("node:assert/strict");
global.window = { ADS: { SEV_RANK: { info: 0, warn: 1, critical: 2 }, t: (k) => k, el() {}, add() {}, clear() {} } };
require("../internal/web/assets/feed.js");
const feed = window.ADS.feed;
const failed = (ip, id) => ({ id, src_ip: ip, kind: "ssh_login_fail", severity: "warn", time: "2026-10-10T12:00:00Z" });
const events = [failed("198.51.100.1", "a"), failed("198.51.100.1", "b"), failed("198.51.100.2", "c")];
const suspects = { items: [
  { ip: "198.51.100.1", attempts: 2, state: "review", event: failed("198.51.100.1", "suspect:1") },
  { ip: "198.51.100.2", attempts: 1, state: "review", event: failed("198.51.100.2", "suspect:2") }
] };
let selected = feed.selectDeck(events, suspects, [], []);
assert.equal(selected.length, 2);
assert.equal(selected[0].src_ip, "198.51.100.2", "one-off attempts should lead manual review");
const bans = [{ ip: "198.51.100.2", applied: true, permanent: true }];
selected = feed.selectDeck(events, suspects, bans, []);
assert.equal(selected.length, 1);
assert.equal(selected[0].src_ip, "198.51.100.1", "the next address must replace the blocked card");
assert.equal(feed.selectDeck(events, suspects, bans, [{ ip: "198.51.100.1" }]).length, 0);
assert.equal(feed.selectDeck(events, suspects, [{ ...bans[0], applied: false }], []).length, 2, "an unenforced decision must remain visible");
assert.equal(feed.selectDeck(events, null, [], []).length, 2, "fallback must not refill duplicates");
const critical = { ...failed("198.51.100.2", "critical"), kind: "login_after_bruteforce", severity: "critical" };
assert.equal(feed.selectDeck([critical], suspects, bans, [])[0].id, "critical", "blocking must not hide evidence of compromise");
const signature = feed.deckSignature(selected);
selected[0].attempts++;
assert.notEqual(feed.deckSignature(selected), signature, "counts must repaint even if the event ID stays the same");
assert.equal(events.length, 3, "review selection must not mutate journal data");
console.log("Panel review policy checks passed.");

// Session context in event details: honest about what is known.
{
  const ctxFeed = window.ADS.feed;
  const rows = (context) => ctxFeed.contextRows({ context }).map((r) => r.join("="));
  const sudo = rows({ login_uid: "1000", login_user: "alice", effective_uid: "0", effective_user: "root", session_id: "5", pid: "3001",
    session: { addr: "203.0.113.9", confidence: "observed", source: "audit" } });
  assert.ok(sudo.some((r) => r.includes("alice")) && sudo.some((r) => r.includes("root")), "login and effective identity are separate rows");
  assert.ok(sudo.some((r) => r.includes("203.0.113.9") && r.includes("ev.ctx.observed")), "an observed address says so");
  const inferred = rows({ session_id: "5", session: { addr: "198.51.100.4", confidence: "correlated", source: "journald" } });
  assert.ok(inferred.some((r) => r.includes("ev.ctx.correlated")), "an inferred address must not look observed");
  const unknown = rows({ login_uid: "1000", session_id: "9", session: { confidence: "unknown", note: "session not seen" } });
  assert.ok(unknown.some((r) => r.includes("ev.ctx.unknown") && r.includes("session not seen")), "unknown stays unknown, with the reason");
  assert.ok(!unknown.some((r) => /\d+\.\d+\.\d+\.\d+/.test(r)), "no address is invented");
  assert.deepEqual(ctxFeed.contextRows({}), [], "old events without context show nothing");
  console.log("Session context checks passed.");
}
