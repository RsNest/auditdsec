"use strict";

// Exercise the selection policy without a browser or privileged stand.
const assert = require("node:assert/strict");
global.window = { ADS: { SEV_RANK: { info: 0, warn: 1, critical: 2 } } };
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
