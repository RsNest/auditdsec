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

// Version and updates: a failed check is never shown as "up to date", and the
// indicator follows what is known.
{
  require("../internal/web/assets/updates.js");
  const U = window.ADS.Updates;
  assert.equal(U.stateText(null), "upd.state.checking");
  assert.equal(U.stateText({ state: "up_to_date" }), "upd.state.current");
  assert.equal(U.stateText({ state: "available" }), "upd.state.available");
  assert.equal(U.stateText({ state: "unavailable" }), "upd.state.unavailable");
  assert.notEqual(U.stateText({ state: "unavailable", pending: false }), "upd.state.current", "a failed check must not read as current");
  assert.notEqual(U.stateText({ state: "unknown_installed" }), "upd.state.current", "an unplaceable build must not read as current");
  assert.equal(U.stateText({ state: "never" }), "upd.state.never");
  assert.equal(U.stateText({ state: "disabled" }), "upd.state.disabled");
  U.set({ state: "up_to_date", pending: false });
  assert.equal(U.pending(), false);
  U.set({ state: "available", pending: true });
  assert.equal(U.pending(), true, "an available update shows the indicator");
  U.set({ state: "unavailable", pending: true });
  assert.equal(U.pending(), true, "the indicator stays while the source is down, the state says it is stale");
  console.log("Update indicator checks passed.");
}

// The browser error reporter: only while signed in, text only, no query
// strings, identical errors counted once, a bounded queue and bounded retries,
// and it never reports its own failures.
{
  const listeners = {};
  const sent = [];
  let answer = { ok: true, status: 204 };
  global.window = { addEventListener: (n, f) => { listeners[n] = f; } };
  Object.defineProperty(global, "navigator", { value: { userAgent: "UA/1" }, configurable: true });
  global.location = { hash: "#/events?ip=203.0.113.9&session=SECRET", pathname: "/" };
  Object.defineProperty(global, "crypto", { value: require("node:crypto").webcrypto, configurable: true });
  global.fetch = (url, o) => { sent.push({ url, body: JSON.parse(o.body), headers: o.headers }); return Promise.resolve(answer); };
  const timers = [];
  global.setTimeout = (f, ms) => { timers.push({ f, ms }); return timers.length; };
  delete require.cache[require.resolve("../internal/web/assets/report.js")];
  require("../internal/web/assets/report.js");
  const R = window.AUDITDSEC_REPORT;
  let token = null;
  R.provide({ token: () => token, build: () => "v9" });
  assert.match(R.requestId(), /^[0-9a-f]{32}$/, "request IDs have the shape the server accepts");

  R.report("error", "before sign-in", { source: "https://x/app.js?token=SECRET", line: 3 });
  assert.equal(sent.length, 0, "nothing is sent without a session");
  token = "tok";
  R.flush();
  const drain = async () => { for (let i = 0; i < 20; i++) { await Promise.resolve(); while (timers.length) { timers.shift().f(); } } };
  (async () => {
    await drain();
    assert.equal(sent.length, 1);
    const b = sent[0].body;
    assert.equal(sent[0].url, "/api/v1/client-log");
    assert.equal(sent[0].headers["X-Requested-With"], "auditdsec");
    assert.equal(sent[0].headers.Authorization, "Bearer tok");
    assert.ok(!JSON.stringify(b).includes("SECRET") && !JSON.stringify(b).includes("203.0.113.9"), "query strings never leave the page");
    assert.equal(b.route, "#/events");
    assert.equal(b.build, "v9");

    // The same error, many times: one report with a count.
    sent.length = 0;
    answer = { ok: false, status: 503 };
    for (let i = 0; i < 5; i++) { R.report("error", "same", { line: 1 }); }
    for (let i = 0; i < 100; i++) { R.report("error", "distinct " + i, {}); }
    await drain();
    const same = sent.filter((s) => s.body.message === "same");
    assert.ok(same.length >= 1 && same.every((s) => s.body.count === 1 || s.body.count === 5), "identical errors are merged, not queued five times");
    const distinct = new Set(sent.map((s) => s.body.message));
    assert.ok(distinct.size <= 21, "the queue is bounded, got " + distinct.size);
    // A failing server is tried a limited number of times, then dropped.
    const per = sent.filter((s) => s.body.message === "same").length;
    assert.ok(per <= 4, "at most one try and three retries, got " + per);
    // 401 is not retried.
    sent.length = 0;
    answer = { ok: false, status: 401 };
    R.report("error", "after logout", {});
    await drain();
    assert.equal(sent.filter((s) => s.body.message === "after logout").length, 1, "an expired session is not retried");
    console.log("Browser error reporter checks passed.");
  })().catch((e) => { console.error(e); process.exit(1); });
}
