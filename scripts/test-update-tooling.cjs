"use strict";
// Offline checks of the release-notes validator, the metadata generator and
// the signing script. Run by CI: node --test scripts/test-update-tooling.cjs
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { problems } = require("./release-notes.cjs");
const { build, MAX_BUILDS } = require("./make-update-metadata.cjs");
const { sign } = require("./sign-update.cjs");

const good = () => ({
  id: "2026-10-11-example-change", date: "2026-10-11",
  title: { en: "Example", ru: "Пример" },
  added: { en: ["Something new."], ru: ["Что-то новое."] },
  breaking: [], requires: { installer_update: false, migration: "none" },
  evidence: ["scripts/release-notes.cjs"],
});
const FILE = "release-notes/entries/2026-10-11-example-change.json";

test("a good entry passes", () => { assert.deepEqual(problems(good(), FILE), []); });

test("what must be refused", () => {
  const bad = {
    "id and file differ": (e) => { e.id = "2026-10-11-other-name"; },
    "no Russian": (e) => { e.title.ru = ""; },
    "Russian without Cyrillic": (e) => { e.added.ru = ["Something new."]; },
    "English with Cyrillic": (e) => { e.added.en = ["Что-то новое."]; },
    "lists of different length": (e) => { e.added.ru = ["Раз.", "Два."]; },
    "an empty entry": (e) => { e.added = { en: [], ru: [] }; },
    "too many items": (e) => { e.added = { en: Array(9).fill("x."), ru: Array(9).fill("х.") }; },
    "a long item": (e) => { e.added.en = ["x".repeat(300)]; },
    "no evidence": (e) => { e.evidence = []; },
    "evidence that does not exist": (e) => { e.evidence = ["internal/nothing/here"]; },
    "a path escaping the repository": (e) => { e.evidence = ["../etc/passwd"]; },
    "a bot token": (e) => { e.added.en = ["Set 123456789:AAbbCCddEEffGGhhIIjjKKllMMnnOOppQQr now."]; },
    "a password": (e) => { e.added.en = ["Use password=hunter2 for it."]; },
    "a real IP": (e) => { e.added.en = ["Moved to 8.8.4.4 today."]; },
    "an e-mail": (e) => { e.added.en = ["Write to boss@company.io."]; },
    "a local path": (e) => { e.added.en = ["Edit /home/ruslan/x."]; },
    "tooling names": (e) => { e.added.en = ["Written by Claude."]; },
    "an irreversible migration without a warning": (e) => { e.requires.migration = "irreversible"; },
    "a bad migration kind": (e) => { e.requires.migration = "maybe"; },
    "a digest": (e) => { e.added.en = ["Pin sha256:" + "a".repeat(64) + "."]; },
  };
  for (const [name, mutate] of Object.entries(bad)) {
    const e = good();
    mutate(e);
    assert.ok(problems(e, FILE).length > 0, name + " was accepted");
  }
  const ok = good();
  ok.added.en = ["Example host 203.0.113.9 and 127.0.0.1 are fine."];
  assert.deepEqual(problems(ok, FILE), [], "documentation addresses are allowed");
});

const images = () => Object.fromEntries(["auditdsec", "auditdsec-enforce", "auditdsec-probe"].map((n) => [n, {
  ref: "ghcr.io/rsnest/" + n + ":sha-x", digest: "sha256:" + "b".repeat(64), platforms: ["linux/amd64", "linux/arm64"],
}]));
const sha = (n) => n.toString(16).padStart(40, "0");
const entry = (id) => ({ ...good(), id: "2026-10-11-" + id, evidence: undefined });
const base = (o) => ({ channel: "main", version: "0.3.0-dev+x", published: "2026-10-11T10:00:00Z", images: images(), entries: [entry("one-aaa")], isNewer: () => true, ...o });

test("the first publication and the ones after it", () => {
  const first = build(base({ commit: sha(1), previous: null })).doc;
  assert.equal(first.builds[0].seq, 1);
  assert.equal(first.builds[0].entries.length, 1);
  const second = build(base({ commit: sha(2), previous: first, entries: [entry("one-aaa"), entry("two-bbb")] })).doc;
  assert.equal(second.builds[0].seq, 2);
  assert.deepEqual(second.builds[0].entries.map((e) => e.id), ["2026-10-11-two-bbb"], "an entry ships once, in the build that first has it");
  assert.equal(second.builds[1].entries.length, 1, "the earlier build keeps its notes");
  assert.equal(second.builds[1].images, undefined);
});

test("order is a counter, never a comparison of commits", () => {
  let doc = null;
  for (const c of [0xfff, 0x100, 0x500]) { doc = build(base({ commit: sha(c), previous: doc })).doc; }
  assert.deepEqual(doc.builds.map((b) => b.seq), [3, 2, 1]);
});

test("an older run does not move the channel back", () => {
  const first = build(base({ commit: sha(5), previous: null })).doc;
  const r = build(base({ commit: sha(4), previous: first, isNewer: () => false }));
  assert.equal(r.skip, true);
});

test("the same commit published again keeps its number", () => {
  const first = build(base({ commit: sha(5), previous: null })).doc;
  const again = build(base({ commit: sha(5), previous: first })).doc;
  assert.equal(again.builds.length, 1);
  assert.equal(again.builds[0].seq, 1);
});

test("the history is bounded", () => {
  let doc = null;
  for (let i = 1; i <= MAX_BUILDS + 5; i++) { doc = build(base({ commit: sha(i), previous: doc, entries: [] })).doc; }
  assert.equal(doc.builds.length, MAX_BUILDS);
  assert.equal(doc.builds[0].seq, MAX_BUILDS + 5);
});

test("nothing is published without all images on both platforms", () => {
  const partial = images();
  partial["auditdsec-probe"].platforms = ["linux/amd64"];
  assert.throws(() => build(base({ commit: sha(1), previous: null, images: partial })), /both amd64 and arm64/);
  const noDigest = images();
  noDigest.auditdsec.digest = "latest";
  assert.throws(() => build(base({ commit: sha(1), previous: null, images: noDigest })), /agent image/);
  assert.throws(() => build(base({ commit: "main", previous: null })), /40 hex/);
  assert.throws(() => build(base({ commit: sha(1), previous: { channel: "stable", builds: [] }, channel: "main" })), /another channel/);
});

test("a signature made here verifies with the public key and with nothing else", () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const pem = privateKey.export({ format: "pem", type: "pkcs8" });
  const doc = Buffer.from('{"x":1}\n');
  const sig = Buffer.from(sign(doc, pem), "base64");
  assert.equal(sig.length, 64);
  assert.ok(crypto.verify(null, doc, publicKey, sig));
  assert.ok(!crypto.verify(null, Buffer.from('{"x":2}\n'), publicKey, sig));
});

// ---- publishing and reading back ------------------------------------------

const V = require("./verify-published.cjs");
const docBytes = (seq, commit = "a".repeat(40)) =>
  Buffer.from(JSON.stringify({ schema: 1, channel: "main", repo: "RsNest/auditdsec", builds: [{ seq, commit, version: "v" }] }));
const noSleep = () => Promise.resolve();

test("classify tells a stale copy from a corrupt one", () => {
  const want = docBytes(5, "b".repeat(40));
  assert.equal(V.classify(want, want).kind, "match");
  assert.equal(V.classify(want, docBytes(4)).kind, "stale", "an older build is a stale copy");
  assert.equal(V.classify(want, docBytes(6)).kind, "newer", "a newer build means another run published after this one");
  assert.equal(V.classify(want, Buffer.from("<html>502</html>")).kind, "corrupt", "not a document at all");
  assert.equal(V.classify(want, Buffer.from(want.toString().slice(0, 40))).kind, "corrupt", "a truncated copy");
  assert.equal(V.classify(want, docBytes(5, "c".repeat(40))).kind, "corrupt", "the same build number with other content");
  const other = Buffer.from(JSON.stringify({ schema: 1, channel: "stable", builds: [{ seq: 9, commit: "d".repeat(40) }] }));
  assert.equal(V.classify(want, other).kind, "corrupt", "another channel's document");
});

test("a stale public copy clears after a retry with a changed address", async () => {
  const want = docBytes(5, "b".repeat(40));
  const urls = [];
  const fetchPublic = async (url) => {
    urls.push(url);
    return { status: 200, body: urls.length < 3 ? docBytes(4) : want, headers: { age: "120" } };
  };
  const r = await V.publicCheck({ fetchPublic, url: "https://example.test/main.json", expected: want, sleep: noSleep });
  assert.equal(r.kind, "match");
  assert.equal(r.attempt, 3);
  assert.equal(new Set(urls.map((u) => new URL(u).searchParams.get("cb"))).size, 3, "every try asks a new question");
});

test("a stale copy that does not clear is reported as stale, with both sides", async () => {
  const want = docBytes(5, "b".repeat(40));
  const pauses = [];
  const r = await V.publicCheck({
    fetchPublic: async () => ({ status: 200, body: docBytes(4), headers: { "x-cache": "HIT" } }),
    url: "https://example.test/main.json", expected: want, attempts: 4, sleep: async (ms) => { pauses.push(ms); },
  });
  assert.equal(r.kind, "stale");
  assert.deepEqual([r.want.seq, r.have.seq], [5, 4]);
  assert.equal(r.want.commit, "b".repeat(40));
  assert.equal(r.gotSha, V.sha256(docBytes(4)));
  assert.deepEqual(pauses, [5000, 10000, 20000], "pauses grow");
});

test("a corrupt public copy stays corrupt, and a down address is not 'stale'", async () => {
  const want = docBytes(5);
  const corrupt = await V.publicCheck({ fetchPublic: async () => ({ status: 200, body: Buffer.from("garbage"), headers: {} }), url: "https://e.test/m.json", expected: want, attempts: 2, sleep: noSleep });
  assert.equal(corrupt.kind, "corrupt");
  const down = await V.publicCheck({ fetchPublic: async () => ({ status: 503, body: Buffer.alloc(0), headers: {} }), url: "https://e.test/m.json", expected: want, attempts: 2, sleep: noSleep });
  assert.equal(down.kind, "unreachable");
  assert.equal(down.status, 503);
});

// A fake release API whose assets are replaced on every upload, like --clobber.
function fakeRelease() {
  const state = { assets: [], nextId: 100, lagReads: 0 };
  const upload = (name, bytes) => {
    state.assets = state.assets.filter((a) => a.name !== name);
    state.assets.push({ id: state.nextId++, name, size: bytes.length, bytes, digest: "sha256:" + V.sha256(bytes) });
  };
  const api = async (method, path, opts = {}) => {
    if (path.endsWith("/releases/tags/updates")) {
      if (state.missing) { return { status: 404, body: null }; }
      if (state.failing) { return { status: 502, body: null }; }
      return { status: 200, body: { assets: state.assets.map(({ bytes, ...a }) => (state.noDigest ? { ...a, digest: undefined } : a)) } };
    }
    const m = /\/releases\/assets\/(\d+)$/.exec(path);
    const a = m && state.assets.find((x) => x.id === Number(m[1]));
    if (!a) { return { status: 404, body: null }; }
    return { status: 200, body: opts.raw ? a.bytes : a };
  };
  return { state, upload, api };
}

test("re-publishing under the same name: the asset is checked by ID and digest", async () => {
  const rel = fakeRelease();
  rel.upload("main.json", docBytes(4));
  const first = rel.state.assets[0].id;
  rel.upload("main.json", docBytes(5, "b".repeat(40))); // --clobber: a new asset under the same name
  const bytes = docBytes(5, "b".repeat(40));
  const a = await V.checkAsset({ api: rel.api, repo: "o/r", name: "main.json", expected: bytes, sleep: noSleep });
  assert.notEqual(a.id, first, "the replaced asset has a new ID");
  assert.equal(a.digest, "sha256:" + V.sha256(bytes));
  // Without the digest field the stored bytes are downloaded by ID and hashed.
  rel.state.noDigest = true;
  assert.equal((await V.checkAsset({ api: rel.api, repo: "o/r", name: "main.json", expected: bytes, sleep: noSleep })).id, a.id);
  // Different stored bytes are an error that names both digests.
  await assert.rejects(V.checkAsset({ api: rel.api, repo: "o/r", name: "main.json", expected: docBytes(7), attempts: 2, sleep: noSleep }), /expected sha256:/);
  await assert.rejects(V.checkAsset({ api: rel.api, repo: "o/r", name: "main.json.sig", expected: bytes, attempts: 2, sleep: noSleep }), /not on the release/);
});

test("the previous document: 404 is 'none', a failure is not", async () => {
  const rel = fakeRelease();
  rel.state.missing = true;
  assert.equal(await V.fetchPrevious({ api: rel.api, repo: "o/r", name: "main.json", sleep: noSleep }), null, "no release yet: the first publication");
  rel.state.missing = false;
  assert.equal(await V.fetchPrevious({ api: rel.api, repo: "o/r", name: "main.json", sleep: noSleep }), null, "no such asset: the first on this channel");
  rel.upload("main.json", docBytes(41));
  const got = await V.fetchPrevious({ api: rel.api, repo: "o/r", name: "main.json", sleep: noSleep });
  assert.equal(V.parseDoc(got).seq, 41, "the history is read from the stored asset, not from a cached address");
  // A server error or a network failure must NOT look like 'no history': that would restart the build numbers.
  rel.state.failing = true;
  await assert.rejects(V.fetchPrevious({ api: rel.api, repo: "o/r", name: "main.json", attempts: 3, sleep: noSleep }), /Not continuing/);
  let calls = 0;
  const flaky = async (...a) => { if (++calls < 3) { throw new Error("socket hang up"); } rel.state.failing = false; return rel.api(...a); };
  assert.equal(V.parseDoc(await V.fetchPrevious({ api: flaky, repo: "o/r", name: "main.json", attempts: 4, sleep: noSleep })).seq, 41, "a transient failure is retried");
});
