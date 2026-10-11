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
