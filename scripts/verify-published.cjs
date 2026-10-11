"use strict";
// Publishing the update metadata and proving what was published.
//
// The metadata is a rolling file: the same name under the same URL, uploaded
// again with --clobber for every build. Two things can look like a failure:
//
//   * the release asset was replaced and the API has not caught up, or
//   * a cache in front of the public address still serves the previous copy.
//
// Neither means the document is damaged, and a damaged document must still be
// caught. So the publisher checks, in order:
//
//   1. the asset, by its ID and digest, through the API (authoritative: it is
//      what was stored, with no cache involved);
//   2. the public address, asking for a fresh copy (a changed address and
//      no-cache headers), with a few tries and growing pauses, and then says
//      which of these it saw: the same bytes; a newer build (another run
//      published after this one); an OLDER build (a stale copy); or something
//      that is not a valid copy of this document at all (corrupt).
//
// A stale copy that does not clear is a warning, because the stored asset was
// verified; a corrupt one fails. The signature and the validation of the
// document are done by `auditdsec update-validate`, which the workflow still
// runs on the bytes that were read back.
//
//   verify-published.cjs previous --repo R --channel C --out FILE
//   verify-published.cjs asset    --repo R --channel C --file FILE [--sig FILE]
//   verify-published.cjs public   --url URL --file FILE [--attempts N]
//
// Exit status of `public`: 0 same or newer, 10 stale, 1 corrupt or unreachable.
// Exit status of the others: 0 ok, 1 failed.

const crypto = require("node:crypto");
const fs = require("node:fs");
const cp = require("node:child_process");

const sha256 = (buf) => crypto.createHash("sha256").update(buf).digest("hex");

// parseDoc returns the fields worth printing, or null when buf is not an
// update document at all.
function parseDoc(buf) {
  try {
    const d = JSON.parse(Buffer.from(buf).toString("utf8"));
    if (!d || d.schema !== 1 || !Array.isArray(d.builds) || !d.builds.length || typeof d.channel !== "string") { return null; }
    const top = d.builds[0];
    if (!Number.isInteger(top.seq) || typeof top.commit !== "string") { return null; }
    return { channel: d.channel, seq: top.seq, commit: top.commit };
  } catch (e) { return null; }
}

// classify says what a copy read from the public address is, compared with the
// bytes that were uploaded.
function classify(expected, got) {
  if (sha256(expected) === sha256(got)) { return { kind: "match" }; }
  const want = parseDoc(expected), have = parseDoc(got);
  if (!have) { return { kind: "corrupt", reason: "not a valid update document", want, have }; }
  if (have.channel !== want.channel) { return { kind: "corrupt", reason: `a document for channel ${have.channel}`, want, have }; }
  if (have.seq < want.seq) { return { kind: "stale", reason: `an older build (${have.seq} < ${want.seq})`, want, have }; }
  if (have.seq > want.seq) { return { kind: "newer", reason: `a newer build (${have.seq} > ${want.seq}); another run published after this one`, want, have }; }
  return { kind: "corrupt", reason: "the same build number with different bytes", want, have };
}

const sleepMs = (ms) => new Promise((r) => setTimeout(r, ms));

// publicCheck reads the public address until it shows what was uploaded. fetchPublic(url) resolves to
// { status, body: Buffer, headers: {} }.
async function publicCheck({ fetchPublic, url, expected, attempts = 6, delays = [5000, 10000, 20000, 40000, 60000], sleep = sleepMs, log = () => {} }) {
  let last = null;
  for (let i = 0; i < attempts; i++) {
    if (i > 0) { await sleep(delays[Math.min(i - 1, delays.length - 1)]); }
    const bust = `${Date.now().toString(36)}${i}`;
    let res;
    try { res = await fetchPublic(`${url}${url.includes("?") ? "&" : "?"}cb=${bust}`); }
    catch (e) { last = { kind: "unreachable", reason: String(e.message || e).slice(0, 200), attempt: i + 1 }; log(last); continue; }
    if (res.status !== 200) { last = { kind: "unreachable", reason: `HTTP ${res.status}`, status: res.status, headers: res.headers, attempt: i + 1 }; log(last); continue; }
    const c = classify(expected, res.body);
    last = { ...c, status: res.status, headers: res.headers, gotSha: sha256(res.body), attempt: i + 1 };
    log(last);
    if (c.kind === "match" || c.kind === "newer") { return last; }
    if (c.kind === "corrupt") {
      // A corrupt answer is retried too (a partial copy from a cache is
      // possible), but if it stays corrupt it is reported as such.
      continue;
    }
  }
  return last;
}

// checkAsset proves what was stored, by ID and digest. api(method, path, opts)
// resolves to { status, body } (body: parsed JSON, or a Buffer when opts.raw).
async function checkAsset({ api, repo, name, expected, attempts = 5, sleep = sleepMs, log = () => {} }) {
  const want = "sha256:" + sha256(expected);
  let last = "";
  for (let i = 0; i < attempts; i++) {
    if (i > 0) { await sleep(Math.min(3000 * 2 ** (i - 1), 30000)); }
    const rel = await api("GET", `repos/${repo}/releases/tags/updates`);
    if (rel.status !== 200) { last = `the release lookup answered HTTP ${rel.status}`; log(last); continue; }
    const asset = (rel.body.assets || []).find((a) => a.name === name);
    if (!asset) { last = `the asset ${name} is not on the release`; log(last); continue; }
    let digest = asset.digest || "";
    if (!digest) {
      const dl = await api("GET", `repos/${repo}/releases/assets/${asset.id}`, { raw: true });
      if (dl.status !== 200) { last = `the asset ${asset.id} could not be read (HTTP ${dl.status})`; log(last); continue; }
      digest = "sha256:" + sha256(dl.body);
    }
    if (digest === want) { return { id: asset.id, digest, size: asset.size }; }
    last = `asset ${asset.id} has digest ${digest}, expected ${want}`;
    log(last);
  }
  throw new Error(`${name}: ${last}`);
}

// fetchPrevious returns the previous document's bytes, or null when there is
// none. "None" is only a 404 (no release yet, or no such asset): any other
// answer is a failure that is retried and then thrown, because treating a
// network error as "nothing there" would restart the build numbers.
async function fetchPrevious({ api, repo, name, attempts = 4, sleep = sleepMs, log = () => {} }) {
  let last = "";
  for (let i = 0; i < attempts; i++) {
    if (i > 0) { await sleep(2000 * 2 ** (i - 1)); }
    let rel;
    try { rel = await api("GET", `repos/${repo}/releases/tags/updates`); }
    catch (e) { last = String(e.message || e).slice(0, 200); log(last); continue; }
    if (rel.status === 404) { return null; }
    if (rel.status !== 200) { last = `the release lookup answered HTTP ${rel.status}`; log(last); continue; }
    const asset = (rel.body.assets || []).find((a) => a.name === name);
    if (!asset) { return null; }
    let dl;
    try { dl = await api("GET", `repos/${repo}/releases/assets/${asset.id}`, { raw: true }); }
    catch (e) { last = String(e.message || e).slice(0, 200); log(last); continue; }
    if (dl.status === 404) { return null; }
    if (dl.status !== 200) { last = `the asset download answered HTTP ${dl.status}`; log(last); continue; }
    return dl.body;
  }
  throw new Error(`could not read the previous ${name}: ${last}. Not continuing: building without the history would restart the build numbers.`);
}

// ---- the real transports --------------------------------------------------

// ghApi runs `gh api`; gh reports an HTTP error as a failed exit with
// "(HTTP 404)" on standard error.
function ghApi(method, path, opts = {}) {
  const args = ["api", "-X", method, path];
  if (opts.raw) { args.push("-H", "Accept: application/octet-stream"); }
  const r = cp.spawnSync("gh", args, { maxBuffer: 64 << 20 });
  if (r.error) { throw r.error; }
  if (r.status === 0) { return Promise.resolve({ status: 200, body: opts.raw ? r.stdout : JSON.parse(r.stdout.toString("utf8")) }); }
  const m = /HTTP (\d{3})/.exec(r.stderr.toString("utf8"));
  if (!m) { throw new Error("gh api failed: " + r.stderr.toString("utf8").slice(0, 200)); }
  return Promise.resolve({ status: Number(m[1]), body: null });
}

// fetchPublic asks the public address for a fresh copy. It reports only what is
// safe to print about the answer.
async function fetchPublic(url) {
  const res = await fetch(url, { cache: "no-store", redirect: "follow", headers: { "Cache-Control": "no-cache", Pragma: "no-cache", "User-Agent": "auditdsec-publish-check" } });
  const body = Buffer.from(await res.arrayBuffer());
  const pick = ["etag", "age", "x-cache", "cache-control", "last-modified", "content-length", "x-github-request-id"];
  const headers = { host: new URL(res.url).hostname };
  for (const h of pick) { if (res.headers.get(h)) { headers[h] = res.headers.get(h); } }
  return { status: res.status, body, headers };
}

function describe(r) {
  const lines = [`  result:   ${r.kind}${r.reason ? " - " + r.reason : ""}`];
  if (r.want) { lines.push(`  expected: commit ${r.want.commit}, seq ${r.want.seq}`); }
  if (r.have) { lines.push(`  received: commit ${r.have.commit}, seq ${r.have.seq}`); }
  if (r.gotSha) { lines.push(`  received sha256: ${r.gotSha}`); }
  if (r.status) { lines.push(`  HTTP ${r.status}, ${JSON.stringify(r.headers || {})}`); }
  return lines.join("\n");
}

async function main(argv) {
  const [cmd, ...rest] = argv;
  const opt = (n, d = "") => { const i = rest.indexOf("--" + n); return i >= 0 ? rest[i + 1] : d; };
  const log = (x) => console.error(typeof x === "string" ? "  " + x : `  attempt ${x.attempt || "?"}: ${x.kind}${x.reason ? " (" + x.reason + ")" : ""}`);
  if (cmd === "previous") {
    const buf = await fetchPrevious({ api: ghApi, repo: opt("repo"), name: `${opt("channel")}.json`, log });
    if (buf === null) { fs.writeFileSync(opt("out"), ""); console.log("no previous document (HTTP 404): this is the first publication on this channel"); }
    else { fs.writeFileSync(opt("out"), buf); const d = parseDoc(buf); console.log(`previous document read from the release asset: seq ${d ? d.seq : "?"}, ${buf.length} bytes`); }
    return 0;
  }
  if (cmd === "asset") {
    const files = [[`${opt("channel")}.json`, opt("file")]];
    if (opt("sig")) { files.push([`${opt("channel")}.json.sig`, opt("sig")]); }
    for (const [name, file] of files) {
      const a = await checkAsset({ api: ghApi, repo: opt("repo"), name, expected: fs.readFileSync(file), log });
      console.log(`${name}: asset ${a.id}, ${a.size} bytes, ${a.digest} - the stored bytes are the uploaded bytes`);
    }
    return 0;
  }
  if (cmd === "public") {
    const expected = fs.readFileSync(opt("file"));
    const r = await publicCheck({ fetchPublic, url: opt("url"), expected, attempts: Number(opt("attempts", "6")), log });
    if (r.kind === "match") { console.log(`the public copy matches (attempt ${r.attempt}), sha256 ${r.gotSha}`); return 0; }
    if (r.kind === "newer") { console.log("the public copy is a newer build:\n" + describe(r)); return 0; }
    console.error(`expected sha256: ${sha256(expected)}\n` + describe(r));
    return r.kind === "stale" ? 10 : 1;
  }
  console.error("usage: verify-published.cjs previous|asset|public ...");
  return 2;
}

if (require.main === module) {
  main(process.argv.slice(2)).then((c) => process.exit(c), (e) => { console.error("verify-published: " + e.message); process.exit(1); });
}
module.exports = { sha256, parseDoc, classify, publicCheck, checkAsset, fetchPrevious };
