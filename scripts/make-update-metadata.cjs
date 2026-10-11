"use strict";
// Builds the update metadata of a channel from the previous document, the
// reviewed release notes and the images that were really published.
//
//   node scripts/make-update-metadata.cjs --channel main|stable --commit SHA --version V \
//        --published ISO --images images.json [--previous prev.json] --out out.json
//
// Exit status 3 means "do not publish": the previous document is already for
// this commit or for a newer one (a slow run must never move the channel back).
//
// CI runs this only after the tests passed, every image was pushed and was
// pulled back anonymously, so the document can never name an image that is not
// there yet.

const fs = require("node:fs");
const cp = require("node:child_process");
const { load, problems, publishable } = require("./release-notes.cjs");

const MAX_BUILDS = 60;
const SHA = /^[0-9a-f]{40}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;

function arg(argv, name, required = true) {
  const i = argv.indexOf("--" + name);
  if (i < 0 || i + 1 >= argv.length) {
    if (required) { throw new Error(`--${name} is required`); }
    return "";
  }
  return argv[i + 1];
}

function isAncestor(a, b) {
  try { cp.execFileSync("git", ["merge-base", "--is-ancestor", a, b], { stdio: "ignore" }); return true; }
  catch (e) { return false; }
}

function build({ channel, commit, version, published, images, previous, entries, isNewer }) {
  if (!["main", "stable"].includes(channel)) { throw new Error("channel must be main or stable"); }
  if (!SHA.test(commit)) { throw new Error("commit must be 40 hex digits"); }
  if (!version || version.length > 64) { throw new Error("version is required"); }
  if (Number.isNaN(Date.parse(published))) { throw new Error("published must be an ISO time"); }
  const agent = images && images.auditdsec;
  if (!agent || !DIGEST.test(agent.digest) || !(agent.platforms || []).length) { throw new Error("the agent image with a digest and platforms is required"); }
  for (const [name, img] of Object.entries(images)) {
    if (!DIGEST.test(img.digest) || !String(img.ref).startsWith("ghcr.io/")) { throw new Error(`image ${name} is incomplete`); }
    if (!(img.platforms || []).includes("linux/amd64") || !(img.platforms || []).includes("linux/arm64")) { throw new Error(`image ${name} is not published for both amd64 and arm64`); }
  }
  const prev = previous && previous.builds ? previous.builds : [];
  if (previous && previous.channel && previous.channel !== channel) { throw new Error("the previous document is for another channel"); }
  if (prev.length) {
    const top = prev[0];
    if (top.commit === commit) { return { skip: false, doc: rebuildSame(previous, images, version, published, commit) }; }
    if (isNewer && !isNewer(commit, top.commit)) { return { skip: true, reason: `the channel already has ${top.commit}, which is not older than ${commit}` }; }
  }
  const shipped = new Set(prev.flatMap((b) => (b.entries || []).map((e) => e.id)));
  const fresh = entries.filter((e) => !shipped.has(e.id)).map(publishable).sort((a, b) => a.id.localeCompare(b.id));
  const seq = (prev.length ? prev[0].seq : 0) + 1;
  const builds = [{ seq, version, commit, published, images, entries: fresh }, ...prev.map((b) => ({ ...b, images: undefined }))].slice(0, MAX_BUILDS);
  // Older builds keep their notes and identity; their images are not needed.
  return {
    skip: false,
    doc: { schema: 1, channel, repo: "RsNest/auditdsec", generated_at: published, builds },
  };
}

// The same commit published again (a re-run): keep the order number.
function rebuildSame(previous, images, version, published, commit) {
  const builds = previous.builds.map((b, i) => (i === 0 ? { ...b, images, version, commit } : b));
  return { schema: 1, channel: previous.channel, repo: previous.repo, generated_at: published, builds };
}

function main(argv) {
  const channel = arg(argv, "channel");
  const entries = load().map(({ file, entry, error }) => {
    if (error) { throw new Error(`${file}: ${error}`); }
    const p = problems(entry, file);
    if (p.length) { throw new Error(p.join("\n")); }
    return entry;
  });
  const imagesFile = arg(argv, "images");
  const prevFile = arg(argv, "previous", false);
  const previous = prevFile && fs.existsSync(prevFile) && fs.statSync(prevFile).size > 0 ? JSON.parse(fs.readFileSync(prevFile, "utf8")) : null;
  const r = build({
    channel, commit: arg(argv, "commit"), version: arg(argv, "version"), published: arg(argv, "published"),
    images: JSON.parse(fs.readFileSync(imagesFile, "utf8")), previous, entries,
    isNewer: (cand, existing) => !isAncestor(cand, existing),
  });
  if (r.skip) { console.error("skipped: " + r.reason); process.exit(3); }
  fs.writeFileSync(arg(argv, "out"), JSON.stringify(r.doc, null, 1) + "\n");
  console.log(`channel ${channel}: build ${r.doc.builds[0].seq}, ${r.doc.builds[0].entries.length} new note entries, ${r.doc.builds.length} builds kept`);
}

if (require.main === module) {
  try { main(process.argv.slice(2)); } catch (e) { console.error("make-update-metadata: " + e.message); process.exit(1); }
}
module.exports = { build, MAX_BUILDS };
