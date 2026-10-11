"use strict";
// Turns the raw manifests of published images into the images part of the
// update metadata: the digest (the SHA-256 of the manifest bytes, which is what
// the registry calls the digest) and the platforms of each image.
//
//   node scripts/describe-images.cjs OUT.json NAME=REF=RAWFILE [NAME=REF=RAWFILE ...]
//
// RAWFILE is the output of `docker buildx imagetools inspect --raw REF`.
const crypto = require("node:crypto");
const fs = require("node:fs");

function describe(ref, raw) {
  const doc = JSON.parse(raw.toString("utf8"));
  const platforms = [];
  for (const m of doc.manifests || []) {
    const p = m.platform || {};
    // Provenance and SBOM attachments are listed as unknown/unknown.
    if (p.os && p.architecture && p.os !== "unknown") {
      const name = `${p.os}/${p.architecture}${p.variant ? "/" + p.variant : ""}`;
      if (!platforms.includes(name)) { platforms.push(name); }
    }
  }
  if (!platforms.length) { throw new Error(`${ref}: the manifest lists no platforms (a single-platform image?)`); }
  return { ref, digest: "sha256:" + crypto.createHash("sha256").update(raw).digest("hex"), platforms: platforms.sort() };
}

if (require.main === module) {
  const [out, ...items] = process.argv.slice(2);
  if (!out || !items.length) { console.error("usage: describe-images.cjs OUT.json NAME=REF=RAWFILE ..."); process.exit(2); }
  const images = {};
  for (const it of items) {
    const [name, ref, file] = it.split("=");
    if (!name || !ref || !file) { console.error("bad argument " + it); process.exit(2); }
    images[name] = describe(ref, fs.readFileSync(file));
  }
  fs.writeFileSync(out, JSON.stringify(images, null, 1) + "\n");
  console.log("described " + Object.keys(images).join(", "));
}
module.exports = { describe };
