"use strict";
// Signs an update document with the Ed25519 key in UPDATE_SIGNING_KEY (a PKCS#8
// PEM, as printed by update-keygen.cjs) and writes FILE.sig (base64). The key is
// a CI secret; without it nothing is signed and the build says so.
//
//   UPDATE_SIGNING_KEY=... node scripts/sign-update.cjs FILE
const crypto = require("node:crypto");
const fs = require("node:fs");

function sign(doc, pem) {
  return crypto.sign(null, doc, crypto.createPrivateKey(pem)).toString("base64");
}

if (require.main === module) {
  const file = process.argv[2];
  const pem = process.env.UPDATE_SIGNING_KEY;
  if (!file) { console.error("usage: sign-update.cjs FILE"); process.exit(2); }
  if (!pem) { console.error("UPDATE_SIGNING_KEY is not set: the document is NOT signed"); process.exit(4); }
  fs.writeFileSync(file + ".sig", sign(fs.readFileSync(file), pem) + "\n");
  console.log("signed " + file);
}
module.exports = { sign };
