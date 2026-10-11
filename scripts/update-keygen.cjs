"use strict";
// Makes the signing key pair for update metadata. Run it once, on your own
// machine:
//
//   node scripts/update-keygen.cjs
//
// 1. Put the PRIVATE key (PEM) into the repository secret UPDATE_SIGNING_KEY.
//    Never commit it, never paste it into a chat or an issue.
// 2. Put the PUBLIC key (one line of base64) into internal/update/publickey.txt
//    and commit it. From that build on, installed agents accept only metadata
//    signed with your key.
const crypto = require("node:crypto");

const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
const raw = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
console.log("PUBLIC KEY (commit to internal/update/publickey.txt):\n" + raw.toString("base64") + "\n");
console.log("PRIVATE KEY (repository secret UPDATE_SIGNING_KEY, keep it secret):\n" + privateKey.export({ format: "pem", type: "pkcs8" }));
