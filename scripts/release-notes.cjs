"use strict";
// Release notes: validation and the shape used by the update metadata.
//
//   node scripts/release-notes.cjs check     validate every entry (CI runs this)
//   node scripts/release-notes.cjs draft [--since COMMIT]
//                                            print a skeleton to complete BY HAND
//
// The notes are written and reviewed in the repository, like code. An AI
// assistant may help draft them from the diff, the pull request and the commit
// messages while developing, but nothing here calls one, nothing on an
// installed server does, and the text that ships is the reviewed text.

const fs = require("node:fs");
const path = require("node:path");
const cp = require("node:child_process");

const ROOT = path.join(__dirname, "..");
const DIR = path.join(ROOT, "release-notes", "entries");
const LISTS = ["added", "fixed", "changed", "actions"];
const LANGS = ["en", "ru"];
const MAX_ITEM = 220, MAX_ITEMS = 8, MAX_TITLE = 100;

// Anything that looks like a secret or like development-internal material.
const FORBIDDEN = [
  [/\b\d{6,}:[A-Za-z0-9_-]{20,}\b/, "a Telegram bot token"],
  [/\bgh[pousr]_[A-Za-z0-9]{20,}\b/, "a GitHub token"],
  [/\bAKIA[0-9A-Z]{16}\b/, "a cloud access key"],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, "a private key"],
  [/\b(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*\S+/i, "a credential assignment"],
  [/\bpbkdf2-sha256\$/, "a password hash"],
  [/[A-Za-z]:\\\\?(Users|Windows)\\/i, "a Windows path"],
  [/\/(home|Users|root)\/[A-Za-z0-9._-]+/, "a local path"],
  [/\b[A-Za-z0-9._%+-]+@(?!example\.(com|org|net)\b)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/, "an e-mail address"],
  [/\b(claude|anthropic|chatgpt|openai|co-authored-by|wip\/|todo|fixme|hack)\b/i, "an internal or tooling reference"],
  [/\bsha256:[0-9a-f]{64}\b/, "an image digest (those belong to the metadata, not the text)"],
];
// Documentation addresses only: any other literal IPv4 is a real server.
const IPV4 = /\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g;
const DOC_NETS = [[192, 0, 2], [198, 51, 100], [203, 0, 113]];

function problems(entry, file) {
  const out = [];
  const bad = (m) => out.push(`${file}: ${m}`);
  const id = path.basename(file, ".json");
  if (!/^\d{4}-\d{2}-\d{2}-[a-z0-9][a-z0-9-]{2,60}$/.test(entry.id || "")) { bad("id must look like 2026-10-11-short-name"); }
  if (entry.id !== id) { bad(`id "${entry.id}" must equal the file name "${id}"`); }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(entry.date || "") || Number.isNaN(Date.parse(entry.date))) { bad("date must be YYYY-MM-DD"); }
  const texts = [];
  for (const l of LANGS) {
    const t = entry.title && entry.title[l];
    if (typeof t !== "string" || !t.trim() || t.length > MAX_TITLE) { bad(`title.${l} is required (up to ${MAX_TITLE} characters)`); } else { texts.push(t); }
  }
  let items = 0;
  for (const k of LISTS) {
    const block = entry[k];
    if (block === undefined) { continue; }
    for (const l of LANGS) {
      const list = block && block[l];
      if (!Array.isArray(list)) { bad(`${k}.${l} must be a list`); continue; }
      if (list.length > MAX_ITEMS) { bad(`${k}.${l} has more than ${MAX_ITEMS} items: say less`); }
      list.forEach((s) => {
        if (typeof s !== "string" || !s.trim() || s.length > MAX_ITEM) { bad(`${k}.${l}: items are short sentences (up to ${MAX_ITEM} characters)`); } else { texts.push(s); }
      });
      if ((block.en || []).length !== (block.ru || []).length) { bad(`${k}: English and Russian lists must have the same number of items`); }
    }
    items += (block.en || []).length;
  }
  if (items === 0) { bad("an entry with nothing added, fixed, changed or to do says nothing"); }
  (entry.breaking || []).forEach((b, i) => {
    for (const l of LANGS) {
      if (!b || typeof b[l] !== "string" || !b[l].trim() || b[l].length > MAX_ITEM * 2) { bad(`breaking[${i}].${l} is required`); } else { texts.push(b[l]); }
    }
  });
  const req = entry.requires || {};
  if (req.migration !== undefined && !["none", "reversible", "irreversible"].includes(req.migration)) { bad("requires.migration must be none, reversible or irreversible"); }
  if (req.installer_update !== undefined && typeof req.installer_update !== "boolean") { bad("requires.installer_update must be true or false"); }
  if (req.migration === "irreversible" && !(entry.breaking || []).length) { bad("an irreversible migration must be listed under breaking"); }
  // The Russian text must be Russian and the English text must not be.
  const ru = [entry.title && entry.title.ru, ...LISTS.flatMap((k) => (entry[k] && entry[k].ru) || []), ...(entry.breaking || []).map((b) => b.ru)].filter(Boolean);
  const en = [entry.title && entry.title.en, ...LISTS.flatMap((k) => (entry[k] && entry[k].en) || []), ...(entry.breaking || []).map((b) => b.en)].filter(Boolean);
  if (ru.some((s) => !/[А-Яа-яЁё]/.test(s))) { bad("a Russian text without Cyrillic letters"); }
  if (en.some((s) => /[А-Яа-яЁё]/.test(s))) { bad("an English text with Cyrillic letters"); }
  // Evidence: what in the repository shows each change is real. Not published.
  const ev = entry.evidence;
  if (!Array.isArray(ev) || ev.length === 0) { bad("evidence is required: paths or commits that show these changes exist in the code"); }
  else {
    ev.forEach((e) => {
      if (/^[0-9a-f]{7,40}$/.test(e)) {
        try { cp.execFileSync("git", ["cat-file", "-e", `${e}^{commit}`], { cwd: ROOT, stdio: "ignore" }); }
        catch (x) { bad(`evidence commit ${e} is not in this repository`); }
      } else if (e.includes("..") || path.isAbsolute(e) || !fs.existsSync(path.join(ROOT, e))) { bad(`evidence path ${e} does not exist`); }
    });
  }
  for (const s of texts) {
    for (const [re, what] of FORBIDDEN) { if (re.test(s)) { bad(`"${s.slice(0, 50)}…" contains ${what}`); } }
    for (const m of s.matchAll(IPV4)) {
      const o = m.slice(1).map(Number);
      if (o.some((n) => n > 255)) { continue; }
      if (!DOC_NETS.some((n) => n[0] === o[0] && n[1] === o[1] && n[2] === o[2]) && !(o[0] === 127)) { bad(`"${s.slice(0, 50)}…" contains an IP address that is not a documentation address`); }
    }
  }
  return out;
}

function load() {
  if (!fs.existsSync(DIR)) { return []; }
  return fs.readdirSync(DIR).filter((f) => f.endsWith(".json")).sort().map((f) => {
    const file = path.join("release-notes", "entries", f);
    try { return { file, entry: JSON.parse(fs.readFileSync(path.join(DIR, f), "utf8")) }; }
    catch (e) { return { file, error: e.message }; }
  });
}

function check() {
  const all = load();
  const out = [];
  const ids = new Set();
  for (const { file, entry, error } of all) {
    if (error) { out.push(`${file}: not valid JSON (${error})`); continue; }
    if (ids.has(entry.id)) { out.push(`${file}: duplicate id ${entry.id}`); }
    ids.add(entry.id);
    out.push(...problems(entry, file));
  }
  if (out.length) { console.error(out.join("\n")); process.exit(1); }
  console.log(`Release notes checks passed (${all.length} entries).`);
}

// publishable strips what must not leave the repository.
function publishable(entry) {
  const { evidence, ...rest } = entry;
  return rest;
}

function draft(since) {
  const range = since ? `${since}..HEAD` : "-n 30";
  const git = (...a) => cp.execFileSync("git", a, { cwd: ROOT, encoding: "utf8" });
  const log = since ? git("log", "--format=%h %s", `${since}..HEAD`) : git("log", "--format=%h %s", "-n", "30");
  const files = since ? git("diff", "--stat", "--stat-width=100", since, "HEAD") : "";
  const today = new Date().toISOString().slice(0, 10);
  const skeleton = {
    id: `${today}-short-name`, date: today,
    title: { en: "", ru: "" },
    added: { en: [], ru: [] }, fixed: { en: [], ru: [] }, changed: { en: [], ru: [] }, actions: { en: [], ru: [] },
    breaking: [], requires: { installer_update: false, migration: "none" },
    evidence: [],
  };
  console.log("# Draft from " + range + ". Fill in by hand (or with an assistant), then review like code.");
  console.log("# Say only what the code does. Evidence: paths or commits that prove each change. No secrets, no tooling names.\n");
  console.log("# Commits:\n" + log.split("\n").filter(Boolean).map((l) => "#   " + l).join("\n"));
  if (files) { console.log("\n# Files changed:\n" + files.split("\n").map((l) => "#   " + l).join("\n")); }
  console.log("\n" + JSON.stringify(skeleton, null, 2));
}

if (require.main === module) {
  const [cmd, ...rest] = process.argv.slice(2);
  if (cmd === "check") { check(); }
  else if (cmd === "draft") { draft(rest[0] === "--since" ? rest[1] : ""); }
  else { console.error("usage: release-notes.cjs check | draft [--since COMMIT]"); process.exit(2); }
}
module.exports = { problems, load, publishable, LISTS, LANGS };
