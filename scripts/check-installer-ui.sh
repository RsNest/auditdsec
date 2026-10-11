#!/usr/bin/env bash
# Offline checks of the installer's face and its log: the root check, colour and
# banner rules, the JSON log (masking, rotation, a log that cannot be written),
# the trace lookup, and what the final report may claim. No Docker, network or
# installation. A real run on a server is NOT covered here; docs/VERIFY.md says
# what each kind of check proves.
#
# The functions are the installer's own, loaded by sourcing install.sh. Needs
# python3 (to parse the JSON lines) and gzip.
set -euo pipefail
cd "$(dirname "$0")/.."

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
equal() { [ "$1" = "$2" ] || fail "$3: got <$1>, expected <$2>"; }
contains() { case "$1" in *"$2"*) ;; *) fail "$3: <$1> lacks <$2>" ;; esac; }
lacks() { case "$1" in *"$2"*) fail "$3: <$1> contains <$2>" ;; *) ;; esac; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
export ENV_FILE="$tmp/.env" INSTALL_LOCK="$tmp/lock" DOCKER=false AUDITSEC_LOG_DIR="$tmp/logs"
: > "$ENV_FILE"
load() { AUDITDSEC_INSTALL_SOURCED=1 source ./install.sh --lang en; }

# --- not root ---------------------------------------------------------------
# id is replaced for the child shell only; sudo must never be called.
mkdir "$tmp/bin"
printf '#!/bin/sh\necho "$0 $*" >> "%s/sudo-called"\nexit 1\n' "$tmp" > "$tmp/bin/sudo"
printf '#!/bin/sh\n[ "$1" = "-u" ] && echo 1000 && exit 0\nexec /usr/bin/id "$@"\n' > "$tmp/bin/id"
chmod +x "$tmp/bin/sudo" "$tmp/bin/id"
rc=0
out="$(PATH="$tmp/bin:$PATH" bash ./install.sh --lang en --yes --mode tunnel 2>&1 </dev/null)" || rc=$?
equal "$rc" 1 "a run without root must stop"
contains "$out" "the installer was not run as root" "root error"
contains "$out" "sudo ./install.sh" "root hint"
[ ! -e "$tmp/sudo-called" ] || fail "the installer must not call sudo"
[ ! -e "$tmp/logs" ] || fail "nothing may be written before the root check"
[ ! -s "$ENV_FILE" ] || fail "nothing may be written before the root check"
out="$(PATH="$tmp/bin:$PATH" bash ./install.sh --lang ru --yes 2>&1 </dev/null)" || true
contains "$out" "установщик запущен не от root" "Russian root error"
# Help and status need no privileges.
out="$(PATH="$tmp/bin:$PATH" bash ./install.sh --lang en --help </dev/null)"
contains "$out" "sudo ./install.sh" "help without root"
out="$(PATH="$tmp/bin:$PATH" bash ./install.sh --lang en --status --json </dev/null)"
python3 -c 'import json,sys; json.loads(sys.argv[1])' "$out" || fail "status --json without root must be pure JSON"

# --- colour and banner ------------------------------------------------------
( load; ui_init no
  [ -z "$B$G$R$Y$N" ] || exit 11              # standard output is not a terminal
  [ "$UI_DECOR" = no ] || exit 12 ) || fail "no colour or decoration when output is redirected (exit $?)"
( load; ui_init yes; [ -z "$B$BRAND1$DIM$E_R" ] && [ "$UI_DECOR" = no ] ) || fail "--json must switch decoration off"
out="$( load; ui_init no; UI_DECOR=yes; COLUMNS=100 banner )"
contains "$out" "auditdsec" "wide banner shows the name"
contains "$out" "____" "wide banner draws the letters"
out="$( load; ui_init no; UI_DECOR=yes; COLUMNS=40 banner )"
contains "$out" "AUDITSEC" "narrow banner"
lacks "$out" "____" "narrow banner is compact"
out="$( load; ui_init no; UI_DECOR=no; banner )"
equal "$out" "" "no banner for a machine or a pipe"
out="$( load; ui_init no; UI_DECOR=yes; NO_BANNER=1 banner )"
equal "$out" "" "NO_BANNER"

# --- the log: shape and masking ---------------------------------------------
(
    load
    log_init test
    jlog info probe 'plain'
    jlog warn probe 'quote " backslash \ tab	newline
second line password=hunter2 token: abc123 Authorization: Bearer sekret https://user:pw@host/x pbkdf2-sha256$310000$SALT$KEY'
    jlog error probe "$(head -c 6000 /dev/zero | tr '\0' x)" bad_code 12
)
[ "$(stat -c %a "$tmp/logs")" = 750 ] || fail "log directory must be 0750"
[ "$(stat -c %a "$tmp/logs/installer.jsonl")" = 640 ] || fail "log file must be 0640"
python3 - "$tmp/logs/installer.jsonl" <<'PY' || fail "log lines must be valid JSON with the common keys"
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
assert rows[-1]["event"] == "operation_end", "the exit trap closes the operation"
rows = rows[:3]
for r in rows:
    for k in ("ts", "level", "service", "event", "message", "trace_id", "operation"):
        assert k in r, (k, r)
    assert r["service"] == "installer" and r["ts"].endswith("Z")
text = rows[1]["message"]
for secret in ("hunter2", "abc123", "sekret", "pw@", "SALT", "KEY"):
    assert secret not in text, ("secret leaked", secret, text)
assert "\n" in text and '"' in text and "\\" in text
assert rows[2]["error_code"] == "bad_code" and rows[2]["duration_ms"] == 12
assert len(rows[2]["message"]) < 3700 and rows[2]["message"].endswith("[truncated]")
assert len({r["trace_id"] for r in rows}) == 1 and len(rows[0]["trace_id"]) == 32
PY

# --- the trace ID -------------------------------------------------------------
id1="$( load; AUDITDSEC_TRACE_ID=0123456789abcdef0123456789abcdef log_init t; printf '%s' "$TRACE_ID" )"
equal "$id1" 0123456789abcdef0123456789abcdef "a trace ID from the control service is kept"
id2="$( load; AUDITDSEC_TRACE_ID='x;rm -rf' log_init t; printf '%s' "$TRACE_ID" )"
case "$id2" in *[!0-9a-f]*|'') fail "an invalid trace ID must be replaced, got <$id2>" ;; esac

# --- rotation: during writes, with archives, age and budget --------------------
rm -rf "$tmp/logs"
(
    load
    export LOG_MAX_BYTES=2000 LOG_KEEP=3
    LOG_MAX_BYTES=2000; LOG_KEEP=3
    log_init rot
    for round in 1 2 3 4 5 6; do
        for i in $(seq 1 25); do jlog info fill "round $round line $i $(head -c 40 /dev/zero | tr '\0' z)"; done
        log_maintain
    done
)
[ -s "$tmp/logs/installer.jsonl" ] || fail "the active file must exist after rotation"
count="$(find "$tmp/logs" -maxdepth 1 -name 'installer.jsonl.*' | wc -l)"
[ "$count" -le 3 ] || fail "at most 3 archives are kept, found $count"
[ -e "$tmp/logs/installer.jsonl.1" ] || fail "the newest archive must exist"
ls "$tmp/logs"/installer.jsonl.*.gz >/dev/null 2>&1 || fail "older archives must be compressed"
python3 - "$tmp/logs/installer.jsonl" <<'PY' || fail "the active file must hold whole JSON lines after rotation"
import json, sys
for l in open(sys.argv[1]): json.loads(l)
PY
# old archives go, the active file never does
touch -d '30 days ago' "$tmp/logs/installer.jsonl.1" "$tmp/logs/installer.jsonl.2.gz" 2>/dev/null || true
( load; LOG_MAX_DAYS=14; log_init rot; log_maintain )
[ ! -e "$tmp/logs/installer.jsonl.1" ] || fail "an archive past the age limit must be removed"
[ -e "$tmp/logs/installer.jsonl" ] || fail "the active file must never be removed"
# the size budget removes the oldest archives first
( load; LOG_BUDGET=1; LOG_MAX_BYTES=999999999; log_init rot; log_maintain )
[ -z "$(find "$tmp/logs" -maxdepth 1 -name 'installer.jsonl.*')" ] || fail "over budget: archives must be removed"
[ -e "$tmp/logs/installer.jsonl" ] || fail "over budget: the active file stays"

# --- a log that cannot be written never stops the installer -----------------------
: > "$tmp/notadir"
err="$( load; AUDITSEC_LOG_DIR="$tmp/notadir/x"; LOG_DIR="$tmp/notadir/x"; log_init t 2>&1 >/dev/null; jlog info a b; jlog info c d; ok fine >/dev/null )"
contains "$err" "diagnostic log is unavailable" "a degraded log says so"
[ "$(printf '%s\n' "$err" | grep -c 'unavailable')" = 1 ] || fail "the degraded-log warning must appear once"

# --- following one operation ------------------------------------------------------------
rm -rf "$tmp/logs"
(
    load
    AUDITDSEC_TRACE_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa log_init one; jlog info first 'from the installer'
    AUDITDSEC_TRACE_ID=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb log_init two; jlog info other 'another operation'
)
printf '{"ts":"2026-01-01T00:00:00.000Z","level":"info","service":"api","event":"x","message":"from the api","trace_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}\n' > "$tmp/logs/api.jsonl"
printf '{"ts":"2026-01-01T00:00:01.000Z","level":"info","service":"agent","event":"y","message":"archived","trace_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}\n' | gzip > "$tmp/logs/agent.jsonl.1.gz"
out="$( load; logs_command aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa )"
contains "$out" "from the installer" "trace lookup: installer"
contains "$out" "from the api" "trace lookup: api"
contains "$out" "archived" "trace lookup: compressed archive"
lacks "$out" "another operation" "trace lookup must not mix operations"
rc=0; ( load; logs_command 'a;b' ) >/dev/null 2>&1 || rc=$?
[ "$rc" != 0 ] || fail "an invalid trace ID must be refused"
out="$( load; logs_command "" )"
contains "$out" "Latest operations" "listing without an ID"

# --- the failure block and the result tell the truth ----------------------------------------
out="$( load; ui_init no; log_init t; CURRENT_STAGE="Checking the address and ports"; PASSWORD=hunter2
    report dns_mismatch panel.example.com "public DNS" "the name does not lead here" "fix the records" 2>&1 )"
for want in "Stage:" "Checking the address and ports" "Do next:" "fix the records" "Retry:" "Trace:" "install.sh --logs" "installer.jsonl" "nothing on this server was changed"; do
    contains "$out" "$want" "failure block"
done
lacks "$out" "hunter2" "failure block must not print the password"

summary_with() { # VARS... -> the summary text
    ( load; ui_init no; log_init t
      MODE=domain SITE=panel.example.com HTTPS_PORT=443 HTTPS_SOURCE=default ACME=production ENFORCE=no
      DO_START=yes DO_VERIFY=yes RESTORED=no PAGE_STATE=answers SETUP_STATE=bootstrap TLS_STATE=trusted
      EXT_STATE=not_checked EXT_TLS_STATE="not checked: no outside-check provider is configured."
      compute_panel_url
      eval "$*"
      summary ) 2>&1
}
out="$(summary_with true)"
contains "$out" "[ OK ] auditdsec is running" "a checked setup is reported as running"
contains "$out" "Outside:" "the outside state has its own line"
contains "$out" "not checked" "the missing outside check is named"
contains "$out" "Link: https://panel.example.com" "the link is shown"
lacks "$out" "NOT published" "no 'not published' wording"
lacks "$out" "FAIL" "an unchecked outside state is not a failure"
out="$(summary_with 'TLS_UNTRUSTED=yes; TLS_STATE="NOT trusted (curl code 60)"')"
lacks "$out" "[ OK ]" "an untrusted certificate is not a success"
contains "$out" "[WARN]" "an untrusted certificate is a warning"
contains "$out" "Configured link (the checks above did not pass)" "the link is marked when checks failed"
out="$(summary_with 'EXT_STATE=failed; EXT_TLS_STATE="the check did not pass: timeout."')"
contains "$out" "[ OK ] auditdsec is running" "a failed outside check does not undo a working panel"
contains "$out" "the check did not pass" "but it is shown"
out="$(summary_with 'FAIL_CODE=service_start_failed; FAIL_REASON="service_start_failed: the page is silent"')"
contains "$out" "[FAIL]" "a failure is a failure"
lacks "$out" "[ OK ]" "a failure is not a success"

printf 'Installer UI and log checks passed.\n'
