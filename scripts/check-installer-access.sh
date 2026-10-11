#!/usr/bin/env bash
# Offline checks of the access-change module of install.sh: no Docker, network
# or installation. The pieces that decide a change - the lock, the progress
# events, the status, the backup a rollback uses and the action handling - are
# exercised through the real functions. A full run against real Docker and ACME
# is NOT done here; see docs/VERIFY.md for what each kind of test covers.
set -euo pipefail
cd "$(dirname "$0")/.."

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
equal() { [ "$1" = "$2" ] || fail "$3: got <$1>, expected <$2>"; }
contains() { case "$1" in *"$2"*) ;; *) fail "$3: <$1> lacks <$2>" ;; esac; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
export ENV_FILE="$tmp/.env" INSTALL_LOCK="$tmp/lock" DOCKER=false

# Source the installer without running it.
load() { AUDITDSEC_INSTALL_SOURCED=1 source ./install.sh --lang en; }

# --- status of an installation ------------------------------------------
cat > "$ENV_FILE" <<'EOF'
PANEL_MODE='domain'
PANEL_SITE='panel.example.com'
PANEL_HTTPS_PORT='8443'
PANEL_ACME='production'
PANEL_PUBLIC_URL='https://panel.example.com:8443'
AUDITDSEC_TG_TOKEN='123:secret-token'
AUDITDSEC_WEB_PASSWORD_HASH='pbkdf2-sha256$1$salt$key'
EOF
out="$(bash ./install.sh --lang en --status --json)"
python3 - "$out" <<'PY' || fail "status --json is not valid JSON or lacks fields"
import json, sys
d = json.loads(sys.argv[1])
assert d["installed"] is True and d["mode"] == "domain" and d["site"] == "panel.example.com", d
assert d["https_port"] == "8443" and d["url"] == "https://panel.example.com:8443" and d["acme"] == "production", d
assert "secret" not in sys.argv[1] and "pbkdf2" not in sys.argv[1], "status leaked a secret"
PY
text="$(bash ./install.sh --lang en --status)"
contains "$text" "panel.example.com" "status text"
contains "$text" "Mode:" "status text"
case "$text" in *secret-token*|*pbkdf2*) fail "status text leaked a secret" ;; esac
[ -f "$ENV_FILE.pre-change" ] && fail "status must not write anything"
: > "$tmp/empty.env"
out="$(ENV_FILE="$tmp/empty.env" bash ./install.sh --lang en --status --json)"
contains "$out" '"installed":false' "no installation"

# --- the lock ---------------------------------------------------------------
(
    load
    acquire_lock
    sleep 3
) &
holder=$!
sleep 1
rc=0
INSTALL_EVENTS_FILE="$tmp/events" bash ./install.sh --lang en --action check >"$tmp/second.out" 2>&1 || rc=$?
equal "$rc" 20 "a second change while one runs must exit 20"
contains "$(cat "$tmp/second.out")" "operation_in_progress" "busy message"
contains "$(cat "$tmp/events")" '"code":"operation_in_progress"' "busy event"
wait "$holder"
# Released with the process: the next change can start.
( load; acquire_lock; echo free ) >"$tmp/third.out"
equal "$(cat "$tmp/third.out")" free "the lock must be released"

# --- events are valid JSON lines, escaped ----------------------------------
(
    load
    EVENTS_FILE="$tmp/ev.jsonl"
    stage dns "checking \"quotes\" and \\ backslashes"
    emit_event failure failed dns_mismatch 'cause with "quote"' 'fix'
)
python3 - "$tmp/ev.jsonl" <<'PY' || fail "events are not valid JSON lines"
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
assert [r["kind"] for r in rows] == ["stage", "failure"], rows
assert rows[0]["code"] == "dns" and '"quotes"' in rows[0]["text"], rows
assert rows[1]["code"] == "dns_mismatch" and rows[1]["fix"] == "fix", rows
PY

# --- backup and rollback source ----------------------------------------------
(
    load
    rm -f "$ENV_FILE.last-good" "$ENV_FILE.pre-change"
    equal "$(rollback_source)" "" "nothing to go back to"
    backup_current
    equal "$(rollback_source)" "$ENV_FILE.pre-change" "the pre-change copy is the fallback"
    [ "$(stat -c %a "$ENV_FILE.pre-change" 2>/dev/null || echo 600)" = 600 ] || fail "pre-change copy must be private"
    cp "$ENV_FILE" "$ENV_FILE.last-good"
    equal "$(rollback_source)" "$ENV_FILE.last-good" "a verified configuration wins"
)

# --- actions ---------------------------------------------------------------
(
    load
    valid_action domain && valid_action tunnel && valid_action update || fail "valid actions"
    ! valid_action "rm -rf" || fail "an arbitrary action was accepted"
    ! valid_action "" || fail "an empty action was accepted"
)
(
    load
    ACTION=domain; SITE=""; MODE=""
    ( apply_action_defaults ) >/dev/null 2>&1 && fail "a domain change without a name must stop"
    ACTION=domain; SITE=new.example.com; MODE=""
    apply_action_defaults
    equal "$MODE" domain "domain action"
    ACTION=ip; SITE=""; apply_action_defaults
    equal "$MODE" ip "ip action"
    ACTION=update; MODE=""; apply_action_defaults
    equal "$MODE" domain "update keeps the saved mode"
)
# The old and new settings are described before anything is applied, and the
# description names what is kept.
(
    load
    EVENTS_FILE="$tmp/plan.jsonl"; MODE=ip; SITE=203.0.113.9
    msg="$(announce_change)"
    contains "$msg" "domain panel.example.com" "old setup named"
    contains "$msg" "ip 203.0.113.9" "new setup named"
    contains "$msg" "credentials" "kept data named"
    contains "$msg" "restored" "rollback promised"
    MODE=domain; SITE=panel.example.com
    equal "$(announce_change)" "" "no change, no announcement"
)

# --- the control service link -----------------------------------------------
(
    load
    unit="$(control_unit_text /srv/a/.ctl/bin/auditdsec-ctl /srv/a alice)"
    contains "$unit" "User=alice" "unit user"
    contains "$unit" "ExecStart=/srv/a/.ctl/bin/auditdsec-ctl -dir /srv/a -run-dir /srv/a/.ctl/run" "unit command"
    contains "$unit" "NoNewPrivileges=yes" "unit hardening"
    MODE=domain; ENFORCE=no; COMPOSE_BASE=docker-compose.yml
    printf "PANEL_CONTROL='1'
" >> "$ENV_FILE"
    build_compose_files
    case " ${COMPOSE_FILES[*]} " in *"deploy/compose.control.yml"*) ;; *) fail "the control overlay must be used when enabled" ;; esac
    sed -i "/^PANEL_CONTROL=/d" "$ENV_FILE"
    build_compose_files
    case " ${COMPOSE_FILES[*]} " in *"deploy/compose.control.yml"*) fail "the control overlay must not be used by default" ;; esac
)
valid_ok="enable-control disable-control"
for a in $valid_ok; do ( load; valid_action "$a" ) || fail "$a must be a valid action"; done

# --action without an installation is refused.
rc=0
ENV_FILE="$tmp/empty.env" bash ./install.sh --lang en --yes --action check >/dev/null 2>&1 || rc=$?
[ "$rc" != 0 ] || fail "--action must need an installation"
# An unknown action is refused before anything runs.
rc=0
bash ./install.sh --lang en --yes --action "bogus" >/dev/null 2>&1 || rc=$?
[ "$rc" != 0 ] || fail "an unknown action must be refused"

printf 'Installer access checks passed.\n'
