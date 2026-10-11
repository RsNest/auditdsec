# shellcheck shell=bash
# Changing how the panel is reached after the first installation.
#
# This file is sourced by install.sh and is the ONLY implementation of the
# change: the menu of a repeated run, the non-interactive --action that the
# panel's local control service calls, the lock that keeps two changes from
# running at once, the progress events, and the backup that makes a rollback
# possible. The panel never reimplements any of it; it asks the control
# service (cmd/auditdsec-ctl) to run ./install.sh with checked arguments.

# ------------------------------------------------------------------- lock ---

LOCK_HELD=no

# acquire_lock — one change at a time, whoever starts it (a person at the
# terminal, the control service). flock when there is one, else a directory
# lock with a stale-owner check. Exit status 20 when another change is running.
acquire_lock() {
    [ "$LOCK_HELD" = no ] || return 0
    local lock="${INSTALL_LOCK:-.install.lock}"
    if command -v flock >/dev/null 2>&1; then
        exec 9>"$lock"
        if ! flock -n 9; then
            lock_busy "$lock"
        fi
    else
        if ! mkdir "$lock.d" 2>/dev/null; then
            local pid; pid="$(cat "$lock.d/pid" 2>/dev/null || true)"
            if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then lock_busy "$lock"; fi
            rm -rf "$lock.d"; mkdir "$lock.d" || lock_busy "$lock"
        fi
        printf '%s\n' "$$" > "$lock.d/pid"
        trap 'rm -rf "'"$lock"'.d"' EXIT
    fi
    LOCK_HELD=yes
}

lock_busy() {
    emit_event result failed operation_in_progress "another change is already running"
    installer_printf '%sFAILED: %s%s\n' "$R$B" operation_in_progress "$N" >&2
    installer_printf '  Another installer run or a change started from the panel is in progress.\n' >&2
    installer_printf '  Wait for it to finish, then run this again.\n' >&2
    exit 20
}

# ----------------------------------------------------------------- events ---

# emit_event KIND STATE CODE TEXT [FIX] — one JSON line appended to $EVENTS_FILE, for
# the panel's progress view. Nothing here is a secret: stages, codes, and the
# diagnosed cause and fix texts that are printed on the terminal as well.
EVENTS_FILE="${INSTALL_EVENTS_FILE:-}"

emit_event() {
    [ -n "$EVENTS_FILE" ] || return 0
    local kind="$1" state="$2" code="${3:-}" text="${4:-}" fix="${5:-}"
    printf '{"at":"%s","kind":"%s","state":"%s","code":"%s","text":"%s","fix":"%s"}\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(json_escape "$kind")" "$(json_escape "$state")" \
        "$(json_escape "$code")" "$(json_escape "$text")" "$(json_escape "$fix")" >> "$EVENTS_FILE" 2>/dev/null || true
}

# stage NAME — announces the stage that starts now.
stage() { emit_event stage running "$1" "$2"; }

# ------------------------------------------------------------ pre-change ---

PRE_CHANGE="${ENV_FILE}.pre-change"

# backup_current keeps the configuration that is running now, before a change
# writes a new one. The last VERIFIED configuration (.env.last-good) is what a
# rollback prefers; this copy covers an installation old enough to have none.
backup_current() {
    [ -s "$ENV_FILE" ] || return 0
    local tmp
    tmp="$(mktemp "${PRE_CHANGE}.XXXXXX")"
    cp "$ENV_FILE" "$tmp"
    chmod 0600 "$tmp"
    mv "$tmp" "$PRE_CHANGE"
}

# rollback_source prints the file a failed change goes back to.
rollback_source() {
    if [ -s "$LAST_GOOD" ]; then printf '%s' "$LAST_GOOD"
    elif [ -s "$PRE_CHANGE" ]; then printf '%s' "$PRE_CHANGE"
    fi
}

# ----------------------------------------------------------------- status ---

ST_MODE=""; ST_URL=""; ST_SITE=""; ST_PORT=""; ST_ACME=""; ST_ISSUER=""; ST_NOT_AFTER=""
ST_RUNNING=""; ST_RENEWAL=""

# cert_facts SITE PORT — the issuer and the end date of the certificate the
# local proxy serves for SITE (asked on loopback with the right server name, so
# a server that cannot reach its own public address still answers).
cert_facts() {
    ST_ISSUER=""; ST_NOT_AFTER=""
    command -v openssl >/dev/null 2>&1 || return 0
    local pem
    pem="$(printf '' | openssl s_client -connect "127.0.0.1:$2" -servername "$1" 2>/dev/null | openssl x509 2>/dev/null || true)"
    [ -n "$pem" ] || return 0
    ST_NOT_AFTER="$(printf '%s\n' "$pem" | openssl x509 -noout -enddate 2>/dev/null | sed 's/^notAfter=//' || true)"
    ST_ISSUER="$(printf '%s\n' "$pem" | openssl x509 -noout -issuer 2>/dev/null | sed 's/^issuer= *//' || true)"
}

# gather_status reads what the installation says about itself. It changes
# nothing and needs no password; Docker is optional (the answers it would give
# are then reported as unknown, not guessed).
gather_status() {
    ST_MODE="$(env_get PANEL_MODE)"
    ST_SITE="$(env_get PANEL_SITE)"; [ -n "$ST_SITE" ] || ST_SITE="$(env_get PANEL_DOMAIN)"
    ST_PORT="$(env_get PANEL_HTTPS_PORT)"; ST_PORT="${ST_PORT:-443}"
    ST_ACME="$(env_get PANEL_ACME)"
    ST_URL="$(env_get PANEL_PUBLIC_URL)"
    local up
    up="$(env_get PANEL_UPSTREAM_PORT)"; up="${up:-9477}"
    [ -n "$ST_URL" ] || { [ "$ST_MODE" = tunnel ] && ST_URL="http://127.0.0.1:$up"; }
    ST_RUNNING="unknown"
    if command -v "${DOCKER%% *}" >/dev/null 2>&1; then
        build_compose_files 2>/dev/null || true
        if [ -n "$(compose ps --status running -q 2>/dev/null | head -n 1)" ]; then ST_RUNNING="yes"; else ST_RUNNING="no"; fi
    fi
    case "$ST_MODE" in
        domain|ip|selfsigned)
            [ "$ST_RUNNING" != yes ] || cert_facts "$ST_SITE" "$ST_PORT"
            case "$ST_MODE" in
                domain) ST_RENEWAL="automatic: the proxy renews the certificate about 30 days before it ends" ;;
                ip) ST_RENEWAL="automatic: the certbot container renews the short-lived address certificate" ;;
                *) ST_RENEWAL="none: a self-signed certificate is not renewed" ;;
            esac ;;
        tunnel) ST_RENEWAL="not needed: the connection runs inside an SSH tunnel" ;;
    esac
}

print_status() {
    gather_status
    installer_printf '\n%sCurrent setup%s\n' "$B" "$N"
    installer_printf '  Mode:         %s\n' "${ST_MODE:-not installed}"
    [ -z "$ST_SITE" ] || installer_printf '  Address:      %s\n' "$ST_SITE"
    [ -z "$ST_URL" ] || installer_printf '  Link:         %s\n' "$ST_URL"
    [ -z "$ST_ACME" ] || installer_printf '  Certificate CA: %s\n' "$ST_ACME"
    [ -z "$ST_ISSUER" ] || installer_printf '  Issuer:       %s\n' "$ST_ISSUER"
    [ -z "$ST_NOT_AFTER" ] || installer_printf '  Valid until:  %s\n' "$ST_NOT_AFTER"
    [ -z "$ST_RENEWAL" ] || installer_printf '  Renewal:      %s\n' "$(installer_text "$ST_RENEWAL")"
    installer_printf '  Running:      %s\n' "$ST_RUNNING"
    [ ! -s "$LAST_GOOD" ] || installer_printf '  A verified configuration is saved (./install.sh --restore goes back to it).\n'
}

# status_json — the same facts for the control service. Strings are escaped;
# nothing secret is included.
status_json() {
    gather_status
    printf '{"installed":%s,"mode":"%s","site":"%s","https_port":"%s","url":"%s","acme":"%s","issuer":"%s","not_after":"%s","renewal":"%s","running":"%s","has_last_good":%s}\n' \
        "$([ -n "$ST_MODE" ] && echo true || echo false)" "$(json_escape "$ST_MODE")" "$(json_escape "$ST_SITE")" "$(json_escape "$ST_PORT")" \
        "$(json_escape "$ST_URL")" "$(json_escape "$ST_ACME")" "$(json_escape "$ST_ISSUER")" "$(json_escape "$ST_NOT_AFTER")" \
        "$(json_escape "$ST_RENEWAL")" "$(json_escape "$ST_RUNNING")" "$([ -s "$LAST_GOOD" ] && echo true || echo false)"
}

# ------------------------------------------------------------------- menu ---

# is_installed: an earlier run left a working description of the panel.
is_installed() { [ -s "$ENV_FILE" ] && [ -n "$(env_get PANEL_MODE)" ]; }

# choose_action — the menu of a repeated run. ACTION is one of: check domain ip
# tunnel credentials update (or empty: nothing chosen, leave).
choose_action() {
    print_status
    installer_lines <<'EOF'

What do you want to do?

  1) Check the current state
  2) Connect or change the domain
  3) Switch to access by IP address
  4) Switch to an SSH tunnel (no public access)
  5) Change the login and password
  6) Update the application
  0) Leave

EOF
    local reply
    reply="$(ask "Choose 0-6" "1")"
    case "$reply" in
        1) ACTION=check ;; 2) ACTION=domain ;; 3) ACTION=ip ;; 4) ACTION=tunnel ;;
        5) ACTION=credentials ;; 6) ACTION=update ;; 0|'') ACTION="" ;;
        *) die "pick a number from 0 to 6" ;;
    esac
}

valid_action() { case "$1" in check|domain|ip|tunnel|credentials|update) return 0 ;; *) return 1 ;; esac; }

# apply_action_defaults sets MODE/SITE for the chosen action, from the flags
# of this run and otherwise from the saved installation, so nothing that is
# already known is asked again (Telegram, credentials, e-mail, enforcement).
apply_action_defaults() {
    case "$ACTION" in
        domain) MODE=domain
            if [ -z "$SITE" ] && interactive; then
                SITE="$(ask "Domain name for the panel (e.g. panel.example.com)" "$([ "$(env_get PANEL_MODE)" = domain ] && env_get PANEL_SITE)")"
            fi
            [ -n "$SITE" ] || die "a domain name is required (--site NAME)" ;;
        ip) MODE=ip ;;
        tunnel) MODE=tunnel
            installer_lines <<'EOF'

The public port will be closed: the panel will open only through an SSH
tunnel from your computer. Anyone using the current address will lose access.
EOF
            confirm "Switch to an SSH tunnel?" || { say "Nothing was changed."; exit 0; } ;;
        update|check) MODE="$(env_get PANEL_MODE)" ;;
    esac
}

# ensure_site_change_notice tells, before anything is applied, what will be
# interrupted: the same public port is reused, so the old address stops
# answering while the new one is brought up.
announce_change() {
    local old_mode old_site
    old_mode="$(env_get PANEL_MODE)"; old_site="$(env_get PANEL_SITE)"
    [ -n "$old_mode" ] || return 0
    if [ "$old_mode" != "$MODE" ] || [ "$old_site" != "$SITE" ]; then
        installer_printf '\n%sChange:%s %s %s  ->  %s %s\n' "$B" "$N" "$old_mode" "$old_site" "$MODE" "$SITE"
        installer_printf '  The panel is restarted behind its proxy; expect a short interruption.\n'
        installer_printf '  Events, bans, the allowlist, credentials and settings are kept.\n'
        installer_printf '  If the new address cannot be verified, the previous configuration is restored.\n'
        emit_event plan ready change "$old_mode $old_site -> $MODE $SITE"
    fi
}
