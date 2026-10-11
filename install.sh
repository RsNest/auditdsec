#!/usr/bin/env bash
# shellcheck disable=SC2034
#
# auditdsec — set up the agent and the web panel.
#
#   ./install.sh
#
# Run it as root (sudo ./install.sh); it never calls sudo for you. The stages:
#
#   1. Checking this server: Linux, a supported CPU, Docker with Compose, curl.
#   2. How the panel opens: a domain, this server's IP address, or an SSH tunnel.
#   3. Downloading the application image of this commit (nothing is built here).
#   4. Checking the address and ports: public DNS, the HTTPS port (443 first; if
#      it is taken you choose another, nothing is stopped), what the certificate
#      needs. An outside check by a RemoteProbe is optional extra diagnostics.
#   5. Starting: the plan is shown and confirmed, then applied.
#   6. Checking the panel: it answers, its certificate verifies, sign-in works.
#   Result: what is running, what was and was not checked, and the link.
#
# Every operation gets a trace ID and is logged under /var/log/auditseclogs
# (installer.jsonl, installer-commands.log); ./install.sh --logs TRACE shows it.
#
# The first sign-in is admin / admin. That pair opens only the screen where you
# choose your own login and password; nothing else in the panel works before.
#
# Running it again keeps what is already configured: the credentials you set in
# the panel, the Telegram token, the stored events and the certificates.
#
# A tunnel (--mode tunnel) and a self-signed certificate (--mode selfsigned)
# are still there for development and old setups, but only when asked for by
# name: neither is ever used as a quiet way around a failed check.
#
# Everything can also be given on the command line; see --help.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

ORIG_ARGS=("$@")

# ---------------------------------------------------------------- settings --

ENV_FILE="${ENV_FILE:-.env}"
DOCKER="${DOCKER:-docker}"
COMPOSE_BASE="docker-compose.yml"
# Where the published images live (a mirror or a test registry may replace it),
# the GitHub repository whose Actions build them, and how long to wait for a
# build that is still running.
IMAGE_REPO="${AUDITDSEC_IMAGE_REPO:-ghcr.io/rsnest}"
IMAGE_GITHUB_REPO="${AUDITDSEC_IMAGE_GITHUB_REPO-RsNest/auditdsec}"
IMAGE_WAIT="${AUDITDSEC_IMAGE_WAIT:-900}"

MODE=""           # domain | ip | selfsigned | tunnel
SITE=""
EMAIL=""
LOGIN=""
PORT=""           # the agent's own plain-HTTP port on loopback (the upstream)
HTTPS_PORT=""     # the PUBLIC port the proxy serves the panel on: N | auto
PUBLIC_IP=""      # this server's public address(es), when they cannot be found
PROBE_URL=""      # RemoteProbe provider (a service on ANOTHER machine)
PROBE_TOKEN_FILE=""
PROBE_CACERT=""
NO_EXTERNAL=no    # skip the outside check (a technical mode: never "published")
PASSWORD=""
PASSWORD_FILE=""
ENFORCE=""        # yes | no
ASSUME_YES=no
DO_START=yes
DO_VERIFY=yes
ACME=""           # staging | production (domain and ip modes)
CACERT="${PANEL_CACERT:-}"   # a CA file to verify the panel's certificate against
NO_BUILD=no
BUILD_LOCAL=no
RESTORE=no
ACTION=""           # check | domain | ip | tunnel | credentials | update (a repeated run)
STATUS_ONLY=no
LOGS_MODE=no
LOGS_TRACE=""
REMOTE_CHECK=no
JSON=no
PORT_DEPRECATED=no
PORT_RANGE_LO="${PANEL_PORT_RANGE_LO:-}"
PORT_RANGE_HI="${PANEL_PORT_RANGE_HI:-}"

LE_PRODUCTION="https://acme-v02.api.letsencrypt.org/directory"
LE_STAGING="https://acme-staging-v02.api.letsencrypt.org/directory"

# --------------------------------------------------------------- utilities --

# shellcheck source=deploy/installer-i18n.sh
source deploy/installer-i18n.sh
# shellcheck source=deploy/installer-ui.sh
source deploy/installer-ui.sh
ui_init yes   # plain until the arguments are known; ui_init is called again below
INSTALLER_LANG=ru
installer_choose_language "$@"
installer_load_messages
# shellcheck source=deploy/installer-log.sh
source deploy/installer-log.sh
# shellcheck source=deploy/installer-access.sh
source deploy/installer-access.sh
# shellcheck source=deploy/installer-flow.sh
source deploy/installer-flow.sh
# shellcheck source=deploy/installer-state.sh
source deploy/installer-state.sh

# Output helpers. Every result carries a word as well as a colour, so the text
# alone is complete: [ OK ], [WARN], [FAIL]. Each also goes to the diagnostic log.
CURRENT_STAGE=""
CHANGED=no        # the configuration of this server was written by this run
say()  { printf '%s\n' "$(installer_text "$*")"; }
step() {
    CURRENT_STAGE="$*"
    STEP_N=$((STEP_N + 1))
    if [ "$STEP_N" -le "$STEP_TOTAL" ]; then
        printf '\n%s[%d/%d]%s %s%s%s\n' "$BRAND1$B" "$STEP_N" "$STEP_TOTAL" "$N" "$B" "$(installer_text "$*")" "$N"
    else
        printf '\n%s==>%s %s%s%s\n' "$BRAND1$B" "$N" "$B" "$(installer_text "$*")" "$N"
    fi
    jlog info stage "$*"
}
sub()  { printf '  %s-%s %s\n' "$DIM" "$N" "$(installer_text "$*")"; }
warn() { printf '%s[WARN]%s %s\n' "$E_Y$E_B" "$E_N" "$(installer_text "$*")" >&2; jlog warn warning "$*"; }
die()  { printf '%s[FAIL]%s %s\n' "$E_R$E_B" "$E_N" "$(installer_text "$*")" >&2; jlog error fatal "$*" fatal; exit 1; }
ok()   { printf '%s[ OK ]%s %s\n' "$G$B" "$N" "$(installer_text "$*")"; jlog info ok "$*"; }

usage() {
    installer_lines <<'EOF'
Usage: sudo ./install.sh [options]

Run as root. With no options it asks what it needs, in this order: how the
panel opens (domain, IP address or SSH tunnel), the address, the HTTPS port,
then what the certificate needs. On an existing installation it shows a menu.

Where the panel opens
  --mode domain|ip                     on a domain, or on this server's public IP
  --site NAME|ADDRESS                  the domain, or the public address
  --public-ip ADDRESS[,ADDRESS]        this server's public address(es), when they
                                       cannot be found (NAT, a floating address)
  --https-port N|auto                  the PUBLIC HTTPS port of the panel. The default is
                                       443; when it is taken you are asked for another
                                       one. A port you give is never replaced: if it does
                                       not work, the run stops. auto (only when you ask
                                       for it) tries 443, then up to 16 random high ports.
  --email ADDRESS                      where Let's Encrypt sends expiry warnings

Optional outside check (a RemoteProbe)
  --probe-url URL                      a RemoteProbe provider: cmd/auditdsec-probe running
                                       on ANOTHER machine. It connects to this server's
                                       address and port and reports what it saw.
  --probe-token-file PATH              file with that provider's token
  --probe-cacert FILE                  CA file for the provider's own certificate
  --no-external-check                  do not use it even if configured
  --remote-check                       run only that check against the installed panel
                                       (exit 0 reached, 11 not reached, 16 certificate not
                                       verified, 12 no provider or no answer)
  Without a provider the installer checks everything it can from this server and
  says what it did not check. The installation does not depend on it.

Other settings
  --lang ru|en                        installer language; saved independently of UI/Telegram
  --upstream-port N                    the agent's own port on loopback (default 9477;
                                       never published)
  --port N                             old name of --upstream-port. It was always the
                                       agent's loopback port, not the public one.
  --login NAME / --password-file PATH  install your own login and password instead of the
                                       first-time setup in the browser
  --enforce / --no-enforce             apply bans with nftables, or only record them
                                       (default: only record)

Technical modes
  --staging                            Let's Encrypt staging CA: its certificates are not
                                       trusted by browsers. --production moves back.
  --production                         the real Let's Encrypt CA
  --cacert FILE                        verify the panel's certificate against this CA
  --mode tunnel                        no public port; reach the panel over ssh -L
  --mode selfsigned                    a certificate the proxy signs itself; every
                                       browser warns
  --no-start                           write the configuration and stop
  --no-verify                          start, but do not check the panel answers
  --no-build                           use the image already here; download nothing
  --build-local                        DEVELOPERS: build the images from this tree on this
                                       machine instead of downloading the published ones
  --restore                            put back the last configuration that was verified
  --enable-panel-control               let the panel apply access changes: runs a small local
                                       service on this server (no root, no Docker socket for the
                                       agent); --disable-panel-control removes the link
  --status [--json]                    show the current mode, address and certificate; change
                                       nothing, needs no root. --json prints only JSON.
  --logs [TRACE_ID]                    without an ID: the latest operations; with one: every log
                                       line of that operation from all components
  --action ACTION                      on an existing installation, without the menu: check, update,
                                       domain, ip, tunnel, credentials or logs. Saved settings
                                       (Telegram, credentials, e-mail, enforcement) are reused.
  --events-file PATH                   append progress events (JSON lines) for the panel
  --yes                                ask nothing that already has an answer
  -h, --help                           this text

Logs: /var/log/auditseclogs (AUDITSEC_LOG_DIR), see docs/LOGS.md. Colours and the
banner appear only on a terminal; NO_COLOR=1 turns colours off, NO_BANNER=1 the banner.

Exit status: 0 when every required check passed; otherwise the code of the
first failure:

  10 port_in_use                 the port cannot be bound on this server
  11 external_port_unreachable   (--remote-check) the provider could not reach the panel
  12 external_check_unavailable  (--remote-check) no provider, or it did not answer
  13 dns_mismatch                public DNS does not lead (only) to this server
  14 acme_challenge_unreachable  port 80 (or 443) cannot be used for the challenge
  15 certificate_issuance_failed the CA did not issue the certificate
  16 tls_validation_failed       the panel's certificate does not verify
  17 service_start_failed        the containers did not start or the page is silent
  18 bootstrap_persistence_failed the panel cannot save its credentials
  19 image_unavailable           the image for this commit cannot be downloaded
  20 operation_in_progress       another installer run or panel change is running
   1 anything else (bad input, Docker missing, ...)
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --lang) shift 2 ;;  # already validated before the first output
        --mode) MODE="${2:-}"; shift 2 ;;
        --site) SITE="${2:-}"; shift 2 ;;
        --email) EMAIL="${2:-}"; shift 2 ;;
        --login) LOGIN="${2:-}"; shift 2 ;;
        --port) PORT="${2:-}"; PORT_DEPRECATED=yes; shift 2 ;;
        --upstream-port) PORT="${2:-}"; shift 2 ;;
        --https-port) HTTPS_PORT="${2:-}"; shift 2 ;;
        --public-ip) PUBLIC_IP="${2:-}"; shift 2 ;;
        --probe-url) PROBE_URL="${2:-}"; shift 2 ;;
        --probe-token-file) PROBE_TOKEN_FILE="${2:-}"; shift 2 ;;
        --probe-cacert) PROBE_CACERT="${2:-}"; shift 2 ;;
        --no-external-check) NO_EXTERNAL=yes; shift ;;
        --password-file) PASSWORD_FILE="${2:-}"; shift 2 ;;
        --enforce) ENFORCE=yes; shift ;;
        --no-enforce) ENFORCE=no; shift ;;
        --staging) ACME=staging; shift ;;
        --production) ACME=production; shift ;;
        --cacert) CACERT="${2:-}"; shift 2 ;;
        --restore) RESTORE=yes; shift ;;
        --enable-panel-control) ACTION=enable-control; shift ;;
        --disable-panel-control) ACTION=disable-control; shift ;;
        --action) ACTION="${2:-}"; shift 2 ;;
        --status) STATUS_ONLY=yes; shift ;;
        --logs) LOGS_MODE=yes; LOGS_TRACE=""; shift
                case "${1:-}" in ''|-*) ;; *) LOGS_TRACE="$1"; shift ;; esac ;;
        --remote-check) REMOTE_CHECK=yes; shift ;;
        --json) JSON=yes; shift ;;
        --events-file) EVENTS_FILE="${2:-}"; shift 2 ;;
        --no-build) NO_BUILD=yes; shift ;;
        --build-local) BUILD_LOCAL=yes; shift ;;
        --yes|-y) ASSUME_YES=yes; shift ;;
        --no-start) DO_START=no; shift ;;
        --no-verify) DO_VERIFY=no; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option $1 (try --help)" ;;
    esac
done

ui_init "$JSON"

interactive() { [ -t 0 ] && [ "$ASSUME_YES" = no ]; }

# ask PROMPT DEFAULT -> answer on stdout
ask() {
    local prompt="$1" default="${2:-}" reply=""
    prompt="$(installer_text "$prompt")"
    if ! interactive; then
        printf '%s' "$default"
        return
    fi
    if [ -n "$default" ]; then
        read -r -p "$prompt [$default]: " reply </dev/tty || true
    else
        read -r -p "$prompt: " reply </dev/tty || true
    fi
    printf '%s' "${reply:-$default}"
}

# ask_secret PROMPT -> answer on stdout, never echoed
ask_secret() {
    local prompt="$1" reply=""
    prompt="$(installer_text "$prompt")"
    read -r -s -p "$prompt: " reply </dev/tty || true
    printf '\n' >&2
    printf '%s' "$reply"
}

confirm() {
    local prompt="$1" reply=""
    interactive || return 0
    prompt="$(installer_text "$prompt")"
    local choices='Y/n'
    [ "$INSTALLER_LANG" != ru ] || choices='Д/н'
    read -r -p "$prompt [$choices]: " reply </dev/tty || true
    case "$reply" in [nNнН]*) return 1 ;; *) return 0 ;; esac
}

# ------------------------------------------------------------------ errors --

# Each failure the installer can diagnose has a name and an exit status, so a
# person sees what failed and a script can tell the cases apart.
FAIL_CODE=""
FAIL_REASON=""

code_status() {
    case "$1" in
        port_in_use) echo 10 ;;
        external_port_unreachable) echo 11 ;;
        external_check_unavailable) echo 12 ;;
        dns_mismatch) echo 13 ;;
        acme_challenge_unreachable) echo 14 ;;
        certificate_issuance_failed) echo 15 ;;
        tls_validation_failed) echo 16 ;;
        service_start_failed) echo 17 ;;
        bootstrap_persistence_failed) echo 18 ;;
        image_unavailable) echo 19 ;;
        operation_in_progress) echo 20 ;;
        *) echo 1 ;;
    esac
}

# retry_command — this run's command line again. No argument carries a secret
# (passwords and tokens are only ever named by file), so it is safe to print.
retry_command() {
    local out="./install.sh" a
    for a in ${ORIG_ARGS[@]+"${ORIG_ARGS[@]}"}; do
        case "$a" in *[!A-Za-z0-9_./:@,=+-]*|'') out="$out '$a'" ;; *) out="$out $a" ;; esac
    done
    printf '%s' "$out"
}

# report CODE ENDPOINT CHECK CAUSE FIX — prints one diagnosed failure and
# remembers it. The first failure is the one the exit status names. It says
# where it happened, what still works, what to do next, and how to find the
# technical record (the trace ID).
report() {
    local code="$1" endpoint="$2" check="$3" cause="$4" fix="$5"
    [ -n "$FAIL_CODE" ] || FAIL_CODE="$code"
    [ -n "$FAIL_REASON" ] || FAIL_REASON="$code: $(installer_text "$cause")"
    emit_event failure failed "$code" "$(installer_text "$cause")" "$(installer_text "$fix")"
    jlog error failure "$code at $endpoint: $cause (check: $check)" "$code"
    {
        installer_printf '\n%s[FAIL]%s %s%s%s\n' "$E_R$E_B" "$E_N" "$E_R$E_B" "$code" "$E_N"
        installer_printf '  %-13s %s\n' "$(installer_text 'Stage:')" "$(installer_text "${CURRENT_STAGE:-start}")"
        installer_printf '  %-13s %s\n' "$(installer_text 'Where:')" "$endpoint"
        installer_printf '  %-13s %s\n' "$(installer_text 'Check:')" "$(installer_text "$check")"
        installer_printf '  %-13s %s\n' "$(installer_text 'Result:')" "$(installer_text "$cause")"
        installer_printf '  %-13s %s\n' "$(installer_text 'Do next:')" "$(installer_text "$fix")"
        installer_printf '  %-13s %s\n' "$(installer_text 'Retry:')" "$(retry_command)"
        if [ "$CHANGED" = no ]; then
            installer_printf '  %-13s %s\n' "$(installer_text 'Still works:')" "$(installer_text 'nothing on this server was changed by this run')"
        fi
        [ -z "$TRACE_ID" ] || installer_printf '  %-13s %s  (%s)\n' "$(installer_text 'Trace:')" "$TRACE_ID" "./install.sh --logs $TRACE_ID"
        [ -z "$LOG_FILE" ] || [ -n "$LOG_DEGRADED" ] || installer_printf '  %-13s %s\n' "$(installer_text 'Log:')" "$LOG_FILE"
    } >&2
}

# abort CODE ... — a failure before anything was started: report it, clean up
# (the EXIT trap) and stop with the code's status.
abort() {
    report "$@"
    installer_printf '\n%s[FAIL]%s %s\n' "$E_R$E_B" "$E_N" "$(installer_text 'Stopped before any change. Nothing that was working before was removed.')" >&2
    exit "$(code_status "$1")"
}

# --------------------------------------------------------------- .env edits --

# env_get KEY -> current value, quotes stripped
env_get() {
    [ -f "$ENV_FILE" ] || return 0
    local line
    line="$(grep -E "^$1=" "$ENV_FILE" | tail -n 1 || true)"
    line="${line#"$1"=}"
    case "$line" in
        \'*\') line="${line#\'}"; line="${line%\'}" ;;
        \"*\") line="${line#\"}"; line="${line%\"}" ;;
    esac
    printf '%s' "$line"
}

# env_set KEY VALUE — replaces the line if present, appends it if not, and
# keeps every other line as it was.
#
# The value is always single-quoted. docker compose expands $NAME inside an
# unquoted or double-quoted .env value, which silently eats most of a
# password hash: pbkdf2-sha256$310000$SALT$KEY loses $SALT and $KEY. Single
# quotes are the only form it passes through untouched.
env_set() {
    local key="$1" value="$2" tmp
    case "$value" in *"'"*) die "a single quote in $key is not supported" ;; esac
    touch "$ENV_FILE"
    tmp="$(mktemp "${ENV_FILE}.XXXXXX")"
    grep -vE "^$key=" "$ENV_FILE" > "$tmp" || true
    printf "%s='%s'\n" "$key" "$value" >> "$tmp"
    chmod 0600 "$tmp"
    mv "$tmp" "$ENV_FILE"
}

env_unset() {
    local tmp
    [ -f "$ENV_FILE" ] || return 0
    tmp="$(mktemp "${ENV_FILE}.XXXXXX")"
    grep -vE "^$1=" "$ENV_FILE" > "$tmp" || true
    chmod 0600 "$tmp"
    mv "$tmp" "$ENV_FILE"
}

# cfg NAME — the value from the environment of this run, else from .env. Used
# for the few settings (a private ACME server, the probe) that are given once
# and then remembered.
cfg() {
    local v="${!1:-}"
    [ -n "$v" ] || v="$(env_get "$1")"
    printf '%s' "$v"
}

# ---------------------------------------------------------------- compose ---

COMPOSE_FILES=()

compose() { $DOCKER compose "${COMPOSE_FILES[@]}" "$@"; }

# build_compose_files decides which overlays apply. docker-compose.yml comes
# first on purpose: relative paths inside the overlays resolve against the
# directory of the first file, so the bind mounts only land in the right place
# in this order.
build_compose_files() {
    COMPOSE_FILES=(-f "$COMPOSE_BASE")
    if [ "$ENFORCE" = yes ]; then COMPOSE_FILES+=(-f deploy/compose.enforce.yml); fi
    case "$MODE" in
        domain|ip|selfsigned) COMPOSE_FILES+=(-f deploy/compose.proxy.yml) ;;
        tunnel)               COMPOSE_FILES+=(-f deploy/compose.tunnel.yml) ;;
    esac
    if [ "$MODE" = ip ]; then COMPOSE_FILES+=(-f deploy/compose.acme-ip.yml); fi
    # The panel's link to the local control service, when it was enabled.
    if [ "$(env_get PANEL_CONTROL)" = 1 ]; then COMPOSE_FILES+=(-f deploy/compose.control.yml); fi
    # Extra overlays, for a test harness or a site-specific tweak. Last, so
    # they can override anything above.
    local extra
    for extra in ${PANEL_COMPOSE_EXTRA:-}; do COMPOSE_FILES+=(-f "$extra"); done
    return 0
}

compose_prefix() {
    local base="$DOCKER compose" f
    for f in "${COMPOSE_FILES[@]}"; do base="$base $f"; done
    printf '%s' "$base"
}

# --------------------------------------------------------------- preflight --

PREVIOUS_INSTALL=no

# preflight_env — what this server must have. Nothing is downloaded here; the
# image is a stage of its own.
preflight_env() {
    local os arch
    os="$(uname -s)"; arch="$(uname -m)"
    [ "$os" = Linux ] || die "auditdsec runs on Linux; this is $os"
    case "$arch" in
        x86_64|amd64|aarch64|arm64) ;;
        *) die "unsupported CPU architecture $arch (amd64 and arm64 are supported)" ;;
    esac
    command -v curl >/dev/null 2>&1 || die "curl is needed; install it and run ./install.sh again"
    command -v "${DOCKER%% *}" >/dev/null 2>&1 || die "$DOCKER is not installed"
    $DOCKER compose version >/dev/null 2>&1 || die "'$DOCKER compose' does not work; install the Compose plugin"
    $DOCKER info >/dev/null 2>&1 || die "cannot talk to the Docker daemon; is it running?"
    [ -r /var/log/audit/audit.log ] \
        || warn "/var/log/audit/audit.log is missing: is auditd installed and running? The panel will show nothing until it is."
    ok "Linux $arch, Docker with Compose, curl"

    if [ -n "$(env_get PANEL_MODE)" ] || [ -n "$(env_get AUDITDSEC_WEB)" ]; then
        PREVIOUS_INSTALL=yes
        local pm pu
        pm="$(env_get PANEL_MODE)"; pu="$(env_get PANEL_PUBLIC_URL)"
        ok "an earlier installation is here${pm:+ (mode $pm${pu:+, $pu})}: its data, certificates and credentials are kept"
    fi
}

# load_targets — the addresses an outside check should reach, when this run did
# not look them up itself (a repeated check, --remote-check).
load_targets() {
    TARGETS=()
    local a out
    if [ "$MODE" = domain ]; then
        net_check_env
        out="$(agent net-check domain "$SITE" 2>/dev/null || true)"
        for a in $(kv A "$out" | tr ',' ' ') $(kv AAAA "$out" | tr ',' ' '); do TARGETS+=("$a $(family_of "$a")"); done
    fi
    [ ${#TARGETS[@]} -gt 0 ] || TARGETS=("$SITE $(family_of "$SITE")")
}

# logs_command [TRACE] — everything the project wrote about one operation, from
# every component, oldest first; or, without an ID, the latest operations.
logs_command() {
    local t="${1:-}" files=() f
    if [ -z "$t" ]; then
        say "Latest operations (time, trace ID, kind). Show one with ./install.sh --logs TRACE_ID"
        last_operations 15
        return 0
    fi
    valid_trace_id "$t" || die "a trace ID is 16 to 32 characters 0-9 a-f"
    for f in "$LOG_DIR"/*.jsonl "$LOG_DIR"/*.jsonl.[0-9]*; do [ -e "$f" ] && files+=("$f"); done
    [ ${#files[@]} -gt 0 ] || { say "There are no logs in $LOG_DIR yet."; return 0; }
    {
        for f in "${files[@]}"; do
            case "$f" in
                *.gz) gzip -dc "$f" 2>/dev/null ;;
                *) cat "$f" ;;
            esac
        done
    } | grep -F "\"trace_id\":\"$t\"" | sort -s -k1,1 || true
}

# log_start — names the operation, opens the log, and sets up the exits.
log_start() {
    local op=install
    if [ "$REMOTE_CHECK" = yes ]; then op=remote-check
    elif [ "$LOGS_MODE" = yes ]; then op=logs
    elif [ "$RESTORE" = yes ]; then op=restore
    elif [ -n "$ACTION" ]; then op="$ACTION"
    elif is_installed; then op=change; fi
    log_init "$op"
    install_traps
    banner
}


# --------------------------------------------------------------- the image --
#
# The images are built by GitHub Actions, one per commit, and published as
# ghcr.io/rsnest/auditdsec:sha-<commit>. The installer takes the one whose
# commit is the code it was run from, so the scripts next to it and the agent
# inside it are the same version. It never compiles anything on the server.
# --build-local (developers) builds from this tree instead; a failed download
# never falls back to building.

IMAGE=""          # the agent image in use
ENFORCE_IMAGE=""  # the enforcing variant of the same commit
SOURCE_COMMIT=""

# source_commit — the commit of this tree: from git when it is a clone, else
# from deploy/source-commit, which GitHub fills in when it builds a source
# archive. A tree whose agent code has local changes has no published image.
source_commit() {
    local c=""
    if [ -d .git ] && command -v git >/dev/null 2>&1; then
        c="$(git rev-parse HEAD 2>/dev/null || true)"
        if [ -n "$c" ] && [ "$BUILD_LOCAL" = no ] \
                && [ -n "$(git status --porcelain -- cmd internal go.mod deploy/Dockerfile 2>/dev/null)" ]; then
            die "the agent's source code here has local changes, so no published image matches it. Use --build-local, or undo the changes (git stash)."
        fi
    fi
    if [ -z "$c" ] && [ -r deploy/source-commit ]; then
        c="$(tr -d ' \n\r' < deploy/source-commit)"
    fi
    case "$c" in
        [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*) ;;
        *) c="" ;;
    esac
    [ ${#c} = 40 ] || c=""
    printf '%s' "$c"
}

# github_run_state COMMIT — what GitHub Actions says about building that
# commit: building | failed | none | unknown. Public API, no token needed.
github_run_state() {
    local json
    json="$(curl -fsS --max-time 10 -H 'Accept: application/vnd.github+json' \
        "${AUDITDSEC_GITHUB_API:-https://api.github.com}/repos/${IMAGE_GITHUB_REPO}/actions/runs?head_sha=$1&per_page=10" 2>/dev/null)" \
        || { echo unknown; return; }
    case "$json" in
        *'"total_count": 0'*|*'"total_count":0'*) echo none ;;
        *'"status": "queued"'*|*'"status":"queued"'*|*'"status": "in_progress"'*|*'"status":"in_progress"'*|*'"status": "waiting"'*|*'"status":"waiting"'*|*'"status": "pending"'*|*'"status":"pending"'*)
            echo building ;;
        *'"conclusion": "failure"'*|*'"conclusion":"failure"'*|*'"conclusion": "cancelled"'*|*'"conclusion":"cancelled"'*)
            echo failed ;;
        *) echo unknown ;;
    esac
}

# pull_image REF — downloads REF without any login. When the image for this
# commit is still being built, waits a bounded time; never builds instead.
pull_image() {
    local ref="$1" out waited=0 state
    while :; do
        if out="$($DOCKER pull --quiet "$ref" 2>&1)"; then
            return 0
        fi
        case "$out" in
            *denied*|*unauthorized*|*"authentication required"*)
                abort image_unavailable "$ref" "docker pull without credentials" \
                    "the registry refused anonymous access: the package is not public" \
                    "the repository owner must make the package public (GitHub → Packages → Package settings → Change visibility). Nothing was changed on this server." ;;
            *"manifest unknown"*|*"not found"*|*"manifest for"*)
                ;;
            *)
                abort image_unavailable "$ref" "docker pull" \
                    "the download failed: $(printf '%s' "$out" | tail -n 1)" \
                    "check this server's internet access and DNS, then run again. Nothing was changed on this server." ;;
        esac
        state=unknown
        [ -z "$IMAGE_GITHUB_REPO" ] || state="$(github_run_state "$SOURCE_COMMIT")"
        case "$state" in
            building)
                if [ "$waited" -ge "$IMAGE_WAIT" ]; then
                    abort image_unavailable "$ref" "waiting for GitHub Actions to publish the image" \
                        "the image for commit ${SOURCE_COMMIT:0:12} is still being built after $((IMAGE_WAIT / 60)) minutes" \
                        "wait for the build at https://github.com/${IMAGE_GITHUB_REPO}/actions to finish, then run again. Nothing was changed on this server."
                fi
                [ "$waited" -gt 0 ] || say "The image for commit ${SOURCE_COMMIT:0:12} is still being built by GitHub Actions; waiting (at most $((IMAGE_WAIT / 60)) minutes)..."
                sleep 20; waited=$((waited + 20)) ;;
            failed)
                abort image_unavailable "$ref" "GitHub Actions build of commit ${SOURCE_COMMIT:0:12}" \
                    "the build for this commit failed, so no image was published" \
                    "use the code of a commit whose build succeeded (git checkout <commit>), or --build-local. Nothing was changed on this server." ;;
            *)
                abort image_unavailable "$ref" "docker pull" \
                    "no image is published for commit ${SOURCE_COMMIT:0:12} (images are published for commits on main and for release tags)" \
                    "run the installer from a commit on main or a release (git checkout main && git pull), or use --build-local for your own changes. Nothing was changed on this server." ;;
        esac
    done
}

# ensure_image gets the agent image before anything else: the DNS and port
# checks below run inside it.
ensure_image() {
    if [ "$BUILD_LOCAL" = yes ]; then
        build_local minimal
        return 0
    fi
    if [ "$NO_BUILD" = yes ]; then
        # The image this installation already uses, or the one for this commit
        # if it is present; nothing is downloaded.
        IMAGE="$(env_get AUDITDSEC_IMAGE)"
        SOURCE_COMMIT="$(source_commit)"
        [ -n "$IMAGE" ] || [ -z "$SOURCE_COMMIT" ] || IMAGE="${IMAGE_REPO}/auditdsec:sha-${SOURCE_COMMIT}"
        [ -n "$IMAGE" ] && $DOCKER image inspect "$IMAGE" >/dev/null 2>&1 \
            || die "--no-build: no image is present here (${IMAGE:-none}); run without --no-build to download it"
        ENFORCE_IMAGE="$(env_get AUDITDSEC_ENFORCE_IMAGE)"
        [ -n "$ENFORCE_IMAGE" ] || ENFORCE_IMAGE="${IMAGE%/auditdsec:*}/auditdsec-enforce:${IMAGE##*:}"
        return 0
    fi
    SOURCE_COMMIT="$(source_commit)"
    [ -n "$SOURCE_COMMIT" ] || die "cannot tell which commit this code is (no git checkout, and deploy/source-commit is not filled in). Download the code with git clone or as a GitHub archive, or use --build-local."
    IMAGE="${IMAGE_REPO}/auditdsec:sha-${SOURCE_COMMIT}"
    ENFORCE_IMAGE="${IMAGE_REPO}/auditdsec-enforce:sha-${SOURCE_COMMIT}"
    say "Downloading the agent image for commit ${SOURCE_COMMIT:0:12}..."
    pull_image "$IMAGE"
    ok "image $IMAGE"
}

# build_local TARGET — the developer's path: builds this tree here.
build_local() {
    local target="$1" c tag log
    c="$(source_commit)"; c="${c:-unknown}"
    if [ -d .git ] && [ -n "$(git status --porcelain -- cmd internal go.mod deploy/Dockerfile 2>/dev/null)" ]; then
        tag="local-${c:0:12}-dirty"
    else
        tag="local-${c:0:12}"
    fi
    case "$target" in
        minimal) IMAGE="auditdsec:$tag"; ENFORCE_IMAGE="auditdsec-enforce:$tag"; set -- "$IMAGE" ;;
        enforce) set -- "$ENFORCE_IMAGE" ;;
    esac
    say "Building $1 from this tree (--build-local)..."
    log="$(mktemp)"
    if ! $DOCKER build -f deploy/Dockerfile --target "$target" -t "$1" \
            --build-arg VERSION="$(cat VERSION 2>/dev/null || echo dev)-local" \
            --build-arg COMMIT="$c" . >"$log" 2>&1; then
        tail -n 30 "$log" >&2; rm -f "$log"
        die "the image did not build"
    fi
    rm -f "$log"
    ok "built $1"
}

# ensure_enforce_image: the nftables variant, only when blocking is on.
ensure_enforce_image() {
    [ "$ENFORCE" = yes ] || return 0
    $DOCKER image inspect "$ENFORCE_IMAGE" >/dev/null 2>&1 && return 0
    if [ "$BUILD_LOCAL" = yes ]; then build_local enforce; return 0; fi
    [ "$NO_BUILD" = no ] || die "--no-build: the enforcing image $ENFORCE_IMAGE is not present here"
    pull_image "$ENFORCE_IMAGE"
}

# legacy_image — the image an installation from before published images used
# (built here as auditdsec:<version>), if it is still present.
legacy_image() {
    local ref
    ref="auditdsec:$(env_get AUDITDSEC_VERSION)"
    [ "$ref" != "auditdsec:" ] || ref="auditdsec:0.1.0"
    $DOCKER image inspect "$ref" >/dev/null 2>&1 && printf "%s" "$ref"
    return 0
}

# image_facts REF — "version, commit, digest" of an image, for the summary.
image_facts() {
    local v c d
    v="$($DOCKER image inspect -f '{{index .Config.Labels "org.opencontainers.image.version"}}' "$1" 2>/dev/null || true)"
    c="$($DOCKER image inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$1" 2>/dev/null || true)"
    d="$($DOCKER image inspect -f '{{if .RepoDigests}}{{index .RepoDigests 0}}{{else}}{{.Id}}{{end}}' "$1" 2>/dev/null || true)"
    printf '%s|%s|%s' "${v:-?}" "${c:-?}" "${d##*@}"
}

# agent ARGS... — runs one of the agent's own commands in the image, in the
# host's network namespace so it sees this server's addresses and ports. Only
# named variables are passed, by name, so their values never appear in a
# process list.
AGENT_ENV=()
agent() {
    $DOCKER run --rm --network host ${AGENT_ENV[@]+"${AGENT_ENV[@]}"} "$IMAGE" "$@"
}

# kv KEY TEXT — the value of KEY=... in the agent's output.
kv() { printf '%s\n' "$2" | sed -n "s/^$1=//p" | tail -n 1; }

# ------------------------------------------------------- 2. where the panel --

valid_mode() { case "$1" in domain|ip|selfsigned|tunnel) return 0 ;; *) return 1 ;; esac; }


# ------------------------------------------------------- 3. DNS / address ---

TARGETS=()        # "ADDRESS FAMILY" pairs the outside check must reach


net_check_env() {
    AGENT_ENV=()
    [ -z "${PANEL_DNS_RESOLVERS:-}" ] || AGENT_ENV+=(-e PANEL_DNS_RESOLVERS)
    [ -z "${PANEL_NO_EGRESS:-}" ] || AGENT_ENV+=(-e PANEL_NO_EGRESS)
    export PANEL_DNS_RESOLVERS="${PANEL_DNS_RESOLVERS:-}" PANEL_NO_EGRESS="${PANEL_NO_EGRESS:-}"
}

family_of() { case "$1" in *:*) echo 6 ;; *) echo 4 ;; esac; }

ask_site() {
    case "$MODE" in tunnel) return 0 ;; esac
    PUBLIC_IP="${PUBLIC_IP:-$(env_get PANEL_PUBLIC_IP)}"
    net_check_env
    case "$MODE" in
        domain) check_domain ;;
        ip|selfsigned) choose_address ;;
    esac
}


choose_address() {
    local out rc=0 cands previous
    previous="$(env_get PANEL_SITE)"
    case "$(env_get PANEL_MODE)" in ip|selfsigned) ;; *) previous="" ;; esac
    sub "This server's public address"
    out="$(agent net-check ip 2>/dev/null)" || rc=$?
    cands="$(kv CANDIDATES "$out")"
    [ "$(kv NAT "$out")" = yes ] && say "The address seen from outside is not on any interface here (NAT or a floating address)."

    if [ -z "$SITE" ]; then
        local list=() c i
        IFS=',' read -r -a list <<< "$cands"
        if [ ${#list[@]} -eq 0 ] && [ -n "$PUBLIC_IP" ]; then IFS=',' read -r -a list <<< "$PUBLIC_IP"; fi
        if interactive && [ ${#list[@]} -gt 1 ]; then
            say "More than one public address was found:"
            i=1; for c in "${list[@]}"; do say "  $i) $c"; i=$((i + 1)); done
            local reply; reply="$(ask "Which one should the panel use (number or address)" "${previous:-1}")"
            case "$reply" in
                ''|*[!0-9]*) SITE="$reply" ;;
                *) [ "$reply" -ge 1 ] && [ "$reply" -le ${#list[@]} ] || die "no such choice"; SITE="${list[$((reply - 1))]}" ;;
            esac
        elif [ ${#list[@]} -eq 1 ]; then
            SITE="$(ask "The panel's address" "${previous:-${list[0]}}")"
        elif [ ${#list[@]} -gt 1 ]; then
            [ -n "$previous" ] || die "several public addresses were found ($cands); choose one with --site ADDRESS"
            SITE="$previous"
        else
            SITE="$(ask "No public address was found. Type this server's public address" "$previous")"
            [ -n "$SITE" ] || die "no public address of this server was found; give it with --site ADDRESS (and --public-ip if it is behind NAT)"
        fi
    fi
    SITE="${SITE#[}"; SITE="${SITE%]}"   # an IPv6 address goes in bare
    case "$SITE" in *[!0-9a-fA-F.:]*|'') die "'$SITE' is not an IP address; for a name use --mode domain" ;; esac
    case ",$cands," in
        *",$SITE,"*) ok "$SITE (found on this server or as its outgoing address)" ;;
        *) say "$SITE was not seen on this server's interfaces nor as its outgoing address; the outside check decides whether it leads here." ;;
    esac
    TARGETS=("$SITE $(family_of "$SITE")")
}

# ------------------------------------------------------ 4. the public port --

HTTPS_SOURCE=""   # auto | manual
TRIED=()          # "port: reason" for the summary of a failed auto choice
EXT_PORT_STATE="" # reachable | skipped (read by the summary)
PROBE_CONTAINER="auditdsec-probe-listen"
STOPPED_OWN=()    # this installation's containers stopped for the checks
STACK_STARTED=no


# remote_check KIND ADDRESS PORT FAMILY — asks the provider; sets RC_* below.
RC_RESULT=""; RC_DETAIL=""; RC_TLS_VERIFIED=""; RC_TLS_ERROR=""; RC_NOT_AFTER=""
remote_check() {
    local kind="$1" addr="$2" port="$3" fam="$4" out
    RC_RESULT=""; RC_DETAIL=""; RC_TLS_VERIFIED=""; RC_TLS_ERROR=""; RC_NOT_AFTER=""
    AUDITDSEC_PROBE_TOKEN="$(head -n 1 "$PROBE_TOKEN_FILE")"
    export AUDITDSEC_PROBE_TOKEN AUDITDSEC_PROBE_NONCE="${PROBE_NONCE:-}"
    AGENT_ENV=(-e AUDITDSEC_PROBE_TOKEN -e AUDITDSEC_PROBE_NONCE)
    local args=(remote-check -url "$PROBE_URL" -kind "$kind" -ip "$addr" -port "$port" -family "$fam")
    if [ -n "$PROBE_CACERT" ]; then
        AGENT_ENV+=(-v "$PROBE_CACERT:/probe-ca.pem:ro"); args+=(-cacert /probe-ca.pem)
    fi
    if [ "$kind" = tls ]; then
        args+=(-server-name "$SITE")
        [ "$MODE" != domain ] || args+=(-host "$SITE")
    fi
    local wt=()
    if command -v timeout >/dev/null 2>&1; then wt=(timeout "${PROBE_TIMEOUT:-60}"); fi
    out="$("${wt[@]}" $DOCKER run --rm --network host ${AGENT_ENV[@]+"${AGENT_ENV[@]}"} "$IMAGE" "${args[@]}" 2>/dev/null || true)"
    unset AUDITDSEC_PROBE_TOKEN
    AGENT_ENV=()
    RC_RESULT="$(kv RESULT "$out")"; RC_RESULT="${RC_RESULT:-external_check_unavailable}"
    RC_DETAIL="$(kv DETAIL "$out")"
    RC_TLS_VERIFIED="$(kv TLS_VERIFIED "$out")"
    RC_TLS_ERROR="$(kv TLS_ERROR "$out")"
    RC_NOT_AFTER="$(kv TLS_NOT_AFTER "$out")"
}

# bind_check PORT — 0 when the port can be bound on this server (both address
# families). Otherwise BIND_REASON says what holds it.
BIND_REASON=""
bind_check() {
    local out rc=0
    out="$(agent port-check "$1" 2>&1)" || rc=$?
    BIND_REASON=""
    [ "$rc" = 0 ] && return 0
    BIND_REASON="$(kv REASON "$out")"
    [ -n "$BIND_REASON" ] || BIND_REASON="$(printf '%s' "$out" | tail -n 1)"
    if command -v ss >/dev/null 2>&1; then
        local who
        who="$(ss -H -ltnp "sport = :$1" 2>/dev/null | grep -o 'users:(([^)]*' | head -n 1 | sed 's/users:((//' || true)"
        [ -z "$who" ] || BIND_REASON="$BIND_REASON; held by $who"
    fi
    return 1
}

# start_listener PORT — the temporary listener the outside check connects to.
# It serves one random nonce and nothing else: no panel, no API, no secret.
PROBE_NONCE=""
start_listener() {
    local port="$1" tries=0
    stop_listener
    PROBE_NONCE="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    export AUDITDSEC_PROBE_NONCE="$PROBE_NONCE"
    $DOCKER run -d --rm --name "$PROBE_CONTAINER" --network host -e AUDITDSEC_PROBE_NONCE \
        "$IMAGE" probe-listen -port "$port" -ttl 3m >/dev/null 2>&1 || return 1
    while [ "$tries" -lt 20 ]; do
        tries=$((tries + 1))
        if curl -sS --noproxy '*' --max-time 2 "http://127.0.0.1:$port/.well-known/auditdsec-probe/$PROBE_NONCE" 2>/dev/null | grep -q "$PROBE_NONCE"; then
            return 0
        fi
        [ "$($DOCKER inspect -f '{{.State.Running}}' "$PROBE_CONTAINER" 2>/dev/null || true)" = true ] || return 1
        sleep 0.5
    done
    return 1
}

stop_listener() { $DOCKER rm -f "$PROBE_CONTAINER" >/dev/null 2>&1 || true; }

# reach_from_outside PORT — bind a listener and have the provider fetch the
# nonce on every target address. Returns 0 reachable on all, 1 when this port
# is the problem (EXT_REASON), 2 when the check itself failed.
EXT_REASON=""
reach_from_outside() {
    local port="$1" t addr fam
    EXT_REASON=""
    if ! start_listener "$port"; then
        stop_listener
        EXT_REASON="port_in_use: the temporary listener could not bind it (something took the port in the meantime)"
        return 1
    fi
    for t in "${TARGETS[@]}"; do
        addr="${t% *}"; fam="${t#* }"
        remote_check nonce "$addr" "$port" "$fam"
        case "$RC_RESULT" in
            reachable) ;;
            refused|timeout|wrong_endpoint)
                stop_listener
                EXT_REASON="$RC_RESULT on $(hostport "$addr" "$port")${RC_DETAIL:+: $RC_DETAIL}"
                return 1 ;;
            *)
                stop_listener
                EXT_REASON="${RC_DETAIL:-the provider did not give an answer}"
                return 2 ;;
        esac
    done
    stop_listener
    return 0
}

# release_own — stop this installation's proxy and certbot while ports are
# checked: they hold the very ports being tested. They are started again at
# the end, or put back by the EXIT trap when this run stops early.
release_own() {
    local c
    for c in auditdsec-caddy auditdsec-certbot; do
        if [ "$($DOCKER inspect -f '{{.State.Running}}' "$c" 2>/dev/null || true)" = true ]; then
            [ ${#STOPPED_OWN[@]} -gt 0 ] || say "Stopping this installation's own proxy while ports are checked (it is started again)."
            $DOCKER stop -t 10 "$c" >/dev/null 2>&1 && STOPPED_OWN+=("$c")
        fi
    done
    return 0
}

hostport() { case "$1" in *:*) printf '[%s]:%s' "$1" "$2" ;; *) printf '%s:%s' "$1" "$2" ;; esac; }

reserved_port() { # PORT -> reason it may not be the panel's port, or nothing
    local p="$1" up="${PORT:-$(env_get PANEL_UPSTREAM_PORT)}"
    up="${up:-$(env_get PANEL_PORT)}"; up="${up:-9477}"
    if [ "$p" = 80 ]; then echo "80 is kept for the certificate challenge (HTTP-01)"; return; fi
    if [ "$p" = 2019 ]; then echo "2019 is the proxy's local admin API"; return; fi
    if [ "$p" = "$up" ]; then echo "$p is the agent's own loopback port (--upstream-port)"; return; fi
}


LAST_PORT_CODE=""


port_range() {
    local lo="$PORT_RANGE_LO" hi="$PORT_RANGE_HI"
    [ -n "$lo" ] || lo=20000
    [ -n "$hi" ] || hi=29999
    printf '%s %s\n' "$lo" "$hi"
}



# ----------------------------------------------- 5. certificate needs ------

ACME_PORT_STATE=""


ask_email() {
    case "$MODE" in domain|ip) ;; *) return 0 ;; esac
    EMAIL="${EMAIL:-$(ask "E-mail for certificate expiry warnings (optional for an address)" "$(env_get PANEL_EMAIL)")}"
    if [ "$MODE" = domain ] && [ -z "$EMAIL" ]; then
        die "Let's Encrypt needs an e-mail address for a domain (--email)"
    fi
}

# acme_url_for ENV — the ACME directory for staging or production. The two
# overrides exist for a private ACME server (and for the tests, which run
# one); without them these are Let's Encrypt's.
acme_url_for() {
    case "$1" in
        staging)    local o; o="$(cfg PANEL_ACME_URL_STAGING)";    printf '%s' "${o:-$LE_STAGING}" ;;
        production) local o; o="$(cfg PANEL_ACME_URL_PRODUCTION)"; printf '%s' "${o:-$LE_PRODUCTION}" ;;
    esac
}

# settle_acme: production unless --staging was given, now or on an earlier
# run. Nothing is switched silently: an installation that was set up on
# staging stays on staging until --production says otherwise.
settle_acme() {
    case "$MODE" in domain|ip) ;; *) ACME=""; return 0 ;; esac
    local stored
    stored="$(env_get PANEL_ACME)"
    [ -n "$ACME" ] || ACME="${stored:-production}"
    case "$ACME" in staging|production) ;; *) die "unknown ACME environment '$ACME'" ;; esac
    ACME_URL="$(acme_url_for "$ACME")"
    ACME_CA_ROOT="$(cfg PANEL_ACME_CA_ROOT)"
    if [ -n "$ACME_CA_ROOT" ]; then
        [ -r "$ACME_CA_ROOT" ] || die "PANEL_ACME_CA_ROOT=$ACME_CA_ROOT is not a readable file"
        ACME_CA_ROOT="$(readlink -f "$ACME_CA_ROOT")"
    fi
    if [ -n "$stored" ] && [ "$stored" != "$ACME" ]; then
        say "Switching from $stored to $ACME. The $stored certificates, account and"
        say "settings stay in their own volumes; nothing is deleted."
    fi
    [ "$ACME" = production ] || warn "Let's Encrypt STAGING: browsers will not trust the certificate; the panel is not reported as published."
}

ask_telegram() {
    local token chat
    token="$(env_get AUDITDSEC_TG_TOKEN)"
    chat="$(env_get AUDITDSEC_TG_CHAT_ID)"
    if [ -n "$token" ] && [ -n "$chat" ]; then
        return 0
    fi
    installer_lines <<EOF

Telegram
Telegram is optional. You can configure it later in the panel, under Alerts.
To configure it now, make a bot with @BotFather, send /start to your bot,
then read your chat id from
https://api.telegram.org/bot<TOKEN>/getUpdates

EOF
    if ! interactive; then
        return 0
    fi
    local choice
    choice="$(ask 'Configure Telegram now? (y/N)' 'n')"
    case "$choice" in y|Y|д|Д) ;; *) return 0 ;; esac
    [ -n "$token" ] || token="$(ask_secret 'Telegram bot token (not shown)')"
    [ -n "$token" ] || die "the token is required"
    [ -n "$chat" ] || chat="$(ask 'Your chat id' '')"
    [ -n "$chat" ] || die "the chat id is required"
    env_set AUDITDSEC_TG_TOKEN "$token"
    env_set AUDITDSEC_TG_CHAT_ID "$chat"
}

ask_login() {
    LOGIN="${LOGIN:-$(env_get AUDITDSEC_WEB_LOGIN)}"
    LOGIN="${LOGIN:-admin}"
}

# Blocking stays off unless asked for: --enforce, or an earlier run that had it.
ask_enforce() {
    [ -n "$ENFORCE" ] && return 0
    ENFORCE="$(env_get PANEL_ENFORCE)"
    ENFORCE="${ENFORCE:-no}"
}

# ask_password: nothing is asked. With no password set the panel opens with
# admin / admin, which can do only one thing: lead to the screen where the
# owner chooses a login and password. --password-file installs one instead.
ask_password() {
    if [ -n "$PASSWORD_FILE" ]; then
        [ -r "$PASSWORD_FILE" ] || die "cannot read $PASSWORD_FILE"
        PASSWORD="$(head -n 1 "$PASSWORD_FILE")"
    fi
    return 0
}

# ----------------------------------------------------------- writing config --

PANEL_URL=""
ACME_URL=""
ACME_CA_ROOT=""

# url_host puts an IPv6 address in brackets, which a URL requires.
url_host() {
    case "$1" in *:*) printf '[%s]' "$1" ;; *) printf '%s' "$1" ;; esac
}

# compute_panel_url — the link a person types: the real public port, left out
# only when it is 443.
compute_panel_url() {
    case "$MODE" in
        tunnel) PANEL_URL="http://127.0.0.1:$PORT" ;;
        *)
            PANEL_URL="https://$(url_host "$SITE")"
            [ "${HTTPS_PORT:-443}" = 443 ] || PANEL_URL="$PANEL_URL:$HTTPS_PORT" ;;
    esac
}

write_config() {
    sub "Writing $ENV_FILE"
    CHANGED=yes
    [ -f "$ENV_FILE" ] || { : > "$ENV_FILE"; chmod 0600 "$ENV_FILE"; }

    # PANEL_PORT was the agent's loopback port all along; it is now called
    # PANEL_UPSTREAM_PORT so it cannot be mistaken for the public one.
    PORT="${PORT:-$(env_get PANEL_UPSTREAM_PORT)}"
    PORT="${PORT:-$(env_get PANEL_PORT)}"
    PORT="${PORT:-9477}"
    case "$PORT" in ''|*[!0-9]*) die "the upstream port must be a number" ;; esac
    [ "$PORT_DEPRECATED" = no ] || warn "--port is the old name of --upstream-port: the agent's loopback port, not the public one."

    env_set PANEL_MODE "$MODE"
    env_set PANEL_INSTALLER_LANG "$INSTALLER_LANG"
    env_set PANEL_ENFORCE "$ENFORCE"
    env_set PANEL_UPSTREAM_PORT "$PORT"
    env_unset PANEL_PORT
    # The images of this run. The one the installation used before is kept, so
    # going back is one line in .env (and .env.last-good holds it as well).
    local prev
    prev="$(env_get AUDITDSEC_IMAGE)"
    [ -n "$prev" ] || prev="$(legacy_image)"
    if [ -n "$prev" ] && [ "$prev" != "$IMAGE" ]; then env_set PANEL_IMAGE_PREVIOUS "$prev"; fi
    env_set AUDITDSEC_IMAGE "$IMAGE"
    env_set AUDITDSEC_ENFORCE_IMAGE "$ENFORCE_IMAGE"
    env_set AUDITDSEC_COMMIT "${SOURCE_COMMIT:-unknown}"
    env_unset AUDITDSEC_VERSION
    env_set AUDITDSEC_WEB 1
    env_set AUDITDSEC_WEB_LOGIN "$LOGIN"
    if [ "$ENFORCE" = yes ]; then env_set AUDITDSEC_BAN_BACKEND nftables; else env_unset AUDITDSEC_BAN_BACKEND; fi

    # Settings that depend on how the panel is published. The overlay files
    # set the same keys themselves, so .env must not carry a stale value left
    # over from an earlier choice.
    local k
    for k in PANEL_DOMAIN PANEL_CADDYFILE PANEL_SITE PANEL_SITE_ADDR PANEL_EMAIL PANEL_HTTPS_PORT \
             PANEL_PUBLIC_URL AUDITDSEC_WEB_LISTEN AUDITDSEC_WEB_PUBLIC_URL PANEL_ACME PANEL_ACME_URL \
             PANEL_ACME_SUFFIX PANEL_HSTS PANEL_ACME_CA_ROOT PANEL_CERT_CHECK; do
        env_unset "$k"
    done

    compute_panel_url
    case "$MODE" in
        domain|ip|selfsigned)
            env_set PANEL_SITE "$SITE"
            env_set PANEL_SITE_ADDR "$(url_host "$SITE")"
            env_set PANEL_HTTPS_PORT "$HTTPS_PORT"
            env_set PANEL_PUBLIC_URL "$PANEL_URL"
            [ -z "$EMAIL" ] || env_set PANEL_EMAIL "$EMAIL"
            [ -z "$PUBLIC_IP" ] || env_set PANEL_PUBLIC_IP "$PUBLIC_IP"
            ;;
    esac
    # The agent watches the certificate its panel serves. It can judge the
    # chain only against the public CA store; a staging, self-signed or
    # privately signed certificate is watched for its expiry alone.
    if [ "$MODE" = selfsigned ] || [ "$ACME" = staging ] || [ -n "$CACERT" ]; then
        env_set PANEL_CERT_CHECK expiry
    fi
    case "$MODE" in
        domain)     env_set PANEL_CADDYFILE ./deploy/Caddyfile ;;
        ip)         env_set PANEL_CADDYFILE ./deploy/Caddyfile.acme-ip ;;
        selfsigned) env_set PANEL_CADDYFILE ./deploy/Caddyfile.selfsigned ;;
    esac
    # The probe: its URL and the PATH of its token file, never the token.
    if [ -n "$PROBE_URL" ] && [ "$NO_EXTERNAL" = no ]; then
        env_set PANEL_PROBE_URL "$PROBE_URL"
        env_set PANEL_PROBE_TOKEN_FILE "$PROBE_TOKEN_FILE"
        if [ -n "$PROBE_CACERT" ]; then env_set PANEL_PROBE_CACERT "$PROBE_CACERT"; else env_unset PANEL_PROBE_CACERT; fi
    fi
    case "$MODE" in
        domain|ip)
            env_set PANEL_ACME "$ACME"
            env_set PANEL_ACME_URL "$ACME_URL"
            # Staging and production keep separate volumes: an account, a
            # certificate and a renewal state from one must never be mistaken
            # for the other's. Production keeps the plain names, so an
            # installation made before staging existed is still production.
            if [ "$ACME" = staging ]; then
                env_set PANEL_ACME_SUFFIX -staging
                # HSTS would remove the browser's "continue anyway" button on a
                # certificate that is untrusted on purpose.
                env_set PANEL_HSTS 'max-age=0'
            fi
            [ -z "$ACME_CA_ROOT" ] || env_set PANEL_ACME_CA_ROOT "$ACME_CA_ROOT"
            local o
            for o in PANEL_ACME_URL_STAGING PANEL_ACME_URL_PRODUCTION; do
                [ -z "$(cfg "$o")" ] || env_set "$o" "$(cfg "$o")"
            done
            ;;
    esac
    ok "saved; existing settings and the Telegram credentials were kept"
}

# hash_password turns the password into the stored hash inside the agent's own
# image, so the hashing code is the code that will check it. The password
# goes in on stdin and is never an argument, so it is not in a process list.
hash_password() {
    [ -n "$PASSWORD" ] || return 0
    sub "Hashing the password"
    local hash errfile
    errfile="$(mktemp)"
    if ! hash="$(printf '%s\n' "$PASSWORD" | $DOCKER run --rm -i "$IMAGE" hash-password -stdin 2>"$errfile")"; then
        warn "the agent refused the password: $(head -c 300 "$errfile")"
        rm -f "$errfile"
        return 1
    fi
    rm -f "$errfile"
    case "$hash" in 'pbkdf2-sha256$'*) ;; *) warn "the hash looks wrong; not saving it"; return 1 ;; esac
    env_set AUDITDSEC_WEB_PASSWORD_HASH "$hash"
    ok "stored as a hash; the password itself is not written anywhere"
}

# ------------------------------------------------------------- the proxy ---

# version_at_least A B — true when A >= B, comparing dotted numbers.
version_at_least() {
    [ -n "${1:-}" ] || return 1
    [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n 1)" = "$2" ]
}

# certtool runs the certificate helper in a throw-away certbot container that
# has the same volumes as the real one.
certtool() {
    compose run --rm --no-deps -T --entrypoint python3 certbot /hooks/certtool.py "$@"
}

# issue_ip_certificate makes sure /certs holds a certificate the proxy can
# rightly use, and issues one only when it does not. A file being there
# proves nothing: it may be for another address, a staging certificate, an
# expired one, or one whose key was lost.
issue_ip_certificate() {
    [ "$MODE" = ip ] || return 0
    sub "Certificate for $SITE (Let's Encrypt $ACME)"

    local reasons rc=0
    if reasons="$(certtool check --cert /certs/fullchain.pem --key /certs/privkey.pem \
            --site "$SITE" --acme "$ACME" --directory "$ACME_URL" --meta /certs/meta.json 2>/dev/null)"; then
        ok "the certificate already in place fits: this address, still valid, issued by this CA, key matches"
        return 0
    else
        rc=$?
    fi
    if [ "$rc" != 3 ]; then
        report certificate_issuance_failed "$SITE" "inspecting the certificate in the certbot volume" \
            "the certificate helper could not run (exit $rc)" "check that the certbot image is available (CERTBOT_IMAGE) and run again"
        return 1
    fi
    case "$reasons" in
        *"no usable certificate file"*) say "No certificate yet." ;;
        *)
            say "The certificate that is there cannot be reused:"
            printf '%s\n' "$reasons" | sed 's/^/  - /'
            ;;
    esac

    # certbot's own copy may be fine when only /certs was lost or is stale.
    if certtool adopt >/dev/null 2>&1; then
        ok "certbot already held a fitting certificate; copied it into place"
        return 0
    fi

    local version
    version="$(compose run --rm --no-deps -T --entrypoint certbot certbot --version 2>/dev/null \
        | awk '{print $2}' | tail -n 1 || true)"
    if [ -z "$version" ] || ! version_at_least "$version" 5.3; then
        report certificate_issuance_failed "$SITE" "running certbot from ${CERTBOT_IMAGE:-the pinned certbot image}" \
            "${version:+certbot $version cannot issue certificates for addresses}${version:-the certbot image did not run}" \
            "certbot 5.3 or newer is needed for --ip-address; set CERTBOT_IMAGE or check the network, then run again"
        return 1
    fi

    local args=(certonly --standalone --non-interactive --agree-tos
        --server "$ACME_URL" --cert-name panel --preferred-profile shortlived
        --ip-address "$SITE" --deploy-hook /hooks/deploy.sh)
    if [ -n "$EMAIL" ]; then args+=(-m "$EMAIL"); else args+=(--register-unsafely-without-email); fi
    # An existing lineage that is not fit (another address, nearly expired) has
    # to be replaced even though certbot would call it "not yet due".
    if compose run --rm --no-deps -T --entrypoint sh certbot -c 'test -s /etc/letsencrypt/renewal/panel.conf' >/dev/null 2>&1; then
        args+=(--force-renewal)
    fi

    say "Let's Encrypt ($ACME) connects to port 80 on $SITE now."
    # PANEL_NO_RELOAD: the proxy is not running yet, so the hook only copies.
    if ! compose run --rm --no-deps -T -e PANEL_NO_RELOAD=1 --entrypoint certbot certbot "${args[@]}"; then
        report certificate_issuance_failed "$(hostport "$SITE" 80)" \
            "certbot certonly --standalone --preferred-profile shortlived --ip-address $SITE against $ACME_URL" \
            "the CA did not issue the certificate (its reason is in certbot's output above)" \
            "port 80 was reachable from outside a moment ago, so look at the CA's answer: a rate limit (production: 5 certificates per address per week; --staging tests the rest without spending it), or a firewall rule that changed. Then run again."
        return 1
    fi

    if reasons="$(certtool check --cert /certs/fullchain.pem --key /certs/privkey.pem \
            --site "$SITE" --acme "$ACME" --directory "$ACME_URL" --meta /certs/meta.json 2>/dev/null)"; then
        ok "certificate issued and checked: this address, valid, key matches"
    else
        report certificate_issuance_failed "$SITE" "checking the issued certificate" \
            "certbot reported success, but the certificate in place is not fit: $(printf '%s' "$reasons" | tr '\n' ';')" \
            "run again; if it repeats, look at: $(compose_prefix) logs certbot"
        return 1
    fi
}

# ------------------------------------------------------------------ start ---

start_stack() {
    sub "Starting the containers"
    hash_password || { report bootstrap_persistence_failed "$ENV_FILE" "hashing the password from --password-file" "the agent refused it" "use a password the panel accepts (8+ characters, a lower-case and an upper-case letter)"; return 1; }
    issue_ip_certificate || return 1
    if [ "$DO_START" != yes ]; then say "(--no-start: not starting)"; return 0; fi
    local up=(up -d --remove-orphans)
    up+=(--no-build)   # images are downloaded (or built) before, never here
    if ! compose "${up[@]}"; then
        report service_start_failed "$(compose_prefix)" "docker compose up" \
            "the containers did not start (Docker's message is above)" \
            "look at: $(compose_prefix) logs --tail 80; a port taken between the check and the start shows up as 'address already in use'. Then run again."
        return 1
    fi
    STACK_STARTED=yes
    STOPPED_OWN=()
}

# ------------------------------------------------------- last known good ---

LAST_GOOD="${ENV_FILE}.last-good"
RESTORED=no

# save_last_good keeps the configuration that has just been shown to work, so
# that a later attempt which fails can put it back. It holds the same secrets
# as .env and has the same permissions.
save_last_good() {
    local tmp
    tmp="$(mktemp "${LAST_GOOD}.XXXXXX")"
    cp "$ENV_FILE" "$tmp"
    chmod 0600 "$tmp"
    mv "$tmp" "$LAST_GOOD"
}

load_state_from_env() {
    MODE="$(env_get PANEL_MODE)"
    SITE="$(env_get PANEL_SITE)"; [ -n "$SITE" ] || SITE="$(env_get PANEL_DOMAIN)"
    PORT="$(env_get PANEL_UPSTREAM_PORT)"; PORT="${PORT:-$(env_get PANEL_PORT)}"; PORT="${PORT:-9477}"
    HTTPS_PORT="$(env_get PANEL_HTTPS_PORT)"; HTTPS_PORT="${HTTPS_PORT:-443}"
    ENFORCE="$(env_get PANEL_ENFORCE)"; ENFORCE="${ENFORCE:-no}"
    LOGIN="$(env_get AUDITDSEC_WEB_LOGIN)"; LOGIN="${LOGIN:-admin}"
    EMAIL="$(env_get PANEL_EMAIL)"
    ACME="$(env_get PANEL_ACME)"
    ACME_URL="$(env_get PANEL_ACME_URL)"
    PROBE_URL="$(env_get PANEL_PROBE_URL)"
    PROBE_TOKEN_FILE="$(env_get PANEL_PROBE_TOKEN_FILE)"
    PROBE_CACERT="$(env_get PANEL_PROBE_CACERT)"
    PASSWORD=""
    IMAGE="$(env_get AUDITDSEC_IMAGE)"
    EXT_CONFIGURED=no
    if [ -n "$PROBE_URL" ] && [ -n "$PROBE_TOKEN_FILE" ] && [ -r "$PROBE_TOKEN_FILE" ] && [ "$NO_EXTERNAL" = no ] && [ "$MODE" != tunnel ]; then
        EXT_CONFIGURED=yes
    fi
    TARGETS=()
    [ -z "$SITE" ] || [ "$MODE" = domain ] || TARGETS=("$SITE $(family_of "$SITE")")
    compute_panel_url
    build_compose_files
}

# restore_last_good puts the last verified configuration back and starts it.
# The failed one is kept beside it as .env.failed for diagnosis; no volume is
# touched, so certificates and stored events are exactly as they were.
restore_last_good() {
    local src="${1:-$LAST_GOOD}"
    [ -s "$src" ] || return 1
    step "Restoring the last configuration that was verified working"
    if [ -f "$ENV_FILE" ]; then
        cp "$ENV_FILE" "${ENV_FILE}.failed"
        chmod 0600 "${ENV_FILE}.failed"
    fi
    cp "$src" "$ENV_FILE"
    chmod 0600 "$ENV_FILE"
    # A configuration saved before images were published names none: it ran
    # the locally built one, which is what it gets back.
    if [ -z "$(env_get AUDITDSEC_IMAGE)" ] && [ -n "$(legacy_image)" ]; then
        env_set AUDITDSEC_IMAGE "$(legacy_image)"
    fi
    load_state_from_env
    local up=(up -d --remove-orphans)
    up+=(--no-build)   # images are downloaded (or built) before, never here
    compose "${up[@]}" || { warn "could not start the previous configuration either"; return 1; }
    STACK_STARTED=yes
    STOPPED_OWN=()
    RESTORED=yes
    ok "started again: mode $MODE${SITE:+, $SITE}${ACME:+, $ACME}"
}

# --------------------------------------------------------------- cleanup ---

CA_TMP=""

cleanup() {
    local rc=$?
    [ -z "$CA_TMP" ] || rm -f "$CA_TMP"
    [ -z "${LOCK_DIR:-}" ] || rm -rf "$LOCK_DIR"
    [ -z "$TRACE_ID" ] || jlog info operation_end "exit status $rc" "" ""
    stop_listener 2>/dev/null || true
    unset AUDITDSEC_PROBE_TOKEN 2>/dev/null || true
    # This run stopped the installation's own proxy for the port checks and
    # then failed before starting anything: put it back as it was.
    if [ "$STACK_STARTED" = no ] && [ ${#STOPPED_OWN[@]} -gt 0 ]; then
        $DOCKER start "${STOPPED_OWN[@]}" >/dev/null 2>&1 \
            && installer_printf 'The previous proxy (%s) was started again.\n' "${STOPPED_OWN[*]}" >&2 || true
    fi
}
trap cleanup EXIT

# ------------------------------------------------------------ verification ---

TLS_STATE=""
LOGIN_STATE=""
LOGIN_ROUTE=""
PAGE_STATE=""
RENEW_STATE=""
SETUP_STATE=""
EXT_TLS_STATE=""
NOT_AFTER=""
TLS_UNTRUSTED=no
TLS_TRUSTED=no
RELOAD_PROBLEM=no
# ROUTE is empty unless this server cannot reach its own public address (some
# clouds do not loop it back). Then every local check is sent to the loopback
# address instead, with the same name in the URL, so the certificate and its
# name are still verified exactly as before.
ROUTE=()

# json_escape is enough for a password: backslash and quote are the only
# printable characters that break a JSON string.
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    printf '%s' "$s"
}

# wait_for_page URL — waits for the sign-in page to answer. It sends no
# credentials, only a GET for the page itself, which is why it may skip
# certificate verification (-k) so that "the proxy is up but its certificate
# is wrong" can be told from "nothing answers".
wait_for_page() {
    local url="$1" max="${2:-45}" code tries=0 k=()
    case "$url" in https://*) k=(-k) ;; esac
    while [ "$tries" -lt "$max" ]; do
        tries=$((tries + 1))
        code="$(curl -sS --noproxy '*' ${ROUTE[@]+"${ROUTE[@]}"} "${k[@]}" -o /dev/null -w '%{http_code}' --max-time 4 "$url/" 2>/dev/null || true)"
        [ "$code" = 200 ] && return 0
        sleep 2
    done
    return 1
}

# fetch_internal_ca copies the root certificate of the proxy's own CA out of
# the container, for the self-signed mode.
fetch_internal_ca() {
    local tries=0
    CA_TMP="$(mktemp)"
    while [ "$tries" -lt 10 ]; do
        tries=$((tries + 1))
        if compose cp caddy:/data/caddy/pki/authorities/local/root.crt "$CA_TMP" >/dev/null 2>&1 && [ -s "$CA_TMP" ]; then
            printf '%s' "$CA_TMP"
            return 0
        fi
        sleep 1
    done
    return 1
}

# post_login URL [CURL TRUST ARGS...] — prints the reply. It refuses to run
# when asked to skip certificate verification: a password is never sent over a
# connection whose other end was not verified.
post_login() {
    local url="$1" a body
    shift
    for a in "$@"; do
        case "$a" in
            --insecure|--proxy-insecure|-k|-[a-zA-Z]*k*)
                die "internal error: refusing to send a password without verifying TLS" ;;
        esac
    done
    body="{\"login\":\"$(json_escape "$LOGIN")\",\"password\":\"$(json_escape "$PASSWORD")\"}"
    printf '%s' "$body" | curl -sS --noproxy '*' "$@" --max-time 15 -X POST \
        -H 'X-Requested-With: auditdsec' -H 'Content-Type: application/json' \
        --data-binary @- "$url/api/v1/login" 2>/dev/null || true
}

# setup_state — bootstrap | ready | locked, asked of the agent on loopback.
setup_state() {
    curl -sS --noproxy '*' --max-time 5 "http://127.0.0.1:$PORT/api/v1/setup/state" 2>/dev/null \
        | sed -n 's/.*"state":"\([a-z]*\)".*/\1/p'
}

# verify_stack returns 0 when everything checked out, 1 when the panel is not
# working (a reason to put the previous configuration back) and 2 when it
# works but something a person must look at is wrong (an untrusted production
# certificate, an outside check that failed or could not run).
verify_stack() {
    if [ "$DO_START" != yes ] || [ "$DO_VERIFY" != yes ]; then
        PAGE_STATE="not checked"
        return 0
    fi
    sub "Checking that the panel actually answers"

    local url="$PANEL_URL" local_url="http://127.0.0.1:$PORT" soft=0
    local trust=()      # curl arguments naming the CA to verify against

    ROUTE=()
    local reached=no routed=no
    if wait_for_page "$url" 12; then
        reached=yes
    else
        case "$MODE" in
            domain|ip|selfsigned)
                ROUTE=(--connect-to "::127.0.0.1:")
                if wait_for_page "$url" 33; then reached=yes; routed=yes; else ROUTE=(); fi ;;
            *) if wait_for_page "$url" 33; then reached=yes; fi ;;
        esac
    fi
    if [ "$reached" = no ]; then
        PAGE_STATE="NOT ANSWERING"
        report service_start_failed "$url" "GET $url/ from this server for 90 seconds" \
            "the sign-in page did not answer" \
            "look at: $(compose_prefix) logs --tail 80 auditdsec$([ "$MODE" = tunnel ] || printf ' ; %s logs --tail 40 caddy' "$(compose_prefix)")"
        return 1
    fi
    PAGE_STATE="answers"
    if [ "$routed" = yes ]; then
        PAGE_STATE="answers (from this server only through its loopback: it cannot reach its own public address)"
    fi
    ok "the sign-in page answers at $url"

    # The first-time setup state. "locked" means the agent cannot keep the
    # credentials the owner would choose: setup must not be offered.
    SETUP_STATE="$(setup_state)"
    if [ "$SETUP_STATE" = locked ]; then
        report bootstrap_persistence_failed "$local_url/api/v1/setup/state" \
            "asking the agent whether first-time setup can be saved" \
            "the panel is locked: its state volume cannot be written, or the saved credentials are damaged or missing after setup was completed" \
            "look at: $(compose_prefix) logs --tail 40 auditdsec. Restore the file from a backup, or reset locally with: $(compose_prefix) run --rm auditdsec reset-credentials -yes"
        return 1
    fi

    # Trust: curl WITHOUT -k, against the system store, or against the one CA
    # the person named (--cacert), or, for the self-signed mode, against the
    # root of the proxy's own CA.
    case "$MODE" in
        domain|ip|selfsigned)
            local ca="$CACERT" verify
            if [ -z "$ca" ] && [ "$MODE" = selfsigned ]; then ca="$(fetch_internal_ca || true)"; fi
            [ -z "$ca" ] || trust=(--cacert "$ca")
            verify="$(curl -sS --noproxy '*' ${ROUTE[@]+"${ROUTE[@]}"} "${trust[@]}" -o /dev/null -w '%{ssl_verify_result}' --max-time 6 "$url/" 2>/dev/null || true)"
            verify="${verify:-99}"
            if [ "$verify" = 0 ]; then
                TLS_TRUSTED=yes
                case "$MODE" in
                    selfsigned) TLS_STATE="encrypted, verified against this server's own CA (browsers do not know it, so they warn)" ;;
                    *) if [ -n "$CACERT" ]; then TLS_STATE="valid, verified against the CA file you gave"
                       else TLS_STATE="valid and trusted (checked from this server against its CA store)"; fi ;;
                esac
                ok "the certificate verifies"
            else
                case "$MODE" in
                    selfsigned) TLS_STATE="encrypted, but this installer could not verify it (curl code $verify)" ;;
                    *)
                        if [ "$ACME" = staging ]; then
                            TLS_STATE="STAGING certificate: not trusted, as expected (curl code $verify)"
                        else
                            TLS_STATE="NOT trusted (curl code $verify)"
                            TLS_UNTRUSTED=yes
                        fi ;;
                esac
                warn "the certificate did not verify from here (curl code $verify)."
            fi
            ;;
        tunnel) TLS_STATE="none needed: the connection runs inside the SSH tunnel" ;;
    esac

    if [ "$MODE" != tunnel ] && command -v openssl >/dev/null 2>&1; then
        local peer; peer="$(hostport "$SITE" "$HTTPS_PORT")"
        [ ${#ROUTE[@]} -eq 0 ] || peer="127.0.0.1:$HTTPS_PORT"
        NOT_AFTER="$(printf '' | openssl s_client -connect "$peer" -servername "$SITE" 2>/dev/null \
            | openssl x509 -noout -enddate 2>/dev/null | sed 's/^notAfter=//' || true)"
    fi

    # Sign in: with the password from --password-file when one was given,
    # otherwise with admin / admin while setup is pending (it is not a secret;
    # what it opens is the setup screen only). Over the public address only
    # when its certificate verified; otherwise on this machine's loopback.
    local default_probe=no
    if [ -z "$PASSWORD" ] && [ "$SETUP_STATE" = bootstrap ]; then
        default_probe=yes
        LOGIN="admin"; PASSWORD="admin"
    fi
    if [ -n "$PASSWORD" ]; then
        local target reply
        case "$MODE" in
            tunnel)
                target="$local_url"; trust=()
                LOGIN_ROUTE="on the server's own loopback address (the tunnel is made from your computer)" ;;
            *)
                if [ "$TLS_TRUSTED" = yes ]; then
                    target="$url"
                    LOGIN_ROUTE="over the verified TLS connection to $url"
                else
                    target="$local_url"; trust=()
                    LOGIN_ROUTE="on this server's loopback address ONLY: the certificate at $url could not be verified, so the password was not sent there"
                fi ;;
        esac
        reply="$(post_login "$target" ${ROUTE[@]+"${ROUTE[@]}"} "${trust[@]}")"
        case "$reply" in
            *'"setup":true'*)
                LOGIN_STATE="first-time setup is waiting: admin / admin opens only the screen where the owner chooses a login and password"
                ok "admin / admin leads to first-time setup only" ;;
            *'"token"'*) LOGIN_STATE="signed in with the password from --password-file"; ok "$(installer_text "$LOGIN_STATE"), $(installer_text "$LOGIN_ROUTE")" ;;
            *)
                LOGIN_STATE="SIGN-IN FAILED"
                report bootstrap_persistence_failed "$target/api/v1/login" "signing in $LOGIN_ROUTE" \
                    "the panel refused $([ "$default_probe" = yes ] && echo 'admin / admin while setup is pending' || echo 'the password that was just set')" \
                    "look at: $(compose_prefix) logs --tail 80 auditdsec"
                return 1 ;;
        esac
    elif [ "$SETUP_STATE" = ready ]; then
        LOGIN_STATE="your own credentials are in force (admin / admin no longer works)"
    else
        LOGIN_STATE="not tested"
    fi
    if [ "$default_probe" = yes ]; then PASSWORD=""; fi

    # In address mode the renewal loop owns the certificate. Ask it whether
    # the file it manages is the one the panel's port serves right now.
    if [ "$MODE" = ip ]; then
        local st="" tries=0
        while [ "$tries" -lt 8 ]; do
            tries=$((tries + 1))
            if st="$(compose exec -T certbot python3 /hooks/certtool.py status 2>&1)"; then break; fi
            sleep 3
        done
        if [ "$st" = ok ]; then
            RENEW_STATE="the certificate on disk is the one port $HTTPS_PORT serves; the renewal loop is healthy"
            ok "$RENEW_STATE"
        else
            RENEW_STATE="PROBLEM: $st"
            RELOAD_PROBLEM=yes
            warn "the renewal loop reports: $st"
            soft=2
        fi
    fi

    external_tls_check   # advice only: it never fails the run

    # A certificate that does not verify defeats the point of the two modes
    # that exist to get a trusted one, so it is a failure, not a footnote.
    if [ "$TLS_UNTRUSTED" = yes ] && [ -z "$FAIL_CODE" ]; then
        report tls_validation_failed "$url" "TLS verification against the system CA store, from this server" \
            "$TLS_STATE" \
            "the name or address in the certificate may not be the one in the link, issuance may have failed (logs below), or the clock is wrong. Fix it and run again, or go back with ./install.sh --restore"
        soft=2
    fi
    return "$soft"
}


# ssh_command works out the address the person actually reaches this server
# by, for the tunnel mode.
ssh_command() {
    local host="" port=22 user p=""
    if [ -n "${SSH_CONNECTION:-}" ]; then
        # shellcheck disable=SC2086
        set -- $SSH_CONNECTION
        host="${3:-}"; port="${4:-22}"
    fi
    [ -n "$host" ] || host="$(env_get PANEL_SSH_HOST)"
    if [ -n "$host" ]; then env_set PANEL_SSH_HOST "$host"; else host="<server-address>"; fi
    user="${SUDO_USER:-$(id -un)}"
    [ "$port" != 22 ] && p=" -p $port"
    printf 'ssh%s -L %s:127.0.0.1:%s %s@%s' "$p" "$PORT" "$PORT" "$user" "$host"
}

# ----------------------------------------------------------------- summary ---



# -------------------------------------------------------------------- main ---

exit_status() {
    if [ -n "$FAIL_CODE" ]; then code_status "$FAIL_CODE"; else echo "${1:-0}"; fi
}

main() {
    # Reading the state and the help need no privileges; everything else does,
    # and is refused before anything is read or written.
    if [ "$STATUS_ONLY" = yes ]; then
        if [ "$JSON" = yes ]; then status_json; else print_status; fi
        return 0
    fi
    need_root
    log_start
    if [ "$LOGS_MODE" = yes ]; then logs_command "$LOGS_TRACE"; return 0; fi
    acquire_lock
    log_maintain
    jlog info operation_start "$OPERATION started"
    emit_event stage running start "started"

    if [ "$REMOTE_CHECK" = yes ]; then
        local rcc=0
        remote_check_command || rcc=$?
        return "$rcc"
    fi

    if [ "$RESTORE" = yes ]; then
        steps_begin 2
        preflight_light
        [ -s "$LAST_GOOD" ] || die "there is no verified configuration to go back to ($LAST_GOOD)"
        restore_last_good || die "the previous configuration would not start"
        step "Checking the panel"
        local rrc=0
        verify_stack || rrc=$?
        summary
        return "$(exit_status "$rrc")"
    fi

    if is_installed; then
        if [ -z "$ACTION" ] && [ -z "$MODE" ] && interactive; then
            choose_action
            if [ -z "$ACTION" ]; then say "Nothing was changed."; return 0; fi
        fi
        if [ -n "$ACTION" ]; then
            valid_action "$ACTION" || die "unknown action '$ACTION': use check, update, domain, ip, tunnel, credentials or logs"
            local arc=0
            run_action || arc=$?
            [ "$arc" != 99 ] || arc=0   # 99: the action continues as an ordinary change
            if [ "$ACTION_DONE" = yes ]; then return "$arc"; fi
        fi
    elif [ -n "$ACTION" ]; then
        die "--action needs an existing installation; run ./install.sh without it first"
    fi

    steps_begin 6
    stage preflight "checking this server"
    step "Checking this server"
    preflight_env
    step "How the panel opens"
    choose_mode                       # domain, IP address or tunnel
    stage image "downloading the application image"
    step "Downloading the application image"
    ensure_image
    stage dns "checking the address and ports"
    step "Checking the address and ports"
    ask_site                          # DNS or the address
    setup_probe                       # optional outside check
    select_port                       # the public HTTPS port
    stage challenge "checking what the certificate needs"
    check_challenge
    ask_email
    settle_acme
    ask_telegram
    ask_login
    ask_enforce
    ask_password
    ensure_enforce_image              # before anything is written
    compute_panel_url
    confirm_plan

    announce_change
    backup_current                    # what a rollback goes back to
    stage apply "writing the configuration and starting"
    step "Starting"
    write_config
    build_compose_files

    local vrc=0 started=yes
    if ! start_stack; then
        started=no
        [ -n "$FAIL_CODE" ] || report service_start_failed "$(compose_prefix)" "starting the stack" "it did not start" "see the messages above"
    else
        stage verify "checking the new address"
        step "Checking the panel"
        verify_stack || vrc=$?
    fi

    # The new settings do not work. When there is a configuration that did,
    # put it back rather than leave a person with nothing; the failed one is
    # kept for diagnosis.
    if [ "$started" = no ] || [ "$vrc" = 1 ]; then
        local rsrc; rsrc="$(rollback_source)"
        if [ -n "$rsrc" ] && ! cmp -s "$ENV_FILE" "$rsrc"; then
            local code="$FAIL_CODE" reason="$FAIL_REASON"
            stage rollback "restoring the previous configuration"
            if restore_last_good "$rsrc"; then
                TLS_UNTRUSTED=no; LOGIN_STATE=""; LOGIN_ROUTE=""; TLS_STATE=""; RENEW_STATE=""; RELOAD_PROBLEM=no
                PAGE_STATE=""; PASSWORD=""; EXT_TLS_STATE=""; EXT_STATE=""; EXT_CONFIGURED=no
                step "Checking the restored panel"
                verify_stack || true
                FAIL_CODE="$code"; FAIL_REASON="$reason"
            fi
        else
            say ""
            say "There is no earlier working configuration to go back to."
        fi
        step "Result"
        summary
        if [ "$RESTORED" = yes ]; then emit_event result rolled_back "$FAIL_CODE" "$FAIL_REASON"; else emit_event result failed "$FAIL_CODE" "$FAIL_REASON"; fi
        jlog error result "$FAIL_CODE: $FAIL_REASON" "$FAIL_CODE"
        return "$(exit_status 1)"
    fi

    if [ "$DO_START" = yes ] && [ "$DO_VERIFY" = yes ] && [ "$vrc" = 0 ] && [ -z "$FAIL_CODE" ]; then
        save_last_good
    fi
    step "Result"
    summary
    if [ -n "$FAIL_CODE" ] || [ "$vrc" != 0 ]; then
        emit_event result failed "$FAIL_CODE" "$FAIL_REASON"
        jlog error result "${FAIL_CODE:-verify}: $FAIL_REASON" "${FAIL_CODE:-verify_failed}"
    else
        emit_event result ok "" "$PANEL_URL"
        jlog info result "ok: $PANEL_URL"
    fi
    return "$(exit_status "$vrc")"
}

# run_action performs the part of a chosen action that is not an ordinary
# change. check and credentials finish here (ACTION_DONE=yes); domain, ip,
# tunnel and update set the mode and continue as a normal change, which
# reuses everything saved.
ACTION_DONE=no
run_action() {
    case "$ACTION" in
        check)
            ACTION_DONE=yes
            steps_begin 1
            preflight_light
            load_state_from_env
            step "Checking the panel"
            local crc=0
            verify_stack || crc=$?
            summary
            emit_event result "$([ "$crc" = 0 ] && echo ok || echo failed)" "$FAIL_CODE" "$FAIL_REASON"
            return "$(exit_status "$crc")" ;;
        credentials)
            ACTION_DONE=yes
            steps_begin 1
            preflight_light
            load_state_from_env
            installer_lines <<'EOF'

The login and password will be reset: the next sign-in is admin / admin and
opens only the screen where you choose new ones. Events, bans, the allowlist,
Telegram and every other setting are kept.
EOF
            confirm "Reset the login and password?" || { say "Nothing was changed."; return 0; }
            stage apply "resetting the credentials"
            step "Resetting the login and password"
            if compose run --rm auditdsec reset-credentials -yes; then
                ok "reset; open the panel and choose a new login and password"
                emit_event result ok "" "credentials reset"
                return 0
            fi
            report service_start_failed "$(compose_prefix)" "reset-credentials" "the agent did not reset the credentials" "run: $(compose_prefix) run --rm auditdsec reset-credentials -yes"
            emit_event result failed "$FAIL_CODE" "$FAIL_REASON"
            return "$(exit_status 1)" ;;
        update)
            if [ -d .git ] && command -v git >/dev/null 2>&1 && interactive && confirm "Fetch the latest version of the installer and application sources (git pull --ff-only)?"; then
                git pull --ff-only || warn "git pull did not succeed; continuing with the sources that are here"
            fi
            apply_action_defaults
            return 99 ;;
        logs)
            ACTION_DONE=yes
            logs_menu
            return 0 ;;
        enable-control|disable-control)
            ACTION_DONE=yes
            preflight_light
            load_state_from_env
            if [ "$ACTION" = enable-control ]; then enable_control; else disable_control; fi
            return $? ;;
        domain|ip|tunnel)
            apply_action_defaults
            return 99 ;;
    esac
}

# preflight_light is what --restore needs: Docker, and nothing built.
preflight_light() {
    command -v "${DOCKER%% *}" >/dev/null 2>&1 || die "$DOCKER is not installed"
    $DOCKER info >/dev/null 2>&1 || die "cannot talk to the Docker daemon"
}

if [ -z "${AUDITDSEC_INSTALL_SOURCED:-}" ]; then main; fi
