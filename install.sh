#!/usr/bin/env bash
#
# auditdsec — set up the agent and the web panel.
#
#   ./install.sh
#
# The order is fixed:
#
#   1. preflight: Linux, a supported CPU, Docker with Compose, curl; what an
#      earlier installation left (it is kept). The agent image is built here,
#      because the checks below run inside it.
#   2. where the panel opens: on a domain or on this server's public IP
#   3. the domain's public DNS (or the address) is checked against this server
#   4. the public HTTPS port: picked automatically (443 first, then up to 16
#      random high ports) or given by you. Each candidate is bound locally and
#      then reached from OUTSIDE by a RemoteProbe provider you run elsewhere.
#   5. what the certificate needs: port 80 for HTTP-01 (or 443 for TLS-ALPN
#      on a domain), the e-mail for Let's Encrypt, the Telegram bot
#   6. the configuration is written, the stack started, and the panel checked
#      again from outside, this time over verified TLS
#   7. only then the summary with the link. Any failure has its own code, a
#      non-zero exit status, and says what to fix and how to run this again.
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

cd "$(dirname "$0")"

ORIG_ARGS=("$@")

# ---------------------------------------------------------------- settings --

ENV_FILE="${ENV_FILE:-.env}"
DOCKER="${DOCKER:-docker}"
COMPOSE_BASE="docker-compose.yml"
IMAGE_TAG="auditdsec:${AUDITDSEC_VERSION:-0.1.0}"

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
RESTORE=no
PORT_DEPRECATED=no
PORT_RANGE_LO="${PANEL_PORT_RANGE_LO:-}"
PORT_RANGE_HI="${PANEL_PORT_RANGE_HI:-}"

LE_PRODUCTION="https://acme-v02.api.letsencrypt.org/directory"
LE_STAGING="https://acme-staging-v02.api.letsencrypt.org/directory"

# --------------------------------------------------------------- utilities --

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    B=$'\033[1m'; R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; N=$'\033[0m'
else
    B=""; R=""; G=""; Y=""; N=""
fi

say()  { printf '%s\n' "$*"; }
step() { printf '\n%s==>%s %s\n' "$B" "$N" "$*"; }
warn() { printf '%s!%s  %s\n' "$Y" "$N" "$*" >&2; }
die()  { printf '%serror:%s %s\n' "$R" "$N" "$*" >&2; exit 1; }
ok()   { printf '%s/%s  %s\n' "$G" "$N" "$*"; }

usage() {
    cat <<'EOF'
Usage: ./install.sh [options]

With no options it asks what it needs, in this order: domain or IP, the
address, the HTTPS port, then what the certificate needs.

Where the panel opens
  --mode domain|ip                     on a domain, or on this server's public IP
  --site NAME|ADDRESS                  the domain, or the public address
  --public-ip ADDRESS[,ADDRESS]        this server's public address(es), when they
                                       cannot be found (NAT, a floating address)
  --https-port N|auto                  the PUBLIC HTTPS port of the panel. auto (the
                                       default on a new setup) tries 443, then up to 16
                                       random high ports. A port you give is never
                                       replaced: if it does not work, the run stops.
  --email ADDRESS                      where Let's Encrypt sends expiry warnings

The check from outside
  --probe-url URL                      a RemoteProbe provider: cmd/auditdsec-probe running
                                       on ANOTHER machine. It connects to this server's
                                       address and port and reports what it saw.
  --probe-token-file PATH              file with that provider's token
  --probe-cacert FILE                  CA file for the provider's own certificate
  --no-external-check                  skip it. A technical mode: the panel is then never
                                       reported as published.

Other settings
  --upstream-port N                    the agent's own port on loopback (default 9477;
                                       never published)
  --port N                             old name of --upstream-port. It was always the
                                       agent's loopback port, not the public one.
  --login NAME / --password-file PATH  install your own login and password instead of the
                                       first-time setup in the browser
  --enforce / --no-enforce             apply bans with nftables, or only record them
                                       (default: only record)

Technical modes (never reported as "published and ready")
  --staging                            Let's Encrypt staging CA: its certificates are not
                                       trusted by browsers. --production moves back.
  --production                         the real Let's Encrypt CA
  --cacert FILE                        verify the panel's certificate against this CA
  --mode tunnel                        no public port; reach the panel over ssh -L
  --mode selfsigned                    a certificate the proxy signs itself; every
                                       browser warns
  --no-start                           write the configuration and stop
  --no-verify                          start, but do not check the panel answers
  --no-build                           use the image that exists, do not build
  --restore                            put back the last configuration that was verified
  --yes                                ask nothing that already has an answer
  -h, --help                           this text

Exit status: 0 when every check that ran passed; otherwise the code of the
first failure:

  10 port_in_use                 the port cannot be bound on this server
  11 external_port_unreachable   bound here, but not reached from outside
  12 external_check_unavailable  no RemoteProbe provider, or it did not answer
  13 dns_mismatch                public DNS does not lead (only) to this server
  14 acme_challenge_unreachable  port 80 (or 443) cannot be used for the challenge
  15 certificate_issuance_failed the CA did not issue the certificate
  16 tls_validation_failed       the panel's certificate does not verify
  17 service_start_failed        the containers did not start or the page is silent
  18 bootstrap_persistence_failed the panel cannot save its credentials
   1 anything else (bad input, Docker missing, ...)
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
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
        --no-build) NO_BUILD=yes; shift ;;
        --yes|-y) ASSUME_YES=yes; shift ;;
        --no-start) DO_START=no; shift ;;
        --no-verify) DO_VERIFY=no; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option $1 (try --help)" ;;
    esac
done

interactive() { [ -t 0 ] && [ "$ASSUME_YES" = no ]; }

# ask PROMPT DEFAULT -> answer on stdout
ask() {
    local prompt="$1" default="${2:-}" reply=""
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
    read -r -s -p "$prompt: " reply </dev/tty || true
    printf '\n' >&2
    printf '%s' "$reply"
}

confirm() {
    local prompt="$1" reply=""
    interactive || return 0
    read -r -p "$prompt [Y/n]: " reply </dev/tty || true
    case "$reply" in [nN]*) return 1 ;; *) return 0 ;; esac
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
# remembers it. The first failure is the one the exit status names.
report() {
    local code="$1" endpoint="$2" check="$3" cause="$4" fix="$5"
    [ -n "$FAIL_CODE" ] || FAIL_CODE="$code"
    [ -n "$FAIL_REASON" ] || FAIL_REASON="$code: $cause"
    {
        printf '\n%sFAILED: %s%s\n' "$R$B" "$code" "$N"
        printf '  endpoint: %s\n' "$endpoint"
        printf '  check:    %s\n' "$check"
        printf '  result:   %s\n' "$cause"
        printf '  fix:      %s\n' "$fix"
        printf '  retry:    %s\n' "$(retry_command)"
    } >&2
}

# abort CODE ... — a failure before anything was started: report it, clean up
# (the EXIT trap) and stop with the code's status.
abort() {
    report "$@"
    printf '\n%sThe panel was NOT published.%s Nothing that was working before was removed.\n' "$R$B" "$N" >&2
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

preflight() {
    step "Preflight"
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
    $DOCKER info >/dev/null 2>&1 || die "cannot talk to the Docker daemon; is it running, and are you root (or in the docker group)?"
    [ -r /var/log/audit/audit.log ] || [ "$(id -u)" != 0 ] \
        || warn "/var/log/audit/audit.log is missing: is auditd installed and running? The panel will show nothing until it is."
    ok "Linux $arch, Docker with Compose, curl"

    if [ -n "$(env_get PANEL_MODE)" ] || [ -n "$(env_get AUDITDSEC_WEB)" ]; then
        PREVIOUS_INSTALL=yes
        local pm pu
        pm="$(env_get PANEL_MODE)"; pu="$(env_get PANEL_PUBLIC_URL)"
        ok "an earlier installation is here${pm:+ (mode $pm${pu:+, $pu})}: its data, certificates and credentials are kept"
    fi

    ensure_image
}

# ensure_image builds the agent image first: the DNS and port checks below run
# inside it, so they work the same with or without Go on this machine.
ensure_image() {
    if [ "$NO_BUILD" = yes ]; then
        $DOCKER image inspect "$IMAGE_TAG" >/dev/null 2>&1 \
            || die "--no-build was given but the image $IMAGE_TAG does not exist"
        return 0
    fi
    say "Building the agent image (the checks run inside it)..."
    local log
    log="$(mktemp)"
    if ! compose_build >"$log" 2>&1; then
        tail -n 30 "$log" >&2; rm -f "$log"
        die "the image did not build"
    fi
    rm -f "$log"
    ok "image $IMAGE_TAG ready"
}

compose_build() { $DOCKER compose -f "$COMPOSE_BASE" build auditdsec; }

# agent ARGS... — runs one of the agent's own commands in the image, in the
# host's network namespace so it sees this server's addresses and ports. Only
# named variables are passed, by name, so their values never appear in a
# process list.
AGENT_ENV=()
agent() {
    $DOCKER run --rm --network host ${AGENT_ENV[@]+"${AGENT_ENV[@]}"} "$IMAGE_TAG" "$@"
}

# kv KEY TEXT — the value of KEY=... in the agent's output.
kv() { printf '%s\n' "$2" | sed -n "s/^$1=//p" | tail -n 1; }

# ------------------------------------------------------- 2. where the panel --

valid_mode() { case "$1" in domain|ip|selfsigned|tunnel) return 0 ;; *) return 1 ;; esac; }

choose_mode() {
    if [ -n "$MODE" ]; then
        valid_mode "$MODE" || die "unknown mode '$MODE': use domain or ip (or, for development, tunnel or selfsigned)"
        return 0
    fi
    local previous
    previous="$(env_get PANEL_MODE)"
    if ! interactive; then
        # A re-run keeps what was chosen before, including a tunnel or a
        # self-signed setup that someone asked for by name back then.
        [ -n "$previous" ] || die "say where the panel should open: --mode domain --site NAME, or --mode ip [--site ADDRESS]"
        MODE="$previous"
        return 0
    fi
    if [ "$previous" = tunnel ] || [ "$previous" = selfsigned ]; then
        if confirm "This installation uses --mode $previous. Keep it?"; then MODE="$previous"; return 0; fi
    fi
    cat <<EOF

${B}Where should the panel open?${N}

  1) On a domain        https://panel.example.com
     A domain whose A/AAAA records point at this server.

  2) On this server's public IP address
     Let's Encrypt certifies public addresses too (6-day certificates,
     renewed automatically).

Both get a certificate every browser trusts, and both are checked from
outside before the link is shown.

EOF
    local default=1 reply
    [ "$previous" = ip ] && default=2
    reply="$(ask "Choose 1 or 2" "$default")"
    case "$reply" in
        1|domain) MODE=domain ;;
        2|ip) MODE=ip ;;
        *) die "pick 1 or 2" ;;
    esac
}

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

check_domain() {
    local previous out rc=0 name
    previous="$(env_get PANEL_SITE)"; [ -n "$previous" ] || previous="$(env_get PANEL_DOMAIN)"
    [ "$(env_get PANEL_MODE)" = domain ] || previous=""
    SITE="${SITE:-$(ask "Domain name for the panel (e.g. panel.example.com)" "$previous")}"
    [ -n "$SITE" ] || die "a domain name is required (--site NAME)"

    step "Public DNS for $SITE"
    local args=(net-check domain "$SITE")
    [ -z "$PUBLIC_IP" ] || args+=(-public-ip "$PUBLIC_IP")
    out="$(agent "${args[@]}")" || rc=$?
    name="$(kv NAME "$out")"
    if [ "$rc" = 3 ]; then
        abort dns_mismatch "${name:-$SITE}" \
            "A and AAAA records from several independent public DNS servers, compared with this server's addresses" \
            "the name does not lead only to this server (A: $(kv A "$out" | sed 's/^$/-/'), AAAA: $(kv AAAA "$out" | sed 's/^$/-/'); this server: $(kv SERVER "$out" | sed 's/^$/unknown/'))" \
            "make every A and AAAA record of ${name:-$SITE} point at this server (delete a wrong AAAA rather than leave it), turn off any CDN proxying (DNS only), wait for DNS to spread, and run again. If this server is behind NAT, give its public address with --public-ip."
    elif [ "$rc" != 0 ]; then
        die "the DNS check could not run (exit $rc)"
    fi
    SITE="$name"

    TARGETS=()
    local a
    for a in $(kv A "$out" | tr ',' ' ') $(kv AAAA "$out" | tr ',' ' '); do
        TARGETS+=("$a $(family_of "$a")")
    done
    ok "$SITE -> $(printf '%s ' "${TARGETS[@]%% *}")- every A/AAAA record leads to this server"
}

choose_address() {
    local out rc=0 cands previous
    previous="$(env_get PANEL_SITE)"
    case "$(env_get PANEL_MODE)" in ip|selfsigned) ;; *) previous="" ;; esac
    step "This server's public address"
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
EXT_PORT_STATE="" # reachable | skipped
PROBE_CONTAINER="auditdsec-probe-listen"
STOPPED_OWN=()    # this installation's containers stopped for the checks
STACK_STARTED=no

setup_probe() {
    PROBE_URL="${PROBE_URL:-$(env_get PANEL_PROBE_URL)}"
    PROBE_TOKEN_FILE="${PROBE_TOKEN_FILE:-$(env_get PANEL_PROBE_TOKEN_FILE)}"
    PROBE_CACERT="${PROBE_CACERT:-$(env_get PANEL_PROBE_CACERT)}"
    [ "$MODE" = tunnel ] && return 0
    if [ "$NO_EXTERNAL" = yes ]; then
        warn "--no-external-check: whether the internet reaches the panel will NOT be known; it is not reported as published."
        return 0
    fi
    if [ -z "$PROBE_URL" ] && interactive; then
        cat <<EOF

${B}Check from outside${N}
A check made from this server proves nothing about the internet: a cloud
firewall, NAT or the provider's security group are only seen from outside.
The installer asks a RemoteProbe provider to connect here: cmd/auditdsec-probe,
running on ANOTHER machine you control (see docs/PANEL.md). No public service
is assumed and no secret is sent anywhere else.

EOF
        PROBE_URL="$(ask "RemoteProbe URL (https://..., empty if you have none)" "")"
        if [ -n "$PROBE_URL" ] && [ -z "$PROBE_TOKEN_FILE" ]; then
            PROBE_TOKEN_FILE="$(ask "File with its token (kept here, only its path is saved)" "")"
        fi
    fi
    if [ -z "$PROBE_URL" ] || [ -z "$PROBE_TOKEN_FILE" ]; then
        abort external_check_unavailable "${SITE:-this server}" \
            "looking for a RemoteProbe provider (--probe-url and --probe-token-file)" \
            "no provider is configured, so whether the panel can be reached from the internet cannot be checked" \
            "run cmd/auditdsec-probe on another machine (docs/PANEL.md, 'Проверка снаружи') and pass --probe-url and --probe-token-file. Or pass --no-external-check: the panel is then started but not reported as published."
    fi
    [ -r "$PROBE_TOKEN_FILE" ] || die "cannot read the probe token file $PROBE_TOKEN_FILE"
    PROBE_TOKEN_FILE="$(readlink -f "$PROBE_TOKEN_FILE")"
    if [ -n "$PROBE_CACERT" ]; then
        [ -r "$PROBE_CACERT" ] || die "cannot read $PROBE_CACERT"
        PROBE_CACERT="$(readlink -f "$PROBE_CACERT")"
    fi
}

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
    out="$(agent "${args[@]}" 2>/dev/null || true)"
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
        "$IMAGE_TAG" probe-listen -port "$port" -ttl 3m >/dev/null 2>&1 || return 1
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

# try_port PORT — 0 when the port is free here and reached from outside.
# 1: this port does not work (TRIED gets the reason). 2: the check itself
# failed, which another port would not fix.
try_port() {
    local p="$1" why
    why="$(reserved_port "$p")"
    if [ -n "$why" ]; then TRIED+=("$p: $why"); LAST_PORT_CODE=port_in_use; return 1; fi
    if ! bind_check "$p"; then
        TRIED+=("$p: in use on this server ($BIND_REASON)"); LAST_PORT_CODE=port_in_use
        return 1
    fi
    if [ "$NO_EXTERNAL" = yes ] || [ "$MODE" = tunnel ]; then return 0; fi
    local rc=0
    reach_from_outside "$p" || rc=$?
    case "$rc" in
        0) return 0 ;;
        1) TRIED+=("$p: $EXT_REASON")
           case "$EXT_REASON" in port_in_use*) LAST_PORT_CODE=port_in_use ;; *) LAST_PORT_CODE=external_port_unreachable ;; esac
           return 1 ;;
        *) return 2 ;;
    esac
}

LAST_PORT_CODE=""

select_port() {
    case "$MODE" in tunnel) return 0 ;; esac
    local previous
    previous="$(env_get PANEL_HTTPS_PORT)"
    if [ -z "$HTTPS_PORT" ]; then
        if [ -n "$previous" ] && [ "$(env_get PANEL_MODE)" = "$MODE" ]; then
            HTTPS_PORT="$previous"
            interactive && ! confirm "Keep the panel on port $previous?" && HTTPS_PORT=""
        elif [ "$PREVIOUS_INSTALL" = yes ] && [ -z "$previous" ] && [ -n "$(env_get PANEL_MODE)" ] && [ "$(env_get PANEL_MODE)" != tunnel ]; then
            HTTPS_PORT=443   # set up before the port was a choice: it was 443
        fi
    fi
    if [ -z "$HTTPS_PORT" ]; then
        if interactive; then
            cat <<EOF

${B}Panel port${N}
This is the public HTTPS port in the link. 443 lets the link go without a
port; another port works just as well, and the certificate is the same.

  1) Pick automatically: 443 if it is free and reachable, else a random high port
  2) I will give the port

EOF
            case "$(ask "Choose 1 or 2" 1)" in
                1|auto) HTTPS_PORT=auto ;;
                2) HTTPS_PORT="$(ask "Port (1-65535)" "")" ;;
                *) die "pick 1 or 2" ;;
            esac
        else
            HTTPS_PORT=auto
        fi
    fi

    release_own
    step "Choosing the panel's public port"
    if [ "$HTTPS_PORT" != auto ]; then
        HTTPS_SOURCE=manual
        case "$HTTPS_PORT" in ''|*[!0-9]*) die "the port must be a number from 1 to 65535" ;; esac
        [ "$HTTPS_PORT" -ge 1 ] && [ "$HTTPS_PORT" -le 65535 ] || die "the port must be a number from 1 to 65535"
        local rc=0
        try_port "$HTTPS_PORT" || rc=$?
        case "$rc" in
            0) ;;
            1) port_failure "$HTTPS_PORT" ;;
            *) external_unavailable "$(hostport "${TARGETS[0]% *}" "$HTTPS_PORT")" ;;
        esac
    else
        HTTPS_SOURCE=auto
        local lo hi up cands p rc found=no
        up="${PORT:-$(env_get PANEL_UPSTREAM_PORT)}"; up="${up:-$(env_get PANEL_PORT)}"; up="${up:-9477}"
        read -r lo hi < <(port_range)
        cands="$(agent port-plan -first 443 -n 16 -lo "$lo" -hi "$hi" -exclude "80,2019,$up")"
        for p in $cands; do
            rc=0
            try_port "$p" || rc=$?
            case "$rc" in
                0) HTTPS_PORT="$p"; found=yes; break ;;
                1) say "  $p: ${TRIED[${#TRIED[@]}-1]#*: }" ;;
                *) external_unavailable "$(hostport "${TARGETS[0]% *}" "$p")" ;;
            esac
        done
        if [ "$found" = no ]; then
            local list; list="$(printf '%s; ' "${TRIED[@]}")"
            abort "${LAST_PORT_CODE:-external_port_unreachable}" "${SITE}, ports $(printf '%s' "$cands" | tr '\n' ' ')" \
                "443 and $(($(printf '%s\n' "$cands" | wc -l) - 1)) random ports from $lo-$hi: bound here, then reached from outside" \
                "the UI could not be published: none of the checked ports is available (${list%; }). Only these ports were tried, not every port." \
                "open one port for TCP in this server's firewall AND in the provider's firewall / security group, then run again with --https-port THAT_PORT"
        fi
    fi
    if [ "$NO_EXTERNAL" = yes ]; then
        EXT_PORT_STATE=skipped
        ok "port $HTTPS_PORT can be bound here (reachability from outside NOT checked)"
    else
        EXT_PORT_STATE=reachable
        ok "port $HTTPS_PORT: free here and reached from outside on $(printf '%s ' "${TARGETS[@]%% *}")"
    fi
}

port_range() {
    local lo="$PORT_RANGE_LO" hi="$PORT_RANGE_HI"
    [ -n "$lo" ] || lo=20000
    [ -n "$hi" ] || hi=29999
    printf '%s %s\n' "$lo" "$hi"
}

port_failure() {
    local p="$1" last="${TRIED[${#TRIED[@]}-1]#*: }"
    case "$LAST_PORT_CODE" in
        port_in_use)
            abort port_in_use "$(hostport "${TARGETS[0]% *}" "$p")" \
                "binding TCP port $p on all IPv4 and IPv6 addresses of this server" \
                "$last" \
                "free the port or choose another one with --https-port N (or --https-port auto). Nothing that holds it was stopped." ;;
        *)
            abort external_port_unreachable "$(hostport "${TARGETS[0]% *}" "$p")" \
                "a temporary listener on $p, fetched from outside by the RemoteProbe provider" \
                "port $p is free here, but the outside check did not reach it: $last" \
                "allow TCP $p in this server's firewall (e.g. ufw allow $p/tcp) and in the provider's firewall / security group; check NAT port forwarding. A timeout does not say which of them drops it. Then run again." ;;
    esac
}

external_unavailable() {
    abort external_check_unavailable "$1" \
        "asking the RemoteProbe provider $PROBE_URL to connect" \
        "the provider could not be used: $EXT_REASON. This says nothing about the port itself." \
        "make sure the provider runs, its URL and token are right (--probe-url, --probe-token-file, --probe-cacert), then run again"
}

# ----------------------------------------------- 5. certificate needs ------

ACME_PORT_STATE=""

# check_challenge makes sure the CA can reach this server to validate it.
# A certificate is bound to the name or address, not to a port, but proving
# control of it needs port 80 (HTTP-01) or 443 (TLS-ALPN-01), whatever port
# the panel itself uses.
check_challenge() {
    case "$MODE" in domain|ip) ;; *) return 0 ;; esac
    step "What the certificate needs"
    local alpn=no
    # Caddy answers TLS-ALPN-01 only when the panel itself is on 443.
    [ "$MODE" = domain ] && [ "$HTTPS_PORT" = 443 ] && alpn=yes

    # Port 80 must be free here even with TLS-ALPN: Caddy binds it for the
    # HTTP-01 challenge and the redirect, and certbot for HTTP-01.
    if ! bind_check 80; then
        abort acme_challenge_unreachable "$(hostport "${TARGETS[0]% *}" 80)" \
            "binding port 80, where Let's Encrypt sends the HTTP-01 challenge" \
            "port 80 is used by another program ($BIND_REASON)" \
            "this installer does not stop another web server, and does not route the challenge through one. Free port 80 (or move that site), or put the panel on a domain served by that web server yourself. DNS-01 is not supported by this installer yet."
    fi
    if [ "$NO_EXTERNAL" = yes ]; then
        ACME_PORT_STATE="port 80 free here; reachability from outside NOT checked"
        say "$ACME_PORT_STATE"
        return 0
    fi
    local rc=0
    reach_from_outside 80 || rc=$?
    case "$rc" in
        0) ACME_PORT_STATE="port 80 reached from outside (HTTP-01)"; ok "$ACME_PORT_STATE"; return 0 ;;
        2) external_unavailable "$(hostport "${TARGETS[0]% *}" 80)" ;;
    esac
    if [ "$alpn" = yes ]; then
        ACME_PORT_STATE="port 80 NOT reached from outside; Caddy uses TLS-ALPN-01 on 443 instead"
        warn "$ACME_PORT_STATE ($EXT_REASON). http:// links will not redirect."
        return 0
    fi
    local need="80"
    [ "$MODE" = ip ] && need="80 (certificates for an IP address are validated over HTTP-01 on port 80 only; DNS-01 cannot apply to an address)"
    abort acme_challenge_unreachable "$(hostport "${TARGETS[0]% *}" 80)" \
        "a temporary listener on port 80, fetched from outside by the RemoteProbe provider" \
        "Let's Encrypt could not validate this ${MODE/ip/address}: port 80 is not reached from outside ($EXT_REASON). The panel port $HTTPS_PORT being open does not help: the CA only connects to 80 or 443." \
        "allow TCP $need in this server's firewall and in the provider's firewall, or choose port 443 for the panel on a domain (TLS-ALPN-01). Then run again."
}

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
    cat <<EOF

${B}Telegram${N}
The agent needs a bot before it will start: that is where the alerts go, and
the panel is an addition to it, not a replacement. Make one with @BotFather,
then write to your bot and read the chat id from
https://api.telegram.org/bot<TOKEN>/getUpdates

EOF
    if ! interactive; then
        die "AUDITDSEC_TG_TOKEN and AUDITDSEC_TG_CHAT_ID must be in $ENV_FILE"
    fi
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
    step "Writing $ENV_FILE"
    [ -f "$ENV_FILE" ] || { : > "$ENV_FILE"; chmod 0600 "$ENV_FILE"; }

    # PANEL_PORT was the agent's loopback port all along; it is now called
    # PANEL_UPSTREAM_PORT so it cannot be mistaken for the public one.
    PORT="${PORT:-$(env_get PANEL_UPSTREAM_PORT)}"
    PORT="${PORT:-$(env_get PANEL_PORT)}"
    PORT="${PORT:-9477}"
    case "$PORT" in ''|*[!0-9]*) die "the upstream port must be a number" ;; esac
    [ "$PORT_DEPRECATED" = no ] || warn "--port is the old name of --upstream-port: the agent's loopback port, not the public one."

    env_set PANEL_MODE "$MODE"
    env_set PANEL_ENFORCE "$ENFORCE"
    env_set PANEL_UPSTREAM_PORT "$PORT"
    env_unset PANEL_PORT
    env_set AUDITDSEC_WEB 1
    env_set AUDITDSEC_WEB_LOGIN "$LOGIN"
    if [ "$ENFORCE" = yes ]; then env_set AUDITDSEC_BAN_BACKEND nftables; else env_unset AUDITDSEC_BAN_BACKEND; fi

    # Settings that depend on how the panel is published. The overlay files
    # set the same keys themselves, so .env must not carry a stale value left
    # over from an earlier choice.
    local k
    for k in PANEL_DOMAIN PANEL_CADDYFILE PANEL_SITE PANEL_SITE_ADDR PANEL_EMAIL PANEL_HTTPS_PORT \
             PANEL_PUBLIC_URL AUDITDSEC_WEB_LISTEN AUDITDSEC_WEB_PUBLIC_URL PANEL_ACME PANEL_ACME_URL \
             PANEL_ACME_SUFFIX PANEL_HSTS PANEL_ACME_CA_ROOT; do
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
    step "Hashing the password"
    local hash errfile
    errfile="$(mktemp)"
    if ! hash="$(printf '%s\n' "$PASSWORD" | $DOCKER run --rm -i "$IMAGE_TAG" hash-password -stdin 2>"$errfile")"; then
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
    step "Certificate for $SITE (Let's Encrypt $ACME)"

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
    step "Starting"
    hash_password || { report bootstrap_persistence_failed "$ENV_FILE" "hashing the password from --password-file" "the agent refused it" "use a password the panel accepts (8+ characters, a lower-case and an upper-case letter)"; return 1; }
    issue_ip_certificate || return 1
    if [ "$DO_START" != yes ]; then say "(--no-start: not starting)"; return 0; fi
    local up=(up -d --remove-orphans)
    [ "$NO_BUILD" = yes ] && up+=(--no-build)
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
    TARGETS=()
    [ -z "$SITE" ] || [ "$MODE" = domain ] || TARGETS=("$SITE $(family_of "$SITE")")
    compute_panel_url
    build_compose_files
}

# restore_last_good puts the last verified configuration back and starts it.
# The failed one is kept beside it as .env.failed for diagnosis; no volume is
# touched, so certificates and stored events are exactly as they were.
restore_last_good() {
    [ -s "$LAST_GOOD" ] || return 1
    step "Restoring the last configuration that was verified working"
    if [ -f "$ENV_FILE" ]; then
        cp "$ENV_FILE" "${ENV_FILE}.failed"
        chmod 0600 "${ENV_FILE}.failed"
    fi
    cp "$LAST_GOOD" "$ENV_FILE"
    chmod 0600 "$ENV_FILE"
    load_state_from_env
    local up=(up -d --remove-orphans)
    [ "$NO_BUILD" = yes ] && up+=(--no-build)
    compose "${up[@]}" || { warn "could not start the previous configuration either"; return 1; }
    STACK_STARTED=yes
    STOPPED_OWN=()
    RESTORED=yes
    ok "started again: mode $MODE${SITE:+, $SITE}${ACME:+, $ACME}"
}

# --------------------------------------------------------------- cleanup ---

CA_TMP=""

cleanup() {
    [ -z "$CA_TMP" ] || rm -f "$CA_TMP"
    stop_listener 2>/dev/null || true
    unset AUDITDSEC_PROBE_TOKEN 2>/dev/null || true
    # This run stopped the installation's own proxy for the port checks and
    # then failed before starting anything: put it back as it was.
    if [ "$STACK_STARTED" = no ] && [ ${#STOPPED_OWN[@]} -gt 0 ]; then
        $DOCKER start "${STOPPED_OWN[@]}" >/dev/null 2>&1 \
            && printf 'The previous proxy (%s) was started again.\n' "${STOPPED_OWN[*]}" >&2 || true
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
PUBLISHED=no
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
    step "Checking that the panel actually answers"

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
            *'"token"'*) LOGIN_STATE="signed in with the password from --password-file"; ok "$LOGIN_STATE, $LOGIN_ROUTE" ;;
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

    external_tls_check || {
        local erc=$?
        [ "$erc" -le "$soft" ] || soft="$erc"
    }

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

# external_tls_check: the final check, from outside, on the real port and
# with certificate verification. 0 published, 1 not reachable (the setup does
# not work), 2 reachable but not verifiable or the check could not run.
external_tls_check() {
    case "$MODE" in tunnel) EXT_TLS_STATE="not applicable (tunnel)"; return 0 ;; esac
    if [ "$NO_EXTERNAL" = yes ]; then
        EXT_TLS_STATE="NOT checked (--no-external-check)"
        return 0
    fi
    if [ ${#TARGETS[@]} -eq 0 ]; then
        EXT_TLS_STATE="NOT checked (the addresses to check are not known in this run)"
        return 0
    fi
    step "Checking the panel from outside"
    local t addr fam worst=0
    for t in "${TARGETS[@]}"; do
        addr="${t% *}"; fam="${t#* }"
        remote_check tls "$addr" "$HTTPS_PORT" "$fam"
        case "$RC_RESULT" in
            reachable)
                [ -z "$RC_NOT_AFTER" ] || NOT_AFTER="$RC_NOT_AFTER"
                if [ "$RC_TLS_VERIFIED" = yes ]; then
                    ok "$(hostport "$addr" "$HTTPS_PORT"): reached from outside, certificate verified (valid until ${RC_NOT_AFTER:-?})"
                elif [ "$MODE" = selfsigned ] || [ "$ACME" = staging ]; then
                    ok "$(hostport "$addr" "$HTTPS_PORT"): reached from outside; the certificate is not publicly trusted, as expected for $([ "$MODE" = selfsigned ] && echo 'a self-signed setup' || echo 'staging')"
                else
                    report tls_validation_failed "$(hostport "$addr" "$HTTPS_PORT")" \
                        "TLS handshake from the RemoteProbe provider, verifying the chain for $SITE" \
                        "the panel answers, but its certificate does not verify from outside: ${RC_TLS_ERROR:-unknown reason}" \
                        "make sure the certificate was issued by the production CA for $SITE (logs: $(compose_prefix) logs caddy$([ "$MODE" = ip ] && echo ' certbot')), then run again"
                    [ "$worst" -ge 2 ] || worst=2
                fi ;;
            refused|timeout|wrong_endpoint)
                report external_port_unreachable "$(hostport "$addr" "$HTTPS_PORT")" \
                    "HTTPS request from the RemoteProbe provider to the started panel" \
                    "$RC_RESULT${RC_DETAIL:+: $RC_DETAIL}. The same port was reached by the temporary listener a moment ago." \
                    "look at: $(compose_prefix) logs --tail 40 caddy (the proxy may have failed to bind the port), and at firewall rules changed in the meantime"
                worst=1 ;;
            *)
                EXT_REASON="${RC_DETAIL:-no answer}"
                report external_check_unavailable "$(hostport "$addr" "$HTTPS_PORT")" \
                    "asking the RemoteProbe provider $PROBE_URL" "${RC_DETAIL:-the provider did not answer}" \
                    "check the provider and run again; the panel is running but is not reported as published"
                [ "$worst" -ge 2 ] || worst=2 ;;
        esac
    done
    case "$worst" in
        0) if [ "$MODE" = selfsigned ] || [ "$ACME" = staging ]; then
               EXT_TLS_STATE="reached from outside (certificate not publicly trusted)"
           else
               EXT_TLS_STATE="reached from outside over verified TLS"
           fi ;;
        1) EXT_TLS_STATE="NOT reached from outside" ;;
        *) EXT_TLS_STATE="NOT verified from outside" ;;
    esac
    return "$worst"
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

decide_published() {
    PUBLISHED=no
    [ "$DO_START" = yes ] && [ "$DO_VERIFY" = yes ] || return 0
    [ "$RESTORED" = no ] && [ -z "$FAIL_CODE" ] || return 0
    case "$MODE" in domain|ip) ;; *) return 0 ;; esac
    [ "$ACME" = production ] && [ "$NO_EXTERNAL" = no ] && [ "$TLS_UNTRUSTED" = no ] && [ "$RELOAD_PROBLEM" = no ] || return 0
    [ "$EXT_TLS_STATE" = "reached from outside over verified TLS" ] || return 0
    PUBLISHED=yes
}

summary() {
    local line
    decide_published
    line="$(printf '%*s' 70 '' | tr ' ' '-')"
    printf '\n%s\n' "$line"
    if [ "$RESTORED" = yes ] && [ "$RESTORE" = yes ]; then
        printf '%sThe last verified configuration is running again.%s\n' "$B" "$N"
    elif [ "$RESTORED" = yes ]; then
        printf '%sThe new settings did not work; the previous ones are running again.%s\n' "$R$B" "$N"
    elif [ "$PUBLISHED" = yes ] && [ "$SETUP_STATE" = bootstrap ]; then
        printf '%sThe panel is published and waits for first-time setup.%s\n' "$G$B" "$N"
    elif [ "$PUBLISHED" = yes ]; then
        printf '%sThe panel is published.%s\n' "$G$B" "$N"
    elif [ -n "$FAIL_CODE" ]; then
        printf '%sNOT published: %s%s\n' "$R$B" "$FAIL_CODE" "$N"
    elif [ "$DO_START" != yes ]; then
        printf '%sConfigured, not started (--no-start). Not published.%s\n' "$B" "$N"
    elif [ "$DO_VERIFY" != yes ]; then
        printf '%sStarted, not checked (--no-verify). Not reported as published.%s\n' "$Y$B" "$N"
    elif [ "$MODE" = tunnel ]; then
        printf '%sThe panel is up on this server'"'"'s loopback (SSH tunnel mode).%s\n' "$G$B" "$N"
    elif [ "$ACME" = staging ]; then
        printf '%sStarted on the Let'"'"'s Encrypt STAGING CA: a dry run, not published.%s\n' "$Y$B" "$N"
    elif [ "$MODE" = selfsigned ]; then
        printf '%sStarted with a self-signed certificate: every browser warns. Not published.%s\n' "$Y$B" "$N"
    elif [ "$NO_EXTERNAL" = yes ]; then
        printf '%sStarted, but NOT verified from outside (--no-external-check). Not published.%s\n' "$Y$B" "$N"
    else
        printf '%sStarted, but not published.%s\n' "$Y$B" "$N"
    fi
    printf '%s\n\n' "$line"

    if [ -n "$FAIL_REASON" ]; then
        printf '  What went wrong: %s\n' "$FAIL_REASON"
        [ "$RESTORED" != yes ] || printf '  The failed settings are in %s.failed (same permissions as %s).\n' "$ENV_FILE" "$ENV_FILE"
        printf '  Run again after fixing it: %s\n\n' "$(retry_command)"
    fi

    printf '  Page:      %s\n' "${PAGE_STATE:-not checked}"
    printf '  Sign-in:   %s\n' "${LOGIN_STATE:-not checked}"
    [ -z "$LOGIN_ROUTE" ] || printf '             sent %s\n' "$LOGIN_ROUTE"
    if [ "$MODE" != tunnel ]; then
        printf '  Port:      %s (%s)\n' "$HTTPS_PORT" "$([ "$HTTPS_SOURCE" = manual ] && echo 'given by you' || { [ "$HTTPS_SOURCE" = auto ] && echo 'picked automatically' || echo 'kept'; })"
        printf '  Outside:   port %s; panel %s\n' "${EXT_PORT_STATE:-not checked}" "${EXT_TLS_STATE:-not checked}"
        [ -z "$ACME_PORT_STATE" ] || printf '  Challenge: %s\n' "$ACME_PORT_STATE"
        printf '  TLS:       %s\n' "${TLS_STATE:-not checked}"
        [ -z "$NOT_AFTER" ] || printf '  Expires:   %s\n' "$NOT_AFTER"
    fi
    [ -z "$RENEW_STATE" ] || printf '  Renewal:   %s\n' "$RENEW_STATE"
    case "$MODE" in
        domain) printf '             Caddy renews the certificate itself, about 30 days before it ends.\n' ;;
        ip)     printf '             Address certificates last about 6 days; the certbot container renews them\n'
                printf '             and checks every minute that port %s serves the file on disk. Port 80\n' "$HTTPS_PORT"
                printf '             must stay open and unused for the renewals.\n' ;;
        selfsigned)
                printf '  Trust:     each browser warns. Compare the fingerprint it shows with:\n'
                printf '               printf "" | openssl s_client -connect %s 2>/dev/null | openssl x509 -noout -fingerprint -sha256\n' "$(hostport "$SITE" "$HTTPS_PORT")" ;;
    esac
    if [ "$ACME" = staging ] && [ "$RESTORED" != yes ]; then
        printf '\n  %sSTAGING.%s Browsers do not trust this certificate, on purpose. Switch with:\n' "$Y$B" "$N"
        printf '    ./install.sh --production     (nothing is deleted)\n'
    fi

    printf '\n  Diagnostics:\n'
    printf '    %s ps\n' "$(compose_prefix)"
    printf '    %s logs --tail 80 auditdsec\n' "$(compose_prefix)"
    case "$MODE" in domain|ip|selfsigned) printf '    %s logs --tail 40 caddy\n' "$(compose_prefix)" ;; esac
    [ "$MODE" != ip ] || printf '    %s exec certbot python3 /hooks/certtool.py status\n' "$(compose_prefix)"
    printf '  Run ./install.sh again to change anything: data, certificates and credentials are kept.\n'
    [ ! -s "$LAST_GOOD" ] || printf '  Back to the last verified configuration: ./install.sh --restore\n'

    # The sign-in and the link come last, so they are what stays on screen.
    printf '\n'
    if [ "$SETUP_STATE" = bootstrap ] && [ "$RESTORED" != yes ] && [ "$DO_START" = yes ]; then
        printf '  First login:  %sadmin%s / %sadmin%s\n' "$B" "$N" "$B" "$N"
        printf '                It opens only the mandatory setup screen: choose your login (or tick\n'
        printf '                "keep admin") and a password of 8+ characters with a lower-case and an\n'
        printf '                upper-case letter. Do it now: whoever signs in first can choose them.\n'
    elif [ "$SETUP_STATE" = ready ] || [ -n "$(env_get AUDITDSEC_WEB_PASSWORD_HASH)" ]; then
        printf '  Sign in with the login and password you chose (admin / admin no longer works).\n'
    fi
    if [ "$MODE" = tunnel ]; then
        printf '  On your computer, run and leave open:  %s\n' "$(ssh_command)"
    fi
    if [ "$PUBLISHED" = yes ] || [ "$MODE" = tunnel ] || [ "$RESTORED" = yes ]; then
        printf '  Link: %s%s%s\n' "$B" "$PANEL_URL" "$N"
    else
        printf '  Link (NOT published): %s\n' "$PANEL_URL"
    fi
    printf '%s\n' "$line"
}

# -------------------------------------------------------------------- main ---

exit_status() {
    if [ -n "$FAIL_CODE" ]; then code_status "$FAIL_CODE"; else echo "${1:-0}"; fi
}

main() {
    if [ "$RESTORE" = yes ]; then
        preflight_light
        [ -s "$LAST_GOOD" ] || die "there is no verified configuration to go back to ($LAST_GOOD)"
        restore_last_good || die "the previous configuration would not start"
        NO_EXTERNAL=yes   # the restored setup was verified when it was saved
        [ -z "$PROBE_URL" ] || [ -z "$PROBE_TOKEN_FILE" ] || [ ! -r "$PROBE_TOKEN_FILE" ] || NO_EXTERNAL=no
        local rrc=0
        verify_stack || rrc=$?
        summary
        return "$(exit_status "$rrc")"
    fi

    preflight
    choose_mode                       # 2. domain or IP
    ask_site                          # 3. DNS or the address
    setup_probe
    select_port                       # 4. the public port, checked from outside
    check_challenge                   # 5. what the certificate needs
    ask_email
    settle_acme
    ask_telegram
    ask_login
    ask_enforce
    ask_password

    write_config                      # 6. configure and start
    build_compose_files

    local vrc=0 started=yes
    if ! start_stack; then
        started=no
        [ -n "$FAIL_CODE" ] || report service_start_failed "$(compose_prefix)" "starting the stack" "it did not start" "see the messages above"
    else
        verify_stack || vrc=$?
    fi

    # The new settings do not work. When there is a configuration that did,
    # put it back rather than leave a person with nothing; the failed one is
    # kept for diagnosis.
    if [ "$started" = no ] || [ "$vrc" = 1 ]; then
        if [ -s "$LAST_GOOD" ] && ! cmp -s "$ENV_FILE" "$LAST_GOOD"; then
            local code="$FAIL_CODE" reason="$FAIL_REASON"
            if restore_last_good; then
                TLS_UNTRUSTED=no; LOGIN_STATE=""; LOGIN_ROUTE=""; TLS_STATE=""; RENEW_STATE=""; RELOAD_PROBLEM=no
                PAGE_STATE=""; PASSWORD=""; EXT_TLS_STATE=""; NO_EXTERNAL=yes
                verify_stack || true
                FAIL_CODE="$code"; FAIL_REASON="$reason"
            fi
        else
            say ""
            say "There is no earlier working configuration to go back to."
        fi
        summary
        return "$(exit_status 1)"
    fi

    if [ "$DO_START" = yes ] && [ "$DO_VERIFY" = yes ] && [ "$vrc" = 0 ] && [ -z "$FAIL_CODE" ]; then
        save_last_good
    fi
    summary
    return "$(exit_status "$vrc")"
}

# preflight_light is what --restore needs: Docker, and nothing built.
preflight_light() {
    command -v "${DOCKER%% *}" >/dev/null 2>&1 || die "$DOCKER is not installed"
    $DOCKER info >/dev/null 2>&1 || die "cannot talk to the Docker daemon"
}

main
