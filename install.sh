#!/usr/bin/env bash
#
# auditdsec — set up the agent and the web panel.
#
#   ./install.sh
#
# Asks where the panel should be opened (a domain or this server's public
# IP address) and on which HTTPS port, checks DNS and the port, checks from a
# machine outside that the world can reach it, gets a trusted certificate,
# starts everything and prints the link only after the checks passed.
#
# Running it again keeps what is already configured: the password, the
# Telegram token, the stored events and the certificates. Answer the
# questions again only for what you want to change.
#
# Everything can also be given on the command line, which is what the test
# harness does; see --help.

set -euo pipefail

cd "$(dirname "$0")"

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
PORT_RANGE_LO="${PANEL_PORT_RANGE_LO:-20000}"
PORT_RANGE_HI="${PANEL_PORT_RANGE_HI:-29999}"

LE_PRODUCTION="https://acme-v02.api.letsencrypt.org/directory"
LE_STAGING="https://acme-staging-v02.api.letsencrypt.org/directory"

# --------------------------------------------------------------- utilities --

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    B=$'\033[1m'; DIM=$'\033[2m'; R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; N=$'\033[0m'
else
    B=""; DIM=""; R=""; G=""; Y=""; N=""
fi

say()  { printf '%s\n' "$*"; }
step() { printf '\n%s==>%s %s\n' "$B" "$N" "$*"; }
warn() { printf '%s!%s  %s\n' "$Y" "$N" "$*" >&2; }
die()  { printf '%serror:%s %s\n' "$R" "$N" "$*" >&2; exit 1; }
ok()   { printf '%s/%s  %s\n' "$G" "$N" "$*"; }

usage() {
    cat <<'EOF'
Usage: ./install.sh [options]

With no options it asks what it needs. Options are for scripts and tests.

  --mode domain|ip|selfsigned|tunnel   how the panel is reached
  --site NAME|ADDRESS                  domain (domain mode) or address (ip, selfsigned)
  --email ADDRESS                      where Let's Encrypt sends expiry warnings
  --login NAME                         panel login name (default: admin)
  --https-port N|auto                  the PUBLIC HTTPS port of the panel (default: auto: 443,
                                       then up to 16 random high ports). A port you give is
                                       never replaced silently.
  --upstream-port N                    the agent's own port on loopback (default: 9477)
  --port N                             old name of --upstream-port (it was never the public port)
  --public-ip ADDRESS                  this server's public address, if it cannot be found
  --probe-url URL                      a RemoteProbe provider: a service running on ANOTHER
                                       machine that connects to this server from outside
  --probe-token-file PATH              file with that provider's token
  --probe-cacert FILE                  CA file for the provider's own certificate
  --no-external-check                  skip the check from outside. A technical mode: nothing
                                       is then reported as published and ready.
  --password-file PATH                 read the panel password from this file
  --enforce / --no-enforce             apply bans with nftables, or only record them
  --staging                            Let's Encrypt staging CA: a dry run whose certificates
                                       no browser trusts. Kept apart from production.
  --production                         the real Let's Encrypt CA. This is also the way out of
                                       --staging; nothing is deleted on the way.
  --cacert FILE                        verify the panel's certificate against this CA instead
                                       of the system store (for a staging or private CA)
  --restore                            put back the last configuration that was verified working
  --no-build                           do not build the image; use the one that exists
  --yes                                do not ask anything that has an answer already
  --no-start                           write the configuration and stop
  --no-verify                          start, but skip checking the panel answers
  -h, --help                           this text

The password is only ever sent to the panel over a connection whose certificate
was verified. When it cannot be verified (staging, an unknown CA) it is sent to
the agent on this machine's loopback address instead, and the summary says so.

The modes:

  domain      a domain pointing at this server. A certificate from Let's
              Encrypt, no browser warning. Needs ports 80 and 443.
  ip          this server's public address. Let's Encrypt certifies public
              addresses under its shortlived profile: about six days per
              certificate, renewed for you. Needs ports 80 and 443.
  selfsigned  a certificate the proxy issues itself. Encrypted, but every
              browser warns, and nothing tells that warning apart from a real
              attack. Only when the two above are impossible.
  tunnel      no port open at all. The panel listens on the server's loopback
              address and you reach it over `ssh -L`.
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

confirm_no() {
    local prompt="$1" reply=""
    interactive || return 1
    read -r -p "$prompt [y/N]: " reply </dev/tty || true
    case "$reply" in [yY]*) return 0 ;; *) return 1 ;; esac
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

# ------------------------------------------------------------------ checks --

require_docker() {
    command -v "${DOCKER%% *}" >/dev/null 2>&1 || die "$DOCKER is not installed"
    $DOCKER compose version >/dev/null 2>&1 || die "'$DOCKER compose' does not work; install the Compose plugin"
    $DOCKER info >/dev/null 2>&1 || die "cannot talk to the Docker daemon; is it running, and are you root?"
}

# ------------------------------------------------------------------ asking --

# cfg NAME — the value from the environment of this run, else from .env. Used
# for the few settings (a private ACME server) that are given once and then
# remembered.
cfg() {
    local v="${!1:-}"
    [ -n "$v" ] || v="$(env_get "$1")"
    printf '%s' "$v"
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

valid_mode() { case "$1" in domain|ip|selfsigned|tunnel) return 0 ;; *) return 1 ;; esac; }

choose_mode() {
    if [ -n "$MODE" ]; then
        valid_mode "$MODE" || die "unknown mode '$MODE': use domain, ip, selfsigned or tunnel"
        return 0
    fi
    local previous
    previous="$(env_get PANEL_MODE)"
    if ! interactive; then
        MODE="${previous:-tunnel}"
        return 0
    fi
    cat <<EOF

${B}How should the panel be reachable?${N}

  1) A domain name pointing at this server
     Real certificate, no browser warning. Needs ports 80 and 443 open.

  2) This server's public IP address
     Also a real certificate: Let's Encrypt certifies public addresses, with
     a six-day lifetime that is renewed for you. Needs ports 80 and 443 open.

  3) Only through an SSH tunnel
     Nothing is open to the internet. You run
     ssh -L 9477:127.0.0.1:9477 <server> and open it locally. Safest, and
     the least convenient.

  4) A certificate the server signs itself
     ${DIM}For when none of the above fit: a private address, or port 80 closed.
     Encrypted, but every browser warns, and that warning looks exactly like
     the one a real attack would cause.${N}

EOF
    local default=1 reply
    case "$previous" in domain) default=1 ;; ip) default=2 ;; tunnel) default=3 ;; selfsigned) default=4 ;; esac
    reply="$(ask "Choose 1-4" "$default")"
    case "$reply" in
        1|domain) MODE=domain ;;
        2|ip) MODE=ip ;;
        3|tunnel) MODE=tunnel ;;
        4|selfsigned) MODE=selfsigned ;;
        *) die "pick 1, 2, 3 or 4" ;;
    esac
}

ask_site() {
    case "$MODE" in tunnel) return 0 ;; esac
    local previous want
    previous="${SITE:-$(env_get PANEL_SITE)}"
    [ -n "$previous" ] || previous="$(env_get PANEL_DOMAIN)"   # the old name
    case "$MODE" in
        domain) want="Domain name for the panel (e.g. panel.example.com)" ;;
        ip)     want="This server's public address" ;;
        *)      want="Address or name to serve the panel on" ;;
    esac
    SITE="$(ask "$want" "$previous")"
    [ -n "$SITE" ] || die "a domain or address is required for this mode"
    SITE="${SITE#[}"; SITE="${SITE%]}"   # an IPv6 address goes in bare

    if [ "$MODE" = domain ] || [ "$MODE" = ip ]; then
        step "Checking $SITE"
        if run_site_check; then
            :
        else
            warn "the check above was not conclusive."
            confirm "Carry on anyway?" || die "stopped; fix the address and run ./install.sh again"
        fi
    fi
}

# run_site_check uses the agent's own check, from the image if it is already
# built and from the source tree otherwise, so it also works before the first
# build.
run_site_check() {
    local args=(check-site "$SITE")
    if $DOCKER image inspect "$IMAGE_TAG" >/dev/null 2>&1; then
        $DOCKER run --rm --network host "$IMAGE_TAG" "${args[@]}"
    elif command -v go >/dev/null 2>&1; then
        go run ./cmd/auditdsec "${args[@]}"
    else
        say "(skipping the check: no image built yet and no Go toolchain)"
        return 0
    fi
}

ask_email() {
    case "$MODE" in domain|ip) ;; *) return 0 ;; esac
    EMAIL="${EMAIL:-$(ask "Email for certificate expiry warnings (optional for an address)" "$(env_get PANEL_EMAIL)")}"
    if [ "$MODE" = domain ] && [ -z "$EMAIL" ]; then
        die "Let's Encrypt needs an address to warn you at"
    fi
}

# ask_acme settles staging or production for the two modes that use Let's
# Encrypt. Nothing is switched silently: an installation that was set up on
# staging stays on staging until --production says otherwise.
ask_acme() {
    case "$MODE" in domain|ip) ;; *) ACME=""; return 0 ;; esac
    local stored
    stored="$(env_get PANEL_ACME)"
    if [ -z "$ACME" ]; then
        if [ -n "$stored" ]; then
            ACME="$stored"
        elif interactive; then
            cat <<EOF

${B}Let's Encrypt: dry run first?${N}
Let's Encrypt has a staging CA for trying this out: the same steps with much
higher limits, but its certificates are not trusted by any browser. The real
CA limits how often you may ask (for addresses: 5 certificates a week), so a
new setup is better tried on staging first. Later, ./install.sh --production
moves to the real one and deletes nothing.

EOF
            if confirm_no "Use the staging CA for this run?"; then ACME=staging; else ACME=production; fi
        else
            ACME=production
        fi
    fi
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
    [ -n "$token" ] || token="$(ask_secret 'Telegram bot token')"
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

ask_enforce() {
    [ -n "$ENFORCE" ] && return 0
    local previous
    previous="$(env_get PANEL_ENFORCE)"
    if ! interactive; then
        ENFORCE="${previous:-no}"
        return 0
    fi
    cat <<EOF

${B}Blocking${N}
The agent can either only write down that an address should be banned, or
actually block it with nftables. Blocking needs NET_ADMIN and the host's
network namespace.

EOF
    if [ "$previous" = yes ]; then
        confirm "Keep applying bans with nftables?" && ENFORCE=yes || ENFORCE=no
    else
        confirm "Apply bans with nftables?" && ENFORCE=yes || ENFORCE=no
    fi
}

# ask_password leaves PASSWORD empty when there is already a hash and the
# person does not want to change it, so a re-run keeps the old one.
ask_password() {
    local existing
    existing="$(env_get AUDITDSEC_WEB_PASSWORD_HASH)"

    if [ -n "$PASSWORD_FILE" ]; then
        [ -r "$PASSWORD_FILE" ] || die "cannot read $PASSWORD_FILE"
        PASSWORD="$(head -n 1 "$PASSWORD_FILE")"
    elif [ -n "$existing" ]; then
        if interactive; then
            if confirm "A panel password is already set. Keep it?"; then
                PASSWORD=""
                return 0
            fi
        else
            PASSWORD=""
            return 0
        fi
    fi

    # Nothing is asked. With no password set the panel opens with the account
    # admin / admin, and that account can do only one thing: replace itself.
    # The first sign-in in the browser makes a person pick a new login and a
    # new password (12+ characters); every other call is refused until then.
    # Pass --password-file to skip that and install your own password.
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

write_config() {
    step "Writing $ENV_FILE"
    [ -f "$ENV_FILE" ] || { : > "$ENV_FILE"; chmod 0600 "$ENV_FILE"; }

    PORT="${PORT:-$(env_get PANEL_PORT)}"
    PORT="${PORT:-9477}"
    case "$PORT" in ''|*[!0-9]*) die "the port must be a number" ;; esac

    env_set PANEL_MODE "$MODE"
    env_set PANEL_ENFORCE "$ENFORCE"
    env_set PANEL_PORT "$PORT"
    env_set AUDITDSEC_WEB 1
    env_set AUDITDSEC_WEB_LOGIN "$LOGIN"
    if [ "$ENFORCE" = yes ]; then env_set AUDITDSEC_BAN_BACKEND nftables; else env_unset AUDITDSEC_BAN_BACKEND; fi

    # Settings that depend on how the panel is published. The overlay files
    # set the same keys themselves, so .env must not carry a stale value left
    # over from an earlier choice.
    env_unset PANEL_DOMAIN           # the old name; PANEL_SITE replaces it
    env_unset PANEL_CADDYFILE
    env_unset PANEL_SITE
    env_unset PANEL_EMAIL
    env_unset AUDITDSEC_WEB_LISTEN
    env_unset AUDITDSEC_WEB_PUBLIC_URL
    env_unset PANEL_ACME
    env_unset PANEL_ACME_URL
    env_unset PANEL_ACME_SUFFIX
    env_unset PANEL_HSTS
    env_unset PANEL_ACME_CA_ROOT

    case "$MODE" in
        domain)
            env_set PANEL_SITE "$SITE"; env_set PANEL_EMAIL "$EMAIL"
            env_set PANEL_CADDYFILE ./deploy/Caddyfile
            PANEL_URL="https://$(url_host "$SITE")"
            ;;
        ip)
            env_set PANEL_SITE "$SITE"
            if [ -n "$EMAIL" ]; then env_set PANEL_EMAIL "$EMAIL"; fi
            env_set PANEL_CADDYFILE ./deploy/Caddyfile.acme-ip
            PANEL_URL="https://$(url_host "$SITE")"
            ;;
        selfsigned)
            env_set PANEL_SITE "$SITE"
            env_set PANEL_CADDYFILE ./deploy/Caddyfile.selfsigned
            PANEL_URL="https://$(url_host "$SITE")"
            ;;
        tunnel)
            PANEL_URL="http://127.0.0.1:$PORT"
            ;;
    esac
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

# port_busy N — something is listening on the port.
port_busy() {
    if command -v ss >/dev/null 2>&1; then
        [ -n "$(ss -H -ltn "sport = :$1" 2>/dev/null)" ]
    else
        (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
    fi
}

# release_port80 gets port 80 free for Let's Encrypt's challenge. The one
# thing that may legitimately hold it is this installation's own proxy from an
# earlier mode: a domain setup keeps port 80 open to redirect to HTTPS, and
# the address setup needs the same port for a few seconds. That proxy is
# stopped, not removed; the next `up` starts the right one again. Anything
# else on port 80 is not ours to stop.
release_port80() {
    port_busy 80 || return 0
    if [ "$($DOCKER inspect -f '{{.State.Running}}' auditdsec-caddy 2>/dev/null || true)" = true ]; then
        say "Port 80 is held by the proxy of the previous setup; stopping it while the"
        say "certificate is issued. It is started again below."
        $DOCKER stop -t 10 auditdsec-caddy >/dev/null 2>&1 || warn "could not stop auditdsec-caddy"
        sleep 1
    fi
    if port_busy 80; then
        warn "port 80 is in use by something that is not this installation's proxy:"
        ss -ltnp 'sport = :80' 2>/dev/null | sed 's/^/    /' >&2 || true
        say "Let's Encrypt validates an address over port 80. Free it, or choose the SSH-tunnel option."
        return 1
    fi
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
        warn "could not inspect the certificate (exit $rc). Is the certbot image available? (CERTBOT_IMAGE)"
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
    [ -n "$version" ] || { warn "cannot run the certbot image; check the network and CERTBOT_IMAGE"; return 1; }
    version_at_least "$version" 5.3 \
        || { warn "certbot $version cannot issue certificates for addresses; 5.3 or newer is needed (set CERTBOT_IMAGE)"; return 1; }

    release_port80 || return 1

    local args=(certonly --standalone --non-interactive --agree-tos
        --server "$ACME_URL" --cert-name panel --preferred-profile shortlived
        --ip-address "$SITE" --deploy-hook /hooks/deploy.sh)
    if [ -n "$EMAIL" ]; then args+=(-m "$EMAIL"); else args+=(--register-unsafely-without-email); fi
    # An existing lineage that is not fit (another address, nearly expired) has
    # to be replaced even though certbot would call it "not yet due".
    if compose run --rm --no-deps -T --entrypoint sh certbot -c 'test -s /etc/letsencrypt/renewal/panel.conf' >/dev/null 2>&1; then
        args+=(--force-renewal)
    fi

    say "Let's Encrypt ($ACME) will connect to port 80 on this address. Nothing else may be using it."
    # PANEL_NO_RELOAD: the proxy is not running yet, so the hook only copies.
    if compose run --rm --no-deps -T -e PANEL_NO_RELOAD=1 --entrypoint certbot certbot "${args[@]}"; then
        :
    else
        cat >&2 <<EOT

${R}The certificate was not issued.${N} The usual reasons, in order of likelihood:
  - port 80 is not reachable from the internet at $SITE
    (a firewall, the provider's security group, or something else listening)
  - $SITE is not this server's public address
  - the CA's limit was reached (production: 5 certificates per address per week);
    try --staging to test the rest without spending it
Nothing else needs redoing: fix that and run ./install.sh again.
EOT
        return 1
    fi

    if reasons="$(certtool check --cert /certs/fullchain.pem --key /certs/privkey.pem \
            --site "$SITE" --acme "$ACME" --directory "$ACME_URL" --meta /certs/meta.json 2>/dev/null)"; then
        ok "certificate issued and checked: this address, valid, key matches"
    else
        warn "certbot reported success, but the certificate in place is not fit:"
        printf '%s\n' "$reasons" | sed 's/^/  - /' >&2
        return 1
    fi
}

# ------------------------------------------------------------------ start ---

start_stack() {
    step "Building and starting"
    if [ "$NO_BUILD" = yes ]; then
        $DOCKER image inspect "$IMAGE_TAG" >/dev/null 2>&1 \
            || { warn "--no-build was given but the image $IMAGE_TAG does not exist"; return 1; }
    else
        compose build || { warn "the image did not build"; return 1; }
    fi
    hash_password || return 1
    issue_ip_certificate || return 1
    if [ "$DO_START" != yes ]; then say "(--no-start: not starting)"; return 0; fi
    local up=(up -d --remove-orphans)
    [ "$NO_BUILD" = yes ] && up+=(--no-build)
    compose "${up[@]}" || { warn "docker compose up failed"; return 1; }
}

# ------------------------------------------------------- last known good ---

LAST_GOOD="${ENV_FILE}.last-good"
RESTORED=no
FAIL_REASON=""

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

# compute_panel_url derives the link from the mode and the site.
compute_panel_url() {
    case "$MODE" in
        tunnel) PANEL_URL="http://127.0.0.1:$PORT" ;;
        *)      PANEL_URL="https://$(url_host "$SITE")" ;;
    esac
}

load_state_from_env() {
    MODE="$(env_get PANEL_MODE)"
    SITE="$(env_get PANEL_SITE)"; [ -n "$SITE" ] || SITE="$(env_get PANEL_DOMAIN)"
    PORT="$(env_get PANEL_PORT)"; PORT="${PORT:-9477}"
    ENFORCE="$(env_get PANEL_ENFORCE)"; ENFORCE="${ENFORCE:-no}"
    LOGIN="$(env_get AUDITDSEC_WEB_LOGIN)"; LOGIN="${LOGIN:-admin}"
    EMAIL="$(env_get PANEL_EMAIL)"
    ACME="$(env_get PANEL_ACME)"
    ACME_URL="$(env_get PANEL_ACME_URL)"
    PASSWORD=""
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
    RESTORED=yes
    ok "started again: mode $MODE${SITE:+, $SITE}${ACME:+, $ACME}"
}

# ------------------------------------------------------------ verification ---

TLS_STATE=""
LOGIN_STATE=""
LOGIN_ROUTE=""
PAGE_STATE=""
RENEW_STATE=""
TLS_UNTRUSTED=no
TLS_TRUSTED=no
RELOAD_PROBLEM=no
# ROUTE is empty unless this server cannot reach its own public address (some
# clouds do not loop it back). Then every check is sent to the loopback
# address instead, with the same name in the URL, so the certificate and its
# name are still verified exactly as before.
ROUTE=()
CA_TMP=""

cleanup() { [ -z "$CA_TMP" ] || rm -f "$CA_TMP"; }
trap cleanup EXIT

# json_escape is enough for a password: backslash and quote are the only
# printable characters that break a JSON string.
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    printf '%s' "$s"
}

hostport() { case "$1" in *:*) printf '[%s]:%s' "$1" "$2" ;; *) printf '%s:%s' "$1" "$2" ;; esac; }

compose_prefix() {
    local base="$DOCKER compose" f
    for f in "${COMPOSE_FILES[@]}"; do base="$base $f"; done
    printf '%s' "$base"
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
# the container, for the self-signed mode. Verifying against exactly that one
# certificate is verification: the connection is shown to end at this
# installation's proxy. Browsers do not know the CA, which is why they warn.
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

# verify_stack returns 0 when everything checked out, 1 when the panel is not
# working (a reason to put the previous configuration back) and 2 when it
# works but something a person must look at is wrong (an untrusted production
# certificate, a certificate that is on disk but not being served).
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
        FAIL_REASON="the sign-in page at $url did not answer within 90 seconds"
        warn "$FAIL_REASON."
        say "Look at: $(compose_prefix) logs --tail 80 auditdsec"
        case "$MODE" in domain|ip|selfsigned) say "      and: $(compose_prefix) logs --tail 40 caddy" ;; esac
        return 1
    fi
    PAGE_STATE="answers"
    if [ "$routed" = yes ]; then
        PAGE_STATE="answers, but only through this server's loopback: it cannot reach its own address"
        warn "$url does not answer from this server itself (some clouds do not loop their own"
        warn "public address back). The checks below went to the loopback address instead; they say"
        warn "nothing about whether the outside can reach it."
    fi
    ok "the sign-in page answers at $url"

    # Trust: curl WITHOUT -k, against the system store, or against the one CA
    # the person named (--cacert), or, for the self-signed mode, against the
    # root of the proxy's own CA. This proves the chain, the name or address,
    # and the dates all at once.
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
                    selfsigned) TLS_STATE="encrypted, and verified against this server's own CA (browsers do not know it, so they warn)" ;;
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
        local expiry
        local peer; peer="$(hostport "$SITE" 443)"
        [ ${#ROUTE[@]} -eq 0 ] || peer="127.0.0.1:443"
        expiry="$(printf '' | openssl s_client -connect "$peer" -servername "$SITE" 2>/dev/null \
            | openssl x509 -noout -enddate 2>/dev/null | sed 's/^notAfter=//' || true)"
        if [ -n "$expiry" ]; then TLS_STATE="$TLS_STATE; ends $expiry"; fi
    fi

    # Sign in with the password just chosen. This proves the stored hash
    # survived .env and Compose intact, which is the step that fails silently
    # when a $ is lost on the way. WHERE it is sent depends on trust: over the
    # public address only when its certificate verified; otherwise to the
    # agent's loopback address on this machine, which never leaves it.
    local default_probe=no
    if [ -z "$PASSWORD" ] && [ -z "$(env_get AUDITDSEC_WEB_PASSWORD_HASH)" ]; then
        # The default account: ask whether it still answers. It is not a secret
        # (the whole point is that it must be replaced), but it goes through
        # the same trust rules as a real password.
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
                ok "$LOGIN_STATE" ;;
            *'"token"'*) LOGIN_STATE="signed in with the chosen password"; ok "$LOGIN_STATE, $LOGIN_ROUTE" ;;
            *'"bad_credentials"'*)
                if [ "$default_probe" = yes ]; then
                    # Normal on a re-run: the owner already replaced admin/admin.
                    LOGIN_STATE="the default account is gone (credentials were changed earlier); not tested"
                    ok "$LOGIN_STATE"
                else
                    LOGIN_STATE="SIGN-IN FAILED"
                    FAIL_REASON="the panel is up but refused the password that was just set"
                    warn "$FAIL_REASON."
                    return 1
                fi ;;
            *)
                LOGIN_STATE="SIGN-IN FAILED"
                FAIL_REASON="the panel is up but refused the password that was just set"
                warn "$FAIL_REASON."
                say "Look at: $(compose_prefix) logs --tail 80 auditdsec"
                return 1
                ;;
        esac
    else
        LOGIN_STATE="not tested (the earlier password was kept)"
    fi
    if [ "$default_probe" = yes ]; then PASSWORD=""; fi

    # In address mode the renewal loop owns the certificate. Ask it whether
    # the file it manages is the one port 443 serves right now.
    if [ "$MODE" = ip ]; then
        local st tries=0
        while [ "$tries" -lt 8 ]; do
            tries=$((tries + 1))
            if st="$(compose exec -T certbot python3 /hooks/certtool.py status 2>&1)"; then break; fi
            sleep 3
        done
        if [ "$st" = ok ]; then
            RENEW_STATE="the certificate on disk is the one port 443 serves; the renewal loop is healthy"
            ok "$RENEW_STATE"
        else
            RENEW_STATE="PROBLEM: $st"
            RELOAD_PROBLEM=yes
            warn "the renewal loop reports: $st"
            soft=2
        fi
    fi

    # A certificate that does not verify defeats the point of the two modes
    # that exist to get a trusted one, so it is a failure, not a footnote.
    [ "$TLS_UNTRUSTED" = no ] || soft=2
    return "$soft"
}

# ssh_command works out the address the person actually reaches this server
# by. When the installer runs over SSH the connection says so itself: the
# third word of SSH_CONNECTION is the server address as the client saw it.
ssh_command() {
    local host="" port=22 user p=""
    if [ -n "${SSH_CONNECTION:-}" ]; then
        # shellcheck disable=SC2086
        set -- $SSH_CONNECTION
        host="${3:-}"; port="${4:-22}"
    fi
    [ -n "$host" ] || host="$(env_get PANEL_SSH_HOST)"
    if [ -z "$host" ] && interactive; then
        host="$(ask 'Address or hostname you use to SSH into this server' '')"
    fi
    if [ -n "$host" ]; then env_set PANEL_SSH_HOST "$host"; else host="<server-address>"; fi
    user="${SUDO_USER:-$(id -un)}"
    [ "$port" != 22 ] && p=" -p $port"
    printf 'ssh%s -L %s:127.0.0.1:%s %s@%s' "$p" "$PORT" "$PORT" "$user" "$host"
}

# ----------------------------------------------------------------- summary ---

summary() {
    local line
    line="$(printf '%*s' 66 '' | tr ' ' '-')"
    printf '\n%s\n' "$line"
    if [ "$RESTORED" = yes ]; then
        printf '%sThe new settings did not work; the previous ones are running again.%s\n' "$R$B" "$N"
    elif [ "$PAGE_STATE" = "NOT ANSWERING" ] || [ "$LOGIN_STATE" = "SIGN-IN FAILED" ]; then
        printf '%sInstalled, but the panel is not working.%s\n' "$R$B" "$N"
    elif [ "$TLS_UNTRUSTED" = yes ]; then
        printf '%sThe panel is up, but its certificate is NOT trusted.%s\n' "$Y$B" "$N"
    elif [ "$RELOAD_PROBLEM" = yes ]; then
        printf '%sThe panel is up, but the renewal loop has a problem.%s\n' "$Y$B" "$N"
    elif [ "$DO_START" != yes ]; then
        printf '%sConfigured, not started (--no-start).%s\n' "$B" "$N"
    elif [ "$ACME" = staging ]; then
        printf '%sThe panel is up on the Let'"'"'s Encrypt STAGING CA: a dry run.%s\n' "$Y$B" "$N"
    else
        printf '%sThe panel is up.%s\n' "$G$B" "$N"
    fi
    printf '%s\n\n' "$line"

    if [ -n "$FAIL_REASON" ] && [ "$RESTORED" = yes ]; then
        printf '  What went wrong: %s\n' "$FAIL_REASON"
        printf '  The failed settings are in %s.failed (same permissions as %s).\n\n' "$ENV_FILE" "$ENV_FILE"
    fi

    if [ "$MODE" = tunnel ]; then
        printf '  1. On your own computer, run and leave open:\n\n       %s\n\n' "$(ssh_command)"
        printf '  2. Then open:  %s%s%s\n\n' "$B" "$PANEL_URL" "$N"
    else
        printf '  Link:     %s%s%s\n' "$B" "$PANEL_URL" "$N"
    fi
    if [ -n "$(env_get AUDITDSEC_WEB_PASSWORD_HASH)" ]; then
        printf '  Login:    %s   (and the password you set; only its hash is stored)\n' "$LOGIN"
    else
        printf '  Login:    %sadmin%s   Password:  %sadmin%s\n' "$B" "$N" "$B" "$N"
        printf '            The first sign-in leads to a mandatory screen: choose your own login\n'
        printf '            (or tick "keep admin") and a password of 8+ characters with a lower-case\n'
        printf '            and an upper-case letter. Until then nothing else in the panel opens.\n'
        printf '            Do it right away: whoever opens the link first can choose them.\n'
    fi
    printf '  Page:     %s\n' "${PAGE_STATE:-not checked}"
    printf '  Sign-in:  %s\n' "${LOGIN_STATE:-not checked}"
    [ -z "$LOGIN_ROUTE" ] || printf '            sent %s\n' "$LOGIN_ROUTE"
    printf '  TLS:      %s\n' "${TLS_STATE:-not checked}"
    [ -z "$RENEW_STATE" ] || printf '  Renewal:  %s\n' "$RENEW_STATE"

    case "$MODE" in
        domain)
            printf '            Caddy renews the certificate itself, about 30 days before it ends.\n' ;;
        ip)
            printf '            certificates for addresses last about 6 days. The certbot container checks\n'
            printf '            twice a day, retries a failed renewal after an hour, and every minute makes\n'
            printf '            sure port 443 serves the certificate on disk. Port 80 must stay open and\n'
            printf '            unused for that to keep working.\n' ;;
        selfsigned)
            printf '  Trust:    each browser warns once. Before accepting, compare the fingerprint it\n'
            printf '            shows with the one this server holds:\n'
            printf '              printf "" | openssl s_client -connect %s 2>/dev/null | openssl x509 -noout -fingerprint -sha256\n' "$(hostport "$SITE" 443)"
            printf '            A real domain or public address needs no exception at all.\n' ;;
    esac

    if [ "$ACME" = staging ] && [ "$RESTORED" != yes ]; then
        printf '\n  %sSTAGING.%s Browsers do not trust this certificate, on purpose. A working staging run\n' "$Y$B" "$N"
        printf '  shows the steps work; it does NOT show that the real CA will issue a certificate\n'
        printf '  for this %s (that is a separate request with its own limits).\n' "$([ "$MODE" = ip ] && echo address || echo domain)"
        printf '  When ready, switch with:  ./install.sh --production\n'
        printf '  Nothing is deleted: the staging account, certificates and volumes stay where they are.\n'
    elif [ "$ACME" = production ] && [ "$TLS_TRUSTED" = yes ] && [ "$RESTORED" != yes ]; then
        if [ -n "$CACERT" ]; then
            printf '\n  Production CA, verified against the CA file you gave. That shows the chain is\n'
            printf '  consistent; whether browsers trust that CA is a separate question.\n'
        else
            printf '\n  Production certificate, verified from this server against its system CA store.\n'
        fi
    fi

    if [ "$DO_START" = yes ] && [ "$PAGE_STATE" = answers ]; then
        if [ "$MODE" = tunnel ]; then
            printf '\n  %sOnly the server'"'"'s own loopback was checked.%s The tunnel is made from your computer.\n' "$Y" "$N"
        else
            printf '\n  %sChecked from this server only.%s Reachability from the internet was not tested:\n' "$Y" "$N"
            printf '  open the link from another network to confirm the ports are open on the outside.\n'
        fi
    fi

    if [ "$TLS_UNTRUSTED" = yes ]; then
        printf '\n  Browsers will warn. Likely causes: the name or address in the certificate is not the one in\n'
        printf '  the link, the issuance failed silently (see the logs below), or the clock on this machine is\n'
        printf '  wrong. Nothing was lost: fix it and run ./install.sh again, or put the last working\n'
        printf '  configuration back with ./install.sh --restore.\n'
    fi

    printf '\n  Diagnostics:\n'
    printf '    %s ps\n' "$(compose_prefix)"
    printf '    %s logs --tail 80 auditdsec\n' "$(compose_prefix)"
    case "$MODE" in domain|ip|selfsigned) printf '    %s logs --tail 40 caddy\n' "$(compose_prefix)" ;; esac
    if [ "$MODE" = ip ]; then
        printf '    %s logs --tail 40 certbot\n' "$(compose_prefix)"
        printf '    %s exec certbot python3 /hooks/certtool.py status\n' "$(compose_prefix)"
    fi
    printf '\n  To change anything, run ./install.sh again: data, certificates and settings are kept.\n'
    [ ! -s "$LAST_GOOD" ] || printf '  To go back to the last verified configuration: ./install.sh --restore\n'
    printf '%s\n' "$line"
}

# -------------------------------------------------------------------- main ---

main() {
    require_docker

    if [ "$RESTORE" = yes ]; then
        [ -s "$LAST_GOOD" ] || die "there is no verified configuration to go back to ($LAST_GOOD)"
        restore_last_good || die "the previous configuration would not start"
        local rrc=0
        verify_stack || rrc=$?
        summary
        return "$rrc"
    fi

    choose_mode
    ask_site
    ask_email
    ask_acme
    ask_telegram
    ask_login
    ask_enforce
    ask_password

    write_config
    build_compose_files

    local vrc=0 started=yes
    if ! start_stack; then
        started=no
        FAIL_REASON="${FAIL_REASON:-the stack could not be started}"
    else
        verify_stack || vrc=$?
    fi

    # The new settings do not work. When there is a configuration that did,
    # put it back rather than leave a person with nothing; the failed one is
    # kept for diagnosis.
    if [ "$started" = no ] || [ "$vrc" = 1 ]; then
        if [ -s "$LAST_GOOD" ] && ! cmp -s "$ENV_FILE" "$LAST_GOOD"; then
            local reason="$FAIL_REASON"
            if restore_last_good; then
                TLS_UNTRUSTED=no; LOGIN_STATE=""; LOGIN_ROUTE=""; TLS_STATE=""; RENEW_STATE=""; RELOAD_PROBLEM=no
                PAGE_STATE=""; PASSWORD=""
                verify_stack || true
                FAIL_REASON="$reason"
            fi
        else
            say ""
            say "There is no earlier working configuration to go back to."
        fi
        summary
        return 1
    fi

    if [ "$DO_START" = yes ] && [ "$DO_VERIFY" = yes ] && [ "$vrc" = 0 ]; then
        save_last_good
    fi
    summary
    return "$vrc"
}

main
