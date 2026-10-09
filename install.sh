#!/usr/bin/env bash
#
# auditdsec — set up the agent and the web panel.
#
#   ./install.sh
#
# Asks how the panel should be reachable, writes .env, builds the image,
# starts everything and then checks that the sign-in page actually answers
# before printing the link.
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
PORT=""
PASSWORD=""
PASSWORD_FILE=""
ENFORCE=""        # yes | no
ASSUME_YES=no
DO_START=yes
DO_VERIFY=yes
STAGING=no

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
  --port N                             port the agent listens on (default: 9477)
  --password-file PATH                 read the panel password from this file
  --enforce / --no-enforce             apply bans with nftables, or only record them
  --staging                            Let's Encrypt staging CA, for a dry run
  --yes                                do not ask anything that has an answer already
  --no-start                           write the configuration and stop
  --no-verify                          start, but skip checking the panel answers
  -h, --help                           this text

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
        --port) PORT="${2:-}"; shift 2 ;;
        --password-file) PASSWORD_FILE="${2:-}"; shift 2 ;;
        --enforce) ENFORCE=yes; shift ;;
        --no-enforce) ENFORCE=no; shift ;;
        --staging) STAGING=yes; shift ;;
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
    return 0
}

# ------------------------------------------------------------------ checks --

require_docker() {
    command -v "${DOCKER%% *}" >/dev/null 2>&1 || die "$DOCKER is not installed"
    $DOCKER compose version >/dev/null 2>&1 || die "'$DOCKER compose' does not work; install the Compose plugin"
    $DOCKER info >/dev/null 2>&1 || die "cannot talk to the Docker daemon; is it running, and are you root?"
}

# ------------------------------------------------------------------ asking --

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
    LOGIN="${LOGIN:-$(ask 'Panel login name' "$(env_get AUDITDSEC_WEB_LOGIN)")}"
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
        [ "${#PASSWORD}" -ge 12 ] || die "the password in $PASSWORD_FILE is shorter than 12 characters"
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

    while [ -z "$PASSWORD" ]; do
        interactive || die "no password given; use --password-file"
        local again
        PASSWORD="$(ask_secret 'Panel password')"
        again="$(ask_secret 'Again')"
        if [ "$PASSWORD" != "$again" ]; then
            warn "they do not match."
            PASSWORD=""
            continue
        fi
        if [ "${#PASSWORD}" -lt 12 ]; then
            warn "use at least 12 characters."
            PASSWORD=""
        fi
    done
}

# ----------------------------------------------------------- writing config --

PANEL_URL=""

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
        die "could not hash the password"
    fi
    rm -f "$errfile"
    case "$hash" in 'pbkdf2-sha256$'*) ;; *) die "the hash looks wrong; not saving it" ;; esac
    env_set AUDITDSEC_WEB_PASSWORD_HASH "$hash"
    ok "stored as a hash; the password itself is not written anywhere"
}

# ---------------------------------------------------------------- certbot ---

# version_at_least A B — true when A >= B, comparing dotted numbers.
version_at_least() {
    [ -n "${1:-}" ] || return 1
    [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n 1)" = "$2" ]
}

# issue_ip_certificate asks Let's Encrypt for the address's certificate before
# the proxy starts, because Caddyfile.acme-ip refuses to load without files.
issue_ip_certificate() {
    [ "$MODE" = ip ] || return 0
    step "Requesting a Let's Encrypt certificate for $SITE"

    if compose run --rm --no-deps --entrypoint sh certbot \
            -c 'test -s /certs/fullchain.pem' >/dev/null 2>&1; then
        ok "a certificate is already in place; the renewal loop keeps it current"
        return 0
    fi

    local version
    version="$(compose run --rm --no-deps --entrypoint certbot certbot --version 2>/dev/null \
        | awk '{print $2}' | tail -n 1 || true)"
    [ -n "$version" ] || die "cannot run the certbot image; check the network and CERTBOT_IMAGE"
    version_at_least "$version" 5.3 \
        || die "certbot $version cannot issue certificates for addresses; 5.3 or newer is needed (set CERTBOT_IMAGE)"

    local extra=()
    [ "$STAGING" = yes ] && extra+=(--staging)
    if [ -n "$EMAIL" ]; then extra+=(-m "$EMAIL"); else extra+=(--register-unsafely-without-email); fi

    say "Let's Encrypt will connect to port 80 on this address. Nothing may be using it."
    if compose run --rm --no-deps --entrypoint certbot certbot \
            certonly --standalone --non-interactive --agree-tos \
            --cert-name panel --preferred-profile shortlived \
            --ip-address "$SITE" --deploy-hook /hooks/deploy.sh \
            "${extra[@]}"; then
        ok "certificate issued"
    else
        cat >&2 <<EOF

${R}The certificate was not issued.${N} The usual reasons, in order of likelihood:
  - port 80 is not reachable from the internet at $SITE
    (a firewall, the provider's security group, or something else listening)
  - $SITE is not this server's public address
  - Let's Encrypt's limit of 5 certificates per address per week was reached
Fix that and run ./install.sh again; nothing else needs redoing. If port 80
cannot be opened, the self-signed option works without it.
EOF
        exit 1
    fi
}

# ------------------------------------------------------------------ start ---

start_stack() {
    step "Building and starting"
    compose build
    hash_password
    issue_ip_certificate
    if [ "$DO_START" != yes ]; then say "(--no-start: not starting)"; return 0; fi
    compose up -d --remove-orphans
}

# ------------------------------------------------------------ verification ---

CURL_ARGS=()
TLS_STATE=""
LOGIN_STATE=""
PAGE_STATE=""
TLS_UNTRUSTED=no

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

wait_for_page() {
    local url="$1" code tries=0
    while [ "$tries" -lt 45 ]; do
        tries=$((tries + 1))
        code="$(curl -sS --noproxy '*' "${CURL_ARGS[@]}" -o /dev/null -w '%{http_code}' --max-time 4 "$url/" 2>/dev/null || true)"
        [ "$code" = 200 ] && return 0
        sleep 2
    done
    return 1
}

verify_stack() {
    if [ "$DO_START" != yes ] || [ "$DO_VERIFY" != yes ]; then
        PAGE_STATE="not checked"
        return 0
    fi
    step "Checking that the panel actually answers"

    local url="$PANEL_URL"
    # Whether the page answers and whether its certificate is trusted are two
    # separate facts. Waiting and signing in ignore trust (-k), so that an
    # untrusted certificate is reported as exactly that and not as a panel
    # that is down; trust is judged on its own below.
    CURL_ARGS=()
    case "$MODE" in domain|ip|selfsigned) CURL_ARGS=(-k) ;; esac

    if ! wait_for_page "$url"; then
        PAGE_STATE="NOT ANSWERING"
        warn "the sign-in page at $url did not answer within 90 seconds."
        say "Look at: $(compose_prefix) logs --tail 80 auditdsec"
        return 1
    fi
    PAGE_STATE="answers"
    ok "the sign-in page answers at $url"

    # TLS: curl without -k both proves the chain validates from this machine
    # and lets us read when the certificate ends.
    case "$MODE" in
        domain|ip)
            local verify
            verify="$(curl -sS --noproxy '*' -o /dev/null -w '%{ssl_verify_result}' --max-time 6 "$url/" 2>/dev/null || echo 99)"
            if [ "$verify" = 0 ]; then
                TLS_STATE="valid and trusted (checked from this server)"
                ok "the certificate is trusted"
            else
                TLS_STATE="NOT trusted (curl verify code $verify)"
                [ "$STAGING" = yes ] || TLS_UNTRUSTED=yes
                warn "the certificate did not validate from here; a browser would warn too."
                if [ "$STAGING" = yes ]; then say "That is expected with --staging: staging certificates are never trusted."; fi
            fi
            ;;
        selfsigned) TLS_STATE="self-signed: encrypted, but no browser trusts it" ;;
        tunnel)     TLS_STATE="none needed: the connection runs inside the SSH tunnel" ;;
    esac

    if [ "$MODE" != tunnel ] && command -v openssl >/dev/null 2>&1; then
        local expiry
        expiry="$(printf '' | openssl s_client -connect "$(hostport "$SITE" 443)" -servername "$SITE" 2>/dev/null \
            | openssl x509 -noout -enddate 2>/dev/null | sed 's/^notAfter=//' || true)"
        if [ -n "$expiry" ]; then TLS_STATE="$TLS_STATE; ends $expiry"; fi
    fi

    # Sign in with the password just chosen. This proves the stored hash
    # survived .env and Compose intact, which is the step that fails silently
    # when a $ is lost on the way.
    if [ -n "$PASSWORD" ]; then
        local body reply
        body="{\"login\":\"$(json_escape "$LOGIN")\",\"password\":\"$(json_escape "$PASSWORD")\"}"
        reply="$(printf '%s' "$body" | curl -sS --noproxy '*' "${CURL_ARGS[@]}" --max-time 15 -X POST \
            -H 'X-Requested-With: auditdsec' -H 'Content-Type: application/json' \
            --data-binary @- "$url/api/v1/login" 2>/dev/null || true)"
        case "$reply" in
            *'"token"'*) LOGIN_STATE="signed in with the chosen password"; ok "$LOGIN_STATE" ;;
            *)
                LOGIN_STATE="SIGN-IN FAILED"
                warn "the panel is up but refused the password that was just set."
                say "Look at: $(compose_prefix) logs --tail 80 auditdsec"
                return 1
                ;;
        esac
    else
        LOGIN_STATE="not tested (the earlier password was kept)"
    fi
    # A certificate that does not validate defeats the point of the two modes
    # that exist to get a trusted one, so it is a failure, not a footnote.
    [ "$TLS_UNTRUSTED" = no ] || return 1
    return 0
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
    if [ "$PAGE_STATE" = "NOT ANSWERING" ] || [ "$LOGIN_STATE" = "SIGN-IN FAILED" ]; then
        printf '%sInstalled, but the panel is not working.%s\n' "$R$B" "$N"
    elif [ "$TLS_UNTRUSTED" = yes ]; then
        printf '%sThe panel is up, but its certificate is NOT trusted.%s\n' "$Y$B" "$N"
    elif [ "$DO_START" != yes ]; then
        printf '%sConfigured, not started (--no-start).%s\n' "$B" "$N"
    else
        printf '%sThe panel is up.%s\n' "$G$B" "$N"
    fi
    printf '%s\n\n' "$line"

    if [ "$MODE" = tunnel ]; then
        printf '  1. On your own computer, run and leave open:\n\n       %s\n\n' "$(ssh_command)"
        printf '  2. Then open:  %s%s%s\n\n' "$B" "$PANEL_URL" "$N"
    else
        printf '  Link:     %s%s%s\n' "$B" "$PANEL_URL" "$N"
    fi
    printf '  Login:    %s   (and the password you set; only its hash is stored)\n' "$LOGIN"
    printf '  Page:     %s\n' "${PAGE_STATE:-not checked}"
    printf '  Sign-in:  %s\n' "${LOGIN_STATE:-not checked}"
    printf '  TLS:      %s\n' "${TLS_STATE:-not checked}"

    case "$MODE" in
        domain)
            printf '  Renewal:  Caddy renews the certificate itself, about 30 days before it ends.\n' ;;
        ip)
            printf '  Renewal:  certificates for addresses last about 6 days. The certbot container\n'
            printf '            checks twice a day and reloads Caddy after each renewal. Port 80 must\n'
            printf '            stay open and unused for that to keep working.\n' ;;
        selfsigned)
            printf '  Trust:    each browser warns once. Before accepting, compare the fingerprint it\n'
            printf '            shows with the one this server holds:\n'
            printf '              printf "" | openssl s_client -connect %s 2>/dev/null | openssl x509 -noout -fingerprint -sha256\n' "$(hostport "$SITE" 443)"
            printf '            A real domain or public address needs no exception at all.\n' ;;
    esac

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
        printf '  the link, the issuance failed silently (see the certbot / caddy logs below), or the clock\n'
        printf '  on this machine is wrong. Nothing was lost: fix it and run ./install.sh again.\n'
    fi

    printf '\n  Diagnostics:\n'
    printf '    %s ps\n' "$(compose_prefix)"
    printf '    %s logs --tail 80 auditdsec\n' "$(compose_prefix)"
    case "$MODE" in domain|ip|selfsigned) printf '    %s logs --tail 40 caddy\n' "$(compose_prefix)" ;; esac
    [ "$MODE" = ip ] && printf '    %s logs --tail 40 certbot\n' "$(compose_prefix)"
    printf '\n  To change anything, run ./install.sh again: data, certificates and settings are kept.\n'
    printf '%s\n' "$line"
}

# -------------------------------------------------------------------- main ---

main() {
    require_docker
    choose_mode
    ask_site
    ask_email
    ask_telegram
    ask_login
    ask_enforce
    ask_password

    write_config
    build_compose_files
    start_stack

    local failed=0
    verify_stack || failed=1
    summary
    return "$failed"
}

main
