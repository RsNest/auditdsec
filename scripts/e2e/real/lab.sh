#!/bin/bash
# lab.sh — everything the real-Docker scenarios need, built from what is on
# this machine, for a place with no access to Docker Hub or Let's Encrypt.
#
#   lab.sh up        start dockerd if needed, build the images, start two ACME servers
#   lab.sh down      stop the ACME servers (dockerd and the images stay)
#   lab.sh status
#
# What is real and what is substituted (also listed in docs/VERIFY.md):
#
#   REAL         the Docker daemon, `docker compose`, containers, host networking,
#                named volumes, capabilities, bind mounts, healthchecks; certbot
#                (the PyPI release, pinned); Caddy (the upstream binary); the agent
#                (built from this tree with the Dockerfile's flags)
#   SUBSTITUTED  the images are built `FROM scratch` here, because the registries
#                are not reachable: same tags, same entrypoints, but not the
#                official certbot/caddy images' contents. The agent image replaces
#                only the Dockerfile's build stage.
#                The ACME servers are two Pebble instances (Let's Encrypt's own
#                test server): one stands in for staging, one for production.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
LAB="${LAB:-/tmp/auditdsec-lab}"
CERTBOT_VERSION="${CERTBOT_VERSION:-5.8.0}"
CERTBOT_VENV="${CERTBOT_VENV:-/opt/certbot}"
CADDY_BIN="${CADDY_BIN:-$(command -v caddy || true)}"
PEBBLE_REF="${PEBBLE_REF:-}"

say() { printf '== %s\n' "$*"; }

ensure_dockerd() {
    docker info >/dev/null 2>&1 && return 0
    command -v dockerd >/dev/null || { echo "no docker daemon and no dockerd binary" >&2; exit 1; }
    say "starting dockerd"
    mkdir -p "$LAB/docker"
    (nohup dockerd --data-root "$LAB/docker/data" --exec-root "$LAB/docker/exec" \
        --pidfile "$LAB/docker/dockerd.pid" > "$LAB/docker/dockerd.log" 2>&1 &)
    for _ in $(seq 1 30); do docker info >/dev/null 2>&1 && return 0; sleep 1; done
    echo "dockerd did not come up; see $LAB/docker/dockerd.log" >&2; exit 1
}

# --- images ---------------------------------------------------------------

add_file() { # SRC ROOT — copy a file (following links) to the same path under ROOT
    mkdir -p "$2$(dirname "$1")"
    cp -L "$1" "$2$1"
}

add_libs() { # BINARY ROOT — copy the shared libraries a binary needs
    local lib
    ldd "$1" 2>/dev/null | awk '/=> \// {print $3} /^[[:space:]]*\/lib[^ ]*ld-linux/ {print $1}' | while read -r lib; do
        [ -e "$lib" ] && add_file "$lib" "$2"
    done
}

build_agent_image() {
    local ctx="$LAB/ctx/agent"
    rm -rf "$ctx"; mkdir -p "$ctx"
    (cd "$REPO" && CGO_ENABLED=0 GOFLAGS=-trimpath go build \
        -ldflags "-s -w -X main.version=${AUDITDSEC_VERSION:-0.1.0}" -o "$ctx/auditdsec" ./cmd/auditdsec)
    mkdir -p "$ctx/etc/ssl/certs" "$ctx/usr/share"
    cp /etc/ssl/certs/ca-certificates.crt "$ctx/etc/ssl/certs/"
    cp -r /usr/share/zoneinfo "$ctx/usr/share/zoneinfo"
    cat > "$ctx/Dockerfile" <<'EOF'
# The "minimal" stage of deploy/Dockerfile, with the binary built outside.
FROM scratch
COPY etc /etc
COPY usr/share /usr/share
COPY auditdsec /usr/local/bin/auditdsec
VOLUME ["/var/lib/auditdsec"]
ENV AUDITDSEC_STATE_DIR=/var/lib/auditdsec \
    AUDITDSEC_AUDIT_LOG=/var/log/audit/audit.log \
    AUDITDSEC_LOG_FILE=/var/lib/auditdsec/auditdsec.log
ENTRYPOINT ["/usr/local/bin/auditdsec"]
CMD ["run"]
EOF
    docker build -q -t "auditdsec:${AUDITDSEC_VERSION:-0.1.0}" "$ctx" >/dev/null
}

build_caddy_image() {
    [ -x "$CADDY_BIN" ] || { echo "set CADDY_BIN to a caddy 2.10 binary" >&2; exit 1; }
    local ctx="$LAB/ctx/caddy"
    rm -rf "$ctx"; mkdir -p "$ctx/rootfs/tmp" "$ctx/rootfs/data" "$ctx/rootfs/config" "$ctx/rootfs/etc/ssl/certs" "$ctx/rootfs/usr/bin"
    chmod 1777 "$ctx/rootfs/tmp"
    cp "$CADDY_BIN" "$ctx/rootfs/usr/bin/caddy"
    cp /etc/ssl/certs/ca-certificates.crt "$ctx/rootfs/etc/ssl/certs/"
    cat > "$ctx/Dockerfile" <<'EOF'
FROM scratch
COPY rootfs /
ENV XDG_CONFIG_HOME=/config XDG_DATA_HOME=/data
CMD ["/usr/bin/caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
EOF
    docker build -q -t "${CADDY_IMAGE:-caddy:2.10-alpine}" "$ctx" >/dev/null
}

build_certbot_image() {
    if [ ! -x "$CERTBOT_VENV/bin/certbot" ] || ! "$CERTBOT_VENV/bin/certbot" --version 2>&1 | grep -q "$CERTBOT_VERSION"; then
        say "creating $CERTBOT_VENV with certbot $CERTBOT_VERSION"
        python3 -m venv --copies "$CERTBOT_VENV"
        "$CERTBOT_VENV/bin/pip" install -q "certbot==$CERTBOT_VERSION"
    fi
    local ctx="$LAB/ctx/certbot" R
    R="$ctx/rootfs"
    rm -rf "$ctx"; mkdir -p "$R"
    local pyver
    pyver="$("$CERTBOT_VENV/bin/python" -c 'import sys;print("%d.%d"%sys.version_info[:2])')"
    # Shell and the few tools the scripts use.
    mkdir -p "$R/bin" "$R/usr/bin" "$R/tmp" "$R/etc/ssl/certs"
    chmod 1777 "$R/tmp"
    local b
    for b in bash sleep date cat cp mv rm mkdir chmod ls grep sed env dirname head tail sort id awk test true false openssl; do
        local p; p="$(type -P "$b" || true)"
        [ -n "$p" ] || continue
        p="$(readlink -f "$p")"
        add_file "$p" "$R"; add_libs "$p" "$R"
        [ "$b" = bash ] && cp "$p" "$R/bin/sh" && cp "$p" "$R/bin/bash"
    done
    cp -a "$CERTBOT_VENV" "$R/opt-certbot-tmp" && mkdir -p "$R/opt" && mv "$R/opt-certbot-tmp" "$R/opt/certbot"
    mkdir -p "$R/usr/lib"
    cp -a "/usr/lib/python$pyver" "$R/usr/lib/python$pyver"
    local so
    while read -r so; do add_libs "$so" "$R"; done < <(find "$CERTBOT_VENV" "/usr/lib/python$pyver" -name '*.so*' -type f)
    add_libs "$CERTBOT_VENV/bin/python" "$R"
    local nss
    for nss in /lib/x86_64-linux-gnu/libnss_files.so.2 /lib/x86_64-linux-gnu/libnss_dns.so.2 /lib/x86_64-linux-gnu/libresolv.so.2; do
        [ -e "$nss" ] && add_file "$nss" "$R"
    done
    cp /etc/nsswitch.conf "$R/etc/" 2>/dev/null || printf 'hosts: files dns\n' > "$R/etc/nsswitch.conf"
    cp /etc/ssl/certs/ca-certificates.crt "$R/etc/ssl/certs/"
    mkdir -p "$R/usr/local/bin"
    ln -s /opt/certbot/bin/certbot "$R/usr/local/bin/certbot"
    ln -s /opt/certbot/bin/python3 "$R/usr/local/bin/python3"
    ln -s /opt/certbot/bin/python3 "$R/usr/bin/python3"
    cat > "$ctx/Dockerfile" <<'EOF'
FROM scratch
COPY rootfs /
ENV PATH=/usr/local/bin:/usr/bin:/bin
ENTRYPOINT ["/usr/local/bin/certbot"]
EOF
    docker build -q -t "${CERTBOT_IMAGE:-certbot/certbot:v$CERTBOT_VERSION}" "$ctx" >/dev/null
}

# --- Pebble, the ACME test server -----------------------------------------

build_pebble() {
    [ -x "$LAB/pebble-bin" ] && return 0
    say "building Pebble"
    mkdir -p "$LAB"
    if [ ! -d "$LAB/pebble-src" ]; then
        git clone -q --depth 1 ${PEBBLE_REF:+--branch "$PEBBLE_REF"} https://github.com/letsencrypt/pebble.git "$LAB/pebble-src"
    fi
    (
        cd "$LAB/pebble-src"
        # Pebble's dependencies are vendored, so no module proxy is needed. If
        # this machine's Go is older than the go.mod line, relax the line: the
        # code builds, and this is a test server.
        if ! GOTOOLCHAIN=local GOFLAGS=-mod=vendor go build -o "$LAB/pebble-bin" ./cmd/pebble 2>/dev/null; then
            sed -i -E 's/^go [0-9.]+$/go 1.24.0/; /^toolchain/d' go.mod
            sed -i -E 's/^(## explicit; go )1\.2[5-9].*/\11.24.0/' vendor/modules.txt
            GOTOOLCHAIN=local GOFLAGS=-mod=vendor go build -o "$LAB/pebble-bin" ./cmd/pebble
        fi
    )
}

pebble_config() { # DIR LISTEN MGMT
    mkdir -p "$1"
    cat > "$1/config.json" <<EOF
{ "pebble": {
    "listenAddress": "127.0.0.1:$2",
    "managementListenAddress": "127.0.0.1:$3",
    "certificate": "$LAB/pebble-src/test/certs/localhost/cert.pem",
    "privateKey": "$LAB/pebble-src/test/certs/localhost/key.pem",
    "httpPort": 80, "tlsPort": 443, "ocspResponderURL": "",
    "externalAccountBindingRequired": false,
    "retryAfter": {"authz": 1, "order": 1},
    "keyAlgorithm": "ecdsa",
    "profiles": {
      "default": {"description": "default", "validityPeriod": 7776000},
      "shortlived": {"description": "6 days", "validityPeriod": 518400}
    } } }
EOF
}

start_pebble() { # NAME LISTEN MGMT
    local dir="$LAB/pebble-$1"
    pebble_config "$dir" "$2" "$3"
    if [ -f "$dir/pid" ] && kill -0 "$(cat "$dir/pid")" 2>/dev/null; then return 0; fi
    (cd "$dir" && PEBBLE_VA_NOSLEEP=1 PEBBLE_AUTHZREUSE=0 PEBBLE_WFE_NONCEREJECT=0 \
        nohup "$LAB/pebble-bin" -config config.json > pebble.log 2>&1 & echo $! > pid)
    for _ in $(seq 1 20); do
        curl -s -o /dev/null --cacert "$LAB/pebble-src/test/certs/pebble.minica.pem" "https://localhost:$2/dir" && return 0
        sleep 0.5
    done
    echo "pebble $1 did not start; see $dir/pebble.log" >&2; exit 1
}

cmd_up() {
    mkdir -p "$LAB"
    ensure_dockerd
    build_pebble
    say "images"
    build_agent_image; build_caddy_image; build_certbot_image
    say "ACME servers: staging stand-in on :14000, production stand-in on :14001"
    start_pebble staging 14000 15000
    start_pebble production 14001 15001
    grep -q ' panel.test$' /etc/hosts || echo '127.0.0.1 panel.test' >> /etc/hosts
    # Each Pebble creates a new root CA at startup; save them for --cacert.
    curl -s -k "https://127.0.0.1:15000/roots/0" > "$LAB/root-staging.pem"
    curl -s -k "https://127.0.0.1:15001/roots/0" > "$LAB/root-production.pem"
    cp "$LAB/pebble-src/test/certs/pebble.minica.pem" "$LAB/acme-ca.pem"
    say "ready: $LAB"
}

cmd_down() {
    local n
    for n in staging production; do
        [ -f "$LAB/pebble-$n/pid" ] && kill "$(cat "$LAB/pebble-$n/pid")" 2>/dev/null || true
        rm -f "$LAB/pebble-$n/pid"
    done
}

cmd_status() {
    docker info >/dev/null 2>&1 && echo "docker: up" || echo "docker: down"
    docker images --format '  {{.Repository}}:{{.Tag}}' | grep -E 'auditdsec|caddy|certbot' || true
    local n
    for n in staging production; do
        [ -f "$LAB/pebble-$n/pid" ] && kill -0 "$(cat "$LAB/pebble-$n/pid")" 2>/dev/null && echo "pebble $n: up" || echo "pebble $n: down"
    done
}

case "${1:-}" in
    up) cmd_up ;; down) cmd_down ;; status) cmd_status ;;
    *) echo "usage: $0 up|down|status" >&2; exit 2 ;;
esac
