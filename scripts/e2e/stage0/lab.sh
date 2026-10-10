#!/bin/bash
# lab.sh up|down — the stand for the public-panel installer (stage 0).
#
# Run it INSIDE a disposable Linux machine or a privileged docker:dind
# container that plays the VPS: it adds firewall rules and listeners there.
# Never on a machine you use: see docs/VERIFY.md.
#
# What it starts, all on this "VPS":
#
#   coredns   a DNS server for the test zone .test, on 127.0.0.1:1053. It
#             stands in for public DNS: the installer is pointed at it with
#             PANEL_DNS_RESOLVERS.
#   pebble    Let's Encrypt's test ACME server, on https://localhost:14000.
#             It validates HTTP-01 on port 80 and TLS-ALPN-01 on 443 of the
#             address being certified, like the real CA.
#   registry  a Docker registry on 127.0.0.1:5000 standing in for ghcr.io, and
#             a fake GitHub API on 127.0.0.1:18080 whose answer the scenarios
#             set (building / failed / none).
#   probe     cmd/auditdsec-probe in a container on a SEPARATE Docker network
#             ("outside"): its connections to the VPS come in through the
#             VPS's network interface, so a firewall rule on the VPS's INPUT
#             chain affects it the way it would affect the internet.
#
# What is substituted, and so NOT proven here: real public DNS, the real
# Let's Encrypt, an IPv6 path, and a probe that is really on the internet.
set -euo pipefail

LAB="${LAB:-/lab}"
REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
PEBBLE_IMAGE="${PEBBLE_IMAGE:-ghcr.io/letsencrypt/pebble:2.9.0}"
COREDNS_IMAGE="${COREDNS_IMAGE:-coredns/coredns:1.12.1}"
GO_IMAGE="${GO_IMAGE:-golang:1.24-alpine}"
REGISTRY_IMAGE="${REGISTRY_IMAGE:-registry:2.8.3}"

say() { printf '== %s\n' "$*"; }

# The VPS's "public" address: the address its own containers use to reach it.
vps_ip() { ip -4 -o addr show docker0 | awk '{print $4}' | cut -d/ -f1; }

up() {
    mkdir -p "$LAB"
    local ip; ip="$(vps_ip)"
    [ -n "$ip" ] || { echo "no docker0 address" >&2; exit 1; }
    echo "$ip" > "$LAB/vps-ip"
    docker network inspect outside >/dev/null 2>&1 || docker network create outside >/dev/null

    say "DNS on 127.0.0.1:1053 (panel.test and friends -> $ip)"
    mkdir -p "$LAB/dns"
    cat > "$LAB/dns/hosts" <<EOF
$ip panel.test
10.9.9.9 wrong.test
$ip mixed.test
10.9.9.9 mixed.test
EOF
    cat > "$LAB/dns/Corefile" <<'EOF'
.:53 {
    hosts /dns/hosts {
        reload 1s
    }
}
EOF
    docker rm -f lab-dns >/dev/null 2>&1 || true
    # 1053 for the installer; port 53 on the VPS address for the probe
    # container, whose resolver can only be given as an address.
    docker run -d --name lab-dns -p 1053:53/udp -p 1053:53/tcp -p "$ip:53:53/udp" -v "$LAB/dns:/dns:ro" \
        "$COREDNS_IMAGE" -conf /dns/Corefile >/dev/null

    say "Pebble on https://localhost:14000"
    mkdir -p "$LAB/pebble"
    cat > "$LAB/pebble/config.json" <<'EOF'
{ "pebble": {
    "listenAddress": "0.0.0.0:14000",
    "managementListenAddress": "0.0.0.0:15000",
    "certificate": "/test/certs/localhost/cert.pem",
    "privateKey": "/test/certs/localhost/key.pem",
    "httpPort": 80, "tlsPort": 443, "ocspResponderURL": "",
    "externalAccountBindingRequired": false,
    "retryAfter": {"authz": 1, "order": 1},
    "keyAlgorithm": "ecdsa",
    "profiles": {
      "default": {"description": "default", "validityPeriod": 7776000},
      "shortlived": {"description": "6 days", "validityPeriod": 518400}
    } } }
EOF
    docker rm -f lab-pebble >/dev/null 2>&1 || true
    docker run -d --name lab-pebble -p 14000:14000 -p 15000:15000 \
        -e PEBBLE_VA_NOSLEEP=1 -e PEBBLE_AUTHZREUSE=0 -e PEBBLE_WFE_NONCEREJECT=0 \
        -v "$LAB/pebble/config.json:/lab-config.json:ro" \
        "$PEBBLE_IMAGE" -config /lab-config.json -dnsserver "$ip:1053" >/dev/null
    docker cp lab-pebble:/test/certs/pebble.minica.pem "$LAB/acme-ca.pem" >/dev/null

    for _ in $(seq 1 30); do
        curl -s -o /dev/null --cacert "$LAB/acme-ca.pem" https://localhost:14000/dir && break
        sleep 0.5
    done
    # Pebble makes a new root at every start; the panel's certificates chain to it.
    curl -s --cacert "$LAB/acme-ca.pem" https://localhost:15000/roots/0 > "$LAB/root.pem"
    grep -q 'BEGIN CERTIFICATE' "$LAB/root.pem" || { echo "no Pebble root" >&2; exit 1; }

    say "RemoteProbe on https://127.0.0.1:8443, running on the 'outside' network"
    mkdir -p "$LAB/probe"
    docker run --rm -v "$REPO:/src:ro" -v "$LAB/probe:/out" -w /src -e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false \
        "$GO_IMAGE" go build -o /out/auditdsec-probe ./cmd/auditdsec-probe
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=lab-probe \
        -addext 'subjectAltName=IP:127.0.0.1' -keyout "$LAB/probe/key.pem" -out "$LAB/probe/cert.pem" 2>/dev/null
    cp "$LAB/probe/cert.pem" "$LAB/probe-ca.pem"
    "$LAB/probe/auditdsec-probe" -generate-token > "$LAB/probe-token"
    cp "$LAB/probe-token" "$LAB/probe/token"
    cp "$LAB/root.pem" "$LAB/probe/roots.pem"
    docker rm -f lab-probe >/dev/null 2>&1 || true
    # -allow-private-targets: the lab's "public" address is a private one.
    # A real provider must never run with it.
    docker run -d --name lab-probe --network outside --dns "$ip" -p 127.0.0.1:8443:8443 -v "$LAB/probe:/p:ro" \
        alpine:3.21 /p/auditdsec-probe -listen 0.0.0.0:8443 -cert /p/cert.pem -key /p/key.pem \
        -token-file /p/token -roots /p/roots.pem -allow-private-targets -rate 600 -rate-per-target 600 >/dev/null
    for _ in $(seq 1 30); do
        curl -s -o /dev/null --cacert "$LAB/probe-ca.pem" https://127.0.0.1:8443/healthz && break
        sleep 0.5
    done
    # The VPS resolves the test names too (the installer's own curl to https://panel.test).
    grep -q " panel.test$" /etc/hosts || echo "$ip panel.test" >> /etc/hosts
    docker network inspect outside -f '{{(index .IPAM.Config 0).Subnet}}' > "$LAB/outside-subnet"
    say "image registry on 127.0.0.1:5000 (stands in for ghcr.io), fake GitHub API on 127.0.0.1:18080"
    docker rm -f lab-registry >/dev/null 2>&1 || true
    docker run -d --name lab-registry -p 127.0.0.1:5000:5000 "$REGISTRY_IMAGE" >/dev/null
    mkdir -p "$LAB/ghapi/repos/RsNest/auditdsec/actions"
    echo '{"total_count": 1, "workflow_runs": [{"status": "completed", "conclusion": "success"}]}' \
        > "$LAB/ghapi/repos/RsNest/auditdsec/actions/runs"
    [ ! -f "$LAB/ghapi.pid" ] || kill "$(cat "$LAB/ghapi.pid")" 2>/dev/null || true
    (cd "$LAB/ghapi" && nohup python3 -m http.server 18080 --bind 127.0.0.1 >/dev/null 2>&1 & echo $! > "$LAB/ghapi.pid")
    say "ready: VPS address $ip, outside network $(cat "$LAB/outside-subnet")"
}

down() {
    docker rm -f lab-dns lab-pebble lab-probe lab-registry >/dev/null 2>&1 || true
    [ ! -f "$LAB/ghapi.pid" ] || kill "$(cat "$LAB/ghapi.pid")" 2>/dev/null || true
}

case "${1:-}" in
    up) up ;; down) down ;;
    *) echo "usage: $0 up|down" >&2; exit 2 ;;
esac
