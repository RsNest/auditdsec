#!/bin/bash
# Real Docker, real Caddy, the real agent image: does the panel stay reachable
# when the Compose files change under it?
#
# It reproduces the 502 reported from a server (the proxy in the host network
# waiting on 127.0.0.1:<port>, the agent recreated in a bridge network), shows
# that the installer now keeps the file set in COMPOSE_FILE, and walks through
# the operations that used to lose it: first install, a plain
# `docker compose up -d`, update, restore from an older saved configuration,
# a change of mode, a non-default upstream port, and a refused change.
#
# Run as ROOT on a disposable Linux machine or inside a privileged docker:dind
# container (see launch.sh): it starts containers named auditdsec and
# auditdsec-caddy and removes them (and their volumes) at the end. Never on a
# machine that has a real installation. It needs bash, curl, openssl and
# python3 besides Docker with Compose.
#
#   AUDITDSEC_LAB_IMAGE   an agent image built from THIS tree (required)
#   CADDY_IMAGE           default caddy:2.10-alpine (must be present or pullable)
#
# NOT covered here: Let's Encrypt (the lab uses mode selfsigned, which shares
# deploy/compose.proxy.yml with domain and ip), the enforcing image (NET_ADMIN),
# systemd for the control service. The Compose configuration of those is
# checked, not started: see docs/VERIFY.md.
set -u

REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
LAB="${LAB:-/tmp/compose-consistency}"
WORK="$LAB/work"
IMAGE_SRC="${AUDITDSEC_LAB_IMAGE:?set AUDITDSEC_LAB_IMAGE to an agent image built from this tree}"
CADDY="${CADDY_IMAGE:-caddy:2.10-alpine}"
COMMIT="$(printf compose-consistency-lab | sha1sum | cut -c1-40)"
UP=19477          # a non-default upstream port, on purpose
HP=18443          # a non-default public port
PASS=0; FAIL=0
FAILED_LIST=""
note_fail() { FAILED_LIST="$FAILED_LIST|$1"; }

[ "$(id -u)" = 0 ] || { echo "run as root (this is a lab: see the header)" >&2; exit 2; }
export COMPOSE_PROJECT_NAME=adslab NO_COLOR=1 PANEL_NO_EGRESS=1 NO_BANNER=1

say() { printf '\n== %s\n' "$*"; }
check() { # DESCRIPTION COMMAND...
    local d="$1"; shift
    if "$@" >/dev/null 2>&1; then PASS=$((PASS + 1)); printf '  ok    %s\n' "$d"; else FAIL=$((FAIL + 1)); printf '  FAIL  %s\n' "$d"; fi
}
equal() { # DESCRIPTION GOT EXPECTED
    if [ "$2" = "$3" ]; then PASS=$((PASS + 1)); printf '  ok    %s\n' "$1"; else FAIL=$((FAIL + 1)); note_fail "$1 (got <$2>, expected <$3>)"; printf '  FAIL  %s (got <%s>, expected <%s>)\n' "$1" "$2" "$3"; fi
}
contains() { # DESCRIPTION TEXT NEEDLE
    case "$2" in *"$3"*) PASS=$((PASS + 1)); printf '  ok    %s\n' "$1" ;; *) FAIL=$((FAIL + 1)); note_fail "$1"; printf '  FAIL  %s (no <%s> in <%s>)\n' "$1" "$3" "$(printf '%s' "$2" | tail -c 400)" ;; esac
}

netmode() { docker inspect -f '{{.HostConfig.NetworkMode}}' "$1" 2>/dev/null; }
code() { local c; c="$(curl -sSk --noproxy '*' -o /dev/null -w '%{http_code}' --max-time 5 "$1" 2>/dev/null)"; printf '%s' "${c:-000}"; }
backend() { code "http://127.0.0.1:$UP/api/v1/setup/state"; }
front() { code "https://127.0.0.1:$HP/"; }
health() { docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' auditdsec 2>/dev/null; }
env_val() { sed -n "s/^$1='\(.*\)'$/\1/p" "$WORK/.env" | tail -n 1; }
install() { (cd "$WORK" && ./install.sh --lang en --yes --no-build --no-external-check "$@") ; }
wait_for() { # SECONDS COMMAND...
    local n="$1"; shift
    while [ "$n" -gt 0 ]; do "$@" >/dev/null 2>&1 && return 0; sleep 2; n=$((n - 2)); done
    return 1
}
healthy() { [ "$(health)" = healthy ]; }
page_ok() { [ "$(front)" = 200 ] && [ "$(backend)" = 200 ]; }
backend_ok() { [ "$(backend)" = 200 ]; }

cleanup() {
    (cd "$WORK" 2>/dev/null && docker compose down -v --remove-orphans >/dev/null 2>&1) || true
    docker rm -f auditdsec auditdsec-caddy >/dev/null 2>&1 || true
    docker volume rm adslab_auditdsec-state adslab_caddy-data adslab_caddy-config adslab_panel-certs >/dev/null 2>&1 || true
}
trap 'rc=$?; [ -z "${GITHUB_ACTIONS:-}" ] || [ "$rc" = 0 ] || echo "::error title=compose-consistency::exited with $rc at line $LINENO (failed so far: $FAILED_LIST)"; cleanup' EXIT

# ---------------------------------------------------------------- set up ---
say "Preparing a copy of the installation in $WORK"
cleanup
rm -rf "$LAB"; mkdir -p "$WORK"
(cd "$REPO" && tar --exclude=.git --exclude=bin -cf - .) | tar -xf - -C "$WORK"
printf '%s\n' "$COMMIT" > "$WORK/deploy/source-commit"
docker image inspect "$IMAGE_SRC" >/dev/null 2>&1 || docker pull -q "$IMAGE_SRC" >/dev/null
docker tag "$IMAGE_SRC" "ghcr.io/rsnest/auditdsec:sha-$COMMIT"
docker image inspect "$CADDY" >/dev/null 2>&1 || docker pull -q "$CADDY" >/dev/null
printf "AUDITDSEC_TG_TOKEN='123:lab'\nAUDITDSEC_TG_CHAT_ID='42'\nAUDITSEC_LOG_DIR='%s/logs'\n" "$LAB" > "$WORK/.env"
mkdir -p "$LAB/logs"; chmod 0750 "$LAB/logs"
mkdir -p /var/log/audit

say "A. First install: selfsigned, upstream $UP, public port $HP, with proxy variables set"
out="$(cd "$WORK" && HTTPS_PROXY=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 https_proxy=http://127.0.0.1:9 http_proxy=http://127.0.0.1:9 \
    ./install.sh --lang en --yes --no-build --no-external-check --mode selfsigned --site 127.0.0.1 --https-port "$HP" --upstream-port "$UP" 2>&1)"; rc=$?
equal "install exits 0" "$rc" 0
if [ "$rc" != 0 ]; then
    printf '%s
' "$out" | sed 's/^/      | /' | head -80
    docker ps -a --format '      | container {{.Names}} {{.Status}}' ; docker logs --tail 30 auditdsec 2>&1 | sed 's/^/      | agent: /'
    docker logs --tail 30 auditdsec-caddy 2>&1 | sed 's/^/      | caddy: /'
fi
contains "the result says the panel runs" "$out" "auditdsec is running"
equal "agent network mode" "$(netmode auditdsec)" host
equal "proxy network mode" "$(netmode auditdsec-caddy)" host
equal "backend answers on 127.0.0.1:$UP" "$(backend)" 200
equal "the panel answers through Caddy" "$(front)" 200
equal "nothing listens on the default 9477" "$(code http://127.0.0.1:9477/)" 000
check "the agent's own port is not published" test -z "$(docker inspect -f '{{json .NetworkSettings.Ports}}' auditdsec | tr -d '{}')"
check "the agent becomes healthy (its web server answers)" wait_for 120 healthy
contains "COMPOSE_FILE is saved in .env" "$(env_val COMPOSE_FILE)" "deploy/compose.proxy.yml"
equal "the saved list starts with the base file" "$(env_val COMPOSE_FILE | cut -d: -f1)" docker-compose.yml
check ".env stays private" test "$(stat -c %a "$WORK/.env")" = 600
check ".env holds no secret in COMPOSE_FILE" test -z "$(env_val COMPOSE_FILE | grep -E 'token|password|pbkdf2')"
echo "lab-marker" | docker run --rm -i -v adslab_auditdsec-state:/s alpine sh -c 'cat > /s/lab-marker'

say "B. The loss itself: the agent is recreated from docker-compose.yml alone (what a plain compose command did before)"
(cd "$WORK" && env -u COMPOSE_FILE -u COMPOSE_PATH_SEPARATOR docker compose -f docker-compose.yml up -d --force-recreate --no-deps auditdsec >/dev/null 2>&1)
sleep 6
equal "the proxy is still in the host network" "$(netmode auditdsec-caddy)" host
nm="$(netmode auditdsec)"
check "the agent is no longer in the host network (got $nm)" test "$nm" != host
equal "Caddy answers 502 (the reported symptom)" "$(front)" 502
equal "nothing answers on the upstream address" "$(backend)" 000
out="$(cd "$WORK" && ./install.sh --lang en --yes --no-build --no-external-check --action check 2>&1)"; rc=$?
check "check exits non-zero" test "$rc" != 0
printf "%s
" "$out" | sed "s/^/      | /" | head -40
contains "check says what is wrong" "$out" "The agent is running, but the panel is not reachable"
contains "check names the proxy's expectation" "$out" "Caddy expects the upstream 127.0.0.1:$UP in the host network"
contains "check names the agent's network" "$out" "the agent runs in the $nm network"
contains "check names the fix" "$out" "--action repair"
contains "check prints a trace ID" "$out" "Trace:"

say "C. Repair: the saved configuration is started with all its files; data and the proxy's certificate are kept"
cert_before="$(docker exec auditdsec-caddy sh -c 'ls /data/caddy/pki/authorities/local/root.crt && sha256sum /data/caddy/pki/authorities/local/root.crt' 2>/dev/null | tail -1)"
out="$(cd "$WORK" && ./install.sh --lang en --yes --no-build --no-external-check --action repair 2>&1)"; rc=$?
equal "repair exits 0" "$rc" 0
equal "agent network mode after repair" "$(netmode auditdsec)" host
equal "the panel answers through Caddy again" "$(front)" 200
equal "the state volume was kept" "$(docker run --rm -v adslab_auditdsec-state:/s alpine cat /s/lab-marker 2>/dev/null)" lab-marker
equal "the proxy's certificate authority was kept" "$(docker exec auditdsec-caddy sh -c 'sha256sum /data/caddy/pki/authorities/local/root.crt' 2>/dev/null | tail -1)" "$cert_before"

say "D. A plain 'docker compose up -d' in the directory now keeps the setup (COMPOSE_FILE from .env)"
(cd "$WORK" && env -u COMPOSE_FILE docker compose up -d --force-recreate >/dev/null 2>&1)
check "the agent becomes healthy again" wait_for 120 healthy
equal "agent network mode after a plain compose up" "$(netmode auditdsec)" host
equal "proxy network mode after a plain compose up" "$(netmode auditdsec-caddy)" host
check "the panel answers through Caddy" wait_for 40 page_ok
(cd "$WORK" && env -u COMPOSE_FILE docker compose pull --quiet >/dev/null 2>&1; env -u COMPOSE_FILE docker compose up -d >/dev/null 2>&1)
equal "and after compose pull + up" "$(netmode auditdsec)" host

say "E. An installation from before COMPOSE_FILE existed (its .env has none): the installer's run brings it in"
sed -i '/^COMPOSE_FILE=/d;/^COMPOSE_PATH_SEPARATOR=/d' "$WORK/.env" "$WORK/.env.last-good"
check "the saved last-good configuration has no COMPOSE_FILE (as an old one)" test -z "$(sed -n 's/^COMPOSE_FILE=//p' "$WORK/.env.last-good")"
(cd "$WORK" && env -u COMPOSE_FILE docker compose up -d --force-recreate --no-deps auditdsec >/dev/null 2>&1)
sleep 6
check "on such an installation a plain compose up still loses the proxy settings (the old behaviour)" test "$(front)" = 502
out="$(cd "$WORK" && ./install.sh --lang en --yes --no-build --no-external-check --restore 2>&1)"; rc=$?
equal "restore of an old saved configuration exits 0" "$rc" 0
contains "COMPOSE_FILE is back after the restore" "$(env_val COMPOSE_FILE)" "deploy/compose.proxy.yml"
equal "the panel answers after the restore" "$(front)" 200

say "F. Update: the same files, a new run"
out="$(cd "$WORK" && ./install.sh --lang en --yes --no-build --no-external-check --action update 2>&1)"; rc=$?
equal "update exits 0" "$rc" 0
equal "the panel answers after the update" "$(front)" 200
equal "agent network mode after the update" "$(netmode auditdsec)" host
contains "the result says the panel runs" "$out" "auditdsec is running"

say "G. A change that would break the networking is refused before anything is touched, and the previous setup keeps running"
cat > "$LAB/break.yml" <<EOF
services:
  auditdsec:
    network_mode: bridge
    ports: ["$UP:$UP"]
EOF
out="$(cd "$WORK" && PANEL_COMPOSE_EXTRA="$LAB/break.yml" ./install.sh --lang en --yes --no-build --no-external-check --action update 2>&1)"; rc=$?
check "the broken update exits non-zero" test "$rc" != 0
contains "it says why, with the values" "$out" "would not work"
contains "it names the network mode" "$out" "is not in the host network"
contains "it says the agent's port must stay on loopback" "$out" "publishes ports"
equal "the previous configuration is running again" "$(netmode auditdsec)" host
equal "the panel answers" "$(front)" 200
check "COMPOSE_FILE was not left with the broken overlay" test -z "$(env_val COMPOSE_FILE | grep break.yml)"
check "nothing is published on 0.0.0.0:$UP" test -z "$(docker port auditdsec 2>/dev/null)"

say "H. Switching to an SSH tunnel removes the proxy and the stale files from COMPOSE_FILE"
out="$(cd "$WORK" && ./install.sh --lang en --yes --no-build --no-external-check --action tunnel 2>&1)"; rc=$?
equal "the switch exits 0" "$rc" 0
check "the proxy container is gone" test -z "$(docker ps -aq -f name=auditdsec-caddy)"
equal "the agent stays in the host network" "$(netmode auditdsec)" host
equal "the backend answers on loopback" "$(backend)" 200
check "COMPOSE_FILE no longer names the proxy" test -z "$(env_val COMPOSE_FILE | grep proxy)"
contains "COMPOSE_FILE names the tunnel overlay" "$(env_val COMPOSE_FILE)" "deploy/compose.tunnel.yml"
(cd "$WORK" && env -u COMPOSE_FILE docker compose up -d --force-recreate >/dev/null 2>&1)
check "a plain compose up in tunnel mode keeps the loopback upstream" wait_for 60 backend_ok
check "and starts no proxy" test -z "$(docker ps -aq -f name=auditdsec-caddy)"

say "I. Back to the public setup"
out="$(cd "$WORK" && ./install.sh --lang en --yes --no-build --no-external-check --mode selfsigned --site 127.0.0.1 --https-port "$HP" --upstream-port "$UP" 2>&1)"; rc=$?
equal "the switch exits 0" "$rc" 0
equal "proxy network mode" "$(netmode auditdsec-caddy)" host
equal "the panel answers through Caddy" "$(front)" 200
equal "the state volume survived every step" "$(docker run --rm -v adslab_auditdsec-state:/s alpine cat /s/lab-marker 2>/dev/null)" lab-marker

say "J. The control service link is kept in the saved file list"
(cd "$WORK" && ./install.sh --lang en --yes --no-build --no-external-check --enable-panel-control >/dev/null 2>&1)
contains "COMPOSE_FILE names the control overlay" "$(env_val COMPOSE_FILE)" "deploy/compose.control.yml"
check "the agent keeps the control socket setting after a plain compose up" bash -c "cd '$WORK' && env -u COMPOSE_FILE docker compose up -d --force-recreate >/dev/null 2>&1; docker inspect -f '{{json .Config.Env}}' auditdsec | grep -q AUDITDSEC_CTL_SOCKET"
equal "still in the host network" "$(netmode auditdsec)" host

say "Result"
printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
