#!/bin/bash
# Runs run.sh inside a throw-away privileged docker:dind container that plays
# the server, so nothing touches the Docker you are using. It needs an agent
# image built from this tree on the Docker you are using:
#
#   docker build -f deploy/Dockerfile --target minimal -t auditdsec:lab .
#   AUDITDSEC_LAB_IMAGE=auditdsec:lab scripts/e2e/compose-consistency/launch.sh
#
# The container is removed at the end (set KEEP=1 to keep it for a look).
set -euo pipefail
export MSYS_NO_PATHCONV=1
REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
IMG="${AUDITDSEC_LAB_IMAGE:?set AUDITDSEC_LAB_IMAGE}"
CADDY="${CADDY_IMAGE:-caddy:2.10-alpine}"
NAME="${LAB_NAME:-adsec-lab-compose}"

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker image inspect "$CADDY" >/dev/null 2>&1 || docker pull -q "$CADDY" >/dev/null
docker run -d --privileged --name "$NAME" docker:29-dind >/dev/null
trap '[ "${KEEP:-0}" = 1 ] || docker rm -f "$NAME" >/dev/null 2>&1' EXIT
for _ in $(seq 1 60); do docker exec "$NAME" docker info >/dev/null 2>&1 && break; sleep 1; done
docker exec "$NAME" docker info >/dev/null
docker exec "$NAME" apk add --no-cache bash curl openssl python3 util-linux coreutils >/dev/null
docker save "$IMG" "$CADDY" alpine:3.21 2>/dev/null | docker exec -i "$NAME" docker load >/dev/null
(cd "$REPO" && tar --exclude=.git --exclude=bin -cf - .) | docker exec -i "$NAME" sh -c 'rm -rf /repo && mkdir /repo && tar -xf - -C /repo'
docker exec -e AUDITDSEC_LAB_IMAGE="$IMG" -e CADDY_IMAGE="$CADDY" "$NAME" bash /repo/scripts/e2e/compose-consistency/run.sh
