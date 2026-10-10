#!/bin/bash
# run.sh MODE [install.sh args] — runs ./install.sh against a stand-in for the
# Docker daemon, on a fresh copy of the repo. See docs/VERIFY.md.
#   needs: docker CLI (for the real `docker compose config`), go, python3, openssl,
#          curl; caddy on PATH or CADDY_BIN for the domain/ip/selfsigned modes.
set -u
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
export E2E_STATE="${E2E_STATE:-/tmp/auditdsec-e2e}"
mode="${1:?usage: run.sh tunnel|selfsigned|domain|ip [install.sh args]}"; shift
"$REPO/scripts/e2e/stop.sh"
rm -rf "$E2E_STATE"; mkdir -p "$E2E_STATE/work"
(cd "$REPO" && tar --exclude=.git --exclude=bin -cf - .) | tar -xf - -C "$E2E_STATE/work"
(cd "$REPO" && CGO_ENABLED=0 go build -o "$E2E_STATE/auditdsec" ./cmd/auditdsec) || exit 1
cd "$E2E_STATE/work" || exit 1
printf "AUDITDSEC_TG_TOKEN='123:abc'\nAUDITDSEC_TG_CHAT_ID='42'\n" > .env
# shellcheck disable=SC2016
printf 'a-long-test-password-with-$dollar"quote\\slash\n' > "$E2E_STATE/pw.txt"
export DOCKER="$REPO/scripts/e2e/fakedocker" E2E_REPO="$E2E_STATE/work"
./install.sh --lang en --mode "$mode" --password-file "$E2E_STATE/pw.txt" --yes --no-enforce --no-external-check --upstream-port "${PANEL_PORT:-19477}" "$@"
rc=$?
echo "install.sh exit=$rc"
exit $rc
