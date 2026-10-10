# Sourced by the scenario scripts. Provides:
#   reset            remove everything a previous scenario left (containers, volumes, work dir)
#   inst ARGS...     run ./install.sh in the work copy against the real Docker daemon
#   dc ARGS...       docker compose with the files install.sh used (reads PANEL_MODE etc. from .env)
# shellcheck shell=bash
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
LAB="${LAB:-/tmp/auditdsec-lab}"
WORK="$LAB/work"
export COMPOSE_PROJECT_NAME=e2e
export E2E_AUDIT_DIR="$LAB/audit"
export PANEL_COMPOSE_EXTRA="$WORK/scripts/e2e/real/compose.test.yml"
export PANEL_ACME_URL_STAGING="https://localhost:14000/dir"
export PANEL_ACME_URL_PRODUCTION="https://localhost:14001/dir"
export PANEL_ACME_CA_ROOT="$LAB/acme-ca.pem"
export NO_COLOR=1
export PANEL_RECONCILE_SECONDS=5
PW_FILE="$LAB/pw.txt"
# shellcheck disable=SC2016
printf 'A-long-test-password-with-$dollar"quote\\slash\n' > "$PW_FILE"

reset() {
    docker ps -aq --filter name=auditdsec | xargs -r docker rm -f >/dev/null 2>&1 || true
    docker volume ls -q --filter name=e2e_ | xargs -r docker volume rm -f >/dev/null 2>&1 || true
    rm -rf "$WORK"; mkdir -p "$WORK" "$E2E_AUDIT_DIR"
    : > "$E2E_AUDIT_DIR/audit.log"
    (cd "$REPO" && tar --exclude=.git -cf - .) | tar -xf - -C "$WORK"
    printf "AUDITDSEC_TG_TOKEN='123:abc'\nAUDITDSEC_TG_CHAT_ID='42'\n" > "$WORK/.env"
    chmod 600 "$WORK/.env"
}

# DEFAULT_ACCOUNT=1 leaves the password out, as a person who just runs ./install.sh does.
inst() {
    if [ "${DEFAULT_ACCOUNT:-}" = 1 ]; then
        (cd "$WORK" && ./install.sh --no-build --yes --no-enforce --no-external-check "$@")
    else
        (cd "$WORK" && ./install.sh --no-build --yes --no-enforce --no-external-check --password-file "$PW_FILE" "$@")
    fi
}

dc() { (cd "$WORK" && docker compose "$@"); }
