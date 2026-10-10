# Sourced by scenarios.sh and interactive.py: the stand's environment and a
# clean start. See lab.sh.
# shellcheck shell=bash
# shellcheck disable=SC2034  # VPS, PROBE, TOKEN are for the scripts that source this
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
LAB="${LAB:-/lab}"
WORK="$LAB/work"
OUTDIR="$LAB/out"; mkdir -p "$OUTDIR"

export COMPOSE_PROJECT_NAME=e2e NO_COLOR=1
export E2E_AUDIT_DIR="$LAB/audit"
export PANEL_COMPOSE_EXTRA="$WORK/scripts/e2e/real/compose.test.yml"
export PANEL_ACME_URL_PRODUCTION="https://localhost:14000/dir"
export PANEL_ACME_URL_STAGING="https://localhost:14000/dir"
export PANEL_ACME_CA_ROOT="$LAB/acme-ca.pem"
export PANEL_CACERT="$LAB/root.pem"
export PANEL_DNS_RESOLVERS="127.0.0.1:1053"
export PANEL_NO_EGRESS=1
export PANEL_RECONCILE_SECONDS=5

# Images come from the lab registry instead of ghcr.io, and "GitHub Actions"
# is the fake API whose answer a scenario sets. LAB_COMMIT is the commit the
# work copy claims to be (written into deploy/source-commit, as GitHub does
# for a source archive); the image for it is pushed by scenarios.sh.
export AUDITDSEC_IMAGE_REPO="localhost:5000/rsnest"
export AUDITDSEC_GITHUB_API="http://127.0.0.1:18080"
export AUDITDSEC_IMAGE_WAIT="${AUDITDSEC_IMAGE_WAIT:-120}"
LAB_COMMIT="$(printf stage0-lab | sha1sum | cut -c1-40)"
GHAPI_RUNS="$LAB/ghapi/repos/RsNest/auditdsec/actions/runs"

VPS="$(cat "$LAB/vps-ip")"
OUTSIDE="$(cat "$LAB/outside-subnet")"
PROBE=(--probe-url https://127.0.0.1:8443 --probe-token-file "$LAB/probe-token" --probe-cacert "$LAB/probe-ca.pem")
TOKEN="$(cat "$LAB/probe-token")"
# A firewall on the VPS for traffic from the "outside" network only.
fw_reset() {
    iptables -N LABFW 2>/dev/null || true
    iptables -F LABFW
    iptables -C INPUT -s "$OUTSIDE" -j LABFW 2>/dev/null || iptables -I INPUT -s "$OUTSIDE" -j LABFW
}
fw_drop() { iptables -A LABFW -p tcp --dport "$1" -j DROP; }

reset() {
    docker ps -aq --filter name=auditdsec | xargs -r docker rm -f >/dev/null 2>&1 || true
    docker rm -f lab-blocker >/dev/null 2>&1 || true
    docker volume ls -q --filter name=e2e_ | xargs -r docker volume rm -f >/dev/null 2>&1 || true
    fw_reset
    rm -rf "$WORK"; mkdir -p "$WORK" "$E2E_AUDIT_DIR"
    : > "$E2E_AUDIT_DIR/audit.log"
    (cd "$REPO" && tar --exclude=.git -cf - .) | tar -xf - -C "$WORK"
    printf '%s\n' "$LAB_COMMIT" > "$WORK/deploy/source-commit"
    ghapi completed success
    printf "AUDITDSEC_TG_TOKEN='123:abc'\nAUDITDSEC_TG_CHAT_ID='42'\n" > "$WORK/.env"
    chmod 600 "$WORK/.env"
}

# ghapi STATUS [CONCLUSION] — what the fake GitHub API says about the build.
ghapi() {
    if [ "$1" = none ]; then
        printf '{"total_count": 0, "workflow_runs": []}\n' > "$GHAPI_RUNS"
    else
        printf '{"total_count": 1, "workflow_runs": [{"status": "%s", "conclusion": "%s"}]}\n' "$1" "${2:-null}" > "$GHAPI_RUNS"
    fi
}
