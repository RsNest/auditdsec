#!/bin/bash
# scenarios.sh [NAME...] — ./install.sh against a real Docker daemon on the
# stand from lab.sh (run `lab.sh up` first, on the same disposable machine).
# Prints PASS/FAIL per assertion; exits non-zero if anything failed.
#
# Scenarios: ip_auto setup_persists manual_port port_in_use firewall_timeout
#            auto_skips_blocked no_probe dns_mismatch domain challenge_blocked
#            domain_alpn no_external persistence_fails
# shellcheck disable=SC2016
set -u
# shellcheck source=env.sh
source "$(dirname "$0")/env.sh"

PASS=0; FAIL=0; RC=0; OUT=""
pass() { PASS=$((PASS + 1)); printf '  PASS  %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL  %s\n' "$1"; [ -z "${2:-}" ] || printf '        %s\n' "$2"; }
step() { printf '\n== %s\n' "$*"; }
has()  { grep -qF -- "$1" <<<"$OUT"; }
expect_rc()      { if [ "$RC" = "$1" ]; then pass "exit status $1"; else fail "exit status $1" "got $RC (log: $OUTDIR/$LABEL.log)"; fi; }
expect_out()     { if has "$1"; then pass "output has: $1"; else fail "output has: $1" "log: $OUTDIR/$LABEL.log"; fi; }
expect_out_not() { if ! has "$1"; then pass "output lacks: $1"; else fail "output lacks: $1" "log: $OUTDIR/$LABEL.log"; fi; }
expect()         { local d="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else fail "$d"; fi; }

LABEL=""
inst() { # LABEL ARGS... — run the installer in the work copy, keep the output
    LABEL="$1"; shift
    OUT="$(cd "$WORK" && ./install.sh --lang en --yes "$@" 2>&1)"; RC=$?
    printf '%s\n' "$OUT" > "$OUTDIR/$LABEL.log"
}
last_link() { grep -E '^  Link' <<<"$OUT" | tail -n 1; }
env_val() { grep -E "^$1=" "$WORK/.env" | tail -n 1 | cut -d= -f2- | tr -d "'"; }

api() { # METHOD URL [TOKEN] [JSON]
    curl -sS --noproxy '*' --cacert "$LAB/root.pem" -X "$1" -H 'X-Requested-With: auditdsec' \
        -H 'Content-Type: application/json' ${3:+-H "Authorization: Bearer $3"} ${4:+--data-binary "$4"} "$2" 2>/dev/null
}
token_of() { sed -n 's/.*"token":"\([^"]*\)".*/\1/p'; }
agent_logs_have() { docker logs auditdsec 2>&1 | grep -qF -- "$1"; }
served_ok() { curl -sS --noproxy '*' --cacert "$LAB/root.pem" -o /dev/null -w '%{http_code}' "$1/" 2>/dev/null | grep -q 200; }

# ------------------------------------------------------------- scenarios --

s_ip_auto() {
    step "ip mode, automatic port: 443 free and reachable -> published"
    reset
    inst ip_auto --mode ip --site "$VPS" --public-ip "$VPS" "${PROBE[@]}"
    expect_rc 0
    expect_out "The panel is published and waits for first-time setup."
    expect_out "port 443: free here and reached from outside"
    expect_out "port 80 reached from outside (HTTP-01)"
    expect_out "reached from outside, certificate verified"
    expect_out "First login:  admin / admin"
    if [ "$(last_link)" = "  Link: https://$VPS" ]; then pass "link is the last line, without :443"; else fail "link without :443" "$(last_link)"; fi
    expect_out_not "$TOKEN"
    expect ".env PANEL_HTTPS_PORT=443" [ "$(env_val PANEL_HTTPS_PORT)" = 443 ]
    expect ".env PANEL_PUBLIC_URL" [ "$(env_val PANEL_PUBLIC_URL)" = "https://$VPS" ]
    expect ".env PANEL_UPSTREAM_PORT, no PANEL_PORT" sh -c "grep -q '^PANEL_UPSTREAM_PORT=' '$WORK/.env' && ! grep -q '^PANEL_PORT=' '$WORK/.env'"
    expect "no probe listener left" sh -c '! docker ps -a --format "{{.Names}}" | grep -q auditdsec-probe-listen'
    expect "agent logs the public URL" agent_logs_have '"public_url":"https://'"$VPS"'"'
}

s_setup_persists() {
    step "after first-time setup, a re-run keeps the owner's credentials"
    local url="https://$VPS" tok
    tok="$(api POST "$url/api/v1/login" "" '{"login":"admin","password":"admin"}' | token_of)"
    expect "admin/admin gives a setup token" [ -n "$tok" ]
    expect "a setup token cannot read events" sh -c "! curl -sS --cacert '$LAB/root.pem' -H 'Authorization: Bearer $tok' '$url/api/v1/events' | grep -q '\"events\"'"
    expect "setup completes" sh -c "curl -sS -o /dev/null -w '%{http_code}' --cacert '$LAB/root.pem' -X POST -H 'X-Requested-With: auditdsec' -H 'Content-Type: application/json' -H 'Authorization: Bearer $tok' --data-binary '{\"login\":\"owner\",\"password\":\"Goodpass1\",\"password_confirm\":\"Goodpass1\",\"keep_admin_confirmed\":false}' '$url/api/v1/setup/complete' | grep -q 204"
    inst setup_rerun --mode ip --site "$VPS" --public-ip "$VPS" "${PROBE[@]}"
    expect_rc 0
    expect_out "The panel is published."
    expect_out_not "First login"
    expect_out "admin / admin no longer works"
    expect "admin/admin is refused" sh -c "! curl -sS --cacert '$LAB/root.pem' -X POST -H 'X-Requested-With: auditdsec' -H 'Content-Type: application/json' --data-binary '{\"login\":\"admin\",\"password\":\"admin\"}' '$url/api/v1/login' | grep -q token"
    expect "owner signs in" sh -c "curl -sS --cacert '$LAB/root.pem' -X POST -H 'X-Requested-With: auditdsec' -H 'Content-Type: application/json' --data-binary '{\"login\":\"owner\",\"password\":\"Goodpass1\"}' '$url/api/v1/login' | grep -q token"
}

s_manual_port() {
    step "ip mode, a port given by hand -> the link carries it"
    reset
    inst manual_port --mode ip --site "$VPS" --public-ip "$VPS" --https-port 27431 "${PROBE[@]}"
    expect_rc 0
    if [ "$(last_link)" = "  Link: https://$VPS:27431" ]; then pass "link has :27431"; else fail "link has :27431" "$(last_link)"; fi
    expect "the panel serves a verified certificate on 27431" served_ok "https://$VPS:27431"
    expect "nothing serves the panel on 443" sh -c "! curl -s --max-time 3 -k https://$VPS/ >/dev/null"
    expect "agent logs the public URL with the port" agent_logs_have '"public_url":"https://'"$VPS"':27431"'
}

s_port_in_use() {
    step "a port given by hand is in use -> port_in_use, nothing replaced"
    reset
    AUDITDSEC_PROBE_NONCE=aaaaaaaaaaaaaaaaaaaaaaaa docker run -d --name lab-blocker --network host -e AUDITDSEC_PROBE_NONCE \
        "$LAB_IMAGE" probe-listen -port 27500 -ttl 10m >/dev/null
    sleep 1
    inst port_in_use --mode ip --site "$VPS" --public-ip "$VPS" --https-port 27500 "${PROBE[@]}"
    expect_rc 10
    expect_out "FAILED: port_in_use"
    expect_out "The panel was NOT published."
    expect_out "retry:    ./install.sh"
    expect_out_not "Link: https"
    expect "the program holding the port was left alone" sh -c 'docker ps --format "{{.Names}}" | grep -q lab-blocker'
    docker rm -f lab-blocker >/dev/null 2>&1
}

s_firewall_timeout() {
    step "a port dropped by the firewall -> external_port_unreachable (timeout)"
    reset
    fw_drop 27600
    inst firewall_timeout --mode ip --site "$VPS" --public-ip "$VPS" --https-port 27600 "${PROBE[@]}"
    expect_rc 11
    expect_out "FAILED: external_port_unreachable"
    expect_out "timeout"
    expect_out "port 27600 is free here"
    expect "no container of the stack was started" sh -c '! docker ps --format "{{.Names}}" | grep -qx auditdsec'
    expect "no probe listener left" sh -c '! docker ps -a --format "{{.Names}}" | grep -q auditdsec-probe-listen'
}

s_auto_skips_blocked() {
    step "automatic port with 443 dropped -> a random high port"
    reset
    fw_drop 443
    inst auto_skips_blocked --mode ip --site "$VPS" --public-ip "$VPS" --https-port auto "${PROBE[@]}"
    expect_rc 0
    expect_out "443: timeout"
    local p; p="$(env_val PANEL_HTTPS_PORT)"
    expect "picked a port in 20000-29999 ($p)" sh -c "[ '$p' -ge 20000 ] && [ '$p' -le 29999 ]"
    if [ "$(last_link)" = "  Link: https://$VPS:$p" ]; then pass "link has :$p"; else fail "link has :$p" "$(last_link)"; fi
}

s_no_probe() {
    step "no RemoteProbe provider -> external_check_unavailable"
    reset
    inst no_probe --mode ip --site "$VPS" --public-ip "$VPS"
    expect_rc 12
    expect_out "FAILED: external_check_unavailable"
    expect_out "--no-external-check"
}

s_dns_mismatch() {
    step "DNS that does not lead (only) here -> dns_mismatch"
    reset
    inst dns_wrong --mode domain --site wrong.test --email a@b.test --public-ip "$VPS" "${PROBE[@]}"
    expect_rc 13
    expect_out "FAILED: dns_mismatch"
    expect_out "10.9.9.9"
    inst dns_mixed --mode domain --site MIXED.test. --email a@b.test --public-ip "$VPS" "${PROBE[@]}"
    expect_rc 13
    expect_out "endpoint: mixed.test"
    expect_out "10.9.9.9"
}

s_domain() {
    step "domain mode on 443 -> Caddy gets a certificate, published"
    reset
    inst domain --mode domain --site panel.test --email a@b.test --public-ip "$VPS" "${PROBE[@]}"
    expect_rc 0
    expect_out "every A/AAAA record leads to this server"
    expect_out "The panel is published and waits for first-time setup."
    if [ "$(last_link)" = "  Link: https://panel.test" ]; then pass "link https://panel.test"; else fail "link https://panel.test" "$(last_link)"; fi
}

s_challenge_blocked() {
    step "ip mode with port 80 dropped -> acme_challenge_unreachable"
    reset
    fw_drop 80
    inst challenge_blocked --mode ip --site "$VPS" --public-ip "$VPS" --https-port 27431 "${PROBE[@]}"
    expect_rc 14
    expect_out "FAILED: acme_challenge_unreachable"
    expect_out "the CA only connects to 80 or 443"
}

s_domain_alpn() {
    step "domain on 443 with port 80 dropped -> TLS-ALPN-01 instead, published"
    reset
    fw_drop 80
    inst domain_alpn --mode domain --site panel.test --email a@b.test --public-ip "$VPS" --https-port 443 "${PROBE[@]}"
    expect_rc 0
    expect_out "Caddy uses TLS-ALPN-01 on 443 instead"
    expect_out "The panel is published"
}

s_no_external() {
    step "--no-external-check -> started, but never 'published'"
    reset
    inst no_external --mode ip --site "$VPS" --public-ip "$VPS" --https-port 27431 --no-external-check
    expect_rc 0
    expect_out "NOT verified from outside (--no-external-check). Not published."
    expect_out "Link (NOT published): https://$VPS:27431"
    expect_out_not "The panel is published"
}

s_persistence_fails() {
    # A read-only state volume stops the whole agent (its event store lives
    # there too), so this surfaces as service_start_failed. The narrower case,
    # an agent that runs but cannot save credentials (state "locked" ->
    # bootstrap_persistence_failed), is covered by the Go test
    # TestUnwritableStateDirStopsFirstTimeSetup.
    step "state volume read-only -> not published, no admin/admin offered"
    reset
    cat > "$WORK/ro-state.yml" <<'EOF'
services:
  auditdsec:
    volumes:
      - auditdsec-state:/var/lib/auditdsec:ro
EOF
    PANEL_COMPOSE_EXTRA="$PANEL_COMPOSE_EXTRA $WORK/ro-state.yml" \
        inst persistence_fails --mode ip --site "$VPS" --public-ip "$VPS" --https-port 27431 "${PROBE[@]}"
    expect_rc 17
    expect_out "FAILED: service_start_failed"
    expect_out_not "First login"
    expect_out_not "The panel is published"
}


# ---------------------------------------------------------- images --

LAB_IMAGE="$AUDITDSEC_IMAGE_REPO/auditdsec:sha-$LAB_COMMIT"

# push_image COMMIT — publish the lab image under another commit's tag, as
# GitHub Actions would after building that commit.
push_image() {
    docker tag "$LAB_IMAGE" "$AUDITDSEC_IMAGE_REPO/auditdsec:sha-$1"
    docker push -q "$AUDITDSEC_IMAGE_REPO/auditdsec:sha-$1" >/dev/null
}

s_image_pulled() {
    step "the installer downloads the image of its commit and never builds"
    reset
    docker image rm -f "$LAB_IMAGE" >/dev/null 2>&1 || true   # only the registry has it
    inst image_pulled --mode ip --site "$VPS" --public-ip "$VPS" --https-port 27431 --no-external-check
    expect_rc 0
    expect_out "Downloading the agent image for commit ${LAB_COMMIT:0:12}"
    expect_out_not "Building"
    expect "the image was pulled from the registry" docker image inspect "$LAB_IMAGE"
    expect ".env names the image of this commit" [ "$(env_val AUDITDSEC_IMAGE)" = "$LAB_IMAGE" ]
    expect "the running agent is that image" sh -c "[ \"\$(docker inspect -f '{{.Config.Image}}' auditdsec)\" = '$LAB_IMAGE' ]"
    expect "the agent in it is that commit" sh -c "docker run --rm '$LAB_IMAGE' version | grep -q 'commit $LAB_COMMIT'"
    expect_out "commit $LAB_COMMIT"
    expect_out "digest sha256:"
    expect "no image was built on the server" sh -c '! docker images --format "{{.Repository}}:{{.Tag}}" | grep -q "^auditdsec:local"'
}

s_image_missing() {
    step "no image for this commit -> image_unavailable, nothing changed"
    reset
    local other; other="$(printf other | sha1sum | cut -c1-40)"
    printf '%s\n' "$other" > "$WORK/deploy/source-commit"
    ghapi none
    inst image_missing --mode ip --site "$VPS" --public-ip "$VPS" --https-port 27431 --no-external-check
    expect_rc 19
    expect_out "FAILED: image_unavailable"
    expect_out "--build-local"
    expect_out_not "Building"
    expect "nothing was started" sh -c '! docker ps --format "{{.Names}}" | grep -qx auditdsec'
}

s_image_build_failed() {
    step "the GitHub build of this commit failed -> image_unavailable at once"
    reset
    local other; other="$(printf failed | sha1sum | cut -c1-40)"
    printf '%s\n' "$other" > "$WORK/deploy/source-commit"
    ghapi completed failure
    inst image_build_failed --mode ip --site "$VPS" --public-ip "$VPS" --https-port 27431 --no-external-check
    expect_rc 19
    expect_out "the build for this commit failed"
}

s_image_wait() {
    step "the image is still being built -> a bounded wait, then it is used"
    reset
    local other; other="$(printf later | sha1sum | cut -c1-40)"
    printf '%s\n' "$other" > "$WORK/deploy/source-commit"
    ghapi in_progress
    docker image rm -f "$AUDITDSEC_IMAGE_REPO/auditdsec:sha-$other" >/dev/null 2>&1 || true
    ( sleep 30; push_image "$other"; ghapi completed success ) &
    inst image_wait --mode ip --site "$VPS" --public-ip "$VPS" --https-port 27431 --no-external-check
    wait
    expect_rc 0
    expect_out "still being built by GitHub Actions; waiting"
    expect ".env names the later image" [ "$(env_val AUDITDSEC_IMAGE)" = "$AUDITDSEC_IMAGE_REPO/auditdsec:sha-$other" ]

    step "... and gives up after the limit with a command to retry"
    reset
    other="$(printf never | sha1sum | cut -c1-40)"
    printf '%s\n' "$other" > "$WORK/deploy/source-commit"
    ghapi in_progress
    AUDITDSEC_IMAGE_WAIT=40 inst image_wait_timeout --mode ip --site "$VPS" --public-ip "$VPS" --https-port 27431 --no-external-check
    expect_rc 19
    expect_out "still being built after"
    expect_out "retry:    ./install.sh"
}

s_unstamped() {
    step "a tree that cannot tell its commit -> refused, no guessing"
    reset
    printf '$Format:%%H$\n' > "$WORK/deploy/source-commit"
    inst unstamped --mode ip --site "$VPS" --public-ip "$VPS" --https-port 27431 --no-external-check
    expect_rc 1
    expect_out "cannot tell which commit this code is"
}

# The previous release built its image on the server (auditdsec:0.1.0) and
# wrote no image to .env. Updating must keep .env, the credentials, the
# events and the certificates, and remember the old image for going back.
s_update_from_legacy() {
    step "update an installation made by the previous release"
    reset
    [ -d "$LAB/old" ] || { fail "no previous release in $LAB/old (lab sync copies it)"; return; }
    rm -rf "$WORK"; mkdir -p "$WORK"; cp -a "$LAB/old/." "$WORK/"
    printf "AUDITDSEC_TG_TOKEN='123:abc'\nAUDITDSEC_TG_CHAT_ID='42'\n" > "$WORK/.env"; chmod 600 "$WORK/.env"
    LABEL=legacy_install
    OUT="$(cd "$WORK" && AUDITDSEC_IMAGE_REPO='' ./install.sh --yes --mode ip --site "$VPS" --public-ip "$VPS" --https-port 27431 "${PROBE[@]}" 2>&1)"; RC=$?
    printf '%s\n' "$OUT" > "$OUTDIR/$LABEL.log"
    expect_rc 0
    expect "the old release built auditdsec:0.1.0 here" docker image inspect auditdsec:0.1.0
    local url="https://$VPS:27431" tok
    tok="$(api POST "$url/api/v1/login" "" '{"login":"admin","password":"admin"}' | token_of)"
    api POST "$url/api/v1/setup/complete" "$tok" '{"login":"owner","password":"Goodpass1","password_confirm":"Goodpass1","keep_admin_confirmed":false}' >/dev/null
    printf 'type=USER_AUTH msg=audit(%s.000:4242): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='"'"'op=PAM:authentication acct="root" exe="/usr/sbin/sshd" hostname=198.51.100.77 addr=198.51.100.77 terminal=ssh res=failed'"'"'\n' "$(date +%s)" >> "$E2E_AUDIT_DIR/audit.log"
    sleep 4
    local cert_before; cert_before="$(printf '' | openssl s_client -connect "$VPS:27431" 2>/dev/null | openssl x509 -noout -fingerprint -sha256)"
    cp "$WORK/.env" "$LAB/legacy.env"

    # The new code arrives next to the old .env, as `git pull` would do.
    (cd "$REPO" && tar --exclude=.git -cf - .) | tar -xf - -C "$WORK"
    printf '%s\n' "$LAB_COMMIT" > "$WORK/deploy/source-commit"
    inst update --mode ip --site "$VPS" --public-ip "$VPS" --https-port 27431 "${PROBE[@]}"
    expect_rc 0
    expect "the Telegram settings were kept" grep -q "^AUDITDSEC_TG_TOKEN='123:abc'" "$WORK/.env"
    expect ".env now names the published image" [ "$(env_val AUDITDSEC_IMAGE)" = "$LAB_IMAGE" ]
    expect "the old image is remembered for going back" [ "$(env_val PANEL_IMAGE_PREVIOUS)" = "auditdsec:0.1.0" ]
    expect_out "previous image (for going back): auditdsec:0.1.0"
    expect_out_not "First login"
    tok="$(api POST "$url/api/v1/login" "" '{"login":"owner","password":"Goodpass1"}' | token_of)"
    expect "the owner's credentials survived the update" [ -n "$tok" ]
    expect "admin/admin did not come back" sh -c "! curl -s --cacert '$LAB/root.pem' -X POST -H 'X-Requested-With: auditdsec' -H 'Content-Type: application/json' --data-binary '{\"login\":\"admin\",\"password\":\"admin\"}' '$url/api/v1/login' | grep -q token"
    expect "the stored event survived the update" sh -c "curl -s --cacert '$LAB/root.pem' -H 'Authorization: Bearer $tok' '$url/api/v1/events?limit=50' | grep -q 198.51.100.77"
    local cert_after; cert_after="$(printf '' | openssl s_client -connect "$VPS:27431" 2>/dev/null | openssl x509 -noout -fingerprint -sha256)"
    expect "the certificate was reused, not issued again" sh -c "[ -n '$cert_before' ] && [ '$cert_before' = '$cert_after' ]"
}

ALL="image_pulled image_missing image_build_failed image_wait unstamped update_from_legacy ip_auto setup_persists manual_port port_in_use firewall_timeout auto_skips_blocked no_probe dns_mismatch domain challenge_blocked domain_alpn no_external persistence_fails"

# The images, built once from this tree with the Dockerfile CI uses and
# "published" to the lab registry under LAB_COMMIT, as GitHub Actions would.
if ! docker manifest inspect --insecure "$LAB_IMAGE" >/dev/null 2>&1 || [ "${REBUILD:-}" = 1 ]; then
    step "building and publishing the images to the lab registry"
    for t in minimal enforce; do
        name=auditdsec; [ "$t" = enforce ] && name=auditdsec-enforce
        ref="$AUDITDSEC_IMAGE_REPO/$name:sha-$LAB_COMMIT"
        (cd "$REPO" && docker build -q -f deploy/Dockerfile --target "$t" \
            --build-arg VERSION="$(cat VERSION)-lab" --build-arg COMMIT="$LAB_COMMIT" -t "$ref" .) >/dev/null || exit 1
        docker push -q "$ref" >/dev/null || exit 1
    done
fi
docker pull -q "$LAB_IMAGE" >/dev/null

# shellcheck disable=SC2048,SC2086
for s in ${*:-$ALL}; do "s_$s"; done
[ "${KEEP:-}" = 1 ] || reset >/dev/null 2>&1
iptables -F LABFW 2>/dev/null || true
printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
