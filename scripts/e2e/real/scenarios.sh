#!/bin/bash
# scenarios.sh [NAME...] — runs install.sh against a REAL Docker daemon, with
# the local images and ACME servers from lab.sh. Prints PASS/FAIL per
# assertion and exits non-zero if anything failed.
#
#   lab.sh up && scenarios.sh              # everything
#   scenarios.sh ip_promote untrusted      # some
#
# Scenarios: tunnel default_account selfsigned ip_promote domain_promote ip_change domain_to_ip
#            domain_to_ip_fails restore untrusted reuse renew_and_reload
# shellcheck disable=SC2016
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=env.sh
source "$HERE/env.sh"

OUTDIR="$LAB/out"; mkdir -p "$OUTDIR"
PASS=0; FAIL=0; RC=0; OUT=""
CERTBOT_IMG="${CERTBOT_IMAGE:-certbot/certbot:v5.8.0}"
ROOT_STAGING="$LAB/root-staging.pem"
ROOT_PRODUCTION="$LAB/root-production.pem"
PW="$(head -n 1 "$PW_FILE")"

# ------------------------------------------------------------- assertions --

pass() { PASS=$((PASS + 1)); printf '  PASS  %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL  %s\n' "$1"; [ -z "${2:-}" ] || printf '        %s\n' "$2"; }
expect() { # DESCRIPTION COMMAND...
    local desc="$1"; shift
    if "$@" >/dev/null 2>&1; then pass "$desc"; else fail "$desc"; fi
}
has()   { grep -qF -- "$1" <<<"$OUT"; }
lacks() { ! grep -qF -- "$1" <<<"$OUT"; }
expect_out()      { if has "$2"; then pass "$1"; else fail "$1" "output lacks: $2"; fi; }
expect_out_not()  { if lacks "$2"; then pass "$1"; else fail "$1" "output contains: $2"; fi; }

step() { printf '\n== %s\n' "$*"; }

# run_inst LABEL ARGS... — runs the installer, keeps its output for inspection.
run_inst() {
    local label="$1"; shift
    OUT="$(inst "$@" 2>&1)"; RC=$?
    printf '%s\n' "$OUT" > "$OUTDIR/$label.log"
}

env_val() { grep -E "^$1=" "$WORK/.env" | tail -n 1 | cut -d= -f2- | tr -d "'"; }
hash_intact() { local v re='^pbkdf2-sha256[$][0-9]+[$][^$]+[$][^$]+$'; v="$(env_val AUDITDSEC_WEB_PASSWORD_HASH)"; [[ $v =~ $re ]]; }
vol() { printf 'e2e_%s' "$1"; }
vol_exists() { docker volume inspect "$(vol "$1")" >/dev/null 2>&1; }
vol_cat() { docker run --rm -v "$(vol "$1"):/v:ro" --entrypoint cat "$CERTBOT_IMG" "/v/$2"; }
fp_of_pem() { openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2; }
disk_fp() { vol_cat "$1" fullchain.pem | fp_of_pem; }
served_fp() { printf '' | openssl s_client -connect "${1:-127.0.0.1}:443" ${2:+-servername "$2"} 2>/dev/null | fp_of_pem; }
served_san() { printf '' | openssl s_client -connect "${1:-127.0.0.1}:443" ${2:+-servername "$2"} 2>/dev/null | openssl x509 -noout -ext subjectAltName 2>/dev/null | tail -n 1 | sed "s/^ *//"; }
served_issuer() { printf '' | openssl s_client -connect "${1:-127.0.0.1}:443" ${2:+-servername "$2"} 2>/dev/null | openssl x509 -noout -issuer 2>/dev/null; }
hsts() { curl -sS --noproxy '*' --cacert "$1" -D - -o /dev/null "$2" 2>/dev/null | grep -i '^strict-transport-security' | tr -d '\r'; }
caddy_log() { docker cp auditdsec-caddy:/var/log/caddy/panel.log - 2>/dev/null | tar -xO 2>/dev/null; }
login_to() { # URL CACERT — a real sign-in with the test password
    printf '{"login":"admin","password":"%s"}' "$(printf '%s' "$PW" | sed 's/\\/\\\\/g; s/"/\\"/g')" \
        | curl -sS --noproxy '*' --cacert "$2" -X POST -H 'X-Requested-With: auditdsec' \
            -H 'Content-Type: application/json' --data-binary @- "$1/api/v1/login" 2>/dev/null
}
wait_for() { # SECONDS COMMAND...
    local n="$1" i=0; shift
    while [ "$i" -lt "$n" ]; do "$@" >/dev/null 2>&1 && return 0; i=$((i + 1)); sleep 1; done
    return 1
}
listening() { (exec 3<>"/dev/tcp/${2:-127.0.0.1}/$1") 2>/dev/null; }
lan_ip() { hostname -I | awk '{print $1}'; }
not_on_lan() { local ip; ip="$(lan_ip)"; [ -n "$ip" ] && ! listening "$1" "$ip"; }
san_is() { [ "$(served_san "$1" "${3:-}")" = "$2" ]; }
caddy_has() { caddy_log | grep -q -- "$1"; }
login_ok() { login_to "$@" | grep -q '"token"'; }
export -f listening lan_ip not_on_lan san_is served_fp served_san served_issuer fp_of_pem vol_cat vol disk_fp caddy_log caddy_has login_to login_ok
export LAB CERTBOT_IMG PW

# -------------------------------------------------------------- scenarios --

s_tunnel() {
    step "tunnel mode on the real daemon"
    reset
    run_inst tunnel --mode tunnel --port 19477
    expect "installer succeeds" test "$RC" = 0
    expect_out "the page answers" "the sign-in page answers at http://127.0.0.1:19477"
    expect_out "signed in with the chosen password" "signed in with the chosen password"
    expect "agent container is running" test "$(docker inspect -f '{{.State.Running}}' auditdsec)" = true
    expect "agent is in the host network namespace" test "$(docker inspect -f '{{.HostConfig.NetworkMode}}' auditdsec)" = host
    expect "no proxy was started" test -z "$(docker ps -q --filter name=auditdsec-caddy)"
    expect "the panel answers on loopback" listening 19477
    expect "the panel does not answer on the machine's other address" not_on_lan 19477
    expect ".env is mode 600" test "$(stat -c %a "$WORK/.env")" = 600
    expect "the hash in .env keeps its dollar signs" hash_intact
}

s_default_account() {
    step "no password given: admin/admin, changed at the first sign-in (real daemon)"
    reset
    DEFAULT_ACCOUNT=1 run_inst default --mode tunnel --port 19478
    local u=http://127.0.0.1:19478 tok body new='BrandNewPass1'
    expect "installer succeeds without a password" test "$RC" = 0
    expect_out "the installer says first-time setup is waiting" "first-time setup is waiting"
    expect_out "the summary shows the default login" "Login:    admin   Password:  admin"
    expect_out "the summary says it must be replaced" "mandatory screen"
    expect "no password hash was written to .env" test -z "$(env_val AUDITDSEC_WEB_PASSWORD_HASH)"
    api() { curl -sS --noproxy '*' -o /dev/stderr -w '%{http_code}' -X "$1" -H 'X-Requested-With: auditdsec' \
        -H 'Content-Type: application/json' ${3:+-H "Authorization: Bearer $3"} ${4:+--data-binary "$4"} "$u$2" 2>/dev/null; }
    body="$(curl -sS --noproxy '*' -X POST -H 'X-Requested-With: auditdsec' -H 'Content-Type: application/json' \
        --data-binary '{"login":"admin","password":"admin"}' "$u/api/v1/login")"
    tok="$(sed -n 's/.*"token":"\([^"]*\)".*/\1/p' <<<"$body")"
    expect "admin/admin signs in and is told to change" grep -q '"setup":true' <<<"$body"
    expect "status is refused with the setup session" test "$(api GET /api/v1/status "$tok")" = 401
    expect "bans are refused with the setup session" test "$(api GET /api/v1/bans "$tok")" = 401
    expect "keeping login admin without the tick is refused" test "$(api POST /api/v1/setup/complete "$tok" '{"login":"admin","password":"'"$new"'","password_confirm":"'"$new"'"}')" = 400
    expect "a weak password is refused" test "$(api POST /api/v1/setup/complete "$tok" '{"login":"owner","password":"alllowercase","password_confirm":"alllowercase"}')" = 400
    expect "new credentials are accepted" test "$(api POST /api/v1/setup/complete "$tok" '{"login":"owner","password":"'"$new"'","password_confirm":"'"$new"'"}')" = 204
    expect "admin/admin no longer signs in" test "$(curl -sS --noproxy '*' -o /dev/null -w '%{http_code}' -X POST -H 'X-Requested-With: auditdsec' -H 'Content-Type: application/json' --data-binary '{"login":"admin","password":"admin"}' "$u/api/v1/login")" = 401
    docker restart auditdsec >/dev/null
    expect "the panel is back after a restart" wait_for 40 curl -fsS --noproxy '*' "$u/"
    expect "the default does not come back after a restart" test "$(curl -sS --noproxy '*' -o /dev/null -w '%{http_code}' -X POST -H 'X-Requested-With: auditdsec' -H 'Content-Type: application/json' --data-binary '{"login":"admin","password":"admin"}' "$u/api/v1/login")" = 401
    body="$(curl -sS --noproxy '*' -X POST -H 'X-Requested-With: auditdsec' -H 'Content-Type: application/json' --data-binary '{"login":"owner","password":"'"$new"'"}' "$u/api/v1/login")"
    tok="$(sed -n 's/.*"token":"\([^"]*\)".*/\1/p' <<<"$body")"
    expect "the new account signs in without a forced change" bash -c '! grep -q must_change.:true <<<"$1"' _ "$body"
    expect "and reaches the status page" test "$(api GET /api/v1/status "$tok")" = 200
    expect "the credentials file is mode 600" bash -c 'docker cp auditdsec:/var/lib/auditdsec/panel-credentials.json - | tar -tvf - | grep -q "^-rw------- "'
    expect "the credentials file holds a hash and no password" bash -c \
        'f="$(docker cp auditdsec:/var/lib/auditdsec/panel-credentials.json - | tar -xOf -)"; grep -q "pbkdf2-sha256" <<<"$f" && ! grep -q "$1" <<<"$f"' _ "$new"
    # a second run of the installer keeps the chosen account
    DEFAULT_ACCOUNT=1 run_inst default2 --mode tunnel --port 19478
    expect "a re-run succeeds" test "$RC" = 0
    expect_out "the re-run notices the account was already replaced" "the default account is gone"
    expect "the chosen account still signs in after the re-run" test "$(curl -sS --noproxy '*' -o /dev/null -w '%{http_code}' -X POST -H 'X-Requested-With: auditdsec' -H 'Content-Type: application/json' --data-binary '{"login":"owner","password":"'"$new"'"}' "$u/api/v1/login")" = 200
}

s_selfsigned() {
    step "self-signed mode: verified against the proxy's own CA, never against nothing"
    reset
    run_inst ss1 --mode selfsigned --site 127.0.0.1
    expect "install succeeds" test "$RC" = 0
    expect_out "the certificate verifies against this server's own CA" "verified against this server's own CA"
    expect_out "the password went over that verified connection" "over the verified TLS connection to https://127.0.0.1"
    expect_out "the summary tells the person browsers will warn" "browsers do not know it, so they warn"
    expect "no certbot in this mode" test -z "$(docker ps -q --filter name=auditdsec-certbot)"
    expect "the sign-in reached the proxy" caddy_has '/api/v1/login'
    expect "a client without the CA cannot verify the connection" bash -c '! curl -fsS --noproxy "*" -o /dev/null https://127.0.0.1/'
}

s_ip_promote() {
    step "address mode: staging, re-run, then production — separate state, nothing deleted"
    reset
    run_inst ip1 --mode ip --site 127.0.0.1 --staging --cacert "$ROOT_STAGING"
    expect "staging install succeeds" test "$RC" = 0
    expect_out "summary says STAGING" "STAGING"
    expect_out "summary says staging proves nothing about production" "does NOT show that the real CA will issue"
    expect ".env records staging" test "$(env_val PANEL_ACME)" = staging
    expect ".env selects the staging volumes" test "$(env_val PANEL_ACME_SUFFIX)" = -staging
    expect "staging volumes exist" vol_exists panel-certs-staging
    expect "production volumes do not exist yet" bash -c "! docker volume inspect $(vol panel-certs) >/dev/null 2>&1"
    local fp1; fp1="$(served_fp 127.0.0.1)"
    expect "port 443 serves the staging certificate from disk" test -n "$fp1" -a "$fp1" = "$(disk_fp panel-certs-staging)"
    expect "staging sends HSTS max-age=0" test "$(hsts "$ROOT_STAGING" https://127.0.0.1)" = "strict-transport-security: max-age=0"
    expect "meta.json records staging" bash -c "docker run --rm -v $(vol panel-certs-staging):/v:ro --entrypoint cat $CERTBOT_IMG /v/meta.json | grep -q '\"acme\": \"staging\"'"
    expect "the certificate carries the address" san_is 127.0.0.1 "IP Address:127.0.0.1"
    local iss1; iss1="$(served_issuer 127.0.0.1)"
    local state_created; state_created="$(docker volume inspect -f '{{.CreatedAt}}' "$(vol auditdsec-state)")"

    # A re-run with no flags stays on staging and reuses the certificate.
    run_inst ip2 --cacert "$ROOT_STAGING"
    expect "re-run succeeds" test "$RC" = 0
    expect_out "re-run reuses the certificate" "the certificate already in place fits"
    expect "re-run did not change the certificate" test "$(served_fp 127.0.0.1)" = "$fp1"
    expect "re-run stays on staging" test "$(env_val PANEL_ACME)" = staging

    # The explicit move to production.
    run_inst ip3 --production --cacert "$ROOT_PRODUCTION"
    expect "production install succeeds" test "$RC" = 0
    expect_out "the switch is announced and says nothing is deleted" "nothing is deleted"
    expect ".env records production" test "$(env_val PANEL_ACME)" = production
    expect ".env drops the staging suffix" test -z "$(env_val PANEL_ACME_SUFFIX)"
    expect ".env drops the staging HSTS override" test -z "$(env_val PANEL_HSTS)"
    local fp2; fp2="$(served_fp 127.0.0.1)"
    expect "port 443 now serves a different certificate" test -n "$fp2" -a "$fp2" != "$fp1"
    expect "it is the production one on disk" test "$fp2" = "$(disk_fp panel-certs)"
    expect "it was issued by another CA than the staging one" test "$(served_issuer 127.0.0.1)" != "$iss1"
    expect "production sends a real HSTS" test "$(hsts "$ROOT_PRODUCTION" https://127.0.0.1)" = "strict-transport-security: max-age=31536000"
    expect "meta.json records production" bash -c "docker run --rm -v $(vol panel-certs):/v:ro --entrypoint cat $CERTBOT_IMG /v/meta.json | grep -q '\"acme\": \"production\"'"
    expect "the staging certificate is still in its volume, untouched" test "$(disk_fp panel-certs-staging)" = "$fp1"
    expect "the staging account and lineage are still there" bash -c "docker run --rm -v $(vol letsencrypt-staging):/v:ro --entrypoint ls $CERTBOT_IMG /v/live/panel | grep -q fullchain.pem"
    expect "stored events (agent state) were kept" test "$(docker volume inspect -f '{{.CreatedAt}}' "$(vol auditdsec-state)")" = "$state_created"
    expect_out "the production summary does not claim staging" "Production CA, verified against the CA file you gave"
    expect_out_not "no staging banner after the switch" "STAGING."
    expect "sign-in reached Caddy over verified TLS" caddy_has '/api/v1/login'
}

s_domain_promote() {
    step "domain mode: staging, then production — separate state, nothing deleted"
    reset
    run_inst dom1 --mode domain --site panel.test --email ops@panel.test --staging --cacert "$ROOT_STAGING"
    expect "staging install succeeds" test "$RC" = 0
    expect_out "link is the domain" "Link:     https://panel.test"
    expect_out "certificate verifies against the staging root" "the certificate verifies"
    expect_out "signed in over verified TLS" "over the verified TLS connection to https://panel.test"
    expect "caddy uses the staging data volume" vol_exists caddy-data-staging
    expect "no production caddy volume yet" bash -c "! docker volume inspect $(vol caddy-data) >/dev/null 2>&1"
    local fp1; fp1="$(served_fp 127.0.0.1 panel.test)"
    expect "port 443 serves a certificate for panel.test" san_is 127.0.0.1 "DNS:panel.test" panel.test
    expect "staging sends HSTS max-age=0" test "$(hsts "$ROOT_STAGING" https://panel.test)" = "strict-transport-security: max-age=0"

    run_inst dom2 --production --cacert "$ROOT_PRODUCTION"
    expect "production install succeeds" test "$RC" = 0
    expect ".env records production" test "$(env_val PANEL_ACME)" = production
    local fp2; fp2="$(served_fp 127.0.0.1 panel.test)"
    expect "port 443 now serves a different certificate" test -n "$fp2" -a "$fp2" != "$fp1"
    expect "production volume exists now" vol_exists caddy-data
    expect "staging volume still exists" vol_exists caddy-data-staging
    expect "production HSTS" test "$(hsts "$ROOT_PRODUCTION" https://panel.test)" = "strict-transport-security: max-age=31536000"
}

s_ip_change() {
    step "address changes: the old certificate is not reused"
    reset
    run_inst chg1 --mode ip --site 127.0.0.1 --staging --cacert "$ROOT_STAGING"
    expect "first install succeeds" test "$RC" = 0
    local fp1; fp1="$(served_fp 127.0.0.1)"
    run_inst chg2 --site 127.0.0.2 --cacert "$ROOT_STAGING"
    expect "install for the new address succeeds" test "$RC" = 0
    expect_out "the installer says why the old certificate cannot be reused" "it is for 127.0.0.1, not for 127.0.0.2"
    expect_out "link now points at the new address" "Link:     https://127.0.0.2"
    local fp2; fp2="$(served_fp 127.0.0.2)"
    expect "a new certificate is served" test -n "$fp2" -a "$fp2" != "$fp1"
    expect "its SAN is the new address" san_is 127.0.0.2 "IP Address:127.0.0.2"
    expect "the disk copy is the served one" test "$fp2" = "$(disk_fp panel-certs-staging)"
    expect "the old certificate version is kept in certbot's archive" bash -c "[ \$(docker run --rm -v $(vol letsencrypt-staging):/v:ro --entrypoint ls $CERTBOT_IMG /v/archive/panel | grep -c '^fullchain') -ge 2 ]"
}

s_domain_to_ip() {
    step "domain -> address: the old proxy must not hold port 80"
    reset
    run_inst d2i_1 --mode domain --site panel.test --email ops@panel.test --staging --cacert "$ROOT_STAGING"
    expect "domain install succeeds" test "$RC" = 0
    expect "the domain proxy holds port 80 (the premise)" listening 80
    run_inst d2i_2 --mode ip --site 127.0.0.1 --staging --cacert "$ROOT_STAGING"
    expect "switch to address mode succeeds" test "$RC" = 0
    expect_out "the installer stopped the old proxy for the challenge" "Port 80 is held by the proxy of the previous setup"
    expect ".env is now ip mode" test "$(env_val PANEL_MODE)" = ip
    expect "port 443 serves the address certificate" san_is 127.0.0.1 "IP Address:127.0.0.1"
    expect "the certbot sidecar is running" test "$(docker inspect -f '{{.State.Running}}' auditdsec-certbot)" = true
    expect "port 80 is free again (certbot only holds it while renewing)" bash -c '! listening 80'
    expect "domain-mode data was not deleted" vol_exists caddy-data-staging
}

s_domain_to_ip_fails() {
    step "domain -> address fails: the working domain setup is put back"
    reset
    run_inst fail1 --mode domain --site panel.test --email ops@panel.test --staging --cacert "$ROOT_STAGING"
    expect "domain install succeeds" test "$RC" = 0
    local fp1; fp1="$(served_fp 127.0.0.1 panel.test)"
    PANEL_ACME_URL_STAGING="https://localhost:14999/dir" run_inst fail2 --mode ip --site 127.0.0.1 --staging --cacert "$ROOT_STAGING"
    expect "the failed attempt exits non-zero" test "$RC" != 0
    expect_out "the failure is explained" "The certificate was not issued"
    expect_out "the summary says the previous settings run again" "the previous ones are running again"
    expect ".env is back to domain mode" test "$(env_val PANEL_MODE)" = domain
    expect "the failed settings were kept for diagnosis" grep -q "^PANEL_MODE='ip'" "$WORK/.env.failed"
    expect ".env.failed is mode 600" test "$(stat -c %a "$WORK/.env.failed")" = 600
    expect "the domain page answers again" wait_for 40 curl -fsS --noproxy '*' --cacert "$ROOT_STAGING" -o /dev/null https://panel.test/
    expect "the same certificate is served as before" test "$(served_fp 127.0.0.1 panel.test)" = "$fp1"
    expect "the old password still signs in" login_ok https://panel.test "$ROOT_STAGING"
    expect "no certbot sidecar is left behind" test -z "$(docker ps -q --filter name=auditdsec-certbot)"
}

s_restore() {
    step "--restore puts the last verified configuration back"
    reset
    run_inst rst1 --mode tunnel --port 19477
    expect "tunnel install succeeds" test "$RC" = 0
    expect "last-good exists and is mode 600" test "$(stat -c %a "$WORK/.env.last-good")" = 600
    run_inst rst2 --mode ip --site 127.0.0.1 --staging --cacert "$ROOT_STAGING" --no-verify
    expect "address mode started (unverified)" test "$(env_val PANEL_MODE)" = ip
    expect "last-good was NOT overwritten by an unverified run" grep -q "^PANEL_MODE='tunnel'" "$WORK/.env.last-good"
    run_inst rst3 --restore
    expect "--restore succeeds" test "$RC" = 0
    expect ".env is tunnel mode again" test "$(env_val PANEL_MODE)" = tunnel
    expect "the page answers again" wait_for 30 curl -fsS --noproxy '*' -o /dev/null http://127.0.0.1:19477/
    expect "the proxy containers are gone" test -z "$(docker ps -q --filter name=auditdsec-caddy --filter name=auditdsec-certbot)"
}

s_untrusted() {
    step "an untrusted certificate never receives the password"
    reset
    # No --cacert: the system store does not know the production test CA.
    run_inst unt1 --mode ip --site 127.0.0.1 --production
    expect "the run is reported as a problem (non-zero)" test "$RC" != 0
    expect_out "the certificate is called not trusted" "NOT trusted"
    expect_out "sign-in was done on loopback only" "on this server's loopback address ONLY"
    expect_out "the password was not sent to the public address" "so the password was not sent there"
    expect_out "the agent still accepted the password on loopback" "signed in with the chosen password"
    local log; log="$(caddy_log)"
    expect "the proxy saw the page being fetched" caddy_has '"uri":"/"'
    if printf '%s' "$log" | grep -q '/api/v1/login'; then
        fail "no sign-in request reached the proxy" "the proxy's log has /api/v1/login"
    else
        pass "no sign-in request reached the proxy on 443"
    fi
    expect "the page was fetched through the proxy at all (the log is not just empty)" test -n "$log"

    step "control: with a CA the installer verifies, the sign-in does go through the proxy"
    run_inst unt2 --cacert "$ROOT_PRODUCTION"
    expect "install succeeds once the CA is given" test "$RC" = 0
    if caddy_log | grep -q '/api/v1/login'; then pass "the proxy log does show the sign-in (so the check above can detect one)"
    else fail "control: the proxy log should show /api/v1/login"; fi
}

s_reuse() {
    step "a file on disk is not proof: wrong CA, wrong key"
    reset
    run_inst reuse1 --mode ip --site 127.0.0.1 --staging --cacert "$ROOT_STAGING"
    expect "staging install succeeds" test "$RC" = 0
    # Plant the staging certificate where production looks for it.
    docker volume create "$(vol panel-certs)" >/dev/null
    docker run --rm -v "$(vol panel-certs-staging):/s:ro" -v "$(vol panel-certs):/p" --entrypoint cp "$CERTBOT_IMG" \
        /s/fullchain.pem /s/privkey.pem /s/meta.json /p/ >/dev/null
    run_inst reuse2 --production --cacert "$ROOT_PRODUCTION"
    expect "production install succeeds" test "$RC" = 0
    expect_out "the planted staging certificate was refused" "The certificate that is there cannot be reused"
    expect_out "the reason names the environment" "it was issued for staging, this installation uses production"
    expect_out "a production certificate was then issued" "certificate issued and checked"
    expect "the served certificate is the production one" test "$(served_fp 127.0.0.1)" = "$(disk_fp panel-certs)"

    # A key that does not belong to the certificate; certbot still holds the right pair.
    openssl ecparam -name prime256v1 -genkey -noout -out "$LAB/wrong.key" 2>/dev/null
    openssl pkcs8 -topk8 -nocrypt -in "$LAB/wrong.key" -out "$LAB/wrong.pem" 2>/dev/null
    docker run --rm -v "$(vol panel-certs):/p" -v "$LAB/wrong.pem:/k:ro" --entrypoint cp "$CERTBOT_IMG" /k /p/privkey.pem
    run_inst reuse3 --cacert "$ROOT_PRODUCTION"
    expect "re-run succeeds" test "$RC" = 0
    expect_out "the wrong key is detected" "the private key does not belong to this certificate"
    expect_out "certbot's own good copy is used instead of asking the CA again" "certbot already held a fitting certificate"
    expect "the key on disk matches the certificate again" bash -c "[ \"\$(docker run --rm -v $(vol panel-certs):/v:ro --entrypoint sh $CERTBOT_IMG -c 'cat /v/fullchain.pem' | openssl x509 -noout -pubkey | openssl md5)\" = \"\$(docker run --rm -v $(vol panel-certs):/v:ro --entrypoint cat $CERTBOT_IMG /v/privkey.pem | openssl pkey -pubout | openssl md5)\" ]"
}

s_renew_and_reload() {
    step "renewal: certbot renews on its own, a failed reload is visible and retried, 443 really changes"
    reset
    run_inst ren1 --mode ip --site 127.0.0.1 --staging --cacert "$ROOT_STAGING"
    expect "install succeeds" test "$RC" = 0
    local fp0; fp0="$(served_fp 127.0.0.1)"
    expect "container health check is in place" test -n "$(docker inspect -f '{{.State.Health.Status}}' auditdsec-certbot)"
    local conf=/etc/letsencrypt/renewal/panel.conf

    step "  natural renewal"
    # Make the certificate due now; the loop's own `certbot renew` does the rest.
    docker exec auditdsec-certbot sed -i '1i renew_before_expiry = 7 days' "$conf"
    docker restart auditdsec-certbot >/dev/null
    expect "the loop renewed the certificate and the hook reported success" wait_for 90 bash -c "docker logs auditdsec-certbot 2>&1 | grep -q 'caddy now serves certificate'"
    local fp1; fp1="$(served_fp 127.0.0.1)"
    expect "port 443 serves a NEW certificate after the renewal" test -n "$fp1" -a "$fp1" != "$fp0"
    expect "it is the file certbot wrote" test "$fp1" = "$(disk_fp panel-certs-staging)"
    expect "the health check reports ok" test "$(docker exec auditdsec-certbot python3 /hooks/certtool.py status)" = ok

    step "  renewal while Caddy refuses the reload"
    local cf="$WORK/deploy/Caddyfile.acme-ip"
    cp "$cf" "$LAB/Caddyfile.good"
    printf '\nthis is { not a valid caddyfile\n' >> "$cf"      # in place, so the bind mount sees it
    docker restart auditdsec-certbot >/dev/null
    expect "the failure is logged loudly" wait_for 120 bash -c "docker logs auditdsec-certbot 2>&1 | grep -q 'RELOAD FAILED'"
    local fp2; fp2="$(served_fp 127.0.0.1)"
    expect "meanwhile 443 still serves the previous certificate" test "$fp2" = "$fp1"
    local new_on_disk; new_on_disk="$(disk_fp panel-certs-staging)"
    expect "the renewed certificate is on disk but not served" test "$new_on_disk" != "$fp2"
    local st; st="$(docker exec auditdsec-certbot python3 /hooks/certtool.py status 2>&1)"; local src=$?
    expect "the health check fails while that is true" test "$src" != 0
    expect "and says why" bash -c "grep -q 'does not serve the current certificate' <<<'$st'"
    expect "status.json records the failure" bash -c "docker run --rm -v $(vol panel-certs-staging):/v:ro --entrypoint cat $CERTBOT_IMG /v/status.json | grep -q reload-failed"

    expect "docker itself marks the certbot container unhealthy" \
        wait_for 280 bash -c '[ "$(docker inspect -f "{{.State.Health.Status}}" auditdsec-certbot)" = unhealthy ]'

    step "  the fault is fixed; the next attempt succeeds without any renewal"
    cat "$LAB/Caddyfile.good" > "$cf"
    expect "the loop retried the reload and port 443 now serves the new certificate" \
        wait_for 90 bash -c "[ \"\$(printf '' | openssl s_client -connect 127.0.0.1:443 2>/dev/null | openssl x509 -noout -fingerprint -sha256 | cut -d= -f2)\" = '$new_on_disk' ]"
    expect "the health check passes again" wait_for 30 bash -c "[ \"\$(docker exec auditdsec-certbot python3 /hooks/certtool.py status)\" = ok ]"
    expect "and docker marks the container healthy again" \
        wait_for 150 bash -c '[ "$(docker inspect -f "{{.State.Health.Status}}" auditdsec-certbot)" = healthy ]'
}

s_secrets() {
    step "no secret in anything the installer or the containers printed"
    local f hits=0
    for f in "$OUTDIR"/*.log; do
        [ -e "$f" ] || continue
        if grep -qF 'A-long-test-password' "$f" || grep -qE 'pbkdf2-sha256\$' "$f" || grep -qF '123:abc' "$f"; then
            fail "secret in $f"; hits=1
        fi
    done
    [ "$hits" = 0 ] && pass "installer output has no password, hash or token"
    local logs; logs="$(docker ps -a --format '{{.Names}}' | xargs -r -n1 docker logs 2>&1)"
    if grep -qF 'A-long-test-password' <<<"$logs"; then fail "password in container logs"; else pass "container logs have no password"; fi
}

# ------------------------------------------------------------------- main --

ALL="tunnel default_account selfsigned ip_promote domain_promote ip_change domain_to_ip domain_to_ip_fails restore untrusted reuse renew_and_reload"
want=("$@"); [ ${#want[@]} -gt 0 ] || read -r -a want <<<"$ALL"
for n in "${want[@]}"; do
    "s_$n" || true
done
s_secrets
printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
