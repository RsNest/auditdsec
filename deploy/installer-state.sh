# shellcheck shell=bash disable=SC2034
# What is true after the checks, the optional outside look, the plan shown
# before applying, and the final report. Sourced by install.sh.
#
# "The application runs", "HTTPS is verified" and "the internet reaches it" are
# different facts with different evidence, and are reported separately:
#
#   app      the sign-in page answered (here, on this server)
#   https    the certificate verified against the system trust store (here)
#   outside  confirmed / not checked / check failed / provider unavailable
#
# A successful check from one network point does not prove reachability from the
# whole internet, and a missing outside check does not mean the panel is down.

EXT_STATE=""   # confirmed | not_checked | failed | unavailable

# external_tls_check — the optional last look from outside, with a bounded wait.
# It is advice: it never fails the run and never causes a rollback of an
# application that works here. Returns 0 always.
external_tls_check() {
    case "$MODE" in tunnel) EXT_STATE=not_checked; EXT_TLS_STATE="not applicable (tunnel)"; return 0 ;; esac
    if [ "$NO_EXTERNAL" = yes ]; then
        EXT_STATE=not_checked; EXT_TLS_STATE="not checked (--no-external-check)"; return 0
    fi
    if [ "$EXT_CONFIGURED" != yes ]; then
        EXT_STATE=not_checked
        EXT_TLS_STATE="not checked: no outside-check provider is configured. The panel may well be reachable; this server alone cannot prove it."
        return 0
    fi
    [ ${#TARGETS[@]} -gt 0 ] || load_targets
    sub "Asking the outside-check provider to reach the panel"
    local t addr fam worst=confirmed detail=""
    for t in "${TARGETS[@]}"; do
        addr="${t% *}"; fam="${t#* }"
        remote_check tls "$addr" "$HTTPS_PORT" "$fam"
        case "$RC_RESULT" in
            reachable)
                [ -z "$RC_NOT_AFTER" ] || NOT_AFTER="$RC_NOT_AFTER"
                if [ "$RC_TLS_VERIFIED" = yes ]; then
                    ok "$(hostport "$addr" "$HTTPS_PORT"): reached from the provider's network point, certificate verified (valid until ${RC_NOT_AFTER:-?})"
                elif [ "$MODE" = selfsigned ] || [ "$ACME" = staging ]; then
                    ok "$(hostport "$addr" "$HTTPS_PORT"): reached from the provider; the certificate is not publicly trusted, as expected for a test or self-signed setup"
                else
                    warn "$(hostport "$addr" "$HTTPS_PORT"): the provider reached the panel, but the certificate did not verify there: ${RC_TLS_ERROR:-unknown reason}"
                    worst=failed; detail="${RC_TLS_ERROR:-certificate not verified by the provider}"
                fi ;;
            refused|timeout|wrong_endpoint)
                warn "$(hostport "$addr" "$HTTPS_PORT"): the provider could not reach the panel: $RC_RESULT${RC_DETAIL:+ ($RC_DETAIL)}"
                worst=failed; detail="$RC_RESULT${RC_DETAIL:+: $RC_DETAIL}" ;;
            *)
                warn "The outside-check provider did not answer${RC_DETAIL:+: $RC_DETAIL}. The panel itself is not affected."
                [ "$worst" = failed ] || worst=unavailable
                detail="${RC_DETAIL:-no answer}" ;;
        esac
    done
    EXT_STATE="$worst"
    case "$worst" in
        confirmed) EXT_TLS_STATE="confirmed from the provider's network point (this does not prove reachability from the whole internet)" ;;
        failed) EXT_TLS_STATE="the check did not pass: $detail. The panel works on this server; check the firewall of this server and of your provider." ;;
        *) EXT_TLS_STATE="the checking service was unavailable: $detail" ;;
    esac
    return 0
}

# remote_check_command — the outside diagnostics for automation, as a command of
# its own (./install.sh --remote-check). It needs a configured provider and
# exits 0 when the panel was reached with a verified certificate, 11 when the
# provider could not reach it, 16 when it did but the certificate did not
# verify, 12 when no provider is configured or it did not answer. It changes
# nothing; it is the only place where the outside check decides an exit status.
remote_check_command() {
    preflight_light
    load_state_from_env
    PROBE_URL="$(env_get PANEL_PROBE_URL)"; PROBE_TOKEN_FILE="$(env_get PANEL_PROBE_TOKEN_FILE)"; PROBE_CACERT="$(env_get PANEL_PROBE_CACERT)"
    [ "$MODE" != tunnel ] || die "an SSH tunnel is not reachable from outside by design; there is nothing to check"
    if [ -z "$PROBE_URL" ] || [ -z "$PROBE_TOKEN_FILE" ] || [ ! -r "$PROBE_TOKEN_FILE" ]; then
        say "No RemoteProbe provider is configured (--probe-url and --probe-token-file at install time)."
        return 12
    fi
    EXT_CONFIGURED=yes
    TARGETS=()
    load_targets
    local t rc=0 addr fam
    for t in "${TARGETS[@]}"; do
        addr="${t% *}"; fam="${t#* }"
        remote_check tls "$addr" "$HTTPS_PORT" "$fam"
        case "$RC_RESULT" in
            reachable)
                if [ "$RC_TLS_VERIFIED" = yes ] || [ "$MODE" = selfsigned ] || [ "$ACME" = staging ]; then
                    ok "$(hostport "$addr" "$HTTPS_PORT"): reached, certificate valid until ${RC_NOT_AFTER:-?}"
                else
                    warn "$(hostport "$addr" "$HTTPS_PORT"): reached, but the certificate did not verify: ${RC_TLS_ERROR:-unknown}"
                    rc=16
                fi ;;
            refused|timeout|wrong_endpoint)
                warn "$(hostport "$addr" "$HTTPS_PORT"): not reached: $RC_RESULT${RC_DETAIL:+ ($RC_DETAIL)}"
                [ "$rc" = 16 ] || rc=11 ;;
            *)
                warn "The provider did not answer${RC_DETAIL:+: $RC_DETAIL}"
                [ "$rc" != 0 ] || rc=12 ;;
        esac
    done
    jlog info remote_check "outside check finished with status $rc"
    return "$rc"
}

# ------------------------------------------------------------------ the plan --

# confirm_plan — what is about to be done, before it is done. No secrets.
confirm_plan() {
    local port=""
    { [ "$MODE" = tunnel ] || [ "$HTTPS_PORT" = 443 ]; } || port=":$HTTPS_PORT"
    installer_printf '\n%s%s%s\n' "$B" "$(installer_text 'This will be done:')" "$N"
    case "$MODE" in
        domain) installer_printf '  %s\n' "$(installer_text "The panel at https://$SITE$port (a domain)")" ;;
        ip) installer_printf '  %s\n' "$(installer_text "The panel at https://$(url_host "$SITE")$port (an IP address)")" ;;
        selfsigned) installer_printf '  %s\n' "$(installer_text "The panel at https://$(url_host "$SITE")$port with a SELF-SIGNED certificate")" ;;
        tunnel) installer_printf '  %s\n' "$(installer_text "The panel only on this server (SSH tunnel); nothing is opened to the internet")" ;;
    esac
    case "$MODE" in domain|ip)
        if [ "$ACME" = staging ]; then
            installer_printf '  %s\n' "$(installer_text "Certificate: a TEST certificate from Let's Encrypt staging (browsers will warn)")"
        else
            installer_printf '  %s\n' "$(installer_text "Certificate: a trusted certificate from Let's Encrypt, renewed automatically")"
        fi
        [ -z "$EMAIL" ] || installer_printf '  %s\n' "$(installer_text "Expiry notices go to: $EMAIL")" ;;
    esac
    installer_printf '  %s\n' "$(installer_text "Bans: $([ "$ENFORCE" = yes ] && echo 'applied with nftables' || echo 'only recorded')")"
    installer_printf '  %s\n' "$(installer_text "Nothing else on this server is stopped or changed; no firewall rule is added.")"
    interactive || return 0
    confirm "Apply this now?" || { say "Nothing was changed."; exit 0; }
}

# ---------------------------------------------------------------- the report --

# decide_state sets what can honestly be said once the required checks are
# done. The link is shown whenever the application answers and, where HTTPS is
# part of the setup, its certificate is what was asked for; the outside check
# only adds a line.
APP_OK=no
decide_state() {
    APP_OK=no
    [ "$DO_START" = yes ] && [ "$DO_VERIFY" = yes ] || return 0
    [ "$RESTORED" = no ] && [ -z "$FAIL_CODE" ] || return 0
    [ "$PAGE_STATE" = "answers" ] || case "$PAGE_STATE" in answers*) ;; *) return 0 ;; esac
    case "$MODE" in
        domain|ip) [ "$TLS_UNTRUSTED" = no ] && [ "$RELOAD_PROBLEM" = no ] || return 0 ;;
    esac
    APP_OK=yes
}

# certificate_line — one sentence on the state of the certificate.
certificate_line() {
    case "$MODE" in
        tunnel) printf '%s' "none needed: the connection runs inside the SSH tunnel" ;;
        selfsigned) printf '%s' "SELF-SIGNED: encrypted, but every browser warns" ;;
        domain|ip)
            if [ "$ACME" = staging ]; then printf '%s' "TEST certificate (Let's Encrypt staging): browsers warn on purpose"
            elif [ "$TLS_UNTRUSTED" = yes ]; then printf '%s' "NOT trusted: ${TLS_STATE:-the certificate did not verify}"
            else printf '%s' "${TLS_STATE:-trusted}"; fi ;;
    esac
}

# outside_line — one sentence on the optional outside check.
outside_line() {
    case "$EXT_STATE" in
        confirmed) printf '%s' "confirmed ($EXT_TLS_STATE)" ;;
        failed) printf '%s' "check failed: $EXT_TLS_STATE" ;;
        unavailable) printf '%s' "$EXT_TLS_STATE" ;;
        *) printf '%s' "${EXT_TLS_STATE:-not checked}" ;;
    esac
}

# summary — the result, the link last. Stage 'Result'.
summary() {
    local line
    decide_state
    line="$(installer_printf '%*s' 70 '' | tr ' ' '-')"
    installer_printf '\n%s\n' "$line"
    if [ "$RESTORED" = yes ] && [ "$RESTORE" = yes ]; then
        installer_printf '%s%s%s\n' "$B" "$(installer_text 'The last verified configuration is running again.')" "$N"
    elif [ "$RESTORED" = yes ] && [ "$RESTORE_OK" = no ]; then
        installer_printf '%s[FAIL]%s %s%s%s
' "$R$B" "$N" "$R$B" "$(installer_text 'The new settings did not work, and the previous ones could not be confirmed working either.')" "$N"
    elif [ "$RESTORED" = yes ]; then
        installer_printf '%s[FAIL]%s %s%s%s\n' "$R$B" "$N" "$R$B" "$(installer_text 'The new settings did not work; the previous ones are running again.')" "$N"
    elif [ -n "$FAIL_CODE" ]; then
        installer_printf '%s[FAIL]%s %s%s: %s%s\n' "$R$B" "$N" "$R$B" "$(installer_text 'Not completed')" "$FAIL_CODE" "$N"
    elif [ "$DO_START" != yes ]; then
        installer_printf '%s%s%s\n' "$B" "$(installer_text 'Configured, not started (--no-start).')" "$N"
    elif [ "$DO_VERIFY" != yes ]; then
        installer_printf '%s[WARN]%s %s\n' "$Y$B" "$N" "$(installer_text 'Started, but not checked (--no-verify).')"
    elif [ "$APP_OK" = yes ] && [ "$SETUP_STATE" = bootstrap ]; then
        installer_printf '%s[ OK ]%s %s%s%s\n' "$G$B" "$N" "$G$B" "$(installer_text 'auditdsec is running and waits for first-time setup.')" "$N"
    elif [ "$APP_OK" = yes ]; then
        installer_printf '%s[ OK ]%s %s%s%s\n' "$G$B" "$N" "$G$B" "$(installer_text 'auditdsec is running.')" "$N"
    else
        installer_printf '%s[WARN]%s %s\n' "$Y$B" "$N" "$(installer_text 'Started, but a required check did not pass.')"
    fi
    installer_printf '%s\n\n' "$line"

    if [ -n "$FAIL_REASON" ]; then
        installer_printf '  %s %s\n' "$(installer_text 'What went wrong:')" "$FAIL_REASON"
        [ "$RESTORED" != yes ] || installer_printf '  %s\n' "$(installer_text "The failed settings are in $ENV_FILE.failed (same permissions as $ENV_FILE).")"
        installer_printf '  %s %s\n\n' "$(installer_text 'Run again after fixing it:')" "$(retry_command)"
    fi

    installer_printf '  %-13s %s\n' "$(installer_text 'Application:')" "$(installer_text "${PAGE_STATE:-not checked}")"
    installer_printf '  %-13s %s\n' "$(installer_text 'Sign-in:')" "$(installer_text "${LOGIN_STATE:-not checked}")"
    [ -z "$LOGIN_ROUTE" ] || installer_printf '  %-13s %s\n' "" "$(installer_text "sent $LOGIN_ROUTE")"
    if [ "$MODE" != tunnel ]; then
        installer_printf '  %-13s %s\n' "$(installer_text 'HTTPS:')" "$(installer_text "$(certificate_line)")"
        [ -z "$NOT_AFTER" ] || installer_printf '  %-13s %s\n' "$(installer_text 'Expires:')" "$NOT_AFTER"
        installer_printf '  %-13s %s (%s)\n' "$(installer_text 'Port:')" "$HTTPS_PORT" \
            "$([ "$HTTPS_SOURCE" = manual ] && installer_text 'given by you' || { [ "$HTTPS_SOURCE" = auto ] && installer_text 'picked automatically' || { [ "$HTTPS_SOURCE" = default ] && installer_text 'the standard port' || installer_text 'kept'; }; })"
        installer_printf '  %-13s %s\n' "$(installer_text 'Outside:')" "$(installer_text "$(outside_line)")"
        [ -z "$ACME_PORT_STATE" ] || installer_printf '  %-13s %s\n' "$(installer_text 'Challenge:')" "$(installer_text "$ACME_PORT_STATE")"
    fi
    [ -z "$RENEW_STATE" ] || installer_printf '  %-13s %s\n' "$(installer_text 'Renewal:')" "$(installer_text "$RENEW_STATE")"
    case "$MODE" in
        domain) installer_printf '  %-13s %s\n' "" "$(installer_text 'Caddy renews the certificate itself, about 30 days before it ends.')" ;;
        ip) installer_printf '  %-13s %s\n' "" "$(installer_text "Address certificates last about 6 days; the certbot container renews them and checks every minute that port $HTTPS_PORT serves the file on disk. Port 80 must stay open and unused for the renewals.")" ;;
        selfsigned)
            installer_printf '  %-13s %s\n' "$(installer_text 'Trust:')" "$(installer_text 'each browser warns. Compare the fingerprint it shows with:')"
            installer_printf '    printf "" | openssl s_client -connect %s 2>/dev/null | openssl x509 -noout -fingerprint -sha256\n' "$(hostport "$SITE" "$HTTPS_PORT")" ;;
    esac
    if [ "$ACME" = staging ] && [ "$RESTORED" != yes ]; then
        installer_printf '\n  %s%s%s %s\n' "$Y$B" "$(installer_text 'TEST CERTIFICATE.')" "$N" "$(installer_text 'Browsers do not trust it, on purpose. Switch with:')"
        installer_printf '    ./install.sh --production     (%s)\n' "$(installer_text 'nothing is deleted')"
    fi

    installer_printf '\n  %s%s%s\n' "$DIM" "$(installer_text 'Diagnostics:')" "$N"
    installer_printf '    %s ps\n' "$(compose_prefix)"
    installer_printf '    %s logs --tail 80 auditdsec\n' "$(compose_prefix)"
    case "$MODE" in domain|ip|selfsigned) installer_printf '    %s logs --tail 40 caddy\n' "$(compose_prefix)" ;; esac
    [ "$MODE" != ip ] || installer_printf '    %s exec certbot python3 /hooks/certtool.py status\n' "$(compose_prefix)"
    installer_printf '    %s %s\n' "$(installer_text 'Logs of this operation:')" "./install.sh --logs $TRACE_ID"
    local img facts
    img="${IMAGE:-$(env_get AUDITDSEC_IMAGE)}"
    if [ -n "$img" ]; then
        facts="$(image_facts "$img")"
        installer_printf '  %s%s %s\n' "$DIM" "$(installer_text 'Image:')" "$img"
        installer_printf '             version %s, commit %s\n' "${facts%%|*}" "$(installer_printf '%s' "$facts" | cut -d'|' -f2)"
        installer_printf '             digest %s%s\n' "${facts##*|}" "$N"
        [ -z "$(env_get PANEL_IMAGE_PREVIOUS)" ] || installer_printf '             %s %s\n' "$(installer_text 'previous image (for going back):')" "$(env_get PANEL_IMAGE_PREVIOUS)"
    fi
    installer_printf '  %s\n' "$(installer_text 'Run ./install.sh again to change anything: data, certificates and credentials are kept.')"
    [ ! -s "$LAST_GOOD" ] || installer_printf '  %s\n' "$(installer_text 'Back to the last verified configuration: ./install.sh --restore')"

    # The sign-in and the link come last, so they are what stays on screen.
    installer_printf '\n'
    if [ "$SETUP_STATE" = bootstrap ] && [ "$RESTORED" != yes ] && [ "$DO_START" = yes ] && [ -z "$FAIL_CODE" ]; then
        installer_printf '  %s %sadmin%s / %sadmin%s\n' "$(installer_text 'First login:')" "$B" "$N" "$B" "$N"
        installer_printf '                %s\n' "$(installer_text 'It opens only the mandatory setup screen: choose your login (or tick "keep admin") and a password of 8+ characters with a lower-case and an upper-case letter. Do it now: whoever signs in first can choose them.')"
    elif [ "$SETUP_STATE" = ready ] || [ -n "$(env_get AUDITDSEC_WEB_PASSWORD_HASH)" ]; then
        installer_printf '  %s\n' "$(installer_text 'Sign in with the login and password you chose (admin / admin no longer works).')"
    fi
    if [ "$MODE" = tunnel ]; then
        installer_printf '  %s  %s\n' "$(installer_text 'On your computer, run and leave open:')" "$(ssh_command)"
    fi
    if [ "$APP_OK" = yes ] || [ "$RESTORED" = yes ] || { [ "$MODE" = tunnel ] && [ -z "$FAIL_CODE" ]; }; then
        installer_printf '  %s %s%s%s\n' "$(installer_text 'Link:')" "$B" "$PANEL_URL" "$N"
    else
        installer_printf '  %s %s\n' "$(installer_text 'Configured link (the checks above did not pass):')" "$PANEL_URL"
    fi
    installer_printf '%s\n' "$line"
}
