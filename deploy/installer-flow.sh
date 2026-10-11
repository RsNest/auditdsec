# shellcheck shell=bash disable=SC2034
# The first-run scenario and the questions it asks, in the order a person
# thinks about them: how should the panel be reached, what does that need, what
# will be done. Sourced by install.sh, which keeps the checks and the
# machinery (DNS, ports, certificates, Compose, rollback).
#
# Principles kept here:
#   * Ask only what the chosen option needs; Enter accepts the shown value.
#   * A wrong answer is explained and asked again, not turned into a failure.
#   * The standard HTTPS port (443) is the first choice. When it is taken the
#     reason is shown and the person chooses another port; no port is picked
#     silently and no other program is stopped.
#   * The outside check (RemoteProbe) is optional diagnostics. Without it the
#     installer checks everything it can from this server and says what it did
#     not check; it never makes that a failure.

EXT_CONFIGURED=no   # a RemoteProbe provider is configured and readable

# ask_until PROMPT DEFAULT VALIDATOR ERROR — asks until VALIDATOR accepts the
# answer; says why it did not, with ERROR, and asks again. Enter takes DEFAULT.
ask_until() {
    local prompt="$1" default="$2" validator="$3" error="$4" reply
    while :; do
        reply="$(ask "$prompt" "$default")"
        if "$validator" "$reply"; then printf '%s' "$reply"; return 0; fi
        if ! interactive; then return 1; fi
        warn "$error"
    done
}

valid_port_number() { case "$1" in ''|*[!0-9]*) return 1 ;; esac; [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }

# ---------------------------------------------------------------- access ---

# choose_mode — how the panel will be reached. Domain and IP with a trusted
# HTTPS certificate are the two everyday answers; the tunnel needs nothing
# public; the test and self-signed certificates are kept under "more options"
# and always say what state the certificate will be in.
choose_mode() {
    if [ -n "$MODE" ]; then
        valid_mode "$MODE" || die "unknown mode '$MODE': use domain or ip (or, for development, tunnel or selfsigned)"
        return 0
    fi
    local previous
    previous="$(env_get PANEL_MODE)"
    if ! interactive; then
        # A re-run keeps what was chosen before, including a tunnel or a
        # self-signed setup that someone asked for by name back then.
        [ -n "$previous" ] || die "say where the panel should open: --mode domain --site NAME, or --mode ip [--site ADDRESS]"
        MODE="$previous"
        return 0
    fi
    if [ "$previous" = tunnel ] || [ "$previous" = selfsigned ]; then
        if confirm "This installation uses --mode $previous. Keep it?"; then MODE="$previous"; return 0; fi
    fi
    while :; do
        installer_lines <<'EOF'

How should the panel be reached?

  1) A domain name (recommended)
     https://panel.example.com with a certificate every browser trusts,
     issued by Let's Encrypt and renewed automatically.
     Needs: a domain whose A/AAAA records point at this server, and
     ports 80 and 443 open on it.

  2) This server's public IP address
     https://203.0.113.9 with a trusted certificate for the address
     (valid about 6 days, renewed automatically).
     Needs: a public IP and port 80 open for the renewals.

  3) An SSH tunnel (nothing is opened to the internet)
     The panel listens only on this server; you open it from your computer
     with ssh -L. Needs: SSH access to this server.

  4) More options (test certificate, self-signed)

EOF
        local default=1 reply
        [ "$previous" = ip ] && default=2
        reply="$(ask "Choose 1-4" "$default")"
        case "$reply" in
            1|domain) MODE=domain; return 0 ;;
            2|ip) MODE=ip; return 0 ;;
            3|tunnel) MODE=tunnel; return 0 ;;
            4) choose_more_modes && return 0 ;;
            *) warn "Pick a number from 1 to 4." ;;
        esac
    done
}

# choose_more_modes — the options that do not give a trusted certificate. Each
# one says exactly what the certificate will be.
choose_more_modes() {
    while :; do
        installer_lines <<'EOF'

More options (not for everyday use)

  1) A domain with a TEST certificate (Let's Encrypt staging)
     The page works, but browsers show a warning: the test authority is not
     trusted. Good for trying the setup without using up Let's Encrypt limits.

  2) This server's IP with a TEST certificate (Let's Encrypt staging)
     The same, for an address.

  3) A self-signed certificate on this server's IP
     The traffic is encrypted, but every browser warns and you compare the
     fingerprint yourself.

  0) Back

EOF
        case "$(ask "Choose 0-3" "0")" in
            1) MODE=domain; ACME=staging; return 0 ;;
            2) MODE=ip; ACME=staging; return 0 ;;
            3) MODE=selfsigned; return 0 ;;
            0|'') return 1 ;;
            *) warn "Pick a number from 0 to 3." ;;
        esac
    done
}

# check_domain — asks for the domain when it is not known and compares its
# public DNS with this server. A mismatch usually means DNS has not spread yet
# or a wrong record exists: the person can fix it and check again, or type
# another name, without running the installer again.
check_domain() {
    local previous out rc name
    previous="$(env_get PANEL_SITE)"; [ -n "$previous" ] || previous="$(env_get PANEL_DOMAIN)"
    [ "$(env_get PANEL_MODE)" = domain ] || previous=""
    if [ -z "$SITE" ]; then
        SITE="$(ask_until "Domain name for the panel (e.g. panel.example.com)" "$previous" valid_domain_name \
            "That is not a domain name. Use letters, digits, dots and hyphens, for example panel.example.com.")" \
            || die "a domain name is required (--site NAME)"
    fi
    [ -n "$SITE" ] || die "a domain name is required (--site NAME)"
    while :; do
        sub "Public DNS for $SITE"
        out=""; rc=0
        local args=(net-check domain "$SITE")
        [ -z "$PUBLIC_IP" ] || args+=(-public-ip "$PUBLIC_IP")
        out="$(agent "${args[@]}")" || rc=$?
        name="$(kv NAME "$out")"
        if [ "$rc" = 0 ]; then break; fi
        if [ "$rc" != 3 ]; then die "the DNS check could not run (exit $rc)"; fi
        local why; why="the name does not lead only to this server (A: $(kv A "$out" | sed 's/^$/-/'), AAAA: $(kv AAAA "$out" | sed 's/^$/-/'); this server: $(kv SERVER "$out" | sed 's/^$/unknown/'))"
        local fix="make every A and AAAA record of ${name:-$SITE} point at this server (delete a wrong AAAA rather than leave it), turn off any CDN proxying (DNS only), wait for DNS to spread, and run again. If this server is behind NAT, give its public address with --public-ip."
        if ! interactive; then
            abort dns_mismatch "${name:-$SITE}" \
                "A and AAAA records from several independent public DNS servers, compared with this server's addresses" "$why" "$fix"
        fi
        warn "$why"
        installer_text "$fix"; printf '\n'
        local again
        again="$(ask "Press Enter to check again, type another domain, or 0 to cancel" "")"
        case "$again" in
            0) say "Nothing was changed."; exit 0 ;;
            '') ;;
            *) if valid_domain_name "$again"; then SITE="$again"; else warn "That is not a domain name."; fi ;;
        esac
    done
    SITE="$name"
    TARGETS=()
    local a
    for a in $(kv A "$out" | tr ',' ' ') $(kv AAAA "$out" | tr ',' ' '); do
        TARGETS+=("$a $(family_of "$a")")
    done
    ok "$SITE -> $(printf '%s ' "${TARGETS[@]%% *}")- every A/AAAA record leads to this server"
}

valid_domain_name() {
    case "$1" in ''|*[!A-Za-z0-9.-]*|.*|-*|*..*|*.) return 1 ;; esac
    case "$1" in *.*) return 0 ;; *) return 1 ;; esac
}

# --------------------------------------------------------- the outside check -

# setup_probe reads the RemoteProbe settings. Nothing is asked and nothing is
# required: a RemoteProbe runs on ANOTHER machine, and auditdsec installs,
# updates and works on one server. Without one the outside check is simply
# "not checked". A third-party public service is never used automatically.
setup_probe() {
    PROBE_URL="${PROBE_URL:-$(env_get PANEL_PROBE_URL)}"
    PROBE_TOKEN_FILE="${PROBE_TOKEN_FILE:-$(env_get PANEL_PROBE_TOKEN_FILE)}"
    PROBE_CACERT="${PROBE_CACERT:-$(cfg PANEL_PROBE_CACERT)}"
    EXT_CONFIGURED=no
    [ "$MODE" = tunnel ] && return 0
    if [ "$NO_EXTERNAL" = yes ]; then
        say "The outside check is switched off (--no-external-check)."
        return 0
    fi
    [ -n "$PROBE_URL" ] && [ -n "$PROBE_TOKEN_FILE" ] || return 0
    if [ ! -r "$PROBE_TOKEN_FILE" ]; then
        warn "The RemoteProbe token file $PROBE_TOKEN_FILE cannot be read: the outside check is skipped."
        return 0
    fi
    PROBE_TOKEN_FILE="$(readlink -f "$PROBE_TOKEN_FILE")"
    if [ -n "$PROBE_CACERT" ]; then
        if [ ! -r "$PROBE_CACERT" ]; then
            warn "The RemoteProbe CA file $PROBE_CACERT cannot be read: the outside check is skipped."
            return 0
        fi
        PROBE_CACERT="$(readlink -f "$PROBE_CACERT")"
    fi
    EXT_CONFIGURED=yes
}

# ------------------------------------------------------------------ the port ---

# own_proxy_running — this installation's own proxy is up, so the ports it uses
# (80 and the panel port) are held by us, not by a stranger.
own_proxy_running() {
    [ "$($DOCKER inspect -f '{{.State.Running}}' auditdsec-caddy 2>/dev/null || true)" = true ]
}

# select_port — the panel's public HTTPS port.
#
#   --https-port N     exactly that port; if it does not work the run stops
#   --https-port auto  the older search: 443, then random high ports (explicit only)
#   nothing            an existing installation keeps its port without any check
#                      (its own proxy holds it); a new one starts with 443
select_port() {
    case "$MODE" in tunnel) return 0 ;; esac
    local previous current_mode
    previous="$(env_get PANEL_HTTPS_PORT)"; current_mode="$(env_get PANEL_MODE)"
    if [ -z "$HTTPS_PORT" ]; then
        if [ -n "$previous" ] && [ -n "$current_mode" ] && [ "$current_mode" != tunnel ]; then
            HTTPS_PORT="$previous"; HTTPS_SOURCE=kept
        elif [ "$PREVIOUS_INSTALL" = yes ] && [ -n "$current_mode" ] && [ "$current_mode" != tunnel ]; then
            HTTPS_PORT=443; HTTPS_SOURCE=kept   # set up before the port was a choice: it was 443
        else
            HTTPS_PORT=443; HTTPS_SOURCE=default
        fi
    elif [ "$HTTPS_PORT" = auto ]; then
        HTTPS_SOURCE=auto
    else
        HTTPS_SOURCE=manual
    fi

    sub "The panel's HTTPS port"
    case "$HTTPS_SOURCE" in
        kept)
            if own_proxy_running || [ "$NO_EXTERNAL" = yes ]; then
                ok "port $HTTPS_PORT stays as it is (this installation's own proxy holds it)"
                EXT_PORT_STATE=""
                return 0
            fi ;;
        auto) select_port_auto; return 0 ;;
    esac
    valid_port_number "$HTTPS_PORT" || die "the port must be a number from 1 to 65535"

    while :; do
        local rc=0
        try_port "$HTTPS_PORT" || rc=$?
        case "$rc" in
            0) break ;;
            1)
                local why="${TRIED[${#TRIED[@]}-1]#*: }"
                if [ "$HTTPS_SOURCE" = manual ] || ! interactive; then port_failure "$HTTPS_PORT"; fi
                warn "Port $HTTPS_PORT cannot be used: $why"
                installer_lines <<'EOF'
Nothing that holds the port was stopped and the firewall was not changed.
Choose another HTTPS port; the link will contain it (https://name:PORT).
EOF
                HTTPS_PORT="$(ask_until "Another port (1-65535), or 0 to cancel" "" valid_port_or_cancel "That is not a port number (1-65535).")" \
                    || die "no port was chosen"
                if [ "$HTTPS_PORT" = 0 ]; then say "Nothing was changed."; exit 0; fi
                HTTPS_SOURCE=manual ;;
            *) break ;;   # the outside check itself failed: advice only, see below
        esac
    done
    if [ "$EXT_CONFIGURED" = yes ]; then
        EXT_PORT_STATE=reachable
        ok "port $HTTPS_PORT: free here and reached from outside on $(printf '%s ' "${TARGETS[@]%% *}")"
    else
        EXT_PORT_STATE=skipped
        ok "port $HTTPS_PORT can be bound here (reachability from outside was not checked: no outside-check provider is configured)"
    fi
}

valid_port_or_cancel() { [ "$1" = 0 ] || valid_port_number "$1"; }

# select_port_auto — the older automatic search, only when asked for by name.
select_port_auto() {
    local lo hi up cands p rc found=no
    up="${PORT:-$(env_get PANEL_UPSTREAM_PORT)}"; up="${up:-$(env_get PANEL_PORT)}"; up="${up:-9477}"
    read -r lo hi < <(port_range)
    cands="$(agent port-plan -first 443 -n 16 -lo "$lo" -hi "$hi" -exclude "80,2019,$up")"
    for p in $cands; do
        rc=0
        try_port "$p" || rc=$?
        case "$rc" in
            0) HTTPS_PORT="$p"; found=yes; break ;;
            1) say "  $p: ${TRIED[${#TRIED[@]}-1]#*: }" ;;
            *) HTTPS_PORT="$p"; found=yes; break ;;
        esac
    done
    if [ "$found" = no ]; then
        local list; list="$(printf '%s; ' "${TRIED[@]}")"
        abort "${LAST_PORT_CODE:-port_in_use}" "${SITE}, ports $(printf '%s' "$cands" | tr '\n' ' ')" \
            "443 and $(($(printf '%s\n' "$cands" | wc -l) - 1)) random ports from $lo-$hi" \
            "none of the checked ports is available (${list%; }). Only these ports were tried, not every port." \
            "free a port or give one with --https-port N"
    fi
    EXT_PORT_STATE=skipped; [ "$EXT_CONFIGURED" != yes ] || EXT_PORT_STATE=reachable
    ok "port $HTTPS_PORT chosen automatically (--https-port auto)"
}

# try_port PORT — 0 when the port is free here (and, when an outside check is
# configured, reached from outside). 1: this port does not work (TRIED gets the
# reason). 2: the outside check could not run; that says nothing about the port.
try_port() {
    local p="$1" why
    why="$(reserved_port "$p")"
    if [ -n "$why" ]; then TRIED+=("$p: $why"); LAST_PORT_CODE=port_in_use; return 1; fi
    # This installation's own proxy already holds its port: that is not a conflict.
    if own_proxy_running && [ "$p" = "$(env_get PANEL_HTTPS_PORT)" ]; then return 0; fi
    if ! bind_check "$p"; then
        TRIED+=("$p: in use on this server ($BIND_REASON)"); LAST_PORT_CODE=port_in_use
        return 1
    fi
    if [ "$EXT_CONFIGURED" != yes ] || [ "$MODE" = tunnel ]; then return 0; fi
    local rc=0
    reach_from_outside "$p" || rc=$?
    case "$rc" in
        0) return 0 ;;
        1) # A working provider could not reach the port. The local app would be fine;
           # the person is told, and decides. This is not a reason to refuse to install.
           warn "The outside-check provider could not reach port $p: $EXT_REASON"
           say "Continuing: this server cannot prove or disprove reachability from the internet. Check the firewall of this server and of the provider."
           EXT_PORT_STATE="check failed"
           return 0 ;;
        *) warn "The outside-check provider did not answer: $EXT_REASON"
           EXT_PORT_STATE="provider unavailable"
           return 2 ;;
    esac
}

port_failure() {
    local p="$1" last="${TRIED[${#TRIED[@]}-1]#*: }"
    abort port_in_use "$(hostport "${TARGETS[0]% *}" "$p")" \
        "binding TCP port $p on all IPv4 and IPv6 addresses of this server" \
        "$last" \
        "free the port or choose another one with --https-port N. Nothing that holds it was stopped."
}

# check_challenge — what the certificate needs. Port 80 must be free here (the
# challenge and the redirect use it); whether the internet reaches it is only
# known if an outside check is configured, and is otherwise said to be unknown.
check_challenge() {
    case "$MODE" in domain|ip) ;; *) return 0 ;; esac
    sub "What the certificate needs"
    # This installation's own proxy holds port 80 already: that is not a conflict.
    if ! own_proxy_running && ! bind_check 80; then
        abort acme_challenge_unreachable "$(hostport "${TARGETS[0]% *}" 80)" \
            "binding port 80, where Let's Encrypt sends the HTTP-01 challenge" \
            "port 80 is used by another program ($BIND_REASON)" \
            "this installer does not stop another web server, and does not route the challenge through one. Free port 80 (or move that site), or put the panel on a domain served by that web server yourself. DNS-01 is not supported by this installer yet."
    fi
    if [ "$EXT_CONFIGURED" != yes ]; then
        ACME_PORT_STATE="port 80 is free here; reachability from the internet was not checked"
        say "$ACME_PORT_STATE"
        return 0
    fi
    if own_proxy_running; then
        ACME_PORT_STATE="port 80 is held by this installation's proxy; reachability from the internet was not re-checked"
        say "$ACME_PORT_STATE"
        return 0
    fi
    local rc=0
    reach_from_outside 80 || rc=$?
    case "$rc" in
        0) ACME_PORT_STATE="port 80 reached from outside (HTTP-01)"; ok "$ACME_PORT_STATE" ;;
        1) ACME_PORT_STATE="port 80 was NOT reached by the outside-check provider"
           warn "$ACME_PORT_STATE ($EXT_REASON). If Let's Encrypt cannot reach it either, the certificate will not be issued and the previous configuration will be restored." ;;
        *) ACME_PORT_STATE="port 80 reachability: the provider did not answer"
           warn "$ACME_PORT_STATE ($EXT_REASON)." ;;
    esac
    return 0
}
