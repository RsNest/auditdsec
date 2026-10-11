# shellcheck shell=bash disable=SC2034
# Keeping what runs the same as what was chosen.
#
# The panel works only when the agent and the proxy are set up for each other:
# both in the host's network, the agent's web server on 127.0.0.1:<upstream
# port>, the proxy sending requests there. That depends on several Compose
# files being used together. Before this file existed the set lived only in
# this script's memory, so any later `docker compose up -d` run from the
# directory used docker-compose.yml alone: the agent was recreated in a bridge
# network and the proxy, still running in the host network, answered 502.
#
# Two mechanisms keep that from happening again:
#
#   * COMPOSE_FILE (and COMPOSE_PATH_SEPARATOR) are saved in .env, which is
#     Compose's own mechanism. They are file names only, never a secret. A plain
#     `docker compose up -d` in the installation directory now uses the same set
#     as the installer, and changing the mode rewrites the list, so nothing
#     stale is left behind.
#   * The resolved configuration (what Compose WOULD start) is checked against
#     the chosen mode before anything is applied, both with the installer's
#     explicit file list and the way a plain `docker compose` would read it; and
#     after the start the containers Docker really created are inspected.
#
# Sourced by install.sh.

# compose_file_value — the list of files as COMPOSE_FILE writes it.
compose_file_value() {
    local out="" i
    for ((i = 1; i < ${#COMPOSE_FILES[@]}; i += 2)); do
        out="${out:+$out:}${COMPOSE_FILES[$i]}"
    done
    printf '%s' "$out"
}

# persist_compose_files — writes the current file list into .env. Called after
# build_compose_files wherever a configuration is applied or restored. An old
# configuration without these keys (an installation from before they existed,
# or a .env.last-good that predates them) gets them here.
persist_compose_files() {
    [ -f "$ENV_FILE" ] || return 0
    env_set COMPOSE_FILE "$(compose_file_value)"
    env_set COMPOSE_PATH_SEPARATOR ":"
}

# deploy_expect_flags — the arguments of `auditdsec deploy-check` for the
# configuration in MODE, PORT, HTTPS_PORT, ENFORCE and the control link.
deploy_expect_flags() {
    local f=(-mode "$MODE" -upstream-port "$PORT")
    [ "$MODE" = tunnel ] || f+=(-https-port "$HTTPS_PORT")
    [ "$ENFORCE" != yes ] || f+=(-enforce)
    [ "$(env_get PANEL_CONTROL)" != 1 ] || f+=(-control)
    printf '%s\n' "${f[@]}"
}

# DEPLOY_PROBLEMS — one line per disagreement found by deploy_check.
DEPLOY_PROBLEMS=""

# deploy_check JSON — runs the checker of the application image on a Compose
# configuration read from the variable. Returns 0 consistent, 3 not, 2 when the
# image has no such command (an old image: restoring one must not be blocked by
# a checker it does not have).
deploy_check() {
    local out rc=0 flags=()
    mapfile -t flags < <(deploy_expect_flags)
    out="$(printf '%s' "$1" | $DOCKER run --rm -i --network none "$IMAGE" deploy-check "${flags[@]}" 2>&1)" || rc=$?
    DEPLOY_PROBLEMS=""
    case "$rc" in
        0) return 0 ;;
        3) DEPLOY_PROBLEMS="$(printf '%s\n' "$out" | sed -n 's/^PROBLEM|//p')"; return 3 ;;
        *) return 2 ;;
    esac
}

# plain_compose_config — what `docker compose config` prints in this directory
# with no -f at all, which is what a plain `docker compose up -d` would start.
plain_compose_config() {
    env -u COMPOSE_FILE -u COMPOSE_PATH_SEPARATOR $DOCKER compose config --format json 2>/dev/null
}

# check_compose_consistency — the guard before anything is applied. The
# explicit file list and the plain reading must both describe the chosen
# architecture. A failure is reported as service_start_failed with the
# disagreeing values, and nothing has been started yet.
check_compose_consistency() {
    local explicit plain rc=0
    explicit="$(compose config --format json 2>/dev/null)" || { sub "docker compose cannot resolve the configuration"; return 0; }
    deploy_check "$explicit" || rc=$?
    case "$rc" in
        0) sub "The Compose configuration matches the chosen mode ($MODE, upstream 127.0.0.1:$PORT)" ;;
        3)
            report service_start_failed "$(compose_prefix)" "checking the Compose configuration against the chosen mode ($MODE)" \
                "it would not work: $(printf '%s' "$DEPLOY_PROBLEMS" | tr '\n' ';')" \
                "this is a fault in the installation's files, not in your input: do not start it. Report it with the trace ID below; ./install.sh --restore returns to the last working configuration"
            return 1 ;;
        *) sub "This image cannot check the Compose configuration (an older version): skipped" ;;
    esac
    if [ "$ENV_FILE" != ".env" ] || [ "$rc" = 2 ]; then return 0; fi
    plain="$(plain_compose_config)" || return 0
    rc=0
    deploy_check "$plain" || rc=$?
    if [ "$rc" = 3 ]; then
        report service_start_failed "docker compose (without -f) in $(pwd)" "reading the configuration the way a plain 'docker compose up -d' would" \
            "COMPOSE_FILE in $ENV_FILE does not give the chosen setup: $(printf '%s' "$DEPLOY_PROBLEMS" | tr '\n' ';')" \
            "run ./install.sh again; it rewrites COMPOSE_FILE. Until then do not run docker compose by hand in this directory"
        return 1
    fi
    sub "A plain 'docker compose up -d' here would start the same setup (COMPOSE_FILE is saved in $ENV_FILE)"
    return 0
}

# netmode NAME — the network mode Docker really gave a container, or nothing.
netmode() { $DOCKER inspect -f '{{.HostConfig.NetworkMode}}' "$1" 2>/dev/null || true; }

# running NAME — whether the container is running.
running() { [ "$($DOCKER inspect -f '{{.State.Running}}' "$1" 2>/dev/null || true)" = true ]; }

# deployment_facts — what Docker has actually created, set in DEP_AGENT_NET and
# DEP_PROXY_NET (empty when the container does not exist).
DEP_AGENT_NET=""
DEP_PROXY_NET=""
deployment_facts() {
    DEP_AGENT_NET="$(netmode auditdsec)"
    DEP_PROXY_NET=""
    case "$MODE" in domain|ip|selfsigned) DEP_PROXY_NET="$(netmode auditdsec-caddy)" ;; esac
}

# deployment_problem — compares the created containers with the architecture
# (both in the host network; the agent on 127.0.0.1:PORT). Prints one sentence
# naming the actual values when they disagree, nothing when they agree or when
# there is nothing to compare. This needs Docker, so it is the installer's job,
# not the agent's: the agent gets no Docker socket for diagnosis.
deployment_problem() {
    deployment_facts
    [ -n "$DEP_AGENT_NET" ] || return 0
    case "$MODE" in
        tunnel)
            [ "$DEP_AGENT_NET" = host ] && return 0
            printf 'The agent runs in network %s; with an SSH tunnel it must be in the host network to listen on 127.0.0.1:%s.' "$DEP_AGENT_NET" "$PORT" ;;
        domain|ip|selfsigned)
            [ -n "$DEP_PROXY_NET" ] || return 0
            [ "$DEP_AGENT_NET" = host ] && [ "$DEP_PROXY_NET" = host ] && return 0
            printf 'Caddy expects the upstream 127.0.0.1:%s in the %s network; the agent runs in the %s network.' "$PORT" "$DEP_PROXY_NET" "$DEP_AGENT_NET" ;;
    esac
}

# diagnose_unreachable — called when the panel does not answer. It says what is
# known: whether the backend answers on its upstream, what the proxy answers,
# and which networks the containers are in. The agent keeps handling audit
# events whatever the state of its web server.
diagnose_unreachable() {
    local backend proxy_code mismatch
    backend="$(curl -sS --noproxy '*' --max-time 3 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/api/v1/setup/state" 2>/dev/null || true)"
    mismatch="$(deployment_problem)"
    DIAG_TEXT=""
    if [ "$MODE" != tunnel ]; then
        proxy_code="$(curl -sSk --noproxy '*' ${ROUTE[@]+"${ROUTE[@]}"} --max-time 5 -o /dev/null -w '%{http_code}' "$PANEL_URL/" 2>/dev/null || true)"
    fi
    if [ -n "$mismatch" ]; then
        DIAG_TEXT="The agent is running, but the panel is not reachable. $mismatch"
    elif [ "${backend:-000}" != 200 ]; then
        DIAG_TEXT="The agent does not answer on 127.0.0.1:$PORT (HTTP ${backend:-none}); the proxy answers ${proxy_code:-nothing}."
    elif [ "${proxy_code:-}" = 502 ]; then
        DIAG_TEXT="The agent answers on 127.0.0.1:$PORT, but the proxy answers 502: it is not sending requests to that address."
    else
        DIAG_TEXT="The agent answers on 127.0.0.1:$PORT (HTTP $backend); the proxy answers ${proxy_code:-nothing}."
    fi
    jlog error diagnosis "$DIAG_TEXT (agent network ${DEP_AGENT_NET:-none}, proxy network ${DEP_PROXY_NET:-none}, backend ${backend:-none}, proxy ${proxy_code:-none})"
}

# check_created_containers — after the start: the containers Docker created
# must be in the networks the architecture needs. A failure is reported with
# the real values. Returns 0 when they agree.
check_created_containers() {
    local problem
    problem="$(deployment_problem)"
    if [ -n "$problem" ]; then
        report service_start_failed "docker inspect auditdsec${DEP_PROXY_NET:+ auditdsec-caddy}" "reading the network settings of the containers that were created" \
            "The agent is running, but the panel is not reachable. $problem" \
            "the containers were created with another set of Compose files than the installer chose. Run ./install.sh --action repair; do not start this directory with docker compose -f of your own"
        return 1
    fi
    [ -z "$DEP_AGENT_NET" ] || sub "Containers: the agent is in the $DEP_AGENT_NET network${DEP_PROXY_NET:+, the proxy in the $DEP_PROXY_NET network}"
    return 0
}

# agent_note — said with a failure: the agent's job (reading the audit log and
# alerting) does not depend on its web server, and a broken panel does not stop it.
agent_note() {
    [ "${DOCKER:-}" != false ] || return 0
    running auditdsec || return 0
    printf 'still running and processing audit events; only the panel is affected'
}

# repair_deployment — brings the running containers back to the saved
# configuration: the same files, nothing removed. Volumes (events, credentials,
# certificates, ACME account) are not touched and no certificate is requested
# again; the data stay where they are. Used by --action repair.
repair_deployment() {
    persist_compose_files
    check_compose_consistency || return 1
    local upcmd=(up -d --no-build --remove-orphans)
    if ! compose "${upcmd[@]}"; then
        report service_start_failed "$(compose_prefix)" "docker compose up" "the containers did not start" "look at: $(compose_prefix) logs --tail 80"
        return 1
    fi
    STACK_STARTED=yes
    return 0
}
