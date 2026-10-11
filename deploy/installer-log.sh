# shellcheck shell=bash disable=SC2034
# The installer's diagnostic log.
#
# Everything the project's own code logs on this server goes under one
# directory, /var/log/auditseclogs (override: AUDITSEC_LOG_DIR), one stream per
# component and never one file shared by two processes:
#
#   installer.jsonl           this script: installs, updates, access changes (JSON lines)
#   installer-commands.log    raw output of the programs it ran (docker pull, compose up, ...)
#
# The agent, the panel API, the browser error reports, the control service, the
# proxy and the certificate renewal write their own streams there (see
# docs/LOGS.md). This file is written by exactly one process at a time (the
# installer holds the lock) and rotated here, by the installer, and by nobody
# else. The agent only removes archives that are too old or over the budget.
#
# Every operation gets a trace_id. The control service passes the one it made
# in AUDITDSEC_TRACE_ID, so one change can be followed from the panel through
# the installer.

LOG_DIR="${AUDITSEC_LOG_DIR:-/var/log/auditseclogs}"
LOG_MAX_BYTES="${AUDITSEC_LOG_MAX_BYTES:-10485760}"      # 10 MiB per active file
LOG_KEEP="${AUDITSEC_LOG_KEEP:-5}"                        # archives per stream
LOG_MAX_DAYS="${AUDITSEC_LOG_MAX_DAYS:-14}"              # age limit of archives
LOG_BUDGET="${AUDITSEC_LOG_BUDGET:-536870912}"           # 512 MiB for the directory
LOG_MAX_LINE=3500                                         # a record stays a single atomic append

LOG_FILE=""
LOG_RAW=""
LOG_DEGRADED=""
TRACE_ID=""
OPERATION=""

# log_commit — the commit of this tree, or nothing (an unexpanded export-subst
# placeholder is not a commit). Read once.
LOG_COMMIT_CACHE=""
log_commit() {
    if [ -z "$LOG_COMMIT_CACHE" ]; then
        local c
        c="$(head -n 1 deploy/source-commit 2>/dev/null || true)"
        case "$c" in ''|*[!0-9a-f]*) c="" ;; esac
        LOG_COMMIT_CACHE="${c:-none}"
    fi
    [ "$LOG_COMMIT_CACHE" = none ] || printf '%s' "$LOG_COMMIT_CACHE"
}

new_trace_id() { head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

valid_trace_id() { case "$1" in ''|*[!0-9a-f]*) return 1 ;; esac; [ "${#1}" -ge 16 ] && [ "${#1}" -le 32 ]; }

# jstr STRING — a JSON string body: quotes, backslashes and every control
# character handled, secrets of the usual shapes masked, and the length capped.
jstr() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"; s="${s//$'\r'/\\r}"; s="${s//$'\t'/\\t}"
    s="$(printf '%s' "$s" | LC_ALL=C tr -d '\000-\010\013\014\016-\037\177')"
    s="$(printf '%s' "$s" | LC_ALL=C sed -E \
        -e 's#(password|passwd|secret|token|api[_-]?key)([=:] *)[^ ",;]+#\1\2***#Ig' \
        -e 's#(Authorization:? *(Bearer|Basic) +)[^ ",;]+#\1***#Ig' \
        -e 's#(://[^/:@ ]+:)[^/@ ]+@#\1***@#g' \
        -e 's#(pbkdf2-sha256\$)[^ ",;]+#\1***#g')"
    if [ "${#s}" -gt "$LOG_MAX_LINE" ]; then s="${s:0:LOG_MAX_LINE}...[truncated]"; fi
    printf '%s' "$s"
}

# log_init OPERATION — names the operation and its trace, and prepares the
# directory and files. A directory that cannot be used degrades the log (said
# once, on standard error) and never stops the installer.
log_init() {
    OPERATION="$1"
    if valid_trace_id "${AUDITDSEC_TRACE_ID:-}"; then TRACE_ID="$AUDITDSEC_TRACE_ID"; else TRACE_ID="$(new_trace_id)"; fi
    export AUDITDSEC_TRACE_ID="$TRACE_ID"
    LOG_FILE="$LOG_DIR/installer.jsonl"
    LOG_RAW="$LOG_DIR/installer-commands.log"
    if ! mkdir -p "$LOG_DIR" 2>/dev/null || ! chmod 0750 "$LOG_DIR" 2>/dev/null \
        || ! { : >> "$LOG_FILE"; } 2>/dev/null || ! chmod 0640 "$LOG_FILE" 2>/dev/null; then
        log_degrade "cannot write to $LOG_DIR"
    fi
}

log_degrade() {
    [ -n "$LOG_DEGRADED" ] && return 0
    LOG_DEGRADED="$1"
    printf '%s\n' "$(installer_text 'warning: the diagnostic log is unavailable:') $1" >&2
}

# log_rotate FILE — size-based rotation with compression of older archives.
# Called with the installer lock held, so there is no concurrent writer.
log_rotate() {
    local f="$1" size i suf
    [ -f "$f" ] || return 0
    size="$(wc -c < "$f" 2>/dev/null || echo 0)"
    [ "$size" -gt "$LOG_MAX_BYTES" ] || return 0
    rm -f "$f.$LOG_KEEP" "$f.$LOG_KEEP.gz"
    for ((i = LOG_KEEP - 1; i >= 1; i--)); do
        for suf in "" .gz; do
            [ -e "$f.$i$suf" ] && mv -f "$f.$i$suf" "$f.$((i + 1))$suf"
        done
    done
    mv -f "$f" "$f.1" && : > "$f" && chmod 0640 "$f"
    if [ -e "$f.2" ] && command -v gzip >/dev/null 2>&1; then gzip -f "$f.2" 2>/dev/null || true; fi
    return 0
}

# log_maintain — rotate this installer's streams, drop archives past the age
# limit, and keep the directory under its budget by removing the oldest
# archives (never an active file).
log_maintain() {
    [ -z "$LOG_DEGRADED" ] || return 0
    log_rotate "$LOG_FILE"
    log_rotate "$LOG_RAW"
    find "$LOG_DIR" -maxdepth 1 -type f \( -name '*.jsonl.[0-9]*' -o -name '*.log.[0-9]*' \) -mtime "+$LOG_MAX_DAYS" -delete 2>/dev/null || true
    local total oldest
    total="$(du -sk "$LOG_DIR" 2>/dev/null | cut -f1)"; total=$((${total:-0} * 1024))
    while [ "$total" -gt "$LOG_BUDGET" ]; do
        oldest="$(find "$LOG_DIR" -maxdepth 1 -type f \( -name '*.jsonl.[0-9]*' -o -name '*.log.[0-9]*' \) -printf '%T@ %p\n' 2>/dev/null | sort -n | head -n 1 | cut -d' ' -f2-)"
        [ -n "$oldest" ] || break
        rm -f "$oldest" || break
        total="$(du -sk "$LOG_DIR" 2>/dev/null | cut -f1)"; total=$((${total:-0} * 1024))
    done
}

# jlog LEVEL EVENT MESSAGE [ERROR_CODE [DURATION_MS]] — one JSON line.
jlog() {
    [ -n "$LOG_FILE" ] && [ -z "$LOG_DEGRADED" ] || return 0
    local level="$1" event="$2" msg="$3" code="${4:-}" dur="${5:-}" line
    line="{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)\",\"level\":\"$(jstr "$level")\",\"service\":\"installer\",\"event\":\"$(jstr "$event")\",\"message\":\"$(jstr "$msg")\""
    line="$line,\"version\":\"$(jstr "$(head -n 1 VERSION 2>/dev/null || true)")\",\"commit\":\"$(log_commit)\""
    line="$line,\"trace_id\":\"$TRACE_ID\",\"operation\":\"$(jstr "$OPERATION")\""
    [ -z "$dur" ] || line="$line,\"duration_ms\":$dur"
    [ -z "$code" ] || line="$line,\"error_code\":\"$(jstr "$code")\""
    if ! printf '%s}\n' "$line" >> "$LOG_FILE" 2>/dev/null; then log_degrade "write to $LOG_FILE failed (disk full or no permission)"; fi
    return 0
}

# logged LABEL COMMAND... — runs a program, shows its output as it comes, keeps
# it unchanged in installer-commands.log, and logs the result as a record. The
# exit status is the program's.
logged() {
    local label="$1" started rc ms
    shift
    started="$(date +%s%3N 2>/dev/null || echo 0)"
    if [ -n "$LOG_RAW" ] && [ -z "$LOG_DEGRADED" ]; then
        printf -- '--- %s trace=%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$TRACE_ID" "$label" >> "$LOG_RAW" 2>/dev/null || true
        { "$@" 2>&1; echo "$?" > "$LOG_DIR/.rc.$$"; } | tee -a "$LOG_RAW" || true
        rc="$(cat "$LOG_DIR/.rc.$$" 2>/dev/null || echo 1)"; rm -f "$LOG_DIR/.rc.$$"
    else
        "$@" && rc=0 || rc=$?
    fi
    ms=$(( $(date +%s%3N 2>/dev/null || echo 0) - started ))
    if [ "$rc" = 0 ]; then jlog info command_ok "$label" "" "$ms"; else jlog error command_failed "$label exited with $rc" "exit_$rc" "$ms"; fi
    return "$rc"
}

# last_operations — the most recent operations and their trace IDs (a read-only
# view for the diagnostics menu).
last_operations() {
    [ -r "$LOG_DIR/installer.jsonl" ] || return 0
    { grep -h '"event":"operation_start"' "$LOG_DIR/installer.jsonl" 2>/dev/null || true; } | tail -n "${1:-10}" \
        | sed -E 's/.*"ts":"([^"]+)".*"trace_id":"([0-9a-f]+)".*"operation":"([^"]*)".*/\1  \2  \3/'
}
