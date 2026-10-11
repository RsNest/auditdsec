# shellcheck shell=bash disable=SC2034
# The installer's face: colours, the banner, numbered stages, and the checks
# that must happen before anything else (root).
#
# Rules this file keeps:
#   * Colour only helps: every result also has a word (OK, WARN, FAIL), so the
#     output is complete without colour.
#   * No colour, no banner and nothing animated unless a person is looking:
#     standard output is a terminal, NO_COLOR is unset, TERM is not dumb, and
#     the run is interactive. Redirected output, log files, --json and
#     non-interactive runs get plain text only.
#   * Nothing clears the screen or hides what was already printed.
#   * No progress percentages: only stages that really exist ([2/5] ...).
#   * Nothing needs figlet, toilet or any other package.

# ui_init sets the colour variables. $1 is yes when the output is machine
# readable (--json), which turns every decoration off.
ui_init() {
    local machine="${1:-no}"
    B=""; R=""; G=""; Y=""; N=""; BRAND1=""; BRAND2=""; DIM=""
    E_R=""; E_Y=""; E_B=""; E_N=""
    UI_DECOR=no
    [ "$machine" = no ] || return 0
    local ok=yes
    [ -z "${NO_COLOR:-}" ] || ok=no
    case "${TERM:-dumb}" in dumb|"") ok=no ;; esac
    if [ "$ok" = yes ] && [ -t 1 ]; then
        B=$'\033[1m'; R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; N=$'\033[0m'
        case "${TERM:-}${COLORTERM:-}" in
            *256color*|*truecolor*|*24bit*) BRAND1=$'\033[38;5;81m'; BRAND2=$'\033[38;5;141m'; DIM=$'\033[38;5;245m' ;;
            *) BRAND1=$'\033[36m'; BRAND2=$'\033[35m'; DIM=$'\033[2m' ;;
        esac
    fi
    # Messages for errors go to standard error, which may be a terminal even
    # when standard output is a file, or the other way round.
    if [ "$ok" = yes ] && [ -t 2 ]; then
        E_B=$'\033[1m'; E_R=$'\033[31m'; E_Y=$'\033[33m'; E_N=$'\033[0m'
    fi
    # The banner is for a person at a terminal who can answer questions.
    if [ -t 1 ] && [ -t 0 ]; then UI_DECOR=yes; fi
}

ui_cols() {
    local c="${COLUMNS:-}"
    case "$c" in ''|*[!0-9]*) c="$(tput cols 2>/dev/null || true)" ;; esac
    case "$c" in ''|*[!0-9]*) c=80 ;; esac
    printf '%s' "$c"
}

# banner prints the AUDITSEC banner, the project name, the version and a short
# description. A narrow terminal gets a compact one. Never in machine output.
banner() {
    [ "$UI_DECOR" = yes ] && [ "${NO_BANNER:-}" != 1 ] || return 0
    local cols ver
    cols="$(ui_cols)"
    ver="$(ui_version)"
    printf '\n'
    if [ "$cols" -ge 60 ]; then
        local rows=(
"    _    _   _ ____ ___ _____ ____  _____ ____ "
"   / \\  | | | |  _ \\_ _|_   _/ ___|| ____/ ___|"
"  / _ \\ | | | | | | | |  | | \\___ \\|  _|| |    "
" / ___ \\| |_| | |_| | |  | |  ___) | |__| |___ "
"/_/   \\_\\___/|____/___| |_| |____/|_____\\____|"
        )
        local i=0 row
        for row in "${rows[@]}"; do
            if [ "$i" -lt 3 ]; then printf '%s%s%s\n' "$BRAND1" "$row" "$N"; else printf '%s%s%s\n' "$BRAND2" "$row" "$N"; fi
            i=$((i + 1))
        done
    else
        printf '%s== %sAUDIT%sSEC%s%s ==%s\n' "$BRAND1" "$B" "$BRAND2" "$N" "$BRAND1" "$N"
    fi
    printf '\n  %sauditdsec%s %s\n' "$B$BRAND1" "$N" "$ver"
    printf '  %s%s%s\n\n' "$DIM" "$(installer_text 'Understandable Linux audit alerts, brute-force protection and a web panel.')" "$N"
}

# ui_version — "v0.3.0 (commit abcdef123456)" from the files next to the script.
ui_version() {
    local v c
    v="$(head -n 1 VERSION 2>/dev/null || true)"
    c="$(head -n 1 deploy/source-commit 2>/dev/null || true)"
    case "$c" in *[!0-9a-f]*|'') c="" ;; esac
    if [ -z "$c" ] && command -v git >/dev/null 2>&1 && [ -d .git ]; then c="$(git rev-parse HEAD 2>/dev/null || true)"; fi
    printf 'v%s%s' "${v:-?}" "${c:+ (commit ${c:0:12})}"
}

# ---------------------------------------------------------------- stages ---

STEP_N=0
STEP_TOTAL=0

# steps_begin N — the number of stages the operation has. Stages are counted as
# they start; there is no percentage, only "stage n of N".
steps_begin() { STEP_N=0; STEP_TOTAL="$1"; }

# ---------------------------------------------------------------- root ---

# need_root stops the run, before anything is read or written, when it is not
# root. sudo is never called for the person and no password is asked for here.
need_root() {
    [ "$(id -u)" = 0 ] && return 0
    {
        installer_printf '%s%s%s\n' "$E_R$E_B" "$(installer_text 'ERROR: the installer was not run as root.')" "$E_N"
        installer_text 'Run the command with administrator rights:'; printf '\n'
        printf '  sudo ./install.sh\n'
        if ! command -v sudo >/dev/null 2>&1; then
            installer_text 'sudo is not installed here: sign in as root and run ./install.sh again.'; printf '\n'
        fi
    } >&2
    exit 1
}

# install_traps makes Ctrl+C and termination leave through the EXIT trap, which
# releases the lock and removes temporary resources.
install_traps() {
    trap 'exit 130' INT
    trap 'exit 143' TERM
}
