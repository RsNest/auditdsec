# shellcheck shell=bash
# Display-only translations. Never translate commands, configuration values,
# or states used by the installer to decide whether publication succeeded.
# The catalog is data, not shell code; neither it nor user input is evaluated.
declare -A INSTALLER_MESSAGES=()
INSTALLER_PATTERNS=()
INSTALLER_TRANSLATIONS=()

installer_load_messages() {
    local en ru rest i ch regex
    while IFS=$'\t' read -r en ru rest || [ -n "$en" ]; do
        [[ -z "$en" || "$en" == \#* ]] && continue
        if [ -z "$ru" ] || [ -n "$rest" ]; then
            printf 'Invalid installer translation: %s\n' "$en" >&2
            return 1
        fi
        INSTALLER_MESSAGES["$en"]="$ru"
        [[ "$en" == *'%s'* ]] || continue
        regex='^'
        for ((i=0; i<${#en}; i++)); do
            if [ "${en:i:2}" = '%s' ]; then
                regex+='(.*)'; i=$((i + 1)); continue
            fi
            ch="${en:i:1}"
            case "$ch" in
                '.'|'['|']'|'\'|'*'|'^'|'$'|'('|')'|'+'|'?'|'{'|'}'|'|') regex+="\\$ch" ;;
                *) regex+="$ch" ;;
            esac
        done
        INSTALLER_PATTERNS+=("$regex"'$')
        INSTALLER_TRANSLATIONS+=("$ru")
    done < deploy/installer.messages
}

installer_text() {
    local text="$1" i
    if [ "$INSTALLER_LANG" = en ] || [ -z "$text" ]; then printf '%s' "$text"; return; fi
    if [ "${INSTALLER_MESSAGES[$text]+present}" = present ]; then
        printf '%s' "${INSTALLER_MESSAGES[$text]}"
        return
    fi
    for i in "${!INSTALLER_PATTERNS[@]}"; do
        if [[ "$text" =~ ${INSTALLER_PATTERNS[$i]} ]]; then
            # Only the catalog supplies the printf format. Captures are data,
            # including %, backslashes and shell metacharacters in an address.
            # shellcheck disable=SC2059
            printf -- "${INSTALLER_TRANSLATIONS[$i]}" "${BASH_REMATCH[@]:1}"
            return
        fi
    done
    printf '%s' "$text"  # foreign output, URLs and machine codes stay intact
}

installer_printf() {
    local format="$1"
    shift
    if [ "$INSTALLER_LANG" = ru ] && [ -n "$format" ] && [ "${INSTALLER_MESSAGES[$format]+present}" = present ]; then
        format="${INSTALLER_MESSAGES[$format]}"
    fi
    # shellcheck disable=SC2059
    printf -- "$format" "$@"
}

installer_lines() {
    local line
    while IFS= read -r line || [ -n "$line" ]; do
        installer_text "$line"
        printf '\n'
    done
}

installer_choose_language() {
    local explicit='' saved='' quiet=no option value reply args=("$@") i
    for ((i=0; i<${#args[@]}; i++)); do
        option="${args[$i]}"
        case "$option" in
            --lang)
                i=$((i + 1)); value="${args[$i]:-}"
                if [ "$value" != ru ] && [ "$value" != en ]; then
                    printf 'Ошибка: --lang принимает ru или en / Error: --lang requires ru or en\n' >&2
                    return 1
                fi
                explicit="$value" ;;
            --yes|-y|--help|-h) quiet=yes ;;
        esac
    done
    # Read just this setting; never source .env containing credentials.
    if [ -f "$ENV_FILE" ]; then
        saved="$(grep '^PANEL_INSTALLER_LANG=' "$ENV_FILE" | tail -n 1 || true)"
        saved="${saved#PANEL_INSTALLER_LANG=}"
        saved="${saved%$'\r'}"
        saved="${saved#\'}"; saved="${saved%\'}"
        saved="${saved#\"}"; saved="${saved%\"}"
    fi
    case "$saved" in ru|en) ;; *) saved='' ;; esac
    INSTALLER_LANG="${explicit:-${saved:-ru}}"
    if [ -n "$explicit" ] || [ -n "$saved" ] || [ "$quiet" = yes ] || [ ! -t 0 ]; then return 0; fi
    printf '\nВыберите язык установщика / Choose installer language:\n\n'
    printf '  1) Русский — оставить\n  2) English\n\n'
    while :; do
        read -r -p 'Ваш выбор / Your choice [1]: ' reply </dev/tty || reply=''
        case "$reply" in
            ''|1|ru) INSTALLER_LANG=ru; return 0 ;;
            2|en) INSTALLER_LANG=en; return 0 ;;
            *) printf 'Выберите 1 или 2 / Choose 1 or 2\n' >&2 ;;
        esac
    done
}
