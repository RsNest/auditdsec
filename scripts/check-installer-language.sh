#!/usr/bin/env bash
# Language and output checks only: no Docker, network or installation.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=../deploy/installer-i18n.sh
source deploy/installer-i18n.sh
INSTALLER_LANG=ru
installer_load_messages

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
equal() { [ "$1" = "$2" ] || fail "$3: got <$1>, expected <$2>"; }

# A mistranslated printf placeholder can lose an address or insert arguments
# into the wrong diagnostic. Check every catalog entry before publication.
declare -A seen=()
while IFS=$'\t' read -r en ru extra; do
    [[ -z "$en" || "$en" == \#* ]] && continue
    [ -n "$ru" ] && [ -z "$extra" ] || fail "invalid catalog row: $en"
    [ "${seen[$en]+present}" != present ] || fail "duplicate catalog key: $en"
    seen["$en"]=1
    a="${en//'%s'/}"; b="${ru//'%s'/}"
    [ "$(( (${#en} - ${#a}) / 2 ))" = "$(( (${#ru} - ${#b}) / 2 ))" ] || fail "placeholder mismatch: $en"
done < deploy/installer.messages

equal "$(installer_text '')" '' 'empty message'
equal "$(installer_text 'Choose 1 or 2')" 'Выберите 1 или 2' 'Russian prompt'
equal "$(installer_text 'Keep the panel on port 55443?')" 'Оставить панель на порту 55443?' 'dynamic port'
equal "$(installer_printf '%sThe panel is published.%s\n' '' '')" 'Панель опубликована.' 'publication summary'
equal "$(installer_printf '\n%sFAILED: %s%s\n' '' port_in_use '')" $'\nОШИБКА: port_in_use' 'unchanged machine code'
equal "$(installer_text 'https://[2001:db8::1]:55443')" 'https://[2001:db8::1]:55443' 'unchanged URL'
equal "$(installer_printf '  Link: %s%s%s\n' '' 'https://example.com:55443' '')" '  Link: https://example.com:55443' 'unchanged link'
# shellcheck disable=SC2016
literal='image $(exit 99);%s\n'
equal "$(installer_text "$literal")" 'образ $(exit 99);%s\n' 'captures are data, not code or a format'
INSTALLER_LANG=en
equal "$(installer_text 'Choose 1 or 2')" 'Choose 1 or 2' 'English prompt'
equal "$(installer_printf '%sThe panel is published.%s\n' '' '')" 'The panel is published.' 'English summary'

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
export ENV_FILE="$tmp/settings.env"
out="$(bash ./install.sh --help </dev/null)"
[[ "$out" == *'Использование:'* && "$out" == *'--lang ru|en'* ]] || fail 'headless default must be Russian'
[ ! -e "$ENV_FILE" ] || fail 'help must not write configuration'
printf "PANEL_INSTALLER_LANG='en'\nAUDITDSEC_LANG='ru'\n" > "$ENV_FILE"
before="$(cat "$ENV_FILE")"
out="$(bash ./install.sh --help </dev/null)"
[[ "$out" == *'Usage:'* ]] || fail 'saved language must be reused'
out="$(bash ./install.sh --help --lang ru </dev/null)"
[[ "$out" == *'Использование:'* ]] || fail 'explicit language must override saved language, even after --help'
equal "$(cat "$ENV_FILE")" "$before" 'help must not change Telegram settings'
if bash ./install.sh --lang de --help > "$tmp/invalid" 2>&1; then fail 'invalid language accepted'; fi
grep -q -- '--lang' "$tmp/invalid" || fail 'invalid language must explain the flag'
printf 'Installer language checks passed.\n'
