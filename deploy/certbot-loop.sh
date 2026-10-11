#!/bin/sh
# The certbot container's main process.
#
#   - every 12 hours: certbot renew. A failed attempt is retried after an hour,
#     not after another 12, because a certificate that lives six days cannot
#     afford to wait.
#   - every minute: certtool.py reconcile. It compares what is on disk with
#     what port 443 really serves and repairs the difference, so a reload that
#     failed once is retried until it works instead of being forgotten. The
#     renewal itself is not repeated for that; only the reload is.
trap 'exit 0' TERM INT

# Every renewal and every failure is also written, one JSON record each, to the
# central log directory (certs.jsonl, see docs/LOGS.md) next to the container's
# own output. A log that cannot be written never stops the loop. The file is
# rotated here by size (10 MiB, 5 archives); only this loop writes it.
LOG_DIR="${AUDITSEC_LOG_DIR:-/var/log/auditseclogs}"
LOG_FILE="$LOG_DIR/certs.jsonl"
log_event() { # LEVEL EVENT MESSAGE
    [ -d "$LOG_DIR" ] || return 0
    if [ -f "$LOG_FILE" ] && [ "$(wc -c < "$LOG_FILE" 2>/dev/null || echo 0)" -gt 10485760 ]; then
        i=4
        while [ "$i" -ge 1 ]; do
            [ -f "$LOG_FILE.$i" ] && mv -f "$LOG_FILE.$i" "$LOG_FILE.$((i + 1))"
            i=$((i - 1))
        done
        mv -f "$LOG_FILE" "$LOG_FILE.1" 2>/dev/null || true
    fi
    msg=$(printf '%s' "$3" | tr -d '\000-\037' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | cut -c1-500)
    printf '{"ts":"%s","level":"%s","service":"certs","event":"%s","message":"%s","site":"%s"}\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" "$2" "$msg" "${PANEL_SITE:-}" >> "$LOG_FILE" 2>/dev/null || true
}
RENEW_EVERY="${RENEW_EVERY:-43200}"
RETRY_AFTER="${RETRY_AFTER:-3600}"
TICK="${TICK:-60}"
next=0
log_event info start "certificate loop started"
while :; do
    now=$(date +%s)
    if [ "$now" -ge "$next" ]; then
        # --no-random-sleep-on-renew: without a terminal certbot waits a random
        # time up to eight minutes before renewing, which is pointless here (the
        # loop's own start time is already arbitrary) and long for a six-day
        # certificate.
        if certbot renew --cert-name panel --standalone --non-interactive \
                --no-random-sleep-on-renew --deploy-hook /hooks/deploy.sh; then
            next=$((now + RENEW_EVERY))
            log_event info renew_ok "certbot renew finished"
        else
            echo "certbot renew FAILED; trying again in ${RETRY_AFTER}s" >&2
            log_event error renew_failed "certbot renew failed; trying again in ${RETRY_AFTER}s"
            next=$((now + RETRY_AFTER))
        fi
    fi
    python3 /hooks/certtool.py reconcile || log_event warn reconcile_failed "the certificate on disk and the one served on port ${TLS_PORT:-443} could not be reconciled"
    sleep "$TICK" &
    wait $!
done
