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
RENEW_EVERY="${RENEW_EVERY:-43200}"
RETRY_AFTER="${RETRY_AFTER:-3600}"
TICK="${TICK:-60}"
next=0
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
        else
            echo "certbot renew FAILED; trying again in ${RETRY_AFTER}s" >&2
            next=$((now + RETRY_AFTER))
        fi
    fi
    python3 /hooks/certtool.py reconcile || true
    sleep "$TICK" &
    wait $!
done
