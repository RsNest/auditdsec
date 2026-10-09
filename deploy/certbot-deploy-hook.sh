#!/bin/sh
# Certbot runs this after it issues or renews the certificate.
#
# It copies the new files where Caddy reads them and asks Caddy to re-read
# them. Caddy treats a reload of an unchanged configuration as a no-op, so
# the request carries Cache-Control: must-revalidate, which is what makes it
# load the files again rather than keep the certificate it already has.
#
# A failure here leaves the renewed certificate on disk, so the worst case is
# that Caddy serves the old one until it is restarted.
set -eu

CERT_DIR="${CERT_DIR:-/certs}"
CADDY_ADMIN="${CADDY_ADMIN:-http://127.0.0.1:2019}"
CADDYFILE="${CADDYFILE:-/etc/caddy/Caddyfile}"

if [ -z "${RENEWED_LINEAGE:-}" ]; then
    echo "deploy hook: RENEWED_LINEAGE is not set; certbot did not call this" >&2
    exit 1
fi

mkdir -p "$CERT_DIR"
# Write beside the target and move into place, so Caddy can never read a
# half-written certificate.
cp "$RENEWED_LINEAGE/fullchain.pem" "$CERT_DIR/.fullchain.new"
cp "$RENEWED_LINEAGE/privkey.pem" "$CERT_DIR/.privkey.new"
chmod 0644 "$CERT_DIR/.fullchain.new"
chmod 0640 "$CERT_DIR/.privkey.new"
mv "$CERT_DIR/.fullchain.new" "$CERT_DIR/fullchain.pem"
mv "$CERT_DIR/.privkey.new" "$CERT_DIR/privkey.pem"
echo "deploy hook: certificate copied to $CERT_DIR"

if [ ! -r "$CADDYFILE" ]; then
    echo "deploy hook: $CADDYFILE is not readable, leaving the reload to the next restart" >&2
    exit 0
fi

# python3 is in the certbot image; curl is not guaranteed to be.
PANEL_SITE="${PANEL_SITE:-}" CADDY_ADMIN="$CADDY_ADMIN" CADDYFILE="$CADDYFILE" python3 - <<'PY' || {
import os, sys, urllib.error, urllib.request

body = open(os.environ["CADDYFILE"], "rb").read()
req = urllib.request.Request(
    os.environ["CADDY_ADMIN"].rstrip("/") + "/load",
    data=body,
    method="POST",
    headers={
        "Content-Type": "text/caddyfile",
        # Without this, Caddy sees the same configuration and does nothing,
        # so it would keep serving the certificate it already had.
        "Cache-Control": "must-revalidate",
    },
)
try:
    with urllib.request.urlopen(req, timeout=30) as res:
        print("deploy hook: caddy reloaded, HTTP", res.status)
except urllib.error.URLError as err:
    print("deploy hook: cannot reach caddy:", err, file=sys.stderr)
    sys.exit(1)
PY
    echo "deploy hook: caddy was not reloaded; it will use the new certificate after a restart" >&2
    exit 0
}
