#!/usr/bin/env python3
"""Certificate helper that runs inside the certbot container.

It does the four things the shell hook could not do honestly:

  check      is the certificate on disk fit to be used as it is?
  adopt      use certbot's own copy when it is fit, without asking the CA
  deploy     certbot's deploy hook: put the new files where Caddy reads them,
             make Caddy load them, and PROVE it by comparing the fingerprint of
             the certificate Caddy actually serves on port 443 with the file
  reconcile  the retry loop: if the files and what port 443 serves disagree,
             fix that, whatever the reason was last time
  status     the container's health check

Only the standard library and `cryptography`, which certbot itself depends on,
are used, so it needs nothing the certbot image does not already have.

Environment (all optional):
  CERT_DIR       where Caddy reads the files           /certs
  LINEAGE_DIR    certbot's live directory              /etc/letsencrypt/live/panel
  CADDY_ADMIN    Caddy's admin API                     http://127.0.0.1:2019
  CADDYFILE      the file posted back to Caddy         /etc/caddy/Caddyfile
  TLS_HOST       where to look at what Caddy serves    127.0.0.1
  TLS_PORT       and on which port                     443
  PANEL_SITE     the domain or address
  PANEL_ACME     staging or production
  PANEL_ACME_URL the ACME directory in use
  PANEL_NO_RELOAD=1  copy only; for the very first issuance, before Caddy runs
"""
import datetime
import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import serialization

CERT_DIR = os.environ.get("CERT_DIR", "/certs")
LINEAGE_DIR = os.environ.get("LINEAGE_DIR", "/etc/letsencrypt/live/panel")
CADDY_ADMIN = os.environ.get("CADDY_ADMIN", "http://127.0.0.1:2019")
CADDYFILE = os.environ.get("CADDYFILE", "/etc/caddy/Caddyfile")
TLS_HOST = os.environ.get("TLS_HOST", "127.0.0.1")
TLS_PORT = int(os.environ.get("TLS_PORT", "443"))
VERIFY_WAIT = float(os.environ.get("VERIFY_WAIT", "15"))
RELOAD_ATTEMPTS = int(os.environ.get("RELOAD_ATTEMPTS", "6"))

PEM_RE = re.compile(rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.S)


def log(msg, err=False):
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"{stamp} certtool: {msg}", file=sys.stderr if err else sys.stdout, flush=True)


def leaf_of(path):
    data = open(path, "rb").read()
    blocks = PEM_RE.findall(data)
    if not blocks:
        raise ValueError(f"{path} holds no certificate")
    return x509.load_pem_x509_certificate(blocks[0])


def fingerprint_of(cert):
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def file_fingerprint(path):
    try:
        return fingerprint_of(leaf_of(path))
    except (OSError, ValueError):
        return None


def served_fingerprint(site):
    """The fingerprint of the certificate port 443 presents right now, or None.

    No credentials of any kind are sent: this is a bare TLS handshake, which is
    why it may skip verification. What it asks is "which certificate", not
    "is it trusted".
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sni = None
    try:
        ipaddress.ip_address(site)
    except ValueError:
        sni = site or None
    try:
        with socket.create_connection((TLS_HOST, TLS_PORT), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni) as tls:
                der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError):
        return None
    return hashlib.sha256(der).hexdigest() if der else None


def san_of(cert):
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return [], []
    return ext.get_values_for_type(x509.DNSName), ext.get_values_for_type(x509.IPAddress)


def key_matches(cert, key_path):
    try:
        key = serialization.load_pem_private_key(open(key_path, "rb").read(), password=None)
    except (OSError, ValueError, TypeError):
        return None
    pub = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    return key.public_key().public_bytes(*pub) == cert.public_key().public_bytes(*pub)


def read_json(path):
    try:
        return json.load(open(path))
    except (OSError, ValueError):
        return {}


def write_json(path, value):
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(value, fh, indent=1)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc)


# ------------------------------------------------------------------ check --

def check(cert_path, key_path, site, acme, directory, meta_path, min_remaining, require_meta=True):
    """Return the list of reasons the certificate cannot be reused; empty means fine."""
    reasons = []
    try:
        cert = leaf_of(cert_path)
    except (OSError, ValueError) as err:
        return [f"no usable certificate file ({err})"]

    dns, ips = san_of(cert)
    try:
        want_ip = ipaddress.ip_address(site)
    except ValueError:
        want_ip = None
    if want_ip is not None:
        have = sorted({str(ipaddress.ip_address(i)) for i in ips})
        if want_ip not in {ipaddress.ip_address(i) for i in ips}:
            reasons.append(f"it is for {', '.join(have) or 'no address'}, not for {site}")
    else:
        names = sorted({d.lower() for d in dns})
        if site.lower() not in names:
            reasons.append(f"it is for {', '.join(names) or 'no name'}, not for {site}")

    now = now_utc()
    if cert.not_valid_before_utc > now + datetime.timedelta(minutes=5):
        reasons.append(f"it is not valid before {cert.not_valid_before_utc:%Y-%m-%d %H:%M} UTC")
    left = (cert.not_valid_after_utc - now).total_seconds()
    if left <= 0:
        reasons.append(f"it expired on {cert.not_valid_after_utc:%Y-%m-%d %H:%M} UTC")
    elif left < min_remaining:
        reasons.append(f"it ends in {int(left // 3600)} h ({cert.not_valid_after_utc:%Y-%m-%d %H:%M} UTC), too soon to rely on")

    matched = key_matches(cert, key_path)
    if matched is None:
        reasons.append("the private key is missing or unreadable")
    elif not matched:
        reasons.append("the private key does not belong to this certificate")

    issuer = cert.issuer.rfc4514_string()
    if acme == "production" and "STAGING" in issuer.upper():
        reasons.append(f"it was issued by a staging CA ({issuer}), not a production one")
    meta = read_json(meta_path)
    if meta:
        if meta.get("acme") and meta["acme"] != acme:
            reasons.append(f"it was issued for {meta['acme']}, this installation uses {acme}")
        if directory and meta.get("directory") and meta["directory"] != directory:
            reasons.append("it came from a different ACME server than the one configured now")
        if meta.get("site") and meta["site"].lower() != site.lower():
            reasons.append(f"it was issued for {meta['site']}")
    elif require_meta:
        reasons.append("nothing records which CA issued it")
    return reasons


def renewal_server(conf="/etc/letsencrypt/renewal/panel.conf"):
    try:
        for line in open(conf):
            key, _, value = line.partition("=")
            if key.strip() == "server":
                return value.strip()
    except OSError:
        pass
    return ""


def adopt(site):
    """Use certbot's own lineage when it is fit, without asking the CA for anything.

    This covers a /certs directory that was lost or never filled while the
    lineage in /etc/letsencrypt is fine. The same tests as `check` apply, and
    the lineage must also have come from the ACME server configured now.
    """
    acme = os.environ.get("PANEL_ACME", "production")
    directory = os.environ.get("PANEL_ACME_URL", "")
    cert = os.path.join(LINEAGE_DIR, "fullchain.pem")
    key = os.path.join(LINEAGE_DIR, "privkey.pem")
    reasons = check(cert, key, site, acme, directory, "", 86400, require_meta=False)
    server = renewal_server()
    if directory and server and server != directory:
        reasons.append("certbot's lineage came from a different ACME server")
    if reasons:
        for r in reasons:
            print(r)
        return 3
    copy_lineage()
    return 0


# ----------------------------------------------------------------- deploy --

def copy_lineage():
    """Put the lineage's files where Caddy reads them. Returns the new fingerprint."""
    os.makedirs(CERT_DIR, exist_ok=True)
    pairs = [("fullchain.pem", 0o644), ("privkey.pem", 0o640)]
    for name, mode in pairs:
        src = os.path.join(LINEAGE_DIR, name)
        tmp = os.path.join(CERT_DIR, "." + name + ".new")
        with open(src, "rb") as fi, open(tmp, "wb") as fo:
            fo.write(fi.read())
        os.chmod(tmp, mode)
    # Move the key first and the chain last: whoever sees the new chain finds
    # the key that goes with it already there.
    os.replace(os.path.join(CERT_DIR, ".privkey.pem.new"), os.path.join(CERT_DIR, "privkey.pem"))
    os.replace(os.path.join(CERT_DIR, ".fullchain.pem.new"), os.path.join(CERT_DIR, "fullchain.pem"))
    fp = file_fingerprint(os.path.join(CERT_DIR, "fullchain.pem"))
    write_json(os.path.join(CERT_DIR, "meta.json"), {
        "site": os.environ.get("PANEL_SITE", ""),
        "acme": os.environ.get("PANEL_ACME", "production"),
        "directory": os.environ.get("PANEL_ACME_URL", ""),
        "fingerprint": fp,
        "copied": now_utc().isoformat(),
    })
    return fp


def post_reload():
    """Ask Caddy to load its configuration again. Returns an error string or None."""
    try:
        body = open(CADDYFILE, "rb").read()
    except OSError as err:
        return f"cannot read {CADDYFILE}: {err}"
    req = urllib.request.Request(
        CADDY_ADMIN.rstrip("/") + "/load", data=body, method="POST",
        headers={"Content-Type": "text/caddyfile",
                 # Caddy ignores a reload of a configuration identical to the
                 # one it has, and would keep serving the old certificate.
                 "Cache-Control": "must-revalidate"})
    try:
        with urllib.request.urlopen(req, timeout=30) as res:
            return None if res.status == 200 else f"caddy answered HTTP {res.status}"
    except urllib.error.HTTPError as err:
        return f"caddy refused the configuration: HTTP {err.code} {err.read(300).decode('utf-8', 'replace')}"
    except (urllib.error.URLError, OSError) as err:
        return f"cannot reach caddy's admin API at {CADDY_ADMIN}: {err}"


def reload_and_verify(site, want, attempts):
    """Reload Caddy until port 443 serves the certificate with fingerprint `want`."""
    last = "unknown"
    for n in range(1, attempts + 1):
        err = post_reload()
        if err is None:
            deadline = time.time() + VERIFY_WAIT
            while time.time() < deadline:
                got = served_fingerprint(site)
                if got == want:
                    return True, ""
                time.sleep(0.5)
            got = served_fingerprint(site)
            last = ("caddy reloaded but port 443 serves "
                    + (f"{got[:16]}…" if got else "nothing")
                    + f", not the new certificate {want[:16]}…")
        else:
            last = err
        if n < attempts:
            pause = min(2 ** n, 30)
            log(f"reload attempt {n}/{attempts} failed: {last}; retrying in {pause}s", err=True)
            time.sleep(pause)
    return False, last


def set_status(state, detail="", fingerprint=None):
    path = os.path.join(CERT_DIR, "status.json")
    old = read_json(path)
    since = old.get("since") if old.get("state") == state else None
    write_json(path, {"state": state, "detail": detail, "fingerprint": fingerprint,
                      "since": since or now_utc().isoformat(),
                      "checked": now_utc().isoformat()})


def deploy(site):
    lineage = os.environ.get("RENEWED_LINEAGE")
    if not lineage:
        log("RENEWED_LINEAGE is not set; certbot did not call this", err=True)
        return 1
    global LINEAGE_DIR
    LINEAGE_DIR = lineage
    fp = copy_lineage()
    log(f"certificate {fp[:16]}… copied to {CERT_DIR}")
    if os.environ.get("PANEL_NO_RELOAD") == "1":
        set_status("not-loaded", "copied; the proxy has not been started yet", fp)
        log("PANEL_NO_RELOAD=1: not reloading (the proxy starts after the first issuance)")
        return 0
    ok, why = reload_and_verify(site, fp, RELOAD_ATTEMPTS)
    if ok:
        set_status("ok", "", fp)
        log(f"caddy now serves certificate {fp[:16]}… on port {TLS_PORT}")
        return 0
    set_status("reload-failed", why, fp)
    log(f"RELOAD FAILED: {why}. The new certificate is on disk but is NOT being served; "
        "the retry loop will keep trying every minute.", err=True)
    return 1


# -------------------------------------------------------------- reconcile --

def reconcile(site):
    lineage_fp = file_fingerprint(os.path.join(LINEAGE_DIR, "fullchain.pem"))
    if lineage_fp is None:
        log("no certificate has been issued yet")
        return 0
    disk = os.path.join(CERT_DIR, "fullchain.pem")
    if file_fingerprint(disk) != lineage_fp:
        log(f"the files in {CERT_DIR} are not the newest certificate; copying {lineage_fp[:16]}…")
        copy_lineage()
    want = file_fingerprint(disk)
    served = served_fingerprint(site)
    if served == want:
        if read_json(os.path.join(CERT_DIR, "status.json")).get("state") != "ok":
            log(f"caddy serves the current certificate {want[:16]}…")
        set_status("ok", "", want)
        return 0
    if served is None:
        log("nothing answers TLS on port %d yet; will look again" % TLS_PORT, err=True)
        set_status("caddy-down", "port %d does not answer" % TLS_PORT, want)
        return 1
    log(f"port 443 serves {served[:16]}…, the current certificate is {want[:16]}…; reloading", err=True)
    ok, why = reload_and_verify(site, want, 2)
    if ok:
        set_status("ok", "", want)
        log(f"caddy now serves certificate {want[:16]}…")
        return 0
    set_status("reload-failed", why, want)
    log(f"RELOAD FAILED: {why}", err=True)
    return 1


def status(site):
    st = read_json(os.path.join(CERT_DIR, "status.json"))
    disk = os.path.join(CERT_DIR, "fullchain.pem")
    want = file_fingerprint(disk)
    if want is None:
        print("no certificate")
        return 1
    cert = leaf_of(disk)
    if cert.not_valid_after_utc <= now_utc():
        print("certificate expired")
        return 1
    if served_fingerprint(site) != want:
        print("port 443 does not serve the current certificate: " + (st.get("detail") or st.get("state", "?")))
        return 1
    print("ok")
    return 0


# ------------------------------------------------------------------- main --

def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    cmd, args = argv[1], argv[2:]
    site = os.environ.get("PANEL_SITE", "")
    if cmd == "check":
        opts = dict(zip(args[::2], args[1::2]))
        reasons = check(opts["--cert"], opts["--key"], opts["--site"], opts["--acme"],
                        opts.get("--directory", ""), opts.get("--meta", ""),
                        int(opts.get("--min-remaining", "86400")))
        for r in reasons:
            print(r)
        return 3 if reasons else 0
    if cmd == "fingerprint":
        fp = file_fingerprint(args[0])
        print(fp or "")
        return 0 if fp else 1
    if cmd == "served":
        fp = served_fingerprint(args[0] if args else site)
        print(fp or "")
        return 0 if fp else 1
    if cmd == "deploy":
        return deploy(site)
    if cmd == "adopt":
        return adopt(site)
    if cmd == "reconcile":
        return reconcile(site)
    if cmd == "status":
        return status(site)
    print(f"unknown command {cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
