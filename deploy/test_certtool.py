"""Tests for certtool.check: when a certificate on disk may be reused.

Run with any Python that has `cryptography`, for example the certbot image's:

    python3 -m unittest deploy/test_certtool.py -v
"""
import datetime
import ipaddress
import json
import os
import sys
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import certtool  # noqa: E402

NOW = datetime.datetime.now(datetime.timezone.utc)
DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"


def make(dir_, *, ips=(), dns=(), start=None, end=None, issuer="Fake CA", key=None):
    """Write fullchain.pem and privkey.pem; return their paths."""
    key = key or ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)])
    san = [x509.IPAddress(ipaddress.ip_address(i)) for i in ips] + [x509.DNSName(d) for d in dns]
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([]))
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(start or NOW - datetime.timedelta(hours=1))
            .not_valid_after(end or NOW + datetime.timedelta(days=5))
            .add_extension(x509.SubjectAlternativeName(san), critical=True)
            .sign(ec.generate_private_key(ec.SECP256R1()), hashes.SHA256()))
    cert_path, key_path = os.path.join(dir_, "fullchain.pem"), os.path.join(dir_, "privkey.pem")
    with open(cert_path, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as fh:
        fh.write(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cert_path, key_path


class CheckTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.meta = os.path.join(self.dir, "meta.json")

    def tearDown(self):
        self.tmp.cleanup()

    def write_meta(self, **kw):
        base = {"site": "203.0.113.4", "acme": "production", "directory": DIRECTORY}
        base.update(kw)
        with open(self.meta, "w") as fh:
            json.dump(base, fh)

    def check(self, cert, key, site="203.0.113.4", acme="production", directory=DIRECTORY, **kw):
        return certtool.check(cert, key, site, acme, directory, self.meta, kw.pop("min_remaining", 86400), **kw)

    def test_fitting_certificate_is_reusable(self):
        cert, key = make(self.dir, ips=["203.0.113.4"])
        self.write_meta()
        self.assertEqual(self.check(cert, key), [])

    def test_other_address(self):
        cert, key = make(self.dir, ips=["203.0.113.9"])
        self.write_meta()
        reasons = self.check(cert, key)
        self.assertTrue(any("203.0.113.9" in r and "not for 203.0.113.4" in r for r in reasons), reasons)

    def test_ipv6_is_compared_as_an_address_not_as_text(self):
        cert, key = make(self.dir, ips=["2001:db8::1"])
        self.write_meta(site="2001:0db8:0:0:0:0:0:1")
        self.assertEqual(self.check(cert, key, site="2001:0db8:0:0:0:0:0:1"), [])

    def test_domain_matches_case_insensitively_and_rejects_others(self):
        cert, key = make(self.dir, dns=["panel.example.com"])
        self.write_meta(site="Panel.Example.com")
        self.assertEqual(self.check(cert, key, site="Panel.Example.com"), [])
        self.assertTrue(self.check(cert, key, site="other.example.com"))

    def test_an_address_certificate_does_not_fit_a_domain(self):
        cert, key = make(self.dir, ips=["203.0.113.4"])
        self.write_meta(site="panel.example.com")
        self.assertTrue(self.check(cert, key, site="panel.example.com"))

    def test_expired(self):
        cert, key = make(self.dir, ips=["203.0.113.4"],
                         start=NOW - datetime.timedelta(days=8), end=NOW - datetime.timedelta(days=2))
        self.write_meta()
        self.assertTrue(any("expired" in r for r in self.check(cert, key)))

    def test_ending_too_soon(self):
        cert, key = make(self.dir, ips=["203.0.113.4"], end=NOW + datetime.timedelta(hours=5))
        self.write_meta()
        self.assertTrue(any("too soon" in r for r in self.check(cert, key)))

    def test_not_yet_valid(self):
        cert, key = make(self.dir, ips=["203.0.113.4"], start=NOW + datetime.timedelta(days=1),
                         end=NOW + datetime.timedelta(days=6))
        self.write_meta()
        self.assertTrue(any("not valid before" in r for r in self.check(cert, key)))

    def test_key_of_another_certificate(self):
        cert, _ = make(self.dir, ips=["203.0.113.4"])
        other = tempfile.TemporaryDirectory()
        try:
            _, other_key = make(other.name, ips=["203.0.113.4"])
            self.write_meta()
            self.assertTrue(any("does not belong" in r for r in self.check(cert, other_key)))
        finally:
            other.cleanup()

    def test_missing_key(self):
        cert, key = make(self.dir, ips=["203.0.113.4"])
        os.unlink(key)
        self.write_meta()
        self.assertTrue(any("key is missing" in r for r in self.check(cert, key)))

    def test_missing_certificate(self):
        self.assertTrue(any("no usable certificate" in r for r in
                            self.check(os.path.join(self.dir, "nope.pem"), os.path.join(self.dir, "nope.key"))))

    def test_staging_issuer_is_refused_in_production(self):
        cert, key = make(self.dir, ips=["203.0.113.4"], issuer="(STAGING) Pretend Pear X1")
        self.write_meta()
        self.assertTrue(any("staging CA" in r for r in self.check(cert, key)))

    def test_recorded_environment_must_match(self):
        cert, key = make(self.dir, ips=["203.0.113.4"])
        self.write_meta(acme="staging")
        reasons = self.check(cert, key, acme="production")
        self.assertTrue(any("issued for staging" in r for r in reasons), reasons)
        self.write_meta(acme="production")
        self.assertTrue(any("issued for production" in r for r in self.check(cert, key, acme="staging")))

    def test_other_acme_server(self):
        cert, key = make(self.dir, ips=["203.0.113.4"])
        self.write_meta(directory="https://acme-staging-v02.api.letsencrypt.org/directory")
        self.assertTrue(any("different ACME server" in r for r in self.check(cert, key)))

    def test_no_record_of_the_issuer_is_a_reason_unless_adopting(self):
        cert, key = make(self.dir, ips=["203.0.113.4"])
        self.assertTrue(any("records which CA" in r for r in self.check(cert, key)))
        self.assertEqual(self.check(cert, key, require_meta=False), [])

    def test_recorded_site_must_match(self):
        cert, key = make(self.dir, ips=["203.0.113.4"])
        self.write_meta(site="203.0.113.77")
        self.assertTrue(any("issued for 203.0.113.77" in r for r in self.check(cert, key)))


if __name__ == "__main__":
    unittest.main()
