#!/usr/bin/env python3
"""
AA5-followup live smoke: configure-saml discovers ALL signing certs.

Closes the AA5 weakest-point. Before this slice, `aether sso
configure-saml` extracted only the FIRST `<X509Certificate>` from
the IdP metadata. Operators rotating IdP certs had to:

  1. Run configure-saml against the new metadata (gets only ONE cert).
  2. Manually grep the metadata XML for the other certs.
  3. Hand-write each PEM to ~/.aether/saml/idp-certs/NN-name.pem.
  4. AA5's multi-cert loader then accepts SAMLResponses signed by
     either key.

This slice automates steps 2-3. Configure-saml now:
  - Extracts ALL `<KeyDescriptor use="signing"><X509Certificate>`
    nodes from the metadata, preserving document order.
  - Writes each as `~/.aether/saml/idp-certs/NN-discovered.pem`
    (PEM-armored, mode 0600). NN reflects metadata order, so the
    lex-sort the AA5 loader applies matches discovery order.
  - On re-run, clears existing `*.pem` in the directory first so
    stale certs from a prior rotation aren't silently retained.
  - Bails with a clear error when metadata has no signing certs.

The smoke:
  1. Mints two unrelated RSA-2048 IdP keypairs.
  2. Stands up a Python fake metadata server that returns both
     certs inside two separate `<md:KeyDescriptor use="signing">`
     blocks (canonical SAML metadata shape).
  3. Runs `aether sso configure-saml` against it.
  4. Asserts ~/.aether/saml/idp-certs/ contains exactly 2 PEM files,
     mode 0600, names `00-discovered.pem` and `01-discovered.pem`,
     each round-tripping byte-for-byte to its original cert DER.
  5. Drives a Y7-style SAML login signing with the SECOND key —
     AA5's multi-cert loader picks the directory, walks past slot
     0, matches slot 1, and Y3->Y7 pipeline completes; sso.token
     written at 0600.

Verifies both the discovery code path (configure-saml) and the
verify code path (load_idp_signing_keys + verify_saml_assertion_
signature first-match-wins) end-to-end against ZERO operator
hand-editing.
"""
import base64
import datetime as dt
import hashlib
import http.server
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID
import lxml.etree as ET

AETHER_BIN = "/root/aether-blueprint/target/release/aether"
NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
NS_DS = "http://www.w3.org/2000/09/xmldsig#"
SP_ENTITY = "https://sp.test/saml"
IDP_ENTITY = "https://idp.test/saml/metadata"
IDP_SSO_URL = "https://idp.test/saml/sso"


def exc_c14n(elem):
    return ET.tostring(elem, method="c14n", exclusive=True, with_comments=False)


def mint_keypair_and_cert(common_name: str):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    subj = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = dt.datetime.now(dt.UTC).replace(tzinfo=None)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subj)
        .issuer_name(issuer)
        .public_key(pub)
        .serial_number(1)
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .sign(priv, hashes.SHA256())
    )
    return priv, cert


def cert_der_b64(cert) -> str:
    return base64.standard_b64encode(
        cert.public_bytes(serialization.Encoding.DER)
    ).decode()


METADATA_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                     entityID="{idp_entity}">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>{cert_a_b64}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>{cert_b_b64}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="{sso_url}"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
"""


def build_signed_response_xml(priv, assertion_id: str, sp_entity: str):
    now = dt.datetime.now(dt.UTC).replace(tzinfo=None)
    issue = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    not_before = (now - dt.timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    not_after = (now + dt.timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    nsmap = {"saml": NS_SAML, "samlp": NS_SAMLP, "ds": NS_DS}

    def q(ns, name):
        return f"{{{ns}}}{name}"

    response = ET.Element(q(NS_SAMLP, "Response"), nsmap=nsmap)
    status = ET.SubElement(response, q(NS_SAMLP, "Status"))
    sc = ET.SubElement(status, q(NS_SAMLP, "StatusCode"))
    sc.set("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")
    assertion = ET.SubElement(
        response, q(NS_SAML, "Assertion"),
        ID=assertion_id, Version="2.0", IssueInstant=issue,
    )
    ai = ET.SubElement(assertion, q(NS_SAML, "Issuer"))
    ai.text = IDP_ENTITY
    subject = ET.SubElement(assertion, q(NS_SAML, "Subject"))
    nameid = ET.SubElement(subject, q(NS_SAML, "NameID"))
    nameid.text = "alice-aa5fu@idp.test"
    sub_conf = ET.SubElement(
        subject, q(NS_SAML, "SubjectConfirmation"),
        Method="urn:oasis:names:tc:SAML:2.0:cm:bearer",
    )
    ET.SubElement(
        sub_conf, q(NS_SAML, "SubjectConfirmationData"),
        NotOnOrAfter=not_after,
    )
    cond = ET.SubElement(
        assertion, q(NS_SAML, "Conditions"),
        NotBefore=not_before, NotOnOrAfter=not_after,
    )
    aud_r = ET.SubElement(cond, q(NS_SAML, "AudienceRestriction"))
    aud = ET.SubElement(aud_r, q(NS_SAML, "Audience"))
    aud.text = sp_entity

    digest_b64 = base64.standard_b64encode(
        hashlib.sha256(exc_c14n(assertion)).digest()
    ).decode()
    signature = ET.Element(q(NS_DS, "Signature"))
    signed_info = ET.SubElement(signature, q(NS_DS, "SignedInfo"))
    ET.SubElement(
        signed_info, q(NS_DS, "CanonicalizationMethod"),
        Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
    )
    ET.SubElement(
        signed_info, q(NS_DS, "SignatureMethod"),
        Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    )
    ref = ET.SubElement(signed_info, q(NS_DS, "Reference"), URI=f"#{assertion_id}")
    transforms = ET.SubElement(ref, q(NS_DS, "Transforms"))
    ET.SubElement(
        transforms, q(NS_DS, "Transform"),
        Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature",
    )
    ET.SubElement(
        transforms, q(NS_DS, "Transform"),
        Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
    )
    ET.SubElement(
        ref, q(NS_DS, "DigestMethod"),
        Algorithm="http://www.w3.org/2001/04/xmlenc#sha256",
    )
    dv = ET.SubElement(ref, q(NS_DS, "DigestValue"))
    dv.text = digest_b64

    assertion.insert(0, signature)
    si_after = signature.find(q(NS_DS, "SignedInfo"))
    sig_bytes = priv.sign(exc_c14n(si_after), padding.PKCS1v15(), hashes.SHA256())
    sv = ET.SubElement(signature, q(NS_DS, "SignatureValue"))
    sv.text = base64.standard_b64encode(sig_bytes).decode()

    return ET.tostring(response).decode()


def make_metadata_handler(meta_xml: str):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a, **kw):
            pass

        def do_GET(self):
            if self.path == "/metadata":
                body = meta_xml.encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/samlmetadata+xml")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
    return H


def find_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]; s.close()
    return p


def main():
    tmp = Path(tempfile.mkdtemp(prefix="aether-aa5fu-"))
    home = tmp

    # 1. Two unrelated keypairs.
    priv_a, cert_a = mint_keypair_and_cert("aa5fu-idp-A")
    priv_b, cert_b = mint_keypair_and_cert("aa5fu-idp-B")
    meta_xml = METADATA_TEMPLATE.format(
        idp_entity=IDP_ENTITY,
        sso_url=IDP_SSO_URL,
        cert_a_b64=cert_der_b64(cert_a),
        cert_b_b64=cert_der_b64(cert_b),
    )

    # 2. Stand up the metadata server.
    port = find_port()
    httpd = http.server.HTTPServer(("127.0.0.1", port), make_metadata_handler(meta_xml))
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    meta_url = f"http://127.0.0.1:{port}/metadata"
    print(f"[smoke] fake metadata at {meta_url}")

    # 3. Run configure-saml.
    env = os.environ.copy()
    env["HOME"] = str(home)
    res = subprocess.run(
        [AETHER_BIN, "sso", "configure-saml",
         "--idp-metadata-url", meta_url,
         "--sp-entity-id", SP_ENTITY],
        env=env, capture_output=True, text=True, timeout=20,
    )
    print(res.stdout)
    print(res.stderr, file=sys.stderr)
    if res.returncode != 0:
        print(f"FAIL: configure-saml exit {res.returncode}")
        sys.exit(1)
    if "2 discovered" not in res.stderr:
        print("FAIL: configure-saml did not report 2 signing certs discovered")
        sys.exit(1)

    # 4. Assert idp-certs/ directory shape.
    idp_certs_dir = home / ".aether" / "saml" / "idp-certs"
    if not idp_certs_dir.is_dir():
        print(f"FAIL: {idp_certs_dir} not a directory")
        sys.exit(1)
    pems = sorted(p.name for p in idp_certs_dir.glob("*.pem"))
    if pems != ["00-discovered.pem", "01-discovered.pem"]:
        print(f"FAIL: unexpected idp-certs/ contents: {pems}")
        sys.exit(1)
    for name in pems:
        p = idp_certs_dir / name
        mode = p.stat().st_mode & 0o777
        if mode != 0o600:
            print(f"FAIL: {name} mode is 0{mode:o}, expected 0600")
            sys.exit(1)
        # Round-trip: written PEM → decode → DER == original.
        loaded = x509.load_pem_x509_certificate(p.read_bytes())
        expected = cert_a if name == "00-discovered.pem" else cert_b
        if loaded.public_bytes(serialization.Encoding.DER) != \
                expected.public_bytes(serialization.Encoding.DER):
            print(f"FAIL: {name} did not round-trip to its source cert")
            sys.exit(1)
    print("[smoke] idp-certs/ has 2 PEMs (mode 0600); both round-trip "
          "byte-for-byte to source certs")

    # 5. Drive a Y7-style SAML login signing with key B (slot 1) →
    #    AA5's multi-cert verifier must walk past slot 0 and accept.
    env["AETHER_SAML_CLOCK_SKEW_S"] = "120"
    log = home / "aether-login.log"
    proc = subprocess.Popen(
        [AETHER_BIN, "sso", "login"],
        env=env, stdout=open(log, "wb"), stderr=subprocess.STDOUT,
    )
    ports_seen = None
    relay_state = None
    for _ in range(80):
        try:
            data = log.read_text()
        except FileNotFoundError:
            data = ""
        m = re.search(r"waiting on 127\.0\.0\.1:(\d+)", data)
        if m:
            ports_seen = int(m.group(1))
            rs = re.search(r"RelayState=([A-Za-z0-9_\-]+)", data)
            if rs:
                relay_state = rs.group(1)
            break
        time.sleep(0.1)
    if ports_seen is None:
        proc.kill()
        print("FAIL: no listener port emitted")
        print(log.read_text())
        sys.exit(1)

    response_xml = build_signed_response_xml(priv_b, "_a-aa5fu", SP_ENTITY)
    resp_b64 = base64.standard_b64encode(response_xml.encode()).decode()
    body = "SAMLResponse=" + urllib.parse.quote(resp_b64, safe="")
    if relay_state:
        body += "&RelayState=" + urllib.parse.quote(relay_state, safe="")
    req = urllib.request.Request(
        f"http://127.0.0.1:{ports_seen}/sso/saml/acs",
        data=body.encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        if r.status != 200:
            print(f"FAIL: ACS HTTP {r.status}")
            sys.exit(1)
    proc.wait(timeout=15)
    log_text = log.read_text()
    if "against 2 configured IdP cert(s)" not in log_text:
        print("FAIL: aether log does not mention 2-cert verify")
        print(log_text)
        sys.exit(1)
    sso_token = home / ".aether" / "sso.token"
    if not sso_token.exists() or not sso_token.read_text().startswith("saml.v1."):
        print("FAIL: sso.token not written / wrong prefix")
        sys.exit(1)
    print("[smoke] login with key-B-signed response verified against the 2 "
          "auto-discovered certs (slot 0 missed, slot 1 matched)")
    print("[smoke] AA5-followup LIVE-VERIFIED OK "
          "(configure-saml multi-cert discovery + verifier rotation)")

    httpd.shutdown()


if __name__ == "__main__":
    main()
