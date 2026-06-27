#!/usr/bin/env python3
"""
Y7 live smoke: generate an RSA-2048 keypair + a properly signed
SAMLResponse (using lxml's exc-c14n), write the IdP cert to
~/.aether/saml/idp-cert.pem, launch `aether sso login`, POST the
signed response, and verify that ~/.aether/sso.token gets written
by Y7.
"""
import base64
import datetime as dt
import hashlib
import os
import re
import subprocess
import sys
import tempfile
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


def exc_c14n(elem):
    return ET.tostring(elem, method="c14n", exclusive=True, with_comments=False)


def main():
    tmp = Path(tempfile.mkdtemp(prefix="aether-y7-"))
    home = tmp
    saml_dir = home / ".aether" / "saml"
    saml_dir.mkdir(parents=True)

    privkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pubkey = privkey.public_key()
    subj = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "y7-idp")])
    now = dt.datetime.now(dt.UTC).replace(tzinfo=None)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subj)
        .issuer_name(issuer)
        .public_key(pubkey)
        .serial_number(1)
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .sign(privkey, hashes.SHA256())
    )
    (saml_dir / "idp-cert.pem").write_bytes(
        cert.public_bytes(serialization.Encoding.PEM)
    )

    (home / ".aether" / "sso-saml.json").write_text(
        '{"version":1,"idp_entity_id":"%s","sso_url":"https://idp.test/saml/sso",'
        '"sso_binding":"Redirect","sp_entity_id":"%s"}' % (IDP_ENTITY, SP_ENTITY)
    )

    # Build assertion as a real XML tree so lxml can c14n it.
    issue = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    not_before = (now - dt.timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    not_after = (now + dt.timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")

    nsmap = {"saml": NS_SAML, "samlp": NS_SAMLP, "ds": NS_DS}

    def q(ns, name):
        return f"{{{ns}}}{name}"

    # Response wrapper.
    response = ET.Element(q(NS_SAMLP, "Response"), nsmap=nsmap)
    status = ET.SubElement(response, q(NS_SAMLP, "Status"))
    sc = ET.SubElement(status, q(NS_SAMLP, "StatusCode"))
    sc.set("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")
    assertion = ET.SubElement(
        response, q(NS_SAML, "Assertion"),
        ID="_a-y7", Version="2.0", IssueInstant=issue,
    )
    ai = ET.SubElement(assertion, q(NS_SAML, "Issuer"))
    ai.text = IDP_ENTITY
    subject = ET.SubElement(assertion, q(NS_SAML, "Subject"))
    nameid = ET.SubElement(subject, q(NS_SAML, "NameID"))
    nameid.text = "alice-y7@idp.test"
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
    aud.text = SP_ENTITY

    # Reference digest: c14n the Assertion (without Signature yet).
    assertion_canonical = exc_c14n(assertion)
    digest_b64 = base64.standard_b64encode(
        hashlib.sha256(assertion_canonical).digest()
    ).decode()

    # SignedInfo with that digest.
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
    ref = ET.SubElement(signed_info, q(NS_DS, "Reference"), URI="#_a-y7")
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

    # Splice the Signature INTO the assertion (as first child) so
    # the enveloped-signature transform is applicable when aether
    # canonicalizes the assertion for the digest verify.
    assertion.insert(0, signature)
    # We need to put SignedInfo into the spliced signature; we've
    # already constructed it as a child of `signature`, so that's
    # done.

    # Now compute the SignatureValue: c14n the SignedInfo subtree
    # (after splicing — so its inherited namespace context matches
    # what aether sees).
    signed_info_after_splice = signature.find(q(NS_DS, "SignedInfo"))
    signed_info_canonical = exc_c14n(signed_info_after_splice)
    sig_bytes = privkey.sign(
        signed_info_canonical, padding.PKCS1v15(), hashes.SHA256()
    )
    sig_b64 = base64.standard_b64encode(sig_bytes).decode()
    sv = ET.SubElement(signature, q(NS_DS, "SignatureValue"))
    sv.text = sig_b64

    response_xml = ET.tostring(response).decode()
    resp_b64 = base64.standard_b64encode(response_xml.encode()).decode()
    body = "SAMLResponse=" + urllib.parse.quote(resp_b64, safe="")

    log = home / "aether.log"
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["AETHER_SAML_CLOCK_SKEW_S"] = "120"
    proc = subprocess.Popen(
        [AETHER_BIN, "sso", "login"],
        env=env,
        stdout=open(log, "wb"),
        stderr=subprocess.STDOUT,
    )
    port = None
    relay_state = None
    for _ in range(80):
        try:
            data = log.read_text()
        except FileNotFoundError:
            data = ""
        m = re.search(r"waiting on 127\.0\.0\.1:(\d+)", data)
        if m:
            port = int(m.group(1))
            # Extract the RelayState from the redirect URL so we can
            # echo it back in the ACS POST (mandatory CSRF check).
            rs_m = re.search(r"RelayState=([A-Za-z0-9_\-]+)", data)
            if rs_m:
                relay_state = rs_m.group(1)
            break
        time.sleep(0.1)
    if port is None:
        proc.kill()
        print("FAIL: no listener port")
        print(log.read_text())
        sys.exit(1)
    print(f"[smoke] ACS port={port}, RelayState={relay_state}")

    post_body = body
    if relay_state:
        post_body += "&RelayState=" + urllib.parse.quote(relay_state, safe="")

    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/sso/saml/acs",
        data=post_body.encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        print(f"[smoke] POST returned HTTP {r.status}")

    proc.wait(timeout=15)
    print("--- aether log ---")
    print(log.read_text())
    sso_token_path = home / ".aether" / "sso.token"
    if not sso_token_path.exists():
        print("FAIL: ~/.aether/sso.token was NOT written")
        sys.exit(1)
    token_text = sso_token_path.read_text()
    print(f"--- sso.token ({len(token_text)} bytes) ---")
    print(token_text)
    if not token_text.startswith("saml.v1."):
        print("FAIL: token does not have saml.v1. prefix")
        sys.exit(1)
    mode = sso_token_path.stat().st_mode & 0o777
    if mode != 0o600:
        print(f"FAIL: token file mode is 0{mode:o}, expected 0600")
        sys.exit(1)
    print(f"[smoke] sso.token mode = 0{mode:o} (expected 0600)")
    print("[smoke] Y7 LIVE-VERIFIED OK")


if __name__ == "__main__":
    main()
