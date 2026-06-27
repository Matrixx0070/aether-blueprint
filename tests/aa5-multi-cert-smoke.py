#!/usr/bin/env python3
"""
AA5 live smoke: multi-cert IdP rotation.

Demonstrates that two IdP signing certs can coexist in
~/.aether/saml/idp-certs/ and aether's first-match-wins verifier
accepts a SAMLResponse signed by EITHER. This is the
zero-downtime cert-rotation workflow:

  Day N    — `~/.aether/saml/idp-certs/00-old.pem` only.
  Day N+1  — drop `10-new.pem` next to it; the IdP starts signing
             with the new key. Aether logins keep working because
             the verifier still matches either configured key.
  Day N+M  — remove `00-old.pem` once the IdP has fully rotated.

The smoke runs two `aether sso login` invocations against the same
home directory with both certs present:

  1. SAMLResponse signed by the OLD key  → verify succeeds (the
     verifier finds a match in the first slot).
  2. SAMLResponse signed by the NEW key  → verify succeeds (the
     verifier walks past the first slot and matches the second).

Both runs assert the aether log mentions "against 2 configured IdP
cert(s)" and `sso.token` is written at 0600 with the saml.v1.
prefix.
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


def build_signed_response_xml(priv, assertion_id: str, sp_entity: str):
    """Returns (response_xml_str, RelayState placeholder unused here)."""
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
    nameid.text = "alice-aa5@idp.test"
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


def run_aether_login(home: Path, response_xml: str, label: str):
    """Launch aether sso login + POST the signed SAMLResponse; return aether log."""
    log = home / f"aether-{label}.log"
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["AETHER_SAML_CLOCK_SKEW_S"] = "120"
    proc = subprocess.Popen(
        [AETHER_BIN, "sso", "login"],
        env=env, stdout=open(log, "wb"), stderr=subprocess.STDOUT,
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
            rs_m = re.search(r"RelayState=([A-Za-z0-9_\-]+)", data)
            if rs_m:
                relay_state = rs_m.group(1)
            break
        time.sleep(0.1)
    if port is None:
        proc.kill()
        print(f"FAIL [{label}]: no listener port")
        print(log.read_text())
        sys.exit(1)

    resp_b64 = base64.standard_b64encode(response_xml.encode()).decode()
    body = "SAMLResponse=" + urllib.parse.quote(resp_b64, safe="")
    if relay_state:
        body += "&RelayState=" + urllib.parse.quote(relay_state, safe="")
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/sso/saml/acs",
        data=body.encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        if r.status != 200:
            print(f"FAIL [{label}]: ACS HTTP {r.status}")
            sys.exit(1)
    proc.wait(timeout=15)
    return log.read_text()


def main():
    tmp = Path(tempfile.mkdtemp(prefix="aether-aa5-"))
    home = tmp
    saml_dir = home / ".aether" / "saml"
    saml_dir.mkdir(parents=True)
    certs_dir = saml_dir / "idp-certs"
    certs_dir.mkdir()

    # Mint two unrelated keypairs + write both certs to the dir.
    # Filenames chosen so lex order matches conceptual order.
    priv_old, cert_old = mint_keypair_and_cert("aa5-idp-old")
    priv_new, cert_new = mint_keypair_and_cert("aa5-idp-new")
    (certs_dir / "00-old.pem").write_bytes(
        cert_old.public_bytes(serialization.Encoding.PEM)
    )
    (certs_dir / "10-new.pem").write_bytes(
        cert_new.public_bytes(serialization.Encoding.PEM)
    )
    print(f"[smoke] wrote 2 certs to {certs_dir}")

    (home / ".aether" / "sso-saml.json").write_text(
        '{"version":1,"idp_entity_id":"%s","sso_url":"%s",'
        '"sso_binding":"Redirect","sp_entity_id":"%s"}'
        % (IDP_ENTITY, IDP_SSO_URL, SP_ENTITY)
    )

    # ── Run 1: signed by OLD key (first slot) ────────────────────────
    response_old = build_signed_response_xml(priv_old, "_a-aa5-old", SP_ENTITY)
    log1 = run_aether_login(home, response_old, "old")
    if "against 2 configured IdP cert(s)" not in log1:
        print("FAIL [old]: aether log does not mention 2-cert verify")
        print(log1)
        sys.exit(1)
    if not (home / ".aether" / "sso.token").exists():
        print("FAIL [old]: sso.token not written")
        sys.exit(1)
    print("[smoke] OLD-key signed response → verified against 2 configured IdP cert(s)")

    # Wipe sso.token between runs so we know run 2 wrote a fresh one.
    (home / ".aether" / "sso.token").unlink()

    # ── Run 2: signed by NEW key (second slot) ───────────────────────
    response_new = build_signed_response_xml(priv_new, "_a-aa5-new", SP_ENTITY)
    log2 = run_aether_login(home, response_new, "new")
    if "against 2 configured IdP cert(s)" not in log2:
        print("FAIL [new]: aether log does not mention 2-cert verify")
        print(log2)
        sys.exit(1)
    sso_token = home / ".aether" / "sso.token"
    if not sso_token.exists():
        print("FAIL [new]: sso.token not written")
        sys.exit(1)
    mode = sso_token.stat().st_mode & 0o777
    if mode != 0o600:
        print(f"FAIL [new]: sso.token mode is 0{mode:o}, expected 0600")
        sys.exit(1)
    token = sso_token.read_text()
    if not token.startswith("saml.v1."):
        print(f"FAIL [new]: token prefix wrong: {token[:30]!r}")
        sys.exit(1)
    print("[smoke] NEW-key signed response → verified against 2 configured IdP cert(s) "
          "(verifier walked past slot 0 to find a match)")
    print(f"[smoke] sso.token mode = 0{mode:o}; saml.v1. prefix; both runs OK")
    print("[smoke] AA5 LIVE-VERIFIED OK (multi-cert rotation: either key accepted)")


if __name__ == "__main__":
    main()
