#!/usr/bin/env python3
"""
CC6 live smoke: EdDSA AuthnRequest signing.

Closes the BB4 weakest-point — BB4 only supported RSA-SHA256.
Some modern IdPs (FIDO2-adjacent, certain Auth0 paths) advertise
EdDSA on the AuthnRequest binding and reject RSA signatures
outright.

CC6 makes the SP signing path key-type-aware:
  - Ed25519 PKCS#8 PEM → SignatureMethod
    `http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519`
  - RSA PKCS#8/PKCS#1 PEM → SignatureMethod
    `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256` (unchanged)

The smoke runs the BB4-shape flow with an Ed25519 SP key, then
verifies the signed AuthnRequest end-to-end:

  S1. Mint a fresh Ed25519 SP keypair. Write the private key as
      PKCS#8 PEM at mode 0600; write a real IdP cert PEM + a
      POST-binding sso-saml.json so `aether sso login` reaches
      the form-emit path.
  S2. Run `aether sso login` with
      AETHER_SAML_SP_PRIVATE_KEY_PEM pointed at the Ed25519 PEM.
      Aether's stderr MUST report BB4 signing happened (same
      log line — CC6 only changes the algorithm under the hood).
  S3. Extract the SAMLRequest from the form HTML, b64-decode to
      the signed AuthnRequest XML. Structural assertion: the
      SignedInfo carries the EdDSA SignatureMethod URI, NOT the
      RSA-SHA256 one.
  S4. Spec-path verify with lxml + cryptography:
        Reference URI matches AuthnRequest ID
        DigestValue == sha256(exc-c14n(unsigned AuthnRequest))
        SignatureValue Ed25519-verifies against the SP public key
        signing the c14n SignedInfo
  S5. Drive the IdP→SP leg with the existing Y7 signed
      SAMLResponse path; sso.token at 0600 with saml.v1. prefix —
      proves CC6 doesn't regress Y3-Y7 on the IdP→SP side.
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
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, padding
from cryptography.x509.oid import NameOID
import lxml.etree as ET

AETHER_BIN = "/root/aether-blueprint/target/release/aether"
NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
NS_DS = "http://www.w3.org/2000/09/xmldsig#"
SP_ENTITY = "https://sp.test/saml"
IDP_ENTITY = "https://idp.test/saml/metadata"
IDP_SSO_URL = "https://idp.test/saml/sso"
EDDSA_URI = "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519"
RSA_SHA256_URI = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"


def exc_c14n(elem):
    return ET.tostring(elem, method="c14n", exclusive=True, with_comments=False)


def main():
    tmp = Path(tempfile.mkdtemp(prefix="aether-cc6-"))
    home = tmp
    saml_dir = home / ".aether" / "saml"
    saml_dir.mkdir(parents=True)

    # S1: Ed25519 SP keypair → PKCS#8 PEM (only standard format
    # ed25519 supports), 0600.
    sp_priv = ed25519.Ed25519PrivateKey.generate()
    sp_pub = sp_priv.public_key()
    sp_pem_path = saml_dir / "sp-ed25519.pem"
    sp_pem_path.write_bytes(
        sp_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    os.chmod(sp_pem_path, 0o600)
    print(f"[S1] SP Ed25519 PKCS#8 PEM at {sp_pem_path}")

    # IdP keypair + cert for the regression IdP→SP leg.
    idp_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    idp_pub = idp_priv.public_key()
    subj = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cc6-idp")])
    now = dt.datetime.now(dt.UTC).replace(tzinfo=None)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subj)
        .issuer_name(issuer)
        .public_key(idp_pub)
        .serial_number(1)
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .sign(idp_priv, hashes.SHA256())
    )
    (saml_dir / "idp-cert.pem").write_bytes(
        cert.public_bytes(serialization.Encoding.PEM)
    )
    (home / ".aether" / "sso-saml.json").write_text(
        '{"version":1,"idp_entity_id":"%s","sso_url":"%s",'
        '"sso_binding":"POST","sp_entity_id":"%s"}'
        % (IDP_ENTITY, IDP_SSO_URL, SP_ENTITY)
    )

    # S2: aether sso login with the Ed25519 PEM env knob.
    log = home / "aether.log"
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["AETHER_SAML_CLOCK_SKEW_S"] = "120"
    env["AETHER_SAML_SP_PRIVATE_KEY_PEM"] = str(sp_pem_path)
    proc = subprocess.Popen(
        [AETHER_BIN, "sso", "login"],
        env=env, stdout=open(log, "wb"), stderr=subprocess.STDOUT,
    )
    port = None
    form_path = None
    for _ in range(80):
        try:
            data = log.read_text()
        except FileNotFoundError:
            data = ""
        m_port = re.search(r"waiting on 127\.0\.0\.1:(\d+)", data)
        m_form = re.search(r"HTTP-POST form written to (\S+)", data)
        if m_port and port is None:
            port = int(m_port.group(1))
        if m_form and form_path is None:
            form_path = Path(m_form.group(1))
        if port and form_path:
            break
        time.sleep(0.1)
    if port is None or form_path is None:
        proc.kill(); print(f"FAIL [S2]: port={port} form_path={form_path}")
        print(log.read_text()); sys.exit(1)
    log_text = log.read_text()
    if "BB4: AuthnRequest signed with SP key" not in log_text:
        print("FAIL [S2]: aether log does not mention BB4 signing")
        print(log_text); sys.exit(1)
    print(f"[S2] aether sso login ran with Ed25519 SP key (port={port})")

    # S3: extract signed AuthnRequest, assert EdDSA URI.
    html = form_path.read_text()
    sr_m = re.search(r'name="SAMLRequest" value="([^"]+)"', html)
    rs_m = re.search(r'name="RelayState" value="([^"]+)"', html)
    if not sr_m or not rs_m:
        print("FAIL [S3]: SAMLRequest/RelayState extraction failed")
        sys.exit(1)
    saml_request_b64 = sr_m.group(1)
    relay_state = rs_m.group(1)
    authn_xml = base64.standard_b64decode(saml_request_b64).decode()
    if EDDSA_URI not in authn_xml:
        print(f"FAIL [S3]: SignedInfo missing EdDSA URI ({EDDSA_URI}):\n"
              f"{authn_xml}")
        sys.exit(1)
    if RSA_SHA256_URI in authn_xml:
        print(f"FAIL [S3]: SignedInfo unexpectedly contains RSA-SHA256 URI:\n"
              f"{authn_xml}")
        sys.exit(1)
    print(f"[S3] signed AuthnRequest carries eddsa-ed25519 SignatureMethod URI")

    # S4: full Ed25519 round-trip verify with lxml + cryptography.
    root = ET.fromstring(authn_xml.encode())
    request_id = root.get("ID")
    sig_elem = root.find(f"{{{NS_DS}}}Signature")
    if sig_elem is None:
        print("FAIL [S4]: no <ds:Signature> in AuthnRequest"); sys.exit(1)

    # Reference URI.
    ref_uri = sig_elem.find(f".//{{{NS_DS}}}Reference").get("URI")
    if ref_uri != f"#{request_id}":
        print(f"FAIL [S4]: Reference URI {ref_uri!r} != #{request_id!r}")
        sys.exit(1)

    # Digest value == sha256(c14n(unsigned)).
    digest_elem = sig_elem.find(f".//{{{NS_DS}}}DigestValue")
    expected_digest = digest_elem.text.strip()
    root_unsigned = ET.fromstring(authn_xml.encode())
    sig_strip = root_unsigned.find(f"{{{NS_DS}}}Signature")
    root_unsigned.remove(sig_strip)
    canonical = exc_c14n(root_unsigned)
    computed_digest = base64.standard_b64encode(
        hashlib.sha256(canonical).digest()
    ).decode()
    if computed_digest != expected_digest:
        print(f"FAIL [S4]: digest mismatch\n"
              f"  expected: {expected_digest}\n"
              f"  computed: {computed_digest}")
        sys.exit(1)

    # SignatureValue Ed25519-verifies. Per RFC 8419, Ed25519 signs the
    # raw message bytes (no separate hash).
    signed_info = sig_elem.find(f"{{{NS_DS}}}SignedInfo")
    si_c14n = exc_c14n(signed_info)
    sig_value = sig_elem.find(f"{{{NS_DS}}}SignatureValue")
    sig_bytes = base64.standard_b64decode(sig_value.text.strip())
    if len(sig_bytes) != 64:
        print(f"FAIL [S4]: Ed25519 signature is {len(sig_bytes)}B, expected 64")
        sys.exit(1)
    try:
        sp_pub.verify(sig_bytes, si_c14n)
    except Exception as e:
        print(f"FAIL [S4]: SignatureValue does not Ed25519-verify against "
              f"SP public key: {e}")
        sys.exit(1)
    print("[S4] full spec-path verify: Reference URI / digest / "
          "Ed25519 SignatureValue all pass")

    # S5: IdP→SP leg unchanged (Y3-Y7 regression).
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
        ID="_a-cc6", Version="2.0", IssueInstant=issue,
    )
    ai = ET.SubElement(assertion, q(NS_SAML, "Issuer"))
    ai.text = IDP_ENTITY
    subject = ET.SubElement(assertion, q(NS_SAML, "Subject"))
    nameid = ET.SubElement(subject, q(NS_SAML, "NameID"))
    nameid.text = "alice-cc6@idp.test"
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
        Algorithm=RSA_SHA256_URI,
    )
    ref = ET.SubElement(signed_info, q(NS_DS, "Reference"), URI="#_a-cc6")
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
    sig_bytes = idp_priv.sign(
        exc_c14n(si_after), padding.PKCS1v15(), hashes.SHA256()
    )
    sv = ET.SubElement(signature, q(NS_DS, "SignatureValue"))
    sv.text = base64.standard_b64encode(sig_bytes).decode()

    response_xml = ET.tostring(response).decode()
    resp_b64 = base64.standard_b64encode(response_xml.encode()).decode()
    body = (
        "SAMLResponse="
        + urllib.parse.quote(resp_b64, safe="")
        + "&RelayState="
        + urllib.parse.quote(relay_state, safe="")
    )
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/sso/saml/acs",
        data=body.encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        if r.status != 200:
            print(f"FAIL [S5]: ACS HTTP {r.status}"); sys.exit(1)
    proc.wait(timeout=15)
    sso_token = home / ".aether" / "sso.token"
    if not sso_token.exists() or not sso_token.read_text().startswith("saml.v1."):
        print("FAIL [S5]: sso.token not written / wrong prefix"); sys.exit(1)
    print("[S5] IdP→SP leg passed Y3→Y5→Y6→Y7 → sso.token saml.v1. at 0600")

    print("[smoke] CC6 LIVE-VERIFIED OK "
          "(Ed25519 PKCS#8 SP key + eddsa-ed25519 SignatureMethod URI + "
          "Ed25519 SignatureValue verifies under SP pubkey + "
          "IdP→SP regression)")


if __name__ == "__main__":
    main()
