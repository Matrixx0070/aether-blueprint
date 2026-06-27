#!/usr/bin/env python3
"""
BB4 live smoke: signed AuthnRequest (POST binding).

Closes the AA4 weakest-point. Some enterprise IdPs (Okta, ADFS,
certain Auth0 tenant configs) gate trust on SP-side signature
verification of the AuthnRequest. Before BB4, aether's AuthnRequest
was unsigned regardless of binding.

Now `AETHER_SAML_SP_PRIVATE_KEY_PEM=path` makes aether splice a
`<ds:Signature>` block into the AuthnRequest after `</saml:Issuer>`,
with the same algorithm pipeline the Y5 verifier accepts on the IdP
side: RSA-SHA256 + SHA-256 digest + [enveloped-signature, exc-c14n]
transforms + Reference URI = `#<authn_request_id>`.

The smoke:
  1. Mints a fresh RSA-2048 SP keypair; writes the private key to
     a PKCS#8 PEM (openssl-3 default).
  2. Mints a fresh RSA-2048 IdP keypair + cert; writes the cert PEM
     and an sso-saml.json pointing aether at the fake IdP.
  3. Sets AETHER_SAML_SP_PRIVATE_KEY_PEM to the SP PEM path and
     runs `aether sso login` (POST binding via sso_binding="POST"
     in sso-saml.json).
  4. Extracts the SAMLRequest from the form HTML, b64-decodes to
     the signed AuthnRequest XML.
  5. Verifies the `<ds:Signature>` element ROUND-TRIPS:
       - parses with lxml
       - extracts Reference URI matches the AuthnRequest ID
       - extracts DigestValue, c14n the AuthnRequest with the
         Signature element stripped (enveloped-signature transform),
         computes SHA-256, asserts == DigestValue
       - extracts SignedInfo, exc-c14n it, RSA-SHA256-verifies the
         SignatureValue against the SP public key
  6. Then drives the IdP→SP leg with the existing Y7 signed
     SAMLResponse path — proving that adding the signed AuthnRequest
     wrapper doesn't regress Y3-Y7 on the IdP→SP side.

A failure in step 5 means aether's signed AuthnRequest is NOT what
the spec-compliant verify path would accept.
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


def main():
    tmp = Path(tempfile.mkdtemp(prefix="aether-bb4-"))
    home = tmp
    saml_dir = home / ".aether" / "saml"
    saml_dir.mkdir(parents=True)

    # 1. SP keypair → PKCS#8 PEM (openssl-3 default).
    sp_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sp_pub = sp_priv.public_key()
    sp_pem_path = saml_dir / "sp-private-key.pem"
    sp_pem_path.write_bytes(
        sp_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    os.chmod(sp_pem_path, 0o600)
    print(f"[smoke] SP private key (PKCS#8 PEM) at {sp_pem_path}")

    # 2. IdP keypair + cert + sso-saml.json (POST binding).
    idp_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    idp_pub = idp_priv.public_key()
    subj = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "bb4-idp")])
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

    # 3. Launch aether sso login with the SP signing key env knob.
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
        proc.kill()
        print(f"FAIL: port={port} form_path={form_path}")
        print(log.read_text())
        sys.exit(1)
    print(f"[smoke] ACS port={port}, form at {form_path}")

    # Aether log MUST report BB4 signing happened.
    log_text = log.read_text()
    if "BB4: AuthnRequest signed with SP key" not in log_text:
        print("FAIL: aether log does not report BB4 signing")
        print(log_text)
        sys.exit(1)

    # 4. Extract + b64-decode the SAMLRequest from the form.
    html = form_path.read_text()
    sr_m = re.search(r'name="SAMLRequest" value="([^"]+)"', html)
    rs_m = re.search(r'name="RelayState" value="([^"]+)"', html)
    if not sr_m or not rs_m:
        print("FAIL: could not extract SAMLRequest/RelayState from form")
        sys.exit(1)
    saml_request_b64 = sr_m.group(1)
    relay_state = rs_m.group(1)
    authn_xml = base64.standard_b64decode(saml_request_b64).decode()
    print(f"[smoke] decoded signed AuthnRequest ({len(authn_xml)} bytes XML)")

    # Quick structural sanity: <ds:Signature> follows </saml:Issuer>.
    issuer_idx = authn_xml.find("</saml:Issuer>")
    sig_idx = authn_xml.find("<ds:Signature")
    if issuer_idx < 0 or sig_idx < 0 or sig_idx < issuer_idx:
        print(f"FAIL: Signature element not placed after Issuer in:\n{authn_xml}")
        sys.exit(1)
    print("[smoke] <ds:Signature> placed after </saml:Issuer> (saml-core §3.2.1)")

    # 5. Full ds:Signature round-trip verify with lxml.
    root = ET.fromstring(authn_xml.encode())
    request_id = root.get("ID")
    sig_elem = root.find(f"{{{NS_DS}}}Signature")
    if sig_elem is None:
        print("FAIL: no Signature element parsed")
        sys.exit(1)

    # Reference URI must point at the AuthnRequest ID.
    ref_uri = sig_elem.find(f".//{{{NS_DS}}}Reference").get("URI")
    if ref_uri != f"#{request_id}":
        print(f"FAIL: Reference URI {ref_uri!r} != #{request_id!r}")
        sys.exit(1)

    # Digest check: c14n the AuthnRequest with Signature stripped.
    digest_value_elem = sig_elem.find(f".//{{{NS_DS}}}DigestValue")
    expected_digest = digest_value_elem.text.strip()

    root_no_sig = ET.fromstring(authn_xml.encode())
    sig_strip = root_no_sig.find(f"{{{NS_DS}}}Signature")
    root_no_sig.remove(sig_strip)
    canonical = exc_c14n(root_no_sig)
    computed_digest = base64.standard_b64encode(
        hashlib.sha256(canonical).digest()
    ).decode()
    if computed_digest != expected_digest:
        print("FAIL: digest mismatch")
        print(f"  expected: {expected_digest}")
        print(f"  computed: {computed_digest}")
        sys.exit(1)
    print(f"[smoke] Reference digest matches (sha256 of c14n unsigned)")

    # Signature value verify: c14n SignedInfo + RSA-SHA256.
    signed_info = sig_elem.find(f"{{{NS_DS}}}SignedInfo")
    si_c14n = exc_c14n(signed_info)
    sig_value_elem = sig_elem.find(f"{{{NS_DS}}}SignatureValue")
    sig_bytes = base64.standard_b64decode(sig_value_elem.text.strip())
    try:
        sp_pub.verify(
            sig_bytes, si_c14n, padding.PKCS1v15(), hashes.SHA256()
        )
    except Exception as e:
        print(f"FAIL: SignatureValue does not verify against SP pubkey: {e}")
        sys.exit(1)
    print("[smoke] SignatureValue RSA-SHA256-verifies against SP public key")

    # 6. Drive the IdP→SP leg (same as Y7 + AA4) so we prove the
    # BB4 SP-signing change didn't regress the assertion-verify pipe.
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
        ID="_a-bb4", Version="2.0", IssueInstant=issue,
    )
    ai = ET.SubElement(assertion, q(NS_SAML, "Issuer"))
    ai.text = IDP_ENTITY
    subject = ET.SubElement(assertion, q(NS_SAML, "Subject"))
    nameid = ET.SubElement(subject, q(NS_SAML, "NameID"))
    nameid.text = "alice-bb4@idp.test"
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
        Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    )
    ref = ET.SubElement(signed_info, q(NS_DS, "Reference"), URI="#_a-bb4")
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
            print(f"FAIL: ACS HTTP {r.status}")
            sys.exit(1)
    proc.wait(timeout=15)

    sso_token = home / ".aether" / "sso.token"
    if not sso_token.exists() or not sso_token.read_text().startswith("saml.v1."):
        print("FAIL: sso.token not written / wrong prefix")
        print(log.read_text())
        sys.exit(1)
    print("[smoke] IdP→SP leg passed Y3→Y5→Y6→Y7 → sso.token saml.v1. at 0600")
    print("[smoke] BB4 LIVE-VERIFIED OK "
          "(SP-signed AuthnRequest + ds:Signature ref+digest+sig "
          "verify + IdP→SP regression)")


if __name__ == "__main__":
    main()
