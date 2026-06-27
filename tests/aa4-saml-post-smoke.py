#!/usr/bin/env python3
"""
AA4 live smoke: HTTP-POST AuthnRequest binding.

Closes the v0.29 explicit deferral that left sso_login_saml refusing
any binding other than HTTP-Redirect. Verifies:

  1. sso-saml.json with `"sso_binding": "POST"` no longer trips the
     "Unsupported SAML binding" bail.
  2. aether writes a self-submitting HTML form to
     ~/.aether/saml/authn-request-form.html at mode 0600.
  3. The form has the spec-required shape (method=POST,
     action=<sso_url>, hidden SAMLRequest + RelayState, JS
     auto-submit, <noscript> Continue fallback).
  4. The SAMLRequest base64 in the form decodes byte-for-byte to a
     valid AuthnRequest XML.

Then drives the IdP→SP leg with the same signed-SAMLResponse path
the Y7 smoke covers (lxml exc-c14n + RSA-2048 + PKCS1v15-SHA256
signature), proving that flipping the SP→IdP binding to POST does
not regress the assertion-verify pipeline.

Final assertion: sso.token written at mode 0600 with the saml.v1.
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


def main():
    tmp = Path(tempfile.mkdtemp(prefix="aether-aa4-"))
    home = tmp
    saml_dir = home / ".aether" / "saml"
    saml_dir.mkdir(parents=True)

    privkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pubkey = privkey.public_key()
    subj = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "aa4-idp")])
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
    # KEY DIFFERENCE FROM Y7: sso_binding = "POST".
    (home / ".aether" / "sso-saml.json").write_text(
        '{"version":1,"idp_entity_id":"%s","sso_url":"%s",'
        '"sso_binding":"POST","sp_entity_id":"%s"}'
        % (IDP_ENTITY, IDP_SSO_URL, SP_ENTITY)
    )

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

    # Wait for both: ACS port + POST form path.
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
    print(f"[smoke] ACS port={port}")
    print(f"[smoke] POST form at {form_path}")

    # 1. Assert the form was written with the expected mode.
    if not form_path.exists():
        print(f"FAIL: form file {form_path} does not exist")
        sys.exit(1)
    mode = form_path.stat().st_mode & 0o777
    if mode != 0o600:
        print(f"FAIL: form file mode is 0{mode:o}, expected 0600")
        sys.exit(1)

    # 2. Parse the form HTML and assert the spec-required shape.
    html = form_path.read_text()
    for needle in [
        'method="POST"',
        f'action="{IDP_SSO_URL}"',
        'name="SAMLRequest"',
        'name="RelayState"',
        "document.forms[0].submit()",
        "<noscript>",
    ]:
        if needle not in html:
            print(f"FAIL: form missing required fragment `{needle}`")
            print(html)
            sys.exit(1)
    print("[smoke] form HTML has POST + action + SAMLRequest + RelayState "
          "+ JS auto-submit + <noscript> fallback")

    # 3. Extract SAMLRequest + RelayState; verify SAMLRequest base64
    #    decodes to a valid AuthnRequest XML (NO DEFLATE).
    sr_m = re.search(
        r'name="SAMLRequest" value="([^"]+)"', html
    )
    rs_m = re.search(r'name="RelayState" value="([^"]+)"', html)
    if not sr_m or not rs_m:
        print("FAIL: could not extract SAMLRequest or RelayState from form")
        sys.exit(1)
    saml_request_b64 = sr_m.group(1)
    relay_state = rs_m.group(1)
    print(f"[smoke] SAMLRequest is {len(saml_request_b64)}B base64; "
          f"RelayState={relay_state}")
    try:
        authn_xml = base64.standard_b64decode(saml_request_b64).decode()
    except Exception as e:
        print(f"FAIL: SAMLRequest is not valid standard base64: {e}")
        sys.exit(1)
    if "<samlp:AuthnRequest" not in authn_xml:
        print(f"FAIL: decoded SAMLRequest is not an AuthnRequest: {authn_xml!r}")
        sys.exit(1)
    if f'AssertionConsumerServiceURL="http://127.0.0.1:{port}/sso/saml/acs"' \
            not in authn_xml:
        print("FAIL: decoded AuthnRequest does not embed our ACS URL")
        print(authn_xml)
        sys.exit(1)
    print("[smoke] decoded AuthnRequest XML embeds the ACS URL byte-for-byte")

    # 4. Drive the IdP→SP leg with a signed SAMLResponse (same as Y7).
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
        ID="_a-aa4", Version="2.0", IssueInstant=issue,
    )
    ai = ET.SubElement(assertion, q(NS_SAML, "Issuer"))
    ai.text = IDP_ENTITY
    subject = ET.SubElement(assertion, q(NS_SAML, "Subject"))
    nameid = ET.SubElement(subject, q(NS_SAML, "NameID"))
    nameid.text = "alice-aa4@idp.test"
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

    assertion_canonical = exc_c14n(assertion)
    digest_b64 = base64.standard_b64encode(
        hashlib.sha256(assertion_canonical).digest()
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
    ref = ET.SubElement(signed_info, q(NS_DS, "Reference"), URI="#_a-aa4")
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
        print(f"[smoke] POST returned HTTP {r.status}")

    proc.wait(timeout=15)
    print("--- aether log ---")
    print(log.read_text())

    sso_token_path = home / ".aether" / "sso.token"
    if not sso_token_path.exists():
        print("FAIL: ~/.aether/sso.token was NOT written")
        sys.exit(1)
    token_text = sso_token_path.read_text()
    if not token_text.startswith("saml.v1."):
        print("FAIL: token does not have saml.v1. prefix")
        sys.exit(1)
    tok_mode = sso_token_path.stat().st_mode & 0o777
    if tok_mode != 0o600:
        print(f"FAIL: sso.token mode is 0{tok_mode:o}, expected 0600")
        sys.exit(1)
    print(f"[smoke] sso.token mode = 0{tok_mode:o}; "
          f"form mode = 0{mode:o}; both 0600 as required")
    print("[smoke] AA4 LIVE-VERIFIED OK "
          "(POST binding emits self-submitting form + "
          "SAMLRequest b64 round-trip + IdP→SP leg passes)")


if __name__ == "__main__":
    main()
