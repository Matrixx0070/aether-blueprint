#!/usr/bin/env python3
"""
DD4 live smoke: Y5 EdDSA assertion verifier.

Closes the CC6 weakest-point — CC6 made the SP signer Ed25519-aware
on the AuthnRequest leg; DD4 makes the inbound Y5 verifier accept
Ed25519-signed SAMLResponses on the IdP→SP leg. This is the
symmetric remediation that lets aether INTEROPERATE with an IdP
using Ed25519 keys (FIDO2-adjacent, certain Auth0 paths, modern
ADFS configs).

The smoke is the mirror of Y7's RSA-based smoke with the algorithm
flipped to EdDSA:

  S1. Mint a fresh Ed25519 IdP keypair. Build an Ed25519 x509
      self-signed cert. Write the cert PEM to
      ~/.aether/saml/idp-cert.pem (idp-certs/ dir-mode also works
      via AA5; we use the legacy single-file path for simplicity).
      Write sso-saml.json (Redirect binding — DD4 is about the
      IdP→SP leg, not the SP→IdP leg, so Redirect is fine).
  S2. Launch `aether sso login`. Capture the ACS port + RelayState.
  S3. Build an Ed25519-signed SAMLResponse:
        - Construct the Assertion (lxml).
        - Compute the Reference digest = sha256(exc-c14n(assertion))
          (enveloped-signature transform strips the Signature we're
          about to splice).
        - Build SignedInfo with the EdDSA SignatureMethod URI
          (http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519).
        - exc-c14n the SignedInfo.
        - Sign with cryptography's Ed25519PrivateKey (raw bytes;
          Ed25519 hashes internally per RFC 8419).
        - Splice the Signature into the Assertion as the FIRST
          child.
  S4. POST the SAMLResponse to the ACS endpoint. Aether's Y3 parser
      surfaces the Ed25519 SignedInfo; Y5 algorithm gate accepts
      eddsa-ed25519; the per-key dispatch picks the configured
      Ed25519 verifying key, runs `ed25519_dalek::Verifier::verify`
      on the c14n SignedInfo bytes — succeeds.
  S5. Aether's stderr MUST mention "assertion signature verified".
      sso.token written at 0600 with saml.v1. prefix → proves
      Y3→Y5→Y6→Y7 composed correctly through the Ed25519 path.

A failure in S4/S5 means the verifier didn't dispatch correctly
on the Ed25519 cert + EdDSA signature combination.
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
from cryptography.hazmat.primitives.asymmetric import ed25519
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


def exc_c14n(elem):
    return ET.tostring(elem, method="c14n", exclusive=True, with_comments=False)


def main():
    tmp = Path(tempfile.mkdtemp(prefix="aether-dd4-"))
    home = tmp
    saml_dir = home / ".aether" / "saml"
    saml_dir.mkdir(parents=True)

    # S1: Ed25519 IdP keypair + x509 self-signed cert.
    idp_priv = ed25519.Ed25519PrivateKey.generate()
    idp_pub = idp_priv.public_key()
    subj = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "dd4-idp")])
    now = dt.datetime.now(dt.UTC).replace(tzinfo=None)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subj)
        .issuer_name(issuer)
        .public_key(idp_pub)
        .serial_number(1)
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .sign(idp_priv, None)  # Ed25519 signing doesn't take a hash arg
    )
    (saml_dir / "idp-cert.pem").write_bytes(
        cert.public_bytes(serialization.Encoding.PEM)
    )
    (home / ".aether" / "sso-saml.json").write_text(
        '{"version":1,"idp_entity_id":"%s","sso_url":"%s",'
        '"sso_binding":"Redirect","sp_entity_id":"%s"}'
        % (IDP_ENTITY, IDP_SSO_URL, SP_ENTITY)
    )
    print(f"[S1] Ed25519 IdP cert at {saml_dir / 'idp-cert.pem'}")

    # S2: launch sso login, capture port + RelayState.
    log = home / "aether.log"
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
            rs = re.search(r"RelayState=([A-Za-z0-9_\-]+)", data)
            if rs:
                relay_state = rs.group(1)
            break
        time.sleep(0.1)
    if port is None:
        proc.kill()
        print("FAIL [S2]: no listener port")
        print(log.read_text()); sys.exit(1)
    print(f"[S2] aether ACS waiting on port {port}")

    # S3: build Ed25519-signed SAMLResponse with EdDSA SignedInfo.
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
        ID="_a-dd4", Version="2.0", IssueInstant=issue,
    )
    ai = ET.SubElement(assertion, q(NS_SAML, "Issuer"))
    ai.text = IDP_ENTITY
    subject = ET.SubElement(assertion, q(NS_SAML, "Subject"))
    nameid = ET.SubElement(subject, q(NS_SAML, "NameID"))
    nameid.text = "alice-dd4@idp.test"
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

    # Reference digest: sha256(exc-c14n(assertion-without-Signature)).
    digest_b64 = base64.standard_b64encode(
        hashlib.sha256(exc_c14n(assertion)).digest()
    ).decode()

    # Build SignedInfo carrying the EdDSA SignatureMethod URI.
    signature = ET.Element(q(NS_DS, "Signature"))
    signed_info = ET.SubElement(signature, q(NS_DS, "SignedInfo"))
    ET.SubElement(
        signed_info, q(NS_DS, "CanonicalizationMethod"),
        Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
    )
    ET.SubElement(
        signed_info, q(NS_DS, "SignatureMethod"),
        Algorithm=EDDSA_URI,
    )
    ref = ET.SubElement(signed_info, q(NS_DS, "Reference"), URI="#_a-dd4")
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

    # Splice Signature INTO Assertion (first child) so enveloped-
    # signature transform sees it during aether's verify-side c14n.
    assertion.insert(0, signature)

    # Sign exc-c14n(SignedInfo) with Ed25519. Ed25519 signs the raw
    # bytes (no separate hash).
    signed_info_after_splice = signature.find(q(NS_DS, "SignedInfo"))
    sig_bytes = idp_priv.sign(exc_c14n(signed_info_after_splice))
    if len(sig_bytes) != 64:
        print(f"FAIL [S3]: Ed25519 signature {len(sig_bytes)}B, expected 64")
        sys.exit(1)
    sv = ET.SubElement(signature, q(NS_DS, "SignatureValue"))
    sv.text = base64.standard_b64encode(sig_bytes).decode()

    response_xml = ET.tostring(response).decode()
    print(f"[S3] Ed25519-signed SAMLResponse built ({len(response_xml)}B XML, "
          f"SignatureMethod={EDDSA_URI[-13:]}…)")

    # S4: POST to aether's ACS endpoint.
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
            print(f"FAIL [S4]: ACS HTTP {r.status}"); sys.exit(1)
    proc.wait(timeout=15)
    print("[S4] aether ACS accepted the Ed25519-signed POST")

    # S5: log mentions "Y5: assertion signature verified"; sso.token
    # written at 0600 with saml.v1. prefix.
    log_text = log.read_text()
    if "assertion signature verified" not in log_text:
        print(f"FAIL [S5]: aether log missing 'assertion signature verified'\n"
              f"{log_text}")
        sys.exit(1)
    sso_token = home / ".aether" / "sso.token"
    if not sso_token.exists():
        print("FAIL [S5]: sso.token not written"); print(log_text); sys.exit(1)
    if not sso_token.read_text().startswith("saml.v1."):
        print(f"FAIL [S5]: sso.token wrong prefix: {sso_token.read_text()[:30]!r}")
        sys.exit(1)
    mode = sso_token.stat().st_mode & 0o777
    if mode != 0o600:
        print(f"FAIL [S5]: sso.token mode 0{mode:o}, expected 0600")
        sys.exit(1)
    print(f"[S5] Y5 Ed25519 verify succeeded → Y3-Y7 composed; "
          f"sso.token at 0o{mode:o} with saml.v1. prefix")

    print("[smoke] DD4 LIVE-VERIFIED OK "
          "(Ed25519 IdP cert + Ed25519-signed SAMLResponse + "
          "Y5 EdDSA verifier + Y3-Y7 composition end-to-end)")


if __name__ == "__main__":
    main()
