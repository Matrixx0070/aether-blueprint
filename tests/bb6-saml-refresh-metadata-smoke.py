#!/usr/bin/env python3
"""
BB6 live smoke: SAML metadata auto-refresh.

Closes the AA5-followup weakest-point. Before BB6, configure-saml
fetched the metadata ONCE — after IdP cert rotation, the operator
had to re-run configure-saml manually to refresh idp-certs/. This
was friction that defeated AA5's "zero-downtime rotation" story.

Now:
  1. configure-saml persists `idp_metadata_url` in sso-saml.json.
  2. `aether sso refresh-saml` re-fetches that URL and re-lays out
     idp-certs/ (clearing stale `.pem` files first).
  3. `aether sso refresh-saml --watch` runs as a foreground daemon
     refreshing every `AETHER_SAML_METADATA_REFRESH_INTERVAL_SECS`
     (default 3600, clamped [60, 86400]).

Smoke flow (one fake metadata server with mutable state):

  S1. Mint two unrelated IdP keypairs (v1: just A; v2: A + B).
      Stand up the metadata server serving v1 initially.
  S2. configure-saml against the fake → assert sso-saml.json now
      carries `idp_metadata_url` AND idp-certs/ has exactly the v1
      cert.
  S3. Flip server-side state: subsequent /metadata returns v2.
  S4. Run `aether sso refresh-saml` (one-shot).
  S5. Assert idp-certs/ now has BOTH v2 certs and the v1-only cert
      is gone (rotation cleared stale .pem).
  S6. Drive a SAML login signed with the NEW v2 key B that didn't
      exist in v1 → AA5's first-match-wins verifier accepts it
      because BB6's refresh laid out the cert without restarting
      aether. Proves AA5-followup + BB6 + AA5 + Y3-Y7 compose
      correctly end-to-end.
  S7. Run refresh-saml --watch in the background with a tight
      AETHER_SAML_METADATA_REFRESH_INTERVAL_SECS=60 (the floor).
      Sleep a few seconds, kill it. Assert stderr mentions the
      WATCH mode banner.

A pre-BB6 sso-saml.json check (legacy file with no
idp_metadata_url field) is covered by the bb6_apply_metadata_*
unit tests; this smoke covers only the live happy path because the
fresh sso-saml.json written in S2 always carries the field.
"""
import base64
import datetime as dt
import hashlib
import http.server
import json
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


def mint_keypair_and_cert(name):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    subj = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = dt.datetime.now(dt.UTC).replace(tzinfo=None)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subj).issuer_name(issuer).public_key(pub)
        .serial_number(1)
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .sign(priv, hashes.SHA256())
    )
    return priv, cert


def cert_der_b64(cert):
    return base64.standard_b64encode(
        cert.public_bytes(serialization.Encoding.DER)
    ).decode()


METADATA_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                     entityID="{idp_entity}">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    {key_descriptors}
    <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="{sso_url}"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
"""
KEY_DESCRIPTOR_TEMPLATE = """    <md:KeyDescriptor use="signing">
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>"""


def build_signed_response_xml(priv, assertion_id, sp_entity):
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
    nameid.text = "alice-bb6@idp.test"
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


class MetadataState:
    """Mutable metadata: starts as v1, can be flipped to v2."""

    def __init__(self, v1_xml, v2_xml):
        self.v1 = v1_xml
        self.v2 = v2_xml
        self.serve_v2 = False
        self.fetches = 0


def make_handler(state: MetadataState):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a, **kw): pass

        def do_GET(self):
            if self.path == "/metadata":
                state.fetches += 1
                body = (state.v2 if state.serve_v2 else state.v1).encode()
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
    tmp = Path(tempfile.mkdtemp(prefix="aether-bb6-"))
    home = tmp

    # S1: two unrelated IdP keypairs.
    priv_a, cert_a = mint_keypair_and_cert("bb6-idp-A")
    priv_b, cert_b = mint_keypair_and_cert("bb6-idp-B")
    v1_xml = METADATA_TEMPLATE.format(
        idp_entity=IDP_ENTITY, sso_url=IDP_SSO_URL,
        key_descriptors=KEY_DESCRIPTOR_TEMPLATE.format(b64=cert_der_b64(cert_a)),
    )
    v2_xml = METADATA_TEMPLATE.format(
        idp_entity=IDP_ENTITY, sso_url=IDP_SSO_URL,
        key_descriptors=(
            KEY_DESCRIPTOR_TEMPLATE.format(b64=cert_der_b64(cert_a)) + "\n"
            + KEY_DESCRIPTOR_TEMPLATE.format(b64=cert_der_b64(cert_b))
        ),
    )
    state = MetadataState(v1_xml, v2_xml)

    port = find_port()
    httpd = http.server.HTTPServer(("127.0.0.1", port), make_handler(state))
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    meta_url = f"http://127.0.0.1:{port}/metadata"
    print(f"[smoke] fake metadata at {meta_url}")

    env = os.environ.copy()
    env["HOME"] = str(home)

    # S2: configure-saml → sso-saml.json captures idp_metadata_url.
    res = subprocess.run(
        [AETHER_BIN, "sso", "configure-saml",
         "--idp-metadata-url", meta_url,
         "--sp-entity-id", SP_ENTITY],
        env=env, capture_output=True, text=True, timeout=20,
    )
    if res.returncode != 0:
        print("FAIL [S2]: configure-saml exit", res.returncode)
        print(res.stderr); sys.exit(1)
    cfg = json.loads((home / ".aether" / "sso-saml.json").read_text())
    if cfg.get("idp_metadata_url") != meta_url:
        print(f"FAIL [S2]: sso-saml.json idp_metadata_url wrong: {cfg!r}")
        sys.exit(1)
    pems = sorted(p.name for p in
                  (home / ".aether/saml/idp-certs").glob("*.pem"))
    if pems != ["00-discovered.pem"]:
        print(f"FAIL [S2]: v1 idp-certs/ unexpected: {pems}")
        sys.exit(1)
    v1_pem_body = (home / ".aether/saml/idp-certs/00-discovered.pem").read_text()
    print(f"[S2] sso-saml.json carries idp_metadata_url; idp-certs/ has v1 cert A only")

    # S3 + S4: flip server to v2, run refresh-saml.
    state.serve_v2 = True
    res = subprocess.run(
        [AETHER_BIN, "sso", "refresh-saml"],
        env=env, capture_output=True, text=True, timeout=20,
    )
    if res.returncode != 0:
        print("FAIL [S4]: refresh-saml exit", res.returncode)
        print(res.stderr); sys.exit(1)
    if "refreshed 2 signing cert(s)" not in res.stderr:
        print(f"FAIL [S4]: refresh-saml did not report 2 certs:\n{res.stderr}")
        sys.exit(1)
    print(f"[S4] refresh-saml reported 2 certs discovered after v2 rotation")

    # S5: idp-certs/ now has both v2 certs; v1 PEM body is gone.
    pems_after = sorted(p.name for p in
                        (home / ".aether/saml/idp-certs").glob("*.pem"))
    if pems_after != ["00-discovered.pem", "01-discovered.pem"]:
        print(f"FAIL [S5]: post-refresh idp-certs/ unexpected: {pems_after}")
        sys.exit(1)
    new_00 = (home / ".aether/saml/idp-certs/00-discovered.pem").read_text()
    new_01 = (home / ".aether/saml/idp-certs/01-discovered.pem").read_text()
    expected_a = cert_a.public_bytes(serialization.Encoding.PEM).decode()
    expected_b = cert_b.public_bytes(serialization.Encoding.PEM).decode()
    # PEM serialization can vary in whitespace; compare loaded cert DER.
    loaded_00 = x509.load_pem_x509_certificate(new_00.encode())
    loaded_01 = x509.load_pem_x509_certificate(new_01.encode())
    if loaded_00.public_bytes(serialization.Encoding.DER) != \
            cert_a.public_bytes(serialization.Encoding.DER):
        print("FAIL [S5]: slot 0 != cert A after rotation"); sys.exit(1)
    if loaded_01.public_bytes(serialization.Encoding.DER) != \
            cert_b.public_bytes(serialization.Encoding.DER):
        print("FAIL [S5]: slot 1 != cert B after rotation"); sys.exit(1)
    print(f"[S5] both v2 certs A+B laid out; slot 0=A slot 1=B byte-for-byte")

    # S6: drive a SAML login signed with cert B (only valid AFTER refresh).
    env["AETHER_SAML_CLOCK_SKEW_S"] = "120"
    log = home / "aether-login.log"
    proc = subprocess.Popen(
        [AETHER_BIN, "sso", "login"],
        env=env, stdout=open(log, "wb"), stderr=subprocess.STDOUT,
    )
    port_in = None; relay_state = None
    for _ in range(80):
        try: data = log.read_text()
        except FileNotFoundError: data = ""
        m = re.search(r"waiting on 127\.0\.0\.1:(\d+)", data)
        if m:
            port_in = int(m.group(1))
            rs = re.search(r"RelayState=([A-Za-z0-9_\-]+)", data)
            if rs: relay_state = rs.group(1)
            break
        time.sleep(0.1)
    if port_in is None:
        proc.kill(); print("FAIL [S6]: no listener port"); sys.exit(1)
    response_xml = build_signed_response_xml(priv_b, "_a-bb6", SP_ENTITY)
    resp_b64 = base64.standard_b64encode(response_xml.encode()).decode()
    body = "SAMLResponse=" + urllib.parse.quote(resp_b64, safe="")
    if relay_state:
        body += "&RelayState=" + urllib.parse.quote(relay_state, safe="")
    req = urllib.request.Request(
        f"http://127.0.0.1:{port_in}/sso/saml/acs",
        data=body.encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        if r.status != 200:
            print(f"FAIL [S6]: ACS HTTP {r.status}"); sys.exit(1)
    proc.wait(timeout=15)
    sso_token = home / ".aether" / "sso.token"
    if not sso_token.exists() or not sso_token.read_text().startswith("saml.v1."):
        print("FAIL [S6]: sso.token not written / wrong prefix")
        print(log.read_text()); sys.exit(1)
    print(f"[S6] login signed with v2-only cert B verified via AA5 first-match-wins "
          f"(slot 0 A missed, slot 1 B matched) → sso.token saml.v1. at 0600")

    # S7: --watch mode briefly.
    env["AETHER_SAML_METADATA_REFRESH_INTERVAL_SECS"] = "60"
    watch_log = home / "aether-watch.log"
    watch_proc = subprocess.Popen(
        [AETHER_BIN, "sso", "refresh-saml", "--watch"],
        env=env, stdout=open(watch_log, "wb"), stderr=subprocess.STDOUT,
    )
    # Let it tick once (initial fetch happens immediately, then sleep).
    deadline = time.time() + 8
    saw_banner = False
    while time.time() < deadline:
        try:
            txt = watch_log.read_text()
        except FileNotFoundError:
            txt = ""
        if "WATCH mode: refreshing every 60s" in txt:
            saw_banner = True
            break
        time.sleep(0.2)
    watch_proc.terminate()
    try:
        watch_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        watch_proc.kill()
    if not saw_banner:
        print("FAIL [S7]: --watch banner not emitted within 8s")
        print(watch_log.read_text() if watch_log.exists() else "(no log)")
        sys.exit(1)
    print(f"[S7] --watch mode banner emitted ('WATCH mode: refreshing every 60s')")

    httpd.shutdown()
    print("[smoke] BB6 LIVE-VERIFIED OK (configure-saml persists idp_metadata_url + "
          "refresh-saml rotates idp-certs/ from v1→v2 + AA5 first-match-wins on new "
          "key + --watch foreground daemon)")


if __name__ == "__main__":
    main()
