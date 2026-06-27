#!/usr/bin/env python3
"""
CC4 live smoke: SAML metadata drift detection.

Closes the BB6 weakest-point. Before CC4, `aether sso refresh-saml`
unconditionally rewrote sso-saml.json + idp-certs/ on every tick.
Against a stable IdP that hasn't actually rotated, this was wasted
I/O — harmless but noisy in --watch mode.

Now configure-saml persists a sha256 fingerprint over the trust-
relevant fields (idp_entity_id + sso_url + binding + sorted signing
cert set). refresh-saml extracts the new metadata, computes its
fingerprint, and compares:
  - Same fingerprint → "no drift, skipping layout rewrite".
  - Different / first-tick-after-upgrade → full layout rewrite.

The smoke exercises a 4-step chain against one fake metadata server
with mutable state:

  S1. Mint two unrelated IdP keypairs (A + B).
      v1 metadata = cert A only. v2 = A + B.
      Stand up the server serving v1.
  S2. configure-saml → assert sso-saml.json carries
      `metadata_fingerprint` (64 hex chars) AND idp-certs/ has one
      PEM. Capture the mtime of 00-discovered.pem.
  S3. Run refresh-saml AGAINST THE SAME v1 metadata. Assert:
        - stderr contains "no drift ... — skipping layout rewrite"
        - stderr does NOT contain "rewrote"
        - 00-discovered.pem mtime is UNCHANGED (write was skipped).
  S4. Flip server to v2. Run refresh-saml. Assert:
        - stderr contains "drift detected" + "rewrote 2 signing
          cert(s)"
        - idp-certs/ now has 00 + 01.pem
        - 00-discovered.pem mtime is NEWER than the S2 capture.
  S5. Sanity: a third refresh-saml call against the unchanged v2
      metadata reverts to "no drift" (the post-rewrite fingerprint
      matches).

Exit 1 on any assertion failure.
"""
import base64
import datetime as dt
import http.server
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

AETHER_BIN = "/root/aether-blueprint/target/release/aether"
SP_ENTITY = "https://sp.test/saml"
IDP_ENTITY = "https://idp.test/saml/metadata"
IDP_SSO_URL = "https://idp.test/saml/sso"


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


class State:
    def __init__(self, v1_xml, v2_xml):
        self.v1 = v1_xml
        self.v2 = v2_xml
        self.serve_v2 = False
        self.fetches = 0


def make_handler(state: State):
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
            self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers()
    return H


def find_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]; s.close()
    return p


def run(cmd, env, *, ok=True):
    res = subprocess.run([AETHER_BIN, *cmd], env=env,
                         capture_output=True, text=True, timeout=20)
    if ok and res.returncode != 0:
        print(f"FAIL [{' '.join(cmd)}]: exit {res.returncode}")
        print(res.stdout); print(res.stderr); sys.exit(1)
    return res


def main():
    tmp = Path(tempfile.mkdtemp(prefix="aether-cc4-"))
    home = tmp

    # S1: keypairs + metadata variants.
    priv_a, cert_a = mint_keypair_and_cert("cc4-idp-A")
    priv_b, cert_b = mint_keypair_and_cert("cc4-idp-B")
    v1 = METADATA_TEMPLATE.format(
        idp_entity=IDP_ENTITY, sso_url=IDP_SSO_URL,
        key_descriptors=KEY_DESCRIPTOR_TEMPLATE.format(b64=cert_der_b64(cert_a)),
    )
    v2 = METADATA_TEMPLATE.format(
        idp_entity=IDP_ENTITY, sso_url=IDP_SSO_URL,
        key_descriptors=(
            KEY_DESCRIPTOR_TEMPLATE.format(b64=cert_der_b64(cert_a)) + "\n"
            + KEY_DESCRIPTOR_TEMPLATE.format(b64=cert_der_b64(cert_b))
        ),
    )
    state = State(v1, v2)
    port = find_port()
    httpd = http.server.HTTPServer(("127.0.0.1", port), make_handler(state))
    t = threading.Thread(target=httpd.serve_forever, daemon=True); t.start()
    meta_url = f"http://127.0.0.1:{port}/metadata"
    print(f"[smoke] fake metadata at {meta_url}")

    env = os.environ.copy(); env["HOME"] = str(home)

    # S2: configure-saml → fingerprint persisted.
    run(["sso", "configure-saml", "--idp-metadata-url", meta_url,
         "--sp-entity-id", SP_ENTITY], env)
    cfg = json.loads((home / ".aether/sso-saml.json").read_text())
    fp1 = cfg.get("metadata_fingerprint")
    if not fp1 or len(fp1) != 64:
        print(f"FAIL [S2]: metadata_fingerprint missing or wrong shape: {fp1!r}")
        sys.exit(1)
    pems_dir = home / ".aether/saml/idp-certs"
    pem_00 = pems_dir / "00-discovered.pem"
    if not pem_00.exists():
        print(f"FAIL [S2]: {pem_00} missing"); sys.exit(1)
    mtime_s2 = pem_00.stat().st_mtime
    print(f"[S2] sso-saml.json carries metadata_fingerprint={fp1[:16]}…; "
          f"idp-certs/00 mtime captured")

    # S3: refresh-saml against UNCHANGED v1. Must skip rewrite.
    # Sleep 1.05s so a wrongful rewrite would shift the mtime detectably
    # (filesystems with 1s mtime resolution still register the difference).
    time.sleep(1.05)
    res = run(["sso", "refresh-saml"], env)
    if "no drift" not in res.stderr or "skipping layout rewrite" not in res.stderr:
        print(f"FAIL [S3]: stderr missing 'no drift ... skipping layout rewrite':\n"
              f"{res.stderr}")
        sys.exit(1)
    if "rewrote" in res.stderr:
        print(f"FAIL [S3]: stderr unexpectedly contains 'rewrote':\n{res.stderr}")
        sys.exit(1)
    mtime_after_skip = pem_00.stat().st_mtime
    if mtime_after_skip != mtime_s2:
        print(f"FAIL [S3]: 00-discovered.pem mtime shifted by skip path "
              f"({mtime_s2} → {mtime_after_skip})")
        sys.exit(1)
    print(f"[S3] refresh-saml on unchanged metadata: 'no drift ... skipping layout "
          f"rewrite'; pem mtime unchanged")

    # S4: flip to v2; refresh-saml detects drift.
    state.serve_v2 = True
    time.sleep(1.05)
    res = run(["sso", "refresh-saml"], env)
    if "drift detected" not in res.stderr or "rewrote 2 signing cert(s)" not in res.stderr:
        print(f"FAIL [S4]: stderr missing drift-detected + rewrote 2:\n{res.stderr}")
        sys.exit(1)
    pems = sorted(p.name for p in pems_dir.glob("*.pem"))
    if pems != ["00-discovered.pem", "01-discovered.pem"]:
        print(f"FAIL [S4]: post-rewrite idp-certs/ unexpected: {pems}")
        sys.exit(1)
    mtime_after_rewrite = pem_00.stat().st_mtime
    if mtime_after_rewrite <= mtime_s2:
        print(f"FAIL [S4]: 00-discovered.pem mtime did not advance after rewrite "
              f"({mtime_s2} vs {mtime_after_rewrite})")
        sys.exit(1)
    print(f"[S4] refresh-saml on v2: drift detected, rewrote 2 certs, "
          f"pem mtime advanced")

    # S5: third refresh against still-v2 metadata reverts to 'no drift'
    # because the post-rewrite fingerprint matches v2.
    cfg_after = json.loads((home / ".aether/sso-saml.json").read_text())
    fp_after = cfg_after.get("metadata_fingerprint")
    if fp_after == fp1:
        print(f"FAIL [S5]: post-rewrite fingerprint should differ from S2 baseline")
        sys.exit(1)
    time.sleep(1.05)
    res = run(["sso", "refresh-saml"], env)
    if "no drift" not in res.stderr:
        print(f"FAIL [S5]: stderr missing 'no drift' on third refresh:\n{res.stderr}")
        sys.exit(1)
    print(f"[S5] third refresh on still-v2: 'no drift' (post-rewrite fingerprint "
          f"{fp_after[:16]}… matches)")

    httpd.shutdown()
    print("[smoke] CC4 LIVE-VERIFIED OK "
          "(metadata fingerprint persisted + 'no drift' skip on unchanged + "
          "drift-triggered rewrite + post-rewrite fingerprint stable)")


if __name__ == "__main__":
    main()
