#!/usr/bin/env python3
"""
Z5 fake-endpoint Vertex smoke. NOT a real GCP live-verify.

Stands up a Python fake `aiplatform.googleapis.com` that handles
both Vertex Anthropic verbs:
  POST .../publishers/anthropic/models/<model>:rawPredict
       → Anthropic Messages-API JSON (non-streaming)
  POST .../publishers/anthropic/models/<model>:streamRawPredict
       → SSE: `data: {...anthropic event...}\n` per line

Asserts on each request:
  - Authorization: Bearer <token> present
  - body carries `anthropic_version: "vertex-2023-10-16"`
  - body does NOT carry top-level `model` / `stream`

Drives aether through TWO paths:
  1. `aether doctor --probe` (AETHER_PROVIDER=vertex) → :rawPredict.
     Asserts probe stdout shows "vertex responded".
  2. `aether -p "hi"` → :streamRawPredict + SSE delta parser.
     Asserts stdout contains the streamed delta text "hi-from-z5".

Exit 1 on any assertion failure.

Real GCP live-verify was attempted in this session against the user's
gcloud auth and BLOCKED at the Google Cloud billing gate (project had
billingEnabled=false → 403 PERMISSION_DENIED with explicit
"enable billing" URL); even with billing on, Anthropic-on-Vertex
requires a Cloud Marketplace subscription. Honest UNVERIFIED carried
forward — this smoke covers the wire format dimension.
"""
import http.server
import json
import os
import socket
import socketserver
import subprocess
import sys
import threading

AETHER_BIN = "/root/aether-blueprint/target/release/aether"


class Fake:
    def __init__(self):
        self.raw_called = False
        self.stream_called = False
        self.last_authz: str | None = None
        self.last_body: dict | None = None


def make_handler(state: Fake):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a, **kw):
            pass

        def _read_body(self) -> bytes:
            n = int(self.headers.get("Content-Length", "0"))
            return self.rfile.read(n) if n else b""

        def _record(self, body: bytes):
            state.last_authz = self.headers.get("Authorization")
            try:
                state.last_body = json.loads(body)
            except Exception:
                state.last_body = None

        def do_POST(self):
            body = self._read_body()
            self._record(body)
            if self.path.endswith(":rawPredict"):
                state.raw_called = True
                resp = {
                    "id": "z5-fake-1",
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "text", "text": "hi"}],
                    "model": "claude-haiku-4-5",
                    "stop_reason": "end_turn",
                    "usage": {"input_tokens": 5, "output_tokens": 1},
                }
                body_bytes = json.dumps(resp).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body_bytes)))
                self.end_headers()
                self.wfile.write(body_bytes)
                return
            if self.path.endswith(":streamRawPredict"):
                state.stream_called = True
                # SSE: one `data: <json>\n` per Anthropic event.
                events = [
                    {
                        "type": "message_start",
                        "message": {
                            "usage": {"input_tokens": 5, "output_tokens": 0}
                        },
                    },
                    {
                        "type": "content_block_delta",
                        "index": 0,
                        "delta": {"type": "text_delta", "text": "hi-from-z5"},
                    },
                    {
                        "type": "message_delta",
                        "delta": {"stop_reason": "end_turn"},
                        "usage": {"output_tokens": 3},
                    },
                ]
                payload = b""
                for ev in events:
                    payload += b"data: " + json.dumps(ev).encode() + b"\n\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
    return H


def find_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def assert_request_shape(state: Fake, label: str):
    if not state.last_authz or not state.last_authz.startswith("Bearer "):
        print(f"FAIL [{label}]: Authorization header missing or wrong shape "
              f"(got {state.last_authz!r})")
        sys.exit(1)
    if not state.last_body or state.last_body.get("anthropic_version") \
            != "vertex-2023-10-16":
        print(f"FAIL [{label}]: body anthropic_version wrong "
              f"(got {state.last_body!r})")
        sys.exit(1)
    if "model" in (state.last_body or {}):
        print(f"FAIL [{label}]: body should NOT carry top-level 'model' "
              f"(got keys {list(state.last_body.keys())})")
        sys.exit(1)
    if "stream" in (state.last_body or {}):
        print(f"FAIL [{label}]: body should NOT carry top-level 'stream' "
              f"(got keys {list(state.last_body.keys())})")
        sys.exit(1)
    print(f"  [{label}] Bearer + body shape OK "
          f"(authz prefix={state.last_authz[:20]}…)")


def main():
    state = Fake()
    port = find_port()
    httpd = socketserver.ThreadingTCPServer(("127.0.0.1", port), make_handler(state))
    httpd.daemon_threads = True
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{port}"
    print(f"[smoke] fake Vertex listening on {base}")

    env = os.environ.copy()
    env["VERTEX_ACCESS_TOKEN"] = "fake-bearer-z5-smoke-token"
    env["VERTEX_PROJECT"] = "z5-fake-project"
    env["VERTEX_REGION"] = "us-central1"
    env["AETHER_VERTEX_ENDPOINT"] = base
    env["AETHER_PROVIDER"] = "vertex"
    env["AETHER_MODEL"] = "claude-haiku-4-5"

    # ── 1) non-streaming via `doctor --probe` ──────────────────────
    print("[smoke] running: aether doctor --probe (AETHER_PROVIDER=vertex)")
    res = subprocess.run(
        [AETHER_BIN, "doctor", "--probe"],
        env=env, capture_output=True, text=True, timeout=30,
    )
    print(res.stdout)
    print(res.stderr, file=sys.stderr)
    if not state.raw_called:
        print("FAIL: probe did not POST :rawPredict")
        sys.exit(1)
    assert_request_shape(state, "probe")
    if "vertex responded" not in res.stdout:
        print("FAIL: probe stdout missing 'vertex responded'")
        sys.exit(1)
    if res.returncode != 0:
        print(f"FAIL: probe exit code {res.returncode}")
        sys.exit(1)
    print("  [probe] aether parsed JSON response, exit 0")

    # Reset between calls.
    state.last_authz = None
    state.last_body = None
    env["AETHER_NO_COMPACT"] = "1"
    env["AETHER_NO_PARALLEL_TOOLS"] = "1"

    # ── 2) streaming via `aether -p` ────────────────────────────────
    print("[smoke] running: aether -p 'hi'")
    res2 = subprocess.run(
        [AETHER_BIN, "-p", "hi"],
        env=env, capture_output=True, text=True, timeout=30,
    )
    print(res2.stdout)
    print(res2.stderr, file=sys.stderr)
    if not state.stream_called:
        print("FAIL: print mode did not POST :streamRawPredict")
        sys.exit(1)
    assert_request_shape(state, "stream")
    if "hi-from-z5" not in res2.stdout:
        print("FAIL: stdout did not contain streamed delta 'hi-from-z5'")
        sys.exit(1)
    print("  [stream] aether parsed SSE data events and emitted delta")

    httpd.shutdown()
    print("[smoke] Z5 LIVE-VERIFIED OK against fake Vertex "
          "(Bearer + rawPredict JSON + streamRawPredict SSE)")


if __name__ == "__main__":
    main()
