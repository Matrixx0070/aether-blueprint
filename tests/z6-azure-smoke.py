#!/usr/bin/env python3
"""
Z6 fake-endpoint Azure AI Foundry smoke. NOT a real Azure live-verify.

Azure AI Foundry hosts Claude models behind an Anthropic Messages-API-
compatible surface. Unlike Bedrock / Vertex, this provider uses the
existing AZURE_AI_ENDPOINT env directly as the resource base URL, so
no new env-override knob is needed — pointing it at
http://127.0.0.1:NNNN already works.

Stands up a Python fake `services.ai.azure.com` that handles:
  POST /anthropic/v1/messages?api-version=<v>
       → Anthropic Messages-API JSON response.

Asserts on each request:
  - api-key: <token> header present (Azure's auth scheme, NOT
    Authorization: Bearer or x-api-key)
  - anthropic-version: 2023-06-01 header present
  - URL query carries api-version=2024-08-01-preview (the
    aether-llm DEFAULT_API_VERSION)
  - body contains `model`, `messages`, `max_tokens` (Azure's wire
    shape is plain Anthropic Messages, no Bedrock/Vertex stripping
    or anthropic_version discriminator)

Drives aether through TWO paths — note: AzureProvider has no
complete_streamed impl, so the streaming path falls through to the
LlmProvider default which calls complete() and emits the whole text
as ONE chunk. Both paths therefore hit /anthropic/v1/messages
(non-streaming).
  1. `aether doctor --probe` (AETHER_PROVIDER=azure)
  2. `aether -p "hi"`

Exit 1 on any assertion failure.
"""
import http.server
import json
import os
import socket
import socketserver
import subprocess
import sys
import threading
import urllib.parse

AETHER_BIN = "/root/aether-blueprint/target/release/aether"
API_KEY = "fake-azure-z6-key"
EXPECTED_API_VERSION = "2024-08-01-preview"


class Fake:
    def __init__(self):
        self.messages_called = 0
        self.last_api_key: str | None = None
        self.last_anthropic_version: str | None = None
        self.last_api_version_qs: str | None = None
        self.last_body: dict | None = None


def make_handler(state: Fake):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a, **kw):
            pass

        def _read_body(self) -> bytes:
            n = int(self.headers.get("Content-Length", "0"))
            return self.rfile.read(n) if n else b""

        def _record(self, body: bytes, parsed_url):
            state.last_api_key = self.headers.get("api-key") or self.headers.get(
                "Api-Key"
            )
            state.last_anthropic_version = self.headers.get(
                "anthropic-version"
            ) or self.headers.get("Anthropic-Version")
            qs = urllib.parse.parse_qs(parsed_url.query)
            state.last_api_version_qs = qs.get("api-version", [None])[0]
            try:
                state.last_body = json.loads(body)
            except Exception:
                state.last_body = None

        def do_POST(self):
            parsed = urllib.parse.urlparse(self.path)
            body = self._read_body()
            self._record(body, parsed)
            if parsed.path == "/anthropic/v1/messages":
                state.messages_called += 1
                resp = {
                    "id": "z6-fake-1",
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "text", "text": "hi-from-z6"}],
                    "model": "claude-haiku-4-5",
                    "stop_reason": "end_turn",
                    "usage": {"input_tokens": 9, "output_tokens": 4},
                }
                body_bytes = json.dumps(resp).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body_bytes)))
                self.end_headers()
                self.wfile.write(body_bytes)
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
    if state.last_api_key != API_KEY:
        print(f"FAIL [{label}]: api-key header wrong "
              f"(got {state.last_api_key!r}, expected {API_KEY!r})")
        sys.exit(1)
    if state.last_anthropic_version != "2023-06-01":
        print(f"FAIL [{label}]: anthropic-version header wrong "
              f"(got {state.last_anthropic_version!r})")
        sys.exit(1)
    if state.last_api_version_qs != EXPECTED_API_VERSION:
        print(f"FAIL [{label}]: api-version query wrong "
              f"(got {state.last_api_version_qs!r}, "
              f"expected {EXPECTED_API_VERSION!r})")
        sys.exit(1)
    if not state.last_body:
        print(f"FAIL [{label}]: body did not parse as JSON")
        sys.exit(1)
    for key in ("model", "messages", "max_tokens"):
        if key not in state.last_body:
            print(f"FAIL [{label}]: body missing required key '{key}' "
                  f"(got keys {list(state.last_body.keys())})")
            sys.exit(1)
    print(f"  [{label}] api-key + anthropic-version + api-version + "
          f"body shape OK")


def main():
    state = Fake()
    port = find_port()
    httpd = socketserver.ThreadingTCPServer(("127.0.0.1", port), make_handler(state))
    httpd.daemon_threads = True
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{port}"
    print(f"[smoke] fake Azure AI Foundry listening on {base}")

    env = os.environ.copy()
    env["AZURE_AI_ENDPOINT"] = base
    env["AZURE_AI_API_KEY"] = API_KEY
    env["AETHER_PROVIDER"] = "azure"
    env["AETHER_MODEL"] = "claude-haiku-4-5"

    # ── 1) probe path ───────────────────────────────────────────────
    print("[smoke] running: aether doctor --probe (AETHER_PROVIDER=azure)")
    res = subprocess.run(
        [AETHER_BIN, "doctor", "--probe"],
        env=env, capture_output=True, text=True, timeout=30,
    )
    print(res.stdout)
    print(res.stderr, file=sys.stderr)
    if state.messages_called == 0:
        print("FAIL: probe did not POST /anthropic/v1/messages")
        sys.exit(1)
    assert_request_shape(state, "probe")
    if "azure-foundry responded" not in res.stdout:
        print("FAIL: probe stdout missing 'azure-foundry responded'")
        sys.exit(1)
    if res.returncode != 0:
        print(f"FAIL: probe exit code {res.returncode}")
        sys.exit(1)
    print("  [probe] aether parsed JSON response, exit 0")

    # Reset call-level state between runs.
    state.last_api_key = None
    state.last_body = None
    state.last_anthropic_version = None
    state.last_api_version_qs = None
    env["AETHER_NO_COMPACT"] = "1"
    env["AETHER_NO_PARALLEL_TOOLS"] = "1"

    # ── 2) print mode (default complete_streamed → complete) ────────
    print("[smoke] running: aether -p 'hi'")
    res2 = subprocess.run(
        [AETHER_BIN, "-p", "hi"],
        env=env, capture_output=True, text=True, timeout=30,
    )
    print(res2.stdout)
    print(res2.stderr, file=sys.stderr)
    if state.messages_called < 2:
        print("FAIL: print mode did not POST a second /anthropic/v1/messages")
        sys.exit(1)
    assert_request_shape(state, "print")
    if "hi-from-z6" not in res2.stdout:
        print("FAIL: stdout did not contain response text 'hi-from-z6'")
        sys.exit(1)
    print("  [print] aether forwarded complete() response text to stdout")

    httpd.shutdown()
    print("[smoke] Z6 LIVE-VERIFIED OK against fake Azure AI Foundry "
          "(api-key + anthropic-version + Messages API JSON)")


if __name__ == "__main__":
    main()
