#!/usr/bin/env python3
"""
Z4 fake-endpoint Bedrock smoke. NOT a real AWS live-verify — exercises
the wire format (SigV4 request shape + AWS event-stream framing +
Anthropic Messages-API response body) against a Python fake that
stands in for bedrock-runtime.us-east-1.amazonaws.com.

Drives aether through TWO paths:
  1. `aether doctor --probe --provider bedrock`
     → POST /model/<id>/invoke (non-streaming). Asserts:
       - Authorization header starts with `AWS4-HMAC-SHA256`
       - x-amz-date + x-amz-content-sha256 present
       - request body carries `anthropic_version: "bedrock-2023-05-31"`
         and does NOT carry top-level `model` / `stream` (per
         bedrock_body() in aether-llm/bedrock.rs)
       - aether parses the JSON response, prints usage tokens.

  2. `aether p "hi" --provider bedrock`
     → POST /model/<id>/invoke-with-response-stream (streaming).
       Returns 3 chunk events containing message_start / content_block_
       delta / message_delta framed in AWS event-stream format. Asserts
       aether prints the text delta payload to stdout.

A failure in either path exits 1.
"""
import base64
import http.server
import json
import os
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time

AETHER_BIN = "/root/aether-blueprint/target/release/aether"


def event_stream_frame(event_type: str, payload: bytes) -> bytes:
    """Build one AWS event-stream message.

    Frame: [4B total_len][4B headers_len][4B prelude_crc][headers][payload][4B trailing_crc]
    Header for :event-type — name_len(1) + name + type(7 = string) + 2B val_len + val.
    Aether's parse_event_stream_message ignores the CRC bytes, so zeros work.
    """
    name = b":event-type"
    val = event_type.encode()
    header = bytes([len(name)]) + name + bytes([7]) + struct.pack(">H", len(val)) + val
    headers_len = len(header)
    total_len = 12 + headers_len + len(payload) + 4
    prelude_crc = b"\x00\x00\x00\x00"
    trailing_crc = b"\x00\x00\x00\x00"
    return (
        struct.pack(">I", total_len)
        + struct.pack(">I", headers_len)
        + prelude_crc
        + header
        + payload
        + trailing_crc
    )


def make_chunk_payload(delta_obj: dict) -> bytes:
    """Each chunk-event payload wraps the Anthropic delta in {"bytes":"<b64>"}."""
    inner = json.dumps(delta_obj, separators=(",", ":")).encode()
    return json.dumps(
        {"bytes": base64.standard_b64encode(inner).decode()},
        separators=(",", ":"),
    ).encode()


class Fake:
    def __init__(self):
        self.invoke_called = False
        self.invoke_stream_called = False
        self.last_authz: str | None = None
        self.last_amz_date: str | None = None
        self.last_content_sha: str | None = None
        self.last_body: dict | None = None


def make_handler(state: Fake):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a, **kw):
            pass

        def _read_body(self) -> bytes:
            n = int(self.headers.get("Content-Length", "0"))
            return self.rfile.read(n) if n else b""

        def _record_sigv4(self, body: bytes):
            state.last_authz = self.headers.get("Authorization")
            state.last_amz_date = self.headers.get("x-amz-date") or self.headers.get(
                "X-Amz-Date"
            )
            state.last_content_sha = self.headers.get(
                "x-amz-content-sha256"
            ) or self.headers.get("X-Amz-Content-Sha256")
            try:
                state.last_body = json.loads(body)
            except Exception:
                state.last_body = None

        def do_POST(self):
            body = self._read_body()
            self._record_sigv4(body)
            if self.path.endswith("/invoke"):
                state.invoke_called = True
                # Anthropic Messages-API non-streaming response shape.
                resp = {
                    "id": "z4-fake-1",
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "text", "text": "hi"}],
                    "model": "claude-haiku-4-5",
                    "stop_reason": "end_turn",
                    "usage": {"input_tokens": 7, "output_tokens": 1},
                }
                body_bytes = json.dumps(resp).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body_bytes)))
                self.end_headers()
                self.wfile.write(body_bytes)
                return
            if self.path.endswith("/invoke-with-response-stream"):
                state.invoke_stream_called = True
                # Stream three chunk events: message_start, one text
                # delta, message_delta carrying stop_reason + usage.
                frames = [
                    event_stream_frame("chunk", make_chunk_payload({
                        "type": "message_start",
                        "message": {"usage": {"input_tokens": 7, "output_tokens": 0}},
                    })),
                    event_stream_frame("chunk", make_chunk_payload({
                        "type": "content_block_delta",
                        "index": 0,
                        "delta": {"type": "text_delta", "text": "hi-from-z4"},
                    })),
                    event_stream_frame("chunk", make_chunk_payload({
                        "type": "message_delta",
                        "delta": {"stop_reason": "end_turn"},
                        "usage": {"output_tokens": 3},
                    })),
                ]
                payload = b"".join(frames)
                self.send_response(200)
                self.send_header(
                    "Content-Type", "application/vnd.amazon.eventstream"
                )
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


def assert_sigv4(state: Fake, label: str):
    if not state.last_authz or not state.last_authz.startswith("AWS4-HMAC-SHA256"):
        print(f"FAIL [{label}]: Authorization header missing or wrong shape "
              f"(got {state.last_authz!r})")
        sys.exit(1)
    if not state.last_amz_date:
        print(f"FAIL [{label}]: x-amz-date header missing")
        sys.exit(1)
    if not state.last_content_sha or len(state.last_content_sha) != 64:
        print(f"FAIL [{label}]: x-amz-content-sha256 missing or wrong length")
        sys.exit(1)
    if not state.last_body or state.last_body.get("anthropic_version") \
            != "bedrock-2023-05-31":
        print(f"FAIL [{label}]: body anthropic_version wrong "
              f"(got {state.last_body!r})")
        sys.exit(1)
    if "model" in (state.last_body or {}):
        print(f"FAIL [{label}]: body should NOT carry top-level 'model' "
              f"(got keys {list(state.last_body.keys())})")
        sys.exit(1)
    print(f"  [{label}] SigV4 + body shape OK "
          f"(authz prefix={state.last_authz[:30]}…)")


def main():
    state = Fake()
    port = find_port()
    httpd = socketserver.ThreadingTCPServer(("127.0.0.1", port), make_handler(state))
    httpd.daemon_threads = True
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{port}"
    print(f"[smoke] fake Bedrock listening on {base}")

    env = os.environ.copy()
    env["AWS_ACCESS_KEY_ID"] = "AKIAFAKE0000000Z4SMOKE"
    env["AWS_SECRET_ACCESS_KEY"] = "fakeSecret0000000000000000000000000000z4"
    env["AWS_REGION"] = "us-east-1"
    env["AETHER_BEDROCK_ENDPOINT"] = base
    # Force the default model resolver to a known-mappable name so
    # map_model_id() produces a stable bedrock model id.
    env["AETHER_MODEL"] = "claude-haiku-4-5"

    # ── 1) non-streaming via `doctor --probe` ──────────────────────
    print("[smoke] running: aether doctor --probe --provider bedrock")
    # The doctor command honors --probe; --provider flag isn't on
    # doctor (uses build_provider via active_provider_name), so set
    # via AETHER_PROVIDER instead.
    env["AETHER_PROVIDER"] = "bedrock"
    res = subprocess.run(
        [AETHER_BIN, "doctor", "--probe"],
        env=env, capture_output=True, text=True, timeout=30,
    )
    print(res.stdout)
    print(res.stderr, file=sys.stderr)
    if not state.invoke_called:
        print("FAIL: probe did not POST /invoke")
        sys.exit(1)
    assert_sigv4(state, "probe")
    if "bedrock responded" not in res.stdout:
        print("FAIL: probe stdout missing 'bedrock responded'")
        sys.exit(1)
    if res.returncode != 0:
        print(f"FAIL: probe exit code {res.returncode}")
        sys.exit(1)
    print("  [probe] aether parsed JSON response, exit 0")

    # Reset state between calls.
    state.last_authz = None
    state.last_body = None

    # ── 2) streaming via `aether p` ─────────────────────────────────
    # Print-mode (`aether p` / `aether prompt`) drives the agent loop
    # with streaming. We just need ONE turn — set max_tokens implicitly
    # via the prompt; aether will call complete_streamed which hits
    # /invoke-with-response-stream.
    #
    # Disable parallel-tools + compaction kill-switches that could
    # change the request shape.
    env["AETHER_NO_COMPACT"] = "1"
    env["AETHER_NO_PARALLEL_TOOLS"] = "1"
    print("[smoke] running: aether -p 'hi'")
    res2 = subprocess.run(
        [AETHER_BIN, "-p", "hi"],
        env=env, capture_output=True, text=True, timeout=30,
    )
    print(res2.stdout)
    print(res2.stderr, file=sys.stderr)
    if not state.invoke_stream_called:
        print("FAIL: print mode did not POST /invoke-with-response-stream")
        sys.exit(1)
    assert_sigv4(state, "stream")
    if "hi-from-z4" not in res2.stdout:
        print("FAIL: stdout did not contain streamed delta 'hi-from-z4'")
        sys.exit(1)
    print("  [stream] aether parsed event-stream frames and emitted delta")

    httpd.shutdown()
    print("[smoke] Z4 LIVE-VERIFIED OK against fake Bedrock "
          "(SigV4 + event-stream + non-streaming JSON)")


if __name__ == "__main__":
    main()
