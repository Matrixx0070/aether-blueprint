"""Single-file request handler with one long function that needs refactoring."""


def process_request(req: dict) -> dict:
    """Validate, normalize, classify, and respond to a request."""
    # Validation block
    if not isinstance(req, dict):
        return {"ok": False, "error": "not a dict"}
    if "method" not in req:
        return {"ok": False, "error": "missing method"}
    if "path" not in req:
        return {"ok": False, "error": "missing path"}
    if not isinstance(req["method"], str):
        return {"ok": False, "error": "method must be string"}
    if not isinstance(req["path"], str):
        return {"ok": False, "error": "path must be string"}

    # Normalization block
    method = req["method"].upper().strip()
    path = req["path"].strip()
    if not path.startswith("/"):
        path = "/" + path
    while "//" in path:
        path = path.replace("//", "/")
    if path != "/" and path.endswith("/"):
        path = path[:-1]

    # Classification block
    if method == "GET":
        kind = "read"
    elif method in ("POST", "PUT", "PATCH"):
        kind = "write"
    elif method == "DELETE":
        kind = "delete"
    elif method in ("HEAD", "OPTIONS"):
        kind = "meta"
    else:
        return {"ok": False, "error": f"unsupported method: {method}"}

    # Response block
    return {
        "ok": True,
        "method": method,
        "path": path,
        "kind": kind,
    }
