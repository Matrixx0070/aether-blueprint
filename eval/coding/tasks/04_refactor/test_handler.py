"""Behavior-preservation tests for process_request — must keep passing after refactor."""
from handler import process_request


def test_missing_method():
    r = process_request({"path": "/x"})
    assert r == {"ok": False, "error": "missing method"}


def test_missing_path():
    r = process_request({"method": "GET"})
    assert r == {"ok": False, "error": "missing path"}


def test_not_a_dict():
    r = process_request("not a dict")
    assert r == {"ok": False, "error": "not a dict"}


def test_method_normalization():
    r = process_request({"method": "  get  ", "path": "/users"})
    assert r["ok"] is True
    assert r["method"] == "GET"


def test_path_normalization():
    r = process_request({"method": "GET", "path": "users//list/"})
    assert r["ok"] is True
    assert r["path"] == "/users/list"


def test_path_root_preserved():
    r = process_request({"method": "GET", "path": "/"})
    assert r["ok"] is True
    assert r["path"] == "/"


def test_get_is_read():
    assert process_request({"method": "GET", "path": "/x"})["kind"] == "read"


def test_post_is_write():
    assert process_request({"method": "POST", "path": "/x"})["kind"] == "write"


def test_delete_is_delete():
    assert process_request({"method": "DELETE", "path": "/x"})["kind"] == "delete"


def test_head_is_meta():
    assert process_request({"method": "HEAD", "path": "/x"})["kind"] == "meta"


def test_unsupported_method():
    r = process_request({"method": "BREW", "path": "/x"})
    assert r["ok"] is False
    assert "unsupported method" in r["error"]
