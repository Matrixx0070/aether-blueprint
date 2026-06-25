import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent


def run_cli(*args: str) -> tuple[int, str, str]:
    p = subprocess.run(
        [sys.executable, str(HERE / "main.py"), *args],
        capture_output=True,
        text=True,
    )
    return p.returncode, p.stdout, p.stderr


def test_plain_echo():
    rc, out, _ = run_cli("hello")
    assert rc == 0
    assert out.strip() == "hello"


def test_unicode():
    rc, out, _ = run_cli("café")
    assert rc == 0
    assert out.strip() == "café"
