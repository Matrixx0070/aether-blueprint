"""Tiny string-echo CLI. Reads a positional STRING arg and echoes it.

Future plan: add a --reverse flag to reverse the string before echoing.
"""
import argparse
import sys


def echo(s: str, reverse: bool = False) -> str:
    """Return `s`, optionally reversed when `reverse` is True."""
    if reverse:
        return s[::-1]
    return s


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="echo a string")
    p.add_argument("text", help="string to echo")
    args = p.parse_args(argv)
    print(echo(args.text))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
