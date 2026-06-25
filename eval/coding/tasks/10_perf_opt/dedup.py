"""Deduplicate a list of strings — currently O(n²)."""


def dedup(items: list[str]) -> list[str]:
    """Return `items` with duplicates removed, preserving first-seen order.

    Current implementation uses a nested scan (O(n²)). Acceptable for small
    n; pathological at n=50,000 — multi-second wall on modest hardware.
    """
    out: list[str] = []
    for x in items:
        if x not in out:
            out.append(x)
    return out
