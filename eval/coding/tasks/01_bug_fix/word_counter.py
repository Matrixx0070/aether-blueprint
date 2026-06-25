"""Tiny word-counting utility."""


def count_words(text: str) -> int:
    """Return the number of whitespace-separated words in `text`.

    Empty string and whitespace-only strings should return 0.
    """
    # BUG: this counts characters, not words. The fix is to .split() first.
    return len(text)


def count_unique_words(text: str) -> int:
    """Return the number of unique whitespace-separated words in `text`.

    Comparison is case-insensitive.
    """
    return len(set(w.lower() for w in text.split()))
