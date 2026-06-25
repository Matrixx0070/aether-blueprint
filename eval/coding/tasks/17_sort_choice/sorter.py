"""Sort a list of (name, score) tuples — currently UNIMPLEMENTED.

NOTE for the implementer: many decisions are not specified:
  1. Sort by name (alphabetical) OR score (numeric)?
  2. Ascending OR descending?
  3. Stable (preserve original order on ties) OR not?

There is no right answer for a generic util. Whoever implements this
must PICK ONE of each axis, IMPLEMENT it, and DOCUMENT the choice in
the docstring so callers know what they're getting.
"""

from typing import List, Tuple


def sort_records(records: List[Tuple[str, int]]) -> List[Tuple[str, int]]:
    """Sort `records` (list of (name, score) tuples)."""
    raise NotImplementedError("pick sort key + direction + stability, implement, and document")
