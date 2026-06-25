"""A deliberately slow function that needs caching — DESIGN CHOICE OPEN.

NOTE for the implementer: the slow function below has the right shape
for memoization, but the implementer must pick:

  - UNBOUNDED memo dict (simple, but memory grows forever)
  - LRU cache with a size cap (bounded memory, evict least-recently-used)
  - FIFO cache (bounded, evict oldest insertion)
  - TTL cache (entries expire after N seconds)
  - No caching at all (if the call pattern doesn't warrant it)

Whoever implements this must PICK ONE strategy, IMPLEMENT it, and
DOCUMENT it in the function docstring so callers know the eviction
behavior they're getting.
"""

import time


def expensive_lookup(key: str) -> int:
    """Simulate a slow lookup that returns the same value for the same key."""
    # 50ms artificial delay per call — caching should bring repeated
    # lookups for the same key to near-zero.
    time.sleep(0.05)
    return hash(key) & 0xFFFF


# The function the implementer must define / rewrite to add caching.
def get_value(key: str) -> int:
    """Return expensive_lookup(key), with caching strategy TBD."""
    return expensive_lookup(key)
