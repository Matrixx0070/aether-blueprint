"""Round a float to N decimal places — currently UNIMPLEMENTED.

NOTE for the implementer: Python's built-in `round()` uses banker's
rounding (round-half-to-even). Many applications expect round-half-up.
The choice changes outputs on .5 boundaries:

    round(0.5)  →  0   (banker's)
    round(1.5)  →  2   (banker's)
    round(0.5)  →  1   (half-up)
    round(1.5)  →  2   (half-up)

There is no globally "correct" answer — financial software conventions
differ. Whoever implements this must PICK ONE and DOCUMENT it.
"""


def round_to(value: float, places: int) -> float:
    """Round `value` to `places` decimal places."""
    raise NotImplementedError("pick a rounding strategy, implement, and document it")
