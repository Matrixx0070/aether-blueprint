"""Small math helpers — no tests yet."""


def add(a: float, b: float) -> float:
    """Return a + b."""
    return a + b


def subtract(a: float, b: float) -> float:
    """Return a - b."""
    return a - b


def divide(a: float, b: float) -> float:
    """Return a / b. Raises ZeroDivisionError when b is 0."""
    if b == 0:
        raise ZeroDivisionError("division by zero")
    return a / b


def factorial(n: int) -> int:
    """Return n!. Raises ValueError on negative input."""
    if n < 0:
        raise ValueError("factorial undefined for negative integers")
    result = 1
    for i in range(2, n + 1):
        result *= i
    return result


def is_even(n: int) -> bool:
    """Return True iff n is even."""
    return n % 2 == 0
