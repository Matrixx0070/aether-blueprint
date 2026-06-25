"""Order-totalling code — duplicated across files."""

TAX_RATE = 0.08  # DUP — also in invoice.py


def order_total(items: list[dict]) -> float:
    """Sum prices * qty, apply 8% tax."""
    subtotal = 0.0
    for item in items:
        subtotal += item["price"] * item["qty"]
    return subtotal + subtotal * TAX_RATE
