"""Invoice-totalling code — duplicated TAX_RATE constant + identical math."""

TAX_RATE = 0.08  # DUP — also in order.py


def invoice_total(line_items: list[dict]) -> float:
    """Sum prices * qty, apply 8% tax."""
    subtotal = 0.0
    for li in line_items:
        subtotal += li["price"] * li["qty"]
    return subtotal + subtotal * TAX_RATE
