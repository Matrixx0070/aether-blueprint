from order import order_total
from invoice import invoice_total


def test_order_total():
    items = [{"price": 10.0, "qty": 2}, {"price": 5.0, "qty": 1}]
    assert abs(order_total(items) - 27.0) < 1e-6  # (20+5) * 1.08


def test_invoice_total():
    items = [{"price": 10.0, "qty": 2}, {"price": 5.0, "qty": 1}]
    assert abs(invoice_total(items) - 27.0) < 1e-6


def test_empty():
    assert order_total([]) == 0.0
    assert invoice_total([]) == 0.0
