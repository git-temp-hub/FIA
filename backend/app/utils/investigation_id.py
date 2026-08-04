from __future__ import annotations

from datetime import datetime
from itertools import count

_counter = count(1)

def generate_investigation_id() -> str:
    """
    Generate a unique investigation identifier.

    Example:
    INV-20260804-0001
    """

    today = datetime.now().strftime("%Y%m%d")

    number = next(_counter)

    return f"INV-{today}-{number:04d}"