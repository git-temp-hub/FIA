from __future__ import annotations

import uuid
from datetime import datetime

def generate_investigation_id() -> str:
    """
    Generate a unique investigation identifier.

    Example:
    INV-20260804-A1B2C3
    """

    today = datetime.now().strftime("%Y%m%d")

    suffix = uuid.uuid4().hex[:6].upper()

    return f"INV-{today}-{suffix}"