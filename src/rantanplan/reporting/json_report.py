"""
JSON report generator.
"""

import json
from typing import Any


def generate_json_report(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=2)

