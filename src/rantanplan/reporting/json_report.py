"""
JSON report generator.
"""

import json
from typing import Any, Dict


def generate_json_report(data: Dict[str, Any]) -> str:
    return json.dumps(data, indent=2)
