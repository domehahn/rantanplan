"""
Upstream scanner capability inventory and snapshot engine.
"""

import json
import os
import time
from typing import Any, Dict, List

from rantanplan.adapters.base import ScannerAdapter
from rantanplan.adapters.garak import GarakAdapter
from rantanplan.adapters.skil import SKILAdapter
from rantanplan.adapters.skillevaluator import SkillEvaluatorAdapter
from rantanplan.adapters.skillspector import SkillSpectorAdapter


class CapabilityInventoryEngine:
    """Discovers, snapshots, and monitors upstream capabilities of all four target scanners."""

    def __init__(self):
        self.adapters: List[ScannerAdapter] = [
            SKILAdapter(),
            SkillSpectorAdapter(),
            GarakAdapter(),
            SkillEvaluatorAdapter(),
        ]

    def run_snapshot(self, out_dir: str = "snapshots") -> Dict[str, Any]:
        os.makedirs(out_dir, exist_ok=True)
        date_str = time.strftime("%Y-%m-%d")
        snapshot_file = os.path.join(out_dir, f"capability-snapshot-{date_str}.json")

        inventory_data: Dict[str, Any] = {
            "snapshot_date": date_str,
            "scanners": {},
        }

        for adapter in self.adapters:
            ident = adapter.identity()
            doc = adapter.doctor()
            caps = adapter.capabilities()

            inventory_data["scanners"][ident.name] = {
                "identity": ident.model_dump(),
                "doctor": doc.model_dump(),
                "capabilities": caps,
                "supported_domains_count": len(caps),
            }

        with open(snapshot_file, "w", encoding="utf-8") as f:
            json.dump(inventory_data, f, indent=2)

        return inventory_data
