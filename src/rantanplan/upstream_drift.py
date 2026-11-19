"""
Upstream Scanner Capability Drift Monitoring Engine.
"""

import json
from pathlib import Path
from typing import Any


class UpstreamDriftMonitor:
    """Monitors capability drift between snapshot versions."""

    @staticmethod
    def compare_snapshots(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
        changes: list[dict[str, Any]] = []

        prev_scanners = previous.get("scanners", {})
        curr_scanners = current.get("scanners", {})

        for scanner_name, curr_data in curr_scanners.items():
            if scanner_name not in prev_scanners:
                changes.append({
                    "scanner": scanner_name,
                    "change_type": "NEW_SCANNER",
                    "details": f"Scanner {scanner_name} added to inventory",
                })
                continue

            prev_data = prev_scanners[scanner_name]
            prev_caps = set(prev_data.get("capabilities", []))
            curr_caps = set(curr_data.get("capabilities", []))

            added_caps = curr_caps - prev_caps
            removed_caps = prev_caps - curr_caps

            for cap in added_caps:
                changes.append({
                    "scanner": scanner_name,
                    "change_type": "NEW",
                    "details": f"Added capability {cap}",
                })

            for cap in removed_caps:
                changes.append({
                    "scanner": scanner_name,
                    "change_type": "REMOVED",
                    "details": f"Removed capability {cap}",
                })

        return {
            "total_changes": len(changes),
            "changes": changes,
        }

    @classmethod
    def check_drift(cls, snapshot_dir: str = "snapshots") -> dict[str, dict[str, Any]]:
        """Compare the two newest capability snapshots; returns ``target -> {drift, details}``."""
        files = sorted(Path(snapshot_dir).glob("capability-snapshot-*.json"))
        if not files:
            return {"(none)": {"drift": False, "details": f"no snapshot in {snapshot_dir}/ (run `rantanplan inventory` first)"}}
        current = json.loads(files[-1].read_text(encoding="utf-8"))
        scanners = list(current.get("scanners", {}))
        if len(files) < 2:
            return {s: {"drift": False, "details": "baseline snapshot only; nothing to compare yet"} for s in scanners}
        previous = json.loads(files[-2].read_text(encoding="utf-8"))
        report = cls.compare_snapshots(previous, current)
        result: dict[str, dict[str, Any]] = {s: {"drift": False, "details": "Clean"} for s in scanners}
        for change in report["changes"]:
            entry = result.setdefault(change["scanner"], {"drift": False, "details": ""})
            entry["drift"] = True
            entry["details"] = "; ".join(filter(None, [entry["details"] if entry["details"] != "Clean" else "", change["details"]]))
        return result
