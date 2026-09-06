"""
Upstream Scanner Capability Drift Monitoring Engine.
"""

from typing import Dict, Any, List


class UpstreamDriftMonitor:
    """Monitors capability drift between snapshot versions."""

    @staticmethod
    def compare_snapshots(previous: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
        changes: List[Dict[str, Any]] = []

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

