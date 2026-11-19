"""
Target lookup across real ecosystem adapters and built-in calibration targets.
"""

from __future__ import annotations

from functools import lru_cache

from rantanplan.adapters.reference import get_reference_adapters
from rantanplan.ecosystem import get_all_target_adapters
from rantanplan.target_hierarchy import TargetAdapter


@lru_cache(maxsize=1)
def _build_targets() -> dict[str, TargetAdapter]:
    targets: dict[str, TargetAdapter] = {a.identity().name: a for a in get_all_target_adapters()}
    targets.update({a.identity().name: a for a in get_reference_adapters()})
    return targets


def all_targets() -> dict[str, TargetAdapter]:
    """All targets by name. Built once per process (adapter construction probes binary versions)."""
    return dict(_build_targets())


def resolve_target(name: str) -> TargetAdapter:
    targets = all_targets()
    if name not in targets:
        raise KeyError(f"Unknown target '{name}'. Available: {', '.join(sorted(targets))}")
    return targets[name]
