"""
Differential engine for cross-scanner benchmarking and capability matrix tables.
"""

from typing import Any

from rantanplan.models import NormalizedResult, Outcome, TestCase


class DifferentialEngine:
    """Generates cross-scanner differential matrix and capability coverage comparison tables."""

    @staticmethod
    def generate_matrix(cases: list[TestCase], run_results: dict[str, list[NormalizedResult]]) -> dict[str, Any]:
        """
        run_results is a map of scanner_name -> list of NormalizedResult.
        """
        matrix: list[dict[str, Any]] = []

        for case in cases:
            row: dict[str, Any] = {
                "case_id": case.id,
                "title": case.title,
                "domain": case.domain,
                "malicious": case.ground_truth.get("malicious", False),
                "outcomes": {},
            }

            for scanner_name, results in run_results.items():
                match = next((r for r in results if r.case_id == case.id), None)
                if match:
                    row["outcomes"][scanner_name] = match.outcome.value
                else:
                    row["outcomes"][scanner_name] = Outcome.NOT_APPLICABLE.value

            matrix.append(row)

        return {
            "total_cases": len(cases),
            "scanners": list(run_results.keys()),
            "matrix": matrix,
        }

