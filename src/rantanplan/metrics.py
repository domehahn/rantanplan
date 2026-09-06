"""
Metrics calculation module for per-scanner and per-domain analysis.
"""

from typing import Dict, List
from rantanplan.models import NormalizedResult, Outcome


class MetricsCalculator:
    """Calculates True Positive Rate, False Positive Rate, Error Rate, Timeout Rate, and Applicability Metrics."""

    @staticmethod
    def calculate_scanner_metrics(results: List[NormalizedResult]) -> Dict[str, float]:
        if not results:
            return {
                "tpr": 100.0,
                "fpr": 0.0,
                "error_rate": 0.0,
                "timeout_rate": 0.0,
                "total_cases": 0,
            }

        tp = 0
        fn = 0
        fp = 0
        tn = 0
        errors = 0
        timeouts = 0

        for r in results:
            if r.outcome == Outcome.DETECTED:
                tp += 1
            elif r.outcome == Outcome.NOT_DETECTED:
                fn += 1
            elif r.outcome == Outcome.FAIL:
                fp += 1
            elif r.outcome == Outcome.PASS:
                tn += 1
            elif r.outcome == Outcome.ERROR:
                errors += 1
            elif r.outcome == Outcome.TIMEOUT:
                timeouts += 1

        total = len(results)
        tpr = (tp / (tp + fn) * 100.0) if (tp + fn) > 0 else 100.0
        fpr = (fp / (fp + tn) * 100.0) if (fp + tn) > 0 else 0.0
        error_rate = (errors / total * 100.0) if total > 0 else 0.0
        timeout_rate = (timeouts / total * 100.0) if total > 0 else 0.0

        return {
            "tpr": round(tpr, 1),
            "fpr": round(fpr, 1),
            "error_rate": round(error_rate, 1),
            "timeout_rate": round(timeout_rate, 1),
            "total_cases": total,
            "true_positives": tp,
            "false_negatives": fn,
            "false_positives": fp,
            "true_negatives": tn,
        }

