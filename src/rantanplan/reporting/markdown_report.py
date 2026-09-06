"""
Markdown report generator for differential matrices and capability metrics.
"""

from typing import Any


def generate_markdown_report(matrix_data: dict[str, Any], metrics_data: dict[str, Any]) -> str:
    scanners = matrix_data.get("scanners", [])
    matrix = matrix_data.get("matrix", [])

    md = []
    md.append("# Rantanplan Differential Scanner Matrix Report\n")
    md.append("Vendor-neutral AI Security Scanner Conformance & Benchmark Matrix.\n")

    # Metrics Summary Table
    md.append("## Scanner Metrics Summary\n")
    md.append("| Scanner | TPR (Recall) | FPR | Error Rate | Total Cases |")
    md.append("| :--- | :---: | :---: | :---: | :---: |")
    for scanner, m in metrics_data.items():
        md.append(f"| **{scanner}** | {m.get('tpr', 0.0)}% | {m.get('fpr', 0.0)}% | {m.get('error_rate', 0.0)}% | {m.get('total_cases', 0)} |")

    md.append("\n## Differential Test Case Results\n")
    header = "| Case ID | Domain | " + " | ".join(scanners) + " |"
    divider = "| :--- | :--- | " + " | ".join([":---:"] * len(scanners)) + " |"
    md.append(header)
    md.append(divider)

    for row in matrix:
        case_id = row["case_id"]
        domain = row["domain"]
        outcomes = [row["outcomes"].get(s, "N/A") for s in scanners]
        md.append(f"| `{case_id}` | `{domain}` | " + " | ".join(outcomes) + " |")

    return "\n".join(md)

