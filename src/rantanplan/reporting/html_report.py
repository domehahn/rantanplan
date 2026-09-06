"""
Standalone offline HTML report generator.
"""

from typing import Any


def generate_html_report(matrix_data: dict[str, Any], metrics_data: dict[str, Any]) -> str:
    scanners = matrix_data.get("scanners", [])
    matrix = matrix_data.get("matrix", [])

    rows_html = []
    for row in matrix:
        case_id = row["case_id"]
        domain = row["domain"]
        cells = "".join([f"<td><span class='badge {row['outcomes'].get(s, '').lower()}'>{row['outcomes'].get(s, 'N/A')}</span></td>" for s in scanners])
        rows_html.append(f"<tr><td><code>{case_id}</code></td><td>{domain}</td>{cells}</tr>")

    metrics_html = []
    for s, m in metrics_data.items():
        metrics_html.append(f"""
        <div class="card">
            <div class="card-title">{s}</div>
            <div class="card-metric">TPR: {m.get('tpr', 0.0)}%</div>
            <div class="card-sub">FPR: {m.get('fpr', 0.0)}% • Errors: {m.get('error_rate', 0.0)}%</div>
        </div>
        """)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Rantanplan Differential Benchmark Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 2rem; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ border-bottom: 1px solid #334155; padding-bottom: 1rem; margin-bottom: 2rem; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }}
        .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 0.5rem; padding: 1.5rem; }}
        .card-title {{ color: #94a3b8; font-size: 0.85rem; text-transform: uppercase; font-weight: 600; }}
        .card-metric {{ font-size: 1.8rem; font-weight: 700; color: #38bdf8; margin: 0.5rem 0; }}
        .card-sub {{ color: #64748b; font-size: 0.85rem; }}
        table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 0.5rem; overflow: hidden; }}
        th, td {{ padding: 0.75rem 1rem; border-bottom: 1px solid #334155; text-align: left; font-size: 0.9rem; }}
        th {{ background: #0f172a; color: #94a3b8; font-weight: 600; }}
        .badge {{ padding: 0.2rem 0.5rem; border-radius: 0.25rem; font-size: 0.75rem; font-weight: 700; }}
        .badge.detected {{ background: #ef4444; color: #fff; }}
        .badge.pass {{ background: #10b981; color: #000; }}
        .badge.not_detected {{ background: #f59e0b; color: #000; }}
        .badge.not_applicable {{ background: #334155; color: #94a3b8; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Rantanplan AI Security Scanner Conformance Matrix</h1>
        <div class="grid">
            {"".join(metrics_html)}
        </div>
        <table>
            <thead>
                <tr>
                    <th>Case ID</th>
                    <th>Domain</th>
                    {"".join([f"<th>{s}</th>" for s in scanners])}
                </tr>
            </thead>
            <tbody>
                {"".join(rows_html)}
            </tbody>
        </table>
    </div>
</body>
</html>
"""

