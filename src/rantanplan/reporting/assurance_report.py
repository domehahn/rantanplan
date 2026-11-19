"""
Renderers for assurance reports (JSON, Markdown, standalone HTML). All dynamic text is escaped.
"""

from __future__ import annotations

import html
import json

from rantanplan.assurance import AssuranceReport

METRIC_LABELS = {
    "recall": "Recall (attacks detected)",
    "specificity": "Specificity (benign passed)",
    "semantic_robustness": "Semantic robustness",
    "structural_robustness": "Structural robustness",
    "cross_file_robustness": "Cross-file robustness",
    "obfuscation_robustness": "Obfuscation robustness",
    "negative_context_safety": "Negative-context safety",
}


def _fmt(mv) -> str:
    if mv.n == 0 or mv.value is None:
        return "n/a"
    return f"{mv.value * 100:.1f}% (n={mv.n}, 95% CI {mv.ci_low * 100:.0f}-{mv.ci_high * 100:.0f}%)"


def to_json(reports: list[AssuranceReport]) -> str:
    payload = reports[0].to_dict() if len(reports) == 1 else {"targets": [r.to_dict() for r in reports]}
    return json.dumps(payload, indent=2, ensure_ascii=False)


def to_markdown(reports: list[AssuranceReport], title: str = "Rantanplan Assurance Report") -> str:
    lines = [f"# {title}", ""]
    r0 = reports[0]
    lines += [f"Seed: `{r0.seed}`. Every mutant counted below was approved by the metamorphic oracle.", ""]
    lines += ["| Target | Grade | Score | Confidence | Evasions found | Mutants discarded by oracle |", "| :--- | :---: | :---: | :---: | :---: | :---: |"]
    for r in reports:
        sc = r.scorecard
        score = "n/a" if sc.overall is None else f"{sc.overall:.2f}"
        lines.append(f"| `{r.target}` | **{sc.grade}** | {score} | {sc.confidence} | {len(r.evasions)} | {sum(r.discarded.values())} |")
    lines.append("")
    lines += ["## Metrics", "", "| Metric | " + " | ".join(f"`{r.target}`" for r in reports) + " |", "| :--- |" + " :---: |" * len(reports)]
    for key, label in METRIC_LABELS.items():
        lines.append(f"| {label} | " + " | ".join(_fmt(r.scorecard.metrics[key]) for r in reports) + " |")
    lines.append("")
    for r in reports:
        if r.scorecard.notes:
            lines += [f"**`{r.target}` notes:**", *[f"- {n}" for n in r.scorecard.notes], ""]
    return "\n".join(lines)


def to_html(reports: list[AssuranceReport], title: str = "Rantanplan Assurance Report") -> str:
    e = html.escape
    head = "".join(f"<th>{e(r.target)}</th>" for r in reports)
    grades = "".join(
        f"<td><span class='grade'>{e(r.scorecard.grade)}</span> "
        f"{'' if r.scorecard.overall is None else f'{r.scorecard.overall:.2f}'}"
        f"<div class='sub'>confidence: {e(r.scorecard.confidence)}</div></td>"
        for r in reports
    )
    rows = "".join(
        f"<tr><td>{e(label)}</td>" + "".join(f"<td>{e(_fmt(r.scorecard.metrics[key]))}</td>" for r in reports) + "</tr>"
        for key, label in METRIC_LABELS.items()
    )
    evasion_rows = "".join(
        f"<tr><td>{e(r.target)}</td><td><code>{e(ev.parent_id)}</code></td><td>{e(ev.mutator)}</td><td>{e(ev.category)}</td></tr>"
        for r in reports
        for ev in r.evasions[:50]
    )
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>{e(title)}</title>
<style>
body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#0f172a;color:#f8fafc;margin:0;padding:2rem}}
main{{max-width:1100px;margin:auto}} table{{width:100%;border-collapse:collapse;background:#1e293b;margin-bottom:2rem}}
th,td{{padding:.6rem 1rem;border-bottom:1px solid #334155;text-align:left;font-size:.9rem}} th{{background:#0f172a;color:#94a3b8}}
.grade{{font-size:1.6rem;font-weight:700;color:#38bdf8}} .sub{{color:#64748b;font-size:.75rem}}
</style></head><body><main>
<h1>{e(title)}</h1><p>Seed {e(str(reports[0].seed))}. Only oracle-approved mutants are scored.</p>
<table><thead><tr><th></th>{head}</tr></thead><tbody><tr><td>Grade</td>{grades}</tr>{rows}</tbody></table>
<h2>Evasions (first 50 per target)</h2>
<table><thead><tr><th>Target</th><th>Parent case</th><th>Mutator</th><th>Category</th></tr></thead><tbody>{evasion_rows}</tbody></table>
</main></body></html>
"""
