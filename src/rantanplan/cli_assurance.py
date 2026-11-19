"""
Assurance commands: test scanner, compare, mutate, hunt, minimize, gate, export, corpus, benchmark.

Registered onto the main Typer app by ``register``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from rantanplan.assurance import AssuranceReport, run_assurance
from rantanplan.corpus import load_corpus
from rantanplan.corpus_builder import MUTATION_DOMAINS, case_to_yaml, write_corpus
from rantanplan.models import RunProfile, TargetProfile, TestCase
from rantanplan.mutators import ALL_MUTATORS, case_rng, get_mutators
from rantanplan.oracle import MetamorphicOracle
from rantanplan.registry import resolve_target
from rantanplan.reporting.assurance_report import METRIC_LABELS, to_html, to_json, to_markdown
from rantanplan.scoring import GRADES
from rantanplan.search import SearchEngine

REFERENCE_TARGETS = ["mock-blind", "mock-paranoid", "mock-naive", "mock-strict"]
GRADE_ORDER = [g for _, g in GRADES] + ["F"]
DEFAULT_SEED = 42151


def _profile(seed: int, timeout: int = 30) -> RunProfile:
    return RunProfile(profile_type=TargetProfile.OFFLINE, seed=seed, timeout_seconds=timeout)


def _load(corpus: Path | None) -> list[TestCase]:
    return load_corpus(corpus) if corpus else load_corpus()


def _grade_rank(grade: str) -> int:
    return GRADE_ORDER.index(grade) if grade in GRADE_ORDER else len(GRADE_ORDER)


def _assess(target: str, corpus, seed: int, mutants: int, mutators: str | None, timeout: int) -> AssuranceReport:
    adapter = resolve_target(target)
    names = [m.strip() for m in mutators.split(",")] if mutators else None
    return run_assurance(adapter, _load(corpus), get_mutators(names), seed, mutants, _profile(seed, timeout))


def _print_summary(console: Console, reports: list[AssuranceReport]) -> None:
    table = Table(title=f"Rantanplan Scanner Assurance (seed {reports[0].seed})", border_style="cyan")
    table.add_column("Metric")
    for r in reports:
        table.add_column(r.target, justify="right")
    grade_row = []
    for r in reports:
        sc = r.scorecard
        score = "n/a" if sc.overall is None else f"{sc.overall:.2f}"
        grade_row.append(f"[bold]{sc.grade}[/bold] {score} ({sc.confidence})")
    table.add_row("[bold]Grade[/bold]", *grade_row)
    for key, label in METRIC_LABELS.items():
        cells = []
        for r in reports:
            mv = r.scorecard.metrics[key]
            cells.append("n/a" if mv.n == 0 or mv.value is None else f"{mv.value * 100:.0f}% (n={mv.n})")
        table.add_row(label, *cells)
    table.add_row("Evasions found", *[str(len(r.evasions)) for r in reports])
    table.add_row("Mutants rejected by oracle", *[str(sum(r.discarded.values())) for r in reports])
    table.add_row("Incomplete runs", *[str(r.scorecard.incomplete) for r in reports])
    console.print(table)


def _emit(console: Console, reports: list[AssuranceReport], fmt: str, output: Path | None) -> None:
    if fmt == "dashboard":
        _print_summary(console, reports)
        return
    renderers = {"json": to_json, "markdown": to_markdown, "html": to_html}
    if fmt not in renderers:
        raise typer.BadParameter(f"Unknown format '{fmt}' (dashboard, json, markdown, html)")
    text = renderers[fmt](reports)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
        console.print(f"[green]Report written to {output}[/green]")
    else:
        console.print(text, markup=False, highlight=False)


def register(app: typer.Typer, console: Console) -> None:
    test_app = typer.Typer(help="Assurance tests")
    export_app = typer.Typer(help="Export findings")
    corpus_app = typer.Typer(help="Corpus management")
    app.add_typer(test_app, name="test")
    app.add_typer(export_app, name="export")
    app.add_typer(corpus_app, name="corpus")

    @test_app.command("scanner")
    def test_scanner(
        target: str = typer.Option(..., help="Target name (see `rantanplan list scanners`)"),
        corpus: Path | None = typer.Option(None, help="Corpus directory (default: cases/ and corpus/)"),
        seed: int = typer.Option(DEFAULT_SEED, help="Seed for reproducible mutation"),
        mutants_per_case: int = typer.Option(3, help="Mutation attempts per case and mutator"),
        mutators: str | None = typer.Option(None, help="Comma-separated mutator names (default: all 8)"),
        fmt: str = typer.Option("dashboard", "--format", help="dashboard, json, markdown, html"),
        output: Path | None = typer.Option(None, help="Write the report to this file"),
        timeout: int = typer.Option(30, help="Per-run timeout in seconds"),
    ):
        """Score one scanner with oracle-approved metamorphic mutation."""
        report = _assess(target, corpus, seed, mutants_per_case, mutators, timeout)
        _emit(console, [report], fmt, output)

    @app.command()
    def compare(
        targets: str = typer.Option(",".join(REFERENCE_TARGETS), help="Comma-separated target names"),
        corpus: Path | None = typer.Option(None),
        seed: int = typer.Option(DEFAULT_SEED),
        mutants_per_case: int = typer.Option(3),
        fmt: str = typer.Option("dashboard", "--format"),
        output: Path | None = typer.Option(None),
    ):
        """Compare several targets side by side on the identical corpus and mutants."""
        reports = [_assess(t.strip(), corpus, seed, mutants_per_case, None, 30) for t in targets.split(",")]
        _emit(console, reports, fmt, output)

    @app.command()
    def mutate(
        case: str = typer.Option(..., help="Case id"),
        seed: int = typer.Option(DEFAULT_SEED),
        corpus: Path | None = typer.Option(None),
    ):
        """Show every mutant of one case together with the oracle's verdict."""
        cases = {c.id: c for c in _load(corpus)}
        if case not in cases:
            console.print(f"[red]Unknown case '{case}'[/red]")
            raise typer.Exit(2)
        parent, oracle = cases[case], MetamorphicOracle()
        table = Table(title=f"Mutants of {case} (seed {seed})")
        for col in ("Mutator", "Category", "Oracle", "Detail"):
            table.add_column(col)
        for m in ALL_MUTATORS:
            mutant = m.apply(parent, case_rng(seed, parent.id, m.name))
            if mutant is None:
                table.add_row(m.name, m.category, "[dim]n/a[/dim]", "not applicable to this case")
                continue
            v = oracle.check(parent, mutant)
            table.add_row(m.name, m.category, "[green]valid[/green]" if v.valid else "[red]rejected[/red]", "; ".join(v.reasons)[:90])
        console.print(table)

    @app.command()
    def hunt(
        target: str = typer.Option("mock-naive", help="Target name"),
        mode: str = typer.Option("false-negative", help="false-negative or false-positive"),
        iterations: int = typer.Option(50, help="Mutation search iterations per case"),
        case: str | None = typer.Option(None, help="Case id (default: every case with the matching label)"),
        seed: int = typer.Option(DEFAULT_SEED),
        corpus: Path | None = typer.Option(None),
    ):
        """Adaptive hunt for evasions (false negatives) or false positives using oracle-checked mutants."""
        if mode not in ("false-negative", "false-positive"):
            raise typer.BadParameter("mode must be false-negative or false-positive")
        want_malicious = mode == "false-negative"
        pool = [
            c for c in _load(corpus)
            if c.domain in MUTATION_DOMAINS and bool(c.ground_truth.get("malicious")) == want_malicious and (not case or c.id == case)
        ]
        if not pool:
            console.print("[red]No matching cases found[/red]")
            raise typer.Exit(2)
        engine = SearchEngine(resolve_target(target), seed=seed)
        profile = _profile(seed)
        total = 0
        for c in pool:
            found = (engine.hunt_false_negative if want_malicious else engine.hunt_false_positive)(c, profile, iterations)
            total += len(found)
            for mutant, _ in found[:1]:
                console.print(f"[yellow]{c.id}[/yellow]: {mutant.ground_truth['mutation']['mutator']} -> {mode}")
        console.print(f"[bold green]Hunt complete: {total} oracle-valid {mode} candidates across {len(pool)} cases (seed {seed}).[/bold green]")

    @app.command()
    def minimize(
        target: str = typer.Option("mock-naive"),
        case: str = typer.Option(..., help="Case id to minimize"),
        seed: int = typer.Option(DEFAULT_SEED),
        corpus: Path | None = typer.Option(None),
    ):
        """Delta-debug a case to a minimal reproducer that keeps the target's outcome and the label."""
        cases = {c.id: c for c in _load(corpus)}
        if case not in cases:
            console.print(f"[red]Unknown case '{case}'[/red]")
            raise typer.Exit(2)
        reduced = SearchEngine(resolve_target(target), seed=seed).minimize(cases[case], _profile(seed))
        before = sum(len(f["content"].splitlines()) for f in cases[case].files)
        after = sum(len(f["content"].splitlines()) for f in reduced.files)
        console.print(f"[bold green]Minimized {case}: {before} -> {after} lines, {len(reduced.files)} file(s).[/bold green]")
        for f in reduced.files:
            console.print(f"--- {f['path']}", markup=False)
            console.print(f["content"], markup=False)

    @app.command()
    def verify_ground_truth():
        """Validate every case's label against the independent reference semantics."""
        cases, oracle = load_corpus(), MetamorphicOracle()
        checked = [c for c in cases if c.domain in MUTATION_DOMAINS]
        bad = [(c.id, v.reasons[0]) for c in checked if not (v := oracle.label_consistent(c)).valid]
        console.print(f"Checked {len(checked)} of {len(cases)} cases (mutation domains); {len(cases) - len(checked)} outside reference-semantics scope.")
        for cid, reason in bad:
            console.print(f"[red]{cid}[/red]: {reason}")
        if bad:
            console.print(f"[bold red]{len(bad)} label inconsistencies.[/bold red]")
            raise typer.Exit(1)
        console.print(f"[bold green]Successfully verified {len(checked)} cases against ground-truth semantics.[/bold green]")

    @app.command()
    def gate(
        results: Path | None = typer.Option(None, help="JSON from `test scanner --format json`"),
        min_grade: str = typer.Option("B", help="Minimum acceptable grade"),
        allow_low_confidence: bool = typer.Option(False, help="Accept grades issued with low confidence"),
        min_coverage: float = typer.Option(0.0, help="Minimum ecosystem coverage percentage"),
    ):
        """CI gate: fail if the graded result is below ``--min-grade`` (or ecosystem coverage is too low)."""
        failed = False
        if results is not None:
            data = json.loads(results.read_text(encoding="utf-8"))
            targets = data.get("targets", [data])
            for t in targets:
                sc = t["scorecard"]
                grade, conf = sc["grade"], sc["confidence"]
                ok = grade in GRADE_ORDER and _grade_rank(grade) <= _grade_rank(min_grade)
                if conf != "sufficient" and not allow_low_confidence:
                    ok = False
                console.print(f"{'[green]PASS[/green]' if ok else '[red]FAIL[/red]'} {t['target']}: grade {grade}, confidence {conf} (required {min_grade})")
                failed |= not ok
        if min_coverage > 0 or results is None:
            from rantanplan.ecosystem import verify_ecosystem

            cov = verify_ecosystem()["coverage_percentage"]
            if cov < min_coverage:
                console.print(f"[bold red]CI Gate Failed: Coverage {cov}% < Minimum required {min_coverage}%[/bold red]")
                failed = True
            else:
                console.print(f"[bold green]CI Gate Passed: Coverage {cov}% >= Minimum required {min_coverage}%[/bold green]")
        if failed:
            sys.exit(1)

    @export_app.command("regression")
    def export_regression(
        target: str = typer.Option(...),
        output: Path = typer.Option(Path("regression_bundles")),
        seed: int = typer.Option(DEFAULT_SEED),
        mutants_per_case: int = typer.Option(3),
        corpus: Path | None = typer.Option(None),
    ):
        """Write every oracle-valid evasion found for TARGET as a standalone regression case."""
        report = _assess(target, corpus, seed, mutants_per_case, None, 30)
        output.mkdir(parents=True, exist_ok=True)
        for ev in report.evasions:
            safe = ev.case.id.replace("~", "--")
            (output / f"{target}--{safe}.yaml").write_text(case_to_yaml(ev.case), encoding="utf-8")
        console.print(f"[bold green]Exported {len(report.evasions)} regression case(s) to {output}[/bold green]")

    @corpus_app.command("build")
    def corpus_build(out: Path = typer.Option(Path("corpus"), help="Output directory")):
        """Regenerate the deterministic seed corpus (labels are verified against the reference semantics)."""
        console.print(f"[bold green]Wrote {write_corpus(out)} cases to {out}[/bold green]")

    @corpus_app.command("list")
    def corpus_list():
        """List corpus size per domain and label."""
        table = Table(title="Corpus")
        for col in ("Domain", "Malicious", "Benign"):
            table.add_column(col)
        stats: dict[str, list[int]] = {}
        for c in load_corpus():
            stats.setdefault(c.domain, [0, 0])[0 if c.ground_truth.get("malicious") else 1] += 1
        for d, (m, b) in sorted(stats.items()):
            table.add_row(d, str(m), str(b))
        console.print(table)

    @app.command()
    def benchmark(
        output: Path = typer.Option(Path("docs/REFERENCE_BENCHMARK.md"), help="Markdown report path"),
        seed: int = typer.Option(DEFAULT_SEED),
        mutants_per_case: int = typer.Option(3),
    ):
        """Score the built-in calibration targets and write the reference benchmark report."""
        reports = [_assess(t, None, seed, mutants_per_case, None, 30) for t in REFERENCE_TARGETS]
        _print_summary(console, reports)
        body = to_markdown(reports, "Rantanplan Reference Benchmark")
        preface = (
            "<!-- Generated by `rantanplan benchmark`; do not edit by hand. -->\n\n"
            "> **What this is:** calibration of the scoring scale on four built-in targets "
            "(`mock-blind`, `mock-paranoid`, `mock-naive`, `mock-strict`). It shows that the score "
            "orders targets sensibly and that mutation exposes weak detectors. "
            "**It is not a measurement of any real scanner.** `mock-strict` shares its definition of "
            "meaning with the oracle, so its A+ is a ceiling check, not an endorsement.\n\n"
        )
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(preface + body + "\n", encoding="utf-8")
        console.print(f"[green]Reference benchmark written to {output}[/green]")

    @app.command()
    def suite(name: str = typer.Argument("offline-core", help="offline-core (calibration targets, no external binaries)")):
        """Run a benchmark suite. ``offline-core`` scores the calibration targets and asserts the scale is sane."""
        if name != "offline-core":
            console.print(f"[yellow]Suite '{name}' needs external scanners; use `test scanner --target <name>` once installed.[/yellow]")
            raise typer.Exit(2)
        reports = {t: _assess(t, None, DEFAULT_SEED, 3, None, 30) for t in REFERENCE_TARGETS}
        _print_summary(console, list(reports.values()))
        scores = {t: r.scorecard.overall or 0.0 for t, r in reports.items()}
        ordered = scores["mock-blind"] <= scores["mock-naive"] <= scores["mock-strict"] and scores["mock-paranoid"] < scores["mock-strict"]
        if not ordered or reports["mock-strict"].scorecard.grade != "A+":
            console.print("[bold red]Calibration failed: scoring scale does not order the reference targets as expected.[/bold red]")
            raise typer.Exit(1)
        console.print("[bold green]Calibration passed: blind <= naive <= strict, paranoid < strict.[/bold green]")

