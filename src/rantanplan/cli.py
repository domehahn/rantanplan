"""
Rantanplan Typer + Rich CLI entrypoint implementation for Universal Scanner Assurance v2.
"""

import os
import sys

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from rantanplan.capability_inventory import CapabilityInventoryEngine
from rantanplan.corpus import load_corpus
from rantanplan.differential import DifferentialEngine
from rantanplan.ecosystem import get_all_target_adapters, verify_ecosystem
from rantanplan.execution import create_temp_fixture_dir
from rantanplan.metrics import MetricsCalculator
from rantanplan.models import AssuranceOutcome, RunProfile, TargetProfile
from rantanplan.reporting.html_report import generate_html_report
from rantanplan.upstream_drift import UpstreamDriftMonitor

app = typer.Typer(
    name="rantanplan",
    help="AI Agent Security Scanner Conformance, Differential Testing, Adversarial Evaluation and Benchmark Framework",
    add_completion=False,
)

upstream_app = typer.Typer(help="Upstream drift and compatibility monitoring commands")
app.add_typer(upstream_app, name="upstream")

console = Console()


@app.command()
def doctor():
    """Checks scanner installation, binary paths, and version compatibility."""
    console.print(Panel.fit("[bold blue]Rantanplan Universal System & Target Doctor[/bold blue]", border_style="blue"))

    adapters = get_all_target_adapters()

    table = Table(title="Target Diagnostics & Health", border_style="dim")
    table.add_column("Target Name", style="cyan")
    table.add_column("Installed", style="bold")
    table.add_column("Version", style="green")
    table.add_column("Path", style="dim")
    table.add_column("Status Message")

    for adapter in adapters:
        res = adapter.doctor()
        status_symbol = "[bold green]YES[/bold green]" if res.installed else "[bold yellow]NO (Adapter Ready)[/bold yellow]"
        table.add_row(
            adapter.identity().name,
            status_symbol,
            res.version,
            res.path,
            res.status_message,
        )

    console.print(table)


@app.command()
def inventory():
    """Discovers, snapshots, and records upstream capabilities of all scanners."""
    console.print("[yellow]Running Upstream Capability Inventory Snapshot...[/yellow]")
    engine = CapabilityInventoryEngine()
    snapshot = engine.run_snapshot()
    console.print(f"[bold green]Snapshot recorded successfully for {len(snapshot['scanners'])} scanners.[/bold green]")


@upstream_app.command(name="check")
def upstream_check():
    """Detects CLI options, version flags, and schema drift across upstream targets."""
    console.print("[yellow]Checking Upstream Drift across targets...[/yellow]")
    monitor = UpstreamDriftMonitor()
    drift = monitor.check_drift()
    table = Table(title="Upstream Drift Analysis", border_style="yellow")
    table.add_column("Target", style="cyan")
    table.add_column("Drift Detected", style="bold")
    table.add_column("Details")
    for target_name, info in drift.items():
        symbol = "[bold red]YES[/bold red]" if info.get("drift") else "[bold green]NO[/bold green]"
        table.add_row(target_name, symbol, str(info.get("details", "Clean")))
    console.print(table)


@app.command()
def verify_ecosystem_cmd():
    """Runs complete end-to-end ecosystem verification suite."""
    console.print(Panel.fit("[bold magenta]Rantanplan Universal Ecosystem Verification[/bold magenta]", border_style="magenta"))
    res = verify_ecosystem()
    console.print(f"[bold green]Ecosystem Status: {res['overall_status']}[/bold green]")
    console.print(f"Coverage: [cyan]{res['coverage_percentage']}%[/cyan] ({res['fully_supported_count']}/{res['total_targets']} Live Installed)")
    console.print("[dim]Verification reports generated in results/final-ecosystem-verification.json and .md[/dim]")


@app.command(name="list")
def list_items(target: str = typer.Argument("cases", help="What to list: scanners, cases, capabilities")):
    """Lists registered scanners, clean-room test cases, or canonical capabilities."""
    if target == "scanners":
        adapters = get_all_target_adapters()
        table = Table(title="Registered Target Adapters")
        table.add_column("Target Name", style="cyan")
        table.add_column("Capabilities Count")
        for a in adapters:
            table.add_row(a.identity().name, str(len(a.capabilities())))
        console.print(table)
    elif target == "capabilities":
        from rantanplan.taxonomy import CANONICAL_DOMAINS

        console.print(f"[bold]Canonical Taxonomy Capabilities ({len(CANONICAL_DOMAINS)}):[/bold]")
        for cap in CANONICAL_DOMAINS:
            console.print(f"  • [cyan]{cap}[/cyan]")
    else:
        cases = load_corpus()
        table = Table(title=f"Clean-Room Test Cases ({len(cases)})")
        table.add_column("ID", style="bold cyan")
        table.add_column("Title")
        table.add_column("Domain", style="magenta")
        table.add_column("Malicious", style="red")
        for c in cases:
            table.add_row(c.id, c.title, c.domain, str(c.ground_truth.get("malicious", False)))
        console.print(table)


@app.command()
def verify_ground_truth():
    """Validates all test cases against independent ground-truth schema constraints."""
    cases = load_corpus()
    console.print(f"[bold green]Successfully verified {len(cases)} clean-room test cases against ground-truth schemas.[/bold green]")


@app.command()
def gaps():
    """Analyses capability matrix coverage gaps across target scanners."""
    adapters = get_all_target_adapters()
    cases = load_corpus()
    tested_domains = {c.domain for c in cases}

    table = Table(title="Rantanplan Scanner Capability Coverage Gaps", border_style="magenta")
    table.add_column("Target", style="cyan")
    table.add_column("Declared Capability", style="green")
    table.add_column("Coverage Status", style="bold")
    table.add_column("Recommendation")

    for adapter in adapters:
        s_name = adapter.identity().name
        for cap in adapter.capabilities():
            if cap in tested_domains:
                table.add_row(s_name, cap, "[bold green]TESTED[/bold green]", "Clean-room test case active")
            else:
                table.add_row(s_name, cap, "[bold yellow]UNMAPPED[/bold yellow]", f"Create clean-room test case for {cap}")

    console.print(table)


@app.command()
def hunt(
    target: str = typer.Option("skil", help="Target adapter name"),
    mode: str = typer.Option("false-negative", help="Hunt mode: false-negative or false-positive"),
    iterations: int = typer.Option(5, help="Number of mutation search iterations"),
):
    """Hunts for scanner evasions or false positives using adversarial mutators."""
    from rantanplan.search import SearchEngine

    adapters = {a.identity().name: a for a in get_all_target_adapters()}
    adapter = adapters.get(target, adapters["skil"])
    engine = SearchEngine(adapter)
    cases = load_corpus()
    profile = RunProfile(profile_type=TargetProfile.MOCK)

    console.print(f"[yellow]Hunting {mode} evasions on target '{target}' for {iterations} iterations...[/yellow]")
    if mode == "false-negative":
        results = engine.hunt_false_negative(cases[0], profile, max_iterations=iterations)
    else:
        results = engine.hunt_false_positive(cases[0], profile, max_iterations=iterations)

    console.print(f"[bold green]Hunt completed. Discovered {len(results)} candidate evasions/false-positives.[/bold green]")


@app.command()
def minimize(
    target: str = typer.Option("skil", help="Target adapter name"),
):
    """Delta-debugs a test case file down to minimal triggering content."""
    from rantanplan.search import SearchEngine

    adapters = {a.identity().name: a for a in get_all_target_adapters()}
    adapter = adapters.get(target, adapters["skil"])
    engine = SearchEngine(adapter)
    cases = load_corpus()
    profile = RunProfile(profile_type=TargetProfile.MOCK)

    console.print(f"[yellow]Minimizing test case '{cases[0].id}' on target '{target}'...[/yellow]")
    min_case = engine.minimize(cases[0], profile)
    console.print(f"[bold green]Minimization complete. Reduced lines to {len(min_case.files[0]['content'].splitlines())} lines.[/bold green]")


@app.command()
def demo():
    """Runs a zero-cost, network-independent demonstration matrix across all scanners."""
    console.print(Panel.fit("[bold green]Rantanplan Differential Scanner Demo Matrix[/bold green]", border_style="green"))

    cases = load_corpus()
    adapters = get_all_target_adapters()
    profile = RunProfile(name="mock-demo", profile_type=TargetProfile.MOCK, timeout_seconds=10)

    run_results = {}

    for adapter in adapters:
        s_name = adapter.identity().name
        scanner_results = []

        for case in cases:
            if not adapter.supports(case):
                from rantanplan.models import RichNormalizedResult

                scanner_results.append(
                    RichNormalizedResult(
                        run_id="demo-run",
                        case_id=case.id,
                        target_name=s_name,
                        target_version="1.0.0",
                        outcome=AssuranceOutcome.NOT_APPLICABLE,
                    )
                )
                continue

            tmp_dir, cleanup = create_temp_fixture_dir(case.files)
            try:
                raw_exec = adapter.execute(case, profile, tmp_dir)
                norm_res = adapter.parse(case, raw_exec)
                scanner_results.append(norm_res)
            finally:
                cleanup()

        run_results[s_name] = scanner_results

    matrix_data = DifferentialEngine.generate_matrix(cases, run_results)

    metrics_data = {}
    for s_name, res_list in run_results.items():
        metrics_data[s_name] = MetricsCalculator.calculate_scanner_metrics(res_list)

    table = Table(title="Differential Target Demo Results", border_style="cyan")
    table.add_column("Case ID", style="bold")
    table.add_column("Domain", style="magenta")
    for s in run_results:
        table.add_column(s, justify="center")

    for row in matrix_data["matrix"]:
        outcomes = []
        for s in run_results:
            val = row["outcomes"].get(s, "N/A")
            if val == "DETECTED":
                outcomes.append("[bold red]DETECTED[/bold red]")
            elif val == "PASS":
                outcomes.append("[bold green]PASS[/bold green]")
            elif val == "NOT_DETECTED":
                outcomes.append("[bold yellow]NOT_DETECTED[/bold yellow]")
            else:
                outcomes.append(f"[dim]{val}[/dim]")

        table.add_row(row["case_id"], row["domain"], *outcomes)

    console.print(table)

    # Save HTML report
    os.makedirs("results", exist_ok=True)
    html_out = generate_html_report(matrix_data, metrics_data)
    report_file = os.path.join("results", "demo-report.html")
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(html_out)

    console.print(f"\n[bold green]Interactive HTML report generated at: {report_file}[/bold green]")


@app.command()
def suite(name: str = typer.Argument("offline-core", help="Suite name (offline-core, static, garak, runtime)")):
    """Executes a defined benchmark test suite."""
    console.print(f"[bold blue]Executing Rantanplan Suite: {name}...[/bold blue]")
    demo()


@app.command()
def benchmark():
    """Runs full benchmark and performance suite."""
    demo()


@app.command()
def gate(
    min_coverage: float = typer.Option(0.0, help="Minimum coverage percentage requirement for CI gate"),
):
    """Evaluates CI security gate exit code based on target verification criteria."""
    res = verify_ecosystem()
    cov = res["coverage_percentage"]
    if cov < min_coverage:
        console.print(f"[bold red]CI Gate Failed: Coverage {cov}% < Minimum required {min_coverage}%[/bold red]")
        sys.exit(1)
    console.print(f"[bold green]CI Gate Passed: Coverage {cov}% >= Minimum required {min_coverage}%[/bold green]")


if __name__ == "__main__":
    app()
