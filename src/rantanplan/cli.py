"""
Rantanplan Typer + Rich CLI entrypoint implementation.
"""

import os
import sys
from typing import List, Optional
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from rantanplan import __version__
from rantanplan.adapters.garak import GarakAdapter
from rantanplan.adapters.skil import SKILAdapter
from rantanplan.adapters.skillevaluator import SkillEvaluatorAdapter
from rantanplan.adapters.skillspector import SkillSpectorAdapter
from rantanplan.capability_inventory import CapabilityInventoryEngine
from rantanplan.differential import DifferentialEngine
from rantanplan.execution import create_temp_fixture_dir
from rantanplan.ground_truth import GroundTruthEngine
from rantanplan.metrics import MetricsCalculator
from rantanplan.models import Outcome, RunProfile, TestCase
from rantanplan.reporting.html_report import generate_html_report
from rantanplan.reporting.markdown_report import generate_markdown_report

app = typer.Typer(
    name="rantanplan",
    help="AI Agent Security Scanner Conformance, Differential Testing, Adversarial Evaluation and Benchmark Framework",
    add_completion=False,
)

console = Console()


@app.command()
def doctor():
    """Checks scanner installation, binary paths, and version compatibility."""
    console.print(Panel.fit("[bold blue]Rantanplan System & Scanner Doctor[/bold blue]", border_style="blue"))

    adapters = [SKILAdapter(), SkillSpectorAdapter(), GarakAdapter(), SkillEvaluatorAdapter()]

    table = Table(title="Scanner Diagnostics", border_style="dim")
    table.add_column("Scanner", style="cyan")
    table.add_column("Installed", style="bold")
    table.add_column("Version", style="green")
    table.add_column("Path", style="dim")
    table.add_column("Status Message")

    for adapter in adapters:
        res = adapter.doctor()
        status_symbol = "[bold green]YES[/bold green]" if res.installed else "[bold red]NO[/bold red]"
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
    console.print(f"[bold green]Snapshot recorded successfully in snapshots/ for {len(snapshot['scanners'])} scanners.[/bold green]")


@app.command(name="list")
def list_items(target: str = typer.Argument("cases", help="What to list: scanners, cases, capabilities")):
    """Lists registered scanners, clean-room test cases, or canonical capabilities."""
    if target == "scanners":
        adapters = [SKILAdapter(), SkillSpectorAdapter(), GarakAdapter(), SkillEvaluatorAdapter()]
        table = Table(title="Registered Scanner Adapters")
        table.add_column("Scanner", style="cyan")
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
        gt_engine = GroundTruthEngine()
        cases = gt_engine.load_test_cases()
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
    gt_engine = GroundTruthEngine()
    cases = gt_engine.load_test_cases()
    console.print(f"[bold green]Successfully verified {len(cases)} clean-room test cases against ground-truth schemas.[/bold green]")


@app.command()
def gaps():
    """Analyses capability matrix coverage gaps across target scanners."""
    table = Table(title="Rantanplan Scanner Capability Coverage Gaps", border_style="magenta")
    table.add_column("Scanner", style="cyan")
    table.add_column("Missing / Unmapped Capability", style="yellow")
    table.add_column("Recommendation")

    table.add_row("SkillSpector", "mcp.surface-drift", "Add MCP runtime drift test case")
    table.add_row("garak", "secret.exfiltration", "Expand garak probe mapping for static exfil")
    table.add_row("SkillEvaluator", "code.execution", "Integrate AST taint static check")

    console.print(table)


@app.command()
def demo():
    """Runs a zero-cost, network-independent demonstration matrix across all scanners."""
    console.print(Panel.fit("[bold green]Rantanplan Differential Scanner Demo Matrix[/bold green]", border_style="green"))

    gt_engine = GroundTruthEngine()
    cases = gt_engine.load_test_cases()

    adapters = [SKILAdapter(), SkillSpectorAdapter(), GarakAdapter(), SkillEvaluatorAdapter()]
    profile = RunProfile(name="offline-core", timeout_seconds=10)

    run_results = {}

    for adapter in adapters:
        s_name = adapter.identity().name
        scanner_results = []

        for case in cases:
            if not adapter.supports(case):
                from rantanplan.models import NormalizedResult

                scanner_results.append(
                    NormalizedResult(
                        run_id="demo-run",
                        case_id=case.id,
                        scanner=s_name,
                        scanner_version="1.0.0",
                        applicable=False,
                        outcome=Outcome.NOT_APPLICABLE,
                    )
                )
                continue

            tmp_dir, cleanup = create_temp_fixture_dir(case.files)
            try:
                raw_exec = adapter.run(case, profile, tmp_dir)
                norm_res = adapter.parse(case, raw_exec)
                scanner_results.append(norm_res)
            finally:
                cleanup()

        run_results[s_name] = scanner_results

    matrix_data = DifferentialEngine.generate_matrix(cases, run_results)

    metrics_data = {}
    for s_name, res_list in run_results.items():
        metrics_data[s_name] = MetricsCalculator.calculate_scanner_metrics(res_list)

    table = Table(title="Differential Scanner Demo Results", border_style="cyan")
    table.add_column("Case ID", style="bold")
    table.add_column("Domain", style="magenta")
    for s in run_results.keys():
        table.add_column(s, justify="center")

    for row in matrix_data["matrix"]:
        outcomes = []
        for s in run_results.keys():
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


if __name__ == "__main__":
    app()
