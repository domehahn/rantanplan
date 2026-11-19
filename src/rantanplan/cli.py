"""
Rantanplan Typer + Rich CLI entrypoint implementation for Universal Scanner Assurance v2.
"""

import os

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from rantanplan.capability_inventory import CapabilityInventoryEngine
from rantanplan.cli_assurance import register as register_assurance
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
    help="Oracle-gated metamorphic testing that scores how easily AI agent security scanners can be fooled",
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
        from rantanplan.registry import all_targets

        adapters = list(all_targets().values())
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


register_assurance(app, console)


if __name__ == "__main__":
    app()
