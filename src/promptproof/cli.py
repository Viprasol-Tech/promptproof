"""The promptproof command-line interface (Typer)."""

from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from promptproof import __version__
from promptproof.attacks import ATTACK_LIBRARY, attacks_by_category
from promptproof.dashboard import render
from promptproof.guards import make_canary, strong_guard, weak_guard
from promptproof.harness import run
from promptproof.loader import load_target

app = typer.Typer(
    name="promptproof",
    help="Offline prompt-injection red-team test suite for LLM apps.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


@app.command()
def version() -> None:
    """Print the installed promptproof version."""
    console.print(f"promptproof {__version__}")


@app.command(name="attacks")
def list_attacks(
    category: Optional[str] = typer.Option(  # noqa: UP045 - typer needs Optional
        None, "--category", "-c", help="Only show attacks in this category."
    ),
) -> None:
    """List the attack library, optionally filtered by ``--category``."""
    grouped = attacks_by_category()
    if category is not None and category not in grouped:
        console.print(f"[red]unknown category:[/red] {category}")
        console.print("known categories: " + ", ".join(sorted(grouped)))
        raise typer.Exit(code=1)

    table = Table(title="promptproof :: attack library", title_style="bold")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Category", style="magenta")
    table.add_column("Name", style="bold")
    table.add_column("Canary", justify="center")
    table.add_column("Description", style="dim")

    selected = (
        ATTACK_LIBRARY
        if category is None
        else tuple(a for a in ATTACK_LIBRARY if a.category == category)
    )
    for attack in selected:
        table.add_row(
            attack.id,
            attack.category,
            attack.name,
            "yes" if attack.uses_canary else "-",
            attack.description,
        )
    console.print(table)
    console.print(f"[dim]{len(selected)} attacks[/dim]")


@app.command(name="run")
def run_cmd(
    module: str = typer.Option(
        ...,
        "--module",
        "-m",
        help="Import string for your target callable, e.g. 'mypkg.guard:handle'.",
    ),
    category: Optional[str] = typer.Option(  # noqa: UP045 - typer needs Optional
        None, "--category", "-c", help="Restrict to one attack category."
    ),
    canary: Optional[str] = typer.Option(  # noqa: UP045 - typer needs Optional
        None, "--canary", help="Secret canary to substitute (defaults to a fixed token)."
    ),
    show_all: bool = typer.Option(False, "--all", help="Show every attack, not just the breaches."),
) -> None:
    """Run the attack suite against a target loaded from an import string."""
    try:
        target = load_target(module)
    except (ValueError, ImportError, AttributeError) as exc:
        console.print(f"[red]could not load target:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    attacks = (
        ATTACK_LIBRARY
        if category is None
        else tuple(a for a in ATTACK_LIBRARY if a.category == category)
    )
    if not attacks:
        console.print(f"[red]no attacks in category:[/red] {category}")
        raise typer.Exit(code=1)

    if canary is not None:
        report = run(target, attacks=attacks, canary=canary)
    else:
        report = run(target, attacks=attacks)
    render(report, console=console, show_all=show_all)

    # Non-zero exit when anything got through, so this is CI-friendly.
    if report.breached:
        raise typer.Exit(code=1)


@app.command()
def demo() -> None:
    """Run the weak and strong reference guards side by side."""
    canary = make_canary()
    console.print("[bold]promptproof demo[/bold] — a deliberately weak guard vs a hardened one\n")

    weak_report = run(weak_guard, target_name="weak_guard")
    strong_report = run(strong_guard, target_name="strong_guard")

    render(weak_report, console=console, show_all=False)
    console.print()
    render(strong_report, console=console, show_all=False)
    console.print()
    console.print(f"[dim]demo canary token: {canary}[/dim]")
    console.print(
        f"[bold]weak_guard[/bold] scored "
        f"[red]{weak_report.score:.0f}/100[/red]  vs  "
        f"[bold]strong_guard[/bold] "
        f"[green]{strong_report.score:.0f}/100[/green]"
    )


if __name__ == "__main__":  # pragma: no cover
    app()
