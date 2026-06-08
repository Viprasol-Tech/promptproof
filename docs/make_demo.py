"""Render the ``promptproof demo`` visual to an SVG for the README hero.

This reuses the real library: it builds the same weak-vs-strong :class:`Report`
objects the ``promptproof demo`` command builds, then calls the same
:func:`promptproof.dashboard.render` function with a recording ``rich`` console
and exports the result to ``docs/assets/demo.svg``.

Run it from the repo root with::

    PYTHONPATH=src python docs/make_demo.py
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console

from promptproof.dashboard import category_table, score_panel
from promptproof.guards import strong_guard, weak_guard
from promptproof.harness import run
from promptproof.models import Report

_OUT = Path(__file__).resolve().parent / "assets" / "demo.svg"


def _rollup(console: Console, report: Report) -> None:
    """Render the primary visual for one report: score panel + category rollup."""
    console.print(score_panel(report))
    console.print(category_table(report))


def main() -> None:
    """Build the demo reports and save the rendered dashboard as an SVG."""
    console = Console(record=True, width=100)

    console.print("[bold]promptproof demo[/bold] — a deliberately weak guard vs a hardened one\n")

    weak_report = run(weak_guard, target_name="weak_guard")
    strong_report = run(strong_guard, target_name="strong_guard")

    _rollup(console, weak_report)
    console.print()
    _rollup(console, strong_report)
    console.print()
    console.print(
        f"[bold]weak_guard[/bold] scored "
        f"[red]{weak_report.score:.0f}/100[/red]  vs  "
        f"[bold]strong_guard[/bold] "
        f"[green]{strong_report.score:.0f}/100[/green]"
    )

    _OUT.parent.mkdir(parents=True, exist_ok=True)
    console.save_svg(str(_OUT), title="promptproof")
    print(f"wrote {_OUT} ({_OUT.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
