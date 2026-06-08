"""Rich rendering of a promptproof :class:`~promptproof.models.Report`.

Produces a colour-coded per-category rollup table, a detailed per-attack table,
and a headline score panel. Green = the guard blocked the attack, red = the
attack got through.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from promptproof.models import Report

_GRADE_COLOR = {
    "A": "bold green",
    "B": "green",
    "C": "yellow",
    "D": "orange1",
    "F": "bold red",
}


def _score_style(score: float) -> str:
    if score >= 80.0:
        return "green"
    if score >= 50.0:
        return "yellow"
    return "red"


def category_table(report: Report) -> Table:
    """A per-category rollup table: blocked / total and a score bar."""
    table = Table(title="promptproof :: category rollup", title_style="bold")
    table.add_column("Category", style="cyan", no_wrap=True)
    table.add_column("Blocked", justify="right")
    table.add_column("Breached", justify="right")
    table.add_column("Score", justify="right")
    for cat, cs in report.by_category().items():
        breached_cell = (
            Text(str(cs.breached), style="red") if cs.breached else Text("0", style="green")
        )
        table.add_row(
            cat,
            f"{cs.blocked}/{cs.total}",
            breached_cell,
            Text(f"{cs.score:.0f}", style=_score_style(cs.score)),
        )
    return table


def detail_table(report: Report, *, only_breaches: bool = False) -> Table:
    """A per-attack table; pass ``only_breaches=True`` to show just the failures."""
    title = "breaches" if only_breaches else "all attacks"
    table = Table(title=f"promptproof :: {title}", title_style="bold")
    table.add_column("Attack", style="cyan", no_wrap=True)
    table.add_column("Category", style="magenta")
    table.add_column("Result", justify="center")
    table.add_column("Detectors", style="dim")

    rows = report.breaches() if only_breaches else report.results
    for r in rows:
        if only_breaches and r.passed:
            continue
        result_cell = (
            Text("BREACH", style="bold red") if r.succeeded else Text("blocked", style="green")
        )
        table.add_row(
            r.attack.id,
            r.attack.category,
            result_cell,
            ", ".join(r.detector_hits) or "-",
        )
    return table


def score_panel(report: Report) -> Panel:
    """The headline score panel summarising the whole run."""
    grade_style = _GRADE_COLOR.get(report.grade, "white")
    body = Text()
    body.append(f"{report.score:.0f}/100", style=f"bold {_score_style(report.score)}")
    body.append("   grade ", style="dim")
    body.append(report.grade, style=grade_style)
    body.append(
        f"\nblocked {report.blocked}/{report.total} attacks  ·  {report.breached} breaches",
        style="dim",
    )
    return Panel(
        body,
        title=f"[bold]{report.target_name}[/bold] robustness",
        border_style=_score_style(report.score),
        expand=False,
    )


def render(
    report: Report,
    *,
    console: Console | None = None,
    show_all: bool = False,
) -> None:
    """Print the full dashboard for ``report`` to ``console`` (or a fresh one)."""
    con = console or Console()
    con.print(score_panel(report))
    con.print(category_table(report))
    con.print(detail_table(report, only_breaches=not show_all))
