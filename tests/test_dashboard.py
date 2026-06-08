"""Tests for the rich dashboard rendering (smoke + content)."""

from __future__ import annotations

from rich.console import Console

from promptproof.dashboard import (
    category_table,
    detail_table,
    render,
    score_panel,
)
from promptproof.guards import strong_guard, weak_guard
from promptproof.harness import run


def _render_to_text(renderable: object) -> str:
    console = Console(record=True, width=120)
    console.print(renderable)
    return console.export_text()


def test_category_table_renders() -> None:
    report = run(strong_guard)
    text = _render_to_text(category_table(report))
    assert "category rollup" in text
    assert "instruction_override" in text


def test_detail_table_breaches_only() -> None:
    report = run(weak_guard)
    text = _render_to_text(detail_table(report, only_breaches=True))
    assert "BREACH" in text


def test_detail_table_show_all() -> None:
    report = run(strong_guard)
    text = _render_to_text(detail_table(report, only_breaches=False))
    assert "blocked" in text


def test_score_panel_shows_score() -> None:
    report = run(weak_guard)
    text = _render_to_text(score_panel(report))
    assert "/100" in text
    assert "weak_guard" in text


def test_render_full_dashboard_weak() -> None:
    report = run(weak_guard)
    console = Console(record=True, width=120)
    render(report, console=console, show_all=True)
    text = console.export_text()
    assert "robustness" in text
    assert "category rollup" in text


def test_render_full_dashboard_strong() -> None:
    report = run(strong_guard)
    console = Console(record=True, width=120)
    render(report, console=console)
    text = console.export_text()
    assert "strong_guard" in text
