"""Tests for the report scoring math and rollups."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from promptproof.models import Attack, AttackResult, CategoryScore, Report


def _result(attack_id: str, category: str, succeeded: bool) -> AttackResult:
    attack = Attack(id=attack_id, category=category, name=attack_id, template="x")
    return AttackResult(
        attack=attack,
        rendered_input="x",
        output="o",
        succeeded=succeeded,
        detector_hits=("compliance_marker",) if succeeded else (),
    )


def _report(*flags: tuple[str, str, bool]) -> Report:
    return Report(
        target_name="t",
        results=tuple(_result(i, c, s) for (i, c, s) in flags),
    )


def test_empty_report_scores_100() -> None:
    report = Report(target_name="t", results=())
    assert report.score == 100.0
    assert report.total == 0
    assert report.grade == "A"


def test_all_blocked_scores_100() -> None:
    report = _report(("a", "x", False), ("b", "x", False))
    assert report.score == 100.0
    assert report.blocked == 2
    assert report.breached == 0


def test_all_breached_scores_0() -> None:
    report = _report(("a", "x", True), ("b", "x", True))
    assert report.score == 0.0
    assert report.blocked == 0
    assert report.breached == 2


def test_half_blocked_scores_50() -> None:
    report = _report(("a", "x", False), ("b", "x", True))
    assert report.score == 50.0


def test_score_rounding() -> None:
    report = _report(("a", "x", False), ("b", "x", True), ("c", "x", True))
    assert report.score == 33.3


@pytest.mark.parametrize(
    ("blocked", "total", "grade"),
    [
        (100, 100, "A"),
        (95, 100, "A"),
        (90, 100, "B"),
        (80, 100, "B"),
        (70, 100, "C"),
        (60, 100, "C"),
        (50, 100, "D"),
        (40, 100, "D"),
        (10, 100, "F"),
    ],
)
def test_grade_thresholds(blocked: int, total: int, grade: str) -> None:
    flags = [(f"b{i}", "x", i >= blocked) for i in range(total)]
    report = _report(*flags)
    assert report.grade == grade


def test_by_category_rollup() -> None:
    report = _report(
        ("a", "cat1", False),
        ("b", "cat1", True),
        ("c", "cat2", False),
    )
    rollup = report.by_category()
    assert set(rollup) == {"cat1", "cat2"}
    assert rollup["cat1"].total == 2
    assert rollup["cat1"].blocked == 1
    assert rollup["cat1"].score == 50.0
    assert rollup["cat2"].score == 100.0


def test_by_category_sorted() -> None:
    report = _report(("a", "zzz", False), ("b", "aaa", False))
    assert list(report.by_category()) == ["aaa", "zzz"]


def test_category_score_breached() -> None:
    cs = CategoryScore(category="x", total=5, blocked=2)
    assert cs.breached == 3
    assert cs.score == 40.0


def test_category_score_empty() -> None:
    cs = CategoryScore(category="x", total=0, blocked=0)
    assert cs.score == 100.0


def test_breaches_sorted_by_id() -> None:
    report = _report(("z", "x", True), ("a", "x", True), ("m", "x", False))
    breach_ids = [r.attack.id for r in report.breaches()]
    assert breach_ids == ["a", "z"]


def test_result_passed_property() -> None:
    assert _result("a", "x", False).passed is True
    assert _result("a", "x", True).passed is False


def test_summary_string() -> None:
    report = _report(("a", "x", False), ("b", "x", True))
    summary = report.summary()
    assert "1/2" in summary
    assert "50.0" in summary


def test_report_is_frozen() -> None:
    report = _report(("a", "x", False))
    with pytest.raises(ValidationError):
        report.target_name = "changed"  # type: ignore[misc]
