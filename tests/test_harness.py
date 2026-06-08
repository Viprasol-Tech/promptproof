"""Tests for the harness and the core value proposition."""

from __future__ import annotations

from promptproof.attacks import ATTACK_LIBRARY, attacks_by_category
from promptproof.guards import DEMO_CANARY, strong_guard, weak_guard
from promptproof.harness import run
from promptproof.models import Report


def test_run_returns_report() -> None:
    report = run(strong_guard)
    assert isinstance(report, Report)
    assert report.total == len(ATTACK_LIBRARY)


def test_weak_guard_scores_low() -> None:
    report = run(weak_guard)
    assert report.score < 40.0
    assert report.breached > report.blocked


def test_strong_guard_scores_high() -> None:
    report = run(strong_guard)
    assert report.score >= 90.0


def test_strong_beats_weak() -> None:
    weak = run(weak_guard)
    strong = run(strong_guard)
    assert strong.score > weak.score + 50.0


def test_weak_guard_leaks_caught() -> None:
    report = run(weak_guard)
    leaked = [r for r in report.results if "canary_leak" in r.detector_hits]
    assert leaked, "weak guard should leak the canary on at least one attack"


def test_target_name_defaults_to_callable() -> None:
    report = run(weak_guard)
    assert report.target_name == "weak_guard"


def test_target_name_override() -> None:
    report = run(weak_guard, target_name="my_app")
    assert report.target_name == "my_app"


def test_custom_canary_used() -> None:
    seen: list[str] = []

    def spy(text: str) -> str:
        seen.append(text)
        return "I can't help with that."

    run(spy, canary="ZZZ-CANARY")
    canary_inputs = [s for s in seen if "ZZZ-CANARY" in s]
    assert canary_inputs


def test_subset_of_attacks() -> None:
    subset = attacks_by_category()["instruction_override"]
    report = run(strong_guard, attacks=subset)
    assert report.total == len(subset)


def test_harness_swallows_target_exceptions() -> None:
    def crasher(text: str) -> str:
        raise RuntimeError("boom")

    report = run(crasher)
    assert report.total == len(ATTACK_LIBRARY)
    assert all("raised RuntimeError" in r.output for r in report.results)


def test_all_results_have_matching_attack() -> None:
    report = run(strong_guard)
    ids_in = {a.id for a in ATTACK_LIBRARY}
    ids_out = {r.attack.id for r in report.results}
    assert ids_in == ids_out


def test_demo_canary_is_default() -> None:
    # The default canary must match what the weak guard leaks, or leaks go
    # undetected.
    report = run(weak_guard)
    assert any(DEMO_CANARY in r.output for r in report.results)


def test_custom_detectors_passed_through() -> None:
    report = run(strong_guard, detectors=[])
    # With no detectors, nothing can be a breach.
    assert report.breached == 0
    assert report.score == 100.0
