"""CLI smoke tests via typer's CliRunner."""

from __future__ import annotations

from typer.testing import CliRunner

from promptproof import __version__
from promptproof.cli import app

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_attacks_lists_all() -> None:
    result = runner.invoke(app, ["attacks"])
    assert result.exit_code == 0
    assert "attack library" in result.stdout
    assert "io-01" in result.stdout


def test_attacks_filtered_by_category() -> None:
    result = runner.invoke(app, ["attacks", "--category", "roleplay_jailbreak"])
    assert result.exit_code == 0
    assert "rp-01" in result.stdout


def test_attacks_unknown_category() -> None:
    result = runner.invoke(app, ["attacks", "--category", "nope"])
    assert result.exit_code == 1
    assert "unknown category" in result.stdout


def test_demo_runs() -> None:
    result = runner.invoke(app, ["demo"])
    assert result.exit_code == 0
    assert "weak_guard" in result.stdout
    assert "strong_guard" in result.stdout


def test_run_against_strong_guard_passes() -> None:
    result = runner.invoke(app, ["run", "--module", "promptproof.guards:strong_guard"])
    # strong guard blocks everything -> exit 0
    assert result.exit_code == 0
    assert "robustness" in result.stdout


def test_run_against_weak_guard_fails() -> None:
    result = runner.invoke(app, ["run", "--module", "promptproof.guards:weak_guard"])
    # weak guard has breaches -> non-zero exit
    assert result.exit_code == 1
    assert "BREACH" in result.stdout


def test_run_bad_module() -> None:
    result = runner.invoke(app, ["run", "--module", "no.such:thing"])
    assert result.exit_code == 2
    assert "could not load target" in result.stdout


def test_run_with_category() -> None:
    result = runner.invoke(
        app,
        ["run", "--module", "promptproof.guards:strong_guard", "--category", "delimiter_escape"],
    )
    assert result.exit_code == 0


def test_run_with_unknown_category() -> None:
    result = runner.invoke(
        app,
        ["run", "--module", "promptproof.guards:strong_guard", "--category", "nope"],
    )
    assert result.exit_code == 1


def test_run_with_custom_canary() -> None:
    result = runner.invoke(
        app,
        [
            "run",
            "--module",
            "promptproof.guards:strong_guard",
            "--canary",
            "MY-CANARY-123",
        ],
    )
    assert result.exit_code == 0


def test_run_show_all_flag() -> None:
    result = runner.invoke(
        app,
        ["run", "--module", "promptproof.guards:strong_guard", "--all"],
    )
    assert result.exit_code == 0
    assert "all attacks" in result.stdout


def test_no_args_shows_help() -> None:
    result = runner.invoke(app, [])
    # no_args_is_help makes Typer print help and exit with code 2.
    assert result.exit_code == 2
    assert "promptproof" in result.output
