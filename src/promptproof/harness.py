"""The promptproof harness.

:func:`run` is the heart of the library: it renders each attack with the canary,
calls your ``target`` callable, runs the detector stack over the output, and
collects everything into a scored :class:`~promptproof.models.Report`.

It is intentionally tiny and pure — no I/O of its own beyond invoking the target
you hand it — so the whole thing stays deterministic and unit-testable.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from promptproof.attacks import ATTACK_LIBRARY
from promptproof.detectors import Detector, default_detectors, run_detectors
from promptproof.guards import DEMO_CANARY
from promptproof.models import Attack, AttackResult, Report

Target = Callable[[str], str]


def run(
    target: Target,
    *,
    attacks: Sequence[Attack] = ATTACK_LIBRARY,
    detectors: Sequence[Detector] | None = None,
    canary: str = DEMO_CANARY,
    target_name: str | None = None,
) -> Report:
    """Run every attack against ``target`` and return a scored report.

    Args:
        target: Your guard/handler, a callable ``(user_input) -> str``.
        attacks: The attacks to run (defaults to the full library).
        detectors: The detector stack (defaults to :func:`default_detectors`).
        canary: The secret token substituted into ``{canary}`` templates. Must
            match whatever secret your target is supposed to protect.
        target_name: A label for the report; defaults to the callable's name.

    Returns:
        A :class:`~promptproof.models.Report` with per-attack results,
        per-category rollups, and an overall robustness score.
    """
    active_detectors = list(detectors) if detectors is not None else default_detectors()
    name = target_name or getattr(target, "__name__", "target")

    results: list[AttackResult] = []
    for attack in attacks:
        rendered = attack.render(canary)
        try:
            output = target(rendered)
        except Exception as exc:  # surface target crashes as report text
            output = f"<target raised {type(exc).__name__}: {exc}>"
        succeeded, hits = run_detectors(active_detectors, attack, rendered, output, canary)
        results.append(
            AttackResult(
                attack=attack,
                rendered_input=rendered,
                output=output,
                succeeded=succeeded,
                detector_hits=hits,
            )
        )

    return Report(target_name=name, results=tuple(results))
