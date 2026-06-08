"""promptproof — offline prompt-injection red-team test suite for LLM apps.

Point promptproof at your own ``target(user_input: str) -> str`` guard/handler,
and it runs a battery of known injection & jailbreak attacks, scoring how many
got through. No network, no LLM calls — fully deterministic and unit-testable.
"""

from __future__ import annotations

from promptproof.attacks import (
    ATTACK_LIBRARY,
    CATEGORIES,
    attacks_by_category,
    get_attack,
)
from promptproof.detectors import (
    CanaryLeakDetector,
    ComplianceMarkerDetector,
    Detector,
    RefusalAbsenceDetector,
    default_detectors,
    run_detectors,
)
from promptproof.guards import COMPLIANCE_MARKER, make_canary, strong_guard, weak_guard
from promptproof.harness import run
from promptproof.models import Attack, AttackResult, Report

__version__ = "0.1.0"

__all__ = [
    "ATTACK_LIBRARY",
    "CATEGORIES",
    "COMPLIANCE_MARKER",
    "Attack",
    "AttackResult",
    "CanaryLeakDetector",
    "ComplianceMarkerDetector",
    "Detector",
    "RefusalAbsenceDetector",
    "Report",
    "__version__",
    "attacks_by_category",
    "default_detectors",
    "get_attack",
    "make_canary",
    "run",
    "run_detectors",
    "strong_guard",
    "weak_guard",
]
