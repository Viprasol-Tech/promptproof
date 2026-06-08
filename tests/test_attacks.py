"""Tests for the attack library integrity."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from promptproof.attacks import (
    ATTACK_LIBRARY,
    CATEGORIES,
    attacks_by_category,
    get_attack,
)
from promptproof.models import CANARY_PLACEHOLDER, Attack


def test_library_has_enough_attacks() -> None:
    assert 30 <= len(ATTACK_LIBRARY) <= 40


def test_ids_are_unique() -> None:
    ids = [a.id for a in ATTACK_LIBRARY]
    assert len(ids) == len(set(ids))


def test_names_are_nonempty() -> None:
    assert all(a.name.strip() for a in ATTACK_LIBRARY)


def test_templates_are_nonempty() -> None:
    assert all(a.template.strip() for a in ATTACK_LIBRARY)


def test_every_category_present() -> None:
    present = {a.category for a in ATTACK_LIBRARY}
    assert present == set(CATEGORIES)


def test_no_unknown_categories() -> None:
    for attack in ATTACK_LIBRARY:
        assert attack.category in CATEGORIES


def test_each_category_has_attacks() -> None:
    grouped = attacks_by_category()
    for category in CATEGORIES:
        assert grouped[category], f"{category} has no attacks"


@pytest.mark.parametrize("category", CATEGORIES)
def test_category_has_at_least_three(category: str) -> None:
    grouped = attacks_by_category()
    assert len(grouped[category]) >= 3


def test_canary_using_attacks_render_correctly() -> None:
    canary = "CANARY-test"
    for attack in ATTACK_LIBRARY:
        rendered = attack.render(canary)
        assert CANARY_PLACEHOLDER not in rendered
        if attack.uses_canary:
            assert canary in rendered


def test_uses_canary_flag_matches_template() -> None:
    for attack in ATTACK_LIBRARY:
        assert attack.uses_canary == (CANARY_PLACEHOLDER in attack.template)


def test_at_least_one_canary_attack_exists() -> None:
    assert any(a.uses_canary for a in ATTACK_LIBRARY)


def test_get_attack_returns_attack() -> None:
    a = get_attack("io-01")
    assert isinstance(a, Attack)
    assert a.id == "io-01"


def test_get_attack_unknown_raises() -> None:
    with pytest.raises(KeyError):
        get_attack("does-not-exist")


def test_attacks_by_category_keys_sorted() -> None:
    keys = list(attacks_by_category().keys())
    assert keys == sorted(keys)


def test_attacks_by_category_total_matches_library() -> None:
    grouped = attacks_by_category()
    assert sum(len(v) for v in grouped.values()) == len(ATTACK_LIBRARY)


def test_attack_is_frozen() -> None:
    a = ATTACK_LIBRARY[0]
    with pytest.raises(ValidationError):
        a.id = "mutated"  # type: ignore[misc]


def test_render_replaces_all_occurrences() -> None:
    a = Attack(id="x", category="instruction_override", name="n", template="{canary}-{canary}")
    assert a.render("Z") == "Z-Z"
