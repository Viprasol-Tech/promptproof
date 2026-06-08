"""Import-string loader for user-supplied target callables.

Lets the CLI accept ``--module pkg.mod:callable`` and resolve it to an actual
callable, with clear errors when the string is malformed or the attribute is not
callable.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable


def load_target(spec: str) -> Callable[[str], str]:
    """Resolve an import string like ``mypkg.guards:my_guard`` to a callable.

    Args:
        spec: ``module.path:attribute`` — the module is imported and the named
            attribute returned.

    Raises:
        ValueError: if ``spec`` is missing the ``:`` separator or the resolved
            attribute is not callable.
        ModuleNotFoundError / AttributeError: if the module or attribute does
            not exist.
    """
    if ":" not in spec:
        raise ValueError(f"target spec must look like 'module.path:callable', got {spec!r}")
    module_path, _, attr = spec.partition(":")
    if not module_path or not attr:
        raise ValueError(f"target spec must look like 'module.path:callable', got {spec!r}")
    module = importlib.import_module(module_path)
    target = getattr(module, attr)
    if not callable(target):
        raise ValueError(f"{spec!r} resolved to a non-callable {type(target).__name__}")
    return target  # type: ignore[no-any-return]
