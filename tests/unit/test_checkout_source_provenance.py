from __future__ import annotations

from pathlib import Path

import restricted_runtime


ROOT = Path(__file__).resolve().parents[2]


def test_pytest_imports_restricted_runtime_from_the_current_checkout() -> None:
    """A worktree run must not silently exercise an editable sibling checkout."""
    module = Path(restricted_runtime.__file__).resolve()
    assert module.is_relative_to((ROOT / "src").resolve())
