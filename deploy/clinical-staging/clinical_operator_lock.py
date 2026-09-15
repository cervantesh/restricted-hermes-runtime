"""Persistent, operator-scoped serialization for synthetic staging mutators.

This module is introduced as an isolated cold-recovery dependency.  It is not
yet wired into `clinical_staging.ClinicalStaging`; the current per-state
lifecycle lock remains the only lifecycle authority until the integration
slice replaces it deliberately.  Keeping the boundary separate here lets the
durable, project-scoped semantics be tested on their own before any lifecycle
behavior changes.

Why a second namespace exists at all: the current lifecycle lock lives beside
one state directory, so two independently supplied state directories that name
the same Compose project can still race over the same external Docker volumes.
The lock below is keyed by the Compose project, which is the resource that
mutators actually overlap.
"""
from __future__ import annotations

import contextlib
import os
import stat
import tempfile
import threading
from pathlib import Path
from typing import Iterator

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows runs only unit doubles.
    fcntl = None  # type: ignore[assignment]


class OperatorLockError(RuntimeError):
    """The persistent operator boundary could not be established safely."""


_THREAD_LOCKS: dict[Path, threading.RLock] = {}
_THREAD_LOCKS_GUARD = threading.Lock()
_LOCK_STATE = threading.local()


def _thread_lock(path: Path) -> threading.RLock:
    with _THREAD_LOCKS_GUARD:
        return _THREAD_LOCKS.setdefault(path, threading.RLock())


def operator_lock_parent() -> Path:
    """Return the operator-owned directory that holds every persistent lock."""
    if os.name == "posix":
        parent = Path("/var/tmp") / f"restricted-clinical-staging-{os.getuid()}"
    else:  # pragma: no cover - staging itself is Linux-only.
        parent = Path(tempfile.gettempdir()) / "restricted-clinical-staging-locks"
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # `mkdir(exist_ok=True)` accepts a pre-existing symlink to a directory, so
    # the shared `/var/tmp` parent is re-checked without following links.
    info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise OperatorLockError("operator lock parent must be a directory")
    if os.name == "posix" and (
        info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise OperatorLockError(
            "operator lock parent must be operator-owned with mode 0700"
        )
    return parent


def operator_lock_path(state_dir: Path, project: str | None = None) -> Path:
    """Return the per-operator, per-Compose-project persistent lock path."""
    identity = project or state_dir.name
    if not identity or "/" in identity or "\\" in identity or identity in {".", ".."}:
        raise OperatorLockError("operator lock identity must be a single path segment")
    return operator_lock_parent() / f".{identity}.operator.lock"


@contextlib.contextmanager
def persistent_operator_lock(
    state_dir: Path, project: str | None = None
) -> Iterator[None]:
    """Hold a re-entrant, no-follow lock without deleting its durable path.

    The lock file is never unlinked.  Deleting it would let a second operator
    create a fresh inode and hold a lock that the first operator's descriptor
    does not observe.
    """
    lock_path = operator_lock_path(state_dir, project)
    states: dict[Path, tuple[int, int]] = getattr(_LOCK_STATE, "states", {})
    if lock_path in states:
        fd, depth = states[lock_path]
        states[lock_path] = (fd, depth + 1)
        try:
            yield
        finally:
            fd, depth = states[lock_path]
            states[lock_path] = (fd, depth - 1)
        return
    with _thread_lock(lock_path):
        if os.name == "posix" and not hasattr(os, "O_NOFOLLOW"):
            raise OperatorLockError("operator lock requires no-follow file semantics")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(lock_path, flags, 0o600)
        except OSError as exc:
            raise OperatorLockError(
                "could not safely open persistent operator lock"
            ) from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise OperatorLockError("operator lock must be a regular file")
            if os.name == "posix" and (
                info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise OperatorLockError(
                    "operator lock must be an operator-owned regular file with mode 0600"
                )
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_EX)
            states[lock_path] = (fd, 1)
            _LOCK_STATE.states = states
            try:
                yield
            finally:
                states.pop(lock_path, None)
                if fcntl is not None:
                    fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
