"""Persistent, process-wide serialization for synthetic staging mutators."""
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


def operator_lock_path(state_dir: Path, project: str | None = None) -> Path:
    """Return the per-operator, per-Docker-project persistent lock path.

    The Compose project, rather than a private-state pathname, is the resource
    namespace that mutators can overlap.  This also blocks two separately
    supplied state directories from racing over the same named volumes.
    """
    if os.name == "posix":
        parent = Path("/var/tmp") / f"restricted-clinical-staging-{os.getuid()}"
    else:  # pragma: no cover - staging itself is Linux-only.
        parent = Path(tempfile.gettempdir()) / "restricted-clinical-staging-locks"
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise OperatorLockError("operator lock parent must be a directory")
    if os.name == "posix" and (
        info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise OperatorLockError("operator lock parent must be operator-owned with mode 0700")
    identity = project or state_dir.name
    return parent / f".{identity}.operator.lock"


@contextlib.contextmanager
def persistent_operator_lock(state_dir: Path, project: str | None = None) -> Iterator[None]:
    """Hold a re-entrant, no-follow lock without deleting its durable path."""
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
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(lock_path, flags, 0o600)
        except OSError as exc:
            raise OperatorLockError("could not safely open persistent operator lock") from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise OperatorLockError("operator lock must be a regular file")
            if os.name == "posix" and (
                info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise OperatorLockError("operator lock must be an operator-owned regular file with mode 0600")
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
