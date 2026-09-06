"""POSIX main-thread wall-clock guard for one bounded upstream attempt."""
from __future__ import annotations

import os
import signal
import threading
from contextlib import contextmanager

from .contracts import ContractError


def available() -> bool:
    """Check the signal preconditions without changing process signal state."""
    if os.name != "posix" or threading.current_thread() is not threading.main_thread():
        return False
    try:
        blocked = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        return signal.SIGALRM not in blocked and signal.getitimer(signal.ITIMER_REAL)[0] <= 0
    except (AttributeError, OSError, TypeError, ValueError):
        return False


@contextmanager
def absolute_upstream_deadline(seconds: float):
    """Interrupt a serial POSIX attempt while restoring untouched signal state."""
    if not available():
        raise ContractError("clinical adapter upstream deadline unavailable")
    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_timer = signal.getitimer(signal.ITIMER_REAL)

    def expired(_signum, _frame):
        raise TimeoutError

    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, *previous_timer)
        signal.signal(signal.SIGALRM, previous_handler)
