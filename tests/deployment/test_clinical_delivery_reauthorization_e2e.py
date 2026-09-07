#!/usr/bin/env python3
"""Linux-only synthetic proof that unknown delivery authorization is not retried."""
from __future__ import annotations

import importlib.util
import json
import os
import secrets
import shutil
import sys
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HRH_ROOT = Path(os.environ.get("CLINICAL_E2E_HRH_ROOT", ""))
PATIENT = "018f22bb-414d-7cc4-b5a4-83cc8ec92cb1"


def load_wrapper():
    path = ROOT / "deploy" / "clinical-staging" / "clinical_staging.py"
    spec = importlib.util.spec_from_file_location("clinical_staging_reauthorization", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("clinical staging wrapper is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def wait_until(probe, message: str, *, timeout: int = 60) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if probe():
            return
        time.sleep(0.25)
    raise RuntimeError(message)


def main() -> None:
    if os.name != "posix" or not sys.platform.startswith("linux"):
        raise RuntimeError("delivery reauthorization E2E requires local Linux Docker/Compose")
    if not HRH_ROOT.is_dir():
        raise RuntimeError("CLINICAL_E2E_HRH_ROOT must name the clean frozen HRH checkout")
    module = load_wrapper()
    project = "clinicalstagingreauth" + secrets.token_hex(4)
    with tempfile.TemporaryDirectory(prefix="restricted-clinical-reauth-") as raw:
        root = Path(raw)
        state = root / f"{project}.synthetic-clinical-staging"
        staging = module.ClinicalStaging(ROOT, HRH_ROOT, state, project, 18474)
        try:
            staging.init()
            staging.control("mutate", "reset")
            baseline_grants = int(staging.control("grant-count"))
            staging.control("mutate", "crash-delay")
            staging.control("send", "actor", "actor_dm", PATIENT, "reauth-timeout")
            wait_until(
                lambda: int(staging.control("grant-count")) > baseline_grants,
                "clinical read was not granted",
            )
            # The delayed audit exceeds the adapter timeout.  A durable claim
            # must fence the periodic scanner from a second authorization.
            time.sleep(35)
            evidence = json.loads(staging.control("grant-evidence", "reauth-timeout"))
            calls = evidence["audits"].get("restricted_hermes_delivery_reauthorized", 0)
            if calls != 1:
                raise RuntimeError(f"unknown delivery authorization was retried: calls={calls}")
            staging.control("mutate", "drop-crash-delay")
            staging.control("expect", "reauth-timeout", "no-reply")
            if int(staging.control("post-count", "reauth-timeout")) != 0:
                raise RuntimeError("unknown delivery authorization produced a response")
            print(json.dumps({
                "synthetic_only": True,
                "delivery_reauthorization_calls": calls,
                "post_count": 0,
                "nonclaims": ["not PHI", "not production", "not a compliance certification"],
            }, sort_keys=True))
        finally:
            try:
                staging.control("mutate", "drop-crash-delay")
            except Exception:
                pass
            if state.exists():
                try:
                    module.ClinicalStaging(ROOT, HRH_ROOT, state, project, 18474).destroy()
                except Exception:
                    pass


if __name__ == "__main__":
    main()
