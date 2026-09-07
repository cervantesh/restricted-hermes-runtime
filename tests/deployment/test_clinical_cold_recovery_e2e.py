#!/usr/bin/env python3
"""Linux-only, synthetic Compose proof for the staging wrapper's cold restore."""
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
    spec = importlib.util.spec_from_file_location("clinical_staging_recovery", path)
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


def snapshot(staging, record_tag: str | None = None) -> list[dict[str, object]]:
    staging.compose("pause", "ingress")
    try:
        args = ("snapshot-outbox-records", record_tag) if record_tag else ("snapshot-outbox-records",)
        value = json.loads(staging.control(*args))
    finally:
        staging.compose("unpause", "ingress", check=False)
    if not isinstance(value, list):
        raise RuntimeError("outbox snapshot was not a list")
    return value


def blocked_source_record(staging) -> tuple[dict[str, object], dict[str, object]]:
    """Persist a deleted-source outcome before the cold fence."""
    staging.control("mutate", "reset")
    before_grants = int(staging.control("grant-count"))
    staging.control("mutate", "crash-delay")
    staging.control("send", "actor", "actor_dm", PATIENT, "cold-source-deleted")
    wait_until(lambda: int(staging.control("grant-count")) > before_grants, "clinical read was not granted")
    wait_until(lambda: int(staging.control("delivery-delay-active")) == 1, "delivery did not enter pause")
    ready = [row for row in snapshot(staging) if row.get("state") == "READY"]
    if len(ready) != 1:
        raise RuntimeError("source-deletion fixture did not isolate one READY record")
    before = ready[0]
    tag = before.get("record_tag")
    if not isinstance(tag, str) or len(tag) != 64:
        raise RuntimeError("source-deletion record tag is invalid")
    staging.control("delete-source", "cold-source-deleted")
    staging.control("mutate", "drop-crash-delay")
    staging.control("expect", "cold-source-deleted", "no-reply")
    after_rows = snapshot(staging, tag)
    if len(after_rows) != 1:
        raise RuntimeError("terminal source-deletion record is missing")
    after = after_rows[0]
    expected = {
        "record_tag": tag,
        "state": "BLOCKED",
        "reason": "current_authorization_rejected",
        "generation": int(before["generation"]) + 1,
        "nonce_erased": True,
        "ciphertext_erased": True,
    }
    if after != expected:
        raise RuntimeError("source deletion did not produce the erased terminal record")
    return before, after


def main() -> None:
    if os.name != "posix" or not sys.platform.startswith("linux"):
        raise RuntimeError("cold recovery E2E requires local Linux Docker/Compose")
    if not HRH_ROOT.is_dir():
        raise RuntimeError("CLINICAL_E2E_HRH_ROOT must name the clean frozen HRH checkout")
    module = load_wrapper()
    project = "clinicalstagingrecovery" + secrets.token_hex(4)
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="restricted-clinical-recovery-") as raw:
        root = Path(raw)
        state = root / f"{project}.synthetic-clinical-staging"
        backup = root / "cold-backup"
        staging = module.ClinicalStaging(ROOT, HRH_ROOT, state, project, 18473)
        try:
            staging.init()
            # A delivered work item must remain terminal across the restore.
            staging.control("send", "actor", "actor_dm", PATIENT, "cold-already-delivered")
            staging.control("expect", "cold-already-delivered", "reply")
            delivered_before = int(staging.control("post-count", "cold-already-delivered"))
            if delivered_before != 1:
                raise RuntimeError("baseline delivery count was not exactly one")
            source_before, source_after = blocked_source_record(staging)

            # This item is READY at the cold fence.  The recovery may grant it
            # once after restart, never repeatedly or before the fresh check.
            staging.control("mutate", "reset")
            grants_before_ready = int(staging.control("grant-count"))
            staging.control("mutate", "crash-delay")
            staging.control("send", "actor", "actor_dm", PATIENT, "cold-ready")
            wait_until(lambda: int(staging.control("grant-count")) > grants_before_ready, "READY fixture was not authorized")
            wait_until(lambda: int(staging.control("delivery-delay-active")) == 1, "READY fixture did not pause")
            ready_evidence_before = json.loads(staging.control("grant-evidence", "cold-ready"))

            staging.stop()
            backup_receipt = staging.backup(backup)
            external_manifest_hash = backup_receipt["manifest_sha256"]
            if not isinstance(external_manifest_hash, str):
                raise RuntimeError("backup did not provide an external manifest hash")
            staging.destroy()

            restored = module.ClinicalStaging(ROOT, HRH_ROOT, state, project, 18473)
            receipt = restored.restore(backup, external_manifest_hash)
            if receipt["manifest_sha256"] != external_manifest_hash:
                raise RuntimeError("restore receipt did not bind the external manifest hash")
            restored.control("mutate", "drop-crash-delay")
            restored.control("expect", "cold-ready", "reply")
            ready_evidence_after = json.loads(restored.control("grant-evidence", "cold-ready"))
            reauthorized_before = ready_evidence_before["audits"].get("restricted_hermes_delivery_reauthorized", 0)
            reauthorized_after = ready_evidence_after["audits"].get("restricted_hermes_delivery_reauthorized", 0)
            reauthorization_delta = reauthorized_after - reauthorized_before
            # The source generation can commit its in-flight authorization
            # immediately before the cold fence.  Recovery deliberately gets a
            # second fresh authorization before its one post (the established
            # crash-retry contract allows that pair), but must never retry it
            # beyond that bounded window.
            if reauthorization_delta not in {1, 2}:
                raise RuntimeError("restored READY item had an unexpected reauthorization count")
            if int(restored.control("post-count", "cold-ready")) != 1:
                raise RuntimeError("restored READY item was not delivered exactly once")

            if int(restored.control("post-count", "cold-already-delivered")) != delivered_before:
                raise RuntimeError("already delivered work was delivered again after restore")
            restored_blocked = snapshot(restored, str(source_after["record_tag"]))
            if restored_blocked != [source_after]:
                raise RuntimeError("deleted-source terminal erased state changed after restore")
            restored.control("send", "denied", "denied_dm", PATIENT, "cold-isolation")
            restored.control("expect", "cold-isolation", "no-reply")
            restored.control("send", "actor", "actor_dm", PATIENT, "cold-allowed")
            restored.control("expect", "cold-allowed", "reply")

            # Expired policy is a post-restore fail-closed control, not a new
            # backup feature.  It must not revive a response path.
            restored.compose("stop", "ingress")
            restored.control("policy", "cold-expired", "-1")
            restored.compose("up", "--detach", "ingress")
            restored.control("send", "actor", "actor_dm", PATIENT, "cold-expired")
            restored.control("expect", "cold-expired", "no-reply")

            fixture_tokens = ("cold-source-deleted", "cold-ready", "cold-allowed", PATIENT)
            evidence_text = "\n".join(
                path.read_text(encoding="utf-8", errors="replace")
                for path in (state / "evidence").rglob("*")
                if path.is_file()
            )
            compose_logs = restored.compose("logs", "--no-color", check=False).stdout
            if any(value in evidence_text or value in compose_logs for value in fixture_tokens):
                raise RuntimeError("restored Compose logs or exported evidence leaked synthetic fixture content")

            causal_checks = {
                "source_deletion_persisted": True,
                "ready_delivery_continues_once": True,
                "already_delivered_not_redelivered": True,
                "isolation_preserved": True,
                "expired_policy_fails_closed": True,
                "artifacts_clean": True,
                "duration_bounded": time.monotonic() - started <= 1200,
            }
            verified_receipt = restored.finalize_cold_recovery_verification(external_manifest_hash, causal_checks)
            if verified_receipt["verification"] != "causal_e2e_verified":
                raise RuntimeError("causal recovery verification receipt was not published")

            report = {
                "schema": module.BACKUP_SCHEMA,
                "synthetic_only": True,
                "manifest_sha256": external_manifest_hash,
                "source_deletion_before": source_before,
                "source_deletion_after": source_after,
                "delivered_count_before_after": delivered_before,
                "ready_reauthorization_delta": reauthorization_delta,
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "nonclaims": ["not PHI", "not production", "not a compliance certification"],
            }
            if report["elapsed_seconds"] > 1200:
                raise RuntimeError("synthetic cold recovery exceeded the 1200-second bound")
            print(json.dumps(report, sort_keys=True))
        finally:
            if state.exists():
                try:
                    module.ClinicalStaging(ROOT, HRH_ROOT, state, project, 18473).destroy()
                except Exception:
                    pass
            shutil.rmtree(backup, ignore_errors=True)


if __name__ == "__main__":
    main()
