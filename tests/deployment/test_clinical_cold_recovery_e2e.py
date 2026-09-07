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


def ambiguous_source_record(staging) -> tuple[dict[str, object], dict[str, object]]:
    """Persist an unknown delivery result before the cold fence."""
    staging.control("mutate", "reset")
    before_grants = int(staging.control("grant-count"))
    staging.control("mutate", "crash-delay")
    staging.control("send", "actor", "actor_dm", PATIENT, "cold-source-deleted")
    wait_until(lambda: int(staging.control("grant-count")) > before_grants, "clinical read was not granted")
    wait_until(lambda: int(staging.control("delivery-delay-active")) == 1, "delivery did not enter pause")
    in_flight = [row for row in snapshot(staging) if row.get("state") == "IN_FLIGHT"]
    if len(in_flight) != 1:
        raise RuntimeError("source-deletion fixture did not isolate one IN_FLIGHT record")
    before = in_flight[0]
    tag = before.get("record_tag")
    if not isinstance(tag, str) or len(tag) != 64:
        raise RuntimeError("source-deletion record tag is invalid")
    staging.control("delete-source", "cold-source-deleted")
    staging.control("mutate", "drop-crash-delay")
    wait_until(
        lambda: json.loads(staging.control("grant-evidence", "cold-source-deleted"))["audits"].get(
            "restricted_hermes_delivery_reauthorized", 0
        ) == 1,
        "source-deletion unknown authorization did not commit exactly once",
    )
    staging.control("expect", "cold-source-deleted", "no-reply")
    after_rows = snapshot(staging, tag)
    if len(after_rows) != 1:
        raise RuntimeError("terminal source-deletion record is missing")
    after = after_rows[0]
    expected = {
        "record_tag": tag,
        "state": "AMBIGUOUS",
        "reason": "delivery_authorization_unknown",
        "generation": int(before["generation"]) + 1,
        "nonce_erased": True,
        "ciphertext_erased": True,
    }
    if after != expected:
        raise RuntimeError("source deletion did not preserve the erased unknown result")
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
            # A separate ordinary success proves the normal one-authorization,
            # one-post path before the cold fence.
            staging.control("send", "actor", "actor_dm", PATIENT, "cold-already-delivered")
            staging.control("expect", "cold-already-delivered", "reply")
            delivered_before = int(staging.control("post-count", "cold-already-delivered"))
            if delivered_before != 1:
                raise RuntimeError("baseline delivery count was not exactly one")
            delivered_evidence = json.loads(staging.control("grant-evidence", "cold-already-delivered"))
            if delivered_evidence["audits"].get("restricted_hermes_delivery_reauthorized", 0) != 1:
                raise RuntimeError("ordinary known-success delivery did not authorize exactly once")
            source_before, source_after = ambiguous_source_record(staging)

            # This item is IN_FLIGHT at the cold fence with a deliberately
            # unknown authorization outcome. #17 requires restore to classify
            # it ambiguous and erase it, never reauthorize or post it.
            staging.control("mutate", "reset")
            grants_before_unknown = int(staging.control("grant-count"))
            staging.control("mutate", "crash-delay")
            staging.control("send", "actor", "actor_dm", PATIENT, "cold-unknown")
            wait_until(lambda: int(staging.control("grant-count")) > grants_before_unknown, "unknown fixture was not authorized")
            wait_until(lambda: int(staging.control("delivery-delay-active")) == 1, "unknown fixture did not pause")
            unknown_before_rows = [row for row in snapshot(staging) if row.get("state") == "IN_FLIGHT"]
            if len(unknown_before_rows) != 1:
                raise RuntimeError("unknown fixture did not isolate one IN_FLIGHT record")
            unknown_before = unknown_before_rows[0]
            unknown_tag = unknown_before.get("record_tag")
            if not isinstance(unknown_tag, str) or len(unknown_tag) != 64:
                raise RuntimeError("unknown fixture record tag is invalid")

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
            wait_until(
                lambda: json.loads(restored.control("grant-evidence", "cold-unknown"))["audits"].get(
                    "restricted_hermes_delivery_reauthorized", 0
                ) == 1,
                "restored unknown authorization did not commit exactly once",
            )
            restored.control("expect", "cold-unknown", "no-reply")
            unknown_after_rows = snapshot(restored, unknown_tag)
            if len(unknown_after_rows) != 1:
                raise RuntimeError("restored unknown terminal record is missing")
            unknown_after = unknown_after_rows[0]
            expected_unknown_after = {
                "record_tag": unknown_tag,
                "state": "AMBIGUOUS",
                "reason": "restart_in_flight",
                "generation": int(unknown_before["generation"]) + 1,
                "nonce_erased": True,
                "ciphertext_erased": True,
            }
            if unknown_after != expected_unknown_after:
                raise RuntimeError("restore did not erase the unknown delivery result")
            if int(restored.control("post-count", "cold-unknown")) != 0:
                raise RuntimeError("restored unknown delivery produced a post")

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

            fixture_tokens = ("cold-source-deleted", "cold-unknown", "cold-allowed", PATIENT)
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
                "unknown_delivery_is_ambiguous_once": True,
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
                "ordinary_delivery_authorizations": delivered_evidence["audits"].get(
                    "restricted_hermes_delivery_reauthorized", 0
                ),
                "unknown_delivery_before": unknown_before,
                "unknown_delivery_after": unknown_after,
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
