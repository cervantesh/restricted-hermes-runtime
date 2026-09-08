# Cold synthetic TLS renewal: acceptance and evidence

**Base:** `a57d4e89301556b8f5850a4a89e1b6a72059b5db`.
**Candidate:** the implementation commit containing this record; all commands
below used its worktree source, not a separately installed editable runtime.
**Scope:** synthetic clinical-staging certificate lifecycle only. No PHI,
medical deployment, hosted CI, external publication, or certification activity.

## Bounded contract

An explicit `renew-tls` command rotates the synthetic CA plus both leaf/key
pairs while every application workload is cold. Existing operator serialization
and two durable marker phases prevent normal lifecycle commands from accepting
partial publication. Prepared generation bytes are fixed across retries. The
successful command leaves `stopped`; only normal `up` can start/validate service.
Opt-in `restore --renew-tls` completes the same operation after restoring all
volumes and before any workload start. Default source-build/published harnesses
and default restore are unchanged.

The filesystem does not provide a single atomic rename across distinct Docker
volumes. Atomicity is the operational publication boundary: no readers run
during sequential durable per-file replacement; the marker becomes eligible
for startup only after every installed role and host copy matches the prepared
generation. The operator must not manually start containers around this fence.
An unprovable cold state remains rejected. This is not live CA rollover.

## Acceptance matrix

All named tests are in `tests/unit/test_clinical_staging_tls.py` unless stated.
Each PASS below is bounded to the stated engine, not full-stack deployment.

| Requirement / diagnostic | Setup or mutation | Observable effect | Exact test | Engine / result |
|---|---|---|---|---|
| Opt-in surface | Parse command and both restore forms | Renewal available; restore default remains false | `test_explicit_tls_commands_do_not_change_restore_default` | Windows/Linux pytest: PASS |
| Expiry | Generate 31-day-old material | Rejected as expired; new whole generation valid | `test_tls_generation_expiry_and_whole_set_validation` | real cryptography: PASS |
| Missing file | Remove HRH private key | Reject generation | `test_invalid_generation_is_rejected_before_any_install[missing]` | Windows/Linux: PASS |
| Key mismatch | Substitute another key | Reject generation | same test `[wrong-key]` | Windows/Linux: PASS |
| Wrong CA | Substitute another CA | Reject generation | same test `[wrong-ca]` | Windows/Linux: PASS |
| Malformed PEM | Replace certificate bytes | Reject generation | same test `[invalid-pem]` | Windows/Linux: PASS |
| Symlink | Link CA to another source | Reject linked input | same test `[symlink]` | Linux: PASS; Windows privilege skip |
| Cold publication | Renew expired ready stack | Cold witness precedes install; no start; full host generation matches receipt | `test_expired_renewal_is_cold_and_publishes_complete_stopped_generation` | lifecycle command doubles + real certs: PASS |
| Stop failure | Stop command fails | Durable non-operational marker; retry possible | `test_interrupted_renewal_blocks_up_status_backup_and_can_retry[stop]` | lifecycle doubles: PASS |
| Quiescence failure | Cold verifier rejects | No publication; operational commands rejected | same test `[cold]` | lifecycle doubles: PASS |
| Installer failure | Controller fails | Prepared generation retained for retry | same test `[install]` | lifecycle doubles: PASS |
| Invalid receipt | Installer returns wrong schema | No stopped marker | same test `[receipt]` | lifecycle doubles: PASS |
| Host copy interruption | Host publication fails | No stopped marker; retry completes same candidate | same test `[host-publish]` | lifecycle doubles: PASS |
| Prepared corruption | Alter fixed private-key bytes after failure | Retry fails without generating a different candidate | `test_prepared_generation_corruption_never_regenerates_or_starts` | real files/lifecycle doubles: PASS |
| Recovery fence | Invoke renewal inside recovering state | Returns to recovering, never starts a workload | `test_restoring_renewal_preserves_recovery_fence_without_start` | lifecycle doubles: PASS |
| Default restore | Restore actual expired state archive without flag | No implicit renewal | `test_expired_backup_restore_renews_before_start_or_remains_recovering[False-False]` | real archive/manifest codec; app startup doubled: PASS |
| Expired backup renewal | Restore actual expired archive with flag | Valid new generation and real TLS handshake precede startup seam | same test `[True-False]` | real archive/crypto/TLS; volume/startup doubles: PASS |
| Failed restore renewal | Interrupt installer during opted-in restore | No workload start; marker recovering | same test `[True-True]` | real archive + lifecycle doubles: PASS |
| TLS trust behavior | Separate loopback HTTPS process | Expired chain and prior CA denied; renewed chain accepted | `test_real_tls_process_rejects_expiry_and_old_trust_after_renewal` | Windows/Linux real TLS subprocess: PASS |
| Installation/retry | Interrupt real POSIX installer after two writes | Same prepared generation resumes; exact owner/mode/readback and unrelated policy preserved | `test_real_installer_replays_partial_generation_and_preserves_unrelated_state` | isolated Linux root/files + TLS subprocess: PASS |

## Recorded execution

TDD RED before implementation: `2 failed` with `--maxfail=2` (parser rejected
`renew-tls`; TLS lifecycle module did not exist).

Native Windows: Python 3.11. `PYTHONPATH` pointed to this worktree's `src`.
The final adjacent sweep passed **96 tests, 10 platform skips** across TLS,
staging lifecycle, secret boundary, composed environment and static staging
surface. After extending the drill, the TLS-only suite passed **18 tests,
2 platform skips** (symlink privilege and Linux installer ownership).

```text
python -m pytest tests/unit/test_clinical_staging_tls.py \
  tests/unit/test_clinical_staging_lifecycle.py \
  tests/unit/test_clinical_staging_secret_boundary.py \
  tests/unit/test_clinical_composed_e2e_environment.py \
  tests/static/test_clinical_staging_surface.py -q --disable-warnings
```

Ubuntu 24.04 under WSL2: Python 3.12.3, cryptography 50.0.0, pytest 8.4.2.
An isolated temporary virtual environment was used. Tests ran as Linux root
only to exercise the actual installer ownership assignments on temporary
directories; no existing deployment or named Docker volume was changed.

```text
PYTHONPATH=<worktree>/src <temporary-venv>/bin/python -m pytest \
  tests/unit/test_clinical_staging_tls.py \
  tests/unit/test_clinical_staging_lifecycle.py -q --disable-warnings
```

The Linux sweep passed **79 tests, zero skips**. The TLS test peer is the
checked-in `tests/deployment/clinical-tls-drill/server.py`; it binds only an
ephemeral `127.0.0.1` port and is terminated/reaped after every witness.
`compileall` for changed Python modules and `git diff --check` also passed.
Temporary private key and archive material belongs to pytest temporary paths,
not public evidence. Receipts include hashes, not keys or certificate bodies.

## Explicit remaining limits

- No real Mattermost/HRH Compose stack was initialized or deployed for this
  slice. Docker orchestration/source-frame selection in the new lifecycle
  tests is doubled. The existing full composed/cold-recovery suites remain the
  integration destination for the final combined immutable candidate.
- The real Linux witness proves the extracted install function, permissions,
  filesystem readback and TLS, not an independently executed container image.
- Default published/source behavior is protected by adjacent regression tests,
  not a fresh registry publication or source-free download.
- Host reboot during writes, storage fault guarantees beyond the existing
  fsync/atomic marker primitives, external PKI, service-manager rotation, and
  unattended scheduling are not new claims. The operator owns those separate
  controls; reevaluate when the deployment needs live or automatic renewal.
- A still-running privileged helper after an uncontrolled interruption is
  rejected by the existing controller/quiescence checks, not automatically
  removed or silently trusted. Invalid prepared generations require explicit
  recovery decisions; they cannot be bypassed with an edited marker.
