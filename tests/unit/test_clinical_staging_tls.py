from __future__ import annotations

import importlib.util
import io
import json
import os
import shutil
import ssl
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
import tarfile

import pytest


ROOT = Path(__file__).resolve().parents[2]
STAGING = ROOT / "deploy" / "clinical-staging"


def load_staging():
    spec = importlib.util.spec_from_file_location("clinical_staging_tls_test", STAGING / "clinical_staging.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def tls_module():
    load_staging()
    import clinical_tls
    return clinical_tls


def test_explicit_tls_commands_do_not_change_restore_default():
    module = load_staging()
    args = ["--hrh-root", str(ROOT), "--state-dir", "/tmp/clinicalstagingtest.synthetic-clinical-staging", "--project", "clinicalstagingtest"]
    assert module.parse_args([*args, "renew-tls"]).command == "renew-tls"
    restore = [*args, "restore", "--backup-dir", "/backup", "--expected-manifest-sha256", "a" * 64]
    assert module.parse_args(restore).renew_tls is False
    assert module.parse_args([*restore, "--renew-tls"]).renew_tls is True


def test_tls_generation_expiry_and_whole_set_validation(tmp_path):
    tls = tls_module()
    now = datetime.now(UTC)
    tls.generate_material(tmp_path, now=now - timedelta(days=31))
    old = tls.inspect_material(tmp_path, require_current=False)
    with pytest.raises(tls.TlsError, match="expired"):
        tls.inspect_material(tmp_path)
    tls.generate_material(tmp_path, now=now)
    current = tls.inspect_material(tmp_path)
    assert set(current) == set(tls.MATERIAL_NAMES)
    assert all(current[name] != old[name] for name in current)


@pytest.mark.parametrize("mutation", ["missing", "wrong-key", "wrong-ca", "invalid-pem", "symlink"])
def test_invalid_generation_is_rejected_before_any_install(tmp_path, mutation):
    tls = tls_module()
    seed, other = tmp_path / "seed", tmp_path / "other"
    seed.mkdir(); other.mkdir()
    tls.generate_material(seed); tls.generate_material(other)
    if mutation == "missing":
        (seed / "hrh-tls.key").unlink()
    elif mutation == "wrong-key":
        shutil.copyfile(other / "mattermost.key", seed / "mattermost.key")
    elif mutation == "wrong-ca":
        shutil.copyfile(other / "ca.crt", seed / "ca.crt")
    elif mutation == "invalid-pem":
        (seed / "mattermost.crt").write_bytes(b"invalid")
    else:
        (seed / "ca.crt").unlink()
        try:
            (seed / "ca.crt").symlink_to(other / "ca.crt")
        except OSError:
            pytest.skip("host does not grant symlink creation")
    with pytest.raises(tls.TlsError):
        tls.inspect_material(seed)


def staging_fixture(tmp_path, monkeypatch, *, lifecycle="ready", expired=False):
    module = load_staging()
    tls = tls_module()
    project = "clinicalstagingtls"
    state = tmp_path / f"{project}.synthetic-clinical-staging"
    (state / "seed").mkdir(parents=True)
    (state / "evidence").mkdir()
    tls.generate_material(state / "seed", now=datetime.now(UTC) - timedelta(days=31 if expired else 0))
    marker = module.new_marker(project=project, state_dir=state, state_id="1" * 32,
        env_sha256="2" * 64, runtime_head="a" * 40, runtime_tree="b" * 40,
        hrh_head=module.REQUIRED_HRH_SHA, hrh_tree=module.REQUIRED_HRH_TREE,
        lifecycle=lifecycle, expected_images={"ingress": "sha256:" + "c" * 64})
    module.write_json_atomic(state / module.MARKER_NAME, marker, mode=0o600)
    staging = module.ClinicalStaging(ROOT, ROOT, state, project, 18443)
    events = []
    monkeypatch.setattr(staging, "_require_linux", lambda: None)
    monkeypatch.setattr(staging, "_verify_marker_and_source", lambda: module.read_marker(state, project))
    monkeypatch.setattr(staging, "_verify_cold_quiescence", lambda _marker: events.append("cold"))
    monkeypatch.setattr(staging, "_assert_unmounted_backup_volumes", lambda _volumes: events.append("unmounted"))
    monkeypatch.setattr(staging, "_assert_no_controller", lambda: None)
    monkeypatch.setattr(staging, "compose", lambda *args, **kwargs: (events.append(args), SimpleNamespace(returncode=0))[1])
    def control(*args):
        events.append(args)
        assert module.read_marker(state, project)["lifecycle"] == "tls_prepared"
        assert "cold" in events or "unmounted" in events
        return json.dumps({"schema": tls.RECEIPT_SCHEMA, "material": tls.inspect_material(state / "seed" / "tls-next")})
    monkeypatch.setattr(staging, "control", control)
    return module, tls, staging, state, events


def test_expired_renewal_is_cold_and_publishes_complete_stopped_generation(tmp_path, monkeypatch):
    module, tls, staging, state, events = staging_fixture(tmp_path, monkeypatch, expired=True)
    result = staging.renew_tls()
    assert result["lifecycle"] == "stopped"
    assert module.read_marker(state, staging.project)["lifecycle"] == "stopped"
    assert result["material"] == tls.inspect_material(state / "seed")
    assert not any(isinstance(event, tuple) and "up" in event for event in events)
    assert events.index("cold") < next(i for i, event in enumerate(events) if isinstance(event, tuple) and event[0] == "renew-tls")


@pytest.mark.parametrize("failure", ["stop", "cold", "install", "receipt", "host-publish"])
def test_interrupted_renewal_blocks_up_status_backup_and_can_retry(tmp_path, monkeypatch, failure):
    module, tls, staging, state, events = staging_fixture(tmp_path, monkeypatch)
    original_control, original_compose = staging.control, staging.compose
    original_cold, original_publish = staging._verify_cold_quiescence, tls.publish_host_material
    if failure == "stop":
        monkeypatch.setattr(staging, "compose", lambda *_a, **_kw: SimpleNamespace(returncode=1))
    elif failure == "cold":
        monkeypatch.setattr(staging, "_verify_cold_quiescence", lambda *_a: (_ for _ in ()).throw(module.SafetyError("not cold")))
    elif failure == "install":
        monkeypatch.setattr(staging, "control", lambda *_a: (_ for _ in ()).throw(module.CommandError("failed")))
    elif failure == "receipt":
        monkeypatch.setattr(staging, "control", lambda *_a: '{"schema":"wrong"}')
    else:
        monkeypatch.setattr(tls, "publish_host_material", lambda *_a: (_ for _ in ()).throw(tls.TlsError("partial publication")))
    with pytest.raises((module.SafetyError, module.CommandError)):
        staging.renew_tls()
    assert module.read_marker(state, staging.project)["lifecycle"] in {"renewing_tls", "tls_prepared"}
    for operation in (staging.up, staging.status, lambda: staging.backup(tmp_path / "backup")):
        with pytest.raises(module.SafetyError, match="lifecycle"):
            operation()
    monkeypatch.setattr(staging, "compose", original_compose)
    monkeypatch.setattr(staging, "control", original_control)
    monkeypatch.setattr(staging, "_verify_cold_quiescence", original_cold)
    monkeypatch.setattr(tls, "publish_host_material", original_publish)
    assert staging.renew_tls()["material"] == tls.inspect_material(state / "seed")


def test_prepared_generation_corruption_never_regenerates_or_starts(tmp_path, monkeypatch):
    module, tls, staging, state, events = staging_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(staging, "control", lambda *_a: (_ for _ in ()).throw(module.CommandError("stop here")))
    with pytest.raises(module.CommandError):
        staging.renew_tls()
    prepared = state / "seed" / "tls-next"
    (prepared / "hrh-tls.key").write_bytes(b"broken")
    with pytest.raises(module.SafetyError):
        staging.renew_tls()
    assert module.read_marker(state, staging.project)["lifecycle"] == "tls_prepared"
    assert (prepared / "hrh-tls.key").read_bytes() == b"broken"


def test_restoring_renewal_preserves_recovery_fence_without_start(tmp_path, monkeypatch):
    module, tls, staging, state, events = staging_fixture(tmp_path, monkeypatch, lifecycle="recovering", expired=True)
    staging._renew_tls_material(module.read_marker(state, staging.project), restoring=True)
    assert module.read_marker(state, staging.project)["lifecycle"] == "recovering"
    assert "unmounted" in events
    assert not any(isinstance(event, tuple) and "up" in event for event in events)
    tls.inspect_material(state / "seed")


@pytest.mark.parametrize("renew,fail", [(False, False), (True, False), (True, True)])
def test_expired_backup_restore_renews_before_start_or_remains_recovering(tmp_path, monkeypatch, renew, fail):
    module, tls, staging, state, events = staging_fixture(tmp_path, monkeypatch, lifecycle="stopped", expired=True)
    (state / "compose.env").write_text("CLINICAL_SYNTHETIC=true\n")
    marker = module.read_marker(state, staging.project)
    marker["compose_env_sha256"] = module.file_sha256(state / "compose.env")
    module.write_json_atomic(state / module.MARKER_NAME, marker, mode=0o600)
    old = tls.inspect_material(state / "seed", require_current=False)
    backup = tmp_path / "backup"
    (backup / "volumes").mkdir(parents=True)
    module.create_state_archive(state, backup / module.BACKUP_STATE_ARCHIVE)
    for key in module.BACKED_UP_VOLUME_KEYS:
        with tarfile.open(backup / "volumes" / f"{key}.tar", "w") as archive:
            info = tarfile.TarInfo("synthetic")
            info.size = 9
            archive.addfile(info, io.BytesIO(b"synthetic"))
    manifest = module.build_backup_manifest(marker, state, backup)
    module.write_backup_manifest(backup, manifest)
    module.write_backup_completion(backup)
    external_hash = module.file_sha256(backup / module.BACKUP_MANIFEST_NAME)
    shutil.rmtree(state)
    monkeypatch.setattr(module, "verify_source_frame", lambda *_a: manifest["source"])
    monkeypatch.setattr(staging, "_require_empty_restore_destination", lambda: None)
    monkeypatch.setattr(staging, "_create_volumes", lambda *_a: events.append("volumes-created"))
    monkeypatch.setattr(staging, "_restore_volume", lambda key, *_a: events.append(("restore-volume", key)))
    if fail:
        monkeypatch.setattr(staging, "control", lambda *_a: (_ for _ in ()).throw(module.CommandError("install interrupted")))
    def start():
        assert len([event for event in events if isinstance(event, tuple) and event[0] == "restore-volume"]) == len(module.BACKED_UP_VOLUME_KEYS)
        assert module.read_marker(state, staging.project)["lifecycle"] == "recovering"
        observed = tls.inspect_material(state / "seed", require_current=renew)
        assert (observed != old) is renew
        if renew:
            _handshake(state / "seed" / "ca.crt", state / "seed" / "mattermost.crt", state / "seed" / "mattermost.key", accepted=True)
        events.append("workload-start")
    monkeypatch.setattr(staging, "_start_restored_stack", start)
    monkeypatch.setattr(staging, "status", lambda **_kw: {"observed_at": datetime.now(UTC).isoformat()})
    if fail:
        with pytest.raises(module.SafetyError, match="controlled recovery"):
            staging.restore(backup, external_hash, renew_tls=renew)
        assert "workload-start" not in events
        assert module.read_marker(state, staging.project)["lifecycle"] == "recovering"
    else:
        staging.restore(backup, external_hash, renew_tls=renew)
        assert "workload-start" in events
    assert module.file_sha256(backup / module.BACKUP_MANIFEST_NAME) == external_hash


def _handshake(ca: Path, certificate: Path, key: Path, *, accepted: bool):
    server = ROOT / "tests" / "deployment" / "clinical-tls-drill" / "server.py"
    process = subprocess.Popen([sys.executable, str(server), str(certificate), str(key)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        ready = json.loads(process.stdout.readline())
        context = ssl.create_default_context(cafile=str(ca))
        import socket
        def query():
            with socket.create_connection(("127.0.0.1", ready["port"]), timeout=3) as raw:
                with context.wrap_socket(raw, server_hostname="127.0.0.1") as secured:
                    secured.sendall(b"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
                    assert b"200" in secured.recv(4096)
        if accepted:
            query()
        else:
            with pytest.raises(ssl.SSLCertVerificationError):
                query()
    finally:
        process.terminate()
        process.communicate(timeout=5)


def test_real_tls_process_rejects_expiry_and_old_trust_after_renewal(tmp_path, monkeypatch):
    module, tls, staging, state, events = staging_fixture(tmp_path, monkeypatch, expired=True)
    seed = state / "seed"
    old_ca = tmp_path / "old-ca.crt"
    old_ca.write_bytes((seed / "ca.crt").read_bytes())
    _handshake(old_ca, seed / "mattermost.crt", seed / "mattermost.key", accepted=False)
    staging.renew_tls()
    _handshake(seed / "ca.crt", seed / "mattermost.crt", seed / "mattermost.key", accepted=True)
    _handshake(old_ca, seed / "mattermost.crt", seed / "mattermost.key", accepted=False)


@pytest.mark.skipif(not hasattr(os, "getuid") or os.getuid() != 0, reason="real installer ownership requires isolated Linux root")
def test_real_installer_replays_partial_generation_and_preserves_unrelated_state(tmp_path, monkeypatch):
    module, tls, staging, state, events = staging_fixture(tmp_path, monkeypatch, expired=True)
    volumes = [tmp_path / name for name in ("mm", "hrh", "ingress")]
    for volume in volumes:
        volume.mkdir()
    policy = volumes[2] / "policy.json"
    policy.write_bytes(b"unchanged signed-policy bytes")
    original_atomic = tls._atomic_write
    writes = []
    def interrupted(path, raw, **kwargs):
        if path.parent in volumes:
            writes.append(path)
            if len(writes) == 3:
                raise tls.TlsError("simulated hard boundary interruption")
        return original_atomic(path, raw, **kwargs)
    def install(_command, expected):
        return json.dumps(tls.install_generation(state / "seed" / "tls-next", expected, *volumes))
    monkeypatch.setattr(staging, "control", install)
    monkeypatch.setattr(tls, "_atomic_write", interrupted)
    with pytest.raises(module.SafetyError):
        staging.renew_tls()
    assert module.read_marker(state, staging.project)["lifecycle"] == "tls_prepared"
    prepared_hashes = tls.inspect_material(state / "seed" / "tls-next")
    monkeypatch.setattr(tls, "_atomic_write", original_atomic)
    result = staging.renew_tls()
    assert result["material"] == prepared_hashes
    assert policy.read_bytes() == b"unchanged signed-policy bytes"
    assert {path.read_bytes() for path in (volumes[0] / "ca.crt", volumes[1] / "ca.crt", volumes[2] / "ca.crt")} == {(state / "seed" / "ca.crt").read_bytes()}
    _handshake(volumes[0] / "ca.crt", volumes[0] / "server.crt", volumes[0] / "server.key", accepted=True)
