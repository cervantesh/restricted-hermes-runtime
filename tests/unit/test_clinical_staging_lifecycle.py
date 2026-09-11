from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "deploy" / "clinical-staging" / "clinical_staging.py"


def load_module():
    spec = importlib.util.spec_from_file_location("clinical_staging", MODULE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_state_path_is_absolute_bounded_and_project_specific(tmp_path: Path):
    module = load_module()
    valid = tmp_path / "clinicalstagingdemo.synthetic-clinical-staging"
    assert module.validate_state_path(valid, "clinicalstagingdemo") == valid.resolve()

    for invalid in (
        Path("relative"),
        tmp_path,
        tmp_path / "wrong.synthetic-clinical-staging",
        ROOT,
    ):
        with pytest.raises(module.SafetyError):
            module.validate_state_path(invalid, "clinicalstagingdemo")


def test_clinical_staging_rejects_state_inside_either_build_context(tmp_path: Path):
    module = load_module()
    project = "clinicalstagingdemo"
    runtime = tmp_path / "runtime"
    hrh = tmp_path / "hrh"
    runtime.mkdir()
    hrh.mkdir()

    for build_context in (runtime, hrh):
        state = build_context / f"{project}.synthetic-clinical-staging"
        with pytest.raises(module.SafetyError, match="build context"):
            module.ClinicalStaging(runtime, hrh, state, project, 18443)


def test_compose_strips_host_clinical_environment_before_interpolation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    module = load_module()
    runtime, hrh = tmp_path / "runtime", tmp_path / "hrh"
    runtime.mkdir()
    hrh.mkdir()
    state = tmp_path / "clinicalstagingdemo.synthetic-clinical-staging"
    observed: dict[str, object] = {}

    class CapturingShell:
        def run(self, *args, **kwargs):
            observed["args"] = args
            observed["kwargs"] = kwargs
            return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setenv("CLINICAL_HRH_ROOT", "host-override-must-not-reach-compose")
    monkeypatch.setenv("CLINICAL_POLICY_PUBLIC_KEY", "host-override-must-not-reach-compose")
    monkeypatch.setenv("UNRELATED_OPERATOR_SETTING", "preserved")
    staging = module.ClinicalStaging(runtime, hrh, state, "clinicalstagingdemo", 18443, shell=CapturingShell())

    staging.compose("config", "--quiet")

    env = observed["kwargs"]["env"]
    assert "CLINICAL_HRH_ROOT" not in env
    assert "CLINICAL_POLICY_PUBLIC_KEY" not in env
    assert env["UNRELATED_OPERATOR_SETTING"] == "preserved"
    assert "--env-file" in observed["args"]
    assert str(state / "compose.env") in observed["args"]


def test_sealed_compose_environment_reaches_a_real_child_process(monkeypatch: pytest.MonkeyPatch):
    module = load_module()
    monkeypatch.setenv("CLINICAL_HRH_ROOT", "host-override-must-not-reach-child")
    monkeypatch.setenv("UNRELATED_OPERATOR_SETTING", "preserved")

    result = module.Shell().run(
        sys.executable,
        "-c",
        "import os; print(os.getenv('CLINICAL_HRH_ROOT')); print(os.getenv('UNRELATED_OPERATOR_SETTING'))",
        env=module.ClinicalStaging._sealed_compose_environment(),
    )

    assert result.stdout.splitlines() == ["None", "preserved"]


def test_marker_is_closed_and_binds_project_path_and_synthetic_purpose(tmp_path: Path):
    module = load_module()
    state = tmp_path / "clinicalstagingdemo.synthetic-clinical-staging"
    state.mkdir()
    marker = module.new_marker(
        project="clinicalstagingdemo",
        state_dir=state,
        state_id="1" * 32,
        env_sha256="2" * 64,
        runtime_head="a" * 40,
        runtime_tree="b" * 40,
        hrh_head=module.REQUIRED_HRH_SHA,
        hrh_tree="c" * 40,
    )
    module.write_json_atomic(state / module.MARKER_NAME, marker, mode=0o600)
    assert module.read_marker(state, "clinicalstagingdemo") == marker

    for key, value in (
        ("project", "clinicalstagingother"),
        ("state_dir", str(tmp_path / "elsewhere")),
        ("synthetic_only", False),
    ):
        changed = dict(marker)
        changed[key] = value
        (state / module.MARKER_NAME).write_text(json.dumps(changed), encoding="utf-8")
        with pytest.raises(module.SafetyError):
            module.read_marker(state, "clinicalstagingdemo")


@pytest.mark.skipif(os.name != "posix", reason="atomic marker ownership is Linux/POSIX-only")
def test_atomic_marker_write_recovers_legacy_temp_and_rejects_symlink(tmp_path: Path):
    module = load_module()
    marker = tmp_path / "staging-state.json"
    stale = marker.with_name(marker.name + ".tmp")
    first = {"phase": "first"}
    second = {"phase": "second"}

    stale.write_text('{"incomplete": true}\n', encoding="utf-8")
    stale.chmod(0o600)
    module.write_json_atomic(marker, first, mode=0o600)
    assert json.loads(marker.read_text(encoding="utf-8")) == first
    assert not stale.exists()

    sentinel = tmp_path / "must-not-remove"
    sentinel.write_text("retain", encoding="ascii")
    stale.symlink_to(sentinel)
    with pytest.raises(module.SafetyError, match="regular file"):
        module.write_json_atomic(marker, second, mode=0o600)
    assert sentinel.read_text(encoding="ascii") == "retain"
    assert stale.is_symlink()


def test_source_frame_requires_clean_runtime_ancestry_and_exact_clean_hrh(tmp_path: Path):
    module = load_module()
    runtime = tmp_path / "runtime"
    hrh = tmp_path / "hrh"
    runtime.mkdir()
    hrh.mkdir()

    class FakeGit:
        def __init__(self):
            self.values = {
                (runtime, "rev-parse", "HEAD"): "d" * 40,
                (runtime, "rev-parse", "HEAD^{tree}"): "e" * 40,
                (runtime, "status", "--porcelain=v1"): "",
                (hrh, "rev-parse", "HEAD"): module.REQUIRED_HRH_SHA,
                (hrh, "rev-parse", "HEAD^{tree}"): module.REQUIRED_HRH_TREE,
                (hrh, "status", "--porcelain=v1"): "",
            }
            self.ancestor = True

        def git(self, cwd: Path, *args: str) -> str:
            if args[:2] == ("merge-base", "--is-ancestor"):
                if not self.ancestor:
                    raise module.CommandError("not ancestor")
                return ""
            return self.values[(cwd, *args)]

    fake = FakeGit()
    frame = module.verify_source_frame(runtime, hrh, fake)
    assert frame == {
        "runtime_head": "d" * 40,
        "runtime_tree": "e" * 40,
        "hrh_head": module.REQUIRED_HRH_SHA,
        "hrh_tree": module.REQUIRED_HRH_TREE,
    }

    fake.values[(runtime, "status", "--porcelain=v1")] = " M file"
    with pytest.raises(module.SafetyError, match="runtime.*clean"):
        module.verify_source_frame(runtime, hrh, fake)
    fake.values[(runtime, "status", "--porcelain=v1")] = ""
    fake.values[(hrh, "rev-parse", "HEAD")] = "0" * 40
    with pytest.raises(module.SafetyError, match="HRH.*exact"):
        module.verify_source_frame(runtime, hrh, fake)
    fake.values[(hrh, "rev-parse", "HEAD")] = module.REQUIRED_HRH_SHA
    fake.values[(hrh, "rev-parse", "HEAD^{tree}")] = "0" * 40
    with pytest.raises(module.SafetyError, match="HRH tree"):
        module.verify_source_frame(runtime, hrh, fake)


def test_staging_source_frame_matches_composed_current_hrh_subject_and_rejects_previous_subject(
    tmp_path: Path,
):
    """The operator lifecycle and composed runner must bind one HRH source."""
    module = load_module()
    runtime = tmp_path / "runtime"
    hrh = tmp_path / "hrh"
    runtime.mkdir()
    hrh.mkdir()
    current_head = "ad13735e9881a48580a9e138daac137f8c865dea"
    current_tree = "f217b0b1cf7f438422528dfe178d81b78212c68b"
    previous_head = "89fea476ef95a0dfd3cd60a587ec6cb9e1d3aa1f"

    class FakeGit:
        def __init__(self, hrh_head: str, hrh_tree: str):
            self.values = {
                (runtime, "rev-parse", "HEAD"): "d" * 40,
                (runtime, "rev-parse", "HEAD^{tree}"): "e" * 40,
                (runtime, "status", "--porcelain=v1"): "",
                (hrh, "rev-parse", "HEAD"): hrh_head,
                (hrh, "rev-parse", "HEAD^{tree}"): hrh_tree,
                (hrh, "status", "--porcelain=v1"): "",
            }

        def git(self, cwd: Path, *args: str) -> str:
            if args[:2] == ("merge-base", "--is-ancestor"):
                return ""
            return self.values[(cwd, *args)]

    assert module.REQUIRED_HRH_SHA == current_head
    assert module.REQUIRED_HRH_TREE == current_tree
    runner = (ROOT / "tests" / "deployment" / "test_clinical_composed_e2e.py").read_text(encoding="utf-8")
    readme = (ROOT / "deploy" / "clinical-staging" / "README.md").read_text(encoding="utf-8")
    assert f'HRH_SHA = "{current_head}"' in runner
    assert f'HRH_TREE = "{current_tree}"' in runner
    assert current_head in readme
    assert previous_head not in readme
    assert module.verify_source_frame(runtime, hrh, FakeGit(current_head, current_tree))["hrh_head"] == current_head
    with pytest.raises(module.SafetyError, match="HRH.*exact"):
        module.verify_source_frame(runtime, hrh, FakeGit(previous_head, current_tree))


def test_destructive_volume_guard_rejects_missing_labels_and_unexpected_project_volume():
    module = load_module()
    project = "clinicalstagingdemo"
    state_id = "1" * 32
    expected = set(module.volume_names(project).values())
    labels = {
        name: {
            module.PROJECT_LABEL: project,
            module.STATE_LABEL: state_id,
            module.SYNTHETIC_LABEL: "true",
        }
        for name in expected
    }
    assert module.verify_destructive_volumes(project, state_id, expected, labels, "ready") == sorted(expected)

    labels[next(iter(expected))][module.SYNTHETIC_LABEL] = "false"
    with pytest.raises(module.SafetyError, match="label"):
        module.verify_destructive_volumes(project, state_id, expected, labels, "ready")

    labels[next(iter(expected))][module.SYNTHETIC_LABEL] = "true"
    labels[f"{project}_unexpected"] = {
        module.PROJECT_LABEL: project,
        module.STATE_LABEL: state_id,
        module.SYNTHETIC_LABEL: "true",
    }
    with pytest.raises(module.SafetyError, match="unexpected"):
        module.verify_destructive_volumes(project, state_id, expected, labels, "ready")


def test_partial_volume_set_is_cleanable_but_never_widens_the_allowlist():
    module = load_module()
    project = "clinicalstagingdemo"
    state_id = "1" * 32
    expected = set(module.volume_names(project).values())
    present = set(sorted(expected)[:3])
    labels = {
        name: {
            module.PROJECT_LABEL: project,
            module.STATE_LABEL: state_id,
            module.SYNTHETIC_LABEL: "true",
        }
        for name in present
    }
    assert module.verify_destructive_volumes(project, state_id, expected, labels, "initializing") == sorted(present)
    for lifecycle in ("ready", "stopped"):
        with pytest.raises(module.SafetyError, match="exact volume set"):
            module.verify_destructive_volumes(project, state_id, expected, labels, lifecycle)


def test_marker_rejects_any_compose_environment_byte_change(tmp_path: Path):
    module = load_module()
    state = tmp_path / "clinicalstagingdemo.synthetic-clinical-staging"
    state.mkdir()
    env = state / "compose.env"
    env.write_bytes(b"A=one\n")
    marker = module.new_marker(
        project="clinicalstagingdemo",
        state_dir=state,
        state_id="1" * 32,
        env_sha256=module.file_sha256(env),
        runtime_head="a" * 40,
        runtime_tree="b" * 40,
        hrh_head=module.REQUIRED_HRH_SHA,
        hrh_tree=module.REQUIRED_HRH_TREE,
    )
    module.write_json_atomic(state / module.MARKER_NAME, marker, mode=0o600)
    module.verify_effective_env(state, marker)
    env.write_bytes(b"A=two\n")
    with pytest.raises(module.SafetyError, match="compose.env"):
        module.verify_effective_env(state, marker)


def test_destructive_resource_guard_covers_containers_and_networks():
    module = load_module()
    project = "clinicalstagingdemo"
    state_id = "1" * 32
    required = {
        module.PROJECT_LABEL: project,
        module.STATE_LABEL: state_id,
        module.SYNTHETIC_LABEL: "true",
    }
    containers = {f"{project}-ingress-1": {**required, "com.docker.compose.service": "ingress"}}
    networks = {f"{project}_mattermost_edge": required}
    assert module.verify_destructive_resources(
        project, state_id, containers, networks, "initializing"
    ) == (sorted(containers), sorted(networks))
    containers[f"{project}-unknown-1"] = {**required, "com.docker.compose.service": "unknown"}
    with pytest.raises(module.SafetyError, match="container"):
        module.verify_destructive_resources(project, state_id, containers, networks, "initializing")


def test_ready_resource_guard_requires_exact_services_once_and_exact_networks():
    module = load_module()
    project = "clinicalstagingdemo"
    state_id = "1" * 32
    required = {
        module.PROJECT_LABEL: project,
        module.STATE_LABEL: state_id,
        module.SYNTHETIC_LABEL: "true",
    }
    expected_services = (*module.LONG_RUNNING_SERVICES, *module.ONE_SHOT_SERVICES)
    containers = {
        f"{project}-{service}-1": {**required, "com.docker.compose.service": service}
        for service in expected_services
    }
    networks = {f"{project}_{key}": required for key in module.NETWORK_KEYS}
    module.verify_destructive_resources(project, state_id, containers, networks, "ready")

    missing = dict(containers)
    missing.pop(next(iter(missing)))
    with pytest.raises(module.SafetyError, match="exact service set"):
        module.verify_destructive_resources(project, state_id, missing, networks, "ready")

    duplicate = dict(containers)
    duplicate[f"{project}-ingress-2"] = {
        **required,
        "com.docker.compose.service": "ingress",
    }
    with pytest.raises(module.SafetyError, match="duplicate"):
        module.verify_destructive_resources(project, state_id, duplicate, networks, "ready")

    with_controller = dict(containers)
    with_controller[f"{project}-controller-1"] = {
        **required,
        "com.docker.compose.service": "controller",
    }
    with pytest.raises(module.SafetyError, match="controller"):
        module.verify_destructive_resources(project, state_id, with_controller, networks, "ready")

    subset_networks = dict(networks)
    subset_networks.pop(next(iter(subset_networks)))
    with pytest.raises(module.SafetyError, match="exact network set"):
        module.verify_destructive_resources(project, state_id, containers, subset_networks, "stopped")


def test_initializing_resource_guard_rejects_duplicate_service_containers():
    module = load_module()
    project = "clinicalstagingdemo"
    state_id = "1" * 32
    required = {
        module.PROJECT_LABEL: project,
        module.STATE_LABEL: state_id,
        module.SYNTHETIC_LABEL: "true",
    }
    containers = {
        f"{project}-ingress-1": {**required, "com.docker.compose.service": "ingress"},
        f"{project}-ingress-2": {**required, "com.docker.compose.service": "ingress"},
    }
    with pytest.raises(module.SafetyError, match="duplicate"):
        module.verify_destructive_resources(project, state_id, containers, {}, "initializing")


def test_labeled_container_resources_read_nested_config_labels(tmp_path: Path):
    module = load_module()
    project = "clinicalstagingdemo"
    required = {
        module.PROJECT_LABEL: project,
        module.STATE_LABEL: "1" * 32,
        module.SYNTHETIC_LABEL: "true",
        "com.docker.compose.service": "ingress",
    }

    class FakeShell:
        def run(self, *args, **_kwargs):
            if args[:4] == ("docker", "container", "ls", "--all"):
                return SimpleNamespace(stdout="container-id\n", returncode=0)
            if args[:3] == ("docker", "container", "inspect"):
                return SimpleNamespace(
                    stdout=json.dumps([{"Name": "/clinicalstagingdemo-ingress-1", "Config": {"Labels": required}}]),
                    returncode=0,
                )
            raise AssertionError(args)

    runtime = tmp_path / "runtime"
    hrh = tmp_path / "hrh"
    runtime.mkdir()
    hrh.mkdir()
    state = tmp_path / f"{project}.synthetic-clinical-staging"
    staging = module.ClinicalStaging(runtime, hrh, state, project, 18443, shell=FakeShell())
    assert staging._labeled_resources("container") == {
        "clinicalstagingdemo-ingress-1": required
    }


def _restricted_control_inspections():
    return {
        "clinical-adapter": {
            "Config": {"User": "restricted-clinical-adapter"},
            "HostConfig": {
                "Privileged": False,
                "ReadonlyRootfs": True,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges=true"],
                "Tmpfs": {"/tmp": "rw,noexec,nosuid,size=16m,mode=0700,uid=10008,gid=20007"},
            },
            "Mounts": [
                {"Destination": "/run/restricted-clinical", "RW": True},
                {"Destination": "/run/clinical-config", "RW": False},
                {"Destination": "/run/hrh-secret", "RW": False},
                {"Destination": "/run/hrh-tls", "RW": False},
            ],
        },
        "ingress": {
            "Config": {"User": "restricted-mattermost-ingress"},
            "HostConfig": {
                "Privileged": False,
                "ReadonlyRootfs": True,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges=true"],
                "Tmpfs": {"/tmp": "rw,noexec,nosuid,size=16m,mode=0700,uid=10007,gid=20005"},
            },
            "Mounts": [
                {"Destination": "/run/restricted-clinical", "RW": True},
                {"Destination": "/run/ingress", "RW": False},
                {"Destination": "/var/lib/restricted-mattermost-outbox", "RW": True},
            ],
        },
    }


def _publisher_inspections(module, port: str = "18443"):
    def expected():
        return {"18444/tcp": [{"HostIp": "127.0.0.1", "HostPort": port}]}

    result = {
        service: {
            "Id": f"id-{service}",
            "State": {"StartedAt": "2026-09-06T15:00:00.000000000Z"},
            "HostConfig": {"PortBindings": expected() if service == "operator-proxy" else {}},
            "NetworkSettings": {"Ports": expected() if service == "operator-proxy" else {}},
        }
        for service in module.LONG_RUNNING_SERVICES
    }
    for service, controls in _restricted_control_inspections().items():
        result[service]["Config"] = controls["Config"]
        result[service]["HostConfig"].update(controls["HostConfig"])
        result[service]["Mounts"] = controls["Mounts"]
    return result


def _compose_rows(module):
    rows = [
        {"Service": service, "State": "running", "ExitCode": 0, "ID": f"id-{service}"}
        for service in module.LONG_RUNNING_SERVICES
    ]
    rows.extend(
        {"Service": service, "State": "exited", "ExitCode": 0, "ID": f"id-{service}"}
        for service in module.ONE_SHOT_SERVICES
    )
    return rows


def test_compose_rows_require_exact_running_and_successful_one_shot_set():
    module = load_module()
    rows = _compose_rows(module)
    module.verify_compose_rows(rows)

    with_unknown = [*rows, {"Service": "unknown", "State": "running", "ExitCode": 0}]
    with pytest.raises(module.SafetyError, match="exact Compose service set"):
        module.verify_compose_rows(with_unknown)

    duplicate = [*rows, dict(rows[0])]
    with pytest.raises(module.SafetyError, match="duplicate"):
        module.verify_compose_rows(duplicate)

    failed = [dict(row) for row in rows]
    failed[-1]["ExitCode"] = 1
    with pytest.raises(module.SafetyError, match="one-shot.*successfully"):
        module.verify_compose_rows(failed)


def test_publisher_guard_requires_effective_loopback_and_rejects_wildcard_or_nonproxy():
    module = load_module()
    inspected = _publisher_inspections(module)
    inspected["operator-proxy"]["NetworkSettings"]["Ports"]["80/tcp"] = None
    assert module.verify_publishers(inspected, 18443)["effective"] == {
        "container_port": "18444/tcp",
        "host_ip": "127.0.0.1",
        "host_port": "18443",
    }

    inspected["operator-proxy"]["NetworkSettings"]["Ports"] = None
    with pytest.raises(module.SafetyError, match="effective"):
        module.verify_publishers(inspected, 18443)
    inspected = _publisher_inspections(module)
    inspected["operator-proxy"]["NetworkSettings"]["Ports"]["18444/tcp"][0]["HostIp"] = "0.0.0.0"
    with pytest.raises(module.SafetyError, match="effective"):
        module.verify_publishers(inspected, 18443)
    inspected = _publisher_inspections(module)
    inspected["operator-proxy"]["NetworkSettings"]["Ports"]["80/tcp"] = [
        {"HostIp": "127.0.0.1", "HostPort": "18080"}
    ]
    with pytest.raises(module.SafetyError, match="effective"):
        module.verify_publishers(inspected, 18443)
    inspected = _publisher_inspections(module)
    inspected["operator-proxy"]["NetworkSettings"]["Ports"]["18444/tcp"].append(
        {"HostIp": "127.0.0.1", "HostPort": "18444"}
    )
    with pytest.raises(module.SafetyError, match="effective"):
        module.verify_publishers(inspected, 18443)
    inspected = _publisher_inspections(module)
    inspected["hrh"]["NetworkSettings"]["Ports"] = {
        "8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18080"}]
    }
    with pytest.raises(module.SafetyError, match="non-proxy.*effective"):
        module.verify_publishers(inspected, 18443)
    inspected = _publisher_inspections(module)
    inspected["mattermost"]["NetworkSettings"]["Ports"] = {"8065/tcp": None}
    module.verify_publishers(inspected, 18443)


def test_network_guard_requires_internal_core_and_proxy_only_access():
    module = load_module()
    project = "clinicalstagingdemo"
    inspected = _publisher_inspections(module)
    access = f"{project}_operator_access"
    for service, keys in module.EXPECTED_NETWORK_KEYS_BY_SERVICE.items():
        inspected[service]["NetworkSettings"]["Networks"] = {
            f"{project}_{key}": {} for key in keys
        }
    networks = {
        f"{project}_{key}": {
            "Internal": key != "operator_access",
            "Containers": ({"id-operator-proxy": {}} if key == "operator_access" else {}),
        }
        for key in module.NETWORK_KEYS
    }
    module.verify_network_topology(project, inspected, networks)

    networks[f"{project}_mattermost_edge"]["Internal"] = False
    with pytest.raises(module.SafetyError, match="internal"):
        module.verify_network_topology(project, inspected, networks)
    networks[f"{project}_mattermost_edge"]["Internal"] = True
    networks[access]["Containers"]["id-ingress"] = {}
    with pytest.raises(module.SafetyError, match="proxy"):
        module.verify_network_topology(project, inspected, networks)

    networks[access]["Containers"].pop("id-ingress")
    inspected["ingress"]["NetworkSettings"]["Networks"]["bridge"] = {}
    with pytest.raises(module.SafetyError, match="ingress.*network membership"):
        module.verify_network_topology(project, inspected, networks)


def test_restricted_container_guard_requires_exact_effective_confinement():
    module = load_module()
    inspected = _restricted_control_inspections()
    evidence = module.verify_restricted_container_controls(inspected)
    assert evidence["ingress"] == {
        "user": "restricted-mattermost-ingress",
        "privileged": False,
        "read_only_rootfs": True,
        "cap_drop": ["ALL"],
        "no_new_privileges": True,
        "tmpfs": ["/tmp"],
        "read_only_mounts": ["/run/ingress"],
        "writable_mounts": ["/run/restricted-clinical", "/var/lib/restricted-mattermost-outbox"],
    }

    mutations = (
        ("ingress", "Config", "User", "root"),
        ("ingress", "HostConfig", "Privileged", True),
        ("ingress", "HostConfig", "ReadonlyRootfs", False),
        ("ingress", "HostConfig", "CapDrop", []),
        ("ingress", "HostConfig", "CapAdd", ["NET_ADMIN"]),
        ("ingress", "HostConfig", "SecurityOpt", []),
        ("ingress", "HostConfig", "Tmpfs", {"/tmp": "rw,noexec,nosuid,size=16m,size=1g,mode=0700,uid=10007,gid=20005"}),
    )
    for service, section, key, value in mutations:
        changed = json.loads(json.dumps(inspected))
        changed[service][section][key] = value
        with pytest.raises(module.SafetyError, match=service):
            module.verify_restricted_container_controls(changed)

    changed = json.loads(json.dumps(inspected))
    changed["clinical-adapter"]["Mounts"][2]["RW"] = True
    with pytest.raises(module.SafetyError, match="clinical-adapter"):
        module.verify_restricted_container_controls(changed)
    for tmpfs in (
        "rw,noexec,exec,nosuid,size=16m,mode=0700,uid=10007,gid=20005",
        "rw,noexec,nosuid,suid,size=16m,mode=0700,uid=10007,gid=20005",
        "rw,noexec,nosuid,size=16m,mode=0700,mode=0777,uid=10007,gid=20005",
    ):
        changed = json.loads(json.dumps(inspected))
        changed["ingress"]["HostConfig"]["Tmpfs"] = {"/tmp": tmpfs}
        with pytest.raises(module.SafetyError, match="ingress"):
            module.verify_restricted_container_controls(changed)


def test_restricted_process_identity_guard_rejects_live_privilege_or_group_drift():
    module = load_module()
    identities = {
        service: {
            "uid": expected["uid"],
            "gid": expected["gid"],
            "groups": expected["groups"],
        }
        for service, expected in module.RESTRICTED_CONTAINER_CONTROLS.items()
    }
    assert module.verify_restricted_process_identities(identities) == identities
    for field, value in (("uid", 0), ("gid", 0), ("groups", [0])):
        changed = json.loads(json.dumps(identities))
        changed["ingress"][field] = value
        with pytest.raises(module.SafetyError, match="ingress"):
            module.verify_restricted_process_identities(changed)


def test_generated_mattermost_certificate_covers_dns_and_advertised_loopback_ip(tmp_path: Path):
    module = load_module()
    seed = tmp_path / "seed"
    seed.mkdir()
    module._certificate_material(seed)
    certificate = module.x509.load_pem_x509_certificate((seed / "mattermost.crt").read_bytes())
    san = certificate.extensions.get_extension_for_class(module.x509.SubjectAlternativeName).value
    assert san.get_values_for_type(module.x509.DNSName) == ["mattermost"]
    assert [str(value) for value in san.get_values_for_type(module.x509.IPAddress)] == ["127.0.0.1"]


def test_host_tls_probe_fails_closed_on_connection_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    module = load_module()
    runtime = tmp_path / "runtime"
    hrh = tmp_path / "hrh"
    state = tmp_path / "clinicalstagingdemo.synthetic-clinical-staging"
    runtime.mkdir()
    hrh.mkdir()
    state.mkdir()
    staging = module.ClinicalStaging(runtime, hrh, state, "clinicalstagingdemo", 18443)
    monkeypatch.setattr(module.ssl, "create_default_context", lambda **_kwargs: object())
    monkeypatch.setattr(
        module.socket,
        "create_connection",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("refused")),
    )
    with pytest.raises(module.SafetyError, match="CA-verified TLS probe failed"):
        staging._probe_mattermost_tls()


def test_prepared_state_env_points_to_seed_after_atomic_rename(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    module = load_module()
    runtime = tmp_path / "runtime"
    hrh = tmp_path / "hrh"
    runtime.mkdir()
    hrh.mkdir()
    state = tmp_path / "clinicalstagingdemo.synthetic-clinical-staging"
    staging = module.ClinicalStaging(runtime, hrh, state, "clinicalstagingdemo", 18443)
    monkeypatch.setattr(module, "fsync_directory", lambda _path: None)
    frame = {
        "runtime_head": "a" * 40,
        "runtime_tree": "b" * 40,
        "hrh_head": module.REQUIRED_HRH_SHA,
        "hrh_tree": module.REQUIRED_HRH_TREE,
    }

    staging._prepare_new_state(frame)

    env = dict(
        line.split("=", 1)
        for line in staging.env_file.read_text(encoding="utf-8").splitlines()
    )
    assert Path(env["CLINICAL_SEED"]) == state / "seed"
    assert Path(env["CLINICAL_SEED"]).is_dir()


def test_image_build_orders_local_base_images_before_their_consumers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    module = load_module()
    runtime = tmp_path / "runtime"
    hrh = tmp_path / "hrh"
    state = tmp_path / "clinicalstagingdemo.synthetic-clinical-staging"
    runtime.mkdir()
    hrh.mkdir()
    staging = module.ClinicalStaging(runtime, hrh, state, "clinicalstagingdemo", 18443)
    calls: list[tuple[tuple[str, ...], dict]] = []
    monkeypatch.setattr(
        staging,
        "compose",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    staging._build_images()

    assert calls == [
        (("build", "ingress", "clinical-adapter"), {"timeout": 2400}),
        (("build", "controller", "hrh-migrate", "hrh"), {"timeout": 2400}),
    ]


def test_project_name_is_narrow_and_cannot_target_an_unrelated_compose_project():
    module = load_module()
    assert module.validate_project("clinicalstagingdemo") == "clinicalstagingdemo"
    for invalid in ("clinical", "prod", "clinicalstaging-demo", "clinicalstaging", "Clinicalstagingx"):
        with pytest.raises(module.SafetyError):
            module.validate_project(invalid)


def test_nonzero_compose_down_preserves_marker_state_and_volumes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    module = load_module()
    project = "clinicalstagingdemo"
    runtime = tmp_path / "runtime"
    hrh = tmp_path / "hrh"
    runtime.mkdir()
    hrh.mkdir()
    state = tmp_path / f"{project}.synthetic-clinical-staging"
    state.mkdir()
    env = state / "compose.env"
    env.write_bytes(b"SEALED=true\n")
    marker = module.new_marker(
        project=project,
        state_dir=state,
        state_id="1" * 32,
        env_sha256=module.file_sha256(env),
        runtime_head="a" * 40,
        runtime_tree="b" * 40,
        hrh_head=module.REQUIRED_HRH_SHA,
        hrh_tree=module.REQUIRED_HRH_TREE,
    )
    module.write_json_atomic(state / module.MARKER_NAME, marker, mode=0o600)

    staging = module.ClinicalStaging(runtime, hrh, state, project, 18443)
    monkeypatch.setattr(staging, "_verify_marker_and_source", lambda: marker)
    labels = {
        name: {
            module.PROJECT_LABEL: project,
            module.STATE_LABEL: marker["state_id"],
            module.SYNTHETIC_LABEL: "true",
        }
        for name in marker["volumes"].values()
    }
    monkeypatch.setattr(staging, "_volume_labels", lambda: labels)
    monkeypatch.setattr(staging, "_labeled_resources", lambda _kind: {})
    monkeypatch.setattr(
        staging,
        "compose",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(module.CommandError("down failed")),
    )
    removed: list[str] = []
    monkeypatch.setattr(staging.shell, "run", lambda *args, **_kwargs: removed.append(" ".join(args)))

    with pytest.raises(module.CommandError, match="down failed"):
        staging._destroy_resources()
    assert (state / module.MARKER_NAME).exists()
    assert removed == []


def test_status_requires_exact_images_and_sole_loopback_publisher(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    module = load_module()
    project = "clinicalstagingdemo"
    runtime = tmp_path / "runtime"
    hrh = tmp_path / "hrh"
    runtime.mkdir()
    hrh.mkdir()
    state = tmp_path / f"{project}.synthetic-clinical-staging"
    (state / "evidence").mkdir(parents=True)
    expected_images = {service: f"sha256:{index:064x}" for index, service in enumerate(module.LONG_RUNNING_SERVICES, 1)}
    marker = {
        "state_id": "1" * 32,
        "lifecycle": "ready",
        "compose_env_sha256": "3" * 64,
        "runtime_head": "a" * 40,
        "runtime_tree": "b" * 40,
        "hrh_head": module.REQUIRED_HRH_SHA,
        "hrh_tree": module.REQUIRED_HRH_TREE,
        "expected_images": expected_images,
    }
    staging = module.ClinicalStaging(runtime, hrh, state, project, 18443)
    monkeypatch.setattr(staging, "_require_linux", lambda: None)
    monkeypatch.setattr(staging, "_verify_marker_and_source", lambda: marker)
    rows = _compose_rows(module)
    monkeypatch.setattr(staging, "_containers", lambda **_kwargs: rows)
    controller_checks: list[str] = []
    monkeypatch.setattr(staging, "_labeled_resources", lambda _kind: {})
    monkeypatch.setattr(staging, "_assert_no_controller", lambda: controller_checks.append("checked"))
    inspections = _publisher_inspections(module)
    for service, keys in module.EXPECTED_NETWORK_KEYS_BY_SERVICE.items():
        inspections[service]["NetworkSettings"]["Networks"] = {
            f"{project}_{key}": {} for key in keys
        }
    all_inspections = {
        **inspections,
        **{
            service: {
                "Id": f"id-{service}",
                "HostConfig": {"PortBindings": {}},
                "NetworkSettings": {"Ports": {}, "Networks": {}},
            }
            for service in module.ONE_SHOT_SERVICES
        },
    }
    monkeypatch.setattr(staging, "_container_inspections", lambda: all_inspections)
    networks = {
        f"{project}_{key}": {
            "Internal": key != "operator_access",
            "Containers": ({"id-operator-proxy": {}} if key == "operator_access" else {}),
        }
        for key in module.NETWORK_KEYS
    }
    monkeypatch.setattr(staging, "_network_inspections", lambda: networks)
    tls_probe = {"verified": True, "hostname": "127.0.0.1", "path": "/api/v4/system/ping"}
    monkeypatch.setattr(staging, "_probe_mattermost_tls", lambda: tls_probe)
    ingress_log_calls: list[tuple[str, ...]] = []

    def fake_compose(*args, **_kwargs):
        if args[:2] == ("logs", "--no-color"):
            ingress_log_calls.append(args)
            return SimpleNamespace(stdout="mattermost_ingress_outcome=authenticated_ready\n", returncode=0)
        if args[:3] == ("exec", "--no-TTY", "clinical-adapter") and "os.getuid()" in args[-1]:
            return SimpleNamespace(stdout=json.dumps({"uid": 10008, "gid": 20007, "groups": [20006, 20007]}), returncode=0)
        if args[:3] == ("exec", "--no-TTY", "ingress") and "os.getuid()" in args[-1]:
            return SimpleNamespace(stdout=json.dumps({"uid": 10007, "gid": 20005, "groups": [20000, 20001, 20005, 20006]}), returncode=0)
        return SimpleNamespace(
            stdout=json.dumps({"uid": 10008, "gid": 20006, "mode": 0o660, "socket": True}),
            returncode=0,
        )

    monkeypatch.setattr(staging, "compose", fake_compose)
    policy_controls: list[str] = []

    def control(command, *_args):
        policy_controls.append(command)
        return "2" * 64 if command in {"policy-digest", "policy-live"} else ""

    monkeypatch.setattr(staging, "control", control)
    monkeypatch.setattr(
        module,
        "write_json_atomic",
        lambda *_args, **_kwargs: (
            None if len(controller_checks) == 2 else pytest.fail("receipt written before final controller check")
        ),
    )

    monkeypatch.setattr(staging, "_built_images", lambda: {**expected_images, "hrh": "sha256:" + "f" * 64})
    with pytest.raises(module.SafetyError, match="image identities"):
        staging.status()

    controller_checks.clear()
    ingress_log_calls.clear()
    monkeypatch.setattr(staging, "_built_images", lambda: expected_images)
    result = staging.status()
    assert result["built_images"] == expected_images
    assert result["compose_env_sha256"] == marker["compose_env_sha256"]
    assert result["mattermost_publisher"] == {
        "requested": {
            "container_port": "18444/tcp",
            "host_ip": "127.0.0.1",
            "host_port": "18443",
        },
        "effective": {
            "container_port": "18444/tcp",
            "host_ip": "127.0.0.1",
            "host_port": "18443",
        },
    }
    assert result["tls_probe"] == tls_probe
    assert result["network_exception"] == "operator-proxy only: operator_access is non-internal"
    assert result["restricted_process_identities"]["ingress"]["uid"] == 10007
    assert result["ingress_started_at"] == "2026-09-06T15:00:00.000000000Z"
    assert "policy-live" in policy_controls
    assert ingress_log_calls == [
        (
            "logs",
            "--no-color",
            "--since",
            "2026-09-06T15:00:00.000000000Z",
            "ingress",
        )
    ]

    inspections["ingress"]["State"] = {}
    with pytest.raises(module.SafetyError, match="ingress start time"):
        staging.status()
    inspections["ingress"]["State"] = {
        "StartedAt": "2026-09-06T15:00:00.000000000Z"
    }

    inspections["hrh"]["HostConfig"]["PortBindings"] = {"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "18080"}]}
    with pytest.raises(module.SafetyError, match="non-proxy"):
        staging.status()

    inspections["hrh"]["HostConfig"]["PortBindings"] = {}
    monkeypatch.setattr(
        staging,
        "_probe_mattermost_tls",
        lambda: (_ for _ in ()).throw(module.SafetyError("TLS probe failed")),
    )
    with pytest.raises(module.SafetyError, match="TLS probe"):
        staging.status()


@pytest.mark.parametrize("command", ("up", "status", "refresh_policy", "stop"))
def test_operational_commands_reject_initializing_marker_before_compose(
    command: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    module = load_module()
    runtime = tmp_path / "runtime"
    hrh = tmp_path / "hrh"
    state = tmp_path / "clinicalstagingdemo.synthetic-clinical-staging"
    runtime.mkdir()
    hrh.mkdir()
    state.mkdir()
    staging = module.ClinicalStaging(runtime, hrh, state, "clinicalstagingdemo", 18443)
    monkeypatch.setattr(staging, "_require_linux", lambda: None)
    monkeypatch.setattr(staging, "_verify_marker_and_source", lambda: {"lifecycle": "initializing"})
    monkeypatch.setattr(
        staging,
        "compose",
        lambda *_args, **_kwargs: pytest.fail("Compose must not run for an initializing marker"),
    )

    with pytest.raises(module.SafetyError, match="lifecycle"):
        getattr(staging, command)("clinical-e2") if command == "refresh_policy" else getattr(staging, command)()


@pytest.mark.skipif(os.name != "posix", reason="owned initialization recovery is Linux/POSIX-only")
def test_initialization_recovery_removes_only_owned_pre_rename_state(tmp_path: Path):
    module = load_module()
    runtime, hrh = tmp_path / "runtime", tmp_path / "hrh"
    runtime.mkdir()
    hrh.mkdir()
    state = tmp_path / "clinicalstagingdemo.synthetic-clinical-staging"
    orphan = tmp_path / ".clinicalstagingdemo.synthetic-clinical-staging.init-0123456789abcdef"
    orphan.mkdir(mode=0o700)
    (orphan / "seed").mkdir(mode=0o700)
    (orphan / "seed" / "admin_password").write_text("synthetic", encoding="ascii")
    staging = module.ClinicalStaging(runtime, hrh, state, "clinicalstagingdemo", 18443)

    staging._reconcile_owned_initialization_orphans()

    assert not orphan.exists()


@pytest.mark.skipif(os.name != "posix", reason="owned initialization recovery is Linux/POSIX-only")
def test_new_state_preparation_recovers_owned_remnant_before_creating_new_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    module = load_module()
    runtime, hrh = tmp_path / "runtime", tmp_path / "hrh"
    runtime.mkdir()
    hrh.mkdir()
    state = tmp_path / "clinicalstagingdemo.synthetic-clinical-staging"
    orphan = tmp_path / ".clinicalstagingdemo.synthetic-clinical-staging.init-0123456789abcdef"
    orphan.mkdir(mode=0o700)
    (orphan / "seed").mkdir(mode=0o700)
    (orphan / "seed" / "admin_password").write_text("synthetic", encoding="ascii")
    staging = module.ClinicalStaging(runtime, hrh, state, "clinicalstagingdemo", 18443)
    monkeypatch.setattr(staging, "_seed_material", lambda root: (root / "seed").mkdir(mode=0o700))
    monkeypatch.setattr(staging, "_env_values", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(staging, "_env_bytes", lambda _values: b"")

    marker = staging._prepare_new_state({
        "runtime_head": "a" * 40,
        "runtime_tree": "b" * 40,
        "hrh_head": module.REQUIRED_HRH_SHA,
        "hrh_tree": module.REQUIRED_HRH_TREE,
    })

    assert marker["state_dir"] == str(state)
    assert state.is_dir()
    assert not orphan.exists()


@pytest.mark.skipif(os.name != "posix", reason="owned initialization recovery is Linux/POSIX-only")
def test_initialization_recovery_fails_closed_on_symlinked_remnant(tmp_path: Path):
    module = load_module()
    runtime, hrh = tmp_path / "runtime", tmp_path / "hrh"
    runtime.mkdir()
    hrh.mkdir()
    state = tmp_path / "clinicalstagingdemo.synthetic-clinical-staging"
    orphan = tmp_path / ".clinicalstagingdemo.synthetic-clinical-staging.init-0123456789abcdef"
    target = tmp_path / "must-not-remove"
    orphan.mkdir(mode=0o700)
    target.write_text("retain", encoding="ascii")
    (orphan / "unexpected-link").symlink_to(target)
    staging = module.ClinicalStaging(runtime, hrh, state, "clinicalstagingdemo", 18443)

    with pytest.raises(module.SafetyError, match="symlink"):
        staging._reconcile_owned_initialization_orphans()

    assert orphan.exists()
    assert target.read_text(encoding="ascii") == "retain"


@pytest.mark.skipif(os.name != "posix", reason="the production lifecycle lock is Linux/POSIX-only")
def test_lifecycle_lock_blocks_a_second_operator_process(tmp_path: Path):
    module = load_module()
    runtime, hrh = tmp_path / "runtime", tmp_path / "hrh"
    runtime.mkdir()
    hrh.mkdir()
    state = tmp_path / "clinicalstagingdemo.synthetic-clinical-staging"
    released = tmp_path / "second-entered"
    staging = module.ClinicalStaging(runtime, hrh, state, "clinicalstagingdemo", 18443)
    child = """
import importlib.util
import pathlib
import sys
spec = importlib.util.spec_from_file_location('clinical_staging_child', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
staging = module.ClinicalStaging(pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3]), pathlib.Path(sys.argv[4]), 'clinicalstagingdemo', 18443)
with staging._lifecycle_lock():
    pathlib.Path(sys.argv[5]).write_text('entered', encoding='ascii')
"""

    with staging._lifecycle_lock():
        process = subprocess.Popen(
            [sys.executable, "-c", child, str(MODULE_PATH), str(runtime), str(hrh), str(state), str(released)],
        )
        time.sleep(0.15)
        assert not released.exists(), "second lifecycle process entered while the first held the state lock"
    assert process.wait(timeout=5) == 0
    assert released.read_text(encoding="ascii") == "entered"


def test_lifecycle_lock_does_not_treat_another_thread_as_nested(tmp_path: Path):
    module = load_module()
    runtime, hrh = tmp_path / "runtime", tmp_path / "hrh"
    runtime.mkdir()
    hrh.mkdir()
    state = tmp_path / "clinicalstagingdemo.synthetic-clinical-staging"
    staging = module.ClinicalStaging(runtime, hrh, state, "clinicalstagingdemo", 18443)
    first_entered = threading.Event()
    release_first = threading.Event()
    second_entered = threading.Event()

    def first() -> None:
        with staging._lifecycle_lock():
            first_entered.set()
            assert release_first.wait(timeout=5)

    def second() -> None:
        assert first_entered.wait(timeout=5)
        with staging._lifecycle_lock():
            second_entered.set()

    first_thread = threading.Thread(target=first)
    second_thread = threading.Thread(target=second)
    first_thread.start()
    assert first_entered.wait(timeout=5)
    second_thread.start()
    time.sleep(0.1)
    assert not second_entered.is_set(), "another thread bypassed the lifecycle lock as a nested call"
    release_first.set()
    first_thread.join(timeout=5)
    second_thread.join(timeout=5)
    assert not first_thread.is_alive()
    assert not second_thread.is_alive()
    assert second_entered.is_set()


def test_stop_failure_preserves_ready_marker_and_transition_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    module = load_module()
    runtime = tmp_path / "runtime"
    hrh = tmp_path / "hrh"
    state = tmp_path / "clinicalstagingdemo.synthetic-clinical-staging"
    evidence = state / "evidence"
    runtime.mkdir()
    hrh.mkdir()
    evidence.mkdir(parents=True)
    marker = {"lifecycle": "ready", "state_id": "1" * 32}
    previous = b'{"lifecycle":"ready"}\n'
    transition = evidence / "last-transition.json"
    transition.write_bytes(previous)
    staging = module.ClinicalStaging(runtime, hrh, state, "clinicalstagingdemo", 18443)
    monkeypatch.setattr(staging, "_require_linux", lambda: None)
    monkeypatch.setattr(staging, "_verify_marker_and_source", lambda: marker)
    monkeypatch.setattr(
        staging,
        "compose",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=1, stdout="", stderr="stop failed"),
    )
    writes: list[dict] = []
    monkeypatch.setattr(staging, "_write_marker", lambda value: writes.append(dict(value)))

    with pytest.raises(module.CommandError, match="stop"):
        staging.stop()
    assert marker["lifecycle"] == "ready"
    assert writes == []
    assert transition.read_bytes() == previous
