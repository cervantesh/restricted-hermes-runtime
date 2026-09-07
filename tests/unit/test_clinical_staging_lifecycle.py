from __future__ import annotations

import importlib.util
import json
import shutil
import tarfile
from pathlib import Path
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
    assert module.verify_destructive_volumes(project, state_id, expected, labels, "recovering") == sorted(present)
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


def _restricted_control_inspections():
    return {
        "clinical-adapter": {
            "Config": {"User": "restricted-clinical-adapter"},
            "HostConfig": {
                "Privileged": False,
                "ReadonlyRootfs": True,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges=true"],
                "Tmpfs": {
                    "/tmp": "rw,noexec,nosuid,size=16m,mode=0700,uid=10008,gid=20007",
                },
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
                "Tmpfs": {
                    "/tmp": "rw,noexec,nosuid,size=16m,mode=0700,uid=10007,gid=20005",
                },
            },
            "Mounts": [
                {"Destination": "/run/restricted-clinical", "RW": True},
                {"Destination": "/run/ingress", "RW": False},
                {"Destination": "/var/lib/restricted-mattermost-outbox", "RW": True},
            ],
        },
    }


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
        "writable_mounts": [
            "/run/restricted-clinical",
            "/var/lib/restricted-mattermost-outbox",
        ],
    }

    mutations = (
        ("ingress", "Config", "User", "root"),
        ("ingress", "HostConfig", "Privileged", True),
        ("ingress", "HostConfig", "ReadonlyRootfs", False),
        ("ingress", "HostConfig", "CapDrop", []),
        ("ingress", "HostConfig", "CapAdd", ["NET_ADMIN"]),
        ("ingress", "HostConfig", "SecurityOpt", []),
        ("ingress", "HostConfig", "Tmpfs", {
            "/tmp": "rw,noexec,nosuid,size=16m,size=1g,mode=0700,uid=10007,gid=20005",
        }),
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
        "rw,noexec,nosuid,size=16m,size=1g,mode=0700,uid=10007,gid=20005",
        "rw,noexec,nosuid,size=16m,mode=0700,mode=0777,uid=10007,gid=20005",
    ):
        changed = json.loads(json.dumps(inspected))
        changed["ingress"]["HostConfig"]["Tmpfs"] = {"/tmp": tmpfs}
        with pytest.raises(module.SafetyError, match="ingress"):
            module.verify_restricted_container_controls(changed)


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
        return SimpleNamespace(
            stdout=json.dumps({"uid": 10008, "gid": 20006, "mode": 0o660, "socket": True}),
            returncode=0,
        )

    monkeypatch.setattr(staging, "compose", fake_compose)
    monkeypatch.setattr(staging, "control", lambda command, *_args: "2" * 64 if command == "policy-digest" else "")
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
    assert result["restricted_container_controls"]["clinical-adapter"]["read_only_rootfs"] is True
    assert result["ingress_started_at"] == "2026-09-06T15:00:00.000000000Z"
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


def _cold_backup_fixture(module, tmp_path: Path) -> tuple[Path, Path, str]:
    """Create a content-free stopped-state bundle through the public helpers."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    project = "clinicalstagingdemo"
    state = tmp_path / f"{project}.synthetic-clinical-staging"
    state.mkdir(mode=0o700)
    (state / "seed").mkdir(mode=0o700)
    (state / "evidence").mkdir(mode=0o700)
    (state / "seed" / "policy-private.pem").write_text("synthetic-key", encoding="utf-8")
    (state / "compose.env").write_text("CLINICAL_SYNTHETIC=true\n", encoding="utf-8")
    marker = module.new_marker(
        project=project,
        state_dir=state,
        state_id="1" * 32,
        env_sha256=module.file_sha256(state / "compose.env"),
        runtime_head="a" * 40,
        runtime_tree="b" * 40,
        hrh_head=module.REQUIRED_HRH_SHA,
        hrh_tree=module.REQUIRED_HRH_TREE,
        lifecycle="stopped",
        expected_images={"ingress": "sha256:" + "c" * 64},
    )
    module.write_json_atomic(state / module.MARKER_NAME, marker, mode=0o600)
    backup = tmp_path / "cold-backup"
    backup.mkdir(mode=0o700)
    (backup / "volumes").mkdir(mode=0o700)
    module.create_state_archive(state, backup / "state.tar")
    for key in module.BACKED_UP_VOLUME_KEYS:
        archive = backup / "volumes" / f"{key}.tar"
        with tarfile.open(archive, "w") as opened:
            info = tarfile.TarInfo("fixture")
            payload = b"synthetic-volume"
            info.size = len(payload)
            opened.addfile(info, __import__("io").BytesIO(payload))
    manifest = module.build_backup_manifest(marker, state, backup)
    module.write_backup_manifest(backup, manifest)
    module.write_backup_completion(backup)
    return state, backup, module.file_sha256(backup / module.BACKUP_MANIFEST_NAME)


def test_cold_backup_bundle_requires_exact_complete_members_and_external_hash(tmp_path: Path):
    module = load_module()
    state, backup, expected_hash = _cold_backup_fixture(module, tmp_path)
    validated = module.validate_backup_bundle(backup, expected_hash, "clinicalstagingdemo", state)
    assert validated["project"] == "clinicalstagingdemo"
    assert validated["excluded_volume"] == "clinical_socket"

    with pytest.raises(module.SafetyError, match="external manifest hash"):
        module.validate_backup_bundle(backup, "0" * 64, "clinicalstagingdemo", state)

    (backup / module.BACKUP_COMPLETE_NAME).unlink()
    with pytest.raises(module.SafetyError, match="complete"):
        module.validate_backup_bundle(backup, expected_hash, "clinicalstagingdemo", state)


def test_cold_backup_bundle_rejects_unexpected_member_mixed_generation_and_excluded_socket(tmp_path: Path):
    module = load_module()
    state, backup, expected_hash = _cold_backup_fixture(module, tmp_path)
    (backup / "surprise").write_text("no", encoding="utf-8")
    with pytest.raises(module.SafetyError, match="unexpected"):
        module.validate_backup_bundle(backup, expected_hash, "clinicalstagingdemo", state)
    (backup / "surprise").unlink()

    (backup / "unexpected-directory").mkdir()
    with pytest.raises(module.SafetyError, match="directories"):
        module.validate_backup_bundle(backup, expected_hash, "clinicalstagingdemo", state)
    (backup / "unexpected-directory").rmdir()

    with (backup / "volumes" / "hrh_secret.tar").open("ab") as stream:
        stream.write(b"different-generation")
    with pytest.raises(module.SafetyError, match="hash"):
        module.validate_backup_bundle(backup, expected_hash, "clinicalstagingdemo", state)

    state, backup, expected_hash = _cold_backup_fixture(module, tmp_path / "socket")
    socket_archive = backup / "volumes" / "clinical_socket.tar"
    socket_archive.write_bytes(b"forbidden")
    with pytest.raises(module.SafetyError, match="unexpected"):
        module.validate_backup_bundle(backup, expected_hash, "clinicalstagingdemo", state)


def test_cold_backup_bundle_rejects_path_traversal_before_any_restore_mutation(tmp_path: Path):
    module = load_module()
    state, backup, expected_hash = _cold_backup_fixture(module, tmp_path)
    archive = backup / "state.tar"
    with tarfile.open(archive, "w") as opened:
        info = tarfile.TarInfo("../escape")
        payload = b"escape"
        info.size = len(payload)
        opened.addfile(info, __import__("io").BytesIO(payload))
    manifest = json.loads((backup / module.BACKUP_MANIFEST_NAME).read_text(encoding="utf-8"))
    manifest["members"]["state.tar"]["sha256"] = module.file_sha256(archive)
    manifest["members"]["state.tar"]["size"] = archive.stat().st_size
    module.write_backup_manifest(backup, manifest)
    expected_hash = module.file_sha256(backup / module.BACKUP_MANIFEST_NAME)
    with pytest.raises(module.SafetyError, match="path"):
        module.validate_backup_bundle(backup, expected_hash, "clinicalstagingdemo", state)


@pytest.mark.parametrize("member", ("state.tar", "volumes/hrh_secret.tar"))
def test_restore_snapshot_rejects_mid_copy_input_replacement_before_destination_mutation(
    member: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    module = load_module()
    state, backup, expected_hash = _cold_backup_fixture(module, tmp_path)
    project = "clinicalstagingdemo"
    runtime = tmp_path / "runtime"
    hrh = tmp_path / "hrh"
    runtime.mkdir()
    hrh.mkdir()
    shutil.rmtree(state)
    staging = module.ClinicalStaging(runtime, hrh, state, project, 18443)
    monkeypatch.setattr(staging, "_require_linux", lambda: None)
    original_copy = module._copy_regular_file
    replaced = False

    def replace_while_snapshotting(source: Path, destination: Path) -> None:
        nonlocal replaced
        if source == backup / member and not replaced:
            replaced = True
            source.write_bytes(b"different-generation")
        original_copy(source, destination)

    monkeypatch.setattr(module, "_copy_regular_file", replace_while_snapshotting)
    monkeypatch.setattr(
        staging,
        "_require_empty_restore_destination",
        lambda: pytest.fail("destination checks must not follow a failed snapshot validation"),
    )

    with pytest.raises(module.SafetyError, match="hash or size"):
        staging.restore(backup, expected_hash)
    assert replaced
    assert not state.exists()
    assert not list(tmp_path.glob(".clinicalstagingdemo.synthetic-clinical-staging.bundle-*"))


def test_backup_manifest_binds_content_safe_ownership_metadata(tmp_path: Path):
    module = load_module()
    state, backup, expected_hash = _cold_backup_fixture(module, tmp_path)
    manifest = module.validate_backup_bundle(backup, expected_hash, "clinicalstagingdemo", state)
    metadata = manifest["members"]["volumes/hrh_secret.tar"]
    assert set(metadata) == {"sha256", "size", "ownership_sha256"}
    assert len(metadata["ownership_sha256"]) == 64


def test_recovery_lifecycle_is_destroyable_but_never_operational(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    module = load_module()
    project = "clinicalstagingdemo"
    runtime = tmp_path / "runtime"
    hrh = tmp_path / "hrh"
    state = tmp_path / f"{project}.synthetic-clinical-staging"
    runtime.mkdir()
    hrh.mkdir()
    state.mkdir()
    marker = module.new_marker(
        project=project,
        state_dir=state,
        state_id="1" * 32,
        env_sha256="2" * 64,
        runtime_head="a" * 40,
        runtime_tree="b" * 40,
        hrh_head=module.REQUIRED_HRH_SHA,
        hrh_tree=module.REQUIRED_HRH_TREE,
        lifecycle="recovering",
    )
    module.write_json_atomic(state / module.MARKER_NAME, marker, mode=0o600)
    assert module.read_marker(state, project)["lifecycle"] == "recovering"
    staging = module.ClinicalStaging(runtime, hrh, state, project, 18443)
    monkeypatch.setattr(staging, "_require_linux", lambda: None)
    monkeypatch.setattr(staging, "_verify_marker_and_source", lambda: marker)
    monkeypatch.setattr(staging, "compose", lambda *_args, **_kwargs: pytest.fail("must not start recovery state"))
    for command in ("up", "status", "stop"):
        with pytest.raises(module.SafetyError, match="lifecycle"):
            getattr(staging, command)()


def test_verified_recovery_receipt_requires_all_causal_controls(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    module = load_module()
    project = "clinicalstagingdemo"
    runtime = tmp_path / "runtime"
    hrh = tmp_path / "hrh"
    state = tmp_path / f"{project}.synthetic-clinical-staging"
    runtime.mkdir()
    hrh.mkdir()
    state.mkdir()
    (state / "evidence" / "recovery").mkdir(parents=True)
    marker = module.new_marker(
        project=project, state_dir=state, state_id="1" * 32, env_sha256="2" * 64,
        runtime_head="a" * 40, runtime_tree="b" * 40, hrh_head=module.REQUIRED_HRH_SHA,
        hrh_tree=module.REQUIRED_HRH_TREE, lifecycle="ready",
    )
    manifest_hash = "d" * 64
    module.write_json_atomic(state / module.MARKER_NAME, marker, mode=0o600)
    module.write_json_atomic(
        state / "evidence" / "recovery" / f"restore-{manifest_hash}.json",
        {"manifest_sha256": manifest_hash, "verification": "mechanical_restore_only"}, mode=0o600,
    )
    staging = module.ClinicalStaging(runtime, hrh, state, project, 18443)
    monkeypatch.setattr(staging, "_require_linux", lambda: None)
    monkeypatch.setattr(staging, "_verify_marker_and_source", lambda: marker)
    with pytest.raises(module.SafetyError, match="incomplete"):
        staging.finalize_cold_recovery_verification(manifest_hash, {})
    receipt = staging.finalize_cold_recovery_verification(
        manifest_hash, {key: True for key in module.CAUSAL_RECOVERY_CHECKS},
    )
    assert receipt["verification"] == "causal_e2e_verified"
    assert "cold-ready" not in json.dumps(receipt)


def test_restore_destination_rejects_preexisting_named_or_labeled_resources(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    module = load_module()
    project = "clinicalstagingdemo"
    runtime = tmp_path / "runtime"
    hrh = tmp_path / "hrh"
    state = tmp_path / f"{project}.synthetic-clinical-staging"
    runtime.mkdir()
    hrh.mkdir()

    class FakeShell:
        def __init__(self):
            self.existing_volume = False
            self.project_named_container = False

        def run(self, *args, **_kwargs):
            if args[:3] in (("docker", "volume", "inspect"), ("docker", "network", "inspect")):
                return SimpleNamespace(returncode=0 if self.existing_volume else 1, stdout="", stderr="")
            if args[:4] == ("docker", "container", "ls", "--all"):
                names = f"{project}-ingress-1\n" if self.project_named_container else "other\n"
                return SimpleNamespace(returncode=0, stdout=names, stderr="")
            raise AssertionError(args)

    shell = FakeShell()
    staging = module.ClinicalStaging(runtime, hrh, state, project, 18443, shell=shell)
    monkeypatch.setattr(staging, "_labeled_resources", lambda _kind: {})
    staging._require_empty_restore_destination()

    shell.existing_volume = True
    with pytest.raises(module.SafetyError, match="existing Docker volume"):
        staging._require_empty_restore_destination()
    shell.existing_volume = False
    shell.project_named_container = True
    with pytest.raises(module.SafetyError, match="project-named"):
        staging._require_empty_restore_destination()


def test_restore_argument_contract_and_backup_path_cannot_overlap_private_state(tmp_path: Path):
    module = load_module()
    project = "clinicalstagingdemo"
    state = tmp_path / f"{project}.synthetic-clinical-staging"
    state.mkdir()
    with pytest.raises(module.SafetyError, match="outside state"):
        module.validate_backup_path(state / "backup", state_dir=state)
    parsed = module.parse_args([
        "--hrh-root", "/hrh", "--state-dir", str(state), "--project", project,
        "restore", "--backup-dir", "/backups/synthetic", "--expected-manifest-sha256", "a" * 64,
    ])
    assert parsed.command == "restore"
    assert parsed.expected_manifest_sha256 == "a" * 64


def test_volume_transfer_helper_is_pinned_networkless_and_never_uses_socket(tmp_path: Path):
    module = load_module()
    project = "clinicalstagingdemo"
    runtime = tmp_path / "runtime"
    hrh = tmp_path / "hrh"
    state = tmp_path / f"{project}.synthetic-clinical-staging"
    backup = tmp_path / "backup"
    runtime.mkdir()
    hrh.mkdir()
    backup.mkdir()
    (backup / module.BACKUP_VOLUME_DIR).mkdir()

    class FakeShell:
        def __init__(self):
            self.calls = []

        def run(self, *args, **_kwargs):
            self.calls.append(args)
            if args[:3] == ("docker", "run", "--rm") and "/source" in " ".join(args):
                archive = backup / module.BACKUP_VOLUME_DIR / "hrh_secret.tar"
                with tarfile.open(archive, "w") as opened:
                    info = tarfile.TarInfo("secret")
                    info.size = 1
                    opened.addfile(info, __import__("io").BytesIO(b"x"))
            return SimpleNamespace(returncode=0, stdout="", stderr="")

    shell = FakeShell()
    staging = module.ClinicalStaging(runtime, hrh, state, project, 18443, shell=shell)
    staging._backup_volume("hrh_secret", module.volume_names(project)["hrh_secret"], backup)
    staging._restore_volume("hrh_secret", module.volume_names(project)["hrh_secret"], backup)
    assert len(shell.calls) == 2
    for call in shell.calls:
        assert "--network" in call and call[call.index("--network") + 1] == "none"
        assert "--read-only" in call
        assert "--cap-drop" in call and call[call.index("--cap-drop") + 1] == "ALL"
        assert "--cap-add" in call and call[call.index("--cap-add") + 1] == "DAC_OVERRIDE"
        assert "--user" in call and call[call.index("--user") + 1] == "0:0"
        assert "--entrypoint" in call and call[call.index("--entrypoint") + 1] == "sh"
        assert module.RECOVERY_HELPER_IMAGE in call
    assert shell.calls[0][-1] == "tar --numeric-owner -C /source -cf /backup/volumes/hrh_secret.tar ."
    assert shell.calls[1][-1] == "tar --numeric-owner -C /destination -xf /backup/volumes/hrh_secret.tar"
    mounts = [shell.calls[0][index + 1] for index, value in enumerate(shell.calls[0][:-1]) if value == "--mount"]
    module.verify_recovery_helper_boundary(shell.calls[0], source_mount=mounts[0], backup_mount=mounts[1])
    extra_capability = list(shell.calls[0])
    extra_capability[extra_capability.index(module.RECOVERY_HELPER_IMAGE):extra_capability.index(module.RECOVERY_HELPER_IMAGE)] = [
        "--cap-add", "NET_ADMIN",
    ]
    with pytest.raises(module.SafetyError, match="security authority"):
        module.verify_recovery_helper_boundary(tuple(extra_capability), source_mount=mounts[0], backup_mount=mounts[1])
    extra_mount = list(shell.calls[0])
    extra_mount[extra_mount.index(module.RECOVERY_HELPER_IMAGE):extra_mount.index(module.RECOVERY_HELPER_IMAGE)] = [
        "--mount", "type=bind,src=/tmp/unrelated,dst=/unexpected,readonly",
    ]
    with pytest.raises(module.SafetyError, match="unexpected mount"):
        module.verify_recovery_helper_boundary(tuple(extra_mount), source_mount=mounts[0], backup_mount=mounts[1])
    with pytest.raises(module.SafetyError, match="allowlist"):
        staging._backup_volume("clinical_socket", module.volume_names(project)["clinical_socket"], backup)


def test_cold_backup_rejects_even_unlabeled_container_mounting_an_exact_volume(tmp_path: Path):
    module = load_module()
    project = "clinicalstagingdemo"
    runtime = tmp_path / "runtime"
    hrh = tmp_path / "hrh"
    state = tmp_path / f"{project}.synthetic-clinical-staging"
    runtime.mkdir()
    hrh.mkdir()

    class FakeShell:
        def run(self, *args, **_kwargs):
            if args[:4] == ("docker", "container", "ls", "--all"):
                if args[-1] == f"volume={module.volume_names(project)['hrh_secret']}":
                    return SimpleNamespace(returncode=0, stdout="unlabeled-debugger\n", stderr="")
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            if args[:3] == ("docker", "container", "inspect"):
                return SimpleNamespace(returncode=0, stdout=json.dumps([{
                    "Mounts": [{
                        "Type": "volume", "Name": module.volume_names(project)["hrh_secret"], "RW": True,
                    }],
                }]), stderr="")
            raise AssertionError(args)

    staging = module.ClinicalStaging(runtime, hrh, state, project, 18443, shell=FakeShell())
    with pytest.raises(module.SafetyError, match="unlabeled-debugger.*hrh_secret.*rw"):
        staging._assert_unmounted_backup_volumes(module.volume_names(project))


def test_backup_durably_flushes_archives_before_manifest_and_completion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    module = load_module()
    project = "clinicalstagingdemo"
    runtime = tmp_path / "runtime"
    hrh = tmp_path / "hrh"
    state = tmp_path / f"{project}.synthetic-clinical-staging"
    runtime.mkdir()
    hrh.mkdir()
    state.mkdir()
    (state / "seed").mkdir()
    (state / "evidence").mkdir()
    (state / "compose.env").write_text("CLINICAL_SYNTHETIC=true\n", encoding="utf-8")
    marker = module.new_marker(
        project=project, state_dir=state, state_id="1" * 32,
        env_sha256=module.file_sha256(state / "compose.env"), runtime_head="a" * 40,
        runtime_tree="b" * 40, hrh_head=module.REQUIRED_HRH_SHA, hrh_tree=module.REQUIRED_HRH_TREE,
        lifecycle="stopped", expected_images={"ingress": "sha256:" + "c" * 64},
    )
    module.write_json_atomic(state / module.MARKER_NAME, marker, mode=0o600)

    class FakeShell:
        def run(self, *args, **_kwargs):
            if args[:3] == ("docker", "run", "--rm"):
                command = args[-1]
                key = command.split("/backup/volumes/", 1)[1].split(".tar", 1)[0]
                archive = current_backup / module.BACKUP_VOLUME_DIR / f"{key}.tar"
                with tarfile.open(archive, "w") as opened:
                    info = tarfile.TarInfo("fixture")
                    info.size = 1
                    opened.addfile(info, __import__("io").BytesIO(b"x"))
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            raise AssertionError(args)

    staging = module.ClinicalStaging(runtime, hrh, state, project, 18443, shell=FakeShell())
    monkeypatch.setattr(staging, "_require_linux", lambda: None)
    monkeypatch.setattr(staging, "_verify_marker_and_source", lambda: marker)
    monkeypatch.setattr(staging, "_verify_cold_quiescence", lambda _marker: None)
    monkeypatch.setattr(staging, "compose", lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""))
    monkeypatch.setattr(staging, "_assert_unmounted_backup_volumes", lambda _volumes: None)
    events: list[str] = []
    original_fsync_file = module.fsync_file
    original_fsync_directory = module.fsync_directory
    original_write_manifest = module.write_backup_manifest
    original_write_completion = module.write_backup_completion
    current_backup = tmp_path / "unused"

    def record_fsync(path: Path) -> None:
        events.append(path.relative_to(current_backup).as_posix())
        original_fsync_file(path)

    def record_manifest(directory: Path, value: dict) -> None:
        events.append("manifest")
        original_write_manifest(directory, value)

    def record_completion(directory: Path) -> None:
        events.append("complete")
        original_write_completion(directory)

    def record_directory(path: Path) -> None:
        if path.name == module.BACKUP_VOLUME_DIR:
            events.append("dir:volumes")
        elif path == current_backup:
            events.append("dir:bundle")
        elif path == backup.parent:
            events.append("dir:parent")
        original_fsync_directory(path)

    monkeypatch.setattr(module, "fsync_file", record_fsync)
    monkeypatch.setattr(module, "fsync_directory", record_directory)
    monkeypatch.setattr(module, "write_backup_manifest", record_manifest)
    monkeypatch.setattr(module, "write_backup_completion", record_completion)
    backup = tmp_path / "published-backup"
    current_backup = backup.parent / f".{backup.name}.partial-placeholder"

    # The exact randomized temporary name is not observable; bind the recorder
    # lazily to its first archive parent instead.
    def flexible_fsync(path: Path) -> None:
        nonlocal current_backup
        if current_backup.name.endswith("placeholder"):
            current_backup = path.parent.parent if path.parent.name == module.BACKUP_VOLUME_DIR else path.parent
        events.append(path.relative_to(current_backup).as_posix())
        original_fsync_file(path)

    monkeypatch.setattr(module, "fsync_file", flexible_fsync)
    receipt = staging.backup(backup)
    assert receipt["manifest_sha256"] == module.file_sha256(backup / module.BACKUP_MANIFEST_NAME)
    assert events[0] == module.BACKUP_STATE_ARCHIVE
    volume_events = [f"volumes/{key}.tar" for key in module.BACKED_UP_VOLUME_KEYS]
    assert events[1:1 + len(volume_events)] == volume_events
    assert events.index("dir:volumes") > events.index(volume_events[-1])
    assert events.index("manifest") > events.index("dir:volumes")
    assert events.index("dir:bundle") > events.index("manifest")
    assert events.index("complete") > events.index("dir:bundle")
    assert events[-1] == "dir:parent"
    assert (backup / module.BACKUP_COMPLETE_NAME).read_bytes() == b"complete\n"


def test_backup_interruption_never_publishes_a_complete_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    module = load_module()
    project = "clinicalstagingdemo"
    runtime = tmp_path / "runtime"
    hrh = tmp_path / "hrh"
    state = tmp_path / f"{project}.synthetic-clinical-staging"
    runtime.mkdir()
    hrh.mkdir()
    state.mkdir()
    (state / "seed").mkdir()
    (state / "evidence").mkdir()
    (state / "compose.env").write_text("CLINICAL_SYNTHETIC=true\n", encoding="utf-8")
    marker = module.new_marker(
        project=project, state_dir=state, state_id="1" * 32,
        env_sha256=module.file_sha256(state / "compose.env"), runtime_head="a" * 40,
        runtime_tree="b" * 40, hrh_head=module.REQUIRED_HRH_SHA, hrh_tree=module.REQUIRED_HRH_TREE,
        lifecycle="stopped", expected_images={"ingress": "sha256:" + "c" * 64},
    )
    module.write_json_atomic(state / module.MARKER_NAME, marker, mode=0o600)
    staging = module.ClinicalStaging(runtime, hrh, state, project, 18443)
    monkeypatch.setattr(staging, "_require_linux", lambda: None)
    monkeypatch.setattr(staging, "_verify_marker_and_source", lambda: marker)
    monkeypatch.setattr(staging, "_verify_cold_quiescence", lambda _marker: None)
    monkeypatch.setattr(staging, "compose", lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""))
    monkeypatch.setattr(staging, "_assert_unmounted_backup_volumes", lambda _volumes: None)
    monkeypatch.setattr(staging, "_backup_volume", lambda *_args: (_ for _ in ()).throw(module.CommandError("interrupted")))
    backup = tmp_path / "interrupted-backup"

    with pytest.raises(module.CommandError, match="interrupted"):
        staging.backup(backup)
    assert not backup.exists()
    assert not list(tmp_path.glob(".interrupted-backup.partial-*"))


def test_restore_post_start_failure_returns_to_non_operational_recovering_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    module = load_module()
    state, backup, expected_hash = _cold_backup_fixture(module, tmp_path)
    project = "clinicalstagingdemo"
    runtime = tmp_path / "runtime"
    hrh = tmp_path / "hrh"
    runtime.mkdir()
    hrh.mkdir()
    shutil.rmtree(state)
    staging = module.ClinicalStaging(runtime, hrh, state, project, 18443)
    monkeypatch.setattr(staging, "_require_linux", lambda: None)
    manifest = module.validate_backup_bundle(backup, expected_hash, project, state)
    monkeypatch.setattr(module, "verify_source_frame", lambda *_args: manifest["source"])
    monkeypatch.setattr(staging, "_require_empty_restore_destination", lambda: None)
    monkeypatch.setattr(staging, "_create_volumes", lambda _marker: None)
    monkeypatch.setattr(staging, "_restore_volume", lambda *_args: None)
    monkeypatch.setattr(staging, "_start_restored_stack", lambda: None)
    monkeypatch.setattr(
        staging,
        "status",
        lambda *, _allow_recovering=False: (
            (_ for _ in ()).throw(module.SafetyError("post-start readiness failed"))
            if _allow_recovering else pytest.fail("recovery verification must opt in explicitly")
        ),
    )
    compose_calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(
        staging,
        "compose",
        lambda *args, **_kwargs: (compose_calls.append(args), SimpleNamespace(returncode=0, stdout="", stderr=""))[1],
    )

    with pytest.raises(module.SafetyError, match="controlled recovery"):
        staging.restore(backup, expected_hash)
    assert module.read_marker(state, project)["lifecycle"] == "recovering"
    assert compose_calls == [("stop", *module.LONG_RUNNING_SERVICES)]
    assert not (state / "evidence" / "recovery" / f"restore-{expected_hash}.json").exists()


@pytest.mark.parametrize("interruption", ("before-start", "during-start"))
def test_restore_interruption_never_publishes_stopped_or_ready_and_blocks_normal_up(
    interruption: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    module = load_module()
    state, backup, expected_hash = _cold_backup_fixture(module, tmp_path)
    project = "clinicalstagingdemo"
    runtime = tmp_path / "runtime"
    hrh = tmp_path / "hrh"
    runtime.mkdir()
    hrh.mkdir()
    shutil.rmtree(state)
    staging = module.ClinicalStaging(runtime, hrh, state, project, 18443)
    monkeypatch.setattr(staging, "_require_linux", lambda: None)
    manifest = module.validate_backup_bundle(backup, expected_hash, project, state)
    monkeypatch.setattr(module, "verify_source_frame", lambda *_args: manifest["source"])
    monkeypatch.setattr(staging, "_require_empty_restore_destination", lambda: None)
    monkeypatch.setattr(staging, "_create_volumes", lambda _marker: None)
    monkeypatch.setattr(staging, "_restore_volume", lambda *_args: None)
    if interruption == "before-start":
        monkeypatch.setattr(
            staging,
            "_restore_volume",
            lambda *_args: (_ for _ in ()).throw(module.CommandError("interrupted before startup")),
        )
    else:
        monkeypatch.setattr(
            staging,
            "_start_restored_stack",
            lambda: (_ for _ in ()).throw(module.CommandError("interrupted during startup")),
        )
    writes: list[str] = []
    original_write = staging._write_marker
    monkeypatch.setattr(
        staging,
        "_write_marker",
        lambda marker: (writes.append(str(marker["lifecycle"])), original_write(marker))[1],
    )
    compose_calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(
        staging,
        "compose",
        lambda *args, **_kwargs: (compose_calls.append(args), SimpleNamespace(returncode=0, stdout="", stderr=""))[1],
    )

    with pytest.raises(module.SafetyError, match="controlled recovery"):
        staging.restore(backup, expected_hash)
    assert module.read_marker(state, project)["lifecycle"] == "recovering"
    assert "stopped" not in writes and "ready" not in writes
    assert compose_calls == [("stop", *module.LONG_RUNNING_SERVICES)]
    monkeypatch.setattr(
        staging,
        "compose",
        lambda *_args, **_kwargs: pytest.fail("ordinary up must not run from recovering state"),
    )
    with pytest.raises(module.SafetyError, match="lifecycle"):
        staging.up()
