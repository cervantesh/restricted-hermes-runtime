"""W2 mode/Compose RED design; no publication or host-readiness claim.

Source base: 4aa366adfb09cf8d230dce92ff98eb12dcc9029b.
Contract: durable-published-hrh-operator.v1.md at 1d4ee952.
Public input flags were adjudicated as --hrh-trust, --hrh-evidence and
--hrh-docker-config. New predicates fail on the actual existing parser or
effective Compose merge, never because a proposed module cannot be imported.

Acceptance map (all fixture values are synthetic):
 A01: source defaults, parser-optional root, init/restore missing-root denial
      before child processes or target-state mutation.
 A02: supported published syntax, root/input/environment rejection before I/O.
 A03: no second CLI mode/input authority on ordinary lifecycle commands;
      root optional at parsing, then required for an existing source marker
      on every ordinary command, including refresh-policy and reset.
 A05/A06: real Compose CLI config, not a hand-written YAML merge.
 A14: exact existing source frame/marker/backup and built_images result shape.
 A18: reset cannot select a new mode; existing source reset choreography.

Deep valid published-marker/image parsing and persisted published reset are
U3/U4 controls after A10/A15 freezes its nested effective_images schema. W2
does not invent that schema or claim a malformed marker is a valid generation.
Full source lifecycle is also covered by the unchanged adjacent lifecycle/TLS
suites. Config rendering does not build, pull, start or access a Docker daemon.
"""

from __future__ import annotations

from contextlib import nullcontext
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[2]
STAGING = ROOT / "deploy" / "clinical-staging" / "clinical_staging.py"
HARNESS = ROOT / "tests" / "deployment" / "clinical-composed-e2e"
PROJECT = "clinicalstagingw2mode"
SOURCE_HEAD = "e30a4f968de6727519f49c08369f561fdf269ec5"
SOURCE_TREE = "7fb2543a2ceb1649f05c467b38708d1404106659"
PUBLISHED_FLAGS = ("--hrh-trust", "--hrh-evidence", "--hrh-docker-config")
ORDINARY = ("up", "status", "stop", "backup", "destroy", "renew-tls", "refresh-policy", "reset")


@pytest.fixture
def module():
    spec = importlib.util.spec_from_file_location("clinical_staging_w2_modes", STAGING)
    assert spec is not None and spec.loader is not None
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def _paths(tmp_path):
    return tmp_path / f"{PROJECT}.synthetic-clinical-staging", tmp_path / "source-hrh"


def _argv(tmp_path, command, *, with_root=False, extra=()):
    state, hrh = _paths(tmp_path)
    args = ["--runtime-root", str(ROOT), "--state-dir", str(state), "--project", PROJECT]
    if with_root:
        args += ["--hrh-root", str(hrh)]
    args.append(command)
    if command in {"backup", "restore"}:
        args += ["--backup-dir", str(tmp_path / "backup")]
    if command == "restore":
        args += ["--expected-manifest-sha256", "a" * 64]
    if command == "refresh-policy":
        args += ["--epoch", "synthetic-w2-epoch"]
    return args + list(extra)


def _parse_supported(module, args):
    try:
        return module.parse_args(args)
    except SystemExit as exc:
        pytest.fail(f"real operator parser rejected required W2 syntax (exit {exc.code}): {args}", pytrace=False)


def _publication_arguments(tmp_path):
    # Deliberately not valid signed evidence; these paths test argument authority
    # only. No verifier fixture, key, registry credential or attestation is forged.
    return [item for flag, path in zip(PUBLISHED_FLAGS, ("trust.json", "evidence", "docker-reader"))
            for item in (flag, str(tmp_path / path))]


def _published_syntax_gate(module, tmp_path):
    # A negative command cannot pass just because this version lacks --hrh-mode.
    return _parse_supported(module, _argv(tmp_path, "init", extra=[
        "--hrh-mode", "published", *_publication_arguments(tmp_path),
    ]))


def _deny_children(module, monkeypatch):
    calls = []

    def denied(*args, **kwargs):
        calls.append(args)
        pytest.fail("preflight reached a child process before rejecting invalid mode inputs", pytrace=False)

    monkeypatch.setattr(module.subprocess, "run", denied)
    return calls


def _main_exit(module, args):
    try:
        return module.main(args)
    except SystemExit as exc:
        return exc.code


@pytest.mark.parametrize("command", ["init", "restore"])
def test_a01_omitted_mode_preserves_source_build_parser_control(module, tmp_path, command):
    parsed = _parse_supported(module, _argv(tmp_path, command, with_root=True))
    assert parsed.command == command
    assert parsed.hrh_root == _paths(tmp_path)[1]
    # v1 has no mode attribute at all; that existing source default is compatible.
    assert getattr(parsed, "hrh_mode", "source-build") == "source-build"


@pytest.mark.parametrize("command", ["init", "restore", *ORDINARY])
def test_a01_a03_hrh_root_is_parser_optional_before_mode_resolution(module, tmp_path, command):
    parsed = _parse_supported(module, _argv(tmp_path, command))
    assert parsed.hrh_root is None


@pytest.mark.parametrize("command", ["init", "restore"])
def test_a02_published_syntax_accepts_exact_three_paths_without_hrh_checkout(module, tmp_path, command):
    parsed = _parse_supported(module, _argv(tmp_path, command, extra=[
        "--hrh-mode", "published", *_publication_arguments(tmp_path),
    ]))
    assert parsed.hrh_root is None
    assert not _paths(tmp_path)[1].exists()


def test_a02_real_process_advertises_published_creation_interface(tmp_path):
    result = subprocess.run(
        [sys.executable, str(STAGING), *_argv(tmp_path, "init", with_root=True, extra=["--help"])],
        cwd=ROOT, text=True, capture_output=True, timeout=20, check=False,
    )
    assert result.returncode == 0, result.stderr
    for option in ("--hrh-mode", *PUBLISHED_FLAGS):
        assert option in result.stdout, f"real init help does not expose {option}"


@pytest.mark.parametrize("mutation", [
    "root-argument", "root-environment", "missing-trust", "missing-evidence",
    "missing-docker-config", "duplicate-trust", "duplicate-evidence",
    "duplicate-docker-config", "extra-receipt", "extra-signature", "extra-key",
    "environment-only",
])
def test_a02_invalid_published_inputs_fail_before_children_or_state(module, tmp_path, monkeypatch, capsys, mutation):
    _published_syntax_gate(module, tmp_path)
    supplied = _publication_arguments(tmp_path)
    if mutation.startswith("missing-"):
        index = {"missing-trust": 0, "missing-evidence": 2, "missing-docker-config": 4}[mutation]
        del supplied[index:index + 2]
    elif mutation.startswith("duplicate-"):
        index = {"duplicate-trust": 0, "duplicate-evidence": 2, "duplicate-docker-config": 4}[mutation]
        supplied += [supplied[index], str(tmp_path / "conflicting-input")]
    elif mutation.startswith("extra-"):
        supplied += [{"extra-receipt": "--hrh-receipt", "extra-signature": "--hrh-signature", "extra-key": "--hrh-public-key"}[mutation], str(tmp_path / "duplicate-authority")]
    elif mutation == "root-environment":
        monkeypatch.setenv("CLINICAL_HRH_ROOT", str(_paths(tmp_path)[1]))
    elif mutation == "environment-only":
        supplied = []
        for name in ("CLINICAL_HRH_TRUST", "CLINICAL_HRH_EVIDENCE", "CLINICAL_HRH_DOCKER_CONFIG"):
            monkeypatch.setenv(name, str(tmp_path / "ambient-is-not-authority"))
    calls = _deny_children(module, monkeypatch)
    result = _main_exit(module, _argv(tmp_path, "init", with_root=mutation == "root-argument", extra=["--hrh-mode", "published", *supplied]))
    assert result != 0
    assert not calls
    assert not _paths(tmp_path)[0].exists()
    output = capsys.readouterr()
    assert "Traceback" not in output.err
    # Attribution matters: a later nonexistent fixture-file failure cannot
    # masquerade as validation of a duplicate authority or forbidden HRH root.
    diagnostic = output.err.lower()
    if mutation.startswith("duplicate-"):
        assert re.search(r"duplicate|ambiguous|repeated|more than once", diagnostic)
    elif mutation.startswith("root-"):
        assert re.search(r"hrh.root|hrh-root|clinical_hrh_root", diagnostic)
    elif mutation.startswith("missing-"):
        word = {"missing-trust": "trust", "missing-evidence": "evidence", "missing-docker-config": "docker"}[mutation]
        assert word in diagnostic
    elif mutation.startswith("extra-"):
        assert supplied[-2] in diagnostic
    else:
        assert any(option in diagnostic for option in PUBLISHED_FLAGS)


@pytest.mark.parametrize("command", ORDINARY)
def test_a03_a18_ordinary_commands_cannot_select_mode(module, tmp_path, command):
    # This existing GREEN control must remain true after init/restore gain mode.
    with pytest.raises(SystemExit) as exc:
        module.parse_args(_argv(tmp_path, command, with_root=True, extra=["--hrh-mode", "published"]))
    assert exc.value.code == 2


@pytest.mark.parametrize("command", ORDINARY)
@pytest.mark.parametrize("flag", PUBLISHED_FLAGS)
def test_a03_ordinary_commands_cannot_accept_acquisition_inputs(module, tmp_path, command, flag):
    with pytest.raises(SystemExit) as exc:
        module.parse_args(_argv(tmp_path, command, with_root=True, extra=[flag, str(tmp_path / "forbidden-acquisition")]))
    assert exc.value.code == 2


@pytest.mark.parametrize("mode", ["source", "Published", "SOURCE-BUILD", ""])
def test_a01_a02_mode_has_no_aliases(module, tmp_path, mode):
    _published_syntax_gate(module, tmp_path)
    with pytest.raises(SystemExit) as exc:
        module.parse_args(_argv(tmp_path, "init", with_root=True, extra=["--hrh-mode", mode]))
    assert exc.value.code == 2


@pytest.mark.parametrize("flag", PUBLISHED_FLAGS)
def test_a02_source_build_rejects_published_acquisition_paths(module, tmp_path, monkeypatch, flag):
    _published_syntax_gate(module, tmp_path)
    calls = _deny_children(module, monkeypatch)
    assert _main_exit(module, _argv(tmp_path, "init", with_root=True, extra=[flag, str(tmp_path / "not-source-authority")])) != 0
    assert not calls and not _paths(tmp_path)[0].exists()


def _source_marker(module, tmp_path, *, lifecycle="ready"):
    state, _ = _paths(tmp_path)
    state.mkdir(exist_ok=True)
    env = b"CLINICAL_STAGING_PROJECT=" + PROJECT.encode() + b"\n"
    (state / "compose.env").write_bytes(env)
    marker = module.new_marker(
        project=PROJECT, state_dir=state, state_id="1" * 32,
        env_sha256=hashlib.sha256(env).hexdigest(), runtime_head="a" * 40,
        runtime_tree="b" * 40, hrh_head=SOURCE_HEAD, hrh_tree=SOURCE_TREE,
        lifecycle=lifecycle,
    )
    module.write_json_atomic(state / module.MARKER_NAME, marker, mode=0o600)
    return marker


@pytest.mark.parametrize("command", ["init", "restore", *ORDINARY])
def test_a01_a03_source_mode_requires_root_before_children_or_state_mutation(module, tmp_path, monkeypatch, capsys, command):
    _parse_supported(module, _argv(tmp_path, command))
    state, _ = _paths(tmp_path)
    if command in ORDINARY:
        _source_marker(module, tmp_path)
        for name in ("seed", "evidence"):
            (state / name).mkdir()
            (state / name / "preserve.txt").write_bytes(b"synthetic-state-must-survive")

    def snapshot():
        return {
            path.relative_to(tmp_path).as_posix(): None if path.is_dir() else path.read_bytes()
            for path in tmp_path.rglob("*")
        }

    before = snapshot()
    calls = _deny_children(module, monkeypatch)
    # Keep the assertion about missing source authority, not Windows support.
    monkeypatch.setattr(module.ClinicalStaging, "_require_linux", lambda self: None)
    assert _main_exit(module, _argv(tmp_path, command)) != 0
    assert calls == []
    assert snapshot() == before
    if command not in ORDINARY:
        assert not state.exists()
    output = capsys.readouterr()
    assert "Traceback" not in output.err
    assert re.search(r"hrh.root|hrh-root|clinical_hrh_root", output.err.lower())


def _compose_environment(module, tmp_path, *, published):
    state, hrh = _paths(tmp_path)
    state.mkdir(exist_ok=True)
    hrh.mkdir(exist_ok=True)
    values = {
        "CLINICAL_MM_DB_PASSWORD": "synthetic-mm",
        "CLINICAL_HRH_DB_PASSWORD": "synthetic-hrh",
        "CLINICAL_HRH_SESSION_SECRET": "s" * 32,
        "CLINICAL_HRH_ENCRYPTION_KEY": "e" * 64,
        "CLINICAL_HRH_BUILD_SHA": SOURCE_HEAD,
        "CLINICAL_HARNESS": str(HARNESS), "CLINICAL_SEED": str(tmp_path / "seed"),
        "CLINICAL_ADAPTER_IMAGE": "restricted-w2-adapter:config-only",
        "CLINICAL_INGRESS_IMAGE": "restricted-w2-ingress:config-only",
        "CLINICAL_POLICY_PUBLIC_KEY": "A" * 43 + "=",
        "CLINICAL_STAGING_PROJECT": PROJECT, "CLINICAL_STAGING_STATE_ID": "1" * 32,
        "CLINICAL_STAGING_PORT": "18443",
    }
    values.update({f"CLINICAL_VOLUME_{key.upper()}": value for key, value in module.volume_names(PROJECT).items()})
    if published:
        values["CLINICAL_HRH_WEB_IMAGE"] = "registry.invalid/clinical/web@sha256:" + "1" * 64
        values["CLINICAL_HRH_MIGRATE_IMAGE"] = "registry.invalid/clinical/migrate@sha256:" + "2" * 64
    else:
        values["CLINICAL_HRH_ROOT"] = str(hrh)
    env_file = state / "compose.env"
    env_file.write_text("".join(f"{key}={value}\n" for key, value in sorted(values.items())), encoding="utf-8")
    return state, hrh, env_file, values


def _require_compose():
    if shutil.which("docker") is None:
        pytest.skip("real Docker Compose config CLI unavailable; effective merge NOT_VERIFIED")


def test_a05_effective_source_compose_uses_current_operator_source_overlay(module, tmp_path):
    _require_compose()
    state, hrh, _, _ = _compose_environment(module, tmp_path, published=False)

    class ConfigOnlyShell:
        def run(self, *args, **kwargs):
            assert args[:2] == ("docker", "compose")
            assert args[-3:] == ("config", "--format", "json")
            environment = dict(kwargs["env"])
            # The product lifecycle is Linux-only. Native Windows config-only
            # rendering additionally needs packaging/plugin-discovery variables;
            # preserve the operator's selected argv and sealed CLINICAL values.
            if os.name == "nt":
                for name in ("SystemRoot", "ProgramFiles", "ProgramData", "APPDATA", "LOCALAPPDATA", "USERPROFILE", "PATHEXT"):
                    if name in os.environ:
                        environment[name] = os.environ[name]
            result = subprocess.run(args, cwd=ROOT, env=environment, text=True, capture_output=True, timeout=30, check=False)
            assert result.returncode == 0, result.stderr
            return result

    staging = module.ClinicalStaging(ROOT, hrh, state, PROJECT, 18443, shell=ConfigOnlyShell())
    rendered = staging.compose("config", "--format", "json", timeout=30)
    services = json.loads(rendered.stdout)["services"]
    for service, dockerfile in (("hrh", "Dockerfile.web.clinical-candidate"), ("hrh-migrate", "Dockerfile.migrate.clinical-candidate")):
        assert Path(services[service]["build"]["context"]).resolve() == hrh.resolve()
        assert services[service]["build"]["dockerfile"] == dockerfile
    assert services["hrh"]["build"]["args"]["BUILD_SHA"] == SOURCE_HEAD
    assert services["hrh"]["depends_on"]["hrh-migrate"]["condition"] == "service_completed_successfully"


def test_a06_effective_published_merge_cannot_retain_common_hrh_build(module, tmp_path):
    _require_compose()
    _, _, env_file, expected = _compose_environment(module, tmp_path, published=True)
    environment = {key: value for key, value in os.environ.items() if not key.startswith("CLINICAL_")}
    result = subprocess.run([
        "docker", "compose", "--env-file", str(env_file), "--project-name", PROJECT,
        "--file", str(HARNESS / "compose.yaml"),
        "--file", str(HARNESS / "compose.published-hrh.yaml"),
        "--file", str(ROOT / "deploy" / "clinical-staging" / "compose.yaml"),
        "config", "--format", "json",
    ], cwd=ROOT, env=environment, text=True, capture_output=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr
    services = json.loads(result.stdout)["services"]
    for service, key in (("hrh", "CLINICAL_HRH_WEB_IMAGE"), ("hrh-migrate", "CLINICAL_HRH_MIGRATE_IMAGE")):
        actual = services[service]
        assert "build" not in actual, f"{service} still receives build from the common staging overlay"
        assert actual["image"] == expected[key]
        assert actual["pull_policy"] == "never"
        assert not actual.get("volumes"), "HRH published delivery must not mount a source tree"
    assert services["hrh"]["depends_on"]["hrh-migrate"]["condition"] == "service_completed_successfully"


def test_a14_source_marker_and_backup_contract_remain_exact(module, tmp_path):
    marker = _source_marker(module, tmp_path)
    assert module.REQUIRED_HRH_SHA == SOURCE_HEAD
    assert module.REQUIRED_HRH_TREE == SOURCE_TREE
    assert marker["schema"] == "restricted-synthetic-clinical-staging.v1"
    assert set(marker) == {
        "schema", "synthetic_only", "project", "state_dir", "state_id",
        "compose_env_sha256", "lifecycle", "runtime_head", "runtime_tree",
        "hrh_head", "hrh_tree", "volumes", "expected_images",
    }
    assert module.read_marker(_paths(tmp_path)[0], PROJECT) == marker
    assert module.BACKUP_SCHEMA == "restricted-synthetic-clinical-cold-backup.v1"
    assert module.canonical_json_bytes(marker) == (json.dumps(marker, sort_keys=True, separators=(",", ":")) + "\n").encode()


def test_a14_source_status_keeps_built_images_not_published_evidence(module, tmp_path, monkeypatch):
    marker = _source_marker(module, tmp_path)
    state, hrh = _paths(tmp_path)
    (state / "evidence").mkdir()
    staging = module.ClinicalStaging(ROOT, hrh, state, PROJECT, 18443)
    images = {service: "sha256:" + "3" * 64 for service in module.LONG_RUNNING_SERVICES}
    marker["expected_images"] = images
    monkeypatch.setattr(staging, "_require_linux", lambda: None)
    monkeypatch.setattr(staging, "_verify_marker_and_source", lambda: marker)
    monkeypatch.setattr(staging, "_containers", lambda **_: [])
    monkeypatch.setattr(module, "verify_compose_rows", lambda _: None)
    monkeypatch.setattr(staging, "_assert_no_controller", lambda: None)
    inspections = {service: {} for service in (*module.LONG_RUNNING_SERVICES, *module.ONE_SHOT_SERVICES)}
    inspections["ingress"] = {"State": {"StartedAt": "2026-09-07T12:00:00Z"}}
    monkeypatch.setattr(staging, "_container_inspections", lambda: inspections)
    monkeypatch.setattr(staging, "_network_inspections", lambda: {})
    monkeypatch.setattr(module, "verify_publishers", lambda *_: {})
    monkeypatch.setattr(module, "verify_network_topology", lambda *_: None)
    monkeypatch.setattr(module, "verify_restricted_container_controls", lambda *_: {})
    monkeypatch.setattr(staging, "control", lambda *_: "synthetic-policy-digest")
    monkeypatch.setattr(staging, "_probe_mattermost_tls", lambda: {"verified": True})
    monkeypatch.setattr(staging, "_wait_for_authenticated_ingress", lambda *_: None)
    monkeypatch.setattr(staging, "_built_images", lambda: images)
    monkeypatch.setattr(staging, "compose", lambda *_, **__: SimpleNamespace(stdout=json.dumps({"uid": 10008, "gid": 20006, "mode": 0o660, "socket": True})))
    receipt = staging.status()
    assert receipt["built_images"] == images and "effective_images" not in receipt
    assert receipt["schema"] == marker["schema"]


def test_a18_source_reset_preserves_destroy_then_reinitialize(module, tmp_path, monkeypatch, capsys):
    _source_marker(module, tmp_path)
    state, hrh = _paths(tmp_path)
    for name in ("seed", "evidence"):
        (state / name).mkdir()
    actions = []
    monkeypatch.setattr(module, "persistent_operator_lock", lambda *_: nullcontext())
    monkeypatch.setattr(module.ClinicalStaging, "_require_linux", lambda self: None)
    monkeypatch.setattr(module.ClinicalStaging, "_destroy_resources", lambda self: actions.append("destroy"))
    monkeypatch.setenv("CLINICAL_E2E_HRH_MODE", "published")

    def reinitialize(self):
        assert actions == ["destroy"]
        assert not any((state / name).exists() for name in ("seed", "evidence", module.MARKER_NAME, "compose.env"))
        actions.append("init")
        return {"built_images": {}, "synthetic_only": True}

    monkeypatch.setattr(module.ClinicalStaging, "init", reinitialize)
    assert module.main(_argv(tmp_path, "reset", with_root=True)) == 0
    assert json.loads(capsys.readouterr().out) == {"built_images": {}, "synthetic_only": True}
    assert actions == ["destroy", "init"]
