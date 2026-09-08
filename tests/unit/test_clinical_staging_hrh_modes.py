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


# U2 tests intentionally exercise only the pure decision boundary. The real
# operator parser/process and effective-Compose witnesses above stay RED until
# the integrator owns their wiring. A marker header here represents input from
# the future closed marker reader, not proof of a valid published generation.
@pytest.fixture
def pure_mode(monkeypatch):
    path = STAGING.with_name("clinical_hrh_mode.py")
    spec = importlib.util.spec_from_file_location("clinical_hrh_mode_u2", path)
    assert spec is not None and spec.loader is not None
    loaded = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, loaded)
    spec.loader.exec_module(loaded)
    return loaded


@pytest.mark.parametrize("command", ["init", "restore"])
@pytest.mark.parametrize("explicit", [False, True])
def test_u2_source_creation_preserves_default_and_overlay(pure_mode, tmp_path, command, explicit):
    options = ["--hrh-root", str(tmp_path / "not-yet-read")]
    if explicit:
        options += ["--hrh-mode", "source-build"]
    plan = pure_mode.plan_hrh_mode(command, options)
    assert plan.mode == "source-build"
    assert plan.source_root == tmp_path / "not-yet-read"
    assert plan.published_inputs is None
    assert plan.overlay == "compose.source-build.yaml"
    assert plan.build_hrh is True
    assert plan.acquire_hrh is False
    assert plan.compose_pull_policy is None
    assert not plan.source_root.exists()


@pytest.mark.parametrize("command", ["init", "restore", *ORDINARY])
def test_u2_every_source_command_requires_explicit_root(pure_mode, command):
    header = {"marker_schema": pure_mode.SOURCE_MARKER_SCHEMA} if command in ORDINARY else {}
    with pytest.raises(pure_mode.ModeError, match="--hrh-root"):
        pure_mode.plan_hrh_mode(command, (), environment={"CLINICAL_HRH_ROOT": "ambient-root"}, **header)


@pytest.mark.parametrize("command", ["init", "restore"])
def test_u2_published_creation_requires_exact_inputs_and_overlay(pure_mode, tmp_path, command):
    plan = pure_mode.plan_hrh_mode(command, ["--hrh-mode", "published", *_publication_arguments(tmp_path)], environment={})
    assert plan.mode == "published" and plan.source_root is None
    assert plan.published_inputs.trust == tmp_path / "trust.json"
    assert plan.published_inputs.evidence == tmp_path / "evidence"
    assert plan.published_inputs.docker_config == tmp_path / "docker-reader"
    assert plan.overlay == "compose.published-hrh.yaml"
    assert plan.build_hrh is False and plan.acquire_hrh is True
    assert plan.compose_pull_policy == "never"
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("command", ["init", "restore"])
@pytest.mark.parametrize("flag", PUBLISHED_FLAGS)
def test_u2_published_creation_rejects_each_missing_path(pure_mode, tmp_path, command, flag):
    options = _publication_arguments(tmp_path)
    index = options.index(flag)
    del options[index:index + 2]
    with pytest.raises(pure_mode.ModeError, match=flag):
        pure_mode.plan_hrh_mode(command, ["--hrh-mode", "published", *options], environment={})


@pytest.mark.parametrize("mode", ["source", "Published", "SOURCE-BUILD", "", " published"])
def test_u2_exact_modes_only(pure_mode, mode):
    with pytest.raises(pure_mode.ModeError, match="--hrh-mode"):
        pure_mode.plan_hrh_mode("init", ["--hrh-mode", mode, "--hrh-root", "synthetic-root"])


@pytest.mark.parametrize("flag", ["--hrh-mode", "--hrh-root", *PUBLISHED_FLAGS])
@pytest.mark.parametrize("equals", [False, True])
def test_u2_duplicate_option_is_not_last_writer_wins(pure_mode, tmp_path, flag, equals):
    first = "published" if flag == "--hrh-mode" else "synthetic-first"
    second = [f"{flag}=synthetic-second"] if equals else [flag, "synthetic-second"]
    with pytest.raises(pure_mode.ModeError, match="duplicate"):
        pure_mode.plan_hrh_mode("init", [flag, first, *second])


@pytest.mark.parametrize("flag", ["--hrh", "--hrh-tr", "--hrh-receipt", "--hrh-signature", "--hrh-public-key"])
def test_u2_unknown_option_cannot_create_duplicate_authority(pure_mode, flag):
    with pytest.raises(pure_mode.ModeError, match="unsupported"):
        pure_mode.plan_hrh_mode("init", [flag, "synthetic-private-path"])


@pytest.mark.parametrize("command", ["init", "restore"])
@pytest.mark.parametrize("flag", PUBLISHED_FLAGS)
def test_u2_source_creation_rejects_acquisition_inputs(pure_mode, command, flag):
    with pytest.raises(pure_mode.ModeError, match="source-build"):
        pure_mode.plan_hrh_mode(command, ["--hrh-root", "source", flag, "private-input"])


@pytest.mark.parametrize("command", ORDINARY)
@pytest.mark.parametrize("flag", ["--hrh-mode", *PUBLISHED_FLAGS])
def test_u2_ordinary_commands_reject_second_authority(pure_mode, command, flag):
    with pytest.raises(pure_mode.ModeError, match="ordinary"):
        pure_mode.plan_hrh_mode(command, [flag, "published"], marker_schema=pure_mode.PUBLISHED_MARKER_SCHEMA)


@pytest.mark.parametrize("command", ORDINARY)
def test_u2_ordinary_source_plan_uses_marker_not_environment(pure_mode, command):
    plan = pure_mode.plan_hrh_mode(command, ["--hrh-root", "synthetic-source"],
        marker_schema=pure_mode.SOURCE_MARKER_SCHEMA,
        environment={"CLINICAL_E2E_HRH_MODE": "published", "CLINICAL_HRH_MODE": "published"})
    assert plan.mode == "source-build" and plan.acquire_hrh is False
    assert plan.overlay == "compose.source-build.yaml"


@pytest.mark.parametrize("command", [name for name in ORDINARY if name != "reset"])
def test_u2_ordinary_published_plan_has_no_acquisition(pure_mode, command):
    plan = pure_mode.plan_hrh_mode(command, (), marker_schema=pure_mode.PUBLISHED_MARKER_SCHEMA,
        marker_lifecycle="ready", environment={"CLINICAL_HRH_MODE": "source-build"})
    assert plan.mode == "published" and plan.source_root is None
    assert plan.published_inputs is None and plan.acquire_hrh is False
    assert plan.compose_pull_policy == "never"


@pytest.mark.parametrize("schema", [None, "", "source-build", "published", "restricted-synthetic-clinical-staging.v2"])
def test_u2_missing_or_unknown_marker_schema_never_defaults_to_source(pure_mode, schema):
    with pytest.raises(pure_mode.ModeError, match="marker"):
        pure_mode.plan_hrh_mode("status", ["--hrh-root", "synthetic"], marker_schema=schema)


@pytest.mark.parametrize("command", ["init", "restore", "status"])
@pytest.mark.parametrize("root_source", ["argument", "environment", "empty-environment"])
def test_u2_published_rejects_any_source_root_authority(pure_mode, tmp_path, command, root_source):
    options = ["--hrh-mode", "published", *_publication_arguments(tmp_path)] if command != "status" else []
    environment = {}
    if root_source == "argument":
        options += ["--hrh-root", "source"]
    else:
        environment["CLINICAL_HRH_ROOT"] = "" if root_source == "empty-environment" else "source"
    header = {"marker_schema": pure_mode.PUBLISHED_MARKER_SCHEMA} if command == "status" else {}
    with pytest.raises(pure_mode.ModeError, match="HRH root"):
        pure_mode.plan_hrh_mode(command, options, environment=environment, **header)


def test_u2_environment_cannot_supply_published_acquisition(pure_mode):
    environment = {name: "ambient-secret-path" for name in (
        "CLINICAL_HRH_TRUST", "CLINICAL_HRH_EVIDENCE", "CLINICAL_HRH_DOCKER_CONFIG")}
    with pytest.raises(pure_mode.ModeError, match="--hrh-trust"):
        pure_mode.plan_hrh_mode("init", ["--hrh-mode", "published"], environment=environment)


def test_u2_published_reset_is_denied_with_recovery_direction(pure_mode):
    with pytest.raises(pure_mode.ModeError, match="destroy.*init/restore"):
        pure_mode.plan_hrh_mode("reset", (), marker_schema=pure_mode.PUBLISHED_MARKER_SCHEMA, environment={})


@pytest.mark.parametrize("lifecycle", ["initializing", "finalizing"])
def test_u2_published_resume_requires_explicit_fresh_inputs(pure_mode, tmp_path, lifecycle):
    header = {"marker_schema": pure_mode.PUBLISHED_MARKER_SCHEMA, "marker_lifecycle": lifecycle, "environment": {}}
    with pytest.raises(pure_mode.ModeError, match="explicit.*published"):
        pure_mode.plan_hrh_mode("init", (), **header)
    with pytest.raises(pure_mode.ModeError, match="--hrh-trust"):
        pure_mode.plan_hrh_mode("init", ["--hrh-mode", "published"], **header)
    plan = pure_mode.plan_hrh_mode("init", ["--hrh-mode", "published", *_publication_arguments(tmp_path)], **header)
    assert plan.acquire_hrh is True
    with pytest.raises(pure_mode.ModeError, match="resume"):
        pure_mode.plan_hrh_mode("up", (), **header)


@pytest.mark.parametrize("lifecycle", [None, "ready", "stopped", "recovering", "renewing_tls", "tls_prepared", "unknown"])
def test_u2_published_init_cannot_resume_an_unapproved_lifecycle(pure_mode, tmp_path, lifecycle):
    with pytest.raises(pure_mode.ModeError, match="resume"):
        pure_mode.plan_hrh_mode("init", ["--hrh-mode", "published", *_publication_arguments(tmp_path)],
            marker_schema=pure_mode.PUBLISHED_MARKER_SCHEMA, marker_lifecycle=lifecycle, environment={})


def test_u2_existing_generation_cannot_switch_modes(pure_mode, tmp_path):
    with pytest.raises(pure_mode.ModeError, match="marker"):
        pure_mode.plan_hrh_mode("init", ["--hrh-mode", "published", *_publication_arguments(tmp_path)],
            marker_schema=pure_mode.SOURCE_MARKER_SCHEMA, marker_lifecycle="initializing")


def test_u2_planning_never_resolves_paths_or_invokes_children(pure_mode, tmp_path, monkeypatch):
    def denied(*args, **kwargs):
        pytest.fail("pure mode planning performed filesystem or process I/O")

    monkeypatch.setattr(Path, "resolve", denied)
    monkeypatch.setattr(Path, "stat", denied)
    monkeypatch.setattr(Path, "open", denied)
    monkeypatch.setattr(subprocess, "run", denied)
    plan = pure_mode.plan_hrh_mode("restore", ["--hrh-mode", "published", *_publication_arguments(tmp_path)], environment={})
    assert plan.acquire_hrh is True
    assert "docker-reader" not in repr(plan)


@pytest.mark.parametrize("lifecycle", [None, "", "unknown"])
def test_u2_published_up_requires_supplied_lifecycle(pure_mode, lifecycle):
    header = {} if lifecycle is None else {"marker_lifecycle": lifecycle}
    with pytest.raises(pure_mode.ModeError, match="lifecycle"):
        pure_mode.plan_hrh_mode("up", (), marker_schema=pure_mode.PUBLISHED_MARKER_SCHEMA,
            environment={}, **header)


@pytest.mark.parametrize("command", ["init", "restore", *ORDINARY])
def test_u2_published_plan_requires_explicit_environment(pure_mode, tmp_path, command):
    options = ["--hrh-mode", "published", *_publication_arguments(tmp_path)] if command in {"init", "restore"} else []
    header = {"marker_schema": pure_mode.PUBLISHED_MARKER_SCHEMA, "marker_lifecycle": "ready"} if command in ORDINARY else {}
    with pytest.raises(pure_mode.ModeError, match="environment mapping"):
        pure_mode.plan_hrh_mode(command, options, **header)


@pytest.mark.parametrize("environment", [None, "", [], True])
def test_u2_published_environment_requires_mapping(pure_mode, tmp_path, environment):
    with pytest.raises(pure_mode.ModeError, match="environment mapping"):
        pure_mode.plan_hrh_mode("init", ["--hrh-mode", "published", *_publication_arguments(tmp_path)],
            environment=environment)


def _fake_published_verifier(tmp_path, calls):
    trust = {
        "clinical_contract_revision": "c" * 40,
        "build_source_revision": "d" * 40,
        "platform": {"os": "linux", "architecture": "amd64"},
        "publisher_identity": "synthetic@example.invalid",
        "kms_key_version": "projects/test/locations/global/keyRings/test/cryptoKeys/test/cryptoKeyVersions/1",
        "kms_public_key_sha256": "1" * 64,
        "subjects": {
            "web": "registry.invalid/hrh/web@sha256:" + "2" * 64,
            "migrate": "registry.invalid/hrh/migrate@sha256:" + "3" * 64,
            "evidence": "registry.invalid/hrh/evidence@sha256:" + "4" * 64,
        },
    }
    receipt = b"{}"
    files = {"candidate-receipt.json": receipt, "kms-public.pem": b"public"}

    def verify_files(trust_path, evidence, docker_config, *, docker_config_snapshot, runner):
        calls.append(("verify", docker_config_snapshot))
        docker_config_snapshot.mkdir()
        (docker_config_snapshot / "config.json").write_text('{"auths":{}}')
        return {
            "schema_version": "restricted-runtime-hrh-verification.v2",
            "trust_sha256": "5" * 64,
            "receipt_sha256": "6" * 64,
            "receipt_signature_sha256": "7" * 64,
            "evidence_manifest_sha256": "8" * 64,
            "kms_public_key_sha256": "1" * 64,
            "subjects": trust["subjects"],
            "verified_predicates": ["migrate:provenance", "web:provenance"],
        }

    return SimpleNamespace(
        _read_regular_snapshot=lambda path, name: json.dumps(trust).encode(),
        read_evidence_snapshot=lambda path: files,
        _parse_snapshot=lambda data, name: trust if name == "trust declaration" else {},
        validate_candidate=lambda *args: {"trust": trust},
        verify_files=verify_files,
        sealed_docker_environment=lambda: {"PATH": "synthetic"},
        canonical_verification_bytes=lambda result: json.dumps(result, sort_keys=True).encode(),
        CandidateVerificationError=ValueError,
    )


def test_a07_a09_acquisition_uses_one_private_config_and_deletes_it(pure_mode, tmp_path):
    calls = []
    verifier = _fake_published_verifier(tmp_path, calls)
    inputs = pure_mode.PublishedInputs(tmp_path / "trust", tmp_path / "evidence", tmp_path / "docker")

    def runner(args, **kwargs):
        assert "credential-sentinel" not in repr((args, kwargs))
        calls.append((tuple(args[1:3]), Path(kwargs["env"]["DOCKER_CONFIG"])))
        if args[2] == "inspect":
            subject = args[-1]
            stdout = json.dumps([{
                "Id": "sha256:" + ("a" if "/web@" in subject else "b") * 64,
                "RepoDigests": [subject], "Os": "linux", "Architecture": "amd64",
            }])
        else:
            stdout = ""
        return subprocess.CompletedProcess(args, 0, stdout, "")

    result = pure_mode.acquire_published_candidate(
        ROOT, inputs, tmp_path / "snapshots", runner=runner, verifier=verifier,
    )
    configs = {path for _, path in calls}
    assert len(configs) == 1
    assert not next(iter(configs)).exists()
    assert [entry[0] for entry in calls] == [
        "verify", ("image", "pull"), ("image", "inspect"),
        ("image", "pull"), ("image", "inspect"),
    ]
    assert set(result.effective_images) == {"hrh", "hrh-migrate"}


@pytest.mark.skipif(os.name != "posix", reason="run-owned cleanup is a Linux operator contract")
def test_a09_next_acquisition_removes_only_bounded_same_project_orphan(pure_mode, tmp_path):
    parent = tmp_path / "snapshots"
    parent.mkdir(mode=0o700)
    orphan = parent / f".published-acquire-{PROJECT}-{'a' * 16}"
    orphan.mkdir(mode=0o700)
    (orphan / "credential-sentinel").write_text("private")
    other = parent / f".published-acquire-otherproject-{'b' * 16}"
    other.mkdir(mode=0o700)
    calls = []
    verifier = _fake_published_verifier(tmp_path, calls)
    inputs = pure_mode.PublishedInputs(tmp_path / "trust", tmp_path / "evidence", tmp_path / "docker")

    def runner(args, **kwargs):
        subject = args[-1]
        raw = json.dumps([{"Id": "sha256:" + "a" * 64, "RepoDigests": [subject], "Os": "linux", "Architecture": "amd64"}])
        return subprocess.CompletedProcess(args, 0, raw if args[2] == "inspect" else "", "")

    pure_mode.acquire_published_candidate(ROOT, inputs, parent, runner=runner, verifier=verifier, snapshot_key=PROJECT)
    assert not orphan.exists() and other.exists()


def test_a10_published_marker_is_closed_and_role_specific(pure_mode, tmp_path):
    calls = []
    verifier = _fake_published_verifier(tmp_path, calls)
    inputs = pure_mode.PublishedInputs(tmp_path / "trust", tmp_path / "evidence", tmp_path / "docker")

    def runner(args, **kwargs):
        subject = args[-1]
        raw = json.dumps([{"Id": "sha256:" + "a" * 64, "RepoDigests": [subject], "Os": "linux", "Architecture": "amd64"}])
        return subprocess.CompletedProcess(args, 0, raw if args[2] == "inspect" else "", "")

    acquired = pure_mode.acquire_published_candidate(ROOT, inputs, tmp_path / "runs", runner=runner, verifier=verifier)
    state = tmp_path / f"{PROJECT}.synthetic-clinical-staging"
    volumes = {"v": "synthetic"}
    marker = pure_mode.new_published_marker(
        project=PROJECT, state_dir=state, state_id="a" * 32, env_sha256="b" * 64,
        runtime_head="c" * 40, runtime_tree="d" * 40, volumes=volumes, acquisition=acquired,
    )
    assert pure_mode.validate_published_marker(marker, project=PROJECT, state_dir=state, expected_volumes=volumes) == marker
    marker["unknown"] = True
    with pytest.raises(pure_mode.ModeError, match="unknown"):
        pure_mode.validate_published_marker(marker, project=PROJECT, state_dir=state, expected_volumes=volumes)


def test_a10_status_rechecks_container_and_local_image_identity(pure_mode):
    subjects = {"hrh": "registry.invalid/hrh/web@sha256:" + "2" * 64,
                "hrh-migrate": "registry.invalid/hrh/migrate@sha256:" + "3" * 64}
    effective = {service: {"subject": subject, "repo_digest": subject,
                           "image_id": "sha256:" + ("a" if service == "hrh" else "b") * 64,
                           "platform": {"os": "linux", "architecture": "amd64"}}
                 for service, subject in subjects.items()}
    containers = {service: {"Image": value["image_id"], "Config": {"Image": value["subject"]}}
                  for service, value in effective.items()}

    def runner(args, **kwargs):
        expected = effective["hrh" if "/web@" in args[-1] else "hrh-migrate"]
        raw = json.dumps([{"Id": expected["image_id"], "RepoDigests": [expected["subject"]],
                           "Os": "linux", "Architecture": "amd64"}])
        assert "DOCKER_CONFIG" not in kwargs["env"]
        return subprocess.CompletedProcess(args, 0, raw, "")

    pure_mode.verify_effective_containers({"effective_images": effective}, containers, runner=runner)
    containers["hrh"]["Config"]["Image"] = subjects["hrh-migrate"]
    with pytest.raises(pure_mode.ModeError, match="container identity"):
        pure_mode.verify_effective_containers({"effective_images": effective}, containers, runner=runner)


def test_a12_published_up_forces_pull_never(module, tmp_path, monkeypatch):
    plan = module.hrh_mode.HRHModePlan("up", "published")
    staging = module.ClinicalStaging(ROOT, None, _paths(tmp_path)[0], PROJECT, 18443, mode_plan=plan)
    calls = []
    monkeypatch.setattr(staging, "_require_linux", lambda: None)
    monkeypatch.setattr(module, "persistent_operator_lock", lambda *args: nullcontext())
    monkeypatch.setattr(module, "_exclusive_operator_lock", lambda *args: nullcontext())
    monkeypatch.setattr(staging, "_verify_marker_and_source", lambda: {"lifecycle": "ready"})
    monkeypatch.setattr(staging, "compose", lambda *args, **kwargs: calls.append(args))
    monkeypatch.setattr(staging, "control", lambda *args, **kwargs: "")
    monkeypatch.setattr(staging, "status", lambda: {"ok": True})
    assert staging.up() == {"ok": True}
    assert calls == [("up", "--pull", "never", "--detach", *module.ONE_SHOT_SERVICES, *module.LONG_RUNNING_SERVICES)]


def test_a07_a11_published_init_publishes_marker_before_volumes_and_stops_on_migration(module, tmp_path, monkeypatch):
    state = _paths(tmp_path)[0]
    inputs = module.hrh_mode.plan_hrh_mode("init", ["--hrh-mode", "published", *_publication_arguments(tmp_path)], environment={}).published_inputs
    plan = module.hrh_mode.HRHModePlan("init", "published", published_inputs=inputs)
    staging = module.ClinicalStaging(ROOT, None, state, PROJECT, 18443, mode_plan=plan)
    acquired = SimpleNamespace(candidate={"subjects": {"web": "web", "migrate": "migrate"}}, effective_images={})
    marker = {"lifecycle": "initializing", "volumes": {}, "state_id": "a" * 32}
    order = []
    owner = os.getuid() if hasattr(os, "getuid") else 0
    monkeypatch.setattr(staging, "_require_linux", lambda: None)
    monkeypatch.setattr(module, "persistent_operator_lock", lambda *args: nullcontext())
    monkeypatch.setattr(module, "_exclusive_operator_lock", lambda *args: nullcontext())
    monkeypatch.setattr(module.hrh_mode, "verify_runtime_frame", lambda *args, **kwargs: {"runtime_head": "c" * 40, "runtime_tree": "d" * 40})
    monkeypatch.setattr(module.hrh_mode, "acquire_published_candidate", lambda *args, **kwargs: acquired)

    def publish(*args):
        order.append("marker")
        state.mkdir()
        return marker

    monkeypatch.setattr(staging, "_prepare_new_state", publish)
    monkeypatch.setattr(staging, "_reconcile_owned_initialization_orphans", lambda: None)
    monkeypatch.setattr(staging, "_create_volumes", lambda value: order.append("volumes"))
    monkeypatch.setattr(staging, "_build_images", lambda: order.append("build"))
    monkeypatch.setattr(staging, "control", lambda *args, **kwargs: order.append(("control", args)) or "")
    monkeypatch.setattr(module.stat, "S_IMODE", lambda mode: 0o700)
    monkeypatch.setattr(module.os, "getuid", lambda: owner, raising=False)

    def compose(*args, **kwargs):
        order.append(("compose", args))
        return subprocess.CompletedProcess(args, 1 if args[:2] == ("wait", "hrh-migrate") else 0, "", "")

    monkeypatch.setattr(staging, "compose", compose)
    with pytest.raises(module.CommandError, match="migration"):
        staging.init()
    assert order[:2] == ["marker", "volumes"]
    assert [item[1] for item in order if isinstance(item, tuple) and item[0] == "control"] == [("seed-volumes",)]
    starts = [item[1] for item in order if isinstance(item, tuple) and item[0] == "compose" and item[1][:1] == ("up",)]
    assert starts == [("up", "--detach", "mattermost-postgres", "hrh-postgres", "hrh-migrate")]


def test_a17_creation_rejects_marker_mode_swap_before_resources(module, tmp_path, monkeypatch):
    state = _paths(tmp_path)[0]
    state.mkdir()
    (state / module.MARKER_NAME).write_text("{}")
    inputs = module.hrh_mode.plan_hrh_mode("init", ["--hrh-mode", "published", *_publication_arguments(tmp_path)], environment={}).published_inputs
    staging = module.ClinicalStaging(ROOT, None, state, PROJECT, 18443, mode_plan=module.hrh_mode.HRHModePlan("init", "published", published_inputs=inputs))
    monkeypatch.setattr(staging, "_require_linux", lambda: None)
    monkeypatch.setattr(module, "persistent_operator_lock", lambda *args: nullcontext())
    monkeypatch.setattr(module, "_exclusive_operator_lock", lambda *args: nullcontext())
    monkeypatch.setattr(module.hrh_mode, "verify_runtime_frame", lambda *args, **kwargs: {"runtime_head": "c" * 40, "runtime_tree": "d" * 40})
    monkeypatch.setattr(module.hrh_mode, "acquire_published_candidate", lambda *args, **kwargs: SimpleNamespace(candidate={}, effective_images={}))
    monkeypatch.setattr(module, "read_marker", lambda *args: {"schema": module.SCHEMA, "lifecycle": "initializing"})
    monkeypatch.setattr(staging, "_create_volumes", lambda *args: pytest.fail("mode swap reached resources"))
    with pytest.raises(module.SafetyError, match="mode changed"):
        staging.init()


@pytest.mark.parametrize("command", ["init", "status"])
def test_a02_duplicate_global_hrh_root_is_rejected(module, tmp_path, command):
    args = _argv(tmp_path, command, with_root=True)
    args[2:2] = ["--hrh-root", str(tmp_path / "other-hrh")]
    with pytest.raises(SystemExit):
        module.parse_args(args)


@pytest.mark.parametrize("lifecycle", ["stopped", "renewing_tls", "tls_prepared"])
def test_a03_mutator_rebinds_fresh_marker_inside_lock(module, tmp_path, monkeypatch, lifecycle):
    state, hrh = _paths(tmp_path)
    markers = iter([
        {"schema": module.SCHEMA, "lifecycle": "ready", "state_id": "a" * 32},
        {"schema": module.SCHEMA, "lifecycle": lifecycle, "state_id": "b" * 32},
    ])
    monkeypatch.setattr(module, "read_marker", lambda *args: next(markers))
    staging = module.ClinicalStaging(ROOT, hrh, state, PROJECT, 18443, persisted_command="status")
    monkeypatch.setattr(module, "persistent_operator_lock", lambda *args: nullcontext())
    monkeypatch.setattr(staging, "_require_linux", lambda: None)
    monkeypatch.setattr(staging, "_verify_marker_and_source", lambda: staging._locked_marker)
    with pytest.raises(module.SafetyError, match="status rejects"):
        staging.status()


def test_a03_mutator_uses_fresh_generation_not_constructor_generation(module, tmp_path, monkeypatch):
    state, hrh = _paths(tmp_path)
    markers = iter([
        {"schema": module.SCHEMA, "lifecycle": "ready", "state_id": "a" * 32},
        {"schema": module.SCHEMA, "lifecycle": "ready", "state_id": "b" * 32},
    ])
    monkeypatch.setattr(module, "read_marker", lambda *args: next(markers))
    staging = module.ClinicalStaging(ROOT, hrh, state, PROJECT, 18443, persisted_command="stop")
    monkeypatch.setattr(module, "persistent_operator_lock", lambda *args: nullcontext())
    monkeypatch.setattr(staging, "_require_linux", lambda: None)
    monkeypatch.setattr(staging, "_verify_marker_and_source", lambda: staging._locked_marker)
    monkeypatch.setattr(staging, "compose", lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, "", ""))
    written = []
    monkeypatch.setattr(staging, "_write_marker", lambda marker: written.append(dict(marker)))
    monkeypatch.setattr(module, "write_json_atomic", lambda *args, **kwargs: None)
    assert staging.stop()["state_id"] == "b" * 32
    assert written[0]["state_id"] == "b" * 32


def test_a03_destroy_uses_fresh_generation_inside_lock(module, tmp_path, monkeypatch):
    state, hrh = _paths(tmp_path)
    markers = iter([
        {"schema": module.SCHEMA, "lifecycle": "ready", "state_id": "a" * 32},
        {"schema": module.SCHEMA, "lifecycle": "stopped", "state_id": "b" * 32},
    ])
    monkeypatch.setattr(module, "read_marker", lambda *args: next(markers))
    staging = module.ClinicalStaging(ROOT, hrh, state, PROJECT, 18443, persisted_command="destroy")
    monkeypatch.setattr(module, "persistent_operator_lock", lambda *args: nullcontext())
    monkeypatch.setattr(staging, "_require_linux", lambda: None)
    monkeypatch.setattr(staging, "_destroy_resources", lambda: None)
    monkeypatch.setattr(staging, "_assert_destroyed_absent", lambda: None)
    monkeypatch.setattr(module.shutil, "rmtree", lambda *args, **kwargs: None)
    assert staging.destroy()["state_id"] == "b" * 32


def test_a08_every_published_compose_up_injects_pull_never(module, tmp_path):
    class CaptureShell:
        def __init__(self): self.args = None
        def run(self, *args, **kwargs):
            self.args = args
            return subprocess.CompletedProcess(args, 0, "", "")

    shell = CaptureShell()
    staging = module.ClinicalStaging(ROOT, None, _paths(tmp_path)[0], PROJECT, 18443, shell=shell, mode_plan=module.hrh_mode.HRHModePlan("init", "published"))
    staging.state_dir.mkdir()
    staging.env_file.write_text("CLINICAL_TEST=value\n")
    staging.compose("up", "--detach", "hrh-postgres", "hrh-migrate")
    index = shell.args.index("up")
    assert shell.args[index:index + 3] == ("up", "--pull", "never")
