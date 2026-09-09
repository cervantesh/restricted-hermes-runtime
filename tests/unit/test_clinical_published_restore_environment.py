"""Focused controls for target-local published recovery environments."""

from __future__ import annotations

import base64
import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[2]
CAPSULE_PATH = ROOT / "deploy" / "clinical-staging" / "clinical_recovery_capsule.py"
PROJECT = "clinicalstagingrelocation"
STATE_ID = "1" * 32


def _load() -> ModuleType:
    name = "clinical_recovery_capsule_published_environment"
    spec = importlib.util.spec_from_file_location(name, CAPSULE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _identity(module: ModuleType) -> dict[str, Any]:
    subjects = {
        "web": "registry.invalid/hrh/web@sha256:" + "b" * 64,
        "migrate": "registry.invalid/hrh/migrate@sha256:" + "c" * 64,
    }
    return {
        "project": PROJECT,
        "state_id": STATE_ID,
        "hrh_candidate": {"subjects": subjects},
        "volumes": {
            key: f"{PROJECT}_{key}" for key in module.PUBLISHED_VOLUME_KEYS
        },
    }


def _environment(
    module: ModuleType, tmp_path: Path, *, port: int = 18443
) -> tuple[bytes, dict[str, str], Any, dict[str, Any]]:
    runtime = tmp_path / "runtime"
    state = tmp_path / "state"
    seed = state / "seed"
    seed.mkdir(parents=True)
    private = Ed25519PrivateKey.generate()
    (seed / "policy-private.pem").write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public = base64.b64encode(private.public_key().public_bytes_raw()).decode("ascii")
    identity = _identity(module)
    staging = type(
        "Staging",
        (),
        {
            "harness": runtime / "tests" / "deployment" / "clinical-composed-e2e",
            "state_dir": state,
            "port": port,
            "project": PROJECT,
        },
    )()
    secrets = {
        "CLINICAL_MM_DB_PASSWORD": "a" * 48,
        "CLINICAL_HRH_DB_PASSWORD": "b" * 48,
        "CLINICAL_HRH_SESSION_SECRET": "c" * 64,
        "CLINICAL_HRH_ENCRYPTION_KEY": "d" * 64,
    }
    values = {
        **secrets,
        "CLINICAL_HARNESS": staging.harness.as_posix(),
        "CLINICAL_SEED": seed.as_posix(),
        "CLINICAL_INGRESS_IMAGE": f"restricted-clinical-ingress:{PROJECT}",
        "CLINICAL_ADAPTER_IMAGE": f"restricted-clinical-adapter:{PROJECT}",
        "CLINICAL_POLICY_PUBLIC_KEY": public,
        "CLINICAL_STAGING_PROJECT": PROJECT,
        "CLINICAL_STAGING_STATE_ID": STATE_ID,
        "CLINICAL_STAGING_PORT": str(port),
        "CLINICAL_HRH_WEB_IMAGE": identity["hrh_candidate"]["subjects"]["web"],
        "CLINICAL_HRH_MIGRATE_IMAGE": identity["hrh_candidate"]["subjects"]["migrate"],
        **{
            f"CLINICAL_VOLUME_{key.upper()}": identity["volumes"][key]
            for key in module.PUBLISHED_VOLUME_KEYS
        },
    }
    raw = "".join(f"{key}={values[key]}\n" for key in module.PUBLISHED_ENV_KEYS).encode()
    return raw, secrets, staging, identity


def test_closed_published_environment_preserves_only_four_secrets(tmp_path: Path) -> None:
    module = _load()
    raw, secrets, _staging, _identity_value = _environment(module, tmp_path)

    assert len(module.PUBLISHED_ENV_KEYS) == 25
    parsed = module.parse_archived_published_environment(raw)
    assert set(parsed) == set(module.PUBLISHED_ENV_KEYS)
    assert {key: parsed[key] for key in secrets} == secrets


@pytest.mark.parametrize(
    "mutate",
    (
        lambda raw: raw.replace(b"CLINICAL_HARNESS=", b"CLINICAL_UNKNOWN=", 1),
        lambda raw: raw + b"CLINICAL_HRH_ROOT=/source-only\n",
        lambda raw: raw + raw.splitlines(keepends=True)[0],
        lambda raw: raw.replace(b"CLINICAL_HARNESS=", b"CLINICAL_HARNESS=\n", 1),
        lambda raw: raw.replace(b"a" * 48, b"A" * 48, 1),
        lambda raw: raw.replace(b"\n", b"\r\n", 1),
        lambda raw: raw.replace(b"=", b"=\x00", 1),
        lambda raw: raw.rstrip(b"\n"),
    ),
)
def test_closed_published_environment_rejects_noncanonical_inputs(
    tmp_path: Path, mutate
) -> None:
    module = _load()
    raw, _secrets, _staging, _identity_value = _environment(module, tmp_path)

    with pytest.raises(module.CapsuleError, match="RECOVERY_GENERATION_MISMATCH"):
        module.parse_archived_published_environment(mutate(raw))


def test_same_path_regeneration_is_byte_stable(tmp_path: Path) -> None:
    module = _load()
    raw, _secrets, staging, identity = _environment(module, tmp_path)

    assert module.render_effective_published_environment(
        staging, staging.state_dir, identity, identity,
        module.parse_archived_published_environment(raw),
    ) == raw


def test_regeneration_uses_current_port_as_an_integer_authority(tmp_path: Path) -> None:
    module = _load()
    raw, _secrets, staging, identity = _environment(module, tmp_path, port=28443)

    assert isinstance(staging.port, int)
    assert b"CLINICAL_STAGING_PORT=28443\n" in raw
    assert module.render_effective_published_environment(
        staging, staging.state_dir, identity, identity,
        module.parse_archived_published_environment(raw),
    ) == raw


@pytest.mark.parametrize(
    ("key", "replacement"),
    (
        ("CLINICAL_STAGING_PROJECT", "clinicalstagingother"),
        ("CLINICAL_HRH_WEB_IMAGE", "registry.invalid/hrh/web@sha256:" + "0" * 64),
        ("CLINICAL_INGRESS_IMAGE", "restricted-clinical-ingress:other"),
        ("CLINICAL_ADAPTER_IMAGE", "restricted-clinical-adapter:other"),
        ("CLINICAL_VOLUME_HRH_DB", "clinicalstagingother_hrh_db"),
        ("CLINICAL_POLICY_PUBLIC_KEY", "A" * 43 + "="),
    ),
)
def test_regeneration_rejects_inconsistent_authenticated_archived_fields(
    tmp_path: Path, key: str, replacement: str
) -> None:
    module = _load()
    raw, _secrets, staging, identity = _environment(module, tmp_path)
    archived = module.parse_archived_published_environment(raw)
    archived[key] = replacement

    with pytest.raises(module.CapsuleError, match="RECOVERY_GENERATION_MISMATCH"):
        module.render_effective_published_environment(
            staging, staging.state_dir, identity, identity, archived
        )


def test_regeneration_rejects_newline_path_before_environment_publication(
    tmp_path: Path,
) -> None:
    module = _load()
    raw, _secrets, staging, identity = _environment(module, tmp_path)
    restored_target = staging.state_dir
    staging.state_dir = tmp_path / "recovery\nDOCKER_HOST=tcp://attacker.invalid"
    archived = module.parse_archived_published_environment(raw)

    with pytest.raises(module.CapsuleError, match="RECOVERY_GENERATION_MISMATCH"):
        module.render_effective_published_environment(
            staging, restored_target, identity, identity, archived
        )
    assert not (restored_target / "compose.env").exists()
