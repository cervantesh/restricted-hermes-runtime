from __future__ import annotations

import ast
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_mattermost_role_is_standalone_and_has_no_normal_hermes_or_provider_surface():
    files = [
        ROOT / "src/restricted_runtime/mattermost_policy.py",
        ROOT / "src/restricted_runtime/mattermost_outbox.py",
        ROOT / "src/restricted_runtime/mattermost_ingress.py",
        ROOT / "src/restricted_runtime/services/production_mattermost_ingress.py",
    ]
    forbidden = ("run_agent", "plugins", "tools", "gateway", "vertex", "database", "conversation_storage")
    for path in files:
        imported = set()
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        assert all(term not in module for module in imported for term in forbidden)


def test_dedicated_image_is_nonroot_and_removes_unrelated_runtime_modules():
    recipe = (ROOT / "Dockerfile.mattermost-ingress").read_text(encoding="utf-8")
    assert "USER restricted-mattermost-ingress" in recipe
    assert "pip install --no-cache-dir --no-deps ." in recipe
    assert "psycopg" not in recipe
    assert "10007" in recipe and "20001" in recipe
    assert "Dockerfile.local-conversation" not in recipe
    assert "find /usr/local/lib/python3.11/site-packages/restricted_runtime" in recipe
    for allowed in ("contracts.py", "mattermost_policy.py", "mattermost_outbox.py", "mattermost_ingress.py", "upstream_deadline.py", "production_mattermost_ingress.py", "mattermost_outbox_init.py"):
        assert f"! -name '{allowed}'" in recipe
    assert "HERMES" not in recipe and ".env" not in recipe


def test_versioned_container_closure_command_is_pytest_free_and_checks_ac9_imports():
    command = ROOT / "tests/deployment/test_mattermost_ingress_image.sh"
    source = command.read_text(encoding="utf-8")
    assert source.startswith("#!/usr/bin/env bash\n")
    assert "sg-mattermost-004" in source
    assert 'docker build -f Dockerfile.mattermost-ingress' in source
    assert 'docker run --rm --network none --entrypoint python' in source
    assert "pytest" not in source.lower()
    for module in (
        "restricted_runtime.upstream_deadline",
        "restricted_runtime.gateway",
        "restricted_runtime.vertex",
        "restricted_runtime.storage",
        "restricted_runtime.conversation",
        "restricted_runtime.crypto",
        "restricted_runtime.conversation_storage",
        "run_agent",
        "tools",
        "plugins",
        "fastapi",
        "uvicorn",
        "psycopg",
    ):
        assert module in source


def test_operator_docs_preserve_non_phi_and_duplicate_averse_delivery_contract():
    docs = (ROOT / "docs/design/restricted-mattermost-ingress.md").read_text(encoding="utf-8")
    for phrase in (
        "synthetic/non-PHI",
        "duplicate-averse",
        "does not claim exactly-once posting",
        "retention",
        "audit",
        "backup",
        "patching",
        "identity provider",
        "network",
    ):
        assert phrase.lower() in docs.lower()


def test_websocket_transport_requires_proxy_safe_version_and_reconnects_abnormal_closure():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    production = (ROOT / "src/restricted_runtime/services/production_mattermost_ingress.py").read_text(
        encoding="utf-8"
    )
    assert '"websockets>=15,<16"' in pyproject
    assert "ConnectionClosed" in production
    assert "except (OSError, TimeoutError, ConnectionClosed):" in production
    assert "delay = min(delay * 2, 30.0)" in production


def test_test_extra_owns_the_no_build_isolation_backend():
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert "setuptools>=69" in pyproject["project"]["optional-dependencies"]["test"]
