"""Executable closure probe intended to run inside the built ingress image."""
from __future__ import annotations

import importlib.util
import os

import pytest


pytestmark = pytest.mark.skipif(
    os.environ.get("RESTRICTED_MATTERMOST_IMAGE_PROBE") != "1",
    reason="must execute inside the built Mattermost ingress image",
)


def test_built_ingress_image_import_surface_is_closed():
    import restricted_runtime.mattermost_ingress  # noqa: F401
    import restricted_runtime.mattermost_policy  # noqa: F401

    forbidden = ("run_agent", "gateway", "tools", "plugins", "psycopg", "fastapi", "uvicorn")
    assert {name: importlib.util.find_spec(name) for name in forbidden} == {
        name: None for name in forbidden
    }
