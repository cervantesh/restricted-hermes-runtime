import shutil
import subprocess
import pytest

@pytest.mark.skipif(shutil.which("docker") is None,reason="Docker CLI unavailable")
def test_image_recipe_has_no_dynamic_capabilities():
    # Build execution is intentionally a separate operator/CI gate; recipe scan
    # catches accidental home/.env/plugin additions without inventing an image pass.
    conversation=open("Dockerfile.conversation",encoding="utf-8").read()
    gateway=open("Dockerfile.gateway",encoding="utf-8").read()
    for recipe in (conversation,gateway):
        assert ".env" not in recipe and "hermes" not in recipe.lower() and "USER " in recipe
