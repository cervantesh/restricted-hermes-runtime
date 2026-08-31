"""Static closure of the separate local profile; no mutable Vertex selection."""
from pathlib import Path


ROOT = Path("src/restricted_runtime")


def test_local_root_and_image_are_separate_from_vertex_root():
    for module, image, entry in (("production_local_gateway.py", "Dockerfile.local-gateway", "production_local_gateway:app"), ("production_local_conversation.py", "Dockerfile.local-conversation", "production_local_conversation:app")):
        root = (ROOT / "services" / module).read_text(encoding="utf-8")
        recipe = Path(image).read_text(encoding="utf-8")
        assert "GoogleKms" not in root and "google_kms" not in root and "VertexClient" not in root
        assert "LocalFileHmacKey" in root and "OperatorAuthorizationGate" in root
        assert entry in recipe and "restricted_runtime/google_kms.py" in recipe and "restricted_runtime/vertex.py" in recipe


def test_local_client_has_only_unix_socket_dispatch_and_closed_wire_literals():
    source = (ROOT / "local_uds.py").read_text(encoding="utf-8")
    for literal in ("socket.AF_UNIX", "socket.SOCK_STREAM", "POST /v1/restricted/generate HTTP/1.0", "trust_env"):
        # The client has no HTTP library/proxy path; the latter marker is not
        # applicable to raw sockets and is intentionally absent.
        if literal == "trust_env":
            assert literal not in source
        else:
            assert literal in source
    for forbidden in ("AF_INET", "AF_INET6", "httpx", "requests", "retry", "redirect", "stream"):
        assert forbidden not in source


def test_local_conversation_image_excludes_gateway_and_local_provider_modules():
    root = (ROOT / "services" / "production_local_conversation.py").read_text(encoding="utf-8")
    recipe = Path("Dockerfile.local-conversation").read_text(encoding="utf-8")
    assert "conversation_storage" in root and "from ..storage" not in root
    for module in ("gateway.py", "local_uds.py", "storage.py"):
        assert f"restricted_runtime/{module}" in recipe
