"""Static closure of the separate local profile; no mutable Vertex selection."""
from pathlib import Path


ROOT = Path("src/restricted_runtime")


def test_local_root_and_image_are_separate_from_vertex_root():
    root = (ROOT / "services" / "production_local_gateway.py").read_text(encoding="utf-8")
    image = Path("Dockerfile.local-gateway").read_text(encoding="utf-8")
    assert "VertexClient" not in root and "production_gateway" not in root
    assert "LocalUdsClient(policy)" in root and "load_operator_authorization_files" in root
    assert "production_local_gateway:app" in image
    assert "restricted_runtime/vertex.py" in image


def test_local_client_has_only_unix_socket_dispatch_and_closed_wire_literals():
    source = (ROOT / "local_uds.py").read_text(encoding="utf-8")
    for literal in ("socket.AF_UNIX", "socket.SOCK_STREAM", "POST /v1/restricted/generate HTTP/1.1", "trust_env"):
        # The client has no HTTP library/proxy path; the latter marker is not
        # applicable to raw sockets and is intentionally absent.
        if literal == "trust_env":
            assert literal not in source
        else:
            assert literal in source
    for forbidden in ("AF_INET", "AF_INET6", "httpx", "requests", "retry", "redirect", "stream"):
        assert forbidden not in source
