"""Content-free network reachability witness executed inside the ingress container."""
from __future__ import annotations

import http.client
import json
import os
import socket
import ssl


def denied_connect(host: str, port: int, family: int = socket.AF_INET) -> bool:
    candidate = None
    try:
        candidate = socket.socket(family, socket.SOCK_STREAM)
        candidate.settimeout(2)
        candidate.connect((host, port))
    except OSError:
        return True
    finally:
        if candidate is not None:
            candidate.close()
    return False


context = ssl.create_default_context(cafile="/run/ingress/ca.crt")
exact = http.client.HTTPSConnection("mattermost", 8065, timeout=5, context=context)
try:
    exact.request("GET", "/api/v4/system/ping", headers={"Connection": "close"})
    result = exact.getresponse()
    exact_tls = result.status == 200 and json.loads(result.read()).get("status") == "OK"
finally:
    exact.close()

uds = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
uds.settimeout(5)
try:
    uds.connect("/run/restricted-inference/conversation.sock")
    uds.sendall(b"GET /readyz HTTP/1.0\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
    raw = b""
    while True:
        chunk = uds.recv(65536)
        if not chunk:
            break
        raw += chunk
    uds_ready = raw.startswith(b"HTTP/1.1 200 OK\r\n") and json.loads(raw.split(b"\r\n\r\n", 1)[1]).get("status") == "ready"
finally:
    uds.close()

try:
    socket.getaddrinfo("postgres", 5432)
except socket.gaierror:
    postgres_unresolved = True
else:
    postgres_unresolved = False

alternate = http.client.HTTPSConnection("mattermost-alternate", 8065, timeout=5, context=context)
try:
    alternate.request("GET", "/api/v4/system/ping", headers={"Connection": "close"})
    alternate.getresponse().read()
except (OSError, ssl.SSLError, http.client.HTTPException):
    alternate_tls_denied = True
else:
    alternate_tls_denied = False
finally:
    alternate.close()

plain = http.client.HTTPConnection("mattermost", 8065, timeout=5)
try:
    plain.request("GET", "/api/v4/system/ping", headers={"Connection": "close"})
    plaintext_denied = plain.getresponse().status != 200
except (OSError, http.client.HTTPException):
    plaintext_denied = True
finally:
    plain.close()

try:
    socket.getaddrinfo("example.com", 443)
except socket.gaierror:
    external_dns_unresolved = True
else:
    external_dns_unresolved = False

evidence = {
    "exact_tls_mattermost": exact_tls,
    "uds_ready": uds_ready,
    "postgres_unresolved": postgres_unresolved,
    "postgres_ip_unreachable": denied_connect(os.environ["MM_ESR_POSTGRES_IP"], 5432),
    "alternate_tls_denied": alternate_tls_denied,
    "plaintext_denied": plaintext_denied,
    "external_dns_unresolved": external_dns_unresolved,
    "external_dns_unreachable": denied_connect("8.8.8.8", 53),
    "external_ipv4_unreachable": denied_connect("1.1.1.1", 443),
    "external_ipv6_unreachable": denied_connect("2606:4700:4700::1111", 443, socket.AF_INET6),
    "proxy_environment_absent": not any(
        os.environ.get(name)
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy")
    ),
}
if not all(evidence.values()):
    raise SystemExit(1)
print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
