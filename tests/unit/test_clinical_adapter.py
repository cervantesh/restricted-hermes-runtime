from __future__ import annotations

import json
import os
import socket
import ssl
from pathlib import Path

import pytest

from restricted_runtime.clinical_adapter import (
    AdapterConfig,
    ClinicalAdapter,
    ContractError,
    HrhHttpsClient,
    load_api_key,
)
from restricted_runtime.contracts import ClinicalAuthorizationDenied
from restricted_runtime.services import production_clinical_adapter


ACTOR = "actor000000000000000000000"
PATIENT = "123e4567-e89b-42d3-a456-426614174000"
DIGEST = "a" * 64
RESPONSE_DIGEST = "b" * 64
BASE = {
    "mattermostActorId": ACTOR,
    "patientId": PATIENT,
    "requestId": "request_123",
    "integrationId": "hrh-mattermost-01",
    "clinicalPolicyId": "clinical-read-v1",
    "policyEpoch": "mattermost-e1",
    "policyDigest": DIGEST,
}


def wire(path: str, body: dict, *, length: int | None = None) -> bytes:
    raw = json.dumps(body, separators=(",", ":")).encode()
    size = len(raw) if length is None else length
    return (
        f"POST {path} HTTP/1.0\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {size}\r\n\r\n".encode()
        + raw
    )


class Upstream:
    def __init__(self, clinic_timezone="America/New_York"):
        self.calls = []
        self.clinic_timezone = clinic_timezone

    def request(self, path, body):
        self.calls.append((path, body))
        if path.endswith("next-appointment"):
            return {"clinicTimezone": self.clinic_timezone, "appointment": None, "responseDigest": RESPONSE_DIGEST}
        return {"authorized": True}


class DeniedUpstream:
    def request(self, path, body):
        raise ClinicalAuthorizationDenied("denied")


def test_authoritative_hrh_denial_is_preserved_across_the_uds_boundary():
    response = ClinicalAdapter(expected_ingress_uid=10007, expected_clinical_timezone="America/New_York", upstream=DeniedUpstream()).handle(
        10007, wire("/v1/clinical/query", BASE)
    )
    assert response.startswith(b"HTTP/1.1 403 Forbidden\r\n")


def test_adapter_maps_only_two_closed_routes_for_the_authenticated_ingress():
    upstream = Upstream()
    adapter = ClinicalAdapter(expected_ingress_uid=10007, expected_clinical_timezone="America/New_York", upstream=upstream)
    response = adapter.handle(10007, wire("/v1/clinical/query", BASE))
    assert response.startswith(b"HTTP/1.1 200 OK\r\n")
    assert upstream.calls == [("/api/restricted-hermes/clinical/next-appointment", BASE)]

    delivery = {**BASE, "responseDigest": RESPONSE_DIGEST}
    response = adapter.handle(10007, wire("/v1/clinical/reauthorize-delivery", delivery))
    assert response.startswith(b"HTTP/1.1 200 OK\r\n")
    assert upstream.calls[-1] == ("/api/restricted-hermes/clinical/reauthorize-delivery", delivery)


@pytest.mark.parametrize("mutation", [
    lambda: wire("/v1/clinical/other", BASE),
    lambda: wire("/v1/clinical/query", {**BASE, "notes": "forbidden"}),
    lambda: wire("/v1/clinical/query", BASE, length=1),
    lambda: wire("/v1/clinical/reauthorize-delivery", BASE),
    lambda: b"GET /v1/clinical/query HTTP/1.0\r\nHost: localhost\r\n\r\n",
    lambda: wire("/v1/clinical/query", BASE) + b"trailing",
])
def test_adapter_rejects_unknown_partial_or_malformed_requests_without_fallback(mutation):
    upstream = Upstream()
    response = ClinicalAdapter(expected_ingress_uid=10007, expected_clinical_timezone="America/New_York", upstream=upstream).handle(10007, mutation())
    assert response.startswith(b"HTTP/1.1 400 Bad Request\r\n")
    assert upstream.calls == []


def test_wrong_uds_peer_never_reaches_hrh():
    upstream = Upstream()
    response = ClinicalAdapter(expected_ingress_uid=10007, expected_clinical_timezone="America/New_York", upstream=upstream).handle(10009, wire("/v1/clinical/query", BASE))
    assert response.startswith(b"HTTP/1.1 403 Forbidden\r\n")
    assert upstream.calls == []


def test_oversize_request_is_rejected_without_upstream():
    upstream = Upstream()
    response = ClinicalAdapter(expected_ingress_uid=10007, expected_clinical_timezone="America/New_York", upstream=upstream).handle(10007, b"x" * 65_537)
    assert response.startswith(b"HTTP/1.1 400 Bad Request\r\n")
    assert upstream.calls == []


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership and mode contract")
def test_secret_loader_requires_owned_regular_0400_or_0600_file(tmp_path: Path):
    secret = tmp_path / "key"
    secret.write_text("secret-value\n", encoding="ascii")
    os.chmod(secret, 0o600)
    expected_uid = secret.stat().st_uid
    assert load_api_key(secret, expected_uid=expected_uid) == "secret-value"
    os.chmod(secret, 0o640)
    with pytest.raises(ContractError):
        load_api_key(secret, expected_uid=expected_uid)
    link = tmp_path / "link"
    try:
        link.symlink_to(secret)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(ContractError):
        load_api_key(link, expected_uid=expected_uid)


class Response:
    def __init__(self, status=200, body=b"{}", headers=None):
        self.status, self._body = status, body
        self._headers = headers or {"Content-Type": "application/json", "Content-Length": str(len(body))}
    def getheader(self, name):
        return self._headers.get(name)
    def read(self, amount=None):
        if amount is None:
            return self._body
        result, self._body = self._body[:amount], self._body[amount:]
        return result


class Connection:
    def __init__(self, response=None, failure=None):
        self.response, self.failure, self.seen = response, failure, None
    def request(self, method, path, body=None, headers=None):
        if self.failure:
            raise self.failure
        self.seen = (method, path, body, headers)
    def getresponse(self):
        return self.response
    def close(self):
        pass


def config(tmp_path, timezone="America/New_York"):
    ca = tmp_path / "ca.pem"
    ca.write_text("test", encoding="ascii")
    key = tmp_path / "key"
    key.write_text("secret", encoding="ascii")
    os.chmod(key, 0o600)
    return AdapterConfig("https://hrh.internal.example", ca, key, 2.0, 10007, timezone)


def test_https_validation_accepts_the_explicit_non_new_york_adapter_timezone(monkeypatch, tmp_path):
    path = tmp_path / "adapter.json"
    path.write_text(json.dumps({
        "hrh_origin": "https://hrh.internal.example",
        "ca_path": str(tmp_path / "ca.pem"),
        "api_key_path": str(tmp_path / "key"),
        "timeout_seconds": 2,
        "expected_ingress_uid": 10007,
        "expected_clinical_timezone": "Europe/Madrid",
    }), encoding="utf-8")
    (tmp_path / "ca.pem").write_text("test", encoding="ascii")
    (tmp_path / "key").write_text("secret", encoding="ascii")
    response_body = json.dumps({
        "clinicTimezone": "Europe/Madrid", "appointment": None, "responseDigest": RESPONSE_DIGEST,
    }, separators=(",", ":")).encode()
    monkeypatch.setattr("restricted_runtime.clinical_adapter.ssl.create_default_context", lambda cafile: object())
    monkeypatch.setattr("restricted_runtime.clinical_adapter.http.client.HTTPSConnection", lambda *a, **k: Connection(Response(body=response_body)))
    client = HrhHttpsClient(AdapterConfig.load(path), api_key="secret")
    assert client.request("/api/restricted-hermes/clinical/next-appointment", BASE)["clinicTimezone"] == "Europe/Madrid"


def test_adapter_configuration_requires_the_expected_clinical_timezone(tmp_path):
    path = tmp_path / "adapter.json"
    path.write_text(json.dumps({
        "hrh_origin": "https://hrh.internal.example",
        "ca_path": "/run/secrets/hrh-ca.pem",
        "api_key_path": "/run/secrets/hrh-clinical-api-key",
        "timeout_seconds": 5,
        "expected_ingress_uid": 10007,
    }), encoding="utf-8")
    with pytest.raises(ContractError):
        AdapterConfig.load(path)


def test_adapter_rejects_adapter_config_upstream_timezone_mismatch_at_https_and_uds_surfaces(monkeypatch, tmp_path):
    expected = "Europe/Madrid"
    response_body = json.dumps({
        "clinicTimezone": "America/New_York", "appointment": None, "responseDigest": RESPONSE_DIGEST,
    }, separators=(",", ":")).encode()
    monkeypatch.setattr("restricted_runtime.clinical_adapter.ssl.create_default_context", lambda cafile: object())
    monkeypatch.setattr("restricted_runtime.clinical_adapter.http.client.HTTPSConnection", lambda *a, **k: Connection(Response(body=response_body)))
    with pytest.raises(ContractError):
        HrhHttpsClient(AdapterConfig("https://hrh.internal.example", tmp_path / "ca.pem", tmp_path / "key", 2.0, 10007, expected), api_key="secret").request(
            "/api/restricted-hermes/clinical/next-appointment", BASE
        )
    response = ClinicalAdapter(
        expected_ingress_uid=10007, expected_clinical_timezone=expected, upstream=Upstream("America/New_York")
    ).handle(10007, wire("/v1/clinical/query", BASE))
    assert response.startswith(b"HTTP/1.1 400 Bad Request\r\n")


def test_production_entrypoint_threads_configured_timezone_to_https_and_uds_validation(monkeypatch, tmp_path):
    config = type("Config", (), {
        "api_key_path": tmp_path / "key", "expected_ingress_uid": 10007,
        "expected_clinical_timezone": "Europe/Madrid", "timeout_seconds": 2,
    })()
    config.api_key_path.write_text("secret", encoding="ascii")
    captured = {}

    class Stop(Exception):
        pass

    monkeypatch.setattr(production_clinical_adapter.AdapterConfig, "load", lambda _path: config)
    monkeypatch.setattr(production_clinical_adapter, "load_api_key", lambda *_args, **_kwargs: "secret")
    monkeypatch.setattr(production_clinical_adapter, "HrhHttpsClient", lambda received, *, api_key: captured.setdefault("https", (received, api_key)))

    def clinical_adapter(**kwargs):
        captured["uds"] = kwargs
        raise Stop

    monkeypatch.setattr(production_clinical_adapter, "ClinicalAdapter", clinical_adapter)
    with pytest.raises(Stop):
        production_clinical_adapter.run()
    assert captured["https"] == (config, "secret")
    assert captured["uds"]["expected_clinical_timezone"] == "Europe/Madrid"


@pytest.mark.parametrize("origin", [
    "http://hrh.internal.example", "https://user@hrh.internal.example",
    "https://hrh.internal.example/path", "https://hrh.internal.example?x=1",
])
def test_adapter_configuration_requires_one_pinned_https_origin(tmp_path, origin):
    path = tmp_path / "adapter.json"
    path.write_text(json.dumps({
        "hrh_origin": origin,
        "ca_path": "/run/secrets/hrh-ca.pem",
        "api_key_path": "/run/secrets/hrh-clinical-api-key",
        "timeout_seconds": 5,
        "expected_ingress_uid": 10007,
        "expected_clinical_timezone": "America/New_York",
    }), encoding="utf-8")
    with pytest.raises(ContractError):
        AdapterConfig.load(path)


def test_adapter_configuration_schema_is_closed(tmp_path):
    path = tmp_path / "adapter.json"
    path.write_text(json.dumps({
        "hrh_origin": "https://hrh.internal.example",
        "ca_path": "/run/secrets/hrh-ca.pem",
        "api_key_path": "/run/secrets/hrh-clinical-api-key",
        "timeout_seconds": 5,
        "expected_ingress_uid": 10007,
        "expected_clinical_timezone": "America/New_York",
        "fallback_origin": "https://elsewhere.example",
    }), encoding="utf-8")
    with pytest.raises(ContractError):
        AdapterConfig.load(path)


def test_https_client_uses_exact_origin_api_key_and_no_redirect(monkeypatch, tmp_path):
    response_body = json.dumps({"authorized": True}, separators=(",", ":")).encode()
    connection = Connection(Response(body=response_body))
    monkeypatch.setattr("restricted_runtime.clinical_adapter.ssl.create_default_context", lambda cafile: object())
    monkeypatch.setattr("restricted_runtime.clinical_adapter.http.client.HTTPSConnection", lambda *a, **k: connection)
    client = HrhHttpsClient(config(tmp_path), api_key="secret")
    assert client.request("/api/restricted-hermes/clinical/reauthorize-delivery", {**BASE, "responseDigest": RESPONSE_DIGEST}) == {"authorized": True}
    method, path, _body, headers = connection.seen
    assert (method, path) == ("POST", "/api/restricted-hermes/clinical/reauthorize-delivery")
    assert headers["Authorization"] == "Bearer secret"


@pytest.mark.parametrize("response", [
    Response(status=302), Response(status=429), Response(status=500),
    Response(body=b'{"authorized":'),
    Response(body=b"{}", headers={"Content-Type": "text/plain", "Content-Length": "2"}),
    Response(body=b"{}", headers={"Content-Type": "application/json"}),
    Response(body=b"x" * 65_537),
])
def test_https_failures_are_closed(monkeypatch, tmp_path, response):
    monkeypatch.setattr("restricted_runtime.clinical_adapter.ssl.create_default_context", lambda cafile: object())
    monkeypatch.setattr("restricted_runtime.clinical_adapter.http.client.HTTPSConnection", lambda *a, **k: Connection(response))
    with pytest.raises(ContractError):
        HrhHttpsClient(config(tmp_path), api_key="secret").request("/api/restricted-hermes/clinical/next-appointment", BASE)


def test_https_403_is_an_authoritative_denial(monkeypatch, tmp_path):
    monkeypatch.setattr("restricted_runtime.clinical_adapter.ssl.create_default_context", lambda cafile: object())
    monkeypatch.setattr(
        "restricted_runtime.clinical_adapter.http.client.HTTPSConnection",
        lambda *a, **k: Connection(Response(status=403)),
    )
    with pytest.raises(ClinicalAuthorizationDenied):
        HrhHttpsClient(config(tmp_path), api_key="secret").request(
            "/api/restricted-hermes/clinical/next-appointment", BASE
        )


@pytest.mark.parametrize("failure", [TimeoutError(), socket.gaierror(), OSError(), ssl.SSLError("TLS")])
def test_transport_dns_tls_timeout_failures_have_no_fallback(monkeypatch, tmp_path, failure):
    monkeypatch.setattr("restricted_runtime.clinical_adapter.ssl.create_default_context", lambda cafile: object())
    monkeypatch.setattr("restricted_runtime.clinical_adapter.http.client.HTTPSConnection", lambda *a, **k: Connection(failure=failure))
    with pytest.raises(ContractError):
        HrhHttpsClient(config(tmp_path), api_key="secret").request("/api/restricted-hermes/clinical/next-appointment", BASE)


def test_broken_pipe_does_not_prevent_the_next_connection(monkeypatch):
    upstream = Upstream()
    service = ClinicalAdapter(expected_ingress_uid=10007, expected_clinical_timezone="America/New_York", upstream=upstream)
    monkeypatch.setattr(production_clinical_adapter, "peer_uid", lambda _connection: 10007)
    monkeypatch.setattr(production_clinical_adapter, "receive_one", lambda _connection, timeout_seconds: wire("/v1/clinical/query", BASE))

    class Connection:
        def __init__(self, broken=False):
            self.broken, self.response = broken, None
        def sendall(self, response):
            if self.broken:
                raise BrokenPipeError
            self.response = response

    production_clinical_adapter.serve_connection(service, Connection(broken=True), timeout_seconds=5)
    survivor = Connection()
    production_clinical_adapter.serve_connection(service, survivor, timeout_seconds=5)
    assert survivor.response.startswith(b"HTTP/1.1 200 OK\r\n")
    assert len(upstream.calls) == 2
