"""Closed authentication boundary: production accepts verified Google ID tokens only."""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Protocol

from .contracts import ContractError


class Authenticator(Protocol):
    def authenticate(self, authorization: str | None) -> str: ...


@dataclass(frozen=True)
class GoogleOidcAuthenticator:
    """Verifies issuer, audience, service-account subject and expiry from Bearer token."""
    audience: str
    allowed_subject: str
    def authenticate(self, authorization: str | None) -> str:
        if not authorization or not authorization.startswith("Bearer ") or authorization.count(" ") != 1:
            raise ContractError("missing or malformed bearer token")
        token = authorization[7:]
        try:
            from google.auth.transport.requests import Request
            from google.oauth2.id_token import verify_oauth2_token
            claims = verify_oauth2_token(token, Request(), audience=self.audience)
        except Exception as exc:
            raise ContractError("Google ID token verification failed") from exc
        issuer = claims.get("iss")
        subject = claims.get("sub")
        email = claims.get("email")
        if issuer not in {"https://accounts.google.com", "accounts.google.com"} or not claims.get("exp"):
            raise ContractError("untrusted token issuer or expiry")
        # Cloud Run service identity is represented by verified email/sub; the
        # configured principal is checked after signature/audience validation.
        if email != self.allowed_subject and subject != self.allowed_subject:
            raise ContractError("caller is not allowlisted")
        return self.allowed_subject


@dataclass(frozen=True)
class SyntheticAuthenticator:
    """Test-only injector. Production composition rejects this type unconditionally."""
    principal: str
    def authenticate(self, authorization: str | None) -> str:
        if authorization != "Synthetic test credential":
            raise ContractError("synthetic credential rejected")
        return self.principal


@dataclass(frozen=True)
class LocalSocketAuthenticator:
    """Local roots rely on operator-controlled UDS permissions, never cloud tokens."""
    principal: str
    def authenticate(self, authorization: str | None) -> str:
        if authorization is not None:
            raise ContractError("local socket authentication has no bearer channel")
        return self.principal


def production_authenticator(*, audience: str, caller_principal: str) -> GoogleOidcAuthenticator:
    if os.environ.get("RESTRICTED_RUNTIME_MODE", "production") != "production":
        raise RuntimeError("production authenticator requires production runtime mode")
    if not audience or not caller_principal:
        raise RuntimeError("OIDC audience and caller principal are mandatory")
    return GoogleOidcAuthenticator(audience, caller_principal)
