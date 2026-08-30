"""Fail-closed binding between signed policy bytes and deployment configuration."""
from __future__ import annotations


def require_policy_pair(policy, *, epoch: str, digest: str) -> None:
    if (policy.epoch, policy.digest) != (epoch, digest):
        raise RuntimeError("signed policy pair differs from required deployment policy pair")
