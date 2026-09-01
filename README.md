# Restricted Hermes Runtime (synthetic-only v0)

[![CI](https://github.com/cervantesh/restricted-hermes-runtime/actions/workflows/ci.yml/badge.svg)](https://github.com/cervantesh/restricted-hermes-runtime/actions/workflows/ci.yml)

This repository deliberately contains a small, standalone two-service runtime
for the frozen restricted-sensitive-inference contract. It is **not approved
for PHI deployment**. The exact-staging gates under `evidence/` remain blockers
until an owner supplies attributable IAM, egress, BAA, Covered Service,
cache, retention, logging, and exact-revision proof.

This is a research prototype and reproducible evidence package, not a
supported Hermes companion product. See [ROADMAP.md](ROADMAP.md) for the
maintenance, upstream-adoption, and operational-ownership decision gates.

The conversation service has no Vertex client. The gateway owns the single,
non-streaming Vertex `generateContent` dispatch surface. No normal Hermes
agent, tool/plugin system, memory, shell, fallback, retry, streaming, or
dynamic capability surface is imported.

Run unit/static tests with `python -m pytest tests/unit tests/static`.
PostgreSQL integration tests require `DATABASE_URL` and deliberately skip with
an explicit reason when it is absent; they never substitute SQLite or mocks.
