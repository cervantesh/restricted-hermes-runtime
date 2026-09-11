# Synthetic composed E2E receipt — local Linux evidence

This canonical content-safe receipt was produced by the real composed E2E on
2026-09-11. Its SHA-256 is
`f126f48d8146efa9b9e877d56724b7d12a17ae476bab9c56e58e9d1db8597cc7`.

The run used runtime `14793b98d310fab44ef4bc22086c55039e279d46` / tree
`cc83f7c4cad7e6f4da063c4ce9fcc90ad90bce19`, product subject
`c0fc85d894700823deb92a085d36291589160028`, and Health-Record-Hub
`ad13735e9881a48580a9e138daac137f8c865dea` / tree
`f217b0b1cf7f438422528dfe178d81b78212c68b`.

It records only closed outcomes: successful valid delivery, denied
cross-scope and policy paths, source deletion after authorization with zero
delivery and erased payload, crash recovery with no repeated authorization,
container boundary checks, immutable edge-image subjects, and successful
teardown. It contains no logs, seed values, endpoints, certificates,
environment values, or internal record tags.

The execution used WSL2-backed Docker Linux containers on the author host. It
is real-path local evidence only; it does not prove representative-host
conformance, host hardening, PHI authorization, HIPAA/BAA, or production
readiness.
