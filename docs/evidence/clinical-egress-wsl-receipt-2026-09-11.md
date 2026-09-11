# Synthetic clinical egress witness — local WSL evidence

This is a content-safe receipt from a real Docker Linux-container run on
2026-09-11. Its receipt SHA-256 is
`54ec7f0e257dfd6461c5697218f61cc32f3a0c9f12f77cd73afa0315dbcab1b7`.

The executable test created a disposable IPv6-capable Docker network and a
local controlled sink, and verified that a separate non-internal control
network could reach the sink through its host-published route. It attached
the disposable internal network to `ingress` and
`clinical-adapter` separately and observed RED reachability for both. It then
detached the network, required the exact normal memberships, and confirmed
both restricted services could not reach that same controlled external route.
It also checked the permitted internal peer and all seven negative classes for
both services, then removed both temporary networks and the sink. The receipt
is independently canonical-verifiable against its source frame and the exact
two edge-service image digests emitted by staging.

The observed source subject is runtime
`146bf39c9a3ac8fa2155c7f52e53b51af5646fff` / tree
`dc3560ba46df8d8157a1f79ed9c4c82ac274052c` and Health-Record-Hub
`ad13735e9881a48580a9e138daac137f8c865dea` / tree
`f217b0b1cf7f438422528dfe178d81b78212c68b`.

The observed environment was WSL2-backed Docker on the author host. It is
real-path local evidence only. It does not close the representative-host
requirement, host-hardening assessment, PHI authorization, HIPAA/BAA, or
production readiness claims.
