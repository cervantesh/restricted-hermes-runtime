# Synthetic clinical egress witness — local WSL evidence

This is a content-safe receipt from a real Docker Linux-container run on
2026-09-11. Its receipt SHA-256 is
`b1b1dc16bb9ca0670ad78b782372136edc5db363a37b80582bc2146813790093`.

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
`29c321cb06076e935833e01e7b7d4f70d6bf7c10` / tree
`565e2198d09f5a046a91b77ebe4c2a95f3351b2f` and Health-Record-Hub
`ad13735e9881a48580a9e138daac137f8c865dea` / tree
`f217b0b1cf7f438422528dfe178d81b78212c68b`.

The observed environment was WSL2-backed Docker on the author host. It is
real-path local evidence only. It does not close the representative-host
requirement, host-hardening assessment, PHI authorization, HIPAA/BAA, or
production readiness claims.
