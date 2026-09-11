# Synthetic clinical egress witness — local WSL evidence

This is a content-safe receipt from a real Docker Linux-container run on
2026-09-11. Its receipt SHA-256 is
`920284a6a411396f5befb5433a95e89fc6a0cb1d896aa85faf00e87a498ac914`.

The executable test created a disposable IPv6-capable Docker network and a
local controlled sink, and verified that a separate non-internal control
network could reach the sink through its host-published route. It attached
the disposable internal network to `ingress` and
`clinical-adapter` separately and observed RED reachability for both. It then
detached the network, required the exact normal memberships, and confirmed
both restricted services could not reach that same controlled external route.
It also checked the permitted internal peer and all seven negative classes for
both services, then removed both temporary networks and the sink. The receipt
is independently canonical-verifiable against its source frame.

The observed source subject is runtime
`793feea781f2c9b70d0aa3f846c537826db889eb` / tree
`83539372e8c46cc3ebccecf148a17304805fcf70` and Health-Record-Hub
`ad13735e9881a48580a9e138daac137f8c865dea` / tree
`f217b0b1cf7f438422528dfe178d81b78212c68b`.

The observed environment was WSL2-backed Docker on the author host. It is
real-path local evidence only. It does not close the representative-host
requirement, host-hardening assessment, PHI authorization, HIPAA/BAA, or
production readiness claims.
