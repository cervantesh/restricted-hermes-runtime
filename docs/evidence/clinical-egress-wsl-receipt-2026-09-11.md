# Synthetic clinical egress witness — local WSL evidence

This is a content-safe receipt from a real Docker Linux-container run on
2026-09-11. Its receipt SHA-256 is
`101ddd90cde61107dd6ad27a1ba52a0c6dd0794bb7baf53d2306821404ef247a`.

The executable test created a disposable IPv6-capable Docker network and a
local controlled sink. It attached that network to `ingress` and
`clinical-adapter` separately and observed RED reachability for both. It then
detached the network, required the exact normal memberships, checked the
permitted internal peer and all seven negative classes for both services, and
removed the controlled network and sink. The receipt is independently
canonical-verifiable against its source frame.

The observed source subject is runtime
`e06e0a81964544123b507c31cf9190d36593a345` / tree
`e699bbacfa02d77c3ec601810be628ee1cb4720b` and Health-Record-Hub
`ad13735e9881a48580a9e138daac137f8c865dea` / tree
`f217b0b1cf7f438422528dfe178d81b78212c68b`.

The observed environment was WSL2-backed Docker on the author host. It is
real-path local evidence only. It does not close the representative-host
requirement, host-hardening assessment, PHI authorization, HIPAA/BAA, or
production readiness claims.
