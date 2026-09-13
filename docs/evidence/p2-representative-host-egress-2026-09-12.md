# P2 representative-host egress evidence — 2026-09-12

## Result

The exact-source egress witness passed on one dedicated Ubuntu 24.04 x86_64
synthetic host. Its public content-safe summary is
[`p2-representative-host-egress-2026-09-12.json`](p2-representative-host-egress-2026-09-12.json)
and its retained canonical receipt has SHA-256
`2d3f94cb4631725256a0cc28de2da0dabb0bedb11facc60750b83dedc0c74e98`.

| Frame | Exact value |
| --- | --- |
| Runtime commit | `70217864aefc473759c739448831a8203ae81ded` |
| Runtime tree | `73d10d5a90197a6e4984cc6b83e0a97f480e3869` |
| HRH commit | `ad13735e9881a48580a9e138daac137f8c865dea` |
| Egress receipt verification | `PASS` |
| Synthetic data classification | `synthetic_non_phi_only: true` |

The receipt proves a deliberate controlled RED route for ingress and clinical
adapter, removal of that route, GREEN denial for the enumerated dual-stack,
DNS, metadata and proxy-related checks, and cleanup of the owned sink/network.
It also records read-only root filesystems, dropped capabilities, exact mount
destinations, and the allowed/denied internal service paths.

## Published-subject check on the same host

The following public OCI subjects were pulled by immutable digest and passed
their role-closure tests with `--network none`:

| Subject | Digest |
| --- | --- |
| Clinical adapter | `sha256:50ade779752dfcefd135b75ee7058afb1d2051c95643423652cdbe7a7754163c` |
| Mattermost ingress | `sha256:5dbc4a7e17910f62fdcba1162328eefc7e185c2cffe8c81eeb31eefae1e98fd1` |

## Boundary

This is not a unified P2 conformance receipt. The egress composition builds
the restricted services from the clean, exact source worktree, whereas the
published-subject tests execute the OCI subjects independently. The evidence
therefore does **not** claim that the published OCI subjects were the images
that produced the egress result.

It does not establish PHI authorization, HIPAA/BAA compliance, production
approval, or clinical readiness. The remaining P2 controls are tracked in
[the execution frame](../design/p2-immutable-execution-frame-2026-09-12.md).
