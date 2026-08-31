# Local Linux deployment evidence

- Source commit: `<exact 40-hex commit>`
- Compose project: `<unique project name>`
- Host/kernel/Docker/Compose versions: `<captured outputs>`
- Policy digest/epoch: `<public values>`
- Commands and exit status: `<exact commands>`

Record `docker compose config`, image digests, socket metadata and ACL matrix,
PostgreSQL role/privilege negatives, disabled-dispatch control, create/turn/
replay result, broker call count, restart/replay result, missing dependency
controls, and IPv4/IPv6/DNS/proxy egress negatives.

This evidence is **not HIPAA compliance**, **not PHI authorization**, and not
model attestation. Every synthetic receipt/nonclaim remains:

```text
model_attested=false
deployment_conformant=false
phi_authorized=false
```

List every unproved operator control explicitly. Do not infer model provenance,
retention, logging/training posture, firewall correctness, backup/restore,
trusted time, physical security, workforce controls, incident response, BAA or
HIPAA status from a successful protocol test.
