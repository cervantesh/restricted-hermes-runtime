# Clinical egress WSL v2 receipt

## Frame

- Runtime source: `4ff9699d7839c4d00be6aa6ef3fbcac95bc4c3b7` /
  tree `9446b5559fc115be40109cd00b6c57779bba7c34`.
- Health-Record-Hub source: `ad13735e9881a48580a9e138daac137f8c865dea` /
  tree `f217b0b1cf7f438422528dfe178d81b78212c68b`.
- Execution: Ubuntu 24.04 under WSL2, Docker `29.1.3`, Compose
  `2.40.3+ds1-0ubuntu1~24.04.1`.
- Inputs and traffic were synthetic/non-PHI only.

## Real-path command

```text
python3 tests/deployment/test_clinical_egress_witness.py \
  --hrh-root <clean exact-HRH clone> \
  --output /tmp/clinical-egress-v2-4ff9699.json
```

The runner completed and retained the canonical v2 receipt. It exercised each
restricted service on a disposable dual-stack control network, requiring both
controlled IPv4 and controlled IPv6 reachability before restoring normal
membership. The receipt records restored topology, permitted peers, all denied
classes, controlled external denial, and cleanup. After completion, no
`clinicalstagingegress*` containers or networks remained.

## Retained artifact

- JSON: `clinical-egress-wsl-v2-receipt-2026-09-11.json`
- SHA-256:
  `5f3d744f614e86625b1a8c8c5d22c545078493b21df565ddc72aa95d2445ce5d`

The prior v1 receipt remains historical only; it does not attest the repaired
dual-stack control. This receipt is content-safe by construction and is
verified by the versioned unit test against its explicit source and image
subjects.

## Limits

This is Linux-container evidence under WSL2. It does not prove a
representative host firewall, provider qualification, secrets/IAM posture,
PHI authorization, HIPAA/BAA status, or production readiness.
