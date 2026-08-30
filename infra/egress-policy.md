# Required controlled-egress boundary (apply blocker)

Status for the synthetic diagnostic: **UNDETERMINED / HOLD_DEPLOYMENT**. The
Terraform baseline uses Private Google Access, a private `googleapis.com` DNS
zone resolving `*.googleapis.com` to `restricted.googleapis.com`
(`199.36.153.4/30`), an exact TCP/443 allow to that VIP before deny-all, and
has no NAT or broad default route. A private `run.app` wildcard resolves to
the same restricted VIP so internal runner-to-conversation and
conversation-to-gateway URLs remain reachable. Private SQL is separately
allowed on 5432 over the PSA range. Each role receives its own VPC connector;
this is a
network baseline, not a claim that application hostnames were inspected.

The sole Vertex sink is the documented global REST host
`aiplatform.googleapis.com` with the frozen regional publisher-model path.
Unlike the former regional `aiplatform.us.rep.googleapis.com` host, the service name
`aiplatform.googleapis.com` is supported by the restricted VIP. No PSC is
introduced because the exact restricted-VIP route is the narrower supported
path for this closed endpoint.

Source basis: [Vertex Gemini REST quickstart](https://cloud.google.com/vertex-ai/generative-ai/docs/start/quickstart)
uses `aiplatform.googleapis.com` for `generateContent`; [restricted VIP
services](https://cloud.google.com/vpc-service-controls/docs/restricted-vip-services)
lists `aiplatform.googleapis.com` as supported. This documentation does not
replace the required staging FQDN/SNI witness.

It does not claim an inspected FQDN/SNI/certificate witness. This residual result prevents
`READY`, `CLOSED`, and any PHI authorization claim.

Cloud Run and Terraform alone do not prove host/SNI enforcement. The deployment
owner must bind both services to a controlled DNS resolver and an inspected
egress proxy/firewall that validates request hostname plus TLS SNI/certificate.

- Conversation identity: private gateway, private SQL, named KMS key endpoint,
  identity endpoint, controlled DNS only. Deny Vertex, public IPv4/IPv6,
  literal IPs, proxy variables, telemetry, downloads, redirects.
- Gateway identity: exact `aiplatform.googleapis.com` only, private SQL,
  named gateway MAC key endpoint, identity endpoint, controlled DNS only.
  Deny global/alternate Vertex endpoints, proxying, redirects, literal IPs,
  metadata paths other than identity, and all telemetry/download routes.

An exact-staging test must demonstrate each denied route and the internal Run
reachability path before this HOLD can change. This file is a policy input, not
evidence that a network control exists.
