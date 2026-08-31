# Required controlled-egress boundary (apply blocker)

Status for the synthetic diagnostic: **UNDETERMINED / HOLD_DEPLOYMENT**. The
Terraform baseline uses Private Google Access, a private `googleapis.com` DNS
zone resolving ordinary `*.googleapis.com` traffic to
`restricted.googleapis.com` (`199.36.153.4/30`), an exact TCP/443 allow to
that VIP before deny-all, and has no NAT or broad default route. A private
`run.app` wildcard resolves to the same restricted VIP so internal
runner-to-conversation and conversation-to-gateway URLs remain reachable.
Private SQL is separately allowed on 5432 over the PSA range. Each role has a
separate VPC connector; this baseline does not inspect application hostnames.

The frozen Vertex sink remains `aiplatform.us.rep.googleapis.com` with
`location=us`. It is **not** sent to the restricted VIP. Terraform creates a
dedicated `10.77.5.0/28` PSC subnet, reserved internal PSC address, and regional Network Connectivity
endpoint with `target_google_api` exactly
`aiplatform.us.rep.googleapis.com`, an exact private DNS apex A record to that
reserved PSC address, and a gateway-only TCP/443 firewall allow to that single address
before deny-all. The more-specific DNS zone wins over the general
`googleapis.com` zone. This matches Google's PSC pattern for regional or
multi-regional API endpoints; those endpoints are not reached through Private
Google Access/restricted VIP. See [Access regional/multi-regional Google APIs
through private endpoints](https://cloud.google.com/docs/security/compliance/access-regional-google-apis-endpoints).

Provider 6.50 reads the endpoint address back as the literal IP after creation,
although creation requires the reserved address resource URI. Terraform ignores
only the endpoint `address` read-back to avoid a spurious replacement; target
API, network, subnetwork, and access type remain drift-visible.
The lifecycle also replaces the endpoint if its reserved address resource is
replaced, and a postcondition rejects a returned address other than the
reserved PSC IP.

It does not claim an inspected FQDN/SNI/certificate witness. This residual
result prevents `READY`, `CLOSED`, and any PHI authorization claim. Cloud Run
and Terraform alone do not prove host/SNI enforcement. The deployment owner
must bind both services to a controlled DNS resolver and an inspected egress
proxy/firewall that validates request hostname plus TLS SNI/certificate.

- Conversation identity: private gateway, private SQL, named KMS key endpoint,
  identity endpoint, controlled DNS only. Deny Vertex, public IPv4/IPv6,
  literal IPs, proxy variables, telemetry, downloads, redirects.
- Gateway identity: exact `aiplatform.us.rep.googleapis.com` through PSC only,
  private SQL, named gateway MAC key endpoint, identity endpoint, controlled
  DNS only. Deny alternate Vertex endpoints, proxying, redirects, literal IPs,
  metadata paths other than identity, and all telemetry/download routes.

An exact-staging test must demonstrate each denied route and the internal Run
reachability path before this HOLD can change. This file is a policy input, not
evidence that a network control exists.
