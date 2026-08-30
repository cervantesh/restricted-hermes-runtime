# Required controlled-egress boundary (apply blocker)

Cloud Run and Terraform alone do not prove host/SNI enforcement. The deployment
owner must bind both services to a controlled DNS resolver and an inspected
egress proxy/firewall that validates request hostname plus TLS SNI/certificate.

- Conversation identity: private gateway, private SQL, named KMS key endpoint,
  identity endpoint, controlled DNS only. Deny Vertex, public IPv4/IPv6,
  literal IPs, proxy variables, telemetry, downloads, redirects.
- Gateway identity: exact `aiplatform.us.rep.googleapis.com` only, private SQL,
  named gateway MAC key endpoint, identity endpoint, controlled DNS only.
  Deny global/alternate Vertex endpoints, proxying, redirects, literal IPs,
  metadata paths other than identity, and all telemetry/download routes.

An exact-staging test must demonstrate each denied route. This file is a policy
input, not evidence that a network control exists.
