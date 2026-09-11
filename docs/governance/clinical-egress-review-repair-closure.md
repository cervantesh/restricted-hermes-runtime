# Clinical egress witness review repair closure

## Risk reduced

The retained witness must not interpret an unexercised IPv6 address as evidence
of IPv6 enforcement, leak an abandoned staging topology after a failed
initialization, delete a receipt owned by another invocation, or accept
integer lookalikes for boolean outcomes.

## In scope

- Require both IPv4 and IPv6 reachability while each restricted service is
  explicitly attached to the disposable dual-stack control network.
- Destroy a staging topology whenever its state marker exists, including an
  initialization that failed after materializing that marker.
- Delete an output only after this invocation has successfully created it.
- Reject non-boolean controlled outcomes in both builder and verifier paths.

## Closure predicates

1. The unit verifier rejects `0` and `1` for every controlled outcome.
2. Static coverage proves the runner uses both controlled address families and
   treats an existing staging marker as cleanup ownership.
3. A fresh Linux/WSL real-path run emits a versioned receipt whose source is
   the repaired runtime subject.  The old receipt is historical evidence only
   and cannot certify the repaired semantics.
4. The runner leaves no controlled containers or networks and never removes a
   receipt it did not create.

## Nonclaims

This repair does not add a network policy, prove representative-host egress,
authorize PHI, or establish a production or compliance outcome.
