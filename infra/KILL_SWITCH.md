# Durable dispatch kill switch

This is an operator-only pre-rollout control, not a runtime API and not a new
principal. The migration creates exactly one `inference_ledger.runtime_controls`
row with `dispatch_enabled=false`. A gateway can atomically transition a
reserved attempt to `DISPATCH_STARTED` only while that row is enabled.

Before a rollout, rollback, or investigation, connect with the existing
operator-admin private-socket DSN and run:

```sql
UPDATE inference_ledger.runtime_controls
SET dispatch_enabled = false, updated_at = transaction_timestamp()
WHERE control_key = true;
SELECT dispatch_enabled FROM inference_ledger.runtime_controls WHERE control_key = true;
```

The expected result is exactly one row and `false`. This blocks new dispatch
transitions but deliberately does not fabricate a provider outcome for a call
that already crossed `DISPATCH_STARTED`. Re-enable only after approved
synthetic preflight with the same statement using `true`; Cloud Run's
`RESTRICTED_ADMISSION_ENABLED=false` remains the independent startup belt.
