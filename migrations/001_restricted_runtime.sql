CREATE SCHEMA IF NOT EXISTS restricted_content;
CREATE SCHEMA IF NOT EXISTS inference_ledger;
REVOKE ALL ON SCHEMA restricted_content, inference_ledger FROM PUBLIC;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='restricted_content_runtime') THEN CREATE ROLE restricted_content_runtime NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='restricted_ledger_runtime') THEN CREATE ROLE restricted_ledger_runtime NOLOGIN; END IF;
END $$;

CREATE TYPE restricted_content.turn_state AS ENUM ('RECEIVED','REQUEST_COMMITTED','INFERENCE_PENDING','RESPONSE_RECEIVED','COMMITTED','REJECTED','FAILED','INDETERMINATE');
CREATE TABLE restricted_content.conversations (
  tenant_id text NOT NULL, conversation_id text NOT NULL, conversation_epoch text NOT NULL,
  PRIMARY KEY (tenant_id, conversation_id)
);
CREATE TABLE restricted_content.turns (
  tenant_id text NOT NULL, conversation_id text NOT NULL, conversation_epoch text NOT NULL,
  turn_id uuid PRIMARY KEY, client_request_id uuid NOT NULL,
  authenticated_caller_principal text NOT NULL, schema_version text NOT NULL,
  request_mac bytea NOT NULL, mac_key_resource text NOT NULL, mac_key_version text NOT NULL,
  request_ciphertext bytea NOT NULL, request_nonce bytea NOT NULL, response_ciphertext bytea, response_nonce bytea,
  wrapped_data_key bytea NOT NULL, policy_epoch text NOT NULL, policy_digest text NOT NULL, state restricted_content.turn_state NOT NULL,
  lease_owner text, lease_generation bigint NOT NULL DEFAULT 0, lease_expires_at timestamptz,
  gateway_decision_id uuid, gateway_attempt_classification text, failure_class text, created_at timestamptz NOT NULL DEFAULT transaction_timestamp(), updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  UNIQUE (tenant_id, client_request_id), UNIQUE (tenant_id, turn_id)
);
CREATE UNIQUE INDEX one_active_turn_per_conversation ON restricted_content.turns(tenant_id, conversation_id, conversation_epoch)
 WHERE state NOT IN ('COMMITTED','REJECTED','FAILED','INDETERMINATE');
GRANT USAGE ON SCHEMA restricted_content TO restricted_content_runtime;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA restricted_content TO restricted_content_runtime;

CREATE TYPE inference_ledger.attempt_state AS ENUM ('RESERVED','DISPATCH_STARTED','SUCCEEDED','FAILED','INDETERMINATE','CANCELLED_NO_DISPATCH');
-- One durable, operator-controlled dispatch gate. It starts disabled and is
-- consulted in the same UPDATE that claims the only provider-dispatch state.
CREATE TABLE inference_ledger.runtime_controls (
  control_key boolean PRIMARY KEY DEFAULT true CHECK (control_key),
  dispatch_enabled boolean NOT NULL DEFAULT false,
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);
INSERT INTO inference_ledger.runtime_controls (control_key, dispatch_enabled) VALUES (true, false) ON CONFLICT DO NOTHING;
CREATE TABLE inference_ledger.dispatch_guards (
  tenant_id text NOT NULL, turn_id uuid NOT NULL, client_request_id uuid NOT NULL,
  policy_epoch text NOT NULL, policy_digest text NOT NULL,
  PRIMARY KEY (tenant_id, turn_id), UNIQUE (tenant_id, client_request_id)
);
CREATE TABLE inference_ledger.attempts (
  tenant_id text NOT NULL, turn_id uuid NOT NULL, client_request_id uuid NOT NULL, decision_id uuid NOT NULL,
  conversation_epoch text NOT NULL, authenticated_caller_principal text NOT NULL,
  request_mac bytea NOT NULL, mac_key_resource text NOT NULL, mac_key_version text NOT NULL,
  policy_epoch text NOT NULL, policy_digest text NOT NULL, sink_tuple jsonb NOT NULL,
  state inference_ledger.attempt_state NOT NULL, fence_generation bigint NOT NULL DEFAULT 0,
  failure_class text, provider_request_id text, created_at timestamptz NOT NULL DEFAULT transaction_timestamp(), updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY (tenant_id, turn_id), UNIQUE (tenant_id, client_request_id)
);
CREATE TABLE inference_ledger.cancellation_tombstones (
  tenant_id text NOT NULL, turn_id uuid NOT NULL, client_request_id uuid NOT NULL, policy_epoch text NOT NULL, policy_digest text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(), PRIMARY KEY (tenant_id, turn_id), UNIQUE (tenant_id, client_request_id)
);
GRANT USAGE ON SCHEMA inference_ledger TO restricted_ledger_runtime;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA inference_ledger TO restricted_ledger_runtime;
-- Only the operator-admin bootstrap identity can toggle this control. Gateway
-- code needs SELECT in its atomic transition predicate, never UPDATE.
REVOKE INSERT, UPDATE, DELETE ON inference_ledger.runtime_controls FROM restricted_ledger_runtime;
GRANT SELECT ON inference_ledger.runtime_controls TO restricted_ledger_runtime;
