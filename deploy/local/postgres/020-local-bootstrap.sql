CREATE ROLE restricted_local_conversation
  LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  IN ROLE restricted_content_runtime;
CREATE ROLE restricted_local_gateway
  LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  IN ROLE restricted_ledger_runtime;

REVOKE CONNECT ON DATABASE restricted_runtime FROM PUBLIC;
GRANT CONNECT ON DATABASE restricted_runtime
  TO restricted_local_conversation, restricted_local_gateway;

REVOKE ALL ON SCHEMA inference_ledger FROM restricted_local_conversation;
REVOKE ALL ON ALL TABLES IN SCHEMA inference_ledger FROM restricted_local_conversation;
REVOKE ALL ON SCHEMA restricted_content FROM restricted_local_gateway;
REVOKE ALL ON ALL TABLES IN SCHEMA restricted_content FROM restricted_local_gateway;
REVOKE INSERT, UPDATE, DELETE ON inference_ledger.runtime_controls
  FROM restricted_local_gateway;
GRANT SELECT ON inference_ledger.runtime_controls TO restricted_local_gateway;
