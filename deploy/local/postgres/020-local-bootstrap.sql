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

-- PostgreSQL requires some UPDATE privilege for SELECT ... FOR SHARE even
-- though the gateway never mutates this row. Grant one column only, then make
-- every attempted gateway UPDATE fail at execution time.
CREATE FUNCTION inference_ledger.reject_local_gateway_control_update()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF current_user = 'restricted_local_gateway' THEN
    RAISE EXCEPTION 'local gateway cannot update runtime controls'
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER aaa_reject_local_gateway_control_update
BEFORE UPDATE ON inference_ledger.runtime_controls
FOR EACH ROW EXECUTE FUNCTION inference_ledger.reject_local_gateway_control_update();
GRANT UPDATE (updated_at) ON inference_ledger.runtime_controls
  TO restricted_local_gateway;
