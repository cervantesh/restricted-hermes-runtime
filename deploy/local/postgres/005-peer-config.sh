#!/bin/sh
set -eu

cat >"$PGDATA/pg_ident.conf" <<'EOF'
restricted_runtime restricted-local-conversation restricted_local_conversation
restricted_runtime restricted-local-gateway restricted_local_gateway
EOF

cat >"$PGDATA/pg_hba.conf" <<'EOF'
local all postgres peer
local restricted_runtime restricted_local_conversation peer map=restricted_runtime
local restricted_runtime restricted_local_gateway peer map=restricted_runtime
local all all reject
host all all all reject
hostssl all all all reject
hostnossl all all all reject
EOF

chmod 0600 "$PGDATA/pg_ident.conf" "$PGDATA/pg_hba.conf"
