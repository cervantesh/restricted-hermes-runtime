FROM postgres:16.10-bookworm

RUN groupadd --system --gid 20004 restricted-postgres-socket \
 && usermod --append --groups 20004 postgres \
 && useradd --system --uid 10005 --gid 20004 --no-create-home restricted-local-gateway \
 && useradd --system --uid 10006 --gid 20004 --no-create-home restricted-local-conversation

COPY migrations/001_restricted_runtime.sql /docker-entrypoint-initdb.d/010-schema.sql
COPY deploy/local/postgres/005-peer-config.sh /docker-entrypoint-initdb.d/005-peer-config.sh
COPY deploy/local/postgres/020-local-bootstrap.sql /docker-entrypoint-initdb.d/020-local-bootstrap.sql
