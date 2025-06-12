FROM rust:1.87.0-slim-bookworm AS builder
WORKDIR /usr/src/typedb_mcp_server
COPY . .
RUN cargo build --release --bin typedb_mcp_server
RUN cargo build --release --bin vault_bootstrap

FROM debian:12-slim AS final
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /usr/src/typedb_mcp_server/target/release/typedb_mcp_server /usr/local/bin/
COPY --from=builder /usr/src/typedb_mcp_server/target/release/vault_bootstrap /usr/local/bin/
COPY infra/docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh
RUN groupadd --system appuser && useradd --system --gid appuser appuser
USER appuser
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["typedb_mcp_server"]
