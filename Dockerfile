# Estágio 1: Build da aplicação Rust (existente)
FROM rust:1.87.0-slim-bookworm AS builder
WORKDIR /usr/src/typedb_mcp_server
COPY . .
RUN cargo build --release --locked

# Estágio 2: Imagem final de produção
FROM ubuntu:25.10 AS final
ARG VAULT_VERSION=1.17.0
# Instalar dependências e o Vault
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl unzip && \
    curl -Lo vault.zip "https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_linux_amd64.zip" && \
    unzip vault.zip && mv vault /usr/local/bin/vault && rm vault.zip && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copiar binário da aplicação, entrypoint, config do Vault Agent e templates
COPY --from=builder /usr/src/typedb_mcp_server/target/release/typedb_mcp_server /usr/local/bin/
COPY docker-entrypoint.sh vault-agent-config.hcl ./
COPY templates/ ./templates/
RUN chmod +x docker-entrypoint.sh

# Criar usuário não-root
RUN groupadd --system appuser && useradd --system --gid appuser appuser
USER appuser

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["/usr/local/bin/typedb_mcp_server"]
