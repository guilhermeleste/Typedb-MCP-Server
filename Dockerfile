# syntax=docker/dockerfile:1.7

# ----------- BUILDER STAGE -----------
FROM rust:1.87.0-slim-bookworm AS builder

ENV APP_NAME=typedb_mcp_server \
    CARGO_TERM_COLOR=always
WORKDIR /usr/src/$APP_NAME

# Copia manifestos para cache de dependências
COPY Cargo.toml Cargo.lock ./
# Otimiza cache: cria main.rs dummy para baixar dependências
RUN mkdir -p src && echo "fn main() {}" > src/main.rs
RUN cargo build --release --locked || true
RUN rm src/main.rs

# Copia o código fonte real
COPY src ./src

# Compila o binário release
RUN cargo build --release --locked

# ----------- FINAL STAGE (RUNTIME) -----------
FROM ubuntu:latest:24.04 AS final

ENV APP_NAME=typedb_mcp_server

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

# Usuário não-root
RUN groupadd --system $APP_NAME && useradd --system --gid $APP_NAME --home-dir /app --create-home $APP_NAME

WORKDIR /app

# Copia o binário do builder
COPY --from=builder /usr/src/$APP_NAME/target/release/$APP_NAME /usr/local/bin/$APP_NAME

USER $APP_NAME

EXPOSE 8787 8443 9090

# Healthcheck customizado para o MCP Server (ajustável via compose)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8787/health || exit 1

ENTRYPOINT ["/usr/local/bin/typedb_mcp_server"]
CMD []

# ---
# Buildx multiplataforma:
# Para construir para múltiplas arquiteturas (ex: linux/amd64, linux/arm64):
#
#   docker buildx build --platform linux/amd64,linux/arm64 -t seu-usuario/typedb-mcp-server:latest --push .
#
# Certifique-se de que o binário Rust seja compilado com target adequado (ex: x86_64-unknown-linux-gnu, aarch64-unknown-linux-gnu).
# Para builds cross, instale os toolchains necessários:
#   rustup target add aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu
# E configure o buildx com QEMU:
#   docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
# Veja https://docs.docker.com/reference/cli/docker/buildx/ para detalhes.

# ---
# OAuth2 real/mocks:
# Para ambientes com OAuth2 real, configure as variáveis de ambiente:
#   MCP_AUTH_OAUTH_ENABLED=true
#   MCP_AUTH_OAUTH_JWKS_URI=https://seu-auth-server/.well-known/jwks.json
#   MCP_AUTH_OAUTH_AUDIENCE=...
#   MCP_AUTH_OAUTH_ISSUER=...
# Para ambientes de desenvolvimento/teste, use um mock JWKS:
#   MCP_AUTH_OAUTH_ENABLED=true
#   MCP_AUTH_OAUTH_JWKS_URI=http://mock-auth-server/.well-known/jwks.json
#   (Monte um mock_auth_server no docker-compose.yml)
