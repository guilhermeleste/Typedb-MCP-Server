# Typedb-MCP-Server - Docker & OAuth2

## Build Multiplataforma com Docker Buildx

Pré-requisitos:

- Docker com suporte a buildx
- QEMU para cross-build:

  ```sh
  docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
  ```

- Toolchains Rust para multiplataforma:

  ```sh
  rustup target add x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu
  ```

Build multiplataforma e push para Docker Hub:

```sh
docker buildx build --platform linux/amd64,linux/arm64 \
  -t seu-usuario/typedb-mcp-server:latest --push .
```

## Exemplos de Uso com OAuth2

### Ambiente Real (Auth Server Externo)

No `infra/docker-compose.dev.yml`:

```yaml
services:
  typedb-mcp-server:
    environment:
      MCP_AUTH_OAUTH_ENABLED: "true"
      MCP_AUTH_OAUTH_JWKS_URI: "https://seu-auth-server/.well-known/jwks.json"
      MCP_AUTH_OAUTH_AUDIENCE: "<audience>"
      MCP_AUTH_OAUTH_ISSUER: "<issuer>"
```

### Ambiente de Desenvolvimento/Teste (Mock JWKS)

No `infra/docker-compose.dev.yml`:

```yaml
services:
  mock-auth-server:
    image: nginx:alpine
    volumes:
      - ./mock_jwks.json:/usr/share/nginx/html/.well-known/jwks.json:ro
    ports:
      - "9091:80"

  typedb-mcp-server:
    environment:
      MCP_AUTH_OAUTH_ENABLED: "true"
      MCP_AUTH_OAUTH_JWKS_URI: "http://mock-auth-server/.well-known/jwks.json"
```

## Healthcheck

- O endpoint `livez` é usado para liveness/readiness.
- Endpoints adicionais: `livez`, `/readyz`.

## Scripts Auxiliares

### buildx-multiplatform.sh

```sh
#!/bin/bash
# Build multiplataforma e push para Docker Hub
set -e
PLATFORMS="linux/amd64,linux/arm64"
IMAGE="seu-usuario/typedb-mcp-server:latest"

echo "[INFO] Inicializando QEMU para cross-build..."
docker run --rm --privileged multiarch/qemu-user-static --reset -p yes

echo "[INFO] Build multiplataforma para: $PLATFORMS"
docker buildx build --platform $PLATFORMS -t $IMAGE --push .
```

### run-mock-oauth2.sh

```sh
#!/bin/bash
# Sobe um mock JWKS server local para OAuth2
set -e
PORT=${1:-9091}
MOCK_JWKS_FILE=mock_jwks.json

echo "[INFO] Servindo $MOCK_JWKS_FILE em http://localhost:$PORT/.well-known/jwks.json"
docker run --rm -p $PORT:80 -v $(pwd)/$MOCK_JWKS_FILE:/usr/share/nginx/html/.well-known/jwks.json:ro nginx:alpine
```

---

> Consulte o Dockerfile e `infra/docker-compose.dev.yml` para mais exemplos e variáveis de ambiente suportadas.
