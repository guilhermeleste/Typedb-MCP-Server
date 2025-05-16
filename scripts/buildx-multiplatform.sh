#!/bin/bash
# Build multiplataforma e push para Docker Hub
set -e
PLATFORMS="linux/amd64,linux/arm64"
IMAGE="seu-usuario/typedb-mcp-server:latest"

echo "[INFO] Inicializando QEMU para cross-build..."
docker run --rm --privileged multiarch/qemu-user-static --reset -p yes

echo "[INFO] Build multiplataforma para: $PLATFORMS"
docker buildx build --platform $PLATFORMS -t $IMAGE --push .
