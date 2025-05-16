#!/bin/bash
# Sobe um mock JWKS server local para OAuth2
set -e
PORT=${1:-9091}
MOCK_JWKS_FILE=mock_jwks.json

echo "[INFO] Servindo $MOCK_JWKS_FILE em http://localhost:$PORT/.well-known/jwks.json"
docker run --rm -p $PORT:80 -v $(pwd)/$MOCK_JWKS_FILE:/usr/share/nginx/html/.well-known/jwks.json:ro nginx:alpine
