#!/bin/bash

# Script para monitorar logs em tempo real do teste OAuth
set -e

echo "=== Monitorando logs detalhados do teste OAuth ==="
echo "=== Limpando contêineres antigos ==="
docker system prune -f > /dev/null 2>&1

echo "=== Iniciando teste em background ==="
cargo test test_oauth_connection_fails_with_invalid_token_signature --test integration -- --nocapture &
TEST_PID=$!

echo "=== Aguardando contêineres serem criados (30s) ==="
sleep 30

# Encontrar projeto ativo
PROJECT_PATTERN="mcp_conn_oauth_bad_sig_*"
PROJECT_NAME=$(docker ps --format "table {{.Names}}" | grep "mcp_conn_oauth_bad_sig" | head -1 | sed 's/-.*$//')

if [ -z "$PROJECT_NAME" ]; then
    echo "Erro: Nenhum projeto encontrado com padrão $PROJECT_PATTERN"
    exit 1
fi

echo "=== Monitorando logs para projeto: $PROJECT_NAME ==="

echo "--- Contêineres encontrados ---"
docker ps | grep "$PROJECT_NAME"

echo "--- Status detalhado dos contêineres ---"
for container in $(docker ps -q --filter "name=$PROJECT_NAME"); do
    container_name=$(docker inspect --format='{{.Name}}' $container | sed 's/^\/\///')
    container_status=$(docker inspect --format='{{.State.Status}}' $container)
    container_health=$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}no-health{{end}}' $container)
    echo "Container: $container_name, Status: $container_status, Health: $container_health"
done

echo ""
echo "--- Logs COMPLETOS do mcp-server ---"
MCP_CONTAINER=$(docker ps -q --filter "name=${PROJECT_NAME}-mcp-server")
if [ -n "$MCP_CONTAINER" ]; then
    echo "Container ID: $MCP_CONTAINER"
    docker logs $MCP_CONTAINER --timestamps 2>&1
else
    echo "Container mcp-server não encontrado!"
fi

echo ""
echo "--- Logs COMPLETOS do typedb ---"
TYPEDB_CONTAINER=$(docker ps -q --filter "name=${PROJECT_NAME}-typedb")
if [ -n "$TYPEDB_CONTAINER" ]; then
    echo "Container ID: $TYPEDB_CONTAINER"
    docker logs $TYPEDB_CONTAINER --timestamps 2>&1
else
    echo "Container typedb não encontrado!"
fi

echo ""
echo "--- Logs COMPLETOS do mock-oauth ---"
OAUTH_CONTAINER=$(docker ps -q --filter "name=${PROJECT_NAME}-mock-oauth")
if [ -n "$OAUTH_CONTAINER" ]; then
    echo "Container ID: $OAUTH_CONTAINER"
    docker logs $OAUTH_CONTAINER --timestamps 2>&1
else
    echo "Container mock-oauth não encontrado!"
fi

echo ""
echo "=== Aguardando teste terminar (monitorando em tempo real) ==="
timeout 60 bash -c "
while kill -0 $TEST_PID 2>/dev/null; do
    echo '--- Status dos contêineres a cada 10s ---'
    docker ps --filter \"name=$PROJECT_NAME\" --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
    sleep 10
done
" || echo "Timeout ou teste finalizou"

wait $TEST_PID
