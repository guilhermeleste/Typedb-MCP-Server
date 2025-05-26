#!/bin/bash

# Script para debug rápido do teste OAuth
TEST_NAME=${1:-"connection_tests::test_oauth_connection_fails_with_invalid_token_signature"}

echo "=== Iniciando debug rápido do teste OAuth ==="

# Executa o teste e imediatamente após tenta capturar logs
cargo test $TEST_NAME -- --nocapture &
TEST_PID=$!

# Aguarda um pouco e verifica containers
sleep 8

echo "=== Verificando containers criados ==="
CONTAINERS=$(docker ps -a --format "{{.Names}}" | grep "mcp_conn_oauth_bad_sig" | head -5)

if [ -n "$CONTAINERS" ]; then
    echo "Containers encontrados:"
    echo "$CONTAINERS"
    echo
    
    # Captura logs rapidamente, especialmente do mcp-server
    for container in $CONTAINERS; do
        echo "=== Logs do container: $container ==="
        docker logs "$container" 2>&1
        echo "=== Status detalhado: ==="
        docker inspect "$container" --format 'Status={{.State.Status}} ExitCode={{.State.ExitCode}} Error={{.State.Error}} StartedAt={{.State.StartedAt}} FinishedAt={{.State.FinishedAt}}'
        echo
    done
    
    # Se o mcp-server estiver com problemas, captura logs em loop
    MCP_CONTAINER=$(echo "$CONTAINERS" | grep mcp-server | head -1)
    if [ -n "$MCP_CONTAINER" ]; then
        echo "=== Monitorando container MCP em loop por 30s ==="
        for i in {1..10}; do
            echo "Verificação $i:"
            docker inspect "$MCP_CONTAINER" --format 'Status={{.State.Status}} ExitCode={{.State.ExitCode}}'
            docker logs "$MCP_CONTAINER" 2>&1 | tail -5
            sleep 3
        done
    fi
else
    echo "Nenhum container encontrado ainda..."
fi

# Aguarda o teste terminar
wait $TEST_PID
TEST_RESULT=$?

# Se ainda houver containers, captura logs finais
FINAL_CONTAINERS=$(docker ps -a --format "{{.Names}}" | grep "mcp_conn_oauth_bad_sig" | head -5)
if [ -n "$FINAL_CONTAINERS" ]; then
    echo "=== Logs finais ==="
    for container in $FINAL_CONTAINERS; do
        echo "Final logs de $container:"
        docker logs "$container" 2>&1 | tail -10
    done
fi

exit $TEST_RESULT
