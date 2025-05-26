#!/bin/bash
set -e

echo "=== Monitor de Teste em Tempo Real ==="

# Executa teste em background
echo "=== Iniciando teste ==="
cargo test connection_tests::test_oauth_connection_fails_with_invalid_token_signature -- --nocapture &
TEST_PID=$!

# Monitora containers por 60 segundos
echo "=== Monitorando containers por 60 segundos ==="
for i in {1..20}; do
    echo "--- Segundo $((i*3)) ---"
    docker ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Image}}" | grep -E "(mcp_conn|oauth|typedb)" || echo "Nenhum container encontrado ainda"
    
    # Tenta capturar logs do mcp-server se existir
    MCP_CONTAINER=$(docker ps -a --format "{{.Names}}" | grep "mcp-server" | head -1 || true)
    if [[ -n "$MCP_CONTAINER" ]]; then
        echo "=== LOGS DO $MCP_CONTAINER ==="
        docker logs "$MCP_CONTAINER" 2>&1 | tail -10 || echo "Erro ao capturar logs"
        echo "=== FIM LOGS ==="
    fi
    
    sleep 3
done

echo "=== Aguardando teste terminar ==="
wait $TEST_PID
echo "=== Teste finalizado ==="
