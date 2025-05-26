#!/bin/bash

# Script para debugar o teste OAuth que está falhando
# Captura logs dos contêineres para análise

set -e

echo "=== Iniciando debug do teste OAuth ==="

# Função para capturar logs
capture_logs() {
    local project_prefix=$1
    echo "=== Capturando logs para projeto: $project_prefix ==="
    
    # Lista contêineres relacionados
    echo "--- Contêineres encontrados ---"
    docker ps -a | grep "$project_prefix" || echo "Nenhum contêiner encontrado"
    
    # Captura logs de cada serviço se existir
    for service in "mcp-server" "typedb" "mock-oauth"; do
        container_name="${project_prefix}-${service}"
        if docker ps -a --format "{{.Names}}" | grep -q "^${container_name}$"; then
            echo "--- Logs do $service ---"
            docker logs "$container_name" 2>&1 || echo "Falha ao capturar logs do $service"
            echo ""
        fi
    done
}

# Limpar contêineres antigos
echo "=== Limpando contêineres antigos ==="
docker container prune -f 2>/dev/null || true

# Executar o teste em background
echo "=== Iniciando teste em background ==="
cargo test test_oauth_connection_fails_with_invalid_token_signature --test integration -- --nocapture --test-threads=1 > test_output.log 2>&1 &
TEST_PID=$!

# Aguardar contêineres serem criados
echo "=== Aguardando contêineres serem criados (20s) ==="
sleep 20

# Encontrar projeto do teste atual
PROJECT_PREFIX=$(docker ps -a --format "{{.Names}}" | grep "mcp.*oauth.*mcp-server" | head -1 | sed 's/-mcp-server$//' || echo "")

if [ -n "$PROJECT_PREFIX" ]; then
    capture_logs "$PROJECT_PREFIX"
else
    echo "ERRO: Não foi possível encontrar contêineres do teste"
    echo "Contêineres disponíveis:"
    docker ps -a
fi

# Aguardar teste terminar
echo "=== Aguardando teste terminar ==="
wait $TEST_PID
TEST_EXIT_CODE=$?

echo "=== Resultado do teste ==="
echo "Exit code: $TEST_EXIT_CODE"
echo ""
echo "=== Saída do teste ==="
cat test_output.log

# Cleanup final
echo "=== Limpeza final ==="
if [ -n "$PROJECT_PREFIX" ]; then
    # Parar contêineres se ainda estiverem rodando
    docker stop $(docker ps -q --filter "name=${PROJECT_PREFIX}" 2>/dev/null) 2>/dev/null || true
    docker rm $(docker ps -aq --filter "name=${PROJECT_PREFIX}" 2>/dev/null) 2>/dev/null || true
fi

echo "=== Debug concluído ==="
