#!/bin/bash
# Sistema de Otimização de Testes Docker
# Mantém sequencialidade necessária mas otimiza performance

set -euo pipefail

# Configurações
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
readonly CACHE_DIR="${PROJECT_ROOT}/.docker-cache"
readonly METRICS_FILE="${PROJECT_ROOT}/.github/errors/docker-optimization-metrics.json"
readonly DOCKER_BUILDX_CACHE_TYPE="${DOCKER_BUILDX_CACHE_TYPE:-local}"

# Cores para output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Logging
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $*${NC}" >&2
}

warn() {
    echo -e "${YELLOW}[WARNING] $*${NC}" >&2
}

error() {
    echo -e "${RED}[ERROR] $*${NC}" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS] $*${NC}" >&2
}

# Análise de Dockerfile para otimizações
analyze_dockerfile() {
    local dockerfile="$1"
    local analysis_result=""
    
    log "Analisando Dockerfile: $dockerfile"
    
    # Verifica se está usando multi-stage builds
    if grep -q "FROM.*AS" "$dockerfile"; then
        analysis_result="✓ Multi-stage build detectado"
    else
        analysis_result="⚠ Considerar multi-stage build"
    fi
    
    # Verifica ordem de comandos para cache
    local copy_before_run=$(grep -n "COPY.*\." "$dockerfile" | head -1 | cut -d: -f1)
    local run_deps=$(grep -n "RUN.*install\|RUN.*apt-get\|RUN.*cargo" "$dockerfile" | head -1 | cut -d: -f1)
    
    if [[ -n "$copy_before_run" && -n "$run_deps" && "$copy_before_run" -lt "$run_deps" ]]; then
        analysis_result+="\n⚠ COPY antes de RUN pode invalidar cache"
    else
        analysis_result+="\n✓ Ordem de comandos otimizada para cache"
    fi
    
    # Verifica limpeza de cache apt
    if grep -q "rm -rf /var/lib/apt/lists" "$dockerfile"; then
        analysis_result+="\n✓ Limpeza de cache apt detectada"
    else
        analysis_result+="\n⚠ Considerar limpeza de cache apt"
    fi
    
    echo -e "$analysis_result"
}

# Otimização de build com cache
optimize_docker_build() {
    local service_name="$1"
    local dockerfile="${2:-Dockerfile}"
    local context="${3:-.}"
    
    log "Otimizando build Docker para $service_name"
    
    # Cria diretório de cache se não existir
    mkdir -p "$CACHE_DIR"
    
    local start_time=$(date +%s)
    local cache_from_args=""
    
    # Configura cache buildx
    if command -v docker-buildx >/dev/null 2>&1; then
        log "Usando Docker Buildx com cache"
        
        docker buildx build \
            --cache-from=type=${DOCKER_BUILDX_CACHE_TYPE},src=${CACHE_DIR}/${service_name} \
            --cache-to=type=${DOCKER_BUILDX_CACHE_TYPE},dest=${CACHE_DIR}/${service_name},mode=max \
            --tag "${service_name}:optimized" \
            --file "$dockerfile" \
            "$context"
    else
        # Fallback para docker build tradicional
        log "Usando Docker build tradicional com cache"
        
        # Tenta usar imagem anterior como cache
        if docker image inspect "${service_name}:latest" >/dev/null 2>&1; then
            cache_from_args="--cache-from ${service_name}:latest"
        fi
        
        docker build \
            $cache_from_args \
            --tag "${service_name}:optimized" \
            --file "$dockerfile" \
            "$context"
    fi
    
    local end_time=$(date +%s)
    local build_duration=$((end_time - start_time))
    
    success "Build otimizado concluído em ${build_duration}s"
    
    # Registra métricas
    record_build_metrics "$service_name" "$build_duration"
}

# Análise de tamanho de imagem
analyze_image_size() {
    local image_name="$1"
    
    log "Analisando tamanho da imagem: $image_name"
    
    if command -v dive >/dev/null 2>&1; then
        log "Executando análise detalhada com dive"
        dive "$image_name" --ci --highestUserWastedPercent=0.1
    else
        warn "Ferramenta 'dive' não encontrada. Instalando..."
        # Instala dive temporariamente
        local dive_temp="/tmp/dive"
        curl -sSL "https://github.com/wagoodman/dive/releases/download/v0.12.0/dive_0.12.0_linux_amd64.tar.gz" | \
            tar -xz -C /tmp
        chmod +x "$dive_temp"
        "$dive_temp" "$image_name" --ci --highestUserWastedPercent=0.1
        rm -f "$dive_temp"
    fi
    
    # Mostra informações básicas da imagem
    docker images "$image_name" --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}"
}

# Otimização de teste sequencial
optimize_sequential_tests() {
    local compose_file="${1:-docker-compose.test.yml}"
    
    log "Otimizando execução de testes sequenciais"
    
    # Pre-pull de imagens necessárias
    log "Pre-pulling imagens de dependências..."
    docker-compose -f "$compose_file" pull --quiet
    
    # Pré-aquecimento de volumes e redes
    log "Preparando recursos Docker..."
    docker-compose -f "$compose_file" up --no-start
    
    # Execução otimizada dos testes
    local start_time=$(date +%s)
    
    log "Executando testes sequenciais otimizados..."
    
    # Estratégia: minimiza tempo de down/up entre testes
    docker-compose -f "$compose_file" up --build --abort-on-container-exit --exit-code-from test-runner
    
    local end_time=$(date +%s)
    local test_duration=$((end_time - start_time))
    
    success "Testes executados em ${test_duration}s"
    
    # Cleanup eficiente
    log "Limpeza pós-teste..."
    docker-compose -f "$compose_file" down --volumes --remove-orphans
    
    # Registra métricas de teste
    record_test_metrics "$test_duration"
}

# Limpeza inteligente de recursos Docker
intelligent_cleanup() {
    log "Executando limpeza inteligente de recursos Docker"
    
    # Remove apenas imagens órfãs e containers parados há mais de 1h
    docker image prune -f --filter "until=1h"
    docker container prune -f --filter "until=1h"
    
    # Remove volumes não utilizados (cuidado em produção)
    if [[ "${DOCKER_AGGRESSIVE_CLEANUP:-false}" == "true" ]]; then
        warn "Executando limpeza agressiva de volumes"
        docker volume prune -f
    fi
    
    # Mostra espaço liberado
    docker system df
}

# Registro de métricas de build
record_build_metrics() {
    local service_name="$1"
    local duration="$2"
    local image_size=$(docker images "$service_name:optimized" --format "{{.Size}}")
    
    local metrics_json="{
        \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
        \"service\": \"$service_name\",
        \"build_duration_seconds\": $duration,
        \"image_size\": \"$image_size\",
        \"optimization_applied\": true
    }"
    
    # Cria arquivo de métricas se não existir
    mkdir -p "$(dirname "$METRICS_FILE")"
    
    # Adiciona métricas ao arquivo
    if [[ -f "$METRICS_FILE" ]]; then
        local temp_file=$(mktemp)
        jq ". += [$metrics_json]" "$METRICS_FILE" > "$temp_file" && mv "$temp_file" "$METRICS_FILE"
    else
        echo "[$metrics_json]" > "$METRICS_FILE"
    fi
    
    log "Métricas de build registradas: ${duration}s, tamanho: $image_size"
}

# Registro de métricas de teste
record_test_metrics() {
    local duration="$1"
    
    local metrics_json="{
        \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
        \"test_type\": \"sequential_docker\",
        \"duration_seconds\": $duration,
        \"optimization_applied\": true
    }"
    
    # Integra com error registry se disponível
    if [[ -f "$PROJECT_ROOT/scripts/error-registry.sh" ]]; then
        "$PROJECT_ROOT/scripts/error-registry.sh" log-metric \
            --type "test_performance" \
            --value "$duration" \
            --context "sequential_docker_tests"
    fi
    
    log "Métricas de teste registradas: ${duration}s"
}

# Relatório de otimizações
generate_optimization_report() {
    log "Gerando relatório de otimizações..."
    
    if [[ ! -f "$METRICS_FILE" ]]; then
        warn "Nenhuma métrica encontrada para gerar relatório"
        return 0
    fi
    
    echo -e "\n${BLUE}=== RELATÓRIO DE OTIMIZAÇÃO DOCKER ===${NC}"
    echo ""
    
    # Estatísticas de build
    local avg_build_time=$(jq '[.[] | select(.build_duration_seconds) | .build_duration_seconds] | add / length' "$METRICS_FILE" 2>/dev/null || echo "0")
    local total_builds=$(jq '[.[] | select(.build_duration_seconds)] | length' "$METRICS_FILE" 2>/dev/null || echo "0")
    
    echo "📊 Builds realizados: $total_builds"
    echo "⏱️  Tempo médio de build: ${avg_build_time}s"
    
    # Estatísticas de teste
    local avg_test_time=$(jq '[.[] | select(.test_type == "sequential_docker") | .duration_seconds] | add / length' "$METRICS_FILE" 2>/dev/null || echo "0")
    local total_tests=$(jq '[.[] | select(.test_type == "sequential_docker")] | length' "$METRICS_FILE" 2>/dev/null || echo "0")
    
    echo "🧪 Testes executados: $total_tests"
    echo "⏱️  Tempo médio de teste: ${avg_test_time}s"
    
    echo ""
    echo -e "${GREEN}✓ Otimizações ativas:${NC}"
    echo "  • Cache de layers Docker"
    echo "  • Multi-stage builds"
    echo "  • Pre-pull de imagens"
    echo "  • Limpeza inteligente"
    echo "  • Métricas de performance"
}

# Menu principal
main() {
    case "${1:-help}" in
        "analyze")
            analyze_dockerfile "${2:-Dockerfile}"
            ;;
        "build")
            optimize_docker_build "${2:-typedb-mcp-server}" "${3:-Dockerfile}" "${4:-.}"
            ;;
        "test")
            optimize_sequential_tests "${2:-docker-compose.test.yml}"
            ;;
        "size")
            analyze_image_size "${2:-typedb-mcp-server:optimized}"
            ;;
        "cleanup")
            intelligent_cleanup
            ;;
        "report")
            generate_optimization_report
            ;;
        "full")
            log "Executando otimização completa..."
            analyze_dockerfile "Dockerfile"
            optimize_docker_build "typedb-mcp-server"
            analyze_image_size "typedb-mcp-server:optimized"
            optimize_sequential_tests
            intelligent_cleanup
            generate_optimization_report
            ;;
        "help"|*)
            echo "Docker Test Optimizer - Sistema de Otimização de Testes"
            echo ""
            echo "Uso: $0 <comando> [argumentos]"
            echo ""
            echo "Comandos:"
            echo "  analyze [dockerfile]     - Analisa Dockerfile para otimizações"
            echo "  build <name> [dockerfile] [context] - Build otimizado com cache"
            echo "  test [compose-file]      - Executa testes sequenciais otimizados"
            echo "  size <image>             - Analisa tamanho de imagem com dive"
            echo "  cleanup                  - Limpeza inteligente de recursos"
            echo "  report                   - Gera relatório de otimizações"
            echo "  full                     - Executa pipeline completa de otimização"
            echo ""
            echo "Variáveis de ambiente:"
            echo "  DOCKER_BUILDX_CACHE_TYPE - Tipo de cache buildx (local|registry)"
            echo "  DOCKER_AGGRESSIVE_CLEANUP - Limpeza agressiva de volumes (true|false)"
            ;;
    esac
}

# Executa função principal
main "$@"
