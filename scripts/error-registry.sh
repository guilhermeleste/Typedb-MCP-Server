#!/bin/bash

# Error Registry System - Typedb-MCP-Server
# Sistema completo de registro, análise e prevenção de erros

set -euo pipefail

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configurações
ERROR_DIR=".github/errors"
SCRIPTS_DIR="scripts"

# Funções auxiliares
log_header() {
    echo -e "${CYAN}================================${NC}"
    echo -e "${CYAN} $1${NC}"
    echo -e "${CYAN}================================${NC}"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_action() {
    echo -e "${PURPLE}[ACTION]${NC} $1"
}

# Verifica dependências
check_dependencies() {
    local missing_deps=()
    
    if ! command -v cargo >/dev/null 2>&1; then
        missing_deps+=("cargo")
    fi
    
    if ! command -v git >/dev/null 2>&1; then
        missing_deps+=("git")
    fi
    
    if ! command -v bc >/dev/null 2>&1; then
        missing_deps+=("bc")
    fi
    
    if [ ${#missing_deps[@]} -gt 0 ]; then
        log_error "Dependências faltantes: ${missing_deps[*]}"
        log_info "Instale com: apt-get install ${missing_deps[*]}"
        return 1
    fi
    
    return 0
}

# Inicializa estrutura do sistema
initialize_system() {
    log_header "INICIALIZAÇÃO DO SISTEMA"
    
    log_action "Criando estrutura de diretórios..."
    mkdir -p "$ERROR_DIR"/{patterns,solutions,prevention}
    
    # Verifica se scripts existem
    local scripts=("error-capture.sh" "error-analysis.sh" "error-prevention.sh")
    for script in "${scripts[@]}"; do
        if [ ! -f "$SCRIPTS_DIR/$script" ]; then
            log_error "Script não encontrado: $SCRIPTS_DIR/$script"
            return 1
        fi
        chmod +x "$SCRIPTS_DIR/$script"
    done
    
    log_success "Sistema inicializado com sucesso"
}

# Executa captura de erros
run_capture() {
    log_header "CAPTURA DE ERROS"
    
    log_action "Executando captura automática..."
    if ./"$SCRIPTS_DIR/error-capture.sh"; then
        log_success "Captura concluída"
        return 0
    else
        log_error "Falha na captura de erros"
        return 1
    fi
}

# Executa análise de padrões
run_analysis() {
    log_header "ANÁLISE DE PADRÕES"
    
    log_action "Executando análise de padrões..."
    if ./"$SCRIPTS_DIR/error-analysis.sh"; then
        log_success "Análise concluída"
        return 0
    else
        log_error "Falha na análise de padrões"
        return 1
    fi
}

# Executa medidas preventivas
run_prevention() {
    log_header "MEDIDAS PREVENTIVAS"
    
    log_action "Aplicando medidas preventivas..."
    if ./"$SCRIPTS_DIR/error-prevention.sh"; then
        log_success "Prevenção aplicada"
        return 0
    else
        log_error "Falha na aplicação de medidas preventivas"
        return 1
    fi
}

# Mostra status do sistema
show_status() {
    log_header "STATUS DO SISTEMA"
    
    local total_errors=$(find "$ERROR_DIR" -name "*.yml" 2>/dev/null | wc -l)
    local patterns=$(find "$ERROR_DIR/patterns" -name "*.md" 2>/dev/null | wc -l)
    local solutions=$(find "$ERROR_DIR/solutions" -name "*.md" 2>/dev/null | wc -l)
    local prevention_rules=$(find "$ERROR_DIR/prevention" -name "*.md" 2>/dev/null | wc -l)
    
    echo -e "${BLUE}📊 Estatísticas do Sistema:${NC}"
    echo "  • Total de Erros Registrados: $total_errors"
    echo "  • Padrões Identificados: $patterns"
    echo "  • Soluções Documentadas: $solutions"
    echo "  • Regras de Prevenção: $prevention_rules"
    echo ""
    
    if [ $total_errors -gt 0 ]; then
        echo -e "${BLUE}📈 Distribuição por Categoria:${NC}"
        for category in "Compilation" "TypeDB" "MCP" "Authentication" "Configuration" "Testing" "General"; do
            local count=$(find "$ERROR_DIR" -name "*.yml" -exec grep -l "category: $category" {} \; 2>/dev/null | wc -l)
            if [ $count -gt 0 ]; then
                echo "  • $category: $count"
            fi
        done
        echo ""
    fi
    
    # Verifica erros recentes (últimas 24h)
    local recent_errors=$(find "$ERROR_DIR" -name "*.yml" -mtime -1 2>/dev/null | wc -l)
    if [ $recent_errors -gt 0 ]; then
        echo -e "${YELLOW}⚠️  Erros Recentes (24h): $recent_errors${NC}"
        echo ""
    fi
    
    # Verifica erros críticos com alta recorrência
    local critical_errors=0
    if [ -d "$ERROR_DIR" ]; then
        for error_file in "$ERROR_DIR"/*.yml; do
            if [ -f "$error_file" ]; then
                local recurrence=$(grep "^recurrence_count:" "$error_file" 2>/dev/null | sed 's/recurrence_count: *//' || echo "1")
                if [ "$recurrence" -gt 3 ]; then
                    ((critical_errors++))
                fi
            fi
        done
    fi
    
    if [ $critical_errors -gt 0 ]; then
        echo -e "${RED}🚨 Erros Críticos (>3 recorrências): $critical_errors${NC}"
        echo ""
    fi
    
    # Status de compilação atual
    echo -e "${BLUE}🔧 Status de Compilação:${NC}"
    if timeout 30s cargo check >/dev/null 2>&1; then
        echo -e "  • ${GREEN}✅ Projeto compila sem erros${NC}"
    else
        echo -e "  • ${RED}❌ Erros de compilação detectados${NC}"
    fi
    
    # Verificação de saúde do Docker
    echo -e "${BLUE}🐳 Status do Docker:${NC}"
    if ! docker info >/dev/null 2>&1; then
        echo -e "  • ${RED}❌ Docker não disponível${NC}"
        echo -e "  • ${YELLOW}⏭️  Pulando testes que dependem do Docker${NC}"
        return 0
    else
        echo -e "  • ${GREEN}✅ Docker funcionando${NC}"
    fi
    
    # Status de testes com timeout e captura automática de erros
    echo -e "${BLUE}🧪 Status de Testes:${NC}"
    
    # Captura e análise de testes unitários
    local unit_test_output=$(mktemp)
    echo -e "  • ${YELLOW}🔄 Executando testes unitários...${NC}"
    if timeout 60s cargo test --lib --bin typedb_mcp_server > "$unit_test_output" 2>&1; then
        echo -e "  • ${GREEN}✅ Testes unitários passando${NC}"
    else
        echo -e "  • ${RED}❌ Falhas nos testes unitários${NC}"
        capture_test_errors "$unit_test_output" "unit_tests"
    fi
    rm -f "$unit_test_output"
    
    # Captura e análise de testes de integração
    echo -e "  • ${YELLOW}🔄 Verificando testes de integração...${NC}"
    local integration_test_output=$(mktemp)
    
    # Cleanup preventivo antes dos testes de integração
    cleanup_docker_environment
    
    if timeout 120s cargo test --test integration > "$integration_test_output" 2>&1; then
        echo -e "  • ${GREEN}✅ Testes de integração passando${NC}"
    else
        echo -e "  • ${RED}❌ Falhas nos testes de integração${NC}"
        capture_test_errors "$integration_test_output" "integration_tests"
    fi
    
    # Cleanup obrigatório após testes de integração (sucesso ou falha)
    cleanup_docker_environment
    rm -f "$integration_test_output"
}

# Captura e registra automaticamente erros de testes
capture_test_errors() {
    local test_output_file="$1"
    local test_type="$2"
    
    if [[ ! -f "$test_output_file" ]]; then
        return 0
    fi
    
    log_action "Analisando erros de $test_type..."
    
    # Cria arquivo temporário para erros processados
    local processed_errors=$(mktemp)
    
    # Parseia diferentes tipos de erro
    parse_rust_test_errors "$test_output_file" "$test_type" >> "$processed_errors"
    
    # Se encontrou erros, registra no sistema
    if [[ -s "$processed_errors" ]]; then
        local error_count=$(wc -l < "$processed_errors")
        log_warning "Encontrados $error_count erro(s) em $test_type"
        
        # Registra cada erro no sistema
        while IFS= read -r error_line; do
            register_parsed_error "$error_line" "$test_type"
        done < "$processed_errors"
        
        # Mostra resumo dos erros capturados
        echo -e "    ${BLUE}📋 Erros capturados e registrados automaticamente${NC}"
    fi
    
    rm -f "$processed_errors"
}

# Parseia erros específicos do Rust/Cargo
parse_rust_test_errors() {
    local input_file="$1"
    local test_type="$2"
    
    # Verifica se há falhas de teste na seção "failures:"
    if grep -q "failures:" "$input_file"; then
        # Captura a seção de failures e processa cada teste individual
        awk '/^failures:/{flag=1; next} /^test result:/{flag=0} flag && /^    [a-zA-Z]/{gsub(/^    /, ""); print "TEST_FAILURE|'$test_type'|" $0}' "$input_file"
        
        # Captura estatísticas do resultado final
        if grep -q "test result: FAILED" "$input_file"; then
            local result_line=$(grep "test result: FAILED" "$input_file")
            echo "TEST_SUMMARY|$test_type|$result_line"
        fi
    fi
    
    # Captura erros de compilação
    grep -n "error\[E[0-9]*\]" "$input_file" | while read -r line; do
        echo "COMPILATION_ERROR|$test_type|$line"
    done
    
    # Captura panics em detalhes
    if grep -q "thread.*panicked" "$input_file"; then
        grep -n -A 2 "thread.*panicked" "$input_file" | while read -r line; do
            echo "PANIC|$test_type|$line"
        done
    fi
    
    # Captura timeouts
    if grep -q -i "timeout\|exceeded.*time" "$input_file"; then
        grep -n -i "timeout\|exceeded.*time" "$input_file" | while read -r line; do
            echo "TIMEOUT|$test_type|$line"
        done
    fi
    
    # Captura erros de assertion com contexto
    if grep -q "assertion failed" "$input_file"; then
        grep -n -A 1 "assertion failed" "$input_file" | while read -r line; do
            echo "ASSERTION_FAILED|$test_type|$line"
        done
    fi
    
    # Captura erros específicos de Docker/infraestrutura
    
    # 1. Erros de porta já alocada
    if grep -q "port is already allocated" "$input_file"; then
        grep -n "port is already allocated" "$input_file" | while read -r line; do
            echo "PORT_CONFLICT|$test_type|$line"
        done
    fi
    
    # 2. Erros do Docker daemon
    if grep -q "Error response from daemon" "$input_file"; then
        grep -n "Error response from daemon" "$input_file" | while read -r line; do
            echo "DOCKER_DAEMON_ERROR|$test_type|$line"
        done
    fi
    
    # 3. Falhas de conectividade
    if grep -q -i "connection.*refused\|connection.*failed" "$input_file"; then
        grep -n -i "connection.*refused\|connection.*failed" "$input_file" | while read -r line; do
            echo "CONNECTION_ERROR|$test_type|$line"
        done
    fi
    
    # 4. Falhas de OAuth/JWT
    if grep -q -i "jwt\|oauth\|token.*invalid" "$input_file"; then
        grep -n -i "jwt\|oauth\|token.*invalid" "$input_file" | while read -r line; do
            echo "AUTH_ERROR|$test_type|$line"
        done
    fi
    
    # 5. Falhas de TLS/certificados
    if grep -q -i "tls\|certificate\|ssl" "$input_file"; then
        grep -n -i "tls.*error\|certificate.*error\|ssl.*error" "$input_file" | while read -r line; do
            echo "TLS_ERROR|$test_type|$line"
        done
    fi
    
    # 6. Falhas de TypeDB
    if grep -q -i "typedb" "$input_file"; then
        grep -n -i "typedb.*error\|typedb.*failed" "$input_file" | while read -r line; do
            echo "TYPEDB_ERROR|$test_type|$line"
        done
    fi
}

# Registra erro parseado no sistema de registry
register_parsed_error() {
    local error_data="$1"
    local test_context="$2"
    
    # Parse do formato: TIPO|CONTEXTO|DESCRIÇÃO  
    local error_type=$(echo "$error_data" | cut -d'|' -f1)
    local context=$(echo "$error_data" | cut -d'|' -f2)
    local description=$(echo "$error_data" | cut -d'|' -f3-)
    
    # Determina categoria baseada no tipo de erro
    local category
    case "$error_type" in
        "COMPILATION_ERROR") category="Compilation" ;;
        "TEST_FAILURE"|"ASSERTION_FAILED"|"TEST_SUMMARY") category="Test" ;;
        "PANIC") category="Runtime" ;;
        "TIMEOUT"|"INFRASTRUCTURE_ERROR") category="Infrastructure" ;;
        "PORT_CONFLICT"|"DOCKER_DAEMON_ERROR"|"DOCKER_COMPOSE_ERROR") category="Docker" ;;
        "CONNECTION_ERROR") category="Network" ;;
        "AUTH_ERROR") category="Authentication" ;;
        "TLS_ERROR") category="Security" ;;
        "TYPEDB_ERROR") category="Database" ;;
        *) category="Unknown" ;;
    esac
    
    # Gera ID único para o erro usando hash simples
    local error_id="auto_$(date +%s)_$(echo "$description" | head -c 50 | tr -d ' \n' | tr -c '[:alnum:]' '_')"
    
    # Cria entrada de erro estruturada
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    # Garante que o diretório existe
    mkdir -p .github/errors
    
    local error_file=".github/errors/auto_captured_$(date +%Y%m%d).md"
    
    # Escreve entrada de erro
    cat >> "$error_file" << EOF
# Auto-captured from $test_context at $timestamp
id: $error_id
timestamp: $timestamp
category: $category
severity: Medium
component: Tests
description: "$error_type in $test_context: $description"
context:
  test_type: $test_context
  auto_captured: true
  error_pattern: $error_type
analysis:
  root_cause: "Automatic analysis pending"
  trigger: "Test execution failure"
solution:
  approach: "Investigation required"
prevention:
  automated: false

---

EOF
    
    log_success "Erro registrado: $error_id ($category)"
}

# Limpa ambiente Docker para evitar conflitos de porta
cleanup_docker_environment() {
    log_action "Limpeza completa do ambiente Docker..."
    
    if command -v docker >/dev/null 2>&1; then
        # 1. Para todos os containers do projeto
        echo "  📦 Limpando containers do projeto..."
        docker ps -a --format "table {{.Names}}\t{{.Image}}" | grep -E "(typedb|mcp|test)" | awk '{print $1}' | tail -n +2 | while read container; do
            if [ -n "$container" ]; then
                echo "    Parando container: $container"
                docker stop "$container" 2>/dev/null || true
                docker rm "$container" 2>/dev/null || true
            fi
        done
        
        # 2. Remove networks do projeto
        echo "  🌐 Limpando networks do projeto..."
        docker network ls --format "{{.Name}}" | grep -E "(typedb|mcp|test)" | while read network; do
            if [ -n "$network" ]; then
                echo "    Removendo network: $network"
                docker network rm "$network" 2>/dev/null || true
            fi
        done
        
        # 3. Docker compose down para arquivos existentes
        echo "  🐳 Executando docker compose down..."
        for compose_file in "docker-compose.yml" "docker-compose.test.yml"; do
            if [ -f "$compose_file" ]; then
                echo "    Processing $compose_file"
                docker compose -f "$compose_file" down --volumes --remove-orphans --timeout 30 2>/dev/null || true
            fi
        done
        
        # 4. Limpeza inteligente de imagens
        echo "  🖼️  Limpando imagens desnecessárias..."
        
        # Remove imagens órfãs (dangling) - mais agressivo
        local dangling_count=$(docker images -f "dangling=true" -q | wc -l)
        if [ "$dangling_count" -gt 1 ]; then  # header conta como 1
            echo "    Removendo $((dangling_count - 1)) imagens órfãs..."
            docker images -f "dangling=true" -q | xargs -r docker rmi 2>/dev/null || true
        fi
        
        # Remove imagens antigas não utilizadas (mais de 7 dias)
        echo "    Removendo imagens não utilizadas há mais de 7 dias..."
        docker image prune -a -f --filter "until=168h" 2>/dev/null || true
        
        # Remove especificamente imagens do projeto antigas
        echo "    Limpando imagens antigas do projeto..."
        docker images --format "{{.Repository}}:{{.Tag}} {{.ID}}" | \
        grep -E "(typedb|mcp)" | \
        awk '{print $2}' | \
        head -20 | \
        while read image_id; do
            if [ -n "$image_id" ] && [ "$image_id" != "IMAGE" ]; then
                # Verifica se a imagem não está sendo usada
                if ! docker ps -a --format "{{.Image}}" | grep -q "$image_id"; then
                    echo "      Removendo imagem não utilizada: $image_id"
                    docker rmi "$image_id" 2>/dev/null || true
                fi
            fi
        done
        
        # 5. System prune conservador (apenas recursos não utilizados há 24h)
        echo "  🧹 Limpeza geral conservadora..."
        docker system prune -f --filter "until=24h" 2>/dev/null || true
        
        # 6. Remove volumes órfãos do projeto
        echo "  💾 Limpando volumes órfãos..."
        docker volume ls -f "dangling=true" --format "{{.Name}}" | grep -E "(typedb|mcp|test)" | while read volume; do
            if [ -n "$volume" ]; then
                echo "    Removendo volume: $volume"
                docker volume rm "$volume" 2>/dev/null || true
            fi
        done
        
        # 7. Aguarda porta 1729 ficar disponível
        echo "  ⏳ Aguardando liberação da porta 1729..."
        local max_wait=15
        local count=0
        while ss -tulpn | grep -q ":1729" && [ $count -lt $max_wait ]; do
            sleep 1
            ((count++))
        done
        
        if ss -tulpn | grep -q ":1729"; then
            log_warning "Porta 1729 ainda ocupada após cleanup"
        else
            echo "    ✅ Porta 1729 liberada"
        fi
        
        log_success "Ambiente Docker completamente limpo"
        
        # Mostra estatísticas finais
        echo "  📊 Estado pós-limpeza:"
        echo "    Containers ativos: $(docker ps -q | wc -l)"
        echo "    Imagens totais: $(docker images -q | wc -l)"
        echo "    Volumes: $(docker volume ls -q | wc -l)"
        echo "    Networks customizadas: $(docker network ls --filter type=custom -q | wc -l)"
        
    else
        log_warning "Docker não encontrado, pulando cleanup Docker"
    fi
}

# Executa limpeza do sistema
run_cleanup() {
    log_header "LIMPEZA DO SISTEMA"
    
    # Captura estatísticas iniciais para relatório
    if command -v docker >/dev/null 2>&1; then
        local initial_images=$(docker images -q | wc -l)
        local initial_containers=$(docker ps -aq | wc -l)
        local initial_volumes=$(docker volume ls -q | wc -l)
        local initial_networks=$(docker network ls --filter type=custom -q | wc -l)
        
        echo "📊 Estado inicial do Docker:"
        echo "  Imagens: $initial_images"
        echo "  Containers: $initial_containers" 
        echo "  Volumes: $initial_volumes"
        echo "  Networks: $initial_networks"
        echo ""
    fi
    
    log_action "Removendo arquivos temporários..."
    
    # Cleanup Docker primeiro (mais importante)
    cleanup_docker_environment
    
    # Remove arquivos de backup antigos (>30 dias)
    echo "📁 Limpando arquivos antigos..."
    find . -name "*.backup-*" -mtime +30 -delete 2>/dev/null || true
    
    # Remove relatórios antigos (>7 dias)
    find "$ERROR_DIR" -name "analysis-*.md" -mtime +7 -delete 2>/dev/null || true
    find "$ERROR_DIR/prevention" -name "prevention-report-*.md" -mtime +7 -delete 2>/dev/null || true
    
    # Compacta arquivos de erro antigos (>30 dias)
    local old_errors=$(find "$ERROR_DIR" -name "*.yml" -mtime +30 2>/dev/null)
    if [ -n "$old_errors" ]; then
        echo "📦 Compactando erros antigos..."
        local archive_dir="$ERROR_DIR/archive"
        mkdir -p "$archive_dir"
        
        echo "$old_errors" | while read -r old_error; do
            if [ -f "$old_error" ]; then
                mv "$old_error" "$archive_dir/"
            fi
        done
        
        log_info "Arquivos antigos movidos para $archive_dir"
    fi
    
    # Remove arquivos de log antigos de testes
    find . -name "test-*.log" -mtime +7 -delete 2>/dev/null || true
    find . -name "cargo-test-*.out" -mtime +1 -delete 2>/dev/null || true
    
    # Remove arquivos temporários do sistema
    find /tmp -name "*typedb*" -mtime +1 -delete 2>/dev/null || true
    find /tmp -name "*mcp*" -mtime +1 -delete 2>/dev/null || true
    
    # Mostra estatísticas finais se Docker disponível
    if command -v docker >/dev/null 2>&1; then
        local final_images=$(docker images -q | wc -l)
        local final_containers=$(docker ps -aq | wc -l)
        local final_volumes=$(docker volume ls -q | wc -l)
        local final_networks=$(docker network ls --filter type=custom -q | wc -l)
        
        echo ""
        echo "📊 Relatório de Limpeza:"
        echo "  Imagens removidas: $((initial_images - final_images))"
        echo "  Containers removidos: $((initial_containers - final_containers))"
        echo "  Volumes removidos: $((initial_volumes - final_volumes))"
        echo "  Networks removidas: $((initial_networks - final_networks))"
        
        # Verifica se houve economia significativa
        local total_removed=$((initial_images - final_images + initial_containers - final_containers))
        if [ $total_removed -gt 0 ]; then
            log_success "Limpeza concluída! $total_removed recursos Docker removidos"
        else
            echo "  ✅ Sistema já estava limpo"
        fi
    fi
    
    log_success "Limpeza do sistema concluída"
}

# Limpeza agressiva de imagens Docker (uso semanal)
aggressive_image_cleanup() {
    log_header "LIMPEZA AGRESSIVA DE IMAGENS DOCKER"
    
    if ! command -v docker >/dev/null 2>&1; then
        log_warning "Docker não encontrado"
        return 1
    fi
    
    local initial_images=$(docker images -q | wc -l)
    local initial_size=$(docker system df --format "table {{.Type}}\t{{.Size}}" | grep "Images" | awk '{print $2}' || echo "Unknown")
    
    echo "📊 Estado inicial:"
    echo "  Total de imagens: $initial_images"
    echo "  Espaço usado por imagens: $initial_size"
    echo ""
    
    log_action "Executando limpeza agressiva..."
    
    # 1. Remove TODAS as imagens órfãs
    echo "🗑️  Removendo imagens órfãs..."
    docker image prune -f
    
    # 2. Remove imagens não utilizadas há mais de 24h
    echo "🕐 Removendo imagens não utilizadas (>24h)..."
    docker image prune -a -f --filter "until=24h"
    
    # 3. Remove imagens de build cache antigas
    echo "🏗️  Limpando build cache..."
    docker builder prune -f --filter "until=24h"
    
    # 4. Remove imagens sem tag específicas do projeto
    echo "🏷️  Removendo imagens sem tag do projeto..."
    docker images --filter "dangling=true" --filter "reference=*typedb*" -q | xargs -r docker rmi 2>/dev/null || true
    docker images --filter "dangling=true" --filter "reference=*mcp*" -q | xargs -r docker rmi 2>/dev/null || true
    
    # 5. System prune completo (mais agressivo)
    echo "🧹 Limpeza completa do sistema..."
    docker system prune -a -f --filter "until=24h"
    
    local final_images=$(docker images -q | wc -l)
    local final_size=$(docker system df --format "table {{.Type}}\t{{.Size}}" | grep "Images" | awk '{print $2}' || echo "Unknown")
    local removed_images=$((initial_images - final_images))
    
    echo ""
    echo "📊 Relatório de Limpeza Agressiva:"
    echo "  Imagens removidas: $removed_images"
    echo "  Imagens restantes: $final_images"
    echo "  Espaço inicial: $initial_size"
    echo "  Espaço final: $final_size"
    
    if [ $removed_images -gt 0 ]; then
        log_success "Limpeza agressiva concluída! $removed_images imagens removidas"
    else
        echo "  ✅ Nenhuma imagem foi removida (sistema já otimizado)"
    fi
}

# Executa workflow completo
run_full_workflow() {
    log_header "WORKFLOW COMPLETO"
    
    local start_time=$(date +%s)
    
    # Executa todas as etapas
    if ! run_capture; then
        log_error "Falha na captura - interrompendo workflow"
        return 1
    fi
    
    if ! run_analysis; then
        log_error "Falha na análise - interrompendo workflow"
        return 1
    fi
    
    if ! run_prevention; then
        log_error "Falha na prevenção - interrompendo workflow"
        return 1
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    log_header "WORKFLOW CONCLUÍDO"
    log_success "Tempo total: ${duration}s"
    
    # Mostra resumo final
    show_status
}

# Mostra ajuda
show_help() {
    cat << 'EOF'
Error Registry System - Sistema de Registro e Prevenção de Erros

USAGE:
    ./scripts/error-registry.sh [COMMAND]

COMMANDS:
    init        Inicializa estrutura do sistema
    capture     Executa captura de erros
    analyze     Executa análise de padrões
    prevent     Aplica medidas preventivas
    status      Mostra status do sistema
    cleanup     Remove arquivos temporários e antigos
    deep-clean  Limpeza agressiva de imagens Docker (uso semanal)
    full        Executa workflow completo (capture + analyze + prevent)
    help        Mostra esta ajuda

EXEMPLOS:
    # Workflow completo
    ./scripts/error-registry.sh full
    
    # Apenas captura
    ./scripts/error-registry.sh capture
    
    # Status atual
    ./scripts/error-registry.sh status
    
    # Limpeza normal
    ./scripts/error-registry.sh cleanup
    
    # Limpeza agressiva (semanal)
    ./scripts/error-registry.sh deep-clean

ARQUIVOS IMPORTANTES:
    .github/errors/           - Diretório principal de erros
    .github/errors/registry.md - Dashboard central
    scripts/error-*.sh        - Scripts individuais

Para mais informações, consulte:
    .github/errors/registry.md
    .github/prompts/error-learning.prompt.md
EOF
}

# Função principal
main() {
    local command="${1:-help}"
    
    # Verifica dependências
    if ! check_dependencies; then
        exit 1
    fi
    
    case "$command" in
        init)
            initialize_system
            ;;
        capture)
            run_capture
            ;;
        analyze)
            run_analysis
            ;;
        prevent)
            run_prevention
            ;;
        status)
            show_status
            ;;
        cleanup)
            run_cleanup
            ;;
        deep-clean)
            aggressive_image_cleanup
            ;;
        full)
            initialize_system && run_full_workflow
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            log_error "Comando não reconhecido: $command"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

# Execução
if [[ "${BASH_SOURCE[0]:-$0}" == "${0:-}" ]]; then
    main "$@"
fi
