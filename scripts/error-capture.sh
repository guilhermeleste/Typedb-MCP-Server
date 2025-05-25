#!/bin/bash

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Colorr Capture Script - Typedb-MCP-Server
# Captura automática de erros de compilação, testes e runtime

set -euo pipefail

# Configurações
ERROR_DIR=".github/errors"
REGISTRY_FILE="$ERROR_DIR/registry.md"
PATTERNS_DIR="$ERROR_DIR/patterns"
SOLUTIONS_DIR="$ERROR_DIR/solutions"

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YIGHLLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Funções auxiliares
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

# Gera ID único para o erro
generate_error_id() {
    local category=$1
    local date=$(date +%Y%m%d)
    local time=$(date +%H%M%S)
    echo "${category}-${date}-${time}"
}

# Determina categoria do erro baseado no contexto
determine_category() {
    local error_text="$1"
    local file_path="$2"
    
    if echo "$error_text" | grep -qi "borrow\|lifetime\|cannot move\|use of moved"; then
        echo "Compilation"
    elif echo "$error_text" | grep -qi "typedb\|database\|connection\|transaction"; then
        echo "TypeDB"
    elif echo "$error_text" | grep -qi "mcp\|json-rpc\|protocol"; then
        echo "MCP"
    elif echo "$error_text" | grep -qi "auth\|oauth\|token\|certificate"; then
        echo "Authentication"
    elif echo "$error_text" | grep -qi "config\|toml\|setting"; then
        echo "Configuration"
    elif echo "$file_path" | grep -qi "test"; then
        echo "Testing"
    else
        echo "General"
    fi
}

# Determina severidade baseado no tipo de erro
determine_severity() {
    local error_text="$1"
    
    if echo "$error_text" | grep -qi "panic\|fatal\|critical\|abort"; then
        echo "Critical"
    elif echo "$error_text" | grep -qi "error\|failed\|cannot\|denied"; then
        echo "High"
    elif echo "$error_text" | grep -qi "warning\|deprecated\|unused"; then
        echo "Medium"
    else
        echo "Low"
    fi
}

# Captura contexto técnico atual
capture_technical_context() {
    local context_file="$1"
    
    cat > "$context_file" << EOF
cargo_version: "$(cargo --version | cut -d' ' -f2)"
rust_version: "$(rustc --version | cut -d' ' -f2)"
typedb_version: "unknown"
environment: "development"
git_commit: "$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
EOF
}

# Cria arquivo de erro no formato YAML
create_error_file() {
    local error_id="$1"
    local category="$2"
    local severity="$3"
    local component="$4"
    local description="$5"
    local error_message="$6"
    local line_number="$7"
    
    local error_file="$ERROR_DIR/${error_id}.yml"
    local context_file=$(mktemp)
    
    capture_technical_context "$context_file"
    local context=$(cat "$context_file")
    rm -f "$context_file"
    
    mkdir -p "$ERROR_DIR"
    
    cat > "$error_file" << EOF
id: "$error_id"
timestamp: "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
category: $category
severity: "$severity"
component: "$component"
line: $line_number
description: "$description"
context:
  $context
error_message: "$error_message"
reproduction_steps:
  - "Execute comando que causou o erro"
  - "Verificar output detalhado"
analysis:
  root_cause: "A ser analisado"
  contributing_factors: []
solution: null
prevention: null
related_errors: []
recurrence_count: 1
resolved: false
resolved_at: null
resolved_by: null
EOF

    log_success "Erro registrado: $error_file"
    echo "$error_file"
}

# Captura erros de compilação do Cargo
capture_compilation_errors() {
    log_info "Capturando erros de compilação..."
    
    local output_file=$(mktemp)
    local error_count=0
    
    if ! cargo check 2> "$output_file"; then
        while IFS= read -r line; do
            if echo "$line" | grep -q "^error\|^warning"; then
                # Extrai informações do erro
                local error_message="$line"
                local file_component="unknown"
                local line_number=0
                
                # Tenta extrair arquivo e linha
                if echo "$line" | grep -q "-->"; then
                    local location=$(echo "$line" | grep -o "src/[^:]*:[0-9]*" | head -1)
                    if [ -n "$location" ]; then
                        file_component=$(echo "$location" | cut -d: -f1)
                        line_number=$(echo "$location" | cut -d: -f2)
                    fi
                fi
                
                local category=$(determine_category "$error_message" "$file_component")
                local severity=$(determine_severity "$error_message")
                local error_id=$(generate_error_id "$category")
                
                # Cria descrição limpa
                local description=$(echo "$error_message" | sed 's/^error\[E[0-9]*\]: *//' | sed 's/^warning: *//')
                
                create_error_file "$error_id" "$category" "$severity" "$file_component" \
                    "$description" "$error_message" "$line_number"
                
                ((error_count++))
            fi
        done < "$output_file"
        
        log_warning "Capturados $error_count erros de compilação"
    else
        log_success "Nenhum erro de compilação encontrado"
    fi
    
    rm -f "$output_file"
    return $error_count
}

# Captura erros de testes
capture_test_errors() {
    log_info "Capturando erros de testes..."
    
    local output_file=$(mktemp)
    local error_count=0
    
    if ! cargo test 2> "$output_file"; then
        local current_test=""
        local test_error=""
        
        while IFS= read -r line; do
            # Identifica início de falha de teste
            if echo "$line" | grep -q "^test.*FAILED$"; then
                current_test=$(echo "$line" | sed 's/test \(.*\) \.\.\. FAILED/\1/')
            elif echo "$line" | grep -q "^failures:$"; then
                # Processa erros de teste acumulados
                break
            elif [ -n "$current_test" ] && echo "$line" | grep -q "thread.*panicked"; then
                test_error="$line"
                
                local category="Testing"
                local severity="High"
                local component="tests/$current_test"
                local error_id=$(generate_error_id "$category")
                local description="Test failure: $current_test"
                
                create_error_file "$error_id" "$category" "$severity" "$component" \
                    "$description" "$test_error" "0"
                
                ((error_count++))
                current_test=""
                test_error=""
            fi
        done < "$output_file"
        
        log_warning "Capturados $error_count erros de teste"
    else
        log_success "Todos os testes passaram"
    fi
    
    rm -f "$output_file"
    return $error_count
}

# Captura erros de runtime de logs
capture_runtime_errors() {
    log_info "Capturando erros de runtime..."
    
    local log_files=("*.log" "logs/*.log" "/tmp/typedb-mcp-server.log")
    local error_count=0
    
    for pattern in "${log_files[@]}"; do
        if ls $pattern 1> /dev/null 2>&1; then
            for log_file in $pattern; do
                if [ -f "$log_file" ]; then
                    # Procura por linhas de erro nos logs
                    while IFS= read -r line; do
                        if echo "$line" | grep -qi "ERROR\|FATAL\|PANIC"; then
                            local error_message="$line"
                            local category=$(determine_category "$error_message" "$log_file")
                            local severity=$(determine_severity "$error_message")
                            local error_id=$(generate_error_id "$category")
                            local description="Runtime error from logs"
                            
                            create_error_file "$error_id" "$category" "$severity" "runtime" \
                                "$description" "$error_message" "0"
                            
                            ((error_count++))
                        fi
                    done < <(tail -n 100 "$log_file")
                fi
            done
        fi
    done
    
    if [ $error_count -eq 0 ]; then
        log_success "Nenhum erro de runtime encontrado nos logs"
    else
        log_warning "Capturados $error_count erros de runtime"
    fi
    
    return $error_count
}

# Verifica erros similares existentes
check_for_similar_errors() {
    local new_error_file="$1"
    local new_description=$(grep "^description:" "$new_error_file" | sed 's/description: *//' | tr -d '"')
    local new_category=$(grep "^category:" "$new_error_file" | sed 's/category: *//')
    local new_component=$(grep "^component:" "$new_error_file" | sed 's/component: *//' | tr -d '"')
    
    # Busca erros similares
    for existing_error in "$ERROR_DIR"/*.yml; do
        if [ -f "$existing_error" ] && [ "$existing_error" != "$new_error_file" ]; then
            local existing_description=$(grep "^description:" "$existing_error" | sed 's/description: *//' | tr -d '"')
            local existing_category=$(grep "^category:" "$existing_error" | sed 's/category: *//')
            local existing_component=$(grep "^component:" "$existing_error" | sed 's/component: *//' | tr -d '"')
            
            # Verifica similaridade (categoria + componente + palavras-chave na descrição)
            if [ "$new_category" = "$existing_category" ] && [ "$new_component" = "$existing_component" ]; then
                # Calcula similaridade simples baseada em palavras comuns
                local common_words=$(echo "$new_description $existing_description" | tr ' ' '\n' | sort | uniq -d | wc -l)
                if [ "$common_words" -gt 2 ]; then
                    log_warning "Erro similar detectado: $(basename "$existing_error" .yml)"
                    
                    # Incrementa contador de recorrência
                    local current_count=$(grep "^recurrence_count:" "$existing_error" | sed 's/recurrence_count: *//' || echo "1")
                    local new_count=$((current_count + 1))
                    
                    # Atualiza arquivo existente
                    sed -i "s/^recurrence_count: .*/recurrence_count: $new_count/" "$existing_error"
                    
                    # Remove arquivo duplicado
                    rm -f "$new_error_file"
                    
                    log_info "Contador de recorrência atualizado para $new_count"
                    return 0
                fi
            fi
        fi
    done
    
    return 1
}

# Atualiza dashboard de registry
update_registry_dashboard() {
    local total_errors=$(find "$ERROR_DIR" -name "*.yml" | wc -l)
    local recent_errors=$(find "$ERROR_DIR" -name "*.yml" -mtime -1 | wc -l)
    
    # Conta por categoria
    local comp_errors=$(find "$ERROR_DIR" -name "*.yml" -exec grep -l "category: Compilation" {} \; | wc -l)
    local typedb_errors=$(find "$ERROR_DIR" -name "*.yml" -exec grep -l "category: TypeDB" {} \; | wc -l)
    local mcp_errors=$(find "$ERROR_DIR" -name "*.yml" -exec grep -l "category: MCP" {} \; | wc -l)
    local test_errors=$(find "$ERROR_DIR" -name "*.yml" -exec grep -l "category: Testing" {} \; | wc -l)
    
    # Atualiza seção de métricas no registry
    if [ -f "$REGISTRY_FILE" ]; then
        local temp_file=$(mktemp)
        local update_metrics=false
        
        while IFS= read -r line; do
            if echo "$line" | grep -q "## Métricas Atuais"; then
                update_metrics=true
                echo "$line" >> "$temp_file"
                echo "" >> "$temp_file"
                echo "- **Total de Erros:** $total_errors" >> "$temp_file"
                echo "- **Erros Recentes (24h):** $recent_errors" >> "$temp_file"
                echo "- **Por Categoria:**" >> "$temp_file"
                echo "  - Compilation: $comp_errors" >> "$temp_file"
                echo "  - TypeDB: $typedb_errors" >> "$temp_file"
                echo "  - MCP: $mcp_errors" >> "$temp_file"
                echo "  - Testing: $test_errors" >> "$temp_file"
                echo "- **Última Atualização:** $(date)" >> "$temp_file"
                
                # Pula linhas até próxima seção
                while IFS= read -r line && ! echo "$line" | grep -q "^##"; do
                    continue
                done
                echo "$line" >> "$temp_file"
                update_metrics=false
            else
                echo "$line" >> "$temp_file"
            fi
        done < "$REGISTRY_FILE"
        
        mv "$temp_file" "$REGISTRY_FILE"
        log_success "Dashboard atualizado"
    fi
}

# Função principal
main() {
    log_info "Iniciando captura automática de erros..."
    
    local total_captured=0
    
    # Captura diferentes tipos de erro
    capture_compilation_errors
    total_captured=$((total_captured + $?))
    
    capture_test_errors
    total_captured=$((total_captured + $?))
    
    capture_runtime_errors
    total_captured=$((total_captured + $?))
    
    # Verifica por duplicatas e atualiza recorrências
    log_info "Verificando erros duplicados..."
    local processed=0
    for error_file in "$ERROR_DIR"/*.yml; do
        if [ -f "$error_file" ] && [[ $(basename "$error_file") =~ ^[A-Z]+-[0-9]+-[0-9]+\.yml$ ]]; then
            if check_for_similar_errors "$error_file"; then
                ((processed++))
            fi
        fi
    done
    
    if [ $processed -gt 0 ]; then
        log_info "Processados $processed erros duplicados"
    fi
    
    # Atualiza dashboard
    update_registry_dashboard
    
    # Trigger análise automática se houver novos erros
    if [ $total_captured -gt 0 ]; then
        log_info "Novos erros capturados ($total_captured). Triggering análise..."
        if [ -x "$(command -v ./scripts/error-analysis.sh)" ]; then
            ./scripts/error-analysis.sh
        fi
    fi
    
    log_success "Captura concluída. Total de erros no sistema: $(find "$ERROR_DIR" -name "*.yml" | wc -l)"
}

# Execução
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi
