#!/bin/bash

# Error Analysis Script - Typedb-MCP-Server
# Analisa padrões de erro e gera insights para prevenção

set -euo pipefail

# Configurações
ERROR_DIR=".github/errors"
PATTERNS_DIR="$ERROR_DIR/patterns"
SOLUTIONS_DIR="$ERROR_DIR/solutions"
PREVENTION_DIR="$ERROR_DIR/prevention"

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Funções auxiliares
log_info() {
    echo -e "${BLUE}[ANALYSIS]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PATTERN]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[INSIGHT]${NC} $1"
}

log_error() {
    echo -e "${RED}[ALERT]${NC} $1"
}

log_action() {
    echo -e "${PURPLE}[ACTION]${NC} $1"
}

# Analisa frequência de categorias de erro
analyze_error_categories() {
    log_info "Analisando categorias de erro..."
    
    local temp_file=$(mktemp)
    
    # Extrai categorias de todos os arquivos de erro
    find "$ERROR_DIR" -name "*.yml" -exec grep "category:" {} \; | \
        sed 's/category: *//' | sort | uniq -c | sort -rn > "$temp_file"
    
    if [ -s "$temp_file" ]; then
        log_success "Padrões de categoria identificados:"
        while read -r count category; do
            log_warning "  $category: $count ocorrências"
            
            # Gera alerta para categorias com alta frequência
            if [ "$count" -gt 5 ]; then
                log_error "ALERTA: Categoria $category tem alta frequência ($count erros)"
                
                # Cria padrão específico
                create_category_pattern "$category" "$count"
            fi
        done < "$temp_file"
    else
        log_warning "Nenhum erro registrado encontrado"
    fi
    
    rm -f "$temp_file"
}

# Cria arquivo de padrão para categoria específica
create_category_pattern() {
    local category="$1"
    local count="$2"
    local pattern_file="$PATTERNS_DIR/${category,,}-pattern.md"
    
    mkdir -p "$PATTERNS_DIR"
    
    log_action "Criando padrão para categoria: $category"
    
    cat > "$pattern_file" << EOF
# Padrão de Erro: $category

**Frequência:** $count ocorrências  
**Identificado em:** $(date)  
**Status:** Ativo  

## Análise

Esta categoria apresenta padrão recorrente de erros que requer atenção.

## Erros Específicos

EOF

    # Adiciona lista de erros específicos
    find "$ERROR_DIR" -name "*.yml" -exec grep -l "category: $category" {} \; | while read -r error_file; do
        local error_id=$(basename "$error_file" .yml)
        local description=$(grep "description:" "$error_file" | sed 's/description: *//' | tr -d '"' || echo "N/A")
        local component=$(grep "component:" "$error_file" | sed 's/component: *//' | tr -d '"' || echo "N/A")
        local severity=$(grep "severity:" "$error_file" | sed 's/severity: *//' | tr -d '"' || echo "N/A")
        
        echo "- **$error_id** ($severity): $description" >> "$pattern_file"
        echo "  - Componente: $component" >> "$pattern_file"
        echo "" >> "$pattern_file"
    done

    # Adiciona recomendações específicas
    cat >> "$pattern_file" << EOF

## Recomendações de Prevenção

EOF

    case "$category" in
        "Compilation")
            cat >> "$pattern_file" << EOF
- Implementar clippy lints mais rigorosos
- Adicionar pre-commit hooks
- Revisar uso de unwrap() e expect()
- Documentar lifetime patterns complexos
EOF
            ;;
        "TypeDB")
            cat >> "$pattern_file" << EOF
- Implementar connection pooling
- Configurar timeouts adequados
- Adicionar retry logic com exponential backoff
- Monitorar health checks
EOF
            ;;
        "MCP")
            cat >> "$pattern_file" << EOF
- Validação rigorosa de parâmetros JSON-RPC
- Schema validation automática
- Testes de integração mais abrangentes
- Logging estruturado melhorado
EOF
            ;;
        "Authentication")
            cat >> "$pattern_file" << EOF
- Centralizar validação de tokens
- Implementar scope checking automático
- Melhorar certificate rotation
- Audit logging obrigatório
EOF
            ;;
        *)
            cat >> "$pattern_file" << EOF
- Análise de causa raiz necessária
- Implementar monitoramento específico
- Documentar casos de uso
- Considerar refatoração preventiva
EOF
            ;;
    esac

    log_success "Padrão criado: $pattern_file"
}

# Analisa recorrência de erros
analyze_recurrence() {
    log_info "Analisando recorrência de erros..."
    
    local high_recurrence=()
    local total_errors=0
    local recurring_errors=0
    
    find "$ERROR_DIR" -name "*.yml" | while read -r error_file; do
        local recurrence=$(grep "recurrence_count:" "$error_file" | sed 's/recurrence_count: *//' || echo "1")
        total_errors=$((total_errors + 1))
        
        if [ "$recurrence" -gt 1 ]; then
            recurring_errors=$((recurring_errors + 1))
            
            if [ "$recurrence" -gt 3 ]; then
                local error_id=$(basename "$error_file" .yml)
                local description=$(grep "description:" "$error_file" | sed 's/description: *//' | tr -d '"')
                log_error "CRÍTICO: $error_id recorreu $recurrence vezes - $description"
                
                # Cria solução urgente
                create_urgent_solution "$error_id" "$recurrence" "$description"
            fi
        fi
    done
    
    if [ $total_errors -gt 0 ] && [ $recurring_errors -gt 0 ]; then
        local recurrence_rate=$(echo "scale=1; $recurring_errors * 100 / $total_errors" | bc -l 2>/dev/null || echo "N/A")
        log_warning "Taxa de recorrência: $recurrence_rate% ($recurring_errors de $total_errors erros)"
    fi
}

# Cria solução urgente para erros críticos
create_urgent_solution() {
    local error_id="$1"
    local recurrence="$2"
    local description="$3"
    local solution_file="$SOLUTIONS_DIR/urgent-${error_id}.md"
    
    mkdir -p "$SOLUTIONS_DIR"
    
    log_action "Criando solução urgente para: $error_id"
    
    cat > "$solution_file" << EOF
# Solução Urgente: $error_id

**Prioridade:** CRÍTICA  
**Recorrência:** $recurrence vezes  
**Identificado em:** $(date)  

## Descrição do Problema

$description

## Status

⚠️ **REQUER AÇÃO IMEDIATA** - Este erro recorreu $recurrence vezes

## Análise de Impacto

- **Frequência:** Alta ($recurrence ocorrências)
- **Tendência:** Recorrente
- **Impacto:** Potencialmente crítico para estabilidade

## Próximos Passos

1. **Análise Imediata:** Investigar causa raiz
2. **Correção Temporária:** Implementar workaround se necessário
3. **Solução Definitiva:** Planejar refatoração preventiva
4. **Monitoramento:** Adicionar alertas específicos

## Medidas Preventivas Sugeridas

- [ ] Implementar validação adicional
- [ ] Adicionar testes específicos
- [ ] Melhorar error handling
- [ ] Documentar lições aprendidas

EOF

    log_success "Solução urgente criada: $solution_file"
}

# Analisa componentes mais afetados
analyze_components() {
    log_info "Analisando componentes mais afetados..."
    
    local temp_file=$(mktemp)
    
    find "$ERROR_DIR" -name "*.yml" -exec grep "component:" {} \; | \
        sed 's/component: *//' | sort | uniq -c | sort -rn > "$temp_file"
    
    if [ -s "$temp_file" ]; then
        log_success "Componentes mais afetados:"
        head -10 "$temp_file" | while read -r count component; do
            log_warning "  $component: $count erros"
            
            if [ "$count" -gt 3 ]; then
                log_error "ATENÇÃO: Componente $component precisa de revisão ($count erros)"
                create_component_review "$component" "$count"
            fi
        done
    fi
    
    rm -f "$temp_file"
}

# Cria revisão para componente problemático
create_component_review() {
    local component="$1"
    local count="$2"
    local review_file="$SOLUTIONS_DIR/component-review-$(echo "$component" | sed 's/[^a-zA-Z0-9]/-/g').md"
    
    mkdir -p "$SOLUTIONS_DIR"
    
    log_action "Criando revisão para componente: $component"
    
    cat > "$review_file" << EOF
# Revisão de Componente: $component

**Total de Erros:** $count  
**Avaliação:** Requer atenção  
**Data:** $(date)  

## Análise

Este componente apresenta alta concentração de erros ($count ocorrências).

## Erros Identificados

EOF

    # Lista erros específicos do componente
    find "$ERROR_DIR" -name "*.yml" -exec grep -l "component: $component" {} \; | while read -r error_file; do
        local error_id=$(basename "$error_file" .yml)
        local description=$(grep "description:" "$error_file" | sed 's/description: *//' | tr -d '"')
        local severity=$(grep "severity:" "$error_file" | sed 's/severity: *//' | tr -d '"')
        local timestamp=$(grep "timestamp:" "$error_file" | sed 's/timestamp: *//' | tr -d '"')
        
        echo "- **$error_id** [$severity] ($timestamp)" >> "$review_file"
        echo "  $description" >> "$review_file"
        echo "" >> "$review_file"
    done

    cat >> "$review_file" << EOF

## Recomendações

- [ ] Code review completo do componente
- [ ] Refatoração preventiva se necessário
- [ ] Adicionar testes unitários específicos
- [ ] Implementar monitoramento adicional
- [ ] Documentar arquitetura e decisões

## Próximos Passos

1. Agendar revisão técnica
2. Identificar padrões comuns
3. Implementar melhorias
4. Validar com testes

EOF

    log_success "Revisão de componente criada: $review_file"
}

# Gera regras de prevenção
generate_prevention_rules() {
    log_info "Gerando regras de prevenção..."
    
    local rules_file="$PREVENTION_DIR/auto-generated-rules.md"
    mkdir -p "$PREVENTION_DIR"
    
    cat > "$rules_file" << EOF
# Regras de Prevenção Automáticas

**Gerado em:** $(date)  
**Baseado em:** Análise de padrões de erro  

## Clippy Rules (clippy.toml)

EOF

    # Verifica padrões para gerar regras específicas
    if find "$ERROR_DIR" -name "*.yml" -exec grep -l "category: Compilation" {} \; | head -1 | grep -q .; then
        cat >> "$rules_file" << EOF
\`\`\`toml
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
todo = "warn"
unimplemented = "deny"
\`\`\`

EOF
    fi

    cat >> "$rules_file" << EOF
## Linting Rules

### Para erros de compilação:
- Proibir unwrap() em código de produção
- Require explicit error handling
- Enforce documentation para APIs públicas

### Para erros de TypeDB:
- Timeout obrigatório em todas as conexões
- Connection pooling required
- Retry logic mandatório

### Para erros de MCP:
- Parameter validation obrigatória
- Schema validation automática
- JSON-RPC error handling padronizado

## Pre-commit Hooks

\`\`\`yaml
repos:
  - repo: local
    hooks:
      - id: rust-check
        name: Rust Check
        entry: cargo check
        language: system
        files: \\.rs$
      - id: rust-clippy
        name: Rust Clippy
        entry: cargo clippy -- -D warnings
        language: system
        files: \\.rs$
      - id: rust-fmt
        name: Rust Format
        entry: cargo fmt --check
        language: system
        files: \\.rs$
\`\`\`

## CI/CD Rules

### Obrigatório em pipeline:
- [ ] cargo check
- [ ] cargo clippy
- [ ] cargo test
- [ ] cargo fmt --check
- [ ] Security audit
- [ ] Dependencies check

EOF

    log_success "Regras de prevenção geradas: $rules_file"
}

# Função principal
main() {
    log_info "Iniciando análise automática de padrões de erro..."
    
    # Verifica se diretório de erros existe
    if [ ! -d "$ERROR_DIR" ]; then
        log_warning "Diretório de erros não encontrado: $ERROR_DIR"
        log_info "Criando estrutura inicial..."
        mkdir -p "$ERROR_DIR" "$PATTERNS_DIR" "$SOLUTIONS_DIR" "$PREVENTION_DIR"
        log_success "Estrutura criada"
        return 0
    fi
    
    # Verifica se há erros para analisar
    if ! find "$ERROR_DIR" -name "*.yml" | head -1 | grep -q .; then
        log_warning "Nenhum erro encontrado para análise"
        return 0
    fi
    
    # Executa análises
    analyze_error_categories
    echo ""
    analyze_recurrence
    echo ""
    analyze_components
    echo ""
    generate_prevention_rules
    
    log_success "Análise concluída! Verifique os diretórios:"
    log_info "  Padrões: $PATTERNS_DIR"
    log_info "  Soluções: $SOLUTIONS_DIR"
    log_info "  Prevenção: $PREVENTION_DIR"
}

# Execução
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi
