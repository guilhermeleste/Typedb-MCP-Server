#!/bin/bash
# Sistema de Detecção e Aprovação de Grandes Mudanças
# Analisa automaticamente PRs e determina quando aprovação é necessária

set -euo pipefail

# Configurações
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
readonly APPROVAL_CONFIG="${PROJECT_ROOT}/.github/approval-rules.json"
readonly CHANGE_ANALYSIS_DIR="${PROJECT_ROOT}/.github/errors/change-analysis"

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

# Configuração padrão de regras de aprovação
setup_approval_rules() {
    log "Configurando regras de aprovação..."
    
    mkdir -p "$(dirname "$APPROVAL_CONFIG")"
    mkdir -p "$CHANGE_ANALYSIS_DIR"
    
    cat > "$APPROVAL_CONFIG" << 'EOF'
{
  "rules": {
    "file_count_threshold": 10,
    "lines_changed_threshold": 500,
    "critical_files": [
      "src/main.rs",
      "src/lib.rs",
      "src/config.rs",
      "src/auth.rs",
      "src/db.rs",
      "Cargo.toml",
      "Dockerfile",
      "docker-compose.yml",
      "docker-compose.test.yml"
    ],
    "protected_directories": [
      "src/tools/",
      ".github/workflows/",
      "scripts/",
      "certs/"
    ],
    "structural_changes": [
      "new_dependency",
      "api_change",
      "schema_change",
      "security_change",
      "config_change"
    ],
    "approval_requirements": {
      "small_change": {
        "reviewers_required": 1,
        "auto_merge_allowed": true
      },
      "medium_change": {
        "reviewers_required": 2,
        "auto_merge_allowed": false
      },
      "large_change": {
        "reviewers_required": 2,
        "senior_approval_required": true,
        "auto_merge_allowed": false,
        "additional_checks": ["security_review", "performance_review"]
      },
      "critical_change": {
        "reviewers_required": 3,
        "senior_approval_required": true,
        "security_review_required": true,
        "auto_merge_allowed": false,
        "deployment_freeze": true
      }
    }
  }
}
EOF

    success "Regras de aprovação configuradas em $APPROVAL_CONFIG"
}

# Análise de mudanças em um PR
analyze_pr_changes() {
    local base_branch="${1:-main}"
    local head_branch="${2:-HEAD}"
    
    log "Analisando mudanças entre $base_branch e $head_branch"
    
    # Conta arquivos modificados
    local files_changed=$(git diff --name-only "$base_branch"..."$head_branch" | wc -l)
    
    # Conta linhas modificadas
    local lines_changed=$(git diff --stat "$base_branch"..."$head_branch" | tail -1 | grep -o '[0-9]* insertions\|[0-9]* deletions' | grep -o '[0-9]*' | awk '{sum+=$1} END {print sum+0}')
    
    # Verifica arquivos críticos tocados
    local critical_files_touched=()
    while IFS= read -r file; do
        if is_critical_file "$file"; then
            critical_files_touched+=("$file")
        fi
    done < <(git diff --name-only "$base_branch"..."$head_branch")
    
    # Verifica diretórios protegidos
    local protected_dirs_touched=()
    while IFS= read -r file; do
        if is_protected_directory "$file"; then
            protected_dirs_touched+=("$(dirname "$file")")
        fi
    done < <(git diff --name-only "$base_branch"..."$head_branch")
    
    # Detecta mudanças estruturais
    local structural_changes=()
    structural_changes+=($(detect_dependency_changes "$base_branch" "$head_branch"))
    structural_changes+=($(detect_api_changes "$base_branch" "$head_branch"))
    structural_changes+=($(detect_config_changes "$base_branch" "$head_branch"))
    
    # Calcula score de mudança
    local change_score=0
    change_score=$((change_score + files_changed))
    change_score=$((change_score + lines_changed / 10))
    change_score=$((change_score + ${#critical_files_touched[@]} * 50))
    change_score=$((change_score + ${#protected_dirs_touched[@]} * 30))
    change_score=$((change_score + ${#structural_changes[@]} * 100))
    
    # Determina categoria da mudança
    local change_category="small_change"
    if [[ $change_score -ge 1000 ]]; then
        change_category="critical_change"
    elif [[ $change_score -ge 500 ]]; then
        change_category="large_change"
    elif [[ $change_score -ge 200 ]]; then
        change_category="medium_change"
    fi
    
    # Gera relatório da análise
    local analysis_report="$CHANGE_ANALYSIS_DIR/analysis-$(date +%Y%m%d-%H%M%S).json"
    
    cat > "$analysis_report" << EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "base_branch": "$base_branch",
  "head_branch": "$head_branch",
  "metrics": {
    "files_changed": $files_changed,
    "lines_changed": $lines_changed,
    "change_score": $change_score,
    "change_category": "$change_category"
  },
  "critical_files_touched": $(printf '%s\n' "${critical_files_touched[@]}" | jq -R . | jq -s .),
  "protected_directories_touched": $(printf '%s\n' "${protected_dirs_touched[@]}" | sort -u | jq -R . | jq -s .),
  "structural_changes": $(printf '%s\n' "${structural_changes[@]}" | jq -R . | jq -s .),
  "approval_requirements": $(jq ".rules.approval_requirements.$change_category" "$APPROVAL_CONFIG")
}
EOF
    
    success "Análise concluída: $change_category (score: $change_score)"
    echo "$analysis_report"
}

# Verifica se um arquivo é crítico
is_critical_file() {
    local file="$1"
    jq -r '.rules.critical_files[]' "$APPROVAL_CONFIG" | grep -q "^$file$"
}

# Verifica se está em diretório protegido
is_protected_directory() {
    local file="$1"
    local file_dir="$(dirname "$file")/"
    
    while IFS= read -r protected_dir; do
        if [[ "$file_dir" == "$protected_dir"* ]]; then
            return 0
        fi
    done < <(jq -r '.rules.protected_directories[]' "$APPROVAL_CONFIG")
    
    return 1
}

# Detecta mudanças em dependências
detect_dependency_changes() {
    local base_branch="$1"
    local head_branch="$2"
    
    if git diff --name-only "$base_branch"..."$head_branch" | grep -q "Cargo.toml"; then
        if git diff "$base_branch"..."$head_branch" -- Cargo.toml | grep -q "^\+.*="; then
            echo "new_dependency"
        fi
    fi
}

# Detecta mudanças na API
detect_api_changes() {
    local base_branch="$1"
    local head_branch="$2"
    
    # Verifica mudanças em arquivos de API/MCP
    if git diff --name-only "$base_branch"..."$head_branch" | grep -q "src/.*handler\|src/.*service\|src/tools/"; then
        if git diff "$base_branch"..."$head_branch" | grep -q "^\+.*pub fn\|^\-.*pub fn"; then
            echo "api_change"
        fi
    fi
}

# Detecta mudanças de configuração
detect_config_changes() {
    local base_branch="$1"
    local head_branch="$2"
    
    if git diff --name-only "$base_branch"..."$head_branch" | grep -q "config\|\.toml\|\.yml\|\.yaml"; then
        echo "config_change"
    fi
}

# Gera workflow GitHub para aprovação
generate_approval_workflow() {
    log "Gerando workflow GitHub para aprovação automática..."
    
    local workflow_file="$PROJECT_ROOT/.github/workflows/large-changes-approval.yml"
    
    cat > "$workflow_file" << 'EOF'
name: Large Changes Approval

on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  analyze-changes:
    runs-on: ubuntu-latest
    outputs:
      change-category: ${{ steps.analysis.outputs.change-category }}
      approval-required: ${{ steps.analysis.outputs.approval-required }}
      
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      with:
        fetch-depth: 0
        
    - name: Analyze PR changes
      id: analysis
      run: |
        ./scripts/large-changes-detector.sh analyze-pr \
          "${{ github.event.pull_request.base.ref }}" \
          "${{ github.event.pull_request.head.sha }}" > analysis.json
        
        CHANGE_CATEGORY=$(jq -r '.metrics.change_category' analysis.json)
        REVIEWERS_REQUIRED=$(jq -r '.approval_requirements.reviewers_required' analysis.json)
        
        echo "change-category=$CHANGE_CATEGORY" >> $GITHUB_OUTPUT
        echo "approval-required=$([ $REVIEWERS_REQUIRED -gt 1 ] && echo true || echo false)" >> $GITHUB_OUTPUT
        
        # Comenta no PR com a análise
        cat > pr-comment.md << EOL
        ## 🔍 Análise de Mudanças Automática
        
        **Categoria:** \`$CHANGE_CATEGORY\`
        **Revisores necessários:** $REVIEWERS_REQUIRED
        
        ### Detalhes da Análise
        \`\`\`json
        $(cat analysis.json | jq .)
        \`\`\`
        EOL
        
        gh pr comment ${{ github.event.pull_request.number }} --body-file pr-comment.md
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  enforce-approval:
    needs: analyze-changes
    if: needs.analyze-changes.outputs.approval-required == 'true'
    runs-on: ubuntu-latest
    
    steps:
    - name: Check required approvals
      uses: actions/github-script@v7
      with:
        script: |
          const { data: reviews } = await github.rest.pulls.listReviews({
            owner: context.repo.owner,
            repo: context.repo.repo,
            pull_number: context.issue.number
          });
          
          const approvals = reviews.filter(review => review.state === 'APPROVED');
          const changeCategory = '${{ needs.analyze-changes.outputs.change-category }}';
          
          const requirements = {
            'medium_change': { reviewers: 2 },
            'large_change': { reviewers: 2, senior: true },
            'critical_change': { reviewers: 3, senior: true, security: true }
          };
          
          const required = requirements[changeCategory];
          if (!required) return;
          
          if (approvals.length < required.reviewers) {
            core.setFailed(`Mudança ${changeCategory} requer ${required.reviewers} aprovações. Atual: ${approvals.length}`);
          }
          
          if (required.senior) {
            const seniorApprovals = approvals.filter(approval => 
              ['senior', 'architect', 'lead'].some(role => 
                approval.user.login.toLowerCase().includes(role)
              )
            );
            
            if (seniorApprovals.length === 0) {
              core.setFailed('Mudança requer aprovação de desenvolvedor sênior');
            }
          }

  performance-impact:
    needs: analyze-changes
    if: needs.analyze-changes.outputs.change-category == 'large_change' || needs.analyze-changes.outputs.change-category == 'critical_change'
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Run performance impact analysis
      run: |
        ./scripts/docker-test-optimizer.sh analyze Dockerfile
        
        # Executa build de teste para medir impacto
        time ./scripts/docker-test-optimizer.sh build typedb-mcp-server-test
        
        # Registra métricas no error registry
        ./scripts/error-registry.sh log-metric \
          --type "performance_impact_test" \
          --context "large_change_pr" \
          --value "$(date +%s)"

  security-scan:
    needs: analyze-changes
    if: needs.analyze-changes.outputs.change-category == 'critical_change'
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Run security scan
      run: |
        # Cargo audit para dependências
        cargo audit
        
        # Clippy com warnings de segurança
        cargo clippy -- -W clippy::all -W clippy::security
        
        # Scan do Dockerfile
        if command -v hadolint >/dev/null; then
          hadolint Dockerfile
        fi
EOF

    success "Workflow de aprovação criado em $workflow_file"
}

# Gera arquivo CODEOWNERS
generate_codeowners() {
    log "Gerando arquivo CODEOWNERS..."
    
    local codeowners_file="$PROJECT_ROOT/.github/CODEOWNERS"
    
    cat > "$codeowners_file" << 'EOF'
# Arquivo CODEOWNERS - Define proprietários automáticos para revisão
# Veja: https://docs.github.com/articles/about-code-owners/

# Arquivos críticos requerem aprovação de leads
/src/main.rs @project-leads
/src/lib.rs @project-leads
/src/config.rs @project-leads @security-team
/src/auth.rs @security-team @project-leads

# Database e conectividade
/src/db.rs @database-team @project-leads
/src/tools/ @api-team @project-leads

# Infraestrutura e deploy
/Dockerfile @devops-team @project-leads
/docker-compose*.yml @devops-team
/.github/workflows/ @devops-team @project-leads

# Configuração e segurança
/certs/ @security-team @devops-team
/config*.toml @config-team @project-leads

# Scripts críticos
/scripts/ @devops-team @project-leads

# Documentação importante
/docs/security/ @security-team @project-leads
/docs/architecture.md @architecture-team @project-leads

# Sistema de erro registry
/.github/errors/ @project-leads
/src/error_registry.rs @project-leads

# Default: qualquer arquivo não especificado
* @project-leads
EOF

    success "CODEOWNERS criado em $codeowners_file"
}

# Template de PR
generate_pr_template() {
    log "Gerando template de Pull Request..."
    
    local pr_template_file="$PROJECT_ROOT/.github/pull_request_template.md"
    
    cat > "$pr_template_file" << 'EOF'
## 📋 Descrição da Mudança

<!-- Descreva claramente o que esta mudança faz e por que é necessária -->

## 🎯 Tipo de Mudança

- [ ] 🐛 Bug fix (mudança que corrige um problema)
- [ ] ✨ Nova feature (mudança que adiciona funcionalidade)
- [ ] 💥 Breaking change (mudança que pode quebrar compatibilidade)
- [ ] 🔧 Refatoração (mudança que não corrige bug nem adiciona feature)
- [ ] 📚 Documentação (apenas mudanças na documentação)
- [ ] 🏗️ Infraestrutura (mudanças em CI/CD, Docker, scripts)
- [ ] 🔒 Segurança (mudanças relacionadas à segurança)

## 🧪 Como foi testado?

<!-- Descreva os testes que você executou para verificar suas mudanças -->

- [ ] Testes unitários passando
- [ ] Testes de integração passando
- [ ] Testes manuais executados
- [ ] Performance testada

## 📊 Impacto da Mudança

### Arquivos Críticos Modificados
<!-- Liste arquivos críticos que foram modificados -->

### Performance
- [ ] Esta mudança pode impactar a performance
- [ ] Testes de performance foram executados
- [ ] Métricas de antes/depois foram coletadas

### Segurança
- [ ] Esta mudança afeta componentes de segurança
- [ ] Revisão de segurança foi realizada
- [ ] Cargo audit foi executado

### Configuração
- [ ] Esta mudança requer atualização de configuração
- [ ] Documentação de configuração foi atualizada
- [ ] Migrations/scripts de atualização foram criados

## ✅ Checklist

- [ ] Meu código segue as guidelines do projeto
- [ ] Realizei auto-revisão do meu código
- [ ] Comentei partes complexas do código
- [ ] Fiz mudanças correspondentes na documentação
- [ ] Minhas mudanças não geram novos warnings
- [ ] Adicionei testes que provam que minha correção/feature funciona
- [ ] Testes novos e existentes passam localmente
- [ ] Error registry foi atualizado se necessário

## 🔗 Issues Relacionadas

<!-- Use "Closes #123" ou "Fixes #123" para auto-fechar issues -->

## 📸 Screenshots (se aplicável)

<!-- Adicione screenshots para mudanças na UI -->

## 📝 Notas Adicionais

<!-- Qualquer informação adicional que os revisores devem saber -->

---

<!-- 
🤖 Esta análise será automaticamente executada:
- Detecção de tamanho da mudança
- Análise de arquivos críticos
- Determinação de requisitos de aprovação
- Verificações de performance e segurança
-->
EOF

    success "Template de PR criado em $pr_template_file"
}

# Relatório de aprovações
generate_approval_report() {
    log "Gerando relatório de aprovações..."
    
    if [[ ! -d "$CHANGE_ANALYSIS_DIR" ]]; then
        warn "Nenhuma análise de mudança encontrada"
        return 0
    fi
    
    echo -e "\n${BLUE}=== RELATÓRIO DE APROVAÇÕES ===${NC}"
    echo ""
    
    # Estatísticas gerais
    local total_analyses=$(find "$CHANGE_ANALYSIS_DIR" -name "analysis-*.json" | wc -l)
    
    echo "📊 Total de análises: $total_analyses"
    
    if [[ $total_analyses -eq 0 ]]; then
        echo "Nenhuma análise encontrada."
        return 0
    fi
    
    # Distribuição por categoria
    echo ""
    echo "📈 Distribuição por categoria:"
    
    for category in small_change medium_change large_change critical_change; do
        local count=$(find "$CHANGE_ANALYSIS_DIR" -name "analysis-*.json" -exec jq -r 'select(.metrics.change_category == "'$category'") | .metrics.change_category' {} \; | wc -l)
        echo "  $category: $count"
    done
    
    # Arquivos mais modificados
    echo ""
    echo "🔥 Arquivos críticos mais modificados:"
    find "$CHANGE_ANALYSIS_DIR" -name "analysis-*.json" -exec jq -r '.critical_files_touched[]?' {} \; | sort | uniq -c | sort -nr | head -5
    
    # Tendências temporais
    echo ""
    echo "📅 Atividade recente (últimos 7 dias):"
    local week_ago=$(date -d '7 days ago' +%Y%m%d)
    find "$CHANGE_ANALYSIS_DIR" -name "analysis-*.json" -newer <(date -d '7 days ago' +%Y%m%d) | wc -l | xargs echo "  Análises:"
}

# Menu principal
main() {
    case "${1:-help}" in
        "setup")
            setup_approval_rules
            generate_approval_workflow
            generate_codeowners
            generate_pr_template
            ;;
        "analyze-pr")
            analyze_pr_changes "${2:-main}" "${3:-HEAD}"
            ;;
        "analyze-current")
            # Analisa mudanças no working directory
            if [[ -n "$(git status --porcelain)" ]]; then
                git add -A
                git commit -m "temp commit for analysis" --allow-empty
                local temp_commit=$(git rev-parse HEAD)
                analyze_pr_changes "HEAD~1" "$temp_commit"
                git reset --soft HEAD~1
            else
                warn "Nenhuma mudança no working directory para analisar"
            fi
            ;;
        "report")
            generate_approval_report
            ;;
        "help"|*)
            echo "Large Changes Detector - Sistema de Aprovação de Grandes Mudanças"
            echo ""
            echo "Uso: $0 <comando> [argumentos]"
            echo ""
            echo "Comandos:"
            echo "  setup                           - Configura sistema de aprovação completo"
            echo "  analyze-pr <base> <head>        - Analisa mudanças entre branches"
            echo "  analyze-current                 - Analisa mudanças no working directory"
            echo "  report                          - Gera relatório de aprovações"
            echo ""
            echo "Arquivos criados:"
            echo "  .github/approval-rules.json     - Regras de aprovação"
            echo "  .github/workflows/              - Workflows de automação"
            echo "  .github/CODEOWNERS              - Proprietários de código"
            echo "  .github/pull_request_template.md - Template de PR"
            ;;
    esac
}

# Executa função principal
main "$@"
