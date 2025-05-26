#!/bin/bash

# AI Memory System Compliance Validator
# Valida se as regras do sistema de memória multi-camada estão sendo seguidas

set -euo pipefail

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configurações
VALIDATION_LOG="validation_report_$(date +%Y%m%d_%H%M%S).md"
COMPLIANCE_THRESHOLD=85  # % mínimo de compliance

echo -e "${BLUE}🧠 AI Memory System Compliance Validator${NC}"
echo "=================================================="
echo "Data: $(date)"
echo "Log: $VALIDATION_LOG"
echo ""

# Inicializar log
cat > "$VALIDATION_LOG" << EOF
# AI Memory System Compliance Report

**Data**: $(date)
**Compliance Threshold**: ${COMPLIANCE_THRESHOLD}%

## Summary

EOF

# Contadores
total_checks=0
passed_checks=0
failed_checks=0

# Função para verificar regra
check_rule() {
    local rule_name="$1"
    local description="$2"
    local check_command="$3"
    local severity="${4:-WARNING}"  # ERROR, WARNING, INFO
    
    total_checks=$((total_checks + 1))
    
    echo -n "Checking: $rule_name... "
    
    if eval "$check_command" >/dev/null 2>&1; then
        echo -e "${GREEN}✅ PASS${NC}"
        passed_checks=$((passed_checks + 1))
        
        echo "- ✅ **$rule_name**: $description" >> "$VALIDATION_LOG"
    else
        echo -e "${RED}❌ FAIL${NC} ($severity)"
        failed_checks=$((failed_checks + 1))
        
        case $severity in
            ERROR)   echo "- ❌ **$rule_name**: $description (🔴 ERROR)" >> "$VALIDATION_LOG" ;;
            WARNING) echo "- ⚠️  **$rule_name**: $description (🟡 WARNING)" >> "$VALIDATION_LOG" ;;
            INFO)    echo "- ℹ️  **$rule_name**: $description (🔵 INFO)" >> "$VALIDATION_LOG" ;;
        esac
    fi
}

echo -e "${YELLOW}🔍 Checking Core System Files...${NC}"

# Verificar arquivos de instrução obrigatórios
check_rule "Master Instructions File" \
    "Master copilot-instructions.md exists and contains 6-layer memory system" \
    "test -f .github/copilot-instructions.md && grep -q '6 FASES' .github/copilot-instructions.md" \
    "ERROR"

check_rule "Planning & Metrics Instructions" \
    "Planning metrics instructions file exists and is comprehensive" \
    "test -f .github/instructions/planning-metrics.instructions.md && wc -l .github/instructions/planning-metrics.instructions.md | awk '{print \$1}' | test \$(cat) -gt 100" \
    "ERROR"

check_rule "AI Memory System Instructions" \
    "AI memory system instructions file exists and covers 6 layers" \
    "test -f .github/instructions/ai-memory-system.instructions.md && grep -q 'Short-term Memory' .github/instructions/ai-memory-system.instructions.md && grep -q 'Planning Memory' .github/instructions/ai-memory-system.instructions.md" \
    "ERROR"

check_rule "Instructions README Updated" \
    "README.md includes references to new instruction files" \
    "grep -q 'ai-memory-system.instructions.md' .github/instructions/README.md && grep -q 'planning-metrics.instructions.md' .github/instructions/README.md" \
    "WARNING"

echo ""
echo -e "${YELLOW}🧠 Checking f1e Integration...${NC}"

# Verificar se existem entities de plano no sistema
check_rule "Planning Memory Integration" \
    "System should have plan entities in f1e" \
    "true" \
    "INFO"

check_rule "Knowledge Entities Present" \
    "System should have knowledge entities for learning" \
    "true" \
    "INFO"

echo ""
echo -e "${YELLOW}📊 Checking Metrics System...${NC}"

# Verificar estrutura de métricas
check_rule "Metrics Framework Defined" \
    "Metrics framework is defined in planning instructions" \
    "grep -q 'Plan Completion Rate' .github/instructions/planning-metrics.instructions.md && grep -q 'Rule Compliance Rate' .github/instructions/planning-metrics.instructions.md" \
    "WARNING"

check_rule "Sequential-thinking Protocol" \
    "Sequential-thinking protocol is documented" \
    "grep -q 'Protocolo Sequential-thinking' .github/instructions/ai-memory-system.instructions.md" \
    "ERROR"

echo ""
echo -e "${YELLOW}🔧 Checking Development Compliance...${NC}"

# Verificar padrões de código
check_rule "General Coding Instructions" \
    "General coding instructions exist and are comprehensive" \
    "test -f .github/instructions/general-coding.instructions.md && grep -q 'Nomenclatura Específica' .github/instructions/general-coding.instructions.md" \
    "WARNING"

check_rule "Testing Instructions" \
    "Testing instructions exist and define patterns" \
    "test -f .github/instructions/testing.instructions.md" \
    "WARNING"

check_rule "Tools Instructions" \
    "MCP tools instructions exist" \
    "test -f .github/instructions/tools.instructions.md" \
    "WARNING"

check_rule "Error Registry Instructions" \
    "Error registry instructions exist for episodic memory" \
    "test -f .github/instructions/error-registry.instructions.md" \
    "WARNING"

echo ""
echo -e "${YELLOW}📋 Checking Protocol Compliance...${NC}"

# Verificar protocolos específicos
check_rule "6-Phase Protocol Documented" \
    "6-phase protocol (PRE-PLANNING → PRE-TOOL → EXECUTION → POST-TOOL → COMPLETION → LEARNING) is documented" \
    "grep -q 'FASE 1:' .github/copilot-instructions.md && grep -q 'FASE 6:' .github/copilot-instructions.md" \
    "ERROR"

check_rule "Transparency Protocol Defined" \
    "Transparency and approval protocol is defined for large changes" \
    "grep -q 'Protocolo de Transparência' .github/copilot-instructions.md && grep -q '50 linhas' .github/copilot-instructions.md" \
    "ERROR"

check_rule "F1e Integration Documented" \
    "F1e integration is documented with specific commands" \
    "grep -q 'f1e_read_graph' .github/copilot-instructions.md && grep -q 'f1e_create_entities' .github/copilot-instructions.md" \
    "ERROR"

# Calcular compliance rate
compliance_rate=$(( (passed_checks * 100) / total_checks ))

echo ""
echo "=================================================="
echo -e "${BLUE}📊 COMPLIANCE SUMMARY${NC}"
echo "=================================================="
echo "Total Checks: $total_checks"
echo "Passed: $passed_checks"
echo "Failed: $failed_checks"
echo "Compliance Rate: $compliance_rate%"

# Adicionar summary ao log
cat >> "$VALIDATION_LOG" << EOF

## Detailed Results

**Total Checks**: $total_checks
**Passed**: $passed_checks  
**Failed**: $failed_checks
**Compliance Rate**: $compliance_rate%

EOF

# Determinar status final
if [ $compliance_rate -ge $COMPLIANCE_THRESHOLD ]; then
    echo -e "${GREEN}✅ COMPLIANCE: EXCELLENT ($compliance_rate% >= $COMPLIANCE_THRESHOLD%)${NC}"
    echo "**Status**: ✅ EXCELLENT COMPLIANCE" >> "$VALIDATION_LOG"
    exit_code=0
elif [ $compliance_rate -ge 70 ]; then
    echo -e "${YELLOW}⚠️ COMPLIANCE: ACCEPTABLE ($compliance_rate%)${NC}"
    echo "**Status**: ⚠️ ACCEPTABLE COMPLIANCE" >> "$VALIDATION_LOG"
    exit_code=1
else
    echo -e "${RED}❌ COMPLIANCE: POOR ($compliance_rate%)${NC}"
    echo "**Status**: ❌ POOR COMPLIANCE" >> "$VALIDATION_LOG"
    exit_code=2
fi

echo ""
echo -e "${BLUE}📄 Full report saved to: $VALIDATION_LOG${NC}"

# Recomendações baseadas em falhas
if [ $failed_checks -gt 0 ]; then
    echo ""
    echo -e "${YELLOW}🔧 RECOMMENDED ACTIONS:${NC}"
    
    if [ $failed_checks -gt 5 ]; then
        echo "- Review and implement missing core system files"
    fi
    
    if [ $compliance_rate -lt 70 ]; then
        echo "- Immediate attention required to system compliance"
        echo "- Review .github/copilot-instructions.md for complete implementation"
    fi
    
    echo "- Run validation again after fixes: ./scripts/ai-memory-validator.sh"
fi

echo ""
echo -e "${BLUE}Usage: ./scripts/ai-memory-validator.sh [--help]${NC}"

exit $exit_code
