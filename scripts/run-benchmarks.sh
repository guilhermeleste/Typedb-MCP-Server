#!/bin/bash
# Script helper para executar benchmarks do Typedb-MCP-Server
#
# Este script fornece comandos pré-configurados para diferentes tipos
# de execução de benchmarks usando criterion.

set -euo pipefail

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Função para mostrar ajuda
show_help() {
    echo -e "${BLUE}Typedb-MCP-Server Benchmark Runner${NC}"
    echo ""
    echo "Uso: $0 [COMANDO] [OPÇÕES]"
    echo ""
    echo "Comandos:"
    echo "  run         - Executa todos os benchmarks"
    echo "  baseline    - Salva baseline atual (para comparações futuras)"
    echo "  compare     - Compara com baseline salva"
    echo "  quick       - Execução rápida para validação" 
    echo "  internal    - Apenas benchmarks de componentes internos"
    echo "  report      - Abre relatório HTML no navegador"
    echo "  clean       - Limpa dados de benchmark anteriores"
    echo "  help        - Mostra esta ajuda"
    echo ""
    echo "Exemplos:"
    echo "  $0 run                    # Executa todos os benchmarks"
    echo "  $0 baseline initial       # Salva baseline como 'initial'"
    echo "  $0 compare initial        # Compara com baseline 'initial'"
    echo "  $0 quick                  # Teste rápido (3 segundos por benchmark)"
}

# Função para verificar se o projeto compila
check_compilation() {
    echo -e "${YELLOW}Verificando compilação...${NC}"
    if ! cargo check --benches --quiet; then
        echo -e "${RED}Erro: Projeto não compila. Corrija os erros primeiro.${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Compilação OK${NC}"
}

# Executa todos os benchmarks  
run_benchmarks() {
    echo -e "${BLUE}Executando todos os benchmarks...${NC}"
    echo -e "${YELLOW}Isso pode levar alguns minutos. Relatórios serão gerados em target/criterion/${NC}"
    cargo bench --bench performance_benchmarks
    echo -e "${GREEN}✓ Benchmarks concluídos!${NC}"
    echo -e "${BLUE}Relatórios HTML disponíveis em: target/criterion/report/index.html${NC}"
}

# Salva uma baseline para comparações futuras
save_baseline() {
    local baseline_name="${1:-current}"
    echo -e "${BLUE}Salvando baseline '${baseline_name}'...${NC}"
    cargo bench --bench performance_benchmarks -- --save-baseline "$baseline_name"
    echo -e "${GREEN}✓ Baseline '${baseline_name}' salva!${NC}"
}

# Compara com baseline existente
compare_baseline() {
    local baseline_name="${1:-current}"
    echo -e "${BLUE}Comparando com baseline '${baseline_name}'...${NC}"
    if [ ! -d "target/criterion" ]; then
        echo -e "${RED}Erro: Nenhum benchmark anterior encontrado. Execute 'run' primeiro.${NC}"
        exit 1
    fi
    cargo bench --bench performance_benchmarks -- --baseline "$baseline_name"
    echo -e "${GREEN}✓ Comparação concluída!${NC}"
}

# Execução rápida para validação
quick_test() {
    echo -e "${BLUE}Execução rápida de validação (3s por benchmark)...${NC}"
    cargo bench --bench performance_benchmarks -- --quick --measurement-time 3
    echo -e "${GREEN}✓ Teste rápido concluído!${NC}"
}

# Apenas benchmarks internos
internal_only() {
    echo -e "${BLUE}Executando apenas benchmarks de componentes internos...${NC}"
    cargo bench --bench performance_benchmarks bench_internal_components
    echo -e "${GREEN}✓ Benchmarks internos concluídos!${NC}"
}

# Abre relatório no navegador
open_report() {
    local report_path="target/criterion/report/index.html"
    if [ -f "$report_path" ]; then
        echo -e "${BLUE}Abrindo relatório de benchmarks...${NC}"
        if command -v xdg-open > /dev/null; then
            xdg-open "$report_path"
        elif command -v open > /dev/null; then
            open "$report_path"
        else
            echo -e "${YELLOW}Abra manualmente: $report_path${NC}"
        fi
    else
        echo -e "${RED}Erro: Relatório não encontrado. Execute benchmarks primeiro.${NC}"
        exit 1
    fi
}

# Limpa dados de benchmark
clean_benchmarks() {
    echo -e "${YELLOW}Limpando dados de benchmark anteriores...${NC}"
    if [ -d "target/criterion" ]; then
        rm -rf target/criterion
        echo -e "${GREEN}✓ Dados de benchmark limpos!${NC}"
    else
        echo -e "${BLUE}Nenhum dado de benchmark para limpar.${NC}"
    fi
}

# Processamento de comando principal
case "${1:-help}" in
    "run")
        check_compilation
        run_benchmarks
        ;;
    "baseline")
        check_compilation
        save_baseline "$2"
        ;;
    "compare")
        check_compilation
        compare_baseline "$2"
        ;;
    "quick")
        check_compilation
        quick_test
        ;;
    "internal")
        check_compilation
        internal_only
        ;;
    "report")
        open_report
        ;;
    "clean")
        clean_benchmarks
        ;;
    "help"|"--help"|"-h")
        show_help
        ;;
    *)
        echo -e "${RED}Comando desconhecido: $1${NC}"
        echo ""
        show_help
        exit 1
        ;;
esac
