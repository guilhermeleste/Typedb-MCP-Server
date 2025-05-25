#!/bin/bash

# ------------------------------------------------------------------------------
# Script: generate-test-certs.sh
#
# Descrição:
#   Este script automatiza a geração de certificados TLS autoassinados
#   ESPECIFICAMENTE PARA O AMBIENTE DE TESTE do Typedb-MCP-Server,
#   utilizando a ferramenta 'mkcert'.
#   Ele cria certificados para:
#     1. O Typedb-MCP-Server (mcp-server.crt, mcp-server.key)
#     2. Uma instância de teste do TypeDB Server (typedb-server.crt, typedb-server.key)
#     3. A Autoridade Certificadora (CA) raiz local (rootCA.pem) que assinou ambos.
#
#   Os certificados gerados são confiáveis localmente após a execução de
#   `mkcert -install` (que deve ser feita uma vez manualmente pelo desenvolvedor),
#   instalando a CA raiz local do mkcert nos repositórios de confiança do sistema.
#
# Autor: IA (baseado em generate-dev-certs.sh)
# Data: 21/05/2025
# Versão: 1.0
#
# Pré-requisitos:
#   - mkcert: A ferramenta para gerar os certificados. O script verifica sua
#             existência e instrui sobre a instalação se não for encontrado.
#             (https://mkcert.dev/#installation)
#   - Permissões de administrador (sudo): Necessárias para `mkcert -install`
#     na primeira vez que é executado. Este script NÃO executa `mkcert -install`.
#   - Comandos básicos: `cd`, `dirname`, `pwd`, `mkdir`, `rm`, `cp`, `ls`, `read`, `command`, `chmod`.
#
# Uso:
#   ./scripts/generate-test-certs.sh [opções]
#
# Opções:
#   --clean                  Remove o diretório de certificados de teste
#                            ($OUTPUT_DIR) e sai.
#   --mcp-hosts "<hosts>"    Lista de hosts/IPs separados por espaço para o
#                            certificado do Typedb-MCP-Server.
#                            Padrão: "localhost 127.0.0.1 typedb-mcp-server-it mcp.test.local"
#                            (typedb-mcp-server-it é o nome do serviço no Docker para acesso interno)
#   --typedb-hosts "<hosts>" Lista de hosts/IPs separados por espaço para o
#                            certificado do servidor TypeDB de teste.
#                            Padrão: "localhost 127.0.0.1 typedb-server-it typedb-server-tls-it typedb.test.local"
#                            (typedb-server-it e typedb-server-tls-it são nomes de serviço Docker)
#   --force                  Recria os certificados mesmo que já existam, sem perguntar.
#   --help                   Mostra esta mensagem de ajuda e sai.
#
# Exemplo de Uso:
#   ./scripts/generate-test-certs.sh
#   ./scripts/generate-test-certs.sh --force
#   ./scripts/generate-test-certs.sh --clean
#
# Estrutura de Saída:
#   Os certificados e chaves privadas são salvos em:
#   <diretorio_raiz_do_projeto>/tests/test_certs/
#
#   Arquivos Gerados:
#   - mcp-server.crt: Certificado público para o Typedb-MCP-Server.
#   - mcp-server.key: Chave privada para o Typedb-MCP-Server. (Permissões 600)
#   - typedb-server.crt: Certificado público para o servidor TypeDB de teste.
#   - typedb-server.key: Chave privada para o servidor TypeDB de teste. (Permissões 600)
#   - rootCA.pem: O certificado da CA raiz local do mkcert.
#
# Importante:
#   - Estes certificados são ESTRITAMENTE para uso em TESTES AUTOMATIZADOS E DESENVOLVIMENTO LOCAL.
#     NÃO os utilize em produção.
#   - Se `mkcert -install` não foi executado, os certificados não serão confiáveis
#     automaticamente pelo sistema/navegador.
# ------------------------------------------------------------------------------

# Configurações de segurança e robustez do script
# -e: Aborta imediatamente se um comando sair com status diferente de zero.
# -u: Trata variáveis não definidas como erro (exceto onde explicitamente permitido com ${VAR:-}).
# -o pipefail: O status de saída de um pipeline é o do último comando que falhou.
set -e -u -o pipefail

# --- Variáveis e Constantes ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
PROJECT_ROOT_DIR="$(cd "${SCRIPT_DIR}/.." &>/dev/null && pwd)"
OUTPUT_DIR="${PROJECT_ROOT_DIR}/tests/test_certs" # Diretório de saída fixo para testes

# Nomes de host/IP padrão para os certificados de teste
# Inclui nomes de serviço Docker para validação interna na rede Docker,
# e localhost/127.0.0.1 para acesso do host.
DEFAULT_MCP_SERVER_HOSTS="localhost 127.0.0.1 typedb-mcp-server-it mcp.test.local"
DEFAULT_TYPEDB_SERVER_HOSTS="localhost 127.0.0.1 typedb-server-it typedb-server-tls-it typedb.test.local"

# Nomes dos arquivos de certificado e chave
MCP_CERT_FILE="mcp-server.crt"
MCP_KEY_FILE="mcp-server.key"
TYPEDB_CERT_FILE="typedb-server.crt"
TYPEDB_KEY_FILE="typedb-server.key"
MKCERT_CA_ROOT_FILE="rootCA.pem" # Nome para a cópia da CA raiz do mkcert

# Flags de controle
CLEAN_MODE=false
FORCE_MODE=false
MCP_SERVER_HOSTS="${DEFAULT_MCP_SERVER_HOSTS}"
TYPEDB_SERVER_HOSTS="${DEFAULT_TYPEDB_SERVER_HOSTS}"

# --- Funções Auxiliares ---

# Função: log_info
# Descrição: Exibe uma mensagem informativa.
log_info() {
    echo "[INFO] $(date +'%Y-%m-%dT%H:%M:%S%z'): $1"
}

# Função: log_error
# Descrição: Exibe uma mensagem de erro e sai.
log_error() {
    echo "[ERROR] $(date +'%Y-%m-%dT%H:%M:%S%z'): $1" >&2
    exit 1
}

# Função: print_usage
# Descrição: Mostra a mensagem de ajuda do script e sai.
print_usage() {
  echo "Uso: $0 [opções]"
  echo
  echo "Gera certificados de teste autoassinados usando mkcert para o Typedb-MCP-Server."
  echo "Os certificados são salvos em: ${OUTPUT_DIR}"
  echo
  echo "Opções:"
  echo "  --clean                  Remove o diretório ${OUTPUT_DIR} e sai."
  echo "  --mcp-hosts \"<hosts>\"    Hosts/IPs para o certificado do Typedb-MCP-Server."
  echo "                           Padrão: \"${DEFAULT_MCP_SERVER_HOSTS}\""
  echo "  --typedb-hosts \"<hosts>\" Hosts/IPs para o certificado do servidor TypeDB de teste."
  echo "                           Padrão: \"${DEFAULT_TYPEDB_SERVER_HOSTS}\""
  echo "  --force                  Recria os certificados sem perguntar, mesmo se existirem."
  echo "  --help                   Mostra esta mensagem de ajuda e sai."
  echo
  exit 0
}

# Função: validate_hosts
# Descrição: Validação simples de nomes de host/IP.
validate_hosts() {
  local hosts_string="$1"
  local host_type_msg="$2"
  if [ -z "$hosts_string" ]; then
    log_error "A lista de hosts para ${host_type_msg} não pode estar vazia."
  fi
  # Permite nomes DNS (incluindo subdomínios e localhost), endereços IPv4 e IPv6 (sem validação de formato estrita)
  # A validação principal é feita pelo mkcert.
  for host in $hosts_string; do
    if [[ "$host" =~ [[:space:]] ]]; then
      log_error "Nome de host inválido para ${host_type_msg}: '${host}' contém espaços em '${hosts_string}'"
    fi
  done
  return 0
}

# --- Processamento de Argumentos da Linha de Comando ---
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --clean) CLEAN_MODE=true; shift ;;
        --mcp-hosts)
            if [[ -z "$2" || "$2" == --* ]]; then log_error "--mcp-hosts requer um argumento."; fi
            MCP_SERVER_HOSTS="$2";
            validate_hosts "$MCP_SERVER_HOSTS" "Typedb-MCP-Server"
            shift; shift ;;
        --typedb-hosts)
            if [[ -z "$2" || "$2" == --* ]]; then log_error "--typedb-hosts requer um argumento."; fi
            TYPEDB_SERVER_HOSTS="$2";
            validate_hosts "$TYPEDB_SERVER_HOSTS" "TypeDB Server de Teste"
            shift; shift ;;
        --force) FORCE_MODE=true; shift ;;
        --help) print_usage ;;
        *) log_error "Opção desconhecida: $1. Use --help para ver as opções." ;;
    esac
done

# --- Lógica Principal do Script ---
log_info "-------------------------------------------------------------------"
log_info "Gerador de Certificados de TESTE para Typedb-MCP-Server"
log_info "-------------------------------------------------------------------"
log_info "Diretório de Saída: ${OUTPUT_DIR}"

# Modo de Limpeza
if [ "$CLEAN_MODE" = true ]; then
  if [ -d "$OUTPUT_DIR" ]; then
    if [ "$FORCE_MODE" = false ]; then
        read -r -p "Tem certeza que deseja remover o diretório ${OUTPUT_DIR} e todos os seus certificados? (s/N): " confirmation
        if [[ "$confirmation" != "s" && "$confirmation" != "S" ]]; then
            log_info "Limpeza cancelada pelo usuário."
            exit 0
        fi
    fi
    log_info "Removendo diretório de certificados: ${OUTPUT_DIR}"
    rm -rf "$OUTPUT_DIR"
    log_info "Limpeza concluída."
  else
    log_info "Diretório de certificados ${OUTPUT_DIR} não encontrado. Nada para limpar."
  fi
  exit 0
fi

# 1. Verificação de Dependências (mkcert)
log_info "Verificando a presença da ferramenta 'mkcert'..."
if ! command -v mkcert &> /dev/null; then
    log_error "mkcert não encontrado. Por favor, instale mkcert (https://mkcert.dev/#installation) e execute 'mkcert -install'."
fi
log_info "mkcert encontrado: $(command -v mkcert)"

# 2. Verificação da CA local do mkcert
# É importante que `mkcert -install` tenha sido executado pelo menos uma vez.
MKCERT_CAROOT_PATH=$(mkcert -CAROOT 2>/dev/null || true) # Captura CAROOT, ignora erro se mkcert -install não foi rodado
if [ -z "$MKCERT_CAROOT_PATH" ] || [ ! -d "$MKCERT_CAROOT_PATH" ] || [ ! -f "$MKCERT_CAROOT_PATH/$MKCERT_CA_ROOT_FILE" ]; then
    log_info "----------------------------------------------------------------------------------------------------"
    log_info "AVISO: A CA raiz local do mkcert parece não estar instalada ou acessível."
    log_info "         Os certificados gerados podem não ser confiáveis pelo seu sistema/navegador."
    log_info "         Para instalar a CA raiz local, execute o seguinte comando UMA VEZ (pode pedir senha sudo):"
    log_info "           mkcert -install"
    log_info "         Após a instalação, este script poderá copiar o rootCA.pem para ${OUTPUT_DIR}."
    log_info "----------------------------------------------------------------------------------------------------"
    # Não sai com erro aqui, permite gerar os certs mesmo assim, mas eles não serão confiáveis.
fi

# 3. Criação do Diretório de Saída
if [ ! -d "$OUTPUT_DIR" ]; then
    log_info "Criando diretório de saída em: ${OUTPUT_DIR}"
    mkdir -p "$OUTPUT_DIR"
else
    log_info "Diretório de saída já existe: ${OUTPUT_DIR}"
    if [ "$FORCE_MODE" = false ]; then
        # Verifica se arquivos de certificado já existem e pergunta antes de sobrescrever
        if [ -f "${OUTPUT_DIR}/${MCP_CERT_FILE}" ] || [ -f "${OUTPUT_DIR}/${TYPEDB_CERT_FILE}" ]; then
            read -r -p "Certificados existentes foram encontrados em ${OUTPUT_DIR}. Deseja sobrescrevê-los? (s/N): " confirmation
            if [[ "$confirmation" != "s" && "$confirmation" != "S" ]]; then
                log_info "Operação cancelada. Nenhum certificado foi alterado."
                exit 0
            fi
            log_info "Continuando com a recriação dos certificados..."
        fi
    fi
fi

# 4. Geração de Certificado e Chave para o Typedb-MCP-Server
log_info "Gerando certificado para Typedb-MCP-Server..."
log_info "  Hosts: ${MCP_SERVER_HOSTS}"
log_info "  Certificado: ${OUTPUT_DIR}/${MCP_CERT_FILE}"
log_info "  Chave Privada: ${OUTPUT_DIR}/${MCP_KEY_FILE}"
if mkcert -cert-file "${OUTPUT_DIR}/${MCP_CERT_FILE}" -key-file "${OUTPUT_DIR}/${MCP_KEY_FILE}" ${MCP_SERVER_HOSTS}; then
    chmod 600 "${OUTPUT_DIR}/${MCP_KEY_FILE}"
    log_info "Certificado do Typedb-MCP-Server gerado com sucesso."
else
    log_error "Falha ao gerar certificado para Typedb-MCP-Server."
fi

# 5. Geração de Certificado e Chave para o Servidor TypeDB de Teste
log_info "Gerando certificado para o servidor TypeDB de teste..."
log_info "  Hosts: ${TYPEDB_SERVER_HOSTS}"
log_info "  Certificado: ${OUTPUT_DIR}/${TYPEDB_CERT_FILE}"
log_info "  Chave Privada: ${OUTPUT_DIR}/${TYPEDB_KEY_FILE}"
if mkcert -cert-file "${OUTPUT_DIR}/${TYPEDB_CERT_FILE}" -key-file "${OUTPUT_DIR}/${TYPEDB_KEY_FILE}" ${TYPEDB_SERVER_HOSTS}; then
    chmod 600 "${OUTPUT_DIR}/${TYPEDB_KEY_FILE}"
    log_info "Certificado do servidor TypeDB de teste gerado com sucesso."
else
    log_error "Falha ao gerar certificado para o servidor TypeDB de teste."
fi

# 6. Copiar o certificado da CA raiz do mkcert para o diretório de saída
if [ -n "$MKCERT_CAROOT_PATH" ] && [ -f "$MKCERT_CAROOT_PATH/$MKCERT_CA_ROOT_FILE" ]; then
    log_info "Copiando a CA raiz do mkcert (${MKCERT_CAROOT_PATH}/${MKCERT_CA_ROOT_FILE}) para ${OUTPUT_DIR}/${MKCERT_CA_ROOT_FILE}"
    cp "$MKCERT_CAROOT_PATH/$MKCERT_CA_ROOT_FILE" "${OUTPUT_DIR}/${MKCERT_CA_ROOT_FILE}"
else
    log_info "AVISO: Não foi possível copiar o arquivo rootCA.pem do mkcert. Veja o aviso anterior sobre 'mkcert -install'."
fi

# 7. Verificação Final dos Arquivos Gerados
log_info "Verificando a existência dos arquivos gerados em ${OUTPUT_DIR}:"
FILES_TO_CHECK=(
    "${OUTPUT_DIR}/${MCP_CERT_FILE}"
    "${OUTPUT_DIR}/${MCP_KEY_FILE}"
    "${OUTPUT_DIR}/${TYPEDB_CERT_FILE}"
    "${OUTPUT_DIR}/${TYPEDB_KEY_FILE}"
)
# Adiciona rootCA.pem à verificação apenas se esperávamos copiá-lo
if [ -n "$MKCERT_CAROOT_PATH" ] && [ -f "$MKCERT_CAROOT_PATH/$MKCERT_CA_ROOT_FILE" ]; then
    FILES_TO_CHECK+=("${OUTPUT_DIR}/${MKCERT_CA_ROOT_FILE}")
fi

ALL_FILES_EXIST=true
for FILE_PATH in "${FILES_TO_CHECK[@]}"; do
    if [ -f "$FILE_PATH" ]; then
        log_info "  [OK] Arquivo encontrado: $FILE_PATH"
    else
        log_info "  [ERRO] Arquivo NÃO encontrado: $FILE_PATH" >&2
        ALL_FILES_EXIST=false
    fi
done

if [ "$ALL_FILES_EXIST" = false ]; then
    log_error "Um ou mais arquivos de certificado esperados não foram encontrados após a geração. Revise os logs."
fi

log_info "-------------------------------------------------------------------"
log_info "Certificados de TESTE gerados com sucesso em ${OUTPUT_DIR}!"
log_info "-------------------------------------------------------------------"
log_info "Lembre-se: Se você não executou 'mkcert -install' anteriormente,"
log_info "           os certificados podem não ser confiáveis pelo seu sistema."
log_info "           Execute 'mkcert -install' (pode requerer sudo) uma vez."
log_info "-------------------------------------------------------------------"

exit 0