#!/bin/bash
#
# run-mock-oauth2.sh
#
# Descrição:
#   Este script gerencia um contêiner Docker para executar um servidor Nginx
#   configurado para simular um provedor OAuth2/OIDC, servindo um arquivo JWKS estático.
#   É essencial para testes de integração e desenvolvimento local que dependem de
#   autenticação OAuth2.
#
# Funcionalidades:
#   - Determina dinamicamente o diretório raiz do projeto.
#   - Verifica pré-requisitos: Docker instalado e arquivo mock_jwks.json existente.
#   - Para e remove contêineres Nginx mock existentes para evitar conflitos.
#   - Inicia um novo contêiner Nginx:
#     - Mapeia a porta 8088 do host para a porta 80 do contêiner.
#     - Monta o arquivo mock_jwks.json local em /usr/share/nginx/html/.well-known/jwks.json no contêiner.
#     - Monta uma configuração Nginx personalizada (se fornecida) ou usa o padrão.
#     - Executa em modo destacado (detached).
#     - Remove o contêiner automaticamente ao parar (--rm).
#   - Captura o ID do contêiner e verifica se ele está em execução.
#   - Fornece instruções para parar o contêiner manualmente.
#
# Uso:
#   ./scripts/run-mock-oauth2.sh
#
#   Para parar o servidor mock manualmente:
#   docker stop <container_id>
#
# Variáveis de Ambiente (opcional):
#   MOCK_JWKS_PATH: Caminho para o arquivo mock_jwks.json (padrão: ${PROJECT_ROOT}/mock_jwks.json)
#   NGINX_CONF_PATH: Caminho para um arquivo de configuração Nginx personalizado (opcional)
#
# Autor: Guilherme de Oliveira
# Data: 2024-07-29 (última modificação)

# Configurações de segurança e robustez do script
# -e: Aborta imediatamente se um comando sair com status diferente de zero.
# -u: Trata variáveis não definidas como erro.
# -o pipefail: O status de saída de um pipeline é o do último comando que falhou,
#              ou zero se todos os comandos bem-sucedidos.
set -e -u -o pipefail

# --- Funções Auxiliares ---
log_info() {
    echo "[INFO] $(date +'%Y-%m-%dT%H:%M:%S%z'): $1"
}

log_error() {
    echo "[ERROR] $(date +'%Y-%m-%dT%H:%M:%S%z'): $1" >&2
}

# --- Determinação de Caminhos ---
# Obtém o diretório do script para construir caminhos relativos de forma segura
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." &>/dev/null && pwd)" # Assume que scripts está um nível abaixo da raiz

# --- Variáveis ---
CONTAINER_NAME="mock-oauth2-server"
MOCK_JWKS_FILENAME="mock_jwks.json"
MOCK_JWKS_PATH="${MOCK_JWKS_PATH:-${PROJECT_ROOT}/${MOCK_JWKS_FILENAME}}"
NGINX_IMAGE="nginx:alpine"
HOST_PORT="8088"
CONTAINER_PORT="80"

# Caminho para o arquivo de configuração Nginx personalizado (opcional)
# Se NGINX_CONF_PATH for fornecido e o arquivo existir, ele será usado.
# Caso contrário, o Nginx usará sua configuração padrão, que é suficiente para servir arquivos estáticos.
CUSTOM_NGINX_CONF_PATH="${NGINX_CONF_PATH:-}"

# --- Pré-requisitos ---
log_info "Verificando pré-requisitos..."

# 1. Docker
if ! command -v docker &> /dev/null; then
    log_error "Docker não encontrado. Por favor, instale o Docker."
    exit 1
fi
log_info "Docker encontrado."

# 2. Arquivo JWKS
if [ ! -f "${MOCK_JWKS_PATH}" ]; then
    log_error "Arquivo JWKS não encontrado em ${MOCK_JWKS_PATH}."
    log_error "Certifique-se de que o arquivo ${MOCK_JWKS_FILENAME} existe na raiz do projeto ou forneça MOCK_JWKS_PATH."
    exit 1
fi
log_info "Arquivo JWKS encontrado em ${MOCK_JWKS_PATH}."

# --- Limpeza de Contêineres Anteriores ---
log_info "Procurando e parando contêineres '${CONTAINER_NAME}' existentes..."
# Encontra contêineres com o nome especificado, incluindo os parados
EXISTING_CONTAINERS=$(docker ps -a -q --filter "name=${CONTAINER_NAME}")

if [ -n "${EXISTING_CONTAINERS}" ]; then
    log_info "Parando contêineres existentes: ${EXISTING_CONTAINERS}..."
    # shellcheck disable=SC2086 # EXISTING_CONTAINERS pode ter múltiplos IDs
    docker stop ${EXISTING_CONTAINERS} >/dev/null
    log_info "Removendo contêineres existentes (eles já devem ser removidos por --rm, mas como garantia)..."
    # shellcheck disable=SC2086
    docker rm ${EXISTING_CONTAINERS} >/dev/null
    log_info "Contêineres anteriores '${CONTAINER_NAME}' parados e removidos."
else
    log_info "Nenhum contêiner anterior '${CONTAINER_NAME}' encontrado."
fi

# --- Preparação dos Volumes e Configurações do Docker ---
DOCKER_RUN_OPTS=(
    -d # Modo destacado
    --rm # Remove o contêiner quando ele para
    --name "${CONTAINER_NAME}"
    -p "${HOST_PORT}:${CONTAINER_PORT}"
    # Monta o arquivo JWKS no local esperado pelo Nginx
    -v "${MOCK_JWKS_PATH}:/usr/share/nginx/html/.well-known/jwks.json:ro"
)

# Adiciona montagem de configuração Nginx personalizada, se fornecida
if [ -n "${CUSTOM_NGINX_CONF_PATH}" ] && [ -f "${CUSTOM_NGINX_CONF_PATH}" ]; then
    log_info "Usando configuração Nginx personalizada de: ${CUSTOM_NGINX_CONF_PATH}"
    DOCKER_RUN_OPTS+=("-v" "${CUSTOM_NGINX_CONF_PATH}:/etc/nginx/conf.d/default.conf:ro")
elif [ -n "${CUSTOM_NGINX_CONF_PATH}" ]; then
    log_warn "Arquivo de configuração Nginx personalizado especificado em NGINX_CONF_PATH (${CUSTOM_NGINX_CONF_PATH}) não encontrado. Usando configuração padrão do Nginx."
fi

# --- Execução do Contêiner ---
log_info "Iniciando o contêiner mock OAuth2 (Nginx)..."
log_info "Comando Docker: docker run ${DOCKER_RUN_OPTS[*]} ${NGINX_IMAGE}"

# Captura o ID do contêiner diretamente do stdout
# shellcheck disable=SC2046 # Expansão de array é intencional aqui
CONTAINER_ID=$(docker run "${DOCKER_RUN_OPTS[@]}" "${NGINX_IMAGE}")

if [ -z "${CONTAINER_ID}" ]; then
    log_error "Falha ao iniciar o contêiner Docker. Nenhum ID de contêiner retornado."
    exit 1
fi

log_info "Contêiner '${CONTAINER_NAME}' iniciado com ID: ${CONTAINER_ID}"

# --- Verificação ---
# Pequena pausa para dar tempo ao contêiner de iniciar completamente
sleep 3

if docker ps -q --filter "id=${CONTAINER_ID}" --filter "status=running" | grep -q .; then
    log_info "Contêiner '${CONTAINER_NAME}' (ID: ${CONTAINER_ID}) está em execução."
    log_info "Servidor mock OAuth2 (Nginx) escutando em http://localhost:${HOST_PORT}/.well-known/jwks.json"
    log_info "Para parar o servidor, execute: docker stop ${CONTAINER_ID}"
    log_info "Ou simplesmente pare este script (se não estiver em segundo plano), pois --rm foi usado."
else
    log_error "Contêiner '${CONTAINER_NAME}' (ID: ${CONTAINER_ID}) não parece estar em execução."
    log_error "Verifique os logs do Docker para mais detalhes: docker logs ${CONTAINER_ID}"
    # Tenta limpar o contêiner se ele falhou em iniciar corretamente mas ainda existe
    if docker ps -a -q --filter "id=${CONTAINER_ID}" | grep -q .; then
        docker rm "${CONTAINER_ID}" >/dev/null
    fi
    exit 1
fi

# O script pode terminar aqui, o contêiner continuará rodando em segundo plano.
# O usuário precisará pará-lo manualmente ou o --rm cuidará disso quando o contêiner for parado.
# Se o script for interrompido (Ctrl+C), o contêiner também será parado e removido devido ao --rm
# e à forma como o Docker lida com sinais quando o processo principal que o iniciou termina.
# Para garantir a limpeza em caso de saída abrupta do script, um trap poderia ser adicionado,
# mas o --rm já oferece uma boa garantia.

# Exemplo de trap (opcional, pois --rm já está em uso):
# cleanup() {
#     log_info "Parando e removendo o contêiner ${CONTAINER_ID}..."
#     docker stop "${CONTAINER_ID}" >/dev/null
#     # docker rm é desnecessário por causa do --rm
#     log_info "Limpeza concluída."
# }
# trap cleanup EXIT SIGINT SIGTERM

log_info "Script concluído. O servidor mock continua em execução em segundo plano."
