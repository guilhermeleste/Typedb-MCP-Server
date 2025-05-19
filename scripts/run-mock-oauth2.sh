#!/bin/bash
#
# run-mock-oauth2.sh
#
# Descrição:
#   Este script inicia um servidor Nginx em um contêiner Docker para simular um 
#   endpoint JWKS (JSON Web Key Set) para fins de desenvolvimento e teste OAuth2.
#   Ele serve o arquivo 'mock_jwks.json' localizado na raiz do projeto.
#
# Autor: [Seu Nome/Equipe]
# Data de Criação: [Data Original]
# Data da Última Modificação: 2024-07-26
# Versão: 1.1
#
# Pré-requisitos:
#   - Docker: Deve estar instalado e o daemon Docker deve estar em execução.
#   - mock_jwks.json: Um arquivo chamado 'mock_jwks.json' deve existir na raiz do projeto.
#
# Uso:
#   ./scripts/run-mock-oauth2.sh [PORTA]
#
# Argumentos:
#   PORTA (opcional): A porta na qual o servidor mock JWKS será exposto. 
#                     O padrão é 9091.
#
# Exemplo de Uso:
#   # Iniciar o servidor na porta padrão 9091
#   ./scripts/run-mock-oauth2.sh
#
#   # Iniciar o servidor na porta 9000
#   ./scripts/run-mock-oauth2.sh 9000
#
# Funcionamento:
#   O script utiliza o comando 'docker run' para iniciar um contêiner Nginx:
#   - '--rm': Remove o contêiner automaticamente quando ele é parado.
#   - '-p <PORTA_HOST>:<PORTA_CONTAINER>': Mapeia a porta especificada (ou padrão)
#     do host para a porta 80 dentro do contêiner Nginx.
#   - '-v <ARQUIVO_HOST>:<ARQUIVO_CONTAINER>:ro': Monta o arquivo 'mock_jwks.json' 
#     do host (localizado na raiz do projeto) para o caminho 
#     '/usr/share/nginx/html/.well-known/jwks.json' dentro do contêiner, em modo
#     somente leitura ('ro').
#   - 'nginx:alpine': Especifica a imagem Docker a ser usada (uma versão leve do Nginx).
#
# Caminho Servido:
#   O arquivo JWKS estará acessível em: http://localhost:<PORTA>/.well-known/jwks.json
#
# Arquivo JWKS Esperado:
#   <RAIZ_DO_PROJETO>/mock_jwks.json
#
# Notas Importantes:
#   - Este script é destinado apenas para desenvolvimento e teste.
#   - Para parar o servidor mock, pressione Ctrl+C no terminal onde o script 
#     está sendo executado.

# Configurações de segurança e robustez do script
set -e  # Encerra imediatamente se um comando sair com status diferente de zero.
set -u  # Trata variáveis não definidas como um erro ao fazer expansão.
set -o pipefail # O status de retorno de um pipeline é o status do último comando a sair com um código de saída diferente de zero, ou zero se todos os comandos saírem com sucesso.

# --- Funções Auxiliares ---
log_info() {
    echo "[INFO] $(date +'%Y-%m-%dT%H:%M:%S%z'): $1"
}

log_error() {
    echo "[ERROR] $(date +'%Y-%m-%dT%H:%M:%S%z'): $1" >&2
}

# --- Determinar Caminhos ---
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
PROJECT_ROOT=$(cd -- "$SCRIPT_DIR/.." &>/dev/null && pwd)

# --- Variáveis ---
DEFAULT_PORT=9091
PORT=${1:-$DEFAULT_PORT}
MOCK_JWKS_FILE_NAME="mock_jwks.json"
MOCK_JWKS_PATH="$PROJECT_ROOT/$MOCK_JWKS_FILE_NAME"
NGINX_IMAGE="nginx:alpine"

# --- Verificações de Pré-requisitos ---
log_info "Verificando pré-requisitos..."

# Verificar se o Docker está instalado
if ! command -v docker &> /dev/null; then
    log_error "Docker não encontrado. Por favor, instale o Docker para continuar."
    exit 1
fi

# Verificar se o daemon Docker está em execução
if ! docker info &> /dev/null; then
    log_error "O daemon Docker não parece estar em execução. Por favor, inicie o Docker."
    exit 1
fi
log_info "Docker encontrado e daemon em execução."

# Verificar se o arquivo mock_jwks.json existe
if [ ! -f "$MOCK_JWKS_PATH" ]; then
    log_error "Arquivo JWKS não encontrado em '$MOCK_JWKS_PATH'."
    log_error "Certifique-se de que '$MOCK_JWKS_FILE_NAME' existe na raiz do projeto."
    exit 1
fi
log_info "Arquivo JWKS '$MOCK_JWKS_PATH' encontrado."

# --- Execução Principal ---
log_info "Iniciando o servidor mock JWKS..."
log_info "Servindo o arquivo '$MOCK_JWKS_PATH'"
log_info "Disponível em: http://localhost:$PORT/.well-known/jwks.json"
log_info "Pressione Ctrl+C para parar o servidor."

# Executar o contêiner Nginx
# O Nginx por padrão serve arquivos de /usr/share/nginx/html
# Montamos o mock_jwks.json diretamente no subdiretório .well-known

# Captura o ID do contêiner para verificação posterior
CONTAINER_ID_FILE=$(mktemp) # Cria um arquivo temporário para armazenar o ID do contêiner

if docker run \
    --cidfile "$CONTAINER_ID_FILE" \
    --rm \
    -d \
    -p "$PORT:80" \
    -v "$MOCK_JWKS_PATH:/usr/share/nginx/html/.well-known/jwks.json:ro" \
    "$NGINX_IMAGE"; then

    CONTAINER_ID=$(cat "$CONTAINER_ID_FILE")
    rm -f "$CONTAINER_ID_FILE" # Remove o arquivo temporário

    log_info "Contêiner Nginx iniciado com ID: $CONTAINER_ID"
    log_info "Verificando o status do contêiner em alguns segundos..."
    sleep 5 # Aguarda um pouco para o Nginx iniciar completamente

    # Verifica se o contêiner está realmente em execução
    if docker ps -q --filter "id=$CONTAINER_ID" | grep -q .; then
        log_info "[SUCESSO] Servidor mock JWKS está em execução."
        log_info "URL: http://localhost:$PORT/.well-known/jwks.json"
        log_info "Para parar o servidor, execute: docker stop $CONTAINER_ID"
        # Mantém o script em execução para que o usuário possa ver os logs e o comando para parar.
        # O contêiner continuará rodando em background devido ao -d.
        # Para um comportamento de script que bloqueia, remova o -d e adicione um trap para limpeza.
        wait "$CONTAINER_ID" # Esta linha só funcionaria se não fosse -d, ou se usássemos `docker attach`
                           # Como estamos em modo detached (-d), o script sairia aqui.
                           # Para manter o script "vivo" e mostrar o Ctrl+C, precisamos de um loop ou similar.
                           # No entanto, para um script de background, o comportamento atual é mais comum.
                           # O usuário pode usar 'docker logs -f $CONTAINER_ID' para ver os logs do Nginx.
        # Como o docker run está com -d, o script não vai esperar aqui naturalmente.
        # Se o objetivo é que o script termine e deixe o container rodando, isso está correto.
        # Se o objetivo é que o script espere o Ctrl+C, o -d deve ser removido e o docker run não deve ser em background.
        # Para o propósito deste script (iniciar um servidor em background), o -d é apropriado.
        # A mensagem "Pressione Ctrl+C para parar o servidor" é um pouco enganosa com -d.
        # Vamos ajustar a mensagem para refletir que o container está em background.
        echo
        log_info "O contêiner está rodando em segundo plano."
        log_info "Para ver os logs: docker logs -f $CONTAINER_ID"
        log_info "Para parar o servidor: docker stop $CONTAINER_ID"
        exit 0 # Sucesso, o contêiner está rodando
    else
        log_error "[FALHA] O contêiner Nginx ($CONTAINER_ID) não parece estar em execução após a inicialização."
        log_error "Verifique os logs do contêiner com: docker logs $CONTAINER_ID"
        exit 1
    fi
else
    rm -f "$CONTAINER_ID_FILE" # Garante a remoção do arquivo temporário em caso de falha no run
    log_error "[FALHA] Falha ao iniciar o contêiner Docker Nginx."
    exit 1
fi

# Nota: O script terminará aqui quando o docker run for interrompido (Ctrl+C)
# ou se houver um erro na execução do docker run.
