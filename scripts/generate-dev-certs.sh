#!/bin/bash

# ------------------------------------------------------------------------------
# Script: generate-dev-certs.sh
#
# Descrição:
#   Este script automatiza a geração de certificados TLS autoassinados para
#   ambientes de desenvolvimento utilizando a ferramenta 'mkcert'.
#   Ele cria certificados para o Typedb-MCP-Server e para um servidor TypeDB
#   (usado em testes de integração ou desenvolvimento local).
#   Os certificados gerados são confiáveis localmente após a execução de
#   `mkcert -install`, que instala uma autoridade de certificação (CA) raiz local
#   nos repositórios de confiança do sistema e do navegador.
#
# Autor: [Seu Nome/Time] - Atualizado por IA
# Data: 19/05/2025
# Versão: 1.2 (Aprimoramentos de documentação e robustez)
#
# Pré-requisitos:
#   - mkcert: A ferramenta para gerar os certificados. O script verifica sua
#             existência e instrui sobre a instalação se não for encontrado.
#             (https://mkcert.dev/#installation)
#   - Permissões de administrador (sudo): Necessárias para `mkcert -install`
#     na primeira vez que é executado, para instalar a CA raiz local.
#   - Comandos básicos: `cd`, `dirname`, `pwd`, `mkdir`, `rm`, `cp`, `ls`, `read`, `command`.
#
# Uso:
#   ./generate-dev-certs.sh [opções]
#
# Opções:
#   --clean                  Remove o diretório de certificados gerados
#                            anteriormente ($OUTPUT_DIR) e sai.
#   --mcp-hosts "<hosts>"    Lista de hosts/IPs separados por espaço para o
#                            certificado do Typedb-MCP-Server.
#                            Ex: "localhost 127.0.0.1 mcp.dev"
#                            Padrão: "localhost 127.0.0.1 typedb-mcp-server.local"
#   --typedb-hosts "<hosts>" Lista de hosts/IPs separados por espaço para o
#                            certificado do servidor TypeDB.
#                            Ex: "localhost 127.0.0.1 typedb.dev"
#                            Padrão: "typedb-server-it typedb.local localhost"
#   --help                   Mostra esta mensagem de ajuda e sai.
#
# Exemplo de Uso:
#   ./generate-dev-certs.sh
#   ./generate-dev-certs.sh --mcp-hosts "localhost mymcp.dev" --typedb-hosts "localhost mytypedb.dev"
#   ./generate-dev-certs.sh --clean
#
# Estrutura de Saída:
#   Os certificados e chaves privadas são salvos em:
#   <diretorio_do_script>/../certs/generated-dev/
#
#   Arquivos Gerados:
#   - mcp-server.crt: Certificado público para o Typedb-MCP-Server.
#   - mcp-server.key: Chave privada para o Typedb-MCP-Server. (Permissões 600)
#   - typedb-server.crt: Certificado público para o servidor TypeDB.
#   - typedb-server.key: Chave privada para o servidor TypeDB. (Permissões 600)
#   - rootCA.pem: O certificado da CA raiz local do mkcert (copiado para conveniência).
#
# Importante:
#   - Estes certificados são ESTRITAMENTE para uso em DESENVOLVIMENTO LOCAL.
#     NÃO os utilize em produção.
#   - A chave da CA raiz (`rootCA-key.pem` no diretório CAROOT do mkcert)
#     é sensível. `mkcert` a gerencia; não a compartilhe.
# ------------------------------------------------------------------------------

# Define o diretório de saída para os certificados
# Usando um caminho relativo ao diretório do script para portabilidade
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
OUTPUT_DIR="$SCRIPT_DIR/../certs/generated-dev" # Diretório onde os certificados serão salvos

# Valores padrão para nomes de host/IP para os certificados
# Estes podem ser sobrescritos por argumentos de linha de comando.
DEFAULT_MCP_SERVER_HOSTS="localhost 127.0.0.1 typedb-mcp-server.local"
DEFAULT_TYPEDB_SERVER_HOSTS="typedb-server-it typedb.local localhost"

# Inicializa variáveis com valores padrão
MCP_SERVER_HOSTS="$DEFAULT_MCP_SERVER_HOSTS"
TYPEDB_SERVER_HOSTS="$DEFAULT_TYPEDB_SERVER_HOSTS"
CLEAN_MODE=false # Flag para ativar o modo de limpeza

# Nomes dos arquivos de certificado e chave (mantidos fixos por simplicidade)
# Estes nomes são usados para os arquivos gerados no OUTPUT_DIR.
MCP_CERT_FILE="mcp-server.crt"
MCP_KEY_FILE="mcp-server.key"
TYPEDB_CERT_FILE="typedb-server.crt"
TYPEDB_KEY_FILE="typedb-server.key"
MKCERT_CA_ROOT_FILE="rootCA.pem" # Nome do arquivo para a cópia da CA raiz do mkcert

# Função: print_usage
# Descrição: Mostra a mensagem de ajuda do script e sai.
print_usage() {
  echo "Uso: $0 [opções]"
  echo
  echo "Este script gera certificados de desenvolvimento autoassinados usando mkcert."
  echo
  echo "Opções:"
  echo "  --clean                  Remove o diretório de certificados gerados anteriormente ($OUTPUT_DIR) e sai."
  echo "  --mcp-hosts \"<hosts>\"    Lista de hosts separados por espaço para o certificado do Typedb-MCP-Server."
  echo "                           Padrão: \"$DEFAULT_MCP_SERVER_HOSTS\""
  echo "  --typedb-hosts \"<hosts>\" Lista de hosts separados por espaço para o certificado do servidor TypeDB."
  echo "                           Padrão: \"$DEFAULT_TYPEDB_SERVER_HOSTS\""
  echo "  --help                   Mostra esta mensagem de ajuda e sai."
  echo
  echo "Exemplo:"
  echo "  $0 --mcp-hosts \"localhost mymcp.dev\" --typedb-hosts \"localhost mytypedb.dev\""
  echo "  $0 --clean"
  exit 0
}

# Função: validate_hosts
# Descrição: Valida uma string de nomes de host.
# Argumentos:
#   $1: String contendo nomes de host separados por espaço.
#   $2: String descritiva do tipo de host (para mensagens de erro).
# Retorna: 0 se válido, 1 se inválido.
validate_hosts() {
  local hosts_string="$1"
  local host_type_msg="$2"
  if [ -z "$hosts_string" ]; then # Verifica se a string de hosts não está vazia
    echo "ERRO: A lista de hosts para $host_type_msg não pode estar vazia." >&2
    return 1
  fi
  for host in $hosts_string; do
    # Validação simples de nome de host/IP:
    # - Não pode conter espaços.
    # - Não pode começar ou terminar com ponto ou hífen.
    # - Não pode ter pontos ou hífens consecutivos.
    # - Permite apenas caracteres alfanuméricos, pontos e hífens (adequado para nomes DNS e IPs).
    if [[ "$host" =~ [[:space:]] || \
          "$host" =~ ^[.-] || "$host" =~ [.-]$ || \
          "$host" =~ \\.\\. || "$host" =~ -- || "$host" =~ \\.- || "$host" =~ -\\. || \
          ! "$host" =~ ^[a-zA-Z0-9.-]+$ ]]; then
      echo "ERRO: Nome de host inválido para $host_type_msg: '$host' em '$hosts_string'" >&2
      echo "        Hosts devem ser nomes DNS válidos ou endereços IP (alfanuméricos, pontos, hífens)." >&2
      return 1
    fi
  done
  return 0 # Todos os hosts na string são válidos
}

# --- Processamento de Argumentos da Linha de Comando ---
# Loop para ler todas as opções fornecidas ao script.
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --clean) CLEAN_MODE=true; shift ;;
        --mcp-hosts)
            if [[ -z "$2" || "$2" == --* ]]; then echo "ERRO: --mcp-hosts requer um argumento." >&2; print_usage; exit 1; fi
            MCP_SERVER_HOSTS="$2";
            if ! validate_hosts "$MCP_SERVER_HOSTS" "Typedb-MCP-Server"; then print_usage; exit 1; fi
            shift; shift ;;
        --typedb-hosts)
            if [[ -z "$2" || "$2" == --* ]]; then echo "ERRO: --typedb-hosts requer um argumento." >&2; print_usage; exit 1; fi
            TYPEDB_SERVER_HOSTS="$2";
            if ! validate_hosts "$TYPEDB_SERVER_HOSTS" "TypeDB Server"; then print_usage; exit 1; fi
            shift; shift ;;
        --help) print_usage ;;
        *) echo "Opção desconhecida: $1" >&2; print_usage; exit 1 ;;
    esac
done

# --- Início da Lógica Principal do Script ---
echo "-------------------------------------------------------------------"
echo "Gerador de Certificados de Desenvolvimento para Typedb-MCP-Server"
echo "-------------------------------------------------------------------"
echo

# Modo de Limpeza
if [ "$CLEAN_MODE" = true ]; then
  if [ -d "$OUTPUT_DIR" ]; then
    read -r -p "Tem certeza que deseja remover o diretório $OUTPUT_DIR e todos os seus certificados? (s/N): " confirmation
    if [[ "$confirmation" == "s" || "$confirmation" == "S" ]]; then
      echo "[INFO] Removendo diretório de certificados: $OUTPUT_DIR"
      rm -rf "$OUTPUT_DIR"
      echo "[INFO] Limpeza concluída."
    else
      echo "[INFO] Limpeza cancelada pelo usuário."
    fi
  else
    echo "[INFO] Diretório de certificados $OUTPUT_DIR não encontrado. Nada para limpar."
  fi
  exit 0
fi

# 1. Verificação de Dependências
echo "[INFO] Verificando a presença da ferramenta 'mkcert'..."
if ! command -v mkcert &> /dev/null
then
    echo "ERRO: mkcert não encontrado."
    echo "Por favor, instale mkcert seguindo as instruções em: https://mkcert.dev/#installation"
    echo "Em sistemas baseados em Debian/Ubuntu, após instalar as dependências (como libnss3-tools), você pode precisar:"
    echo "  wget -O mkcert https://github.com/FiloSottile/mkcert/releases/download/vX.Y.Z/mkcert-vX.Y.Z-linux-amd64"
    echo "  chmod +x mkcert"
    echo "  sudo mv mkcert /usr/local/bin/"
    exit 1
fi
echo "[INFO] mkcert encontrado: $(command -v mkcert)"
echo

# 2. Criação do Diretório de Saída
if [ ! -d "$OUTPUT_DIR" ]; then
    echo "[INFO] Criando diretório de saída em: $OUTPUT_DIR"
    mkdir -p "$OUTPUT_DIR"
else
    echo "[INFO] Diretório de saída já existe: $OUTPUT_DIR"
fi
echo

# 3. Instalação da CA Local do mkcert (se necessário)
# mkcert -install só precisa ser executado uma vez por máquina.
# Ele solicitará senha de administrador se a CA ainda não estiver instalada.
echo "[INFO] Garantindo que a CA local do mkcert está instalada..."
echo "        (Isso pode solicitar sua senha de administrador se for a primeira vez ou se a CA precisar ser atualizada)"
if mkcert -install; then
    echo "[INFO] CA local do mkcert instalada/verificada com sucesso."
    # Verifica se o diretório CAROOT do mkcert pode ser determinado e acessado.
    MKCERT_CAROOT_PATH=$(mkcert -CAROOT)
    if [ -z "$MKCERT_CAROOT_PATH" ] || [ ! -d "$MKCERT_CAROOT_PATH" ]; then
        echo "ERRO: Não foi possível determinar ou acessar o diretório CAROOT do mkcert após a instalação." >&2
        echo "        Caminho obtido: '$MKCERT_CAROOT_PATH'" >&2
        echo "        Por favor, verifique a instalação do mkcert e se 'mkcert -CAROOT' retorna um caminho válido." >&2
        exit 1
    fi
    echo "[INFO] Diretório CAROOT do mkcert verificado: $MKCERT_CAROOT_PATH"
else
    echo "ERRO: Falha ao instalar/verificar a CA local do mkcert." >&2
    echo "        Verifique as mensagens de erro do mkcert acima." >&2
    exit 1
fi
echo

# 4. Geração de Certificado e Chave para o Typedb-MCP-Server
echo "[INFO] Gerando certificado para Typedb-MCP-Server..."
echo "        Hosts: $MCP_SERVER_HOSTS"
echo "        Certificado: $OUTPUT_DIR/$MCP_CERT_FILE"
echo "        Chave privada será salva em: $OUTPUT_DIR/$MCP_KEY_FILE"
# Comando mkcert para gerar o par de chave/certificado
if mkcert -cert-file "$OUTPUT_DIR/$MCP_CERT_FILE" -key-file "$OUTPUT_DIR/$MCP_KEY_FILE" $MCP_SERVER_HOSTS; then
    echo "[INFO] Certificado do Typedb-MCP-Server gerado com sucesso."
    chmod 600 "$OUTPUT_DIR/$MCP_KEY_FILE" # Define permissões restritivas para a chave privada
else
    echo "ERRO: Falha ao gerar certificado para Typedb-MCP-Server." >&2
    exit 1
fi
echo

# 5. Geração de Certificado e Chave para o Servidor TypeDB
echo "[INFO] Gerando certificado para o servidor TypeDB (desenvolvimento)..."
echo "        Hosts: $TYPEDB_SERVER_HOSTS"
echo "        Certificado: $OUTPUT_DIR/$TYPEDB_CERT_FILE"
echo "        Chave privada será salva em: $OUTPUT_DIR/$TYPEDB_KEY_FILE"
# Comando mkcert para gerar o par de chave/certificado
if mkcert -cert-file "$OUTPUT_DIR/$TYPEDB_CERT_FILE" -key-file "$OUTPUT_DIR/$TYPEDB_KEY_FILE" $TYPEDB_SERVER_HOSTS; then
    echo "[INFO] Certificado do servidor TypeDB gerado com sucesso."
    chmod 600 "$OUTPUT_DIR/$TYPEDB_KEY_FILE" # Define permissões restritivas para a chave privada
else
    echo "ERRO: Falha ao gerar certificado para o servidor TypeDB." >&2
    exit 1
fi
echo

# 6. (Opcional) Copiar o certificado da CA raiz do mkcert para o diretório de saída
# O cliente (nosso Typedb-MCP-Server) precisará confiar na CA que assinou o certificado do TypeDB.
# mkcert instala sua CA raiz nos trust stores do sistema.
# Para cenários onde o trust store do sistema não é usado (ex: configuração explícita de CA em uma aplicação),
# pode ser útil ter o arquivo da CA raiz.
# O caminho para a CA raiz do mkcert pode ser encontrado com `mkcert -CAROOT`
# MKCERT_CAROOT_PATH já foi definido e validado acima
if [ -f "$MKCERT_CAROOT_PATH/$MKCERT_CA_ROOT_FILE" ]; then # Verifica se o arquivo da CA raiz existe
    echo "[INFO] Copiando o certificado da CA raiz do mkcert ($MKCERT_CAROOT_PATH/$MKCERT_CA_ROOT_FILE) para $OUTPUT_DIR/$MKCERT_CA_ROOT_FILE"
    cp "$MKCERT_CAROOT_PATH/$MKCERT_CA_ROOT_FILE" "$OUTPUT_DIR/$MKCERT_CA_ROOT_FILE"
else
    # Este cenário é improvável se `mkcert -install` e `mkcert -CAROOT` funcionaram.
    echo "[AVISO] Não foi possível encontrar o arquivo $MKCERT_CA_ROOT_FILE do mkcert em $MKCERT_CAROOT_PATH."
    echo "         Se você precisar configurar explicitamente a CA para o cliente TypeDB (Typedb-MCP-Server),"
    echo "         você pode precisar localizar manualmente o arquivo $MKCERT_CA_ROOT_FILE do mkcert."
    echo "         Normalmente, ele está em: $(mkcert -CAROOT)/$MKCERT_CA_ROOT_FILE"
fi
echo

# 7. Instruções de Saída
echo "-------------------------------------------------------------------"
echo "Certificados de Desenvolvimento Gerados com Sucesso!"
echo "-------------------------------------------------------------------"
echo
echo "Arquivos gerados em: $OUTPUT_DIR/"
ls -l "$OUTPUT_DIR/"
echo
echo "Próximos Passos:"
echo "1. Configure as seguintes variáveis de ambiente (ex: no seu .env ou config.toml):"
echo
echo "   # Para o Typedb-MCP-Server (servidor WSS)"
echo "   MCP_SERVER_TLS_ENABLED=true"
echo "   MCP_SERVER_CERT_PATH=\"certs/generated-dev/$MCP_CERT_FILE\"  # Relativo à raiz do projeto"
echo "   MCP_SERVER_KEY_PATH=\"certs/generated-dev/$MCP_KEY_FILE\"   # Relativo à raiz do projeto"
echo
echo "   # Para a conexão do Typedb-MCP-Server com um servidor TypeDB (quando atua como cliente TLS)"
echo "   TYPEDB_TLS_ENABLED=true"
echo "   # O servidor TypeDB (ex: em Docker) precisaria ser configurado para usar:"
echo "   #   - Certificado: certs/generated-dev/$TYPEDB_CERT_FILE"
echo "   #   - Chave: certs/generated-dev/$TYPEDB_KEY_FILE"
echo "   # O Typedb-MCP-Server (como cliente) precisa confiar na CA que assinou o certificado do TypeDB:"
echo "   TYPEDB_TLS_CA_PATH=\"certs/generated-dev/$MKCERT_CA_ROOT_FILE\" # Relativo à raiz do projeto"
echo "   # Nota: Se o seu sistema operacional já confia na CA do mkcert (devido ao 'mkcert -install'),"
echo "   # TYPEDB_TLS_CA_PATH pode não ser estritamente necessário para algumas aplicações cliente"
echo "   # que utilizam o repositório de confiança do sistema. No entanto, para bibliotecas como 'rustls',"
echo "   # é comum e mais robusto especificar explicitamente o arquivo da CA."
echo
echo "2. Certifique-se de que os nomes de host usados nos certificados (ex: typedb-mcp-server.local, typedb.local)"
echo "   estão resolvendo para os IPs corretos no seu ambiente de desenvolvimento (ex: via /etc/hosts, se não for localhost)."
echo "   Exemplo para /etc/hosts (ajuste conforme os hosts que você especificou):"
echo "     127.0.0.1 typedb-mcp-server.local # Adicione se usou este host"
echo "     127.0.0.1 typedb.local            # Adicione se usou este host"
echo
echo "3. Se estiver usando containers Docker, certifique-se de montar o diretório '$OUTPUT_DIR'"
echo "   (ou os arquivos de certificado/chave individuais) nos containers e configurar"
echo "   as aplicações dentro deles para usar os caminhos corretos dos certificados."
echo
echo "Lembre-se: Estes certificados são APENAS para desenvolvimento local e NÃO DEVEM ser usados em produção."
echo "-------------------------------------------------------------------"

exit 0 # Sucesso
