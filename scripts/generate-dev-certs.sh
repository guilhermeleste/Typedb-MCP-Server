#!/bin/bash

# Define o diretório de saída para os certificados
# Usando um caminho relativo ao diretório do script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
OUTPUT_DIR="$SCRIPT_DIR/../certs/generated-dev"

# Valores padrão para nomes de host
DEFAULT_MCP_SERVER_HOSTS="localhost 127.0.0.1 typedb-mcp-server.local"
DEFAULT_TYPEDB_SERVER_HOSTS="typedb-server-it typedb.local localhost"

# Inicializa variáveis com valores padrão
MCP_SERVER_HOSTS="$DEFAULT_MCP_SERVER_HOSTS"
TYPEDB_SERVER_HOSTS="$DEFAULT_TYPEDB_SERVER_HOSTS"
CLEAN_MODE=false

# Nomes dos arquivos de certificado e chave (mantidos fixos por simplicidade)
MCP_CERT_FILE="mcp-server.crt"
MCP_KEY_FILE="mcp-server.key"
TYPEDB_CERT_FILE="typedb-server.crt"
TYPEDB_KEY_FILE="typedb-server.key"
MKCERT_CA_ROOT_FILE="rootCA.pem"

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

validate_hosts() {
  local hosts_string="$1"
  local host_type_msg="$2"
  if [ -z "$hosts_string" ]; then
    echo "ERRO: A lista de hosts para $host_type_msg não pode estar vazia." >&2
    return 1
  fi
  for host in $hosts_string; do
    # Validação simples: não pode conter espaços e não pode começar/terminar com ponto ou hífen.
    # Não pode ter pontos ou hífens consecutivos.
    # Permite apenas alfanuméricos, pontos e hífens.
    if [[ "$host" =~ [[:space:]] || \
          "$host" =~ ^[.-] || "$host" =~ [.-]$ || \
          "$host" =~ \.\. || "$host" =~ -- || "$host" =~ \.- || "$host" =~ -\. ||\
          ! "$host" =~ ^[a-zA-Z0-9.-]+$ ]]; then
      echo "ERRO: Nome de host inválido para $host_type_msg: '$host' em '$hosts_string'" >&2
      echo "        Hosts devem ser nomes DNS válidos (alfanuméricos, pontos, hífens)." >&2
      return 1
    fi
  done
  return 0
}

# Processamento de argumentos da linha de comando
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
if ! command -v mkcert &> /dev/null
then
    echo "ERRO: mkcert não encontrado."
    echo "Por favor, instale mkcert seguindo as instruções em: https://mkcert.dev/#installation"
    exit 1
fi
echo "[INFO] mkcert encontrado."
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
echo "        (Isso pode solicitar sua senha de administrador se for a primeira vez)"
if mkcert -install; then
    echo "[INFO] CA local do mkcert instalada/verificada com sucesso."
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
    exit 1
fi
echo

# 4. Geração de Certificado e Chave para o Typedb-MCP-Server
echo "[INFO] Gerando certificado para Typedb-MCP-Server..."
echo "        Hosts: $MCP_SERVER_HOSTS"
echo "        Certificado: $OUTPUT_DIR/$MCP_CERT_FILE"
echo "        Chave: $OUTPUT_DIR/$MCP_KEY_FILE"
if mkcert -cert-file "$OUTPUT_DIR/$MCP_CERT_FILE" -key-file "$OUTPUT_DIR/$MCP_KEY_FILE" $MCP_SERVER_HOSTS; then
    echo "[INFO] Certificado do Typedb-MCP-Server gerado com sucesso."
else
    echo "ERRO: Falha ao gerar certificado para Typedb-MCP-Server."
    exit 1
fi
echo

# 5. Geração de Certificado e Chave para o Servidor TypeDB
echo "[INFO] Gerando certificado para o servidor TypeDB (desenvolvimento)..."
echo "        Hosts: $TYPEDB_SERVER_HOSTS"
echo "        Certificado: $OUTPUT_DIR/$TYPEDB_CERT_FILE"
echo "        Chave: $OUTPUT_DIR/$TYPEDB_KEY_FILE"
if mkcert -cert-file "$OUTPUT_DIR/$TYPEDB_CERT_FILE" -key-file "$OUTPUT_DIR/$TYPEDB_KEY_FILE" $TYPEDB_SERVER_HOSTS; then
    echo "[INFO] Certificado do servidor TypeDB gerado com sucesso."
else
    echo "ERRO: Falha ao gerar certificado para o servidor TypeDB."
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
if [ -f "$MKCERT_CAROOT_PATH/rootCA.pem" ]; then
    echo "[INFO] Copiando o certificado da CA raiz do mkcert ($MKCERT_CAROOT_PATH/rootCA.pem) para $OUTPUT_DIR/$MKCERT_CA_ROOT_FILE"
    cp "$MKCERT_CAROOT_PATH/rootCA.pem" "$OUTPUT_DIR/$MKCERT_CA_ROOT_FILE"
else
    echo "[AVISO] Não foi possível encontrar o arquivo rootCA.pem do mkcert em $MKCERT_CAROOT_PATH."
    echo "         Se você precisar configurar explicitamente a CA para o cliente TypeDB, "
    echo "         você pode precisar localizar manualmente o arquivo rootCA.pem do mkcert."
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
echo "   MCP_SERVER_CERT_PATH="certs/generated-dev/$MCP_CERT_FILE""
echo "   MCP_SERVER_KEY_PATH="certs/generated-dev/$MCP_KEY_FILE""
echo
echo "   # Para a conexão do Typedb-MCP-Server com o TypeDB (cliente TLS)"
echo "   TYPEDB_TLS_ENABLED=true"
echo "   # O TypeDB Server (Docker) usaria: certs/generated-dev/$TYPEDB_CERT_FILE e certs/generated-dev/$TYPEDB_KEY_FILE"
echo "   # O Typedb-MCP-Server (cliente) precisa confiar na CA que assinou o certificado do TypeDB:"
echo "   TYPEDB_TLS_CA_PATH="certs/generated-dev/$MKCERT_CA_ROOT_FILE""
echo "   # Se o seu sistema já confia na CA do mkcert (após mkcert -install), TYPEDB_TLS_CA_PATH pode não ser estritamente necessário"
echo "   # para algumas aplicações cliente que usam o trust store do sistema. No entanto, para rustls, é comum especificar a CA."
echo
echo "2. Certifique-se de que os nomes de host usados nos certificados (ex: typedb-mcp-server.local, typedb.local)"
echo "   estão resolvendo para os IPs corretos no seu ambiente de desenvolvimento (ex: via /etc/hosts, se não for localhost)."
echo "   Exemplo para /etc/hosts (ajuste conforme os hosts que você especificou):"
echo "   127.0.0.1 typedb-mcp-server.local # Se estiver usando este host"
echo "   127.0.0.1 typedb.local            # Se estiver usando este host"
echo
echo "3. Configure seus containers Docker (se aplicável) para montar e usar esses certificados."
echo
echo "Lembre-se: Estes certificados são APENAS para desenvolvimento local."
echo "-------------------------------------------------------------------"

exit 0
