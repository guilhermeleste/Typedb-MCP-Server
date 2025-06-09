#!/bin/sh
set -e

echo "Entrypoint: Iniciando Vault Agent para renderizar segredos..."

# Inicia o Vault Agent. Ele lerá a configuração, autenticará usando os segredos
# montados em /run/secrets/, renderizará os templates para /vault/secrets/, e sairá.
vault agent -config=/app/vault-agent-config.hcl

# Verificar se o segredo foi renderizado
if [ ! -f "/vault/secrets/db_password.txt" ]; then
    echo "ERRO: O Vault Agent falhou em renderizar o segredo db_password.txt" >&2
    exit 1
fi

echo "Entrypoint: Vault Agent concluiu. Exportando caminhos e iniciando aplicação..."

# Exporta a variável de ambiente que a aplicação Rust espera para encontrar o arquivo de senha.
export TYPEDB_PASSWORD_FILE="/vault/secrets/db_password.txt"

# Executa o comando principal passado para o contêiner (o binário Rust).
echo "Entrypoint: Executando o comando principal: $@"
exec "$@"
