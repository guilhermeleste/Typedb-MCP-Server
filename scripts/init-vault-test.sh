#!/bin/sh
set -e

echo "Inicializando Vault para testes de integração..."

# Configuração do Vault para testes
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=test-root-token

# Aguardar Vault estar pronto
echo "Aguardando Vault estar pronto..."
until vault status > /dev/null 2>&1; do
    echo "Vault não está pronto ainda, aguardando..."
    sleep 2
done

echo "Vault está pronto! Configurando KV store e AppRole..."

# 1. Habilitar KV secrets engine
echo "1. Habilitando KV secrets engine..."
vault secrets enable -version=2 kv || echo "KV já habilitado"

# 2. Armazenar senha do TypeDB no KV store
echo "2. Armazenando senha do TypeDB no KV store..."
vault kv put kv/typedb-mcp-server/config typedb_password="password"

# 3. Habilitar AppRole auth method
echo "3. Habilitando AppRole auth method..."
vault auth enable approle || echo "AppRole já habilitado"

# 4. Criar política para o MCP server
echo "4. Criando política para o MCP server..."
vault policy write mcp-server-policy - <<EOF
path "kv/data/typedb-mcp-server/*" {
  capabilities = ["read"]
}
EOF

# 5. Criar AppRole para o MCP server
echo "5. Criando AppRole para o MCP server..."
vault write auth/approle/role/mcp-server \
    token_policies="mcp-server-policy" \
    token_ttl=1h \
    token_max_ttl=4h \
    bind_secret_id=true

# 6. Obter RoleID e criar SecretID
echo "6. Obtendo RoleID e criando SecretID..."
ROLE_ID=$(vault read -field=role_id auth/approle/role/mcp-server/role-id)
SECRET_ID=$(vault write -force -field=secret_id auth/approle/role/mcp-server/secret-id)

echo "Role ID: $ROLE_ID"
echo "Secret ID: $SECRET_ID"

# 6.1. Atualizar arquivos de secrets para que sejam usados pelos containers
echo "6.1. Atualizando arquivos de secrets..."
echo "$ROLE_ID" > /vault/test-secrets/role_id.txt
echo "$SECRET_ID" > /vault/test-secrets/secret_id.txt

# 7. Verificar se conseguimos autenticar com AppRole
echo "7. Testando autenticação AppRole..."
APP_TOKEN=$(vault write -field=token auth/approle/login role_id="$ROLE_ID" secret_id="$SECRET_ID")
echo "Token AppRole obtido: ${APP_TOKEN:0:10}..."

# 8. Testar leitura do segredo com o token AppRole
echo "8. Testando leitura do segredo com token AppRole..."
VAULT_TOKEN=$APP_TOKEN vault kv get -field=typedb_password kv/typedb-mcp-server/config

echo "✅ Vault configurado com sucesso para testes!"
echo "✅ KV store: kv/typedb-mcp-server/config com senha 'password'"
echo "✅ AppRole: mcp-server com política de leitura configurada"
echo "✅ Role ID e Secret ID prontos para uso pelo Vault Agent"
