#!/bin/bash
# scripts/setup-full-ecosystem-vault.sh
set -ex

export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='my-root-token' # Apenas para setup

# 1. PKI Engine (CA)
vault secrets enable -path=pki pki || echo "PKI engine já habilitado."
vault secrets tune -max-lease-ttl=87600h pki
vault write -field=certificate pki/root/generate/internal     common_name="Ecosystem Test CA" ttl=87600h > ca_cert.pem
vault write pki/roles/mcp-server     allowed_domains="localhost,typedb-mcp-server-it"     allow_subdomains=true max_ttl="720h"
vault write pki/roles/typedb-server     allowed_domains="localhost,typedb-server-tls-it"     allow_subdomains=true max_ttl="720h"

# 2. OIDC Engine (Provedor JWT)
vault secrets enable -path=oidc jwt || echo "OIDC engine já habilitado."
vault write -f oidc/key/main-key
vault write oidc/role/admin-role -<<EOF
{
  "key": "main-key",
  "template": "{\"scope\": \"typedb:admin_databases typedb:manage_databases typedb:manage_schema typedb:read_data typedb:write_data typedb:validate_queries\"}",
  "ttl": "15m"
}
EOF
vault write oidc/role/readonly-role -<<EOF
{
  "key": "main-key",
  "template": "{\"scope\": \"typedb:read_data\"}",
  "ttl": "1h"
}
EOF

# 3. KV Store (Configurações)
vault secrets enable -path=ecosystem kv-v2 || echo "KV ecosystem já habilitado."
vault kv put ecosystem/config/mcp-server jwks_uri="${VAULT_ADDR}/v1/oidc/jwks" issuer="${VAULT_ADDR}"

# 4. AppRole e Políticas
vault auth enable approle || echo "AppRole auth já habilitado."
vault policy write mcp-server-policy - <<EOF
path "pki/issue/mcp-server" { capabilities = ["update"] }
path "ecosystem/data/config/mcp-server" { capabilities = ["read"] }
path "pki/ca/pem" { capabilities = ["read"] }
EOF
vault policy write sentinel-client-policy - <<EOF
path "oidc/token/admin-role" { capabilities = ["read"] }
path "oidc/token/readonly-role" { capabilities = ["read"] }
path "pki/ca/pem" { capabilities = ["read"] }
EOF
vault write auth/approle/role/mcp-server-app policies="mcp-server-policy"
vault write auth/approle/role/sentinel-client-app policies="sentinel-client-policy"

echo "✅ Vault configurado com sucesso."
