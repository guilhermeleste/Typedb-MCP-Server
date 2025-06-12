#!/bin/sh
set -e
echo "Iniciando bootstrap do Vault para o typedb-mcp-server..."
vault_bootstrap
. /tmp/vault_exports.env
echo "Bootstrap concluído. Iniciando a aplicação principal..."
exec typedb_mcp_server
