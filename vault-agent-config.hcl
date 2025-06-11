exit_after_auth = true
pid_file = "/tmp/agent_pid"

vault {
  # O endereço do Vault para ambiente de teste
  address = "http://vault-test:8200"
}

auto_auth {
  method "approle" {
    # O Vault Agent lerá o RoleID e SecretID destes caminhos,
    # que serão montados pelo Docker Secrets.
    mount_path = "auth/approle"
    config = {
      role_id_file_path   = "/run/secrets/mcp_approle_role_id"
      secret_id_file_path = "/run/secrets/mcp_approle_secret_id"
      remove_secret_id_file_after_read = true
    }
  }

  sink "file" {
    config = {
      path = "/tmp/vault-token"
    }
  }
}

# Template para renderizar a senha do TypeDB
template {
  source      = "/app/templates/db_password.ctmpl"
  destination = "/vault/secrets/db_password.txt"
  perms       = "0400"
}
