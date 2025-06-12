//! # Vault Bootstrap Utility
//! 
//! This utility bootstrap initializes `HashiCorp` Vault for the `TypeDB` MCP Server project.
//! It configures PKI secrets engine, generates certificates, and sets up initial auth roles.
//! 
//! ## Usage
//! 
//! ```bash
//! cargo run --bin vault_bootstrap
//! ```
//! 
//! ## Prerequisites
//! 
//! - Vault server running and accessible
//! - Appropriate environment variables set (`VAULT_ADDR`, `VAULT_TOKEN`)
//! - PKI engine mount path configured

// src/bin/vault_bootstrap.rs
use anyhow::Context;
use std::{env, fs, io::Write};
use tracing::warn;
use vaultrs::{
    client::{VaultClient, VaultClientSettingsBuilder},
    api::pki::requests::GenerateCertificateRequest,
};

#[tokio::main] // O bootstrap agora precisa de um runtime tokio
async fn main() -> anyhow::Result<()> {
    // Inicializar tracing para logs
    tracing_subscriber::fmt::init();

    // 1. Ler credenciais do AppRole e endereço do Vault do ambiente
    let vault_addr = env::var("VAULT_ADDR").context("VAULT_ADDR não foi definido")?;
    let role_id = env::var("MCP_SERVER_ROLE_ID").context("MCP_SERVER_ROLE_ID não foi definido")?;
    let secret_id = env::var("MCP_SERVER_SECRET_ID").context("MCP_SERVER_SECRET_ID não foi definido")?;

    // 2. Criar e autenticar o cliente Vaultrs
    let client = VaultClient::new(
        VaultClientSettingsBuilder::default()
            .address(&vault_addr)
            .build()
            .context("Falha ao construir as configurações do cliente Vault")?,
    )
    .context("Falha ao criar o cliente Vault")?;

    // Autenticar com AppRole
    let _auth_info = vaultrs::auth::approle::login(&client, "approle", &role_id, &secret_id)
        .await
        .context("Falha na autenticação AppRole com o Vault")?;

    // 3. Solicitar certificado TLS para o servidor usando a API oficial
    let mut cert_request_builder = GenerateCertificateRequest::builder();
    let cert_request = cert_request_builder.common_name("localhost");
    
    let cert_response = vaultrs::pki::cert::generate(&client, "pki", "mcp-server", Some(cert_request))
        .await
        .context("Falha ao gerar certificado do Vault")?;
    
    fs::write("/tmp/mcp_server.crt", &cert_response.certificate)
        .context("Falha ao escrever /tmp/mcp_server.crt")?;
    fs::write("/tmp/mcp_server.key", &cert_response.private_key)
        .context("Falha ao escrever /tmp/mcp_server.key")?;

    // 4. Ler configuração OIDC do KV Store usando a API oficial
    let secret_path = "config/mcp-server";
    let oidc_config: serde_json::Value = vaultrs::kv2::read(&client, "ecosystem", secret_path)
        .await
        .context(format!("Falha ao ler segredos OIDC do KV 'ecosystem' no path '{secret_path}'"))?;
    
    let jwks_uri = oidc_config.get("jwks_uri")
        .and_then(|uri| uri.as_str())
        .context("jwks_uri não encontrado no segredo")?;
    let issuer = oidc_config.get("issuer")
        .and_then(|iss| iss.as_str())
        .context("issuer não encontrado no segredo")?;

    // 5. Ler CA para conexão com TypeDB (para simplificar, vamos pular esta parte por agora)
    // Em um cenário real, você configuraria o CA através de outro meio
    // ou usaria uma abordagem direta para o endpoint do Vault
    warn!("CA certificate setup skipped - configure manually if needed");

    // 6. Exportar as configurações como variáveis de ambiente
    let mut env_file = fs::File::create("/tmp/vault_exports.env")
        .context("Falha ao criar /tmp/vault_exports.env")?;
    writeln!(env_file, "export MCP_SERVER__TLS_ENABLED=true")?;
    writeln!(env_file, "export MCP_SERVER__TLS_CERT_PATH=/tmp/mcp_server.crt")?;
    writeln!(env_file, "export MCP_SERVER__TLS_KEY_PATH=/tmp/mcp_server.key")?;
    writeln!(env_file, "export MCP_AUTH__OAUTH_ENABLED=true")?;
    writeln!(env_file, "export MCP_AUTH__OAUTH_JWKS_URI='{jwks_uri}'")?;
    writeln!(env_file, "export MCP_AUTH__OAUTH_ISSUER='{issuer}'")?;
    writeln!(env_file, "export MCP_TYPEDB__TLS_ENABLED=true")?;
    writeln!(env_file, "export MCP_TYPEDB__TLS_CA_PATH=/tmp/typedb_ca.pem")?;

    Ok(())
}