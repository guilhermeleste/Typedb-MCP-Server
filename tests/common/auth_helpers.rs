// tests/common/auth_helpers.rs
use anyhow::{Context, Result};
use reqwest::Client as HttpClient;
use serde::Deserialize;
use std::env;
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};

// A struct TestClaims e outras constantes como TEST_RSA_PRIVATE_KEY_PEM se tornam obsoletas
// e podem ser removidas. Apenas o algoritmo pode ser útil.
pub use jsonwebtoken::Algorithm as JwtAuthAlgorithm;

/// Gera um token JWT de teste solicitando-o diretamente ao Vault.
/// Esta função espera que as variáveis de ambiente VAULT_ADDR,
/// SENTINEL_ROLE_ID, e SENTINEL_SECRET_ID estejam definidas.
pub async fn generate_test_jwt_from_vault(role_name: &str) -> Result<String> {
    let vault_addr = env::var("VAULT_ADDR")
        .context("A variável de ambiente VAULT_ADDR não foi definida para os testes")?;
    let role_id = env::var("SENTINEL_ROLE_ID")
        .context("A variável de ambiente SENTINEL_ROLE_ID não foi definida")?;
    let secret_id = env::var("SENTINEL_SECRET_ID")
        .context("A variável de ambiente SENTINEL_SECRET_ID não foi definida")?;

    let mut client = VaultClient::new(
        VaultClientSettingsBuilder::default()
            .address(&vault_addr)
            .build()
            .context("Falha ao construir as configurações do cliente Vault para testes")?,
    )?;

    vaultrs::auth::approle::login(&mut client, "approle", &role_id, &secret_id)
        .await
        .context("Falha na autenticação AppRole do helper de teste com o Vault")?;

    #[derive(Deserialize)]
    struct TokenResponse {
        token: String,
    }

    let url = format!("{}/v1/identity/oidc/token/{}", vault_addr, role_name);
    let http = HttpClient::new();
    let res = http
        .post(&url)
        .header("X-Vault-Token", &client.settings.token)
        .send()
        .await
        .context("Falha ao requisitar token OIDC ao Vault")?;
    let status = res.status();
    if !status.is_success() {
        return Err(anyhow::anyhow!(
            "Vault retornou status {} ao gerar token para role {}",
            status,
            role_name
        ));
    }
    let resp: TokenResponse = res.json().await.context("Resposta inválida ao gerar token OIDC")?;

    Ok(resp.token)
}
