use std::process::{Command, Stdio};
use std::time::Duration;
use anyhow::{Context, Result};
use tokio::time::sleep;
use vaultrs::{client::{VaultClient, VaultClientSettingsBuilder}, kv2, sys};

#[tokio::test]
async fn test_vault_dev_server_interaction() -> Result<()> {
    // Inicia servidor Vault em modo dev
    let mut child = Command::new("vault")
        .arg("server")
        .arg("-dev")
        .arg("-dev-root-token-id=root")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to spawn vault dev server")?;

    // Aguarda o servidor iniciar
    sleep(Duration::from_secs(2)).await;

    let client = VaultClient::new(
        VaultClientSettingsBuilder::default()
            .address("http://127.0.0.1:8200")
            .token("root")
            .build()
            .unwrap(),
    )?;

    // Habilita o engine KV v2
    sys::mounts::enable(
        &client,
        "kv",
        "kv",
        sys::mounts::MountType::Kv2,
        None::<sys::mounts::MountConfig>,
    ).await?;

    // Escreve um segredo
    let mut data = std::collections::HashMap::new();
    data.insert("typedb_password".to_string(), "testpw".to_string());
    kv2::set(&client, "typedb-mcp-server/config", data).await?;

    // Lê o segredo de volta
    let secret = kv2::read(&client, "typedb-mcp-server/config").await?;
    let pass = secret.data.get("typedb_password")
        .context("password key missing")?
        .as_str()
        .context("password value not string")?;

    assert_eq!(pass, "testpw");

    let _ = child.kill();
    Ok(())
}
