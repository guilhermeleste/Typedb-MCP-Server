use anyhow::{Context, Result};
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::time::sleep;
use vaultrs::{
    client::{VaultClient, VaultClientSettingsBuilder},
    kv2,
    sys::mount,
};


    sleep(Duration::from_secs(5)).await;
    mount::enable(&client, "kv", "kv-v2", None).await?;
    let pass = secret.get("typedb_password").context("password key missing")?.as_str();
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
    mount::enable(&client, "kv", "kv", None).await?;


    // Escreve um segredo
    let mut data = std::collections::HashMap::new();
    data.insert("typedb_password".to_string(), "testpw".to_string());
    kv2::set(&client, "kv", "typedb-mcp-server/config", &data).await?;

    // Lê o segredo de volta
    let secret: std::collections::HashMap<String, String> =
        kv2::read(&client, "kv", "typedb-mcp-server/config").await?;
    let pass = secret
        .get("typedb_password")
        .context("password key missing")?
        .as_str();


    assert_eq!(pass, "testpw");

    let _ = child.kill();
    Ok(())
}
