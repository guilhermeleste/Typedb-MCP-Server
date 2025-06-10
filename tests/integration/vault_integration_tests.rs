use crate::common::{mcp_utils::get_text_from_call_result, test_env::TestEnvironment};
use anyhow::{Context, Result};
use serial_test::serial;
use tracing::info;

#[tokio::test]
#[serial]
async fn test_startup_with_vault_secrets_succeeds() -> Result<()> {
    let test_env = TestEnvironment::setup_with_vault("vault_ok", None, false, true).await?;
    let mut client = test_env.mcp_client_with_auth(None).await?;
    let list_result =
        client.call_tool("list_databases", None).await.context("call list_databases failed")?;
    info!("list_databases: {}", get_text_from_call_result(list_result));
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_startup_fails_with_invalid_vault_secret_id() -> Result<()> {
    let result =
        TestEnvironment::setup_with_vault("vault_bad_sid", Some("wrong".into()), false, true).await;
    assert!(result.is_err(), "setup_with_vault deveria falhar com secret_id invalido");
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_startup_fails_if_kv_secret_is_missing() -> Result<()> {
    let result = TestEnvironment::setup_with_vault("vault_missing_kv", None, true, true).await;
    assert!(result.is_err(), "setup_with_vault deveria falhar se o segredo KV estiver ausente");
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_startup_fails_if_vault_is_unavailable() -> Result<()> {
    let result = TestEnvironment::setup_with_vault("vault_unavail", None, false, false).await;
    assert!(result.is_err(), "setup_with_vault deveria falhar se o Vault estiver indisponivel");
    Ok(())
}
