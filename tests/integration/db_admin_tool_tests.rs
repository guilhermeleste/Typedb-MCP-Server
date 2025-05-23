// tests/integration/db_admin_tool_tests.rs
// Licença Apache 2.0
// Copyright 2025 Guilherme Leste

//! Testes de integração para as ferramentas MCP de administração de banco de dados
//! (create_database, delete_database, list_databases, database_exists).

use crate::common::{
    constants,
    mcp_utils::get_text_from_call_result,
    // Corrigido: Importar TestEnvironment para chamar TestEnvironment::setup
    test_env::TestEnvironment,
};
use anyhow::{Context as AnyhowContext, Result};
use rmcp::model::ErrorCode as McpErrorCode;
use serde_json::json;
use serial_test::serial;
use tracing::{info, warn}; // Adicionado warn
use uuid::Uuid;

/// Gera um nome de banco de dados único para evitar conflitos entre testes.
fn unique_db_name(suffix: &str) -> String {
    format!("test_db_admin_{}_{}", suffix, Uuid::new_v4().as_simple())
}

/// Helper para criar um banco de dados de teste.
async fn create_test_db(client: &mut crate::common::client::TestMcpClient, db_name: &str) {
    info!("Helper: Criando banco de dados de teste: {}", db_name);
    let result = client.call_tool("create_database", Some(json!({ "name": db_name }))).await;
    assert!(
        result.is_ok(),
        "Falha ao criar banco de teste '{}' via helper: {:?}",
        db_name,
        result.err()
    );
    let response_text = get_text_from_call_result(result.unwrap());
    assert_eq!(response_text, "OK", "Resposta inesperada ao criar banco de teste '{}'", db_name);
    info!("Helper: Banco de dados de teste '{}' criado com sucesso.", db_name);
}

/// Helper para deletar um banco de dados de teste (melhor esforço).
async fn delete_test_db(client: &mut crate::common::client::TestMcpClient, db_name: &str) {
    info!("Helper: Deletando banco de dados de teste: {}", db_name);
    match client.call_tool("delete_database", Some(json!({ "name": db_name }))).await {
        Ok(result) => {
            let response_text = get_text_from_call_result(result);
            if response_text == "OK" {
                info!("Helper: Banco de dados de teste '{}' deletado com sucesso.", db_name);
            } else {
                warn!(
                    // Usa warn! importado
                    "Helper: Resposta inesperada ao deletar banco de dados '{}': {}",
                    db_name, response_text
                );
            }
        }
        Err(e) => {
            warn!(
                // Usa warn! importado
                "Helper: Falha ao deletar banco de dados de teste '{}': {:?}",
                db_name, e
            );
        }
    }
}

#[tokio::test]
#[serial]
async fn test_create_database_succeeds_with_valid_name() -> Result<()> {
    // Corrigido: Chamar TestEnvironment::setup
    let test_env =
        TestEnvironment::setup("db_create_ok", constants::DEFAULT_TEST_CONFIG_FILENAME).await?;
    let mut client = test_env.mcp_client_with_auth(Some("typedb:manage_databases")).await?;

    let db_name = unique_db_name("create_valid");
    info!("Teste: Criando banco '{}'", db_name);

    let result = client
        .call_tool("create_database", Some(json!({ "name": db_name })))
        .await
        .context(format!("Falha ao chamar create_database para '{}'", db_name))?;

    let text_content = get_text_from_call_result(result);
    assert_eq!(text_content, "OK", "Resposta incorreta ao criar banco.");

    let exists_result = client
        .call_tool("database_exists", Some(json!({ "name": db_name })))
        .await
        .context(format!("Falha ao chamar database_exists para '{}'", db_name))?;
    let exists_text = get_text_from_call_result(exists_result);
    assert_eq!(exists_text, "true", "Banco criado não foi encontrado por database_exists.");

    delete_test_db(&mut client, &db_name).await;
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_create_existing_database_fails_gracefully() -> Result<()> {
    let test_env =
        TestEnvironment::setup("db_create_dup", constants::DEFAULT_TEST_CONFIG_FILENAME).await?;
    let mut client = test_env.mcp_client_with_auth(Some("typedb:manage_databases")).await?;

    let db_name = unique_db_name("create_duplicate");
    create_test_db(&mut client, &db_name).await;

    info!("Teste: Tentando criar banco duplicado '{}'", db_name);
    let result_err = client
        .call_tool("create_database", Some(json!({ "name": db_name })))
        .await
        .expect_err("Esperado erro ao tentar criar banco duplicado, mas obteve Ok.");

    match result_err {
        crate::common::client::McpClientError::McpErrorResponse { code, message, .. } => {
            assert_eq!(
                code.0,
                McpErrorCode::INTERNAL_ERROR.0,
                "Código de erro inesperado para banco duplicado. Mensagem: {}",
                message
            );
            assert!(
                message.to_lowercase().contains("database")
                    && message.to_lowercase().contains("exists"),
                "Mensagem de erro não indicou que o banco já existe: {}",
                message
            );
        }
        other_err => panic!("Tipo de erro inesperado ao criar banco duplicado: {:?}", other_err),
    }

    delete_test_db(&mut client, &db_name).await;
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_list_databases_empty_and_with_content() -> Result<()> {
    let test_env =
        TestEnvironment::setup("db_list", constants::DEFAULT_TEST_CONFIG_FILENAME).await?;
    let mut client = test_env.mcp_client_with_auth(Some("typedb:manage_databases")).await?;

    info!("Teste: Listando bancos em servidor limpo.");
    let result_empty = client
        .call_tool("list_databases", None)
        .await
        .context("Falha ao chamar list_databases (vazio)")?;
    let text_empty = get_text_from_call_result(result_empty);
    let dbs_empty: Vec<String> = serde_json::from_str(&text_empty)
        .context("Resposta de list_databases (vazio) não é JSON array")?;
    assert!(dbs_empty.is_empty(), "Esperado lista vazia de bancos, obteve: {:?}", dbs_empty);

    let db_name1 = unique_db_name("list_1");
    let db_name2 = unique_db_name("list_2");
    create_test_db(&mut client, &db_name1).await;
    create_test_db(&mut client, &db_name2).await;

    info!("Teste: Listando bancos após criações.");
    let result_with_dbs = client
        .call_tool("list_databases", None)
        .await
        .context("Falha ao chamar list_databases (com dados)")?;
    let text_with_dbs = get_text_from_call_result(result_with_dbs);
    let dbs_with_content: Vec<String> = serde_json::from_str(&text_with_dbs)
        .context("Resposta de list_databases (com dados) não é JSON array")?;

    assert_eq!(
        dbs_with_content.len(),
        2,
        "Número incorreto de bancos listados: {:?}",
        dbs_with_content
    );
    assert!(
        dbs_with_content.contains(&db_name1),
        "Banco '{}' não encontrado na lista: {:?}",
        db_name1,
        dbs_with_content
    );
    assert!(
        dbs_with_content.contains(&db_name2),
        "Banco '{}' não encontrado na lista: {:?}",
        db_name2,
        dbs_with_content
    );

    delete_test_db(&mut client, &db_name1).await;
    delete_test_db(&mut client, &db_name2).await;
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_database_exists_functionality() -> Result<()> {
    let test_env =
        TestEnvironment::setup("db_exists", constants::DEFAULT_TEST_CONFIG_FILENAME).await?;
    let mut client = test_env.mcp_client_with_auth(Some("typedb:manage_databases")).await?;

    let db_name_existing = unique_db_name("exists_true");
    let db_name_non_existing = unique_db_name("exists_false");

    info!("Teste: Verificando banco inexistente '{}'", db_name_non_existing);
    let result_false = client
        .call_tool("database_exists", Some(json!({ "name": db_name_non_existing })))
        .await
        .context(format!("Falha ao chamar database_exists para '{}'", db_name_non_existing))?;
    let text_false = get_text_from_call_result(result_false);
    assert_eq!(
        text_false, "false",
        "database_exists deveria retornar 'false' para banco inexistente."
    );

    create_test_db(&mut client, &db_name_existing).await;
    info!("Teste: Verificando banco existente '{}'", db_name_existing);
    let result_true = client
        .call_tool("database_exists", Some(json!({ "name": db_name_existing })))
        .await
        .context(format!("Falha ao chamar database_exists para '{}'", db_name_existing))?;
    let text_true = get_text_from_call_result(result_true);
    assert_eq!(text_true, "true", "database_exists deveria retornar 'true' para banco existente.");

    delete_test_db(&mut client, &db_name_existing).await;
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_delete_database_succeeds_and_removes_db() -> Result<()> {
    let test_env =
        TestEnvironment::setup("db_delete_ok", constants::DEFAULT_TEST_CONFIG_FILENAME).await?;
    let mut client = test_env
        .mcp_client_with_auth(Some("typedb:admin_databases typedb:manage_databases"))
        .await?;

    let db_name = unique_db_name("delete_target");
    create_test_db(&mut client, &db_name).await;

    let exists_before_result =
        client.call_tool("database_exists", Some(json!({ "name": db_name }))).await?;
    assert_eq!(get_text_from_call_result(exists_before_result), "true");

    info!("Teste: Deletando banco '{}'", db_name);
    let delete_result = client
        .call_tool("delete_database", Some(json!({ "name": db_name })))
        .await
        .context(format!("Falha ao chamar delete_database para '{}'", db_name))?;
    let delete_text = get_text_from_call_result(delete_result);
    assert_eq!(delete_text, "OK", "Resposta incorreta ao deletar banco.");

    info!("Teste: Verificando se o banco '{}' foi deletado.", db_name);
    let exists_after_result =
        client.call_tool("database_exists", Some(json!({ "name": db_name }))).await?;
    let exists_after_text = get_text_from_call_result(exists_after_result);
    assert_eq!(exists_after_text, "false", "Banco não foi removido após delete_database.");
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_delete_non_existent_database_fails_gracefully() -> Result<()> {
    let test_env =
        TestEnvironment::setup("db_delete_missing", constants::DEFAULT_TEST_CONFIG_FILENAME)
            .await?;
    let mut client = test_env.mcp_client_with_auth(Some("typedb:admin_databases")).await?;

    let db_name_missing = unique_db_name("delete_non_existent");
    info!("Teste: Tentando deletar banco inexistente '{}'", db_name_missing);

    let result_err = client
        .call_tool("delete_database", Some(json!({ "name": db_name_missing })))
        .await
        .expect_err("Esperado erro ao tentar deletar banco inexistente, mas obteve Ok.");

    match result_err {
        crate::common::client::McpClientError::McpErrorResponse { code, message, .. } => {
            assert_eq!(
                code.0,
                McpErrorCode::INTERNAL_ERROR.0,
                "Código de erro inesperado para deleção de banco inexistente. Mensagem: {}",
                message
            );
            assert!(
                message.to_lowercase().contains("database")
                    && (message.to_lowercase().contains("not found")
                        || message.to_lowercase().contains("does not exist")),
                "Mensagem de erro não indicou que o banco não existe: {}",
                message
            );
        }
        other_err => {
            panic!("Tipo de erro inesperado ao deletar banco inexistente: {:?}", other_err)
        }
    }
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_db_admin_operations_require_correct_scopes() -> Result<()> {
    let test_env =
        TestEnvironment::setup("db_admin_scopes", constants::OAUTH_ENABLED_TEST_CONFIG_FILENAME)
            .await?;
    let db_name = unique_db_name("authz_db");

    let mut client_no_perms = test_env.mcp_client_with_auth(Some("other:scope")).await?;

    info!("Teste: Tentando create_database sem escopo 'typedb:manage_databases'");
    let res_create_no_perms =
        client_no_perms.call_tool("create_database", Some(json!({"name": db_name}))).await;
    assert!(res_create_no_perms.is_err());
    if let crate::common::client::McpClientError::McpErrorResponse { code, .. } =
        res_create_no_perms.unwrap_err()
    {
        assert_eq!(code.0, rmcp::model::ErrorCode(-32001).0); // Authorization Failed
    } else {
        panic!("Esperado McpErrorResponse de autorização para create_database");
    }

    let mut client_manage_perms =
        test_env.mcp_client_with_auth(Some("typedb:manage_databases")).await?;
    create_test_db(&mut client_manage_perms, &db_name).await;

    info!("Teste: Tentando delete_database com escopo 'typedb:manage_databases' (insuficiente)");
    let res_delete_manage_perms =
        client_manage_perms.call_tool("delete_database", Some(json!({"name": db_name}))).await;
    assert!(res_delete_manage_perms.is_err());
    if let crate::common::client::McpClientError::McpErrorResponse { code, .. } =
        res_delete_manage_perms.unwrap_err()
    {
        assert_eq!(code.0, rmcp::model::ErrorCode(-32001).0); // Authorization Failed
    } else {
        panic!("Esperado McpErrorResponse de autorização para delete_database");
    }

    let mut client_admin_perms =
        test_env.mcp_client_with_auth(Some("typedb:admin_databases")).await?;
    delete_test_db(&mut client_admin_perms, &db_name).await;
    Ok(())
}
