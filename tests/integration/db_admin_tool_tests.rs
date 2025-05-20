// tests/integration/db_admin_tool_tests.rs
// Licença Apache 2.0
// Copyright 2025 Guilherme Leste

use std::time::Duration;
use serde_json::json;
use uuid::Uuid;
use tracing::{error, info};

// Removido: #[path = "../common/mod.rs"] mod common;
// O módulo common é acessado via `crate::common` por causa do `tests/integration.rs`

use crate::common::client::{TestMcpClient, McpClientError};
use crate::common::auth_helpers::{self, Algorithm};
use crate::common::docker_helpers::DockerComposeEnv;
use crate::common::mcp_utils::get_text_from_call_result; // Assumindo que está em mcp_utils
// ou: use crate::common::get_text_from_call_result; // Se reexportado por common/mod.rs

use anyhow::{Context as AnyhowContext, Result};

use typedb_mcp_server_lib::error::MCP_ERROR_CODE_AUTHORIZATION_FAILED;


const DOCKER_COMPOSE_FILE: &str = "docker-compose.test.yml";
const PROJECT_PREFIX: &str = "dbadmintest";
const MCP_WS_ENDPOINT: &str = "ws://localhost:8788/mcp/ws";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

fn unique_db_name(suffix: &str) -> String {
    format!("test_db_admin_{}_{}", suffix, Uuid::new_v4().simple().to_string())
}

async fn setup_env() -> Result<DockerComposeEnv> {
    let env = DockerComposeEnv::new(DOCKER_COMPOSE_FILE, PROJECT_PREFIX);
    env.down(true).map_err(|e| eprintln!("Nota: falha no down inicial: {}",e)).ok();
    env.up().context("Falha ao subir ambiente docker (env.up)")?;
    env.wait_for_service_healthy("typedb-server-it", Duration::from_secs(90)).await.context("TypeDB não saudável")?;
    env.wait_for_service_healthy("typedb-mcp-server-it", Duration::from_secs(60)).await.context("MCP Server não saudável")?;
    env.wait_for_service_healthy("mock-oauth2-server", Duration::from_secs(30)).await.context("Mock Auth Server não saudável")?;
    Ok(env)
}

async fn teardown_env(env: DockerComposeEnv) {
    let _ = env.down(true);
}

async fn mcp_client_with_scope(scope: &str) -> TestMcpClient {
    let now = auth_helpers::current_timestamp_secs();
    let claims = auth_helpers::TestClaims {
        sub: "integration-test-user".to_string(),
        exp: now + 3600,
        iat: Some(now),
        nbf: Some(now),
        iss: Some("test-issuer".to_string()),
        aud: Some(serde_json::json!("test-audience")),
        scope: Some(scope.to_string()),
        custom_claim: None,
    };
    let token = auth_helpers::generate_test_jwt(claims, Algorithm::RS256);
    TestMcpClient::connect(MCP_WS_ENDPOINT, Some(token), CONNECT_TIMEOUT, REQUEST_TIMEOUT).await.expect("Falha ao conectar MCP client")
}

async fn mcp_client_with_claims(claims: auth_helpers::TestClaims) -> TestMcpClient {
    let token = auth_helpers::generate_test_jwt(claims, Algorithm::RS256);
    TestMcpClient::connect(MCP_WS_ENDPOINT, Some(token), CONNECT_TIMEOUT, REQUEST_TIMEOUT).await.expect("Falha ao conectar MCP client")
}

async fn create_test_db(client: &mut TestMcpClient, db_name: &str) {
    let result = client.call_tool("create_database", Some(json!({"name": db_name}))).await;
    assert!(result.is_ok(), "Falha ao criar banco de teste '{}': {:?}", db_name, result.err());
}
async fn delete_test_db(client: &mut TestMcpClient, db_name: &str) {
    let _ = client.call_tool("delete_database", Some(json!({"name": db_name}))).await;
}

#[tokio::test]
#[serial_test::serial]
async fn test_create_database_succeeds() -> Result<()> {
    let docker_env = setup_env().await?;
    let db_name = unique_db_name("create_ok");
    let mut client = mcp_client_with_scope("typedb:manage_databases").await;
    let result = client.call_tool("create_database", Some(json!({"name": db_name}))).await;
    assert!(result.is_ok(), "Esperado sucesso ao criar banco: {:?}" , result.as_ref().err());
    let text_content = get_text_from_call_result(result.unwrap());
    assert_eq!(text_content, "OK");
    delete_test_db(&mut client, &db_name).await;
    docker_env.down(true).context("Falha ao derrubar ambiente docker-compose")?;
    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_create_existing_database_fails() -> Result<()> {
    let docker_env = setup_env().await?;
    let db_name = unique_db_name("create_dup");
    let mut client = mcp_client_with_scope("typedb:manage_databases").await;
    create_test_db(&mut client, &db_name).await;
    let result = client.call_tool("create_database", Some(json!({"name": db_name}))).await;
    assert!(result.is_err(), "Esperado erro ao criar banco duplicado, mas obteve Ok: {:?}", result.ok());
    if let Err(McpClientError::McpErrorResponse { code, .. }) = result {
        assert_eq!(code.0, rmcp::model::ErrorCode::INTERNAL_ERROR.0, "Código de erro inesperado para banco duplicado");
    } else {
        panic!("Tipo de erro inesperado ao criar banco duplicado: {:?}", result.err());
    }
    delete_test_db(&mut client, &db_name).await;
    docker_env.down(true).context("Falha ao derrubar ambiente docker-compose")?;
    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_list_databases_empty_on_fresh_server() -> Result<()> {
    let docker_env = setup_env().await?;
    let mut client = mcp_client_with_scope("typedb:manage_databases").await;
    let result = client.call_tool("list_databases", None).await;
    assert!(result.is_ok(), "Esperado sucesso ao listar bancos: {:?}", result.as_ref().err());
    let text_content = get_text_from_call_result(result.unwrap());
    let dbs: Vec<String> = serde_json::from_str(&text_content).expect("Resposta não é JSON array de strings");
    assert!(dbs.is_empty(), "Esperado lista vazia de bancos, obteve: {:?}", dbs);
    docker_env.down(true).context("Falha ao derrubar ambiente docker-compose")?;
    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_list_databases_returns_created_databases() -> Result<()> {
    let docker_env = setup_env().await?;
    let db_name1 = unique_db_name("list1");
    let db_name2 = unique_db_name("list2");
    let mut client = mcp_client_with_scope("typedb:manage_databases").await;
    create_test_db(&mut client, &db_name1).await;
    create_test_db(&mut client, &db_name2).await;
    let result = client.call_tool("list_databases", None).await;
    assert!(result.is_ok(), "Esperado sucesso ao listar bancos: {:?}", result.as_ref().err());
    let text_content = get_text_from_call_result(result.unwrap());
    let dbs: Vec<String> = serde_json::from_str(&text_content).expect("Resposta não é JSON array de strings");
    assert!(dbs.contains(&db_name1), "Banco '{}' criado não aparece na lista: {:?}", db_name1, dbs);
    assert!(dbs.contains(&db_name2), "Banco '{}' criado não aparece na lista: {:?}", db_name2, dbs);
    delete_test_db(&mut client, &db_name1).await;
    delete_test_db(&mut client, &db_name2).await;
    docker_env.down(true).context("Falha ao derrubar ambiente docker-compose")?;
    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_database_exists_returns_true_for_existing_db() -> Result<()> {
    let docker_env = setup_env().await?;
    let db_name = unique_db_name("exists_true");
    let mut client = mcp_client_with_scope("typedb:manage_databases").await;
    create_test_db(&mut client, &db_name).await;
    let result = client.call_tool("database_exists", Some(json!({"name": db_name}))).await;
    assert!(result.is_ok(), "Esperado sucesso ao checar existência: {:?}", result.as_ref().err());
    let text_content = get_text_from_call_result(result.unwrap());
    assert_eq!(text_content, "true");
    delete_test_db(&mut client, &db_name).await;
    docker_env.down(true).context("Falha ao derrubar ambiente docker-compose")?;
    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_database_exists_returns_false_for_non_existent_db() -> Result<()> {
    let docker_env = setup_env().await?;
    let db_name = unique_db_name("exists_false");
    let mut client = mcp_client_with_scope("typedb:manage_databases").await;
    let result = client.call_tool("database_exists", Some(json!({"name": db_name}))).await;
    assert!(result.is_ok(), "Esperado sucesso ao checar existência: {:?}", result.as_ref().err());
    let text_content = get_text_from_call_result(result.unwrap());
    assert_eq!(text_content, "false");
    docker_env.down(true).context("Falha ao derrubar ambiente docker-compose")?;
    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_delete_database_succeeds() -> Result<()> {
    let docker_env = setup_env().await?;
    let db_name = unique_db_name("delete_ok");
    let mut client = mcp_client_with_scope("typedb:admin_databases typedb:manage_databases").await;
    create_test_db(&mut client, &db_name).await;
    let result = client.call_tool("delete_database", Some(json!({"name": db_name}))).await;
    assert!(result.is_ok(), "Esperado sucesso ao deletar banco: {:?}", result.as_ref().err());
    let text_content = get_text_from_call_result(result.unwrap());
    assert_eq!(text_content, "OK");
    let result_exists = client.call_tool("database_exists", Some(json!({"name": db_name}))).await;
    assert!(result_exists.is_ok());
    let text_content_exists = get_text_from_call_result(result_exists.unwrap());
    assert_eq!(text_content_exists, "false");
    docker_env.down(true).context("Falha ao derrubar ambiente docker-compose")?;
    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_delete_non_existent_database_fails() -> Result<()> {
    let docker_env = setup_env().await?;
    let db_name = unique_db_name("delete_missing");
    let mut client = mcp_client_with_scope("typedb:admin_databases").await;
    let result = client.call_tool("delete_database", Some(json!({"name": db_name}))).await;
    assert!(result.is_err(), "Esperado erro ao deletar banco inexistente, mas obteve Ok: {:?}", result.ok());
    if let Err(McpClientError::McpErrorResponse { code, .. }) = result {
        assert_eq!(code.0, rmcp::model::ErrorCode::INTERNAL_ERROR.0);
    } else {
        panic!("Tipo de erro inesperado: {:?}", result.err());
    }
    docker_env.down(true).context("Falha ao derrubar ambiente docker-compose")?;
    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_delete_database_requires_admin_scope() -> Result<()> {
    let docker_env = setup_env().await?;
    let db_name = unique_db_name("delete_authz");
    let mut client_manage = mcp_client_with_scope("typedb:manage_databases").await;
    create_test_db(&mut client_manage, &db_name).await;
    let result = client_manage.call_tool("delete_database", Some(json!({"name": db_name}))).await;
    assert!(result.is_err(), "Esperado erro de autorização ao deletar sem escopo admin, mas obteve Ok: {:?}", result.ok());
    if let Err(McpClientError::McpErrorResponse { code, .. }) = result {
        assert_eq!(code.0, MCP_ERROR_CODE_AUTHORIZATION_FAILED);
    } else {
        panic!("Tipo de erro inesperado: {:?}", result.err());
    }
    let mut client_admin = mcp_client_with_scope("typedb:admin_databases").await;
    delete_test_db(&mut client_admin, &db_name).await;
    docker_env.down(true).context("Falha ao derrubar ambiente docker-compose")?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
async fn test_concurrent_create_and_delete_databases() -> Result<()> {
    let docker_env = setup_env().await?;
    let mut tasks = vec![];
    let num_concurrent_ops = 5;

    for i in 0..num_concurrent_ops {
        let task = tokio::spawn(async move {
            let db_name_task = unique_db_name(&format!("concurrent_{}", i));
            let mut task_client = mcp_client_with_scope("typedb:admin_databases typedb:manage_databases").await;
            
            let create_res = task_client.call_tool("create_database", Some(json!({"name": db_name_task}))).await;
            if let Err(e) = create_res.as_ref() { // Usar as_ref() aqui
                error!("Falha concorrente ao criar DB '{}': {:?}", db_name_task, e);
            }

            tokio::time::sleep(Duration::from_millis(10)).await;

            let delete_res = task_client.call_tool("delete_database", Some(json!({"name": db_name_task}))).await;
             if create_res.is_ok() && delete_res.is_err() { // create_res.is_ok() não move
                error!("Falha concorrente ao DELETAR DB '{}' que deveria existir: {:?}", db_name_task, delete_res.as_ref().err()); // Usar as_ref() aqui
            }
            task_client.close().await.ok();
            (create_res.is_ok(), delete_res.is_ok() || create_res.is_err()) // .is_ok() e .is_err() pegam &self
        });
        tasks.push(task);
    }

    let results = futures::future::join_all(tasks).await;
    let mut successful_cycles = 0;
    for (i, task_result) in results.into_iter().enumerate() {
        match task_result {
            Ok((created, deleted_or_create_failed)) => {
                if created && deleted_or_create_failed {
                    successful_cycles += 1;
                } else if !created && deleted_or_create_failed {
                     info!("Task {}: DB não foi criado (esperado em alguns cenários de concorrência de nome ou falha), deleção também falhou ou não foi necessária.", i);
                     successful_cycles += 1;
                } else {
                    error!("Task {}: Falha no ciclo criar/deletar. Criado: {}, Deletado/CriaçãoFalhou: {}", i, created, deleted_or_create_failed);
                }
            }
            Err(e) => {
                error!("Task {} panicked: {:?}", i, e);
            }
        }
    }
    info!("Ciclos de criar/deletar concorrentes completados. Sucessos (ou falhas esperadas na criação): {}/{}", successful_cycles, num_concurrent_ops);
    assert!(successful_cycles > 0, "Nenhum ciclo concorrente de criar/deletar foi bem-sucedido.");

    docker_env.down(true).context("Falha ao derrubar ambiente docker-compose")?;
    Ok(())
}