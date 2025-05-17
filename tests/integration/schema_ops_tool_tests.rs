// tests/integration/schema_ops_tool_tests.rs
// Licença Apache 2.0
// Copyright 2025 Guilherme Leste
//
// Testes de integração para as ferramentas MCP de operações de esquema
// (define_schema, undefine_schema, get_schema) via MCP/WebSocket.
//
// Estes testes exigem:
// - Docker Compose com Typedb-MCP-Server, TypeDB e Mock Auth Server rodando
// - helpers de client, auth e docker em tests/common/

use std::time::Duration;
use serde_json::json;
use tests::common::{client::TestMcpClient, auth_helpers, docker_helpers::{DockerComposeEnv, Result as DockerResult}};

const DOCKER_COMPOSE_FILE: &str = "docker-compose.test.yml";
const PROJECT_PREFIX: &str = "schemaopstest";
const MCP_WS_ENDPOINT: &str = "ws://localhost:8787/mcp/ws";

fn unique_db_name(suffix: &str) -> String {
    format!("test_schema_ops_{}_{}", suffix, uuid::Uuid::new_v4().to_simple())
}

async fn setup_env() -> DockerResult<DockerComposeEnv> {
    let env = DockerComposeEnv::new(DOCKER_COMPOSE_FILE, PROJECT_PREFIX);
    env.up()?;
    env.wait_for_service_healthy("typedb-mcp-server", Duration::from_secs(60)).await?;
    env.wait_for_service_healthy("typedb", Duration::from_secs(60)).await?;
    env.wait_for_service_healthy("mock-auth-server", Duration::from_secs(30)).await?;
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
        iss: Some("integration-test-issuer".to_string()),
        aud: Some(serde_json::json!("integration-test-aud")),
        scope: Some(scope.to_string()),
        custom_claim: None,
    };
    let token = auth_helpers::generate_test_jwt(claims, jsonwebtoken::Algorithm::HS256);
    TestMcpClient::connect(MCP_WS_ENDPOINT, Some(token), Duration::from_secs(10), Duration::from_secs(10)).await.expect("Falha ao conectar MCP client")
}

// Cria e deleta banco para cada teste de isolamento
async fn create_test_db(client: &mut TestMcpClient, db_name: &str) {
    let result = client.call_tool("create_database", Some(json!({"name": db_name}))).await;
    assert!(result.is_ok(), "Falha ao criar banco de teste: {:?}", result);
}
async fn delete_test_db(client: &mut TestMcpClient, db_name: &str) {
    let _ = client.call_tool("delete_database", Some(json!({"name": db_name}))).await;
}

#[tokio::test]
async fn test_define_simple_entity_succeeds_and_is_retrievable() {
    let env = setup_env().await.expect("Falha no setup do ambiente docker");
    let db_name = unique_db_name("define_entity");
    let mut client = mcp_client_with_scope("typedb:manage_databases typedb:manage_schema").await;
    create_test_db(&mut client, &db_name).await;
    let schema = "define person sub entity;";
    let result = client.call_tool("define_schema", Some(json!({"database_name": db_name, "schema_definition": schema}))).await;
    assert!(result.is_ok(), "Esperado sucesso ao definir schema: {:?}", result);
    let content = &result.unwrap().content[0].as_text().unwrap().text;
    assert_eq!(content, "OK");
    // Verifica se está no get_schema
    let result = client.call_tool("get_schema", Some(json!({"database_name": db_name, "schema_type": "full"}))).await;
    assert!(result.is_ok(), "Esperado sucesso ao obter schema");
    let schema_content = &result.unwrap().content[0].as_text().unwrap().text;
    assert!(schema_content.contains("person sub entity"), "Schema retornado não contém definição");
    delete_test_db(&mut client, &db_name).await;
    teardown_env(env).await;
}

#[tokio::test]
async fn test_define_schema_with_invalid_typeql_fails() {
    let env = setup_env().await.expect("Falha no setup do ambiente docker");
    let db_name = unique_db_name("define_invalid");
    let mut client = mcp_client_with_scope("typedb:manage_databases typedb:manage_schema").await;
    create_test_db(&mut client, &db_name).await;
    let invalid_schema = "define person sub entity"; // falta o ponto e vírgula
    let result = client.call_tool("define_schema", Some(json!({"database_name": db_name, "schema_definition": invalid_schema}))).await;
    assert!(result.is_err(), "Esperado erro ao definir schema inválido");
    delete_test_db(&mut client, &db_name).await;
    teardown_env(env).await;
}

#[tokio::test]
async fn test_define_schema_on_nonexistent_db_fails() {
    let env = setup_env().await.expect("Falha no setup do ambiente docker");
    let db_name = unique_db_name("define_nonexistent");
    let mut client = mcp_client_with_scope("typedb:manage_schema").await;
    let schema = "define person sub entity;";
    let result = client.call_tool("define_schema", Some(json!({"database_name": db_name, "schema_definition": schema}))).await;
    assert!(result.is_err(), "Esperado erro ao definir schema em banco inexistente");
    teardown_env(env).await;
}

#[tokio::test]
async fn test_undefine_existing_type_succeeds() {
    let env = setup_env().await.expect("Falha no setup do ambiente docker");
    let db_name = unique_db_name("undefine_type");
    let mut client = mcp_client_with_scope("typedb:manage_databases typedb:manage_schema").await;
    create_test_db(&mut client, &db_name).await;
    let schema = "define animal sub entity;";
    let _ = client.call_tool("define_schema", Some(json!({"database_name": db_name, "schema_definition": schema}))).await.expect("Falha ao definir schema");
    let result = client.call_tool("undefine_schema", Some(json!({"database_name": db_name, "schema_undefinition": "undefine animal;"}))).await;
    assert!(result.is_ok(), "Esperado sucesso ao remover tipo: {:?}", result);
    let content = &result.unwrap().content[0].as_text().unwrap().text;
    assert_eq!(content, "OK");
    // Verifica se foi removido
    let result = client.call_tool("get_schema", Some(json!({"database_name": db_name, "schema_type": "full"}))).await;
    assert!(result.is_ok());
    let schema_content = &result.unwrap().content[0].as_text().unwrap().text;
    assert!(!schema_content.contains("animal sub entity"), "Tipo não foi removido do schema");
    delete_test_db(&mut client, &db_name).await;
    teardown_env(env).await;
}

#[tokio::test]
async fn test_undefine_schema_on_nonexistent_db_fails() {
    let env = setup_env().await.expect("Falha no setup do ambiente docker");
    let db_name = unique_db_name("undefine_nonexistent");
    let mut client = mcp_client_with_scope("typedb:manage_schema").await;
    let result = client.call_tool("undefine_schema", Some(json!({"database_name": db_name, "schema_undefinition": "undefine animal;"}))).await;
    assert!(result.is_err(), "Esperado erro ao remover schema em banco inexistente");
    teardown_env(env).await;
}

#[tokio::test]
async fn test_get_schema_returns_defined_schema_types_only() {
    let env = setup_env().await.expect("Falha no setup do ambiente docker");
    let db_name = unique_db_name("get_types");
    let mut client = mcp_client_with_scope("typedb:manage_databases typedb:manage_schema").await;
    create_test_db(&mut client, &db_name).await;
    let schema = "define car sub entity;";
    let _ = client.call_tool("define_schema", Some(json!({"database_name": db_name, "schema_definition": schema}))).await.expect("Falha ao definir schema");
    let result = client.call_tool("get_schema", Some(json!({"database_name": db_name, "schema_type": "types"}))).await;
    assert!(result.is_ok(), "Esperado sucesso ao obter schema types");
    let schema_content = &result.unwrap().content[0].as_text().unwrap().text;
    assert!(schema_content.contains("car sub entity"), "Schema types não contém definição");
    delete_test_db(&mut client, &db_name).await;
    teardown_env(env).await;
}

#[tokio::test]
async fn test_get_schema_on_empty_database() {
    let env = setup_env().await.expect("Falha no setup do ambiente docker");
    let db_name = unique_db_name("get_empty");
    let mut client = mcp_client_with_scope("typedb:manage_databases typedb:manage_schema").await;
    create_test_db(&mut client, &db_name).await;
    let result = client.call_tool("get_schema", Some(json!({"database_name": db_name, "schema_type": "full"}))).await;
    assert!(result.is_ok(), "Esperado sucesso ao obter schema vazio");
    let schema_content = &result.unwrap().content[0].as_text().unwrap().text;
    assert!(schema_content.trim().is_empty() || schema_content.contains("define"), "Schema vazio não retornou string vazia ou mínima");
    delete_test_db(&mut client, &db_name).await;
    teardown_env(env).await;
}

#[tokio::test]
async fn test_get_schema_on_nonexistent_db_fails() {
    let env = setup_env().await.expect("Falha no setup do ambiente docker");
    let db_name = unique_db_name("get_nonexistent");
    let mut client = mcp_client_with_scope("typedb:manage_schema").await;
    let result = client.call_tool("get_schema", Some(json!({"database_name": db_name, "schema_type": "full"}))).await;
    assert!(result.is_err(), "Esperado erro ao obter schema de banco inexistente");
    teardown_env(env).await;
}

#[tokio::test]
async fn test_get_schema_with_invalid_type_defaults_to_full() {
    let env = setup_env().await.expect("Falha no setup do ambiente docker");
    let db_name = unique_db_name("get_invalid_type");
    let mut client = mcp_client_with_scope("typedb:manage_databases typedb:manage_schema").await;
    create_test_db(&mut client, &db_name).await;
    let schema = "define spaceship sub entity;";
    let _ = client.call_tool("define_schema", Some(json!({"database_name": db_name, "schema_definition": schema}))).await.expect("Falha ao definir schema");
    let result = client.call_tool("get_schema", Some(json!({"database_name": db_name, "schema_type": "invalid_value"}))).await;
    assert!(result.is_ok(), "Esperado sucesso ao obter schema mesmo com tipo inválido");
    let schema_content = &result.unwrap().content[0].as_text().unwrap().text;
    assert!(schema_content.contains("spaceship sub entity"), "Schema retornado não contém definição");
    delete_test_db(&mut client, &db_name).await;
    teardown_env(env).await;
}

// Teste de autorização granular
#[tokio::test]
async fn test_schema_operations_require_correct_scope() {
    let env = setup_env().await.expect("Falha no setup do ambiente docker");
    let db_name = unique_db_name("authz_scope");
    let mut client = mcp_client_with_scope("typedb:manage_databases").await; // Não tem manage_schema
    create_test_db(&mut client, &db_name).await;
    let schema = "define forbidden sub entity;";
    let result = client.call_tool("define_schema", Some(json!({"database_name": db_name, "schema_definition": schema}))).await;
    assert!(result.is_err(), "Esperado erro de permissão para define_schema sem escopo");
    let result = client.call_tool("undefine_schema", Some(json!({"database_name": db_name, "schema_undefinition": "undefine forbidden;"}))).await;
    assert!(result.is_err(), "Esperado erro de permissão para undefine_schema sem escopo");
    let result = client.call_tool("get_schema", Some(json!({"database_name": db_name, "schema_type": "full"}))).await;
    assert!(result.is_err(), "Esperado erro de permissão para get_schema sem escopo");
    delete_test_db(&mut client, &db_name).await;
    teardown_env(env).await;
}
