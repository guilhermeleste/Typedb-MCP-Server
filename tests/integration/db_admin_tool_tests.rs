// tests/integration/db_admin_tool_tests.rs
// Licença Apache 2.0
// Copyright 2025 Guilherme Leste
//
// Testes de integração para as ferramentas MCP de administração de banco de dados
// (create_database, database_exists, list_databases, delete_database) via MCP/WebSocket.
//
// Estes testes exigem:
// - Docker Compose com Typedb-MCP-Server, TypeDB e Mock Auth Server rodando
// - helpers de client, auth e docker em tests/common/

use std::time::Duration;
use serde_json::json;
use futures::future::join_all;
// Corrigido: usar crate::common
use crate::common::{client::{TestMcpClient, McpClientError}, auth_helpers::{self, Algorithm}, docker_helpers::{DockerComposeEnv, Result as DockerResult}};

const DOCKER_COMPOSE_FILE: &str = "docker-compose.test.yml";
const PROJECT_PREFIX: &str = "dbadmintest";
const MCP_WS_ENDPOINT: &str = "ws://localhost:8787/mcp/ws";

// Helper para gerar nomes únicos de banco de dados
fn unique_db_name(suffix: &str) -> String {
    // Corrigido: usar simple().to_string()
    format!("test_db_admin_{}_{}", suffix, uuid::Uuid::new_v4().simple().to_string())
}

// Helper para setup do ambiente docker compose
async fn setup_env() -> DockerResult<DockerComposeEnv> {
    let env = DockerComposeEnv::new(DOCKER_COMPOSE_FILE, PROJECT_PREFIX);
    // Corrigido: Usar .expect() em vez de ?
    env.up().expect("Falha ao iniciar ambiente docker (env.up)");
    // Aguarda serviços ficarem saudáveis (Typedb-MCP-Server, TypeDB, Auth)
    // Corrigido: Usar .expect() em vez de ?
    env.wait_for_service_healthy("typedb-mcp-server", Duration::from_secs(60)).await.expect("Falha ao esperar por typedb-mcp-server");
    env.wait_for_service_healthy("typedb", Duration::from_secs(60)).await.expect("Falha ao esperar por typedb");
    env.wait_for_service_healthy("mock-auth-server", Duration::from_secs(30)).await.expect("Falha ao esperar por mock-auth-server");
    Ok(env)
}

// Helper para teardown
async fn teardown_env(env: DockerComposeEnv) {
    let _ = env.down(true);
}

// Helper para criar cliente MCP autenticado
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
    // Corrigido: Usar Algorithm de auth_helpers
    let token = auth_helpers::generate_test_jwt(claims, Algorithm::HS256);
    TestMcpClient::connect(MCP_WS_ENDPOINT, Some(token), Duration::from_secs(10), Duration::from_secs(10)).await.expect("Falha ao conectar MCP client")
}

// Helper para criar cliente MCP autenticado com claims customizados (para testes de expiração, audience, etc)
async fn mcp_client_with_claims(claims: auth_helpers::TestClaims) -> TestMcpClient {
    // Corrigido: Usar Algorithm de auth_helpers
    let token = auth_helpers::generate_test_jwt(claims, Algorithm::HS256);
    TestMcpClient::connect(MCP_WS_ENDPOINT, Some(token), Duration::from_secs(10), Duration::from_secs(10)).await.expect("Falha ao conectar MCP client")
}


// Teste concorrente: cria e deleta bancos simultaneamente
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_create_and_delete_databases() {
    let env = setup_env().await.expect("Falha no setup do ambiente docker");
    let mut handles = vec![];
    for i in 0..4 {
        let db_name = unique_db_name(&format!("concurrent_{}", i));
        handles.push(tokio::spawn(async move {
            let mut client = mcp_client_with_scope("typedb:admin_databases typedb:manage_databases").await;
            let _ = client.call_tool("create_database", Some(json!({"name": db_name}))).await;
            let _ = client.call_tool("delete_database", Some(json!({"name": db_name}))).await;
        }));
    }
    for h in handles {
        h.await.expect("Task panicked");
    }
    teardown_env(env).await;
}

// Teste: token sem escopo algum (espera PERMISSION_DENIED em todas as operações)
#[tokio::test]
async fn test_all_db_admin_tools_require_scope() {
    let env = setup_env().await.expect("Falha no setup do ambiente docker");
    let mut client = mcp_client_with_scope("").await;
    let db_name = unique_db_name("no_scope");
    // create_database
    let result = client.call_tool("create_database", Some(json!({"name": db_name}))).await;
    assert!(result.is_err(), "Esperado erro de permissão para create_database");
    // list_databases
    let result = client.call_tool("list_databases", None).await;
    assert!(result.is_err(), "Esperado erro de permissão para list_databases");
    // database_exists
    let result = client.call_tool("database_exists", Some(json!({"name": db_name}))).await;
    assert!(result.is_err(), "Esperado erro de permissão para database_exists");
    // delete_database
    let result = client.call_tool("delete_database", Some(json!({"name": db_name}))).await;
    assert!(result.is_err(), "Esperado erro de permissão para delete_database");
    teardown_env(env).await;
}

// Teste: token expirado (espera erro de autenticação)
#[tokio::test]
async fn test_expired_token_fails_authentication() {
    let env = setup_env().await.expect("Falha no setup do ambiente docker");
    let now = auth_helpers::current_timestamp_secs();
    let claims = auth_helpers::TestClaims {
        sub: "integration-test-user".to_string(),
        exp: now - 10, // já expirado
        iat: Some(now - 20),
        nbf: Some(now - 20),
        iss: Some("integration-test-issuer".to_string()),
        aud: Some(serde_json::json!("integration-test-aud")),
        scope: Some("typedb:manage_databases typedb:admin_databases".to_string()),
        custom_claim: None,
    };
    let mut client = mcp_client_with_claims(claims).await;
    let db_name = unique_db_name("expired_token");
    let result = client.call_tool("create_database", Some(json!({"name": db_name}))).await;
    assert!(result.is_err(), "Esperado erro de autenticação para token expirado");
    teardown_env(env).await;
}

// Teste: audience inválido (espera erro de autenticação)
#[tokio::test]
async fn test_invalid_audience_fails_authentication() {
    let env = setup_env().await.expect("Falha no setup do ambiente docker");
    let now = auth_helpers::current_timestamp_secs();
    let claims = auth_helpers::TestClaims {
        sub: "integration-test-user".to_string(),
        exp: now + 3600,
        iat: Some(now),
        nbf: Some(now),
        iss: Some("integration-test-issuer".to_string()),
        aud: Some(serde_json::json!("aud-invalida")),
        scope: Some("typedb:manage_databases typedb:admin_databases".to_string()),
        custom_claim: None,
    };
    let mut client = mcp_client_with_claims(claims).await;
    let db_name = unique_db_name("invalid_aud");
    let result = client.call_tool("create_database", Some(json!({"name": db_name}))).await;
    assert!(result.is_err(), "Esperado erro de autenticação para audience inválido");
    teardown_env(env).await;
}

// Teste: issuer inválido (espera erro de autenticação)
#[tokio::test]
async fn test_invalid_issuer_fails_authentication() {
    let env = setup_env().await.expect("Falha no setup do ambiente docker");
    let now = auth_helpers::current_timestamp_secs();
    let claims = auth_helpers::TestClaims {
        sub: "integration-test-user".to_string(),
        exp: now + 3600,
        iat: Some(now),
        nbf: Some(now),
        iss: Some("issuer-invalido".to_string()),
        aud: Some(serde_json::json!("integration-test-aud")),
        scope: Some("typedb:manage_databases typedb:admin_databases".to_string()),
        custom_claim: None,
    };
    let mut client = mcp_client_with_claims(claims).await;
    let db_name = unique_db_name("invalid_iss");
    let result = client.call_tool("create_database", Some(json!({"name": db_name}))).await;
    assert!(result.is_err(), "Esperado erro de autenticação para issuer inválido");
    teardown_env(env).await;
}

// Teste: criar banco com nome inválido (espera erro apropriado)
#[tokio::test]
async fn test_create_database_with_invalid_name_fails() {
    let env = setup_env().await.expect("Falha no setup do ambiente docker");
    let mut client = mcp_client_with_scope("typedb:manage_databases").await;
    // Corrigido: Garantir que todos os elementos do vetor são &str
    let long_invalid_name = "a".repeat(300);
    let invalid_names: Vec<&str> = vec!["", " ", "!@#", &long_invalid_name];
    for name in invalid_names {
        let result = client.call_tool("create_database", Some(json!({"name": name}))).await;
        assert!(result.is_err(), "Esperado erro ao criar banco com nome inválido: {}", name);
    }
    teardown_env(env).await;
}

// Teste: listar bancos após deleção (garante que banco removido não aparece)
#[tokio::test]
async fn test_list_databases_after_delete() {
    let env = setup_env().await.expect("Falha no setup do ambiente docker");
    let db_name = unique_db_name("list_after_delete");
    let mut client = mcp_client_with_scope("typedb:admin_databases typedb:manage_databases").await;
    let _ = client.call_tool("create_database", Some(json!({"name": db_name}))).await.expect("Falha ao criar banco");
    let _ = client.call_tool("delete_database", Some(json!({"name": db_name}))).await.expect("Falha ao deletar banco");
    let result = client.call_tool("list_databases", None).await;
    assert!(result.is_ok(), "Esperado sucesso ao listar bancos");
    // Corrigido: Acessar o conteúdo da resposta corretamente
    let content_item = &result.unwrap().content[0];
    let text_content = match content_item {
        rmcp::model::ResourceContents::TextResourceContents { text, .. } => text,
        _ => panic!("Conteúdo da resposta não é Texto como esperado."),
    };
    let dbs: Vec<String> = serde_json::from_str(text_content).expect("Resposta não é JSON array");
    assert!(!dbs.iter().any(|n| n == &db_name), "Banco deletado ainda aparece na lista");
    teardown_env(env).await;
}
#[tokio::test]
async fn test_create_database_succeeds() {
    let env = setup_env().await.expect("Falha no setup do ambiente docker");
    let db_name = unique_db_name("create_ok");
    let mut client = mcp_client_with_scope("typedb:manage_databases").await;
    let result = client.call_tool("create_database", Some(json!({"name": db_name}))).await;
    assert!(result.is_ok(), "Esperado sucesso ao criar banco: {:?}", result);
    // Corrigido: Acessar o conteúdo da resposta corretamente
    let content_item = &result.unwrap().content[0];
    let text_content = match content_item {
        rmcp::model::ResourceContents::TextResourceContents { text, .. } => text,
        _ => panic!("Conteúdo da resposta não é Texto como esperado."),
    };
    assert_eq!(text_content, "OK");
    teardown_env(env).await;
}

#[tokio::test]
async fn test_create_existing_database_fails() {
    let env = setup_env().await.expect("Falha no setup do ambiente docker");
    let db_name = unique_db_name("create_dup");
    let mut client = mcp_client_with_scope("typedb:manage_databases").await;
    // Cria banco
    let _ = client.call_tool("create_database", Some(json!({"name": db_name}))).await.expect("Falha ao criar banco inicial");
    // Tenta criar novamente
    let result = client.call_tool("create_database", Some(json!({"name": db_name}))).await;
    assert!(result.is_err(), "Esperado erro ao criar banco duplicado");
    if let Err(e) = result {
        match e {
            McpClientError::McpErrorResponse { code, message: _, data: _ } => {
                assert_eq!(code.0, rmcp::model::ErrorCode::INTERNAL_ERROR);
            },
            _ => panic!("Erro inesperado: {:?}", e),
        }
    }
    teardown_env(env).await;
}

#[tokio::test]
async fn test_list_databases_empty_on_fresh_server() {
    let env = setup_env().await.expect("Falha no setup do ambiente docker");
    let mut client = mcp_client_with_scope("typedb:manage_databases").await;
    let result = client.call_tool("list_databases", None).await;
    assert!(result.is_ok(), "Esperado sucesso ao listar bancos");
    // Corrigido: Acessar o conteúdo da resposta corretamente
    let content_item = &result.unwrap().content[0];
    let text_content = match content_item {
        rmcp::model::ResourceContents::TextResourceContents { text, .. } => text,
        _ => panic!("Conteúdo da resposta não é Texto como esperado."),
    };
    let dbs: Vec<String> = serde_json::from_str(text_content).expect("Resposta não é JSON array");
    assert!(dbs.is_empty(), "Esperado lista vazia de bancos");
    teardown_env(env).await;
}

#[tokio::test]
async fn test_list_databases_returns_created_databases() {
    let env = setup_env().await.expect("Falha no setup do ambiente docker");
    let db_name = unique_db_name("list");
    let mut client = mcp_client_with_scope("typedb:manage_databases").await;
    let _ = client.call_tool("create_database", Some(json!({"name": db_name}))).await.expect("Falha ao criar banco");
    let result = client.call_tool("list_databases", None).await;
    assert!(result.is_ok(), "Esperado sucesso ao listar bancos");
    // Corrigido: Acessar o conteúdo da resposta corretamente
    let content_item = &result.unwrap().content[0];
    let text_content = match content_item {
        rmcp::model::ResourceContents::TextResourceContents { text, .. } => text,
        _ => panic!("Conteúdo da resposta não é Texto como esperado."),
    };
    let dbs: Vec<String> = serde_json::from_str(text_content).expect("Resposta não é JSON array");
    assert!(dbs.iter().any(|n| n == &db_name), "Banco criado não aparece na lista");
    teardown_env(env).await;
}

#[tokio::test]
async fn test_database_exists_returns_true_for_existing_db() {
    let env = setup_env().await.expect("Falha no setup do ambiente docker");
    let db_name = unique_db_name("exists_true");
    let mut client = mcp_client_with_scope("typedb:manage_databases").await;
    let _ = client.call_tool("create_database", Some(json!({"name": db_name}))).await.expect("Falha ao criar banco");
    let result = client.call_tool("database_exists", Some(json!({"name": db_name}))).await;
    assert!(result.is_ok(), "Esperado sucesso ao checar existência");
    // Corrigido: Acessar o conteúdo da resposta corretamente
    let content_item = &result.unwrap().content[0];
    let text_content = match content_item {
        rmcp::model::ResourceContents::TextResourceContents { text, .. } => text,
        _ => panic!("Conteúdo da resposta não é Texto como esperado."),
    };
    assert_eq!(text_content, "true");
    teardown_env(env).await;
}

#[tokio::test]
async fn test_database_exists_returns_false_for_non_existent_db() {
    let env = setup_env().await.expect("Falha no setup do ambiente docker");
    let db_name = unique_db_name("exists_false");
    let mut client = mcp_client_with_scope("typedb:manage_databases").await;
    let result = client.call_tool("database_exists", Some(json!({"name": db_name}))).await;
    assert!(result.is_ok(), "Esperado sucesso ao checar existência");
    // Corrigido: Acessar o conteúdo da resposta corretamente
    let content_item = &result.unwrap().content[0];
    let text_content = match content_item {
        rmcp::model::ResourceContents::TextResourceContents { text, .. } => text,
        _ => panic!("Conteúdo da resposta não é Texto como esperado."),
    };
    assert_eq!(text_content, "false");
    teardown_env(env).await;
}

#[tokio::test]
async fn test_delete_database_succeeds() {
    let env = setup_env().await.expect("Falha no setup do ambiente docker");
    let db_name = unique_db_name("delete_ok");
    let mut client = mcp_client_with_scope("typedb:admin_databases typedb:manage_databases").await;
    let _ = client.call_tool("create_database", Some(json!({"name": db_name}))).await.expect("Falha ao criar banco");
    let result = client.call_tool("delete_database", Some(json!({"name": db_name}))).await;
    assert!(result.is_ok(), "Esperado sucesso ao deletar banco");
    // Corrigido: Acessar o conteúdo da resposta corretamente
    let content_item = &result.unwrap().content[0];
    let text_content = match content_item {
        rmcp::model::ResourceContents::TextResourceContents { text, .. } => text,
        _ => panic!("Conteúdo da resposta não é Texto como esperado."),
    };
    assert_eq!(text_content, "OK");
    // Confirma que não existe mais
    let result = client.call_tool("database_exists", Some(json!({"name": db_name}))).await;
    assert!(result.is_ok());
    // Corrigido: Acessar o conteúdo da resposta corretamente
    let content_item = &result.unwrap().content[0];
    let text_content = match content_item {
        rmcp::model::ResourceContents::TextResourceContents { text, .. } => text,
        _ => panic!("Conteúdo da resposta não é Texto como esperado."),
    };
    assert_eq!(text_content, "false");
    teardown_env(env).await;
}

#[tokio::test]
async fn test_delete_non_existent_database_fails() {
    let env = setup_env().await.expect("Falha no setup do ambiente docker");
    let db_name = unique_db_name("delete_missing");
    let mut client = mcp_client_with_scope("typedb:admin_databases").await;
    let result = client.call_tool("delete_database", Some(json!({"name": db_name}))).await;
    assert!(result.is_err(), "Esperado erro ao deletar banco inexistente");
    if let Err(e) = result {
        match e {
            McpClientError::McpErrorResponse { code, message: _, data: _ } => {
                assert_eq!(code.0, rmcp::model::ErrorCode::INTERNAL_ERROR);
            },
            _ => panic!("Erro inesperado: {:?}", e),
        }
    }
    teardown_env(env).await;
}

// (Opcional) Teste de autorização granular
#[tokio::test]
async fn test_delete_database_requires_admin_scope() {
    let env = setup_env().await.expect("Falha no setup do ambiente docker");
    let db_name = unique_db_name("delete_authz");
    let mut client = mcp_client_with_scope("typedb:manage_databases").await; // Não tem admin
    let _ = client.call_tool("create_database", Some(json!({"name": db_name}))).await.expect("Falha ao criar banco");
    let result = client.call_tool("delete_database", Some(json!({"name": db_name}))).await;
    assert!(result.is_err(), "Esperado erro de autorização ao deletar sem escopo admin");
    if let Err(e) = result {
        match e {
            McpClientError::McpErrorResponse { code, message: _, data: _ } => {
                assert_eq!(code.0, crate::error::MCP_ERROR_CODE_AUTHORIZATION_FAILED);
            },
            _ => panic!("Erro inesperado: {:?}", e),
        }
    }
    teardown_env(env).await;
}
