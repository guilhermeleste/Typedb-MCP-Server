// tests/integration/query_tool_tests.rs
// Licença Apache 2.0
// Copyright 2025 Guilherme Leste

use std::time::Duration;
use serde_json::json;
// Ajustado para usar o common do crate de teste de integração
use crate::common::{
    client::TestMcpClient,
    auth_helpers::{self, Algorithm},
    docker_helpers::DockerComposeEnv,
};
use rmcp::model::{CallToolResult, RawContent};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};


const DOCKER_COMPOSE_FILE: &str = "docker-compose.test.yml";
const PROJECT_PREFIX: &str = "querytooltest";
// REMOVIDO: const MCP_WS_ENDPOINT: &str = "ws://localhost:8788/mcp/ws";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);


fn unique_db_name(suffix: &str) -> String {
    format!("test_query_ops_{}_{}", suffix, uuid::Uuid::new_v4().simple().to_string())
}

async fn setup_env() -> std::result::Result<DockerComposeEnv, String> {
    let env = DockerComposeEnv::new(DOCKER_COMPOSE_FILE, PROJECT_PREFIX);
    
    match env.up() {
        Ok(_) => (),
        Err(e) => return Err(format!("env.up() failed: {}", e)),
    }

    match env.wait_for_service_healthy("typedb-server-it", Duration::from_secs(90)).await {
        Ok(_) => (),
        Err(e) => return Err(format!("wait_for_service_healthy typedb-server-it failed: {}", e)),
    }
    
    match env.wait_for_service_healthy("typedb-mcp-server-it", Duration::from_secs(60)).await {
        Ok(_) => (),
        Err(e) => return Err(format!("wait_for_service_healthy typedb-mcp-server-it failed: {}", e)),
    }
    
    match env.wait_for_service_healthy("mock-oauth2-server", Duration::from_secs(30)).await {
        Ok(_) => (),
        Err(e) => return Err(format!("wait_for_service_healthy mock-oauth2-server failed: {}", e)),
    }
    
    Ok(env)
}


async fn teardown_env(env: DockerComposeEnv) {
    let _ = env.down(true);
}

async fn mcp_client_with_scope(env: &DockerComposeEnv, scope: &str) -> TestMcpClient {
    let mcp_service_internal_port = 8089; // Porta interna do typedb-mcp-server-it
    let mapped_host_port = env.get_service_port("typedb-mcp-server-it", mcp_service_internal_port)
        .expect("Falha ao obter a porta do host mapeada para typedb-mcp-server-it");
    let mcp_ws_endpoint = format!("ws://localhost:{}/mcp/ws", mapped_host_port);

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
    TestMcpClient::connect(&mcp_ws_endpoint, Some(token), CONNECT_TIMEOUT, REQUEST_TIMEOUT)
        .await
        .expect("Falha ao conectar MCP client")
}

// Helpers para criar e deletar banco de dados de teste
async fn create_test_db(client: &mut TestMcpClient, db_name: &str) {
    let result = client.call_tool("create_database", Some(json!({"name": db_name}))).await;
    assert!(result.is_ok(), "Falha ao criar banco de teste '{}': {:?}", db_name, result.err());
}
async fn delete_test_db(client: &mut TestMcpClient, db_name: &str) {
    let _ = client.call_tool("delete_database", Some(json!({"name": db_name}))).await;
}

// Helper para definir um esquema base para os testes
async fn define_base_schema(client: &mut TestMcpClient, db_name: &str) {
    let schema = r#"
        define
            person sub entity, owns name, owns age;
            name sub attribute, value string;
            age sub attribute, value long;
    "#; // Removido employment para simplificar, pode ser adicionado se necessário
    let result = client.call_tool("define_schema", Some(json!({"database_name": db_name, "schema_definition": schema}))).await;
    assert!(result.is_ok(), "Falha ao definir schema base para '{}': {:?}", db_name, result.err());
}

/// Helper para extrair o conteúdo de texto de um CallToolResult.
fn get_text_from_call_result(call_result: CallToolResult) -> String {
    assert!(!call_result.content.is_empty(), "A resposta da ferramenta MCP não pode estar vazia.");
    let content_item = &call_result.content[0]; // Pega o primeiro item de conteúdo
    match &content_item.raw { // Acessa o RawContent através do Deref implícito
        RawContent::Text(text_content) => {
            text_content.text.clone()
        },
        RawContent::Resource(resource_content) => {
            // Se o recurso for texto, extrai. Útil se query_read retornar ResourceContents::TextResourceContents.
            match &resource_content.resource {
                rmcp::model::ResourceContents::TextResourceContents { text, .. } => text.clone(),
                rmcp::model::ResourceContents::BlobResourceContents { blob, .. } => {
                    let decoded_bytes = BASE64_STANDARD.decode(blob).expect("Falha ao decodificar blob base64 no helper");
                    String::from_utf8(decoded_bytes).expect("Blob decodificado não é UTF-8 válido no helper")
                }
                // _ => panic!("Conteúdo do recurso não é texto no helper: {:?}", resource_content.resource),
            }
        }
        _ => panic!("Conteúdo da resposta não é Texto ou Recurso textual como esperado. Conteúdo: {:?}", content_item.raw),
    }
}


#[tokio::test]
#[serial_test::serial]
async fn test_insert_person_and_query_by_name() {
    let docker_env = setup_env().await.expect("Falha no setup do ambiente docker");
    let db_name = unique_db_name("insert_person");
    let mut client = mcp_client_with_scope(&docker_env, "typedb:manage_databases typedb:manage_schema typedb:write_data typedb:read_data").await;
    create_test_db(&mut client, &db_name).await;
    define_base_schema(&mut client, &db_name).await;

    let insert_query = r#"insert $p isa person, has name "Alice", has age 30;"#;
    let result = client.call_tool("insert_data", Some(json!({"database_name": db_name, "query": insert_query}))).await;
    assert!(result.is_ok(), "Falha ao inserir dados: {:?}", result.err());

    let read_query = "match $p isa person, has name $n; get $n;";
    let result = client.call_tool("query_read", Some(json!({"database_name": db_name, "query": read_query}))).await;
    assert!(result.is_ok(), "Falha ao consultar dados: {:?}", result.err());
    
    let text_content = get_text_from_call_result(result.unwrap());
    let json_value: serde_json::Value = serde_json::from_str(&text_content).expect("Falha ao parsear JSON da resposta de query_read");
    
    assert!(json_value.is_array() && !json_value.as_array().unwrap().is_empty(), "Resultado deveria ser um array não vazio");
    assert!(json_value.to_string().contains("Alice"), "Resultado não contém 'Alice'");
    
    delete_test_db(&mut client, &db_name).await;
    docker_env.down(true).expect("Falha ao derrubar ambiente docker-compose");
}

#[tokio::test]
#[serial_test::serial]
async fn test_query_read_aggregate_count() {
    let docker_env = setup_env().await.expect("Falha no setup do ambiente docker");
    let db_name = unique_db_name("aggregate_count");
    let mut client = mcp_client_with_scope(&docker_env, "typedb:manage_databases typedb:manage_schema typedb:write_data typedb:read_data").await;
    create_test_db(&mut client, &db_name).await;
    define_base_schema(&mut client, &db_name).await;

    let insert_query = r#"insert $p isa person, has name "Bob", has age 40;"#;
    let _ = client.call_tool("insert_data", Some(json!({"database_name": db_name, "query": insert_query}))).await;

    let agg_query = "match $p isa person; count;";
    let result = client.call_tool("query_read", Some(json!({"database_name": db_name, "query": agg_query}))).await;
    assert!(result.is_ok(), "Falha ao consultar agregação: {:?}", result.err());

    let text_content = get_text_from_call_result(result.unwrap());
    let json_value: serde_json::Value = serde_json::from_str(&text_content).expect("Falha ao parsear JSON da resposta de query_read (aggregate)");
    
    assert_eq!(json_value, json!(1), "Resultado de agregação não é 1"); // Corrigido para comparar com json!(1)
    
    delete_test_db(&mut client, &db_name).await;
    docker_env.down(true).expect("Falha ao derrubar ambiente docker-compose");
}

#[tokio::test]
#[serial_test::serial]
async fn test_update_attribute_value() {
    let docker_env = setup_env().await.expect("Falha no setup do ambiente docker");
    let db_name = unique_db_name("update_attr");
    let mut client = mcp_client_with_scope(&docker_env, "typedb:manage_databases typedb:manage_schema typedb:write_data typedb:read_data").await;
    create_test_db(&mut client, &db_name).await;
    define_base_schema(&mut client, &db_name).await;

    let insert_query = r#"insert $p isa person, has name "Carol", has age 25;"#;
    let _ = client.call_tool("insert_data", Some(json!({"database_name": db_name, "query": insert_query}))).await;

    let update_query = r#"match $p isa person, has name "Carol", has age $a; delete $p has $a; insert $p has age 26;"#;
    let result = client.call_tool("update_data", Some(json!({"database_name": db_name, "query": update_query}))).await;
    assert!(result.is_ok(), "Falha ao atualizar atributo: {:?}", result.err());

    let read_query = r#"match $p isa person, has name "Carol", has age $a; get $a;"#;
    let result = client.call_tool("query_read", Some(json!({"database_name": db_name, "query": read_query}))).await;
    assert!(result.is_ok(), "Falha ao consultar atributo atualizado: {:?}", result.err());
    
    let text_content = get_text_from_call_result(result.unwrap());
    let json_value: serde_json::Value = serde_json::from_str(&text_content).expect("Falha ao parsear JSON da resposta de query_read (update)");

    assert!(json_value.is_array() && !json_value.as_array().unwrap().is_empty(), "Resultado da consulta de atualização não deveria ser vazio");
    // A estrutura exata da resposta para `get $a;` pode variar.
    // Se for [{"a": {"integer": 26}}], então:
    assert!(json_value.to_string().contains("26"), "Valor atualizado (26) não encontrado na resposta: {}", json_value);
    
    delete_test_db(&mut client, &db_name).await;
    docker_env.down(true).expect("Falha ao derrubar ambiente docker-compose");
}

#[tokio::test]
#[serial_test::serial]
async fn test_delete_entity_and_verify_deletion() {
    let docker_env = setup_env().await.expect("Falha no setup do ambiente docker");
    let db_name = unique_db_name("delete_entity");
    let mut client = mcp_client_with_scope(&docker_env, "typedb:manage_databases typedb:manage_schema typedb:write_data typedb:read_data").await;
    create_test_db(&mut client, &db_name).await;
    define_base_schema(&mut client, &db_name).await;

    let insert_query = r#"insert $p isa person, has name "Dave", has age 50;"#;
    let _ = client.call_tool("insert_data", Some(json!({"database_name": db_name, "query": insert_query}))).await;

    let delete_query = r#"match $p isa person, has name "Dave"; delete $p;"#;
    let result = client.call_tool("delete_data", Some(json!({"database_name": db_name, "query": delete_query}))).await;
    assert!(result.is_ok(), "Falha ao deletar entidade: {:?}", result.err());

    let read_query = r#"match $p isa person, has name "Dave"; get $p;"#;
    let result = client.call_tool("query_read", Some(json!({"database_name": db_name, "query": read_query}))).await;
    assert!(result.is_ok(), "Falha ao consultar entidade após deleção: {:?}", result.err());
    
    let text_content = get_text_from_call_result(result.unwrap());
    let json_value: serde_json::Value = serde_json::from_str(&text_content).expect("Falha ao parsear JSON da resposta de query_read (delete)");
    
    assert!(json_value.as_array().map_or(true, |arr| arr.is_empty()), "Entidade não foi removida, resultado: {}", json_value);
    
    delete_test_db(&mut client, &db_name).await;
    docker_env.down(true).expect("Falha ao derrubar ambiente docker-compose");
}

#[tokio::test]
#[serial_test::serial]
async fn test_validate_syntactically_correct_query_returns_valid() {
    let docker_env = setup_env().await.expect("Falha no setup do ambiente docker");
    let db_name = unique_db_name("validate_ok");
    let mut client = mcp_client_with_scope(&docker_env, "typedb:manage_databases typedb:manage_schema typedb:read_data typedb:validate_queries").await;
    create_test_db(&mut client, &db_name).await;
    define_base_schema(&mut client, &db_name).await;
    
    let valid_query = "match $p isa person; get $p;";
    let result = client.call_tool("validate_query", Some(json!({"database_name": db_name, "query": valid_query, "intended_transaction_type": "read"}))).await;
    assert!(result.is_ok(), "Falha ao validar query válida: {:?}", result.err());
    
    let text_value = get_text_from_call_result(result.unwrap());
    assert_eq!(text_value.trim().to_lowercase(), "valid"); // Comparar com "valid" em minúsculas e trim
    
    delete_test_db(&mut client, &db_name).await;
    docker_env.down(true).expect("Falha ao derrubar ambiente docker-compose");
}

#[tokio::test]
#[serial_test::serial]
async fn test_validate_query_with_syntax_error_returns_error_message() {
    let docker_env = setup_env().await.expect("Falha no setup do ambiente docker");
    let db_name = unique_db_name("validate_syntax_err");
    let mut client = mcp_client_with_scope(&docker_env, "typedb:manage_databases typedb:manage_schema typedb:read_data typedb:validate_queries").await;
    create_test_db(&mut client, &db_name).await;
    define_base_schema(&mut client, &db_name).await;
    
    let invalid_query = "match $p isa person get $p;"; // falta o ponto e vírgula
    let result = client.call_tool("validate_query", Some(json!({"database_name": db_name, "query": invalid_query, "intended_transaction_type": "read"}))).await;
    assert!(result.is_ok(), "Validação de query inválida deveria retornar OK (com mensagem de erro no conteúdo): {:?}", result.err()); // A ferramenta em si não falha, o conteúdo indica o erro.
    
    let text_value = get_text_from_call_result(result.unwrap());
    assert!(text_value.to_lowercase().contains("error") || text_value.to_lowercase().contains("fail"), "Mensagem de erro de sintaxe não encontrada ou não indicativa de erro: '{}'", text_value); // Checagem mais genérica
    
    delete_test_db(&mut client, &db_name).await;
    docker_env.down(true).expect("Falha ao derrubar ambiente docker-compose");
}

#[tokio::test]
#[serial_test::serial]
async fn test_data_operations_require_correct_scopes() {
    let docker_env = setup_env().await.expect("Falha no setup do ambiente docker");
    let db_name = unique_db_name("authz_scope_query");
    let mut client_admin_only = mcp_client_with_scope(&docker_env, "typedb:manage_databases typedb:manage_schema").await;
    create_test_db(&mut client_admin_only, &db_name).await;
    define_base_schema(&mut client_admin_only, &db_name).await;

    let insert_query = r#"insert $p isa person, has name "Eve", has age 22;"#;
    let result_insert = client_admin_only.call_tool("insert_data", Some(json!({"database_name": db_name, "query": insert_query}))).await;
    assert!(result_insert.is_err(), "Esperado erro de permissão para insert_data sem escopo 'typedb:write_data'");

    let read_query = "match $p isa person; get $p;";
    let result_read = client_admin_only.call_tool("query_read", Some(json!({"database_name": db_name, "query": read_query}))).await;
    assert!(result_read.is_err(), "Esperado erro de permissão para query_read sem escopo 'typedb:read_data'");

    // ... (testes para delete_data, update_data, validate_query com escopos insuficientes) ...

    // Limpeza com um cliente que TEM permissão para deletar
    let mut client_full_perms = mcp_client_with_scope(&docker_env, "typedb:admin_databases").await;
    delete_test_db(&mut client_full_perms, &db_name).await;
    docker_env.down(true).expect("Falha ao derrubar ambiente docker-compose");
}