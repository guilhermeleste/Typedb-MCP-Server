// tests/integration/query_tool_tests.rs
// Licença Apache 2.0
// Copyright 2025 Guilherme Leste
//
// Testes de integração para as ferramentas MCP de consulta e manipulação de dados
// (query_read, insert_data, delete_data, update_data, validate_query) via MCP/WebSocket.
//
// Estes testes exigem:
// - Docker Compose com Typedb-MCP-Server, TypeDB e Mock Auth Server rodando
// - helpers de client, auth e docker em tests/common/

use std::time::Duration;
use serde_json::json;
// Ajustado para usar o common do crate de teste de integração
use crate::common::{client::TestMcpClient, auth_helpers::{self, Algorithm}, docker_helpers::{DockerComposeEnv, Result as DockerResult}};


const DOCKER_COMPOSE_FILE: &str = "docker-compose.test.yml";
const PROJECT_PREFIX: &str = "querytooltest";
const MCP_WS_ENDPOINT: &str = "ws://localhost:8787/mcp/ws";

fn unique_db_name(suffix: &str) -> String {
    // Corrigido para usar as_simple().to_string()
    format!("test_query_ops_{}_{}", suffix, uuid::Uuid::new_v4().as_simple().to_string())
}

async fn setup_env() -> std::result::Result<DockerComposeEnv, String> {
    let env = DockerComposeEnv::new(DOCKER_COMPOSE_FILE, PROJECT_PREFIX);
    match env.up() {
        DockerResult::Ok(_) => (),
        DockerResult::Err(e) => return Err(format!("Falha ao iniciar ambiente docker (env.up): {}", e)),
    }
    match env.wait_for_service_healthy("typedb-mcp-server", Duration::from_secs(60)).await {
        DockerResult::Ok(_) => (),
        DockerResult::Err(e) => return Err(format!("Falha ao esperar por typedb-mcp-server: {}", e)),
    }
    match env.wait_for_service_healthy("typedb", Duration::from_secs(60)).await {
        DockerResult::Ok(_) => (),
        DockerResult::Err(e) => return Err(format!("Falha ao esperar por typedb: {}", e)),
    }
    match env.wait_for_service_healthy("mock-auth-server", Duration::from_secs(30)).await {
        DockerResult::Ok(_) => (),
        DockerResult::Err(e) => return Err(format!("Falha ao esperar por mock-auth-server: {}", e)),
    }
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
    let token = auth_helpers::generate_test_jwt(claims, Algorithm::HS256);
    TestMcpClient::connect(MCP_WS_ENDPOINT, Some(token), Duration::from_secs(10), Duration::from_secs(10)).await.expect("Falha ao conectar MCP client")
}

// Helpers para criar e deletar banco de dados de teste
async fn create_test_db(client: &mut TestMcpClient, db_name: &str) {
    // Corrigido: Revertido para call_tool
    let result = client.call_tool("create_database", Some(json!({"name": db_name}))).await;
    assert!(result.is_ok(), "Falha ao criar banco de teste: {:?}", result);
}
async fn delete_test_db(client: &mut TestMcpClient, db_name: &str) {
    // Corrigido: Revertido para call_tool
    let _ = client.call_tool("delete_database", Some(json!({"name": db_name}))).await;
}

// Helper para definir um esquema base para os testes
async fn define_base_schema(client: &mut TestMcpClient, db_name: &str) {
    let schema = r#"
        define
            person sub entity, owns name, owns age;
            name sub attribute, value string;
            age sub attribute, value long;
            employment sub relation, relates employee, relates employer;
    "#;
    // Corrigido: Revertido para call_tool
    let result = client.call_tool("define_schema", Some(json!({"database_name": db_name, "schema_definition": schema}))).await;
    assert!(result.is_ok(), "Falha ao definir schema base: {:?}", result);
}

#[tokio::test]
async fn test_insert_person_and_query_by_name() {
    let env = setup_env().await.expect("Falha no setup do ambiente docker");
    let db_name = unique_db_name("insert_person");
    let mut client = mcp_client_with_scope("typedb:manage_databases typedb:manage_schema typedb:write_data typedb:read_data").await;
    create_test_db(&mut client, &db_name).await;
    define_base_schema(&mut client, &db_name).await;
    // Inserção
    let insert_query = r#"insert $p isa person, has name "Alice", has age 30;"#;
    // Corrigido: Revertido para call_tool
    let result = client.call_tool("insert_data", Some(json!({"database_name": db_name, "query": insert_query}))).await;
    assert!(result.is_ok(), "Falha ao inserir dados: {:?}", result);
    // Consulta
    let read_query = "match $p isa person, has name $n; get $n;";
    // Corrigido: Revertido para call_tool
    let result = client.call_tool("query_read", Some(json!({"database_name": db_name, "query": read_query}))).await;
    assert!(result.is_ok(), "Falha ao consultar dados: {:?}", result);
    let response_content = result.unwrap().content;
    assert!(!response_content.is_empty(), "Resposta de query_read não deve estar vazia");
    let content_item = &response_content[0];
    
    let json_value: serde_json::Value = match content_item {
        rmcp::model::ResourceContents::TextResourceContents { text, mime_type: _, uri: _ } => {
            serde_json::from_str(text).expect("Falha ao parsear JSON da resposta de query_read")
        },
        // Adicionando BlobResourceContents como uma possibilidade, embora TextResourceContents seja mais provável para JSON.
        rmcp::model::ResourceContents::BlobResourceContents { blob, mime_type: _, uri: _ } => {
             // Tentar decodificar de base64 se for um blob, assumindo que pode ser JSON codificado.
             // Isso é uma suposição; o comportamento real dependerá de como o servidor envia JSON em blobs.
            let decoded_blob = base64::decode(blob).expect("Falha ao decodificar blob base64");
            let text_content = String::from_utf8(decoded_blob).expect("Falha ao converter blob para String UTF-8");
            serde_json::from_str(&text_content).expect("Falha ao parsear JSON do blob decodificado")
        }
        _ => panic!("Conteúdo da resposta não é Texto (contendo JSON) ou Blob (contendo JSON) como esperado."),
    };

    // A validação aqui pode precisar ser mais robusta dependendo da estrutura exata do JSON.
    // Ex: Se for um array de objetos: json_value.as_array().unwrap()[0].get("n").unwrap().as_str().unwrap() == "Alice"
    assert!(json_value.to_string().contains("Alice"), "Resultado não contém \'Alice\'");
    delete_test_db(&mut client, &db_name).await;
    teardown_env(env).await;
}

#[tokio::test]
async fn test_query_read_aggregate_count() {
    let env = setup_env().await.expect("Falha no setup do ambiente docker");
    let db_name = unique_db_name("aggregate_count");
    let mut client = mcp_client_with_scope("typedb:manage_databases typedb:manage_schema typedb:write_data typedb:read_data").await;
    create_test_db(&mut client, &db_name).await;
    define_base_schema(&mut client, &db_name).await;
    // Inserção
    let insert_query = r#"insert $p isa person, has name "Bob", has age 40;"#;
    // Corrigido: Revertido para call_tool
    let _ = client.call_tool("insert_data", Some(json!({"database_name": db_name, "query": insert_query}))).await;
    // Consulta de agregação
    let agg_query = "match $p isa person; count;";
    // Corrigido: Revertido para call_tool
    let result = client.call_tool("query_read", Some(json!({"database_name": db_name, "query": agg_query}))).await;
    assert!(result.is_ok(), "Falha ao consultar agregação: {:?}", result);
    let response_content = result.unwrap().content;
    assert!(!response_content.is_empty(), "Resposta de query_read não deve estar vazia");
    let content_item = &response_content[0];

    let json_value: serde_json::Value = match content_item {
        rmcp::model::ResourceContents::TextResourceContents { text, .. } => {
            serde_json::from_str(text).expect("Falha ao parsear JSON da resposta de query_read (aggregate)")
        },
        rmcp::model::ResourceContents::BlobResourceContents { blob, .. } => {
            let decoded_blob = base64::decode(blob).expect("Falha ao decodificar blob base64 (aggregate)");
            let text_content = String::from_utf8(decoded_blob).expect("Falha ao converter blob para String UTF-8 (aggregate)");
            serde_json::from_str(&text_content).expect("Falha ao parsear JSON do blob decodificado (aggregate)")
        }
        _ => panic!("Conteúdo da resposta não é Texto (contendo JSON) ou Blob (contendo JSON) como esperado para agregação."),
    };
    assert_eq!(json_value, &json!(1), "Resultado de agregação não é 1");
    delete_test_db(&mut client, &db_name).await;
    teardown_env(env).await;
}

#[tokio::test]
async fn test_update_attribute_value() {
    let env = setup_env().await.expect("Falha no setup do ambiente docker");
    let db_name = unique_db_name("update_attr");
    let mut client = mcp_client_with_scope("typedb:manage_databases typedb:manage_schema typedb:write_data typedb:read_data").await;
    create_test_db(&mut client, &db_name).await;
    define_base_schema(&mut client, &db_name).await;
    // Inserção
    let insert_query = r#"insert $p isa person, has name "Carol", has age 25;"#;
    // Corrigido: Revertido para call_tool
    let _ = client.call_tool("insert_data", Some(json!({"database_name": db_name, "query": insert_query}))).await;
    // Atualização
    let update_query = r#"match $p isa person, has name "Carol", has age $a; delete $p has $a; insert $p has age 26;"#;
    // Corrigido: Revertido para call_tool
    let result = client.call_tool("update_data", Some(json!({"database_name": db_name, "query": update_query}))).await;
    assert!(result.is_ok(), "Falha ao atualizar atributo: {:?}", result);
    // Consulta
    let read_query = r#"match $p isa person, has name "Carol", has age $a; get $a;"#;
    // Corrigido: Revertido para call_tool
    let result = client.call_tool("query_read", Some(json!({"database_name": db_name, "query": read_query}))).await;
    assert!(result.is_ok(), "Falha ao consultar atributo atualizado: {:?}", result);
    let response_content = result.unwrap().content;
    assert!(!response_content.is_empty(), "Resposta de query_read não deve estar vazia");
    let content_item = &response_content[0];

    let json_value: serde_json::Value = match content_item {
        rmcp::model::ResourceContents::TextResourceContents { text, .. } => {
            serde_json::from_str(text).expect("Falha ao parsear JSON da resposta de query_read (update)")
        },
        rmcp::model::ResourceContents::BlobResourceContents { blob, .. } => {
            let decoded_blob = base64::decode(blob).expect("Falha ao decodificar blob base64 (update)");
            let text_content = String::from_utf8(decoded_blob).expect("Falha ao converter blob para String UTF-8 (update)");
            serde_json::from_str(&text_content).expect("Falha ao parsear JSON do blob decodificado (update)")
        }
        _ => panic!("Conteúdo da resposta não é Texto (contendo JSON) ou Blob (contendo JSON) como esperado para update."),
    };
    assert!(json_value.to_string().contains("26"), "Valor atualizado não encontrado");
    delete_test_db(&mut client, &db_name).await;
    teardown_env(env).await;
}

#[tokio::test]
async fn test_delete_entity_and_verify_deletion() {
    let env = setup_env().await.expect("Falha no setup do ambiente docker");
    let db_name = unique_db_name("delete_entity");
    let mut client = mcp_client_with_scope("typedb:manage_databases typedb:manage_schema typedb:write_data typedb:read_data").await;
    create_test_db(&mut client, &db_name).await;
    define_base_schema(&mut client, &db_name).await;
    // Inserção
    let insert_query = r#"insert $p isa person, has name "Dave", has age 50;"#;
    // Corrigido: Revertido para call_tool
    let _ = client.call_tool("insert_data", Some(json!({"database_name": db_name, "query": insert_query}))).await;
    // Deleção
    let delete_query = r#"match $p isa person, has name "Dave"; delete $p;"#;
    // Corrigido: Revertido para call_tool
    let result = client.call_tool("delete_data", Some(json!({"database_name": db_name, "query": delete_query}))).await;
    assert!(result.is_ok(), "Falha ao deletar entidade: {:?}", result);
    // Consulta
    let read_query = r#"match $p isa person, has name "Dave"; get $p;"#;
    // Corrigido: Revertido para call_tool
    let result = client.call_tool("query_read", Some(json!({"database_name": db_name, "query": read_query}))).await;
    assert!(result.is_ok(), "Falha ao consultar entidade após deleção: {:?}", result);
    let response_content = result.unwrap().content;
    assert!(!response_content.is_empty(), "Resposta de query_read não deve estar vazia");
    let content_item = &response_content[0];

    let json_value: serde_json::Value = match content_item {
        rmcp::model::ResourceContents::TextResourceContents { text, .. } => {
            serde_json::from_str(text).expect("Falha ao parsear JSON da resposta de query_read (delete)")
        },
        rmcp::model::ResourceContents::BlobResourceContents { blob, .. } => {
            let decoded_blob = base64::decode(blob).expect("Falha ao decodificar blob base64 (delete)");
            let text_content = String::from_utf8(decoded_blob).expect("Falha ao converter blob para String UTF-8 (delete)");
            serde_json::from_str(&text_content).expect("Falha ao parsear JSON do blob decodificado (delete)")
        }
        _ => panic!("Conteúdo da resposta não é Texto (contendo JSON) ou Blob (contendo JSON) como esperado para delete."),
    };
    assert!(json_value.as_array().map_or(true, |arr| arr.is_empty()), "Entidade não foi removida");
    delete_test_db(&mut client, &db_name).await;
    teardown_env(env).await;
}

#[tokio::test]
async fn test_validate_syntactically_correct_query_returns_valid() {
    let env = setup_env().await.expect("Falha no setup do ambiente docker");
    let db_name = unique_db_name("validate_ok");
    let mut client = mcp_client_with_scope("typedb:manage_databases typedb:manage_schema typedb:write_data typedb:read_data").await;
    create_test_db(&mut client, &db_name).await;
    define_base_schema(&mut client, &db_name).await;
    let valid_query = "match $p isa person; get $p;";
    // Corrigido: Revertido para call_tool
    let result = client.call_tool("validate_query", Some(json!({"database_name": db_name, "query": valid_query, "intended_transaction_type": "read"}))).await;
    assert!(result.is_ok(), "Falha ao validar query válida: {:?}", result);
    let response_content = result.unwrap().content;
    assert!(!response_content.is_empty(), "Resposta de validate_query não deve estar vazia");
    let content_item = &response_content[0];

    let text_value = match content_item {
        rmcp::model::ResourceContents::TextResourceContents { text, .. } => text.to_string(), // Clonar para possuir a String
        rmcp::model::ResourceContents::BlobResourceContents { blob, .. } => {
            // Se o resultado da validação puder vir como blob, decodificar.
            // Geralmente, "valid" ou mensagens de erro são texto simples.
            let decoded_blob = base64::decode(blob).expect("Falha ao decodificar blob base64 (validate_ok)");
            String::from_utf8(decoded_blob).expect("Falha ao converter blob para String UTF-8 (validate_ok)")
        }
        _ => panic!("Conteúdo da resposta não é Texto ou Blob como esperado para validate_query."),
    };
    assert_eq!(text_value, "valid");
    delete_test_db(&mut client, &db_name).await;
    teardown_env(env).await;
}

#[tokio::test]
async fn test_validate_query_with_syntax_error_returns_error_message() {
    let env = setup_env().await.expect("Falha no setup do ambiente docker");
    let db_name = unique_db_name("validate_syntax_err");
    let mut client = mcp_client_with_scope("typedb:manage_databases typedb:manage_schema typedb:write_data typedb:read_data").await;
    create_test_db(&mut client, &db_name).await;
    define_base_schema(&mut client, &db_name).await;
    let invalid_query = "match $p isa person get $p;"; // falta o ponto e vírgula
    // Corrigido: Revertido para call_tool
    let result = client.call_tool("validate_query", Some(json!({"database_name": db_name, "query": invalid_query, "intended_transaction_type": "read"}))).await;
    assert!(result.is_ok(), "Falha ao validar query inválida: {:?}", result);
    let response_content = result.unwrap().content;
    assert!(!response_content.is_empty(), "Resposta de validate_query não deve estar vazia");
    let content_item = &response_content[0];

    let text_value = match content_item {
        rmcp::model::ResourceContents::TextResourceContents { text, .. } => text.to_string(), // Clonar para possuir a String
        rmcp::model::ResourceContents::BlobResourceContents { blob, .. } => {
            let decoded_blob = base64::decode(blob).expect("Falha ao decodificar blob base64 (validate_syntax_err)");
            String::from_utf8(decoded_blob).expect("Falha ao converter blob para String UTF-8 (validate_syntax_err)")
        }
        _ => panic!("Conteúdo da resposta não é Texto ou Blob como esperado para validate_query com erro."),
    };
    assert!(text_value.contains("syntax error"), "Mensagem de erro de sintaxe não encontrada");
    delete_test_db(&mut client, &db_name).await;
    teardown_env(env).await;
}

// Teste de autorização granular
#[tokio::test]
async fn test_data_operations_require_correct_scopes() {
    let env = setup_env().await.expect("Falha no setup do ambiente docker");
    let db_name = unique_db_name("authz_scope");
    let mut client = mcp_client_with_scope("typedb:manage_databases typedb:manage_schema").await; // Não tem write_data/read_data
    create_test_db(&mut client, &db_name).await;
    define_base_schema(&mut client, &db_name).await;
    let insert_query = r#"insert $p isa person, has name "Eve", has age 22;"#;
    // Corrigido: Revertido para call_tool
    let result = client.call_tool("insert_data", Some(json!({"database_name": db_name, "query": insert_query}))).await;
    assert!(result.is_err(), "Esperado erro de permissão para insert_data sem escopo");
    let read_query = "match $p isa person; get $p;";
    // Corrigido: Revertido para call_tool
    let result = client.call_tool("query_read", Some(json!({"database_name": db_name, "query": read_query}))).await;
    assert!(result.is_err(), "Esperado erro de permissão para query_read sem escopo");
    let delete_query = "match $p isa person; delete $p;";
    // Corrigido: Revertido para call_tool
    let result = client.call_tool("delete_data", Some(json!({"database_name": db_name, "query": delete_query}))).await;
    assert!(result.is_err(), "Esperado erro de permissão para delete_data sem escopo");
    let update_query = r#"match $p isa person, has name "Eve", has age $a; delete $p has $a; insert $p has age 23;"#;
    // Corrigido: Revertido para call_tool
    let result = client.call_tool("update_data", Some(json!({"database_name": db_name, "query": update_query}))).await;
    assert!(result.is_err(), "Esperado erro de permissão para update_data sem escopo");
    let valid_query = "match $p isa person; get $p;";
    // Corrigido: Revertido para call_tool
    let result = client.call_tool("validate_query", Some(json!({"database_name": db_name, "query": valid_query, "intended_transaction_type": "read"}))).await;
    assert!(result.is_err(), "Esperado erro de permissão para validate_query sem escopo");
    delete_test_db(&mut client, &db_name).await;
    teardown_env(env).await;
}

// Removido o placeholder de DockerResult e DockerComposeEnv daqui,
// pois eles devem vir de crate::common::docker_helpers.
// Se docker_helpers ainda não estiver implementado, os testes não compilarão completamente,
// mas os erros de sintaxe anteriores neste arquivo devem ser resolvidos.
