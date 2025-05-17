// tests/integration/resource_tests.rs
// Testes de integração para a funcionalidade de Recursos (Resources) do Typedb-MCP-Server.
// Garante a listagem, leitura e tratamento de erros para recursos estáticos e dinâmicos (schema).

// Copyright 2025 Guilherme Leste
// Licença Apache 2.0

use std::time::Duration;
use std::sync::Once;
use uuid::Uuid;
use tracing::info;

use rmcp::model::{ResourceContents, ErrorCode};

mod common {
    pub use crate::common::client::*;
    pub use crate::common::docker_helpers::*;
    pub use crate::common::auth_helpers::*;
}

static INIT: Once = Once::new();

fn setup_tracing() {
    INIT.call_once(|| {
        let _ = tracing_subscriber::fmt::try_init();
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_list_static_resources_contains_expected_uris_and_names() {
    setup_tracing();
    let (_docker, server_url) = common::setup_docker_and_get_ws_url().await;
    let mut client = common::TestMcpClient::connect(&server_url, None, Duration::from_secs(20), Duration::from_secs(10)).await.expect("Conexão MCP falhou");
    let result = client.list_resources(None).await.expect("Falha ao listar recursos");
    let uris: Vec<_> = result.resources.iter().map(|r| r.uri.as_str()).collect();
    assert!(uris.contains(&"info://typeql/query_types"), "Faltou info://typeql/query_types");
    assert!(uris.contains(&"info://typedb/transactions_and_tools"), "Faltou info://typedb/transactions_and_tools");
    // Checagem detalhada dos campos
    let query_types = result.resources.iter().find(|r| r.uri == "info://typeql/query_types").expect("Recurso QUERY_TYPES_URI não encontrado");
    assert_eq!(query_types.name, "Guia Rápido: Tipos de Consulta TypeQL");
    assert_eq!(query_types.mime_type.as_deref(), Some("text/plain"));
    assert!(query_types.description.as_ref().unwrap().contains("TypeQL"));
    let tx_guide = result.resources.iter().find(|r| r.uri == "info://typedb/transactions_and_tools").expect("Recurso TRANSACTIONS_GUIDE_URI não encontrado");
    assert_eq!(tx_guide.name, "Guia: Transações TypeDB e Ferramentas MCP");
    assert_eq!(tx_guide.mime_type.as_deref(), Some("text/plain"));
    assert!(tx_guide.description.as_ref().unwrap().contains("TypeDB"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_list_resource_templates_contains_schema_template() {
    setup_tracing();
    let (_docker, server_url) = common::setup_docker_and_get_ws_url().await;
    let mut client = common::TestMcpClient::connect(&server_url, None, Duration::from_secs(20), Duration::from_secs(10)).await.expect("Conexão MCP falhou");
    let result = client.list_resource_templates(None).await.expect("Falha ao listar templates");
    let templates: Vec<_> = result.resource_templates.iter().map(|t| t.uri_template.as_str()).collect();
    assert!(templates.contains(&"schema://current/{database_name}?type={schema_type}"), "Template de schema ausente");
    // Checagem detalhada dos campos
    let schema_template = result.resource_templates.iter().find(|t| t.uri_template == "schema://current/{database_name}?type={schema_type}").expect("Template de schema não encontrado");
    assert_eq!(schema_template.name, "Esquema Atual do Banco de Dados");
    assert_eq!(schema_template.mime_type.as_deref(), Some("text/plain"));
    assert!(schema_template.description.as_ref().unwrap().contains("Retorna o esquema TypeQL"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_read_query_types_resource_returns_correct_content() {
    setup_tracing();
    let (_docker, server_url) = common::setup_docker_and_get_ws_url().await;
    let mut client = common::TestMcpClient::connect(&server_url, None, Duration::from_secs(20), Duration::from_secs(10)).await.expect("Conexão MCP falhou");
    let result = client.read_resource("info://typeql/query_types").await.expect("Falha ao ler recurso");
    let contents = &result.contents[0];
    if let ResourceContents::TextResourceContents { text, uri, mime_type } = contents {
        assert!(text.contains("Guia Rápido dos Tipos de Consulta TypeQL"), "Conteúdo inesperado");
        assert_eq!(uri, "info://typeql/query_types");
        assert_eq!(mime_type.as_deref(), Some("text/plain"));
    } else {
        panic!("Tipo de conteúdo inesperado");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_read_transactions_guide_resource_returns_correct_content() {
    setup_tracing();
    let (_docker, server_url) = common::setup_docker_and_get_ws_url().await;
    let mut client = common::TestMcpClient::connect(&server_url, None, Duration::from_secs(20), Duration::from_secs(10)).await.expect("Conexão MCP falhou");
    let result = client.read_resource("info://typedb/transactions_and_tools").await.expect("Falha ao ler recurso");
    let contents = &result.contents[0];
    if let ResourceContents::TextResourceContents { text, uri, mime_type } = contents {
        assert!(text.contains("Guia de Transações TypeDB e Ferramentas MCP"), "Conteúdo inesperado");
        assert_eq!(uri, "info://typedb/transactions_and_tools");
        assert_eq!(mime_type.as_deref(), Some("text/plain"));
    } else {
        panic!("Tipo de conteúdo inesperado");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_read_invalid_static_resource_uri_fails() {
    setup_tracing();
    let (_docker, server_url) = common::setup_docker_and_get_ws_url().await;
    let mut client = common::TestMcpClient::connect(&server_url, None, Duration::from_secs(20), Duration::from_secs(10)).await.expect("Conexão MCP falhou");
    let err = client.read_resource("info://typeql/nao_existe").await.expect_err("Esperava erro para recurso inexistente");
    match err {
        common::McpClientError::McpErrorResponse { code, message, data } => {
            assert_eq!(code, ErrorCode::RESOURCE_NOT_FOUND);
            assert!(message.contains("info://typeql/nao_existe"));
            assert!(data.is_none() || data.as_ref().unwrap().is_null());
        }
        _ => panic!("Tipo de erro inesperado"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_read_dynamic_schema_full_succeeds() {
    setup_tracing();
    let (_docker, server_url) = common::setup_docker_and_get_ws_url().await;
    let mut client = common::TestMcpClient::connect(&server_url, None, Duration::from_secs(20), Duration::from_secs(10)).await.expect("Conexão MCP falhou");
    let db_name = format!("test_resource_db_{}", Uuid::new_v4().to_simple());
    let schema = "define person sub entity, owns name; name sub attribute, value string;";
    client.call_tool("create_database", Some(serde_json::json!({"name": db_name}))).await.expect("Falha ao criar banco");
    client.call_tool("define_schema", Some(serde_json::json!({"database": db_name, "schema": schema}))).await.expect("Falha ao definir schema");
    let uri = format!("schema://current/{}?type=full", db_name);
    let result = client.read_resource(&uri).await.expect("Falha ao ler schema");
    let contents = &result.contents[0];
    if let ResourceContents::TextResourceContents { text, uri: ret_uri, mime_type } = contents {
        assert!(text.contains("person sub entity"), "Schema não retornado corretamente");
        assert_eq!(ret_uri, &uri);
        assert_eq!(mime_type.as_deref(), Some("text/plain+typeql"));
    } else {
        panic!("Tipo de conteúdo inesperado");
    }
    client.call_tool("delete_database", Some(serde_json::json!({"name": db_name}))).await.expect("Falha ao deletar banco");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_read_dynamic_schema_types_only_succeeds() {
    setup_tracing();
    let (_docker, server_url) = common::setup_docker_and_get_ws_url().await;
    let mut client = common::TestMcpClient::connect(&server_url, None, Duration::from_secs(20), Duration::from_secs(10)).await.expect("Conexão MCP falhou");
    let db_name = format!("test_resource_db_{}", Uuid::new_v4().to_simple());
    let schema = "define person sub entity, owns name; name sub attribute, value string;";
    client.call_tool("create_database", Some(serde_json::json!({"name": db_name}))).await.expect("Falha ao criar banco");
    client.call_tool("define_schema", Some(serde_json::json!({"database": db_name, "schema": schema}))).await.expect("Falha ao definir schema");
    let uri = format!("schema://current/{}?type=types", db_name);
    let result = client.read_resource(&uri).await.expect("Falha ao ler schema types");
    let contents = &result.contents[0];
    if let ResourceContents::TextResourceContents { text, uri: ret_uri, mime_type } = contents {
        assert!(text.contains("person sub entity"), "Schema types não retornado corretamente");
        assert_eq!(ret_uri, &uri);
        assert_eq!(mime_type.as_deref(), Some("text/plain+typeql"));
    } else {
        panic!("Tipo de conteúdo inesperado");
    }
    client.call_tool("delete_database", Some(serde_json::json!({"name": db_name}))).await.expect("Falha ao deletar banco");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_read_dynamic_schema_for_non_existent_db_fails() {
    setup_tracing();
    let (_docker, server_url) = common::setup_docker_and_get_ws_url().await;
    let mut client = common::TestMcpClient::connect(&server_url, None, Duration::from_secs(20), Duration::from_secs(10)).await.expect("Conexão MCP falhou");
    let db_name = format!("nao_existe_{}", Uuid::new_v4().to_simple());
    let uri = format!("schema://current/{}?type=full", db_name);
    let err = client.read_resource(&uri).await.expect_err("Esperava erro para banco inexistente");
    match err {
        common::McpClientError::McpErrorResponse { code, message, data } => {
            assert_eq!(code, ErrorCode::RESOURCE_NOT_FOUND);
            assert!(message.contains(&db_name));
            assert!(data.is_some());
        }
        _ => panic!("Tipo de erro inesperado"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_read_dynamic_schema_with_malformed_uri_fails() {
    setup_tracing();
    let (_docker, server_url) = common::setup_docker_and_get_ws_url().await;
    let mut client = common::TestMcpClient::connect(&server_url, None, Duration::from_secs(20), Duration::from_secs(10)).await.expect("Conexão MCP falhou");
    let uri = "schema://current/?type=full";
    let err = client.read_resource(uri).await.expect_err("Esperava erro para URI malformada");
    match err {
        common::McpClientError::McpErrorResponse { code, message, data } => {
            assert_eq!(code, ErrorCode::RESOURCE_NOT_FOUND);
            assert!(message.contains("ausente") || message.contains("inválida"));
            assert!(data.is_none() || data.as_ref().unwrap().is_null());
        }
        _ => panic!("Tipo de erro inesperado"),
    }
}
