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

use crate::common::client::TestMcpClient;
use crate::common::docker_helpers::DockerComposeEnv;

static INIT: Once = Once::new();

fn setup_tracing() {
    INIT.call_once(|| {
        let _ = tracing_subscriber::fmt::try_init();
    });
}

const TEST_COMPOSE_FILE: &str = "docker-compose.test.yml";
const TEST_PROJECT_PREFIX: &str = "resource_tests";
const MCP_SERVER_WS_URL: &str = "ws://localhost:8788/mcp/ws";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

async fn setup_test_environment() -> (DockerComposeEnv, String) {
    setup_tracing();
    info!("Configurando ambiente de teste para resource_tests...");
    let docker_env = DockerComposeEnv::new(TEST_COMPOSE_FILE, TEST_PROJECT_PREFIX);
    docker_env.down(true).expect("Falha ao derrubar ambiente docker-compose pré-existente");
    docker_env.up().expect("Falha ao subir ambiente docker-compose");
    docker_env.wait_for_service_healthy("typedb-server-it", Duration::from_secs(60)).await.expect("TypeDB não ficou saudável");
    docker_env.wait_for_service_healthy("typedb-mcp-server-it", Duration::from_secs(30)).await.expect("MCP Server não ficou saudável");
    info!("Ambiente de teste configurado.");
    (docker_env, MCP_SERVER_WS_URL.to_string())
}

/// Testa se a listagem de recursos estáticos retorna URIs e nomes esperados.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
async fn test_list_static_resources_contains_expected_uris_and_names() {
    let (docker_env, server_url) = setup_test_environment().await;
    let mut client = TestMcpClient::connect(&server_url, None, CONNECT_TIMEOUT, REQUEST_TIMEOUT).await.expect("Conexão MCP falhou");
    let result = client.list_resources(None).await.expect("Falha ao listar recursos");
    let uris: Vec<_> = result.resources.iter().map(|r| r.uri.as_str()).collect();
    assert!(uris.contains(&"info://typeql/query_types"), "Faltou info://typeql/query_types");
    assert!(uris.contains(&"info://typedb/transactions_and_tools"), "Faltou info://typedb/transactions_and_tools");
    
    let query_types = result.resources.iter().find(|r| r.uri == "info://typeql/query_types").expect("Recurso QUERY_TYPES_URI não encontrado");
    assert_eq!(query_types.name, "Guia Rápido: Tipos de Consulta TypeQL");
    assert_eq!(query_types.mime_type.as_deref(), Some("text/plain"));
    assert!(query_types.description.as_ref().expect("Descrição ausente").contains("TypeQL"));
    
    let tx_guide = result.resources.iter().find(|r| r.uri == "info://typedb/transactions_and_tools").expect("Recurso TRANSACTIONS_GUIDE_URI não encontrado");
    assert_eq!(tx_guide.name, "Guia: Transações TypeDB e Ferramentas MCP");
    assert_eq!(tx_guide.mime_type.as_deref(), Some("text/plain"));
    assert!(tx_guide.description.as_ref().expect("Descrição ausente").contains("TypeDB"));

    // Assert de teardown: fechamento do cliente e ambiente docker
    assert!(client.close().await.is_ok(), "Falha ao fechar cliente no teardown");
    assert!(docker_env.down(true).is_ok(), "Falha ao derrubar ambiente docker-compose no teardown");
}

/// Testa se a listagem de templates de recurso inclui o template de schema.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
async fn test_list_resource_templates_contains_schema_template() {
    let (docker_env, server_url) = setup_test_environment().await;
    let mut client = TestMcpClient::connect(&server_url, None, CONNECT_TIMEOUT, REQUEST_TIMEOUT).await.expect("Conexão MCP falhou");
    // O método correto é list_resources, não list_resource_templates
    let result = client.list_resources(None).await.expect("Falha ao listar recursos");
    let templates: Vec<&str> = result.resources.iter().filter_map(|r| r.uri_template.as_deref()).collect();
    assert!(templates.contains(&"schema://current/{database_name}?type={schema_type}"), "Template de schema ausente");
    // Não há estrutura ResourceTemplate, então validamos pelo campo name e uri_template
    let schema_template = result.resources.iter().find(|r| r.uri_template.as_deref() == Some("schema://current/{database_name}?type={schema_type}"));
    assert!(schema_template.is_some(), "Template de schema não encontrado");
    let schema_template = schema_template.unwrap();
    assert_eq!(schema_template.name, "Esquema Atual do Banco de Dados");
    assert_eq!(schema_template.mime_type.as_deref(), Some("text/plain"));
    assert!(schema_template.description.as_ref().expect("Descrição ausente").contains("Retorna o esquema TypeQL"));

    assert!(client.close().await.is_ok(), "Falha ao fechar cliente no teardown");
    assert!(docker_env.down(true).is_ok(), "Falha ao derrubar ambiente docker-compose no teardown");
}

/// Testa se a leitura do recurso QUERY_TYPES retorna o conteúdo correto.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
async fn test_read_query_types_resource_returns_correct_content() {
    let (docker_env, server_url) = setup_test_environment().await;
    let mut client = TestMcpClient::connect(&server_url, None, CONNECT_TIMEOUT, REQUEST_TIMEOUT).await.expect("Conexão MCP falhou");
    let result = client.read_resource("info://typeql/query_types").await.expect("Falha ao ler recurso");
    assert_eq!(result.contents.len(), 1, "Esperado um único conteúdo de recurso");
    let contents = &result.contents[0];
    if let ResourceContents::TextResourceContents { text, uri, mime_type } = contents {
        assert!(text.contains("Guia Rápido dos Tipos de Consulta TypeQL"), "Conteúdo inesperado: {}", text);
        assert_eq!(uri, "info://typeql/query_types");
        assert_eq!(mime_type.as_deref(), Some("text/plain"));
    } else {
        panic!("Tipo de conteúdo inesperado: {:?}", contents);
    }
    assert!(client.close().await.is_ok(), "Falha ao fechar cliente no teardown");
    assert!(docker_env.down(true).is_ok(), "Falha ao derrubar ambiente docker-compose no teardown");
}

/// Testa se a leitura do recurso TRANSACTIONS_GUIDE retorna o conteúdo correto.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
async fn test_read_transactions_guide_resource_returns_correct_content() {
    let (docker_env, server_url) = setup_test_environment().await;
    let mut client = TestMcpClient::connect(&server_url, None, CONNECT_TIMEOUT, REQUEST_TIMEOUT).await.expect("Conexão MCP falhou");
    let result = client.read_resource("info://typedb/transactions_and_tools").await.expect("Falha ao ler recurso");
    assert_eq!(result.contents.len(), 1, "Esperado um único conteúdo de recurso");
    let contents = &result.contents[0];
    if let ResourceContents::TextResourceContents { text, uri, mime_type } = contents {
        assert!(text.contains("Guia de Transações TypeDB e Ferramentas MCP"), "Conteúdo inesperado: {}", text);
        assert_eq!(uri, "info://typedb/transactions_and_tools");
        assert_eq!(mime_type.as_deref(), Some("text/plain"));
    } else {
        panic!("Tipo de conteúdo inesperado: {:?}", contents);
    }
    assert!(client.close().await.is_ok(), "Falha ao fechar cliente no teardown");
    assert!(docker_env.down(true).is_ok(), "Falha ao derrubar ambiente docker-compose no teardown");
}

/// Testa se a leitura de um recurso estático inexistente retorna erro apropriado.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
async fn test_read_invalid_static_resource_uri_fails() {
    let (docker_env, server_url) = setup_test_environment().await;
    let mut client = TestMcpClient::connect(&server_url, None, CONNECT_TIMEOUT, REQUEST_TIMEOUT).await.expect("Conexão MCP falhou");
    let err = client.read_resource("info://typeql/nao_existe").await.expect_err("Esperava erro para recurso inexistente");
    
    // Usando o tipo de erro correto de TestMcpClient
    match err {
        crate::common::client::McpClientError::McpErrorResponse { code, message, data, .. } => {
            assert_eq!(code, ErrorCode::RESOURCE_NOT_FOUND);
            assert!(message.contains("info://typeql/nao_existe"), "Mensagem de erro não contém URI: {}", message);
            assert!(data.is_none() || data.as_ref().map_or(true, |d| d.is_null()), "Dados de erro inesperados: {:?}", data);
        }
        e => panic!("Tipo de erro inesperado: {:?}", e),
    }
    assert!(client.close().await.is_ok(), "Falha ao fechar cliente no teardown");
    assert!(docker_env.down(true).is_ok(), "Falha ao derrubar ambiente docker-compose no teardown");
}

/// Testa se a leitura do schema completo dinâmico retorna o conteúdo correto.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
async fn test_read_dynamic_schema_full_succeeds() {
    let (docker_env, server_url) = setup_test_environment().await;
    let mut client = TestMcpClient::connect(&server_url, None, CONNECT_TIMEOUT, REQUEST_TIMEOUT).await.expect("Conexão MCP falhou");
    let db_name = format!("test_resource_db_{}", Uuid::new_v4().simple()); // Corrigido para simple()
    let schema = "define person sub entity, owns name; name sub attribute, value string;";
    
    // Usando call_tool de TestMcpClient
    client.call_tool("typedb/db_create", Some(serde_json::json!({"database_name": db_name}))).await.expect("Falha ao criar banco");
    client.call_tool("typedb/schema_write", Some(serde_json::json!({"database_name": db_name, "schema": schema}))).await.expect("Falha ao definir schema");
    
    let uri = format!("schema://current/{}?type=full", db_name);
    let result = client.read_resource(&uri).await.expect("Falha ao ler schema");
    assert_eq!(result.contents.len(), 1, "Esperado um único conteúdo de recurso");
    let contents = &result.contents[0];
    if let ResourceContents::TextResourceContents { text, uri: ret_uri, mime_type } = contents {
        assert!(text.contains("person sub entity"), "Schema não retornado corretamente: {}", text);
        assert_eq!(ret_uri, &uri);
        assert_eq!(mime_type.as_deref(), Some("application/typeql")); // Mime type para schema TypeQL
    } else {
        panic!("Tipo de conteúdo inesperado: {:?}", contents);
    }
    client.call_tool("typedb/db_delete", Some(serde_json::json!({"database_name": db_name}))).await.expect("Falha ao deletar banco");
    assert!(client.close().await.is_ok(), "Falha ao fechar cliente no teardown");
    assert!(docker_env.down(true).is_ok(), "Falha ao derrubar ambiente docker-compose no teardown");
}

/// Testa se a leitura do schema apenas tipos retorna o conteúdo correto.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
async fn test_read_dynamic_schema_types_only_succeeds() {
    let (docker_env, server_url) = setup_test_environment().await;
    let mut client = TestMcpClient::connect(&server_url, None, CONNECT_TIMEOUT, REQUEST_TIMEOUT).await.expect("Conexão MCP falhou");
    let db_name = format!("test_resource_db_{}", Uuid::new_v4().simple()); // Corrigido para simple()
    let schema = "define person sub entity, owns name; name sub attribute, value string; rule inference-rule: when { $x isa person; } then { $x has-inferred-knowledge true; };";
    
    client.call_tool("typedb/db_create", Some(serde_json::json!({"database_name": db_name}))).await.expect("Falha ao criar banco");
    client.call_tool("typedb/schema_write", Some(serde_json::json!({"database_name": db_name, "schema": schema}))).await.expect("Falha ao definir schema");
    
    let uri = format!("schema://current/{}?type=types", db_name);
    let result = client.read_resource(&uri).await.expect("Falha ao ler schema types");
    assert_eq!(result.contents.len(), 1, "Esperado um único conteúdo de recurso");
    let contents = &result.contents[0];
    if let ResourceContents::TextResourceContents { text, uri: ret_uri, mime_type } = contents {
        assert!(text.contains("person sub entity"), "Schema types não retornado corretamente: {}", text);
        assert!(!text.contains("inference-rule"), "Schema types não deveria conter regras: {}", text);
        assert_eq!(ret_uri, &uri);
        assert_eq!(mime_type.as_deref(), Some("application/typeql")); // Mime type para schema TypeQL
    } else {
        panic!("Tipo de conteúdo inesperado: {:?}", contents);
    }
    client.call_tool("typedb/db_delete", Some(serde_json::json!({"database_name": db_name}))).await.expect("Falha ao deletar banco");
    assert!(client.close().await.is_ok(), "Falha ao fechar cliente no teardown");
    assert!(docker_env.down(true).is_ok(), "Falha ao derrubar ambiente docker-compose no teardown");
}

/// Testa se a leitura do schema apenas regras retorna o conteúdo correto.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
async fn test_read_dynamic_schema_rules_only_succeeds() {
    let (docker_env, server_url) = setup_test_environment().await;
    let mut client = TestMcpClient::connect(&server_url, None, CONNECT_TIMEOUT, REQUEST_TIMEOUT).await.expect("Conexão MCP falhou");
    let db_name = format!("test_resource_db_{}", Uuid::new_v4().simple());
    let schema = "define person sub entity, owns name; name sub attribute, value string; rule inference-rule: when { $x isa person; } then { $x has-inferred-knowledge true; };";
    
    client.call_tool("typedb/db_create", Some(serde_json::json!({"database_name": db_name}))).await.expect("Falha ao criar banco");
    client.call_tool("typedb/schema_write", Some(serde_json::json!({"database_name": db_name, "schema": schema}))).await.expect("Falha ao definir schema");
    
    let uri = format!("schema://current/{}?type=rules", db_name);
    let result = client.read_resource(&uri).await.expect("Falha ao ler schema rules");
    assert_eq!(result.contents.len(), 1, "Esperado um único conteúdo de recurso");
    let contents = &result.contents[0];
    if let ResourceContents::TextResourceContents { text, uri: ret_uri, mime_type } = contents {
        assert!(text.contains("inference-rule sub rule"), "Schema rules não retornado corretamente: {}", text);
        assert!(!text.contains("person sub entity"), "Schema rules não deveria conter tipos: {}", text);
        assert_eq!(ret_uri, &uri);
        assert_eq!(mime_type.as_deref(), Some("application/typeql"));
    } else {
        panic!("Tipo de conteúdo inesperado: {:?}", contents);
    }
    client.call_tool("typedb/db_delete", Some(serde_json::json!({"database_name": db_name}))).await.expect("Falha ao deletar banco");
    assert!(client.close().await.is_ok(), "Falha ao fechar cliente no teardown");
    assert!(docker_env.down(true).is_ok(), "Falha ao derrubar ambiente docker-compose no teardown");
}


/// Testa se a leitura do schema de um banco inexistente retorna erro apropriado.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
async fn test_read_dynamic_schema_for_nonexistent_db_fails() {
    let (docker_env, server_url) = setup_test_environment().await;
    let mut client = TestMcpClient::connect(&server_url, None, CONNECT_TIMEOUT, REQUEST_TIMEOUT).await.expect("Conexão MCP falhou");
    let db_name = "db_nao_existe_schema_test";
    let uri = format!("schema://current/{}?type=full", db_name);
    let err = client.read_resource(&uri).await.expect_err("Esperava erro para schema de DB inexistente");
    match err {
        crate::common::client::McpClientError::McpErrorResponse { code, message, .. } => {
            assert_eq!(code, ErrorCode::RESOURCE_NOT_FOUND); // Usar RESOURCE_NOT_FOUND pois DATABASE_NOT_FOUND não existe
            assert!(message.contains(db_name), "Mensagem de erro não contém nome do DB: {}", message);
        }
        e => panic!("Tipo de erro inesperado: {:?}", e),
    }
    assert!(client.close().await.is_ok(), "Falha ao fechar cliente no teardown");
    assert!(docker_env.down(true).is_ok(), "Falha ao derrubar ambiente docker-compose no teardown");
}

/// Testa se a leitura do schema com parâmetro type inválido retorna erro apropriado.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
async fn test_read_dynamic_schema_with_invalid_type_param_fails() {
    let (docker_env, server_url) = setup_test_environment().await;
    let mut client = TestMcpClient::connect(&server_url, None, CONNECT_TIMEOUT, REQUEST_TIMEOUT).await.expect("Conexão MCP falhou");
    let db_name = format!("test_resource_db_{}", Uuid::new_v4().simple());
    client.call_tool("typedb/db_create", Some(serde_json::json!({"database_name": db_name}))).await.expect("Falha ao criar banco");
    
    let uri = format!("schema://current/{}?type=invalidtype", db_name);
    let err = client.read_resource(&uri).await.expect_err("Esperava erro para parâmetro type inválido");
    match err {
        crate::common::client::McpClientError::McpErrorResponse { code, message, .. } => {
            assert_eq!(code, ErrorCode::INVALID_PARAMS); // Usar INVALID_PARAMS pois INVALID_PARAMETER não existe
            assert!(message.to_lowercase().contains("invalid schema type parameter"), "Mensagem de erro inesperada: {}", message);
        }
        e => panic!("Tipo de erro inesperado: {:?}", e),
    }
    client.call_tool("typedb/db_delete", Some(serde_json::json!({"database_name": db_name}))).await.expect("Falha ao deletar banco");
    assert!(client.close().await.is_ok(), "Falha ao fechar cliente no teardown");
    assert!(docker_env.down(true).is_ok(), "Falha ao derrubar ambiente docker-compose no teardown");
}
