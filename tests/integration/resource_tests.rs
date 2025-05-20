// tests/integration/resource_tests.rs
// Licença Apache 2.0
// Copyright 2025 Guilherme Leste

use std::sync::Once;
use std::time::Duration;
use serde_json::json;
use uuid::Uuid;
use tracing::info; // 'error' não é usado diretamente, então removido por enquanto

// Assumindo que 'tests/lib.rs' ou 'tests/integration.rs' declara 'pub mod common;'
// e 'common/mod.rs' reexporta os itens necessários.
use crate::common::{
    TestMcpClient, McpClientError,
    DockerComposeEnv, // Usar o módulo auth_helpers para chamar auth_helpers::generate_test_jwt etc.
                  // Algorithm não é usado diretamente aqui.
};
use anyhow::{Context as AnyhowContext, Result};

// rmcp::model::ErrorCode é usado para comparações, os outros podem ser desnecessários se
// get_text_from_call_result lida com eles.
use rmcp::model::{ResourceContents, ErrorCode};
// RawContent, Resource, ResourceTemplate podem não ser necessários se get_text_from_call_result os abstrai.

// A constante MCP_ERROR_CODE_AUTHORIZATION_FAILED não parece ser usada neste arquivo.
// use typedb_mcp_server_lib::error::MCP_ERROR_CODE_AUTHORIZATION_FAILED;


const TEST_COMPOSE_FILE: &str = "docker-compose.test.yml";
const TEST_PROJECT_PREFIX: &str = "resource_tests";
const MCP_SERVER_WS_URL: &str = "ws://localhost:8788/mcp/ws";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

static INIT: Once = Once::new();

fn setup_tracing() {
    INIT.call_once(|| {
        let crate_name = env!("CARGO_CRATE_NAME"); // Obtém o nome do crate atual (o crate de teste)
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| format!("info,{}=info", crate_name).into()); // Default para info e info para o crate de teste
        
        let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
    });
}

fn unique_db_name(prefix: &str) -> String {
    format!("{}_{}", prefix, Uuid::new_v4().simple())
}

async fn setup_test_environment() -> Result<(DockerComposeEnv, String)> {
    setup_tracing();
    info!("Configurando ambiente de teste para resource_tests...");
    let docker_env = DockerComposeEnv::new(TEST_COMPOSE_FILE, TEST_PROJECT_PREFIX);
    docker_env.down(true).map_err(|e| eprintln!("Nota: falha no down inicial: {}",e)).ok();
    docker_env.up().context("Falha ao subir ambiente docker (env.up)")?;
    docker_env.wait_for_service_healthy("typedb-server-it", Duration::from_secs(90)).await.context("TypeDB não saudável")?;
    docker_env.wait_for_service_healthy("typedb-mcp-server-it", Duration::from_secs(60)).await.context("MCP Server não saudável")?;
    docker_env.wait_for_service_healthy("mock-oauth2-server", Duration::from_secs(30)).await.context("Mock Auth Server não saudável")?;
    info!("Ambiente de teste configurado.");
    Ok((docker_env, MCP_SERVER_WS_URL.to_string()))
}

pub async fn create_test_db(client: &mut TestMcpClient, db_name: &str) -> Result<()> {
    client.call_tool("create_database", Some(json!({"name": db_name}))).await
        .with_context(|| format!("Falha ao criar banco de teste '{}'", db_name))?;
    Ok(())
}
pub async fn delete_test_db(client: &mut TestMcpClient, db_name: &str) -> Result<()> {
    client.call_tool("delete_database", Some(json!({"name": db_name}))).await
        .with_context(|| format!("Falha ao deletar banco de teste '{}'", db_name))
        .map(|_| ())
}


#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
pub async fn test_list_static_resources_contains_expected_uris_and_names() -> Result<()> {
    let (docker_env, server_url) = setup_test_environment().await?;
    let mut client = TestMcpClient::connect(&server_url, None, CONNECT_TIMEOUT, REQUEST_TIMEOUT).await.context("Conexão MCP falhou")?;
    
    let result = client.list_resources(None).await.context("Falha ao listar recursos")?;
    
    let uris: Vec<_> = result.resources.iter().map(|r_annotated| r_annotated.raw.uri.as_str()).collect();
    assert!(uris.contains(&"info://typeql/query_types"), "Faltou info://typeql/query_types na lista: {:?}", uris);
    assert!(uris.contains(&"info://typedb/transactions_and_tools"), "Faltou info://typedb/transactions_and_tools na lista: {:?}", uris);
    
    let query_types_resource = result.resources.iter().find(|r_annotated| r_annotated.raw.uri == "info://typeql/query_types")
        .expect("Recurso QUERY_TYPES_URI não encontrado");
    assert_eq!(query_types_resource.raw.name, "Guia Rápido: Tipos de Consulta TypeQL");
    assert_eq!(query_types_resource.raw.mime_type.as_deref(), Some("text/plain"));
    assert!(query_types_resource.raw.description.as_ref().expect("Descrição ausente para query_types").contains("TypeQL"));
    
    let tx_guide_resource = result.resources.iter().find(|r_annotated| r_annotated.raw.uri == "info://typedb/transactions_and_tools")
        .expect("Recurso TRANSACTIONS_GUIDE_URI não encontrado");
    assert_eq!(tx_guide_resource.raw.name, "Guia: Transações TypeDB e Ferramentas MCP");
    assert_eq!(tx_guide_resource.raw.mime_type.as_deref(), Some("text/plain"));
    assert!(tx_guide_resource.raw.description.as_ref().expect("Descrição ausente para tx_guide").contains("TypeDB"));

    client.close().await.context("Falha ao fechar cliente no teardown")?;
    docker_env.down(true).context("Falha ao derrubar ambiente docker-compose no teardown")?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
pub async fn test_list_resource_templates_contains_schema_template() -> Result<()> {
    let (docker_env, server_url) = setup_test_environment().await?;
    let mut client = TestMcpClient::connect(&server_url, None, CONNECT_TIMEOUT, REQUEST_TIMEOUT).await.context("Conexão MCP falhou")?;
    
    let result = client.list_resource_templates(None).await.context("Falha ao listar templates de recursos")?;
    
    let template_uris: Vec<_> = result.resource_templates.iter().map(|template_annotated| template_annotated.raw.uri_template.as_str()).collect();
    assert!(template_uris.contains(&"schema://current/{database_name}?type={schema_type}"), "Template de schema URI ausente: {:?}", template_uris);
    
    let schema_template_annotated = result.resource_templates.iter().find(|template_annotated| template_annotated.raw.uri_template == "schema://current/{database_name}?type={schema_type}")
        .expect("Template de schema não encontrado na lista de templates");
    
    let schema_template_raw = &schema_template_annotated.raw;
    assert_eq!(schema_template_raw.name, "Esquema Atual do Banco de Dados");
    assert_eq!(schema_template_raw.mime_type.as_deref(), Some("text/plain"));
    assert!(schema_template_raw.description.as_ref().expect("Descrição ausente para template de schema").contains("Retorna o esquema TypeQL"));

    client.close().await.context("Falha ao fechar cliente no teardown")?;
    docker_env.down(true).context("Falha ao derrubar ambiente docker-compose no teardown")?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
async fn test_read_query_types_resource_returns_correct_content() -> Result<()> {
    let (docker_env, server_url) = setup_test_environment().await?;
    let mut client = TestMcpClient::connect(&server_url, None, CONNECT_TIMEOUT, REQUEST_TIMEOUT).await.context("Conexão MCP falhou")?;
    let result = client.read_resource("info://typeql/query_types").await.context("Falha ao ler recurso")?;
    assert_eq!(result.contents.len(), 1, "Esperado um único conteúdo de recurso");
    let contents = &result.contents[0];
    if let ResourceContents::TextResourceContents { text, uri, mime_type } = contents {
        assert!(text.contains("Guia Rápido dos Tipos de Consulta TypeQL"), "Conteúdo inesperado: {}", text);
        assert_eq!(uri, "info://typeql/query_types");
        assert_eq!(mime_type.as_deref(), Some("text/plain"));
    } else {
        panic!("Tipo de conteúdo inesperado: {:?}", contents);
    }
    client.close().await.context("Falha ao fechar cliente no teardown")?;
    docker_env.down(true).context("Falha ao derrubar ambiente docker-compose no teardown")?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
async fn test_read_transactions_guide_resource_returns_correct_content() -> Result<()> {
    let (docker_env, server_url) = setup_test_environment().await?;
    let mut client = TestMcpClient::connect(&server_url, None, CONNECT_TIMEOUT, REQUEST_TIMEOUT).await.context("Conexão MCP falhou")?;
    let result = client.read_resource("info://typedb/transactions_and_tools").await.context("Falha ao ler recurso")?;
    assert_eq!(result.contents.len(), 1, "Esperado um único conteúdo de recurso");
    let contents = &result.contents[0];
    if let ResourceContents::TextResourceContents { text, uri, mime_type } = contents {
        assert!(text.contains("Guia de Transações TypeDB e Ferramentas MCP"), "Conteúdo inesperado: {}", text);
        assert_eq!(uri, "info://typedb/transactions_and_tools");
        assert_eq!(mime_type.as_deref(), Some("text/plain"));
    } else {
        panic!("Tipo de conteúdo inesperado: {:?}", contents);
    }
    client.close().await.context("Falha ao fechar cliente no teardown")?;
    docker_env.down(true).context("Falha ao derrubar ambiente docker-compose no teardown")?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
async fn test_read_invalid_static_resource_uri_fails() -> Result<()> {
    let (docker_env, server_url) = setup_test_environment().await?;
    let mut client = TestMcpClient::connect(&server_url, None, CONNECT_TIMEOUT, REQUEST_TIMEOUT).await.context("Conexão MCP falhou")?;
    let err_result = client.read_resource("info://typeql/nao_existe").await.expect_err("Esperava erro para recurso inexistente");
    
    match err_result {
        McpClientError::McpErrorResponse { code, message, data } => {
            assert_eq!(code.0, ErrorCode::RESOURCE_NOT_FOUND.0);
            assert!(message.contains("info://typeql/nao_existe"), "Mensagem de erro não contém URI: {}", message);
            assert!(data.is_none() || data.as_ref().map_or(true, |d| d.is_null()), "Dados de erro inesperados: {:?}", data);
        }
        e => panic!("Tipo de erro inesperado: {:?}", e),
    }
    client.close().await.context("Falha ao fechar cliente no teardown")?;
    docker_env.down(true).context("Falha ao derrubar ambiente docker-compose no teardown")?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
async fn test_read_dynamic_schema_full_succeeds() -> Result<()> {
    let (docker_env, server_url) = setup_test_environment().await?;
    let mut client = TestMcpClient::connect(&server_url, None, CONNECT_TIMEOUT, REQUEST_TIMEOUT).await.expect("Conexão MCP falhou");
    let db_name = unique_db_name("schema_full");
    let schema = "define person sub entity, owns name; name sub attribute, value string;";
    
    create_test_db(&mut client, &db_name).await?;
    client.call_tool("define_schema", Some(json!({"database_name": db_name, "schema_definition": schema}))).await.context("Falha ao definir schema")?;
    
    let uri = format!("schema://current/{}?type=full", db_name);
    let result = client.read_resource(&uri).await.context("Falha ao ler schema")?;
    assert_eq!(result.contents.len(), 1, "Esperado um único conteúdo de recurso");
    let contents = &result.contents[0];
    if let ResourceContents::TextResourceContents { text, uri: ret_uri, mime_type } = contents {
        assert!(text.contains("person sub entity"), "Schema não retornado corretamente: {}", text);
        assert!(text.contains("name sub attribute"), "Schema não retornado corretamente: {}", text);
        assert_eq!(ret_uri, &uri);
        assert_eq!(mime_type.as_deref(), Some("application/typeql"));
    } else {
        panic!("Tipo de conteúdo inesperado para schema: {:?}", contents);
    }
    delete_test_db(&mut client, &db_name).await?;
    client.close().await.context("Falha ao fechar cliente no teardown")?;
    docker_env.down(true).context("Falha ao derrubar ambiente docker-compose no teardown")?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
async fn test_read_dynamic_schema_types_only_succeeds() -> Result<()> {
    let (docker_env, server_url) = setup_test_environment().await?;
    let mut client = TestMcpClient::connect(&server_url, None, CONNECT_TIMEOUT, REQUEST_TIMEOUT).await.expect("Conexão MCP falhou");
    let db_name = unique_db_name("schema_types");
    let schema = "define person sub entity, owns name; name sub attribute, value string; rule inference-rule: when { $x isa person; } then { $x has-inferred-knowledge true; };";
    
    create_test_db(&mut client, &db_name).await?;
    client.call_tool("define_schema", Some(json!({"database_name": db_name, "schema_definition": schema}))).await.context("Falha ao definir schema")?;
    
    let uri = format!("schema://current/{}?type=types", db_name);
    let result = client.read_resource(&uri).await.context("Falha ao ler schema types")?;
    assert_eq!(result.contents.len(), 1, "Esperado um único conteúdo de recurso");
    let contents = &result.contents[0];
    if let ResourceContents::TextResourceContents { text, uri: ret_uri, mime_type } = contents {
        assert!(text.contains("person sub entity"), "Schema types não retornado corretamente: {}", text);
        assert!(!text.contains("inference-rule"), "Schema types não deveria conter regras: {}", text);
        assert_eq!(ret_uri, &uri);
        assert_eq!(mime_type.as_deref(), Some("application/typeql"));
    } else {
        panic!("Tipo de conteúdo inesperado para schema types: {:?}", contents);
    }
    delete_test_db(&mut client, &db_name).await?;
    client.close().await.context("Falha ao fechar cliente no teardown")?;
    docker_env.down(true).context("Falha ao derrubar ambiente docker-compose no teardown")?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
async fn test_read_dynamic_schema_for_nonexistent_db_fails() -> Result<()> {
    let (docker_env, server_url) = setup_test_environment().await?;
    let mut client = TestMcpClient::connect(&server_url, None, CONNECT_TIMEOUT, REQUEST_TIMEOUT).await.context("Conexão MCP falhou")?;
    let db_name = "db_nao_existe_schema_test";
    let uri = format!("schema://current/{}?type=full", db_name);
    let err_result = client.read_resource(&uri).await.expect_err("Esperava erro para schema de DB inexistente");
    
    match err_result {
        McpClientError::McpErrorResponse { code, message, .. } => { // Removido 'data' pois não é usado na asserção
            assert_eq!(code.0, ErrorCode::RESOURCE_NOT_FOUND.0);
            assert!(message.contains(db_name), "Mensagem de erro não contém nome do DB: {}", message);
        }
        e => panic!("Tipo de erro inesperado: {:?}", e),
    }
    client.close().await.context("Falha ao fechar cliente no teardown")?;
    docker_env.down(true).context("Falha ao derrubar ambiente docker-compose no teardown")?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
async fn test_read_dynamic_schema_with_invalid_type_param_uses_default_or_fails() -> Result<()> {
    let (docker_env, server_url) = setup_test_environment().await?;
    let mut client = TestMcpClient::connect(&server_url, None, CONNECT_TIMEOUT, REQUEST_TIMEOUT).await.expect("Conexão MCP falhou");
    let db_name = unique_db_name("schema_invalid_type");
    create_test_db(&mut client, &db_name).await?;
    let schema_def = "define item sub entity;";
    client.call_tool("define_schema", Some(json!({"database_name": db_name, "schema_definition": schema_def}))).await.context("Falha ao definir schema")?;
    
    let uri = format!("schema://current/{}?type=invalidtype", db_name);
    let result = client.read_resource(&uri).await;

    if let Ok(read_result) = result {
        assert_eq!(read_result.contents.len(), 1);
        if let ResourceContents::TextResourceContents { text, .. } = &read_result.contents[0] {
            assert!(text.contains("item sub entity"), "Schema (default full) não retornado corretamente: {}", text);
        } else {
            panic!("Tipo de conteúdo inesperado para schema (default full): {:?}", read_result.contents[0]);
        }
    } else if let Err(McpClientError::McpErrorResponse { code, message, .. }) = result {
        assert_eq!(code.0, ErrorCode::INVALID_PARAMS.0);
        assert!(message.to_lowercase().contains("invalid") && message.to_lowercase().contains("schema type"), "Mensagem de erro inesperada: {}", message);
    } else {
        panic!("Resultado inesperado para tipo de schema inválido: {:?}", result.err());
    }

    delete_test_db(&mut client, &db_name).await?;
    client.close().await.context("Falha ao fechar cliente no teardown")?;
    docker_env.down(true).context("Falha ao derrubar ambiente docker-compose no teardown")?;
    Ok(())
}