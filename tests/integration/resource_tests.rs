// tests/integration/resource_tests.rs
// Licença Apache 2.0
// Copyright 2025 Guilherme Leste

//! Testes de integração para as ferramentas MCP de gerenciamento de recursos
//! (list_resources, list_resource_templates, read_resource).

use crate::common::{
    client::McpClientError, // Para assert de erros específicos
    constants,
    // Helpers de test_utils são agora importados diretamente via crate::common
    create_test_db,
    delete_test_db,
    test_env::TestEnvironment,
    unique_db_name,
};
use anyhow::{Context as AnyhowContext, Result};
use rmcp::model::{ErrorCode as McpErrorCode, ResourceContents};
use serde_json::json;
use serial_test::serial;
use tracing::info;

#[tokio::test]
#[serial]
async fn test_list_static_resources_contains_expected_content() -> Result<()> {
    let test_env =
        TestEnvironment::setup("res_list_static", constants::DEFAULT_TEST_CONFIG_FILENAME).await?;
    let mut client = test_env.mcp_client_with_auth(None).await?;

    info!("Teste: Listando recursos estáticos.");
    let result = client.list_resources(None).await.context("Falha ao chamar list_resources")?;

    assert!(!result.resources.is_empty(), "A lista de recursos não deveria estar vazia.");

    let query_types_res = result
        .resources
        .iter()
        .find(|r_annotated| r_annotated.raw.uri == "info://typeql/query_types")
        .expect("Recurso 'info://typeql/query_types' não encontrado na lista.");
    assert_eq!(query_types_res.raw.name, "Guia Rápido: Tipos de Consulta TypeQL");
    assert_eq!(query_types_res.raw.mime_type.as_deref(), Some("text/plain"));
    assert!(query_types_res
        .raw
        .description
        .as_ref()
        .expect("Descrição ausente para query_types")
        .contains("Tipos de Consulta TypeQL"));
    assert!(
        query_types_res.raw.size.unwrap_or(0) > 0,
        "Tamanho do recurso query_types deveria ser > 0"
    );

    let transactions_guide_res = result
        .resources
        .iter()
        .find(|r_annotated| r_annotated.raw.uri == "info://typedb/transactions_and_tools")
        .expect("Recurso 'info://typedb/transactions_and_tools' não encontrado na lista.");
    assert_eq!(transactions_guide_res.raw.name, "Guia: Transações TypeDB e Ferramentas MCP");
    assert_eq!(transactions_guide_res.raw.mime_type.as_deref(), Some("text/plain"));
    assert!(transactions_guide_res
        .raw
        .description
        .as_ref()
        .expect("Descrição ausente para transactions_guide")
        .contains("Transações TypeDB"));
    assert!(
        transactions_guide_res.raw.size.unwrap_or(0) > 0,
        "Tamanho do recurso transactions_guide deveria ser > 0"
    );

    info!("Recursos estáticos listados e verificados com sucesso.");
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_list_resource_templates_contains_schema_template() -> Result<()> {
    let test_env =
        TestEnvironment::setup("res_list_tpl", constants::DEFAULT_TEST_CONFIG_FILENAME).await?;
    let mut client = test_env.mcp_client_with_auth(None).await?;

    info!("Teste: Listando templates de recursos.");
    let result = client
        .list_resource_templates(None)
        .await
        .context("Falha ao chamar list_resource_templates")?;

    assert!(
        !result.resource_templates.is_empty(),
        "A lista de templates de recursos não deveria estar vazia."
    );

    let schema_template_uri = "schema://current/{database_name}?type={schema_type}";
    let schema_template = result
        .resource_templates
        .iter()
        .find(|rt_annotated| rt_annotated.raw.uri_template == schema_template_uri)
        .expect("Template de schema não encontrado na lista.");

    assert_eq!(schema_template.raw.name, "Esquema Atual do Banco de Dados");
    assert_eq!(schema_template.raw.mime_type.as_deref(), Some("text/plain"));
    assert!(schema_template
        .raw
        .description
        .as_ref()
        .expect("Descrição ausente para o template de schema")
        .contains("Retorna o esquema TypeQL"));

    info!("Templates de recursos listados e template de schema verificado com sucesso.");
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_read_static_resource_query_types() -> Result<()> {
    let test_env =
        TestEnvironment::setup("res_read_static_qtypes", constants::DEFAULT_TEST_CONFIG_FILENAME)
            .await?;
    let mut client = test_env.mcp_client_with_auth(None).await?;
    let resource_uri = "info://typeql/query_types";

    info!("Teste: Lendo recurso estático '{}'", resource_uri);
    let result = client
        .read_resource(resource_uri)
        .await
        .context(format!("Falha ao ler recurso '{}'", resource_uri))?;

    assert_eq!(result.contents.len(), 1, "Esperado um único item de conteúdo.");
    match &result.contents[0] {
        ResourceContents::TextResourceContents { text, uri, mime_type } => {
            assert_eq!(uri, resource_uri);
            assert_eq!(mime_type.as_deref(), Some("text/plain"));
            assert!(text.contains("Guia Rápido dos Tipos de Consulta TypeQL"));
            assert!(text.contains("DEFINE:"));
        }
        other => panic!("Tipo de conteúdo inesperado para recurso estático: {:?}", other),
    }
    info!("Recurso estático '{}' lido com sucesso.", resource_uri);
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_read_invalid_static_resource_uri_fails_gracefully() -> Result<()> {
    let test_env =
        TestEnvironment::setup("res_read_static_invalid", constants::DEFAULT_TEST_CONFIG_FILENAME)
            .await?;
    let mut client = test_env.mcp_client_with_auth(None).await?;
    let invalid_uri = "info://non/existent/resource";

    info!("Teste: Tentando ler URI de recurso estático inválida '{}'", invalid_uri);
    let result_err = client
        .read_resource(invalid_uri)
        .await
        .expect_err("Esperado erro ao ler URI de recurso estático inválida.");

    match result_err {
        McpClientError::McpErrorResponse { code, message, .. } => {
            assert_eq!(code.0, McpErrorCode::RESOURCE_NOT_FOUND.0);
            assert!(message.contains(invalid_uri));
        }
        other => panic!("Tipo de erro inesperado para URI inválida: {:?}", other),
    }
    info!("Falha ao ler URI de recurso estático inválida, como esperado.");
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_read_dynamic_schema_resource_full_and_types() -> Result<()> {
    let test_env =
        TestEnvironment::setup("res_read_dyn_schema", constants::DEFAULT_TEST_CONFIG_FILENAME)
            .await?;
    let db_name = unique_db_name("schema_dyn");

    let mut client = test_env
        .mcp_client_with_auth(Some(
            "typedb:manage_databases typedb:manage_schema typedb:admin_databases",
        ))
        .await?;

    create_test_db(&mut client, &db_name).await?;

    // CORREÇÃO: TypeDB 3.x removeu regras completamente, substituídas por functions
    // Definindo apenas tipos: attributes, relations, entities
    let schema_definition = concat!(
        "define\n",
        "attribute name;\n",
        "name value string;\n",
        "relation friendship;\n",
        "friendship relates friend;\n",
        "entity person, owns name, plays friendship:friend;\n"
    );

    info!("Definindo schema: \n{}", schema_definition);
    let _ = client
        .call_tool(
            "define_schema",
            Some(json!({
                "databaseName": db_name.clone(),
                "schemaDefinition": schema_definition
            })),
        )
        .await
        .context(format!("Falha ao definir schema para '{}'", &db_name))?;

    // 1. Testar type=full (ou default)
    let full_schema_uri = format!("schema://current/{}?type=full", db_name);
    info!("Teste: Lendo schema dinâmico completo: {}", full_schema_uri);
    let result_full = client.read_resource(&full_schema_uri).await?;
    assert_eq!(result_full.contents.len(), 1);
    if let ResourceContents::TextResourceContents { text, uri, mime_type } =
        &result_full.contents[0]
    {
        assert_eq!(uri, &full_schema_uri);
        assert_eq!(mime_type.as_deref(), Some("text/plain+typeql"));
        
        // Debug: Print actual schema content to see exact format
        // Verificar se contém os elementos básicos do schema (formato TypeDB 3.x)
        assert!(text.contains("entity person"));
        assert!(text.contains("attribute name"));
        assert!(text.contains("value string"));
        assert!(text.contains("relation friendship"));
        assert!(text.contains("relates friend"));
        assert!(text.contains("owns name"));
        assert!(text.contains("plays friendship:friend"));
        info!("Schema completo lido com sucesso.");
    } else {
        panic!("Conteúdo inesperado para schema completo.");
    }

    // 2. Testar type=types
    let types_schema_uri = format!("schema://current/{}?type=types", db_name);
    info!("Teste: Lendo apenas tipos do schema dinâmico: {}", types_schema_uri);
    let result_types = client.read_resource(&types_schema_uri).await?;
    assert_eq!(result_types.contents.len(), 1);
    if let ResourceContents::TextResourceContents { text, uri, mime_type } =
        &result_types.contents[0]
    {
        assert_eq!(uri, &types_schema_uri);
        assert_eq!(mime_type.as_deref(), Some("text/plain+typeql"));
        assert!(text.contains("entity person"));
        assert!(text.contains("attribute name"));
        assert!(text.contains("name,\n value string"));
        assert!(text.contains("relation friendship"));
        assert!(text.contains("friendship,\n  relates friend"));
        assert!(text.contains("person,\n  owns name"));
        assert!(text.contains("person,\n  owns name,\n  plays friendship:friend"));
        // Nota: TypeDB 3.x removeu regras, substituídas por functions
        info!("Schema (apenas tipos) lido com sucesso.");
    } else {
        panic!("Conteúdo inesperado para schema (apenas tipos).");
    }

    // 3. Testar com parâmetro de tipo inválido (deve usar default 'full')
    let invalid_type_schema_uri = format!("schema://current/{}?type=invalid", db_name);
    info!("Teste: Lendo schema dinâmico com tipo inválido: {}", invalid_type_schema_uri);
    let result_invalid_type = client.read_resource(&invalid_type_schema_uri).await?;
    assert_eq!(result_invalid_type.contents.len(), 1);
    if let ResourceContents::TextResourceContents { text, .. } = &result_invalid_type.contents[0] {
        assert!(text.contains("entity person"));
        // TypeDB 3.x não tem regras, então testamos apenas tipos
        info!("Schema com tipo inválido deveria defaultar para 'full' (apenas tipos no TypeDB 3.x).");
        info!("Schema com tipo inválido usou default 'full' como esperado.");
    } else {
        panic!("Conteúdo inesperado para schema com tipo inválido.");
    }

    delete_test_db(&mut client, &db_name).await;
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_read_dynamic_schema_for_nonexistent_db_fails() -> Result<()> {
    let test_env =
        TestEnvironment::setup("res_read_dyn_schema_nodb", constants::DEFAULT_TEST_CONFIG_FILENAME)
            .await?;
    let mut client = test_env.mcp_client_with_auth(None).await?;
    let non_existent_db_name = unique_db_name("non_existent_schema");
    let uri = format!("schema://current/{}", non_existent_db_name);

    info!("Teste: Tentando ler schema de banco de dados inexistente '{}'", uri);
    let result_err = client
        .read_resource(&uri)
        .await
        .expect_err("Esperado erro ao ler schema de banco inexistente.");

    match result_err {
        McpClientError::McpErrorResponse { code, message, .. } => {
            assert_eq!(code.0, McpErrorCode::RESOURCE_NOT_FOUND.0);
            assert!(
                message.contains(&non_existent_db_name)
                    || message.to_lowercase().contains("database not found")
            );
        }
        other => panic!("Tipo de erro inesperado: {:?}", other),
    }
    info!("Falha ao ler schema de banco inexistente, como esperado.");
    Ok(())
}