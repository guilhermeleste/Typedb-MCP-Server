// tests/integration/query_tool_tests.rs
// Licença Apache 2.0
// Copyright 2025 Guilherme Leste

//! Testes de integração para as ferramentas MCP de consulta e manipulação de dados
//! (query_read, insert_data, delete_data, update_data, validate_query).

use crate::common::{
    client::McpClientError,
    constants,
    test_env::TestEnvironment,
    mcp_utils::get_text_from_call_result,
};
use anyhow::{Context as AnyhowContext, Result};
use rmcp::model::ErrorCode as McpErrorCode;
use serde_json::{json, Value as JsonValue}; // Adicionado JsonValue
use serial_test::serial;
use tracing::info;
use uuid::Uuid;

/// Gera um nome de banco de dados único para evitar conflitos entre testes.
fn unique_db_name(suffix: &str) -> String {
    format!("test_query_ops_{}_{}", suffix, Uuid::new_v4().as_simple())
}

/// Helper para criar um banco de dados de teste e definir um esquema base.
/// Retorna o cliente MCP usado para o setup, que já tem a sessão inicializada.
async fn setup_database_with_base_schema(
    test_env: &TestEnvironment,
    db_name: &str,
    scopes_for_setup: &str,
) -> Result<crate::common::client::TestMcpClient> {
    let mut client = test_env.mcp_client_with_auth(Some(scopes_for_setup)).await?;

    info!("Helper: Criando banco de dados de teste: {}", db_name);
    let create_result = client
        .call_tool("create_database", Some(json!({ "name": db_name })))
        .await;
    assert!(
        create_result.is_ok(),
        "Falha ao criar banco de teste '{}' via helper: {:?}",
        db_name,
        create_result.err()
    );

    let schema = r#"
        define
            person sub entity,
                owns name,
                owns age,
                plays employment:employee;
            company sub entity,
                owns company-name,
                plays employment:employer;
            employment sub relation,
                relates employee,
                relates employer,
                owns salary;
            name sub attribute, value string;
            company-name sub attribute, value string;
            age sub attribute, value long;
            salary sub attribute, value double;
    "#;
    info!("Helper: Definindo esquema base para o banco: {}", db_name);
    let define_result = client
        .call_tool(
            "define_schema",
            Some(json!({ "database_name": db_name, "schema_definition": schema })),
        )
        .await;
    assert!(
        define_result.is_ok(),
        "Falha ao definir esquema base para '{}': {:?}",
        db_name,
        define_result.err()
    );
    info!("Helper: Banco '{}' e esquema base configurados.", db_name);
    Ok(client) // Retorna o cliente usado para o setup
}

/// Helper para deletar um banco de dados de teste (melhor esforço).
async fn delete_test_db(
    client: &mut crate::common::client::TestMcpClient,
    db_name: &str,
) {
    info!("Helper: Deletando banco de dados de teste: {}", db_name);
    let _ = client
        .call_tool("delete_database", Some(json!({ "name": db_name })))
        .await;
}

#[tokio::test]
#[serial]
async fn test_insert_and_query_read_person() -> Result<()> {
    let test_env =
        TestEnvironment::setup("insert_query_person", constants::DEFAULT_TEST_CONFIG_FILENAME)
            .await?;
    let db_name = unique_db_name("person_iq");
    let mut client = setup_database_with_base_schema(
        &test_env,
        &db_name,
        "typedb:manage_databases typedb:manage_schema typedb:write_data typedb:read_data",
    )
    .await?;

    let insert_query = r#"insert $p isa person, has name "Alice", has age 30;"#;
    info!("Teste: Inserindo dados com query: {}", insert_query);
    let insert_result = client
        .call_tool(
            "insert_data",
            Some(json!({ "database_name": db_name, "query": insert_query })),
        )
        .await
        .context("Falha na ferramenta insert_data")?;
    assert_eq!(insert_result.is_error.unwrap_or(false), false, "insert_data retornou is_error=true");

    let read_query = r#"match $p isa person, has name $n, has age $a; get $n, $a; sort $n asc;"#;
    info!("Teste: Consultando dados com query: {}", read_query);
    let read_result = client
        .call_tool(
            "query_read",
            Some(json!({ "database_name": db_name, "query": read_query })),
        )
        .await
        .context("Falha na ferramenta query_read")?;

    let text_content = get_text_from_call_result(read_result);
    let json_value: JsonValue = // Usar JsonValue aqui
        serde_json::from_str(&text_content).context("Falha ao parsear JSON da resposta de query_read")?;

    info!("Resposta de query_read: {}", json_value);
    let expected_json = json!([
        {
            // A ordem dos campos dentro de 'a' e 'n' pode variar, mas os valores devem ser os mesmos.
            // O TypeDB driver pode não garantir a ordem dos atributos dentro de um ConceptMap.
            // Para uma comparação robusta, seria ideal parsear para uma struct ou comparar campos individualmente.
            // Por simplicidade, vamos manter a comparação direta, mas cientes dessa possível fragilidade.
            "a": { "value": {"integer": 30}, "typeLabel": "age", "valueType": "integer" },
            "n": { "value": {"string": "Alice"}, "typeLabel": "name", "valueType": "string" }
        }
    ]);
    assert_eq!(json_value, expected_json, "Resultado da consulta de pessoa não corresponde ao esperado.");

    delete_test_db(&mut client, &db_name).await;
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_query_read_aggregate_count() -> Result<()> {
    let test_env = TestEnvironment::setup("query_agg_count", constants::DEFAULT_TEST_CONFIG_FILENAME).await?;
    let db_name = unique_db_name("agg_count");
    let mut client = setup_database_with_base_schema(
        &test_env,
        &db_name,
        "typedb:manage_databases typedb:manage_schema typedb:write_data typedb:read_data",
    )
    .await?;

    let insert_queries = [
        r#"insert $p isa person, has name "Bob", has age 40;"#,
        r#"insert $p isa person, has name "Charlie", has age 35;"#,
    ];
    for query in insert_queries {
        client.call_tool("insert_data", Some(json!({ "database_name": db_name, "query": query }))).await?;
    }

    let agg_query = "match $p isa person; count;";
    info!("Teste: Consultando agregação (count) com query: {}", agg_query);
    let agg_result = client
        .call_tool("query_read", Some(json!({ "database_name": db_name, "query": agg_query })))
        .await
        .context("Falha na ferramenta query_read (aggregate)")?;
    
    let text_content = get_text_from_call_result(agg_result);
    let count_value: i64 = serde_json::from_str(&text_content)
        .context("Falha ao parsear resultado de count como i64")?;
    
    assert_eq!(count_value, 2, "Contagem de pessoas incorreta.");

    delete_test_db(&mut client, &db_name).await;
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_update_attribute_value() -> Result<()> {
    let test_env = TestEnvironment::setup("update_attr_val", constants::DEFAULT_TEST_CONFIG_FILENAME).await?;
    let db_name = unique_db_name("upd_attr");
    let mut client = setup_database_with_base_schema(
        &test_env,
        &db_name,
        "typedb:manage_databases typedb:manage_schema typedb:write_data typedb:read_data",
    )
    .await?;

    let insert_query = r#"insert $p isa person, has name "Carol", has age 25;"#;
    client.call_tool("insert_data", Some(json!({ "database_name": db_name, "query": insert_query }))).await?;

    let update_query = r#"match $p isa person, has name "Carol", has age $a; delete $p has age $a; insert $p has age 26;"#;
    info!("Teste: Atualizando atributo com query: {}", update_query);
    let update_result = client
        .call_tool(
            "update_data",
            Some(json!({ "database_name": db_name, "query": update_query })),
        )
        .await
        .context("Falha na ferramenta update_data")?;
    assert_eq!(update_result.is_error.unwrap_or(false), false, "update_data retornou is_error=true");

    let read_query = r#"match $p isa person, has name "Carol", has age $a; get $a;"#;
    let read_result = client
        .call_tool("query_read", Some(json!({ "database_name": db_name, "query": read_query })))
        .await?;
    
    let text_content = get_text_from_call_result(read_result);
    let json_value: JsonValue = serde_json::from_str(&text_content)?; // Usar JsonValue
    info!("Resultado após update: {}", json_value);

    let expected_json = json!([{"a": { "value": {"integer": 26}, "typeLabel": "age", "valueType": "integer" }}]);
    assert_eq!(json_value, expected_json, "Valor do atributo 'age' não foi atualizado corretamente.");

    delete_test_db(&mut client, &db_name).await;
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_delete_entity_and_verify() -> Result<()> {
    let test_env = TestEnvironment::setup("delete_entity_verify", constants::DEFAULT_TEST_CONFIG_FILENAME).await?;
    let db_name = unique_db_name("del_ent");
    let mut client = setup_database_with_base_schema(
        &test_env,
        &db_name,
        "typedb:manage_databases typedb:manage_schema typedb:write_data typedb:read_data",
    )
    .await?;

    let insert_query = r#"insert $p isa person, has name "Dave", has age 50;"#;
    client.call_tool("insert_data", Some(json!({ "database_name": db_name, "query": insert_query }))).await?;

    let delete_query = r#"match $p isa person, has name "Dave"; delete $p;"#;
    info!("Teste: Deletando entidade com query: {}", delete_query);
    let delete_result = client
        .call_tool(
            "delete_data",
            Some(json!({ "database_name": db_name, "query": delete_query })),
        )
        .await
        .context("Falha na ferramenta delete_data")?;
    let delete_text = get_text_from_call_result(delete_result);
    assert_eq!(delete_text, "OK", "Resposta incorreta ao deletar entidade.");

    let read_query = r#"match $p isa person, has name "Dave"; get $p;"#;
    info!("Teste: Verificando se entidade foi deletada com query: {}", read_query);
    let read_result_after_delete = client
        .call_tool("query_read", Some(json!({ "database_name": db_name, "query": read_query })))
        .await?;
    
    let text_content_after_delete = get_text_from_call_result(read_result_after_delete);
    let json_value_after_delete: Vec<JsonValue> = serde_json::from_str(&text_content_after_delete)?; // Usar JsonValue
    
    assert!(json_value_after_delete.is_empty(), "Entidade 'Dave' não foi removida, resultado: {:?}", json_value_after_delete);

    delete_test_db(&mut client, &db_name).await;
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_validate_query_syntax_ok_and_fail() -> Result<()> {
    let test_env = TestEnvironment::setup("validate_query", constants::DEFAULT_TEST_CONFIG_FILENAME).await?;
    let db_name = unique_db_name("val_q");
    let mut client = setup_database_with_base_schema(
        &test_env,
        &db_name,
        "typedb:manage_databases typedb:manage_schema typedb:validate_queries",
    )
    .await?;

    let valid_query = "match $p isa person; get $p;";
    info!("Teste: Validando query sintaticamente correta: {}", valid_query);
    let validate_ok_result = client
        .call_tool(
            "validate_query",
            Some(json!({ "database_name": db_name, "query": valid_query, "intended_transaction_type": "read" })),
        )
        .await?;
    let text_ok = get_text_from_call_result(validate_ok_result);
    assert_eq!(text_ok.trim().to_lowercase(), "valid", "Query válida retornou: {}", text_ok);

    let invalid_query_syntax = "match $p isa person get $p;";
    info!("Teste: Validando query com erro de sintaxe: {}", invalid_query_syntax);
    let validate_err_result = client
        .call_tool(
            "validate_query",
            Some(json!({ "database_name": db_name, "query": invalid_query_syntax, "intended_transaction_type": "read" })),
        )
        .await?;
    let text_err = get_text_from_call_result(validate_err_result);
    assert!(
        text_err.to_lowercase().contains("error") || text_err.to_lowercase().contains("fail"),
        "Mensagem para query inválida não indicou erro: '{}'", text_err
    );

    delete_test_db(&mut client, &db_name).await;
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_query_data_operations_require_correct_scopes_oauth() -> Result<()> {
    let test_env = TestEnvironment::setup(
        "query_scopes_oauth",
        constants::OAUTH_ENABLED_TEST_CONFIG_FILENAME,
    )
    .await?;
    let db_name = unique_db_name("q_scopes");

    // Usar o cliente retornado pelo setup_database_with_base_schema, que já tem os escopos de setup
    let _setup_client = setup_database_with_base_schema(
        &test_env,
        &db_name,
        "typedb:manage_databases typedb:manage_schema", // Escopos apenas para setup
    )
    .await?;
    // setup_client agora é mutável e pode ser usado para deleção, mas os escopos dele são limitados.

    let mut client_readonly = test_env.mcp_client_with_auth(Some("typedb:read_data")).await?;
    let insert_query = r#"insert $p isa person, has name "Eve", has age 22;"#;
    info!("Teste: Tentando insert_data sem escopo 'typedb:write_data'");
    let result_insert_no_scope = client_readonly
        .call_tool("insert_data", Some(json!({ "database_name": db_name, "query": insert_query })))
        .await;
    assert!(result_insert_no_scope.is_err());
    if let McpClientError::McpErrorResponse { code, .. } = result_insert_no_scope.unwrap_err() {
        assert_eq!(code.0, McpErrorCode(-32001).0);
    } else { panic!("Esperado McpErrorResponse de autorização para insert_data"); }

    let mut client_write_perms = test_env.mcp_client_with_auth(Some("typedb:write_data")).await?;
    info!("Teste: Tentando insert_data COM escopo 'typedb:write_data'");
    let insert_ok_result = client_write_perms
        .call_tool("insert_data", Some(json!({ "database_name": db_name, "query": insert_query })))
        .await;
    assert!(insert_ok_result.is_ok(), "insert_data com escopo correto falhou: {:?}", insert_ok_result.err());

    let mut client_no_relevant_scopes = test_env.mcp_client_with_auth(Some("other:unrelated")).await?;
    let read_query = "match $p isa person; get $p;";
    info!("Teste: Tentando query_read sem escopo 'typedb:read_data'");
    let result_read_no_scope = client_no_relevant_scopes
        .call_tool("query_read", Some(json!({ "database_name": db_name, "query": read_query })))
        .await;
    assert!(result_read_no_scope.is_err());
     if let McpClientError::McpErrorResponse { code, .. } = result_read_no_scope.unwrap_err() {
        assert_eq!(code.0, McpErrorCode(-32001).0);
    } else { panic!("Esperado McpErrorResponse de autorização para query_read"); }

    // Usar o cliente com permissões de admin para deletar
    let mut final_cleanup_client = test_env
        .mcp_client_with_auth(Some("typedb:admin_databases"))
        .await?;
    delete_test_db(&mut final_cleanup_client, &db_name).await;
    Ok(())
}