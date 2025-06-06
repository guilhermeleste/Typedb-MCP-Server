// tests/integration/schema_ops_tool_tests.rs
// Licença Apache 2.0
// Copyright 2025 Guilherme Leste

//! Testes de integração para as ferramentas MCP de operações de esquema
//! (define_schema, undefine_schema, get_schema) via MCP/WebSocket.

use crate::common::{
    client::McpClientError, // Para assert de erros específicos
    constants,
    // Helpers de test_utils
    create_test_db,
    delete_test_db,
    get_text_from_call_result, // Para extrair texto das respostas
    test_env::TestEnvironment,
    unique_db_name,
};
use anyhow::{Context as AnyhowContext, Result};
use rmcp::model::ErrorCode as McpErrorCode;
use serde_json::json;
use serial_test::serial;
use tracing::info;
// Uuid não é usado diretamente aqui, unique_db_name cuida disso.

#[tokio::test]
#[serial]
async fn test_define_simple_entity_succeeds_and_is_retrievable() -> Result<()> {
    let test_env =
        TestEnvironment::setup("schm_define_ok", constants::DEFAULT_TEST_CONFIG_FILENAME).await?;
    let db_name = unique_db_name("def_ok");
    // Escopos: manage_databases para criar/deletar, manage_schema para as operações de schema
    let mut client = test_env
        .mcp_client_with_auth(Some(
            "typedb:manage_databases typedb:manage_schema typedb:admin_databases",
        )) // admin para delete_test_db
        .await?;

    create_test_db(&mut client, &db_name).await?;

    let schema_to_define = "define entity person, owns name; attribute name, value string;";
    info!("Teste: Definindo schema para '{}': {}", db_name, schema_to_define);

    let define_result = client
        .call_tool(
            "define_schema",
            Some(json!({ "databaseName": db_name, "schemaDefinition": schema_to_define })),
        )
        .await
        .context("Falha ao chamar define_schema")?;

    let define_text = get_text_from_call_result(define_result);
    assert_eq!(define_text, "OK", "Resposta incorreta ao definir schema.");

    // Verificar se o schema foi aplicado usando get_schema
    info!("Teste: Verificando schema aplicado para '{}' com get_schema.", db_name);
    let get_schema_result = client
        .call_tool("get_schema", Some(json!({ "databaseName": db_name, "schemaType": "full" })))
        .await
        .context("Falha ao chamar get_schema para verificação")?;

    let retrieved_schema_text = get_text_from_call_result(get_schema_result);
    assert!(
        retrieved_schema_text.contains("entity person"),
        "Schema retornado não contém 'entity person'. Recebido: {}",
        retrieved_schema_text
    );
    assert!(
        retrieved_schema_text.contains("attribute name") && retrieved_schema_text.contains("value string"),
        "Schema retornado não contém 'attribute name' e 'value string'. Recebido: {}",
        retrieved_schema_text
    );

    delete_test_db(&mut client, &db_name).await;
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_define_schema_with_invalid_typeql_fails_gracefully() -> Result<()> {
    let test_env =
        TestEnvironment::setup("schm_define_invalid_tql", constants::DEFAULT_TEST_CONFIG_FILENAME)
            .await?;
    let db_name = unique_db_name("def_inv_tql");
    let mut client = test_env
        .mcp_client_with_auth(Some(
            "typedb:manage_databases typedb:manage_schema typedb:admin_databases",
        ))
        .await?;

    create_test_db(&mut client, &db_name).await?;

    let invalid_schema = "define entity person"; // Falta ponto e vírgula
    info!(
        "Teste: Tentando definir schema inválido (TypeQL) para '{}': {}",
        db_name, invalid_schema
    );

    let result_err = client
        .call_tool(
            "define_schema",
            Some(json!({ "databaseName": db_name, "schemaDefinition": invalid_schema })),
        )
        .await
        .expect_err("Esperado erro ao definir schema com TypeQL inválido.");

    match result_err {
        McpClientError::McpErrorResponse { code, message, .. } => {
            // TypeDB geralmente retorna um erro interno genérico para falhas de parsing de query
            assert_eq!(code.0, McpErrorCode::INTERNAL_ERROR.0, "Código de erro inesperado.");
            // A mensagem deve indicar um problema com a query ou o schema
            assert!(
                message.to_lowercase().contains("query")
                    || message.to_lowercase().contains("schema")
                    || message.to_lowercase().contains("syntax"),
                "Mensagem de erro não indicou problema com a query/schema: {}",
                message
            );
        }
        other => panic!("Tipo de erro inesperado: {:?}", other),
    }

    delete_test_db(&mut client, &db_name).await;
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_define_schema_on_nonexistent_db_fails() -> Result<()> {
    let test_env =
        TestEnvironment::setup("schm_define_nodb", constants::DEFAULT_TEST_CONFIG_FILENAME).await?;
    let db_name_non_existent = unique_db_name("def_nodb");
    let mut client = test_env
        .mcp_client_with_auth(Some("typedb:manage_schema")) // Só precisa de manage_schema
        .await?;

    let schema = "define entity person;";
    info!("Teste: Tentando definir schema para banco inexistente '{}'", db_name_non_existent);

    let result_err = client
        .call_tool(
            "define_schema",
            Some(json!({ "databaseName": db_name_non_existent, "schemaDefinition": schema })),
        )
        .await
        .expect_err("Esperado erro ao definir schema em banco inexistente.");

    match result_err {
        McpClientError::McpErrorResponse { message, .. } => {
            // O erro específico pode variar (erro do driver TypeDB ao não encontrar o banco).
            // Pode ser um erro genérico ou um mais específico.
            // Vamos verificar se a mensagem contém o nome do banco.
            assert!(
                message.contains(&db_name_non_existent)
                    || message.to_lowercase().contains("not found")
            );
            // O código pode ser INTERNAL_ERROR ou outro, dependendo de como o driver TypeDB reporta.
        }
        other => panic!("Tipo de erro inesperado: {:?}", other),
    }
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_undefine_existing_type_succeeds() -> Result<()> {
    let test_env =
        TestEnvironment::setup("schm_undef_ok", constants::DEFAULT_TEST_CONFIG_FILENAME).await?;
    let db_name = unique_db_name("undef_ok");
    let mut client = test_env
        .mcp_client_with_auth(Some(
            "typedb:manage_databases typedb:manage_schema typedb:admin_databases",
        ))
        .await?;

    create_test_db(&mut client, &db_name).await?;
    let initial_schema = "define entity animal, owns name; attribute name, value string;";
    client
        .call_tool(
            "define_schema",
            Some(json!({ "databaseName": db_name, "schemaDefinition": initial_schema })),
        )
        .await?;

    let schema_to_undefine = "undefine owns name from animal;";
    info!("Teste: Removendo definição de schema para '{}': {}", db_name, schema_to_undefine);
    let undefine_result = client
        .call_tool(
            "undefine_schema",
            Some(json!({ "databaseName": db_name, "schemaUndefinition": schema_to_undefine })),
        )
        .await?;
    let undefine_text = get_text_from_call_result(undefine_result);
    assert_eq!(undefine_text, "OK", "Resposta incorreta ao remover definição.");

    let get_schema_result = client
        .call_tool("get_schema", Some(json!({ "databaseName": db_name, "schemaType": "full" })))
        .await?;
    let retrieved_schema_text = get_text_from_call_result(get_schema_result);
    // Verifica se "owns name" foi removido de animal. "entity animal" ainda deve existir.
    assert!(retrieved_schema_text.contains("entity animal"));
    assert!(
        !retrieved_schema_text.contains("animal owns name;"),
        "Atributo 'name' não foi removido de 'animal'. Schema: {}",
        retrieved_schema_text
    );

    delete_test_db(&mut client, &db_name).await;
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_get_schema_returns_defined_types_and_full_schema() -> Result<()> {
    let test_env =
        TestEnvironment::setup("schm_get_full_types", constants::DEFAULT_TEST_CONFIG_FILENAME)
            .await?;
    let db_name = unique_db_name("get_schema");
    let mut client = test_env
        .mcp_client_with_auth(Some(
            "typedb:manage_databases typedb:manage_schema typedb:admin_databases",
        ))
        .await?;

    create_test_db(&mut client, &db_name).await?;
    let schema_definition = r#"
        define
            entity person, owns name;
            attribute name, value string;
    "#;
    client
        .call_tool(
            "define_schema",
            Some(json!({ "databaseName": db_name, "schemaDefinition": schema_definition })),
        )
        .await?;

    // 1. Testar schema_type = "full"
    info!("Teste: Obtendo schema completo para '{}'", db_name);
    let result_full = client
        .call_tool("get_schema", Some(json!({ "databaseName": db_name, "schemaType": "full" })))
        .await?;
    let schema_full_text = get_text_from_call_result(result_full);
    assert!(schema_full_text.contains("entity person"));
    // Comentando teste de regra pois rules podem não estar suportadas no TypeQL 3.x
    // assert!(schema_full_text.contains("simple-rule"), "Schema completo não contém a regra.");

    // 2. Testar schema_type = "types"
    info!("Teste: Obtendo apenas tipos do schema para '{}'", db_name);
    let result_types = client
        .call_tool("get_schema", Some(json!({ "databaseName": db_name, "schemaType": "types" })))
        .await?;
    let schema_types_text = get_text_from_call_result(result_types);
    assert!(schema_types_text.contains("entity person"));
    // Comentando teste de regra pois rules podem não estar suportadas no TypeQL 3.x
    // assert!(
    //     !schema_types_text.contains("simple-rule"),
    //     "Schema 'types' não deveria conter regras."
    // );

    // 3. Testar schema_type omitido (deve defaultar para "full")
    info!("Teste: Obtendo schema com schema_type omitido para '{}'", db_name);
    let result_default =
        client.call_tool("get_schema", Some(json!({ "databaseName": db_name }))).await?;
    let schema_default_text = get_text_from_call_result(result_default);
    assert!(schema_default_text.contains("entity person"));
    // Comentando teste de regra pois rules podem não estar suportadas no TypeQL 3.x
    // assert!(
    //     schema_default_text.contains("simple-rule"),
    //     "Schema com tipo omitido deveria defaultar para 'full'."
    // );

    delete_test_db(&mut client, &db_name).await;
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_schema_operations_require_correct_scope_oauth() -> Result<()> {
    let test_env = TestEnvironment::setup(
        "schm_ops_scopes_oauth",
        constants::OAUTH_ENABLED_TEST_CONFIG_FILENAME, // Usar config com OAuth
    )
    .await?;
    let db_name = unique_db_name("authz_schema");

    // Criar DB com cliente que tem permissão para isso
    let mut setup_client = test_env.mcp_client_with_auth(Some("typedb:manage_databases")).await?;
    create_test_db(&mut setup_client, &db_name).await?;

    // Cliente sem escopo `typedb:manage_schema`
    let mut client_no_schema_scope =
        test_env.mcp_client_with_auth(Some("typedb:read_data")).await?; // Escopo insuficiente
    let schema_def = "define entity car;";

    info!("Teste: Tentando define_schema sem escopo 'typedb:manage_schema'");
    let res_define_no_scope = client_no_schema_scope
        .call_tool(
            "define_schema",
            Some(json!({"databaseName": db_name, "schemaDefinition": schema_def})),
        )
        .await;
    assert!(res_define_no_scope.is_err());
    if let McpClientError::McpErrorResponse { code, .. } = res_define_no_scope.unwrap_err() {
        assert_eq!(code.0, McpErrorCode(-32001).0); // Authorization Failed
    } else {
        panic!("Esperado McpErrorResponse de autorização para define_schema");
    }

    info!("Teste: Tentando get_schema sem escopo 'typedb:manage_schema'");
    let res_get_no_scope = client_no_schema_scope
        .call_tool("get_schema", Some(json!({"databaseName": db_name})))
        .await;
    assert!(res_get_no_scope.is_err());
    if let McpClientError::McpErrorResponse { code, .. } = res_get_no_scope.unwrap_err() {
        assert_eq!(code.0, McpErrorCode(-32001).0);
    } else {
        panic!("Esperado McpErrorResponse de autorização para get_schema");
    }

    // Limpeza com cliente que tem permissão para deletar
    let mut admin_client = test_env.mcp_client_with_auth(Some("typedb:admin_databases")).await?;
    delete_test_db(&mut admin_client, &db_name).await;
    Ok(())
}
