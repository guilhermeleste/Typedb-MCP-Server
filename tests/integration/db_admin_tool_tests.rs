// MIT License
//
// Copyright (c) 2025 Guilherme Leste
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//! Testes de integração para as ferramentas MCP de administração de banco de dados
//! (create_database, delete_database, list_databases, database_exists)
//! do `Typedb-MCP-Server`.
//!
//! Estes testes verificam o comportamento de ponta a ponta das ferramentas de
//! administração, interagindo com um servidor MCP real e uma instância TypeDB
//! orquestrados via Docker Compose.

// Importações do crate de teste `common` (definido em `tests/integration.rs`)
use crate::common::{
    client::McpClientError, // Para verificar tipos de erro específicos do cliente MCP
    constants,              // Constantes compartilhadas (nomes de config, portas, etc.)
    mcp_utils::get_text_from_call_result, // Helper para extrair texto de CallToolResult
    test_env::TestEnvironment, // Gerenciador do ambiente de teste (Docker, cliente MCP)
};
use anyhow::{Context as AnyhowContext, Result}; // Para tratamento de erro simplificado
use rmcp::model::ErrorCode as McpErrorCode; // Códigos de erro MCP padrão
use serde_json::json; // Para construir payloads JSON para os argumentos das ferramentas
use serial_test::serial; // Para garantir que testes que modificam estado global (Docker) rodem serialmente
use tracing::info; // Para logging informativo durante os testes
use uuid::Uuid; // Para gerar nomes de banco de dados únicos

/// Gera um nome de banco de dados único prefixado para evitar conflitos entre testes.
///
/// # Argumentos
/// * `suffix`: Um sufixo descritivo para adicionar ao nome do banco.
///
/// # Retorna
/// Uma `String` contendo o nome único do banco de dados (ex: "`test_db_admin_meuteste_uuid`").
fn unique_db_name(suffix: &str) -> String {
    format!("test_db_admin_{}_{}", suffix, Uuid::new_v4().as_simple())
}

/// Função helper para criar um banco de dados de teste.
///
/// Utiliza um `TestMcpClient` existente para chamar a ferramenta `create_database`.
/// Entra em pânico (panic) se a criação falhar, pois geralmente é um pré-requisito
/// para o teste que a invoca.
///
/// # Argumentos
/// * `client`: Referência mutável para um `TestMcpClient` já conectado e inicializado.
/// * `db_name`: O nome do banco de dados a ser criado.
async fn create_test_db(client: &mut crate::common::client::TestMcpClient, db_name: &str) {
    info!("Helper de teste: Criando banco de dados de teste: '{}'", db_name);
    let result = client.call_tool("create_database", Some(json!({ "name": db_name }))).await;
    assert!(
        result.is_ok(),
        "Falha ao criar banco de teste '{}' via helper: {:?}", // Mensagem de pânico mais informativa
        db_name,
        result.err()
    );
    let response_text = get_text_from_call_result(
        result.expect("create_database deveria ter sucesso baseado no assert")
    );
    assert_eq!(response_text, "OK", "Resposta inesperada ao criar banco de teste '{db_name}'");
    info!("Helper de teste: Banco de dados de teste '{}' criado com sucesso.", db_name);
}

/// Função helper para deletar um banco de dados de teste (melhor esforço).
///
/// Utiliza um `TestMcpClient` para chamar `delete_database`. Loga um aviso se a deleção falhar,
/// mas não entra em pânico, para permitir que o teardown de outros testes continue.
///
/// # Argumentos
/// * `client`: Referência mutável para um `TestMcpClient`.
/// * `db_name`: O nome do banco de dados a ser deletado.
async fn delete_test_db(client: &mut crate::common::client::TestMcpClient, db_name: &str) {
    info!("Helper de teste: Deletando banco de dados de teste: '{}'", db_name);
    match client.call_tool("delete_database", Some(json!({ "name": db_name }))).await {
        Ok(result) => {
            let response_text = get_text_from_call_result(result);
            if response_text == "OK" {
                info!(
                    "Helper de teste: Banco de dados de teste '{}' deletado com sucesso.",
                    db_name
                );
            } else {
                tracing::warn!(
                    // Usando a macro diretamente do tracing
                    "Helper de teste: Resposta inesperada ao deletar banco de dados '{}': {}",
                    db_name,
                    response_text
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                // Usando a macro diretamente do tracing
                "Helper de teste: Falha ao deletar banco de dados de teste '{}': {:?}",
                db_name,
                e
            );
        }
    }
}

/// Testa se a ferramenta `create_database` funciona corretamente com um nome válido
/// e se o banco de dados é subsequentemente encontrado por `database_exists`.
#[tokio::test]
#[serial] // Garante execução serial para evitar conflitos de estado no TypeDB
async fn test_create_database_succeeds_with_valid_name() -> Result<()> {
    info!("Iniciando teste: test_create_database_succeeds_with_valid_name");
    // Configura o ambiente de teste usando a configuração padrão.
    let test_env =
        TestEnvironment::setup("db_create_ok", constants::DEFAULT_TEST_CONFIG_FILENAME).await?;
    // Obtém um cliente MCP com escopos suficientes para gerenciar bancos.
    let mut client = test_env.mcp_client_with_auth(Some("typedb:manage_databases")).await?;

    let db_name = unique_db_name("create_valid");
    info!("Teste: Criando banco de dados '{}'", db_name);

    // Chama a ferramenta `create_database`.
    let result = client
        .call_tool("create_database", Some(json!({ "name": db_name })))
        .await
        .with_context(|| format!("Falha ao chamar create_database para '{db_name}'"))?;

    let text_content = get_text_from_call_result(result);
    assert_eq!(text_content, "OK", "Resposta incorreta ao criar banco de dados.");
    info!("Banco de dados '{}' criado com sucesso (resposta 'OK' recebida).", db_name);

    // Verifica se o banco de dados recém-criado agora existe.
    let exists_result = client
        .call_tool("database_exists", Some(json!({ "name": db_name })))
        .await
        .with_context(|| format!("Falha ao chamar database_exists para '{db_name}'"))?;
    let exists_text = get_text_from_call_result(exists_result);
    assert_eq!(
        exists_text, "true",
        "Banco de dados criado ('{db_name}') não foi encontrado por database_exists."
    );
    info!("Verificação database_exists para '{}' retornou 'true'.", db_name);

    // Limpeza: deleta o banco de dados criado.
    delete_test_db(&mut client, &db_name).await;
    info!("Teste test_create_database_succeeds_with_valid_name concluído.");
    Ok(())
}

/// Testa se a tentativa de criar um banco de dados que já existe falha
/// de forma graciosa, retornando um erro apropriado.
#[tokio::test]
#[serial]
async fn test_create_existing_database_fails_gracefully() -> Result<()> {
    info!("Iniciando teste: test_create_existing_database_fails_gracefully");
    let test_env =
        TestEnvironment::setup("db_create_dup", constants::DEFAULT_TEST_CONFIG_FILENAME).await?;
    let mut client = test_env.mcp_client_with_auth(Some("typedb:manage_databases")).await?;

    let db_name = unique_db_name("create_duplicate");
    // Cria o banco de dados uma vez (deve ter sucesso).
    create_test_db(&mut client, &db_name).await;

    info!("Teste: Tentando criar banco de dados duplicado '{}'", db_name);
    // Tenta criar o mesmo banco de dados novamente (deve falhar).
    let result_err = client
        .call_tool("create_database", Some(json!({ "name": db_name })))
        .await
        .expect_err("Esperado erro ao tentar criar banco de dados duplicado, mas obteve Ok.");
    info!("Chamada para criar banco duplicado '{}' falhou como esperado.", db_name);

    // Verifica se o erro retornado é o esperado para "DatabaseAlreadyExists".
    match result_err {
        McpClientError::McpErrorResponse { code, message, data } => {
            // Conforme a correção, esperamos INTERNAL_ERROR com 'data' específico.
            assert_eq!(
                code.0,
                McpErrorCode::INTERNAL_ERROR.0,
                "Código de erro inesperado para banco duplicado. Mensagem: {message}, Data: {data:?}"
            );
            assert!(
                message.to_lowercase().contains("banco de dados")
                    && message.to_lowercase().contains("já existe"),
                "Mensagem de erro não indicou que o banco de dados já existe: {message}"
            );
            // Verifica o campo 'data' para o tipo de erro específico.
            let data_val = data.expect("O campo 'data' não deveria ser None para este erro.");
            assert_eq!(
                data_val.get("type").and_then(|v| v.as_str()),
                Some("DatabaseAlreadyExists"),
                "Campo 'data.type' incorreto."
            );
            assert_eq!(
                data_val.get("databaseName").and_then(|v| v.as_str()),
                Some(db_name.as_str()),
                "Campo 'data.databaseName' incorreto."
            );
            info!("Erro para banco duplicado ('{}') verificado corretamente.", db_name);
        }
        other_err => {
            panic!("Tipo de erro inesperado ao criar banco de dados duplicado: {other_err:?}")
        }
    }

    // Limpeza.
    delete_test_db(&mut client, &db_name).await;
    info!("Teste test_create_existing_database_fails_gracefully concluído.");
    Ok(())
}

/// Testa a funcionalidade de `list_databases`, tanto em um servidor sem bancos
/// quanto após a criação de alguns bancos.
#[tokio::test]
#[serial]
async fn test_list_databases_empty_and_with_content() -> Result<()> {
    info!("Iniciando teste: test_list_databases_empty_and_with_content");
    let test_env =
        TestEnvironment::setup("db_list", constants::DEFAULT_TEST_CONFIG_FILENAME).await?;
    let mut client = test_env.mcp_client_with_auth(Some("typedb:manage_databases")).await?;

    info!("Teste: Listando bancos de dados em servidor potencialmente limpo (pode conter de testes anteriores).");
    // Primeira listagem: pode conter bancos de testes anteriores se o cleanup não for perfeito
    // ou se o ambiente de CI não garantir isolamento total.
    let result_initial = client
        .call_tool("list_databases", None)
        .await
        .context("Falha ao chamar list_databases (inicial)")?;
    let text_initial = get_text_from_call_result(result_initial);
    let dbs_initial: Vec<String> = serde_json::from_str(&text_initial)
        .context("Resposta de list_databases (inicial) não é JSON array")?;
    info!("Lista inicial de bancos (pode conter de testes anteriores): {:?}", dbs_initial);

    // Cria dois bancos de dados para este teste.
    let db_name1 = unique_db_name("list_1");
    let db_name2 = unique_db_name("list_2");
    create_test_db(&mut client, &db_name1).await;
    create_test_db(&mut client, &db_name2).await;

    info!("Teste: Listando bancos de dados após criações específicas do teste.");
    let result_with_dbs = client
        .call_tool("list_databases", None)
        .await
        .context("Falha ao chamar list_databases (com dados)")?;
    let text_with_dbs = get_text_from_call_result(result_with_dbs);
    let dbs_with_content: Vec<String> = serde_json::from_str(&text_with_dbs)
        .context("Resposta de list_databases (com dados) não é JSON array")?;

    // Verifica se os bancos criados neste teste estão presentes na lista.
    // A lista pode conter mais do que apenas estes dois.
    assert!(
        dbs_with_content.len() >= 2,
        "Número incorreto de bancos listados (esperado pelo menos 2, os criados neste teste): {dbs_with_content:?}"
    );
    assert!(
        dbs_with_content.contains(&db_name1),
        "Banco de dados '{db_name1}' não encontrado na lista: {dbs_with_content:?}"
    );
    assert!(
        dbs_with_content.contains(&db_name2),
        "Banco de dados '{db_name2}' não encontrado na lista: {dbs_with_content:?}"
    );
    info!("Bancos de dados criados ('{}', '{}') foram listados com sucesso.", db_name1, db_name2);

    // Limpeza.
    delete_test_db(&mut client, &db_name1).await;
    delete_test_db(&mut client, &db_name2).await;
    info!("Teste test_list_databases_empty_and_with_content concluído.");
    Ok(())
}

/// Testa a funcionalidade de `database_exists` para bancos existentes e inexistentes.
#[tokio::test]
#[serial]
async fn test_database_exists_functionality() -> Result<()> {
    info!("Iniciando teste: test_database_exists_functionality");
    let test_env =
        TestEnvironment::setup("db_exists", constants::DEFAULT_TEST_CONFIG_FILENAME).await?;
    let mut client = test_env.mcp_client_with_auth(Some("typedb:manage_databases")).await?;

    let db_name_existing = unique_db_name("exists_true");
    let db_name_non_existing = unique_db_name("exists_false");

    info!("Teste: Verificando existência do banco de dados inexistente '{}'", db_name_non_existing);
    let result_false = client
        .call_tool("database_exists", Some(json!({ "name": db_name_non_existing })))
        .await
        .with_context(|| {
            format!("Falha ao chamar database_exists para '{db_name_non_existing}'")
        })?;
    let text_false = get_text_from_call_result(result_false);
    assert_eq!(
        text_false, "false",
        "database_exists deveria retornar 'false' para banco de dados inexistente."
    );
    info!("Verificação para banco inexistente '{}' retornou 'false'.", db_name_non_existing);

    // Cria um banco de dados para testar o caso "existente".
    create_test_db(&mut client, &db_name_existing).await;
    info!("Teste: Verificando existência do banco de dados existente '{}'", db_name_existing);
    let result_true = client
        .call_tool("database_exists", Some(json!({ "name": db_name_existing })))
        .await
        .with_context(|| format!("Falha ao chamar database_exists para '{db_name_existing}'"))?;
    let text_true = get_text_from_call_result(result_true);
    assert_eq!(
        text_true, "true",
        "database_exists deveria retornar 'true' para banco de dados existente."
    );
    info!("Verificação para banco existente '{}' retornou 'true'.", db_name_existing);

    // Limpeza.
    delete_test_db(&mut client, &db_name_existing).await;
    info!("Teste test_database_exists_functionality concluído.");
    Ok(())
}

/// Testa se `delete_database` remove um banco de dados existente com sucesso.
#[tokio::test]
#[serial]
async fn test_delete_database_succeeds_and_removes_db() -> Result<()> {
    info!("Iniciando teste: test_delete_database_succeeds_and_removes_db");
    let test_env =
        TestEnvironment::setup("db_delete_ok", constants::DEFAULT_TEST_CONFIG_FILENAME).await?;
    // Requer escopo de admin para deletar, e manage para criar/verificar.
    let mut client = test_env
        .mcp_client_with_auth(Some("typedb:admin_databases typedb:manage_databases"))
        .await?;

    let db_name = unique_db_name("delete_target");
    create_test_db(&mut client, &db_name).await;

    // Confirma que o banco existe antes de deletar.
    let exists_before_result =
        client.call_tool("database_exists", Some(json!({ "name": db_name }))).await?;
    assert_eq!(
        get_text_from_call_result(exists_before_result),
        "true",
        "Banco deveria existir antes da deleção."
    );

    info!("Teste: Deletando banco de dados '{}'", db_name);
    let delete_result = client
        .call_tool("delete_database", Some(json!({ "name": db_name })))
        .await
        .with_context(|| format!("Falha ao chamar delete_database para '{db_name}'"))?;
    let delete_text = get_text_from_call_result(delete_result);
    assert_eq!(delete_text, "OK", "Resposta incorreta ao deletar banco de dados.");
    info!("Banco de dados '{}' deletado com sucesso (resposta 'OK' recebida).", db_name);

    // Confirma que o banco não existe mais após a deleção.
    info!("Teste: Verificando se o banco de dados '{}' foi realmente deletado.", db_name);
    let exists_after_result =
        client.call_tool("database_exists", Some(json!({ "name": db_name }))).await?;
    let exists_after_text = get_text_from_call_result(exists_after_result);
    assert_eq!(
        exists_after_text, "false",
        "Banco de dados ('{db_name}') não foi removido após delete_database."
    );
    info!("Verificação database_exists para '{}' retornou 'false' após deleção.", db_name);
    info!("Teste test_delete_database_succeeds_and_removes_db concluído.");
    Ok(())
}

/// Testa se a tentativa de deletar um banco de dados inexistente falha de forma graciosa.
#[tokio::test]
#[serial]
async fn test_delete_non_existent_database_fails_gracefully() -> Result<()> {
    info!("Iniciando teste: test_delete_non_existent_database_fails_gracefully");
    let test_env =
        TestEnvironment::setup("db_delete_missing", constants::DEFAULT_TEST_CONFIG_FILENAME)
            .await?;
    let mut client = test_env.mcp_client_with_auth(Some("typedb:admin_databases")).await?;

    let db_name_missing = unique_db_name("delete_non_existent");
    info!("Teste: Tentando deletar banco de dados inexistente '{}'", db_name_missing);

    let result_err = client
        .call_tool("delete_database", Some(json!({ "name": db_name_missing })))
        .await
        .expect_err("Esperado erro ao tentar deletar banco de dados inexistente, mas obteve Ok.");
    info!("Chamada para deletar banco inexistente '{}' falhou como esperado.", db_name_missing);

    // Verifica o tipo e a mensagem do erro.
    match result_err {
        McpClientError::McpErrorResponse { code, message, .. } => {
            // O driver TypeDB pode retornar um erro genérico quando o banco não é encontrado para deleção.
            assert_eq!(
                code.0,
                McpErrorCode::INTERNAL_ERROR.0, // Ou outro código se o driver for mais específico
                "Código de erro inesperado para deleção de banco de dados inexistente. Mensagem: {message}"
            );
            // A mensagem deve indicar que o banco não foi encontrado ou não existe.
            assert!(
                message.to_lowercase().contains("database")
                    && (message.to_lowercase().contains("not found")
                        || message.to_lowercase().contains("does not exist")
                        || message.to_lowercase().contains("no such database")), // Cobrir variações
                "Mensagem de erro não indicou que o banco de dados não existe: {message}"
            );
            info!(
                "Erro para deleção de banco inexistente ('{}') verificado corretamente.",
                db_name_missing
            );
        }
        other_err => {
            panic!("Tipo de erro inesperado ao deletar banco de dados inexistente: {other_err:?}")
        }
    }
    info!("Teste test_delete_non_existent_database_fails_gracefully concluído.");
    Ok(())
}

/// Testa se as operações de administração de banco de dados requerem os escopos OAuth2 corretos.
#[tokio::test]
#[serial]
async fn test_db_admin_operations_require_correct_scopes() -> Result<()> {
    info!("Iniciando teste: test_db_admin_operations_require_correct_scopes");
    let test_env = TestEnvironment::setup(
        "db_admin_scopes",
        constants::OAUTH_ENABLED_TEST_CONFIG_FILENAME, // Usa configuração com OAuth habilitado
    )
    .await?;
    let db_name = unique_db_name("authz_db");

    // 1. Cliente sem nenhum escopo relevante para `create_database`.
    let mut client_no_perms = test_env.mcp_client_with_auth(Some("other:scope")).await?;

    info!("Teste: Tentando create_database sem escopo 'typedb:manage_databases'.");
    let res_create_no_perms =
        client_no_perms.call_tool("create_database", Some(json!({"name": db_name}))).await;
    assert!(res_create_no_perms.is_err(), "create_database sem escopo deveria falhar.");
    if let McpClientError::McpErrorResponse { code, .. } = res_create_no_perms.expect_err("create_database deveria falhar baseado no assert") {
        assert_eq!(code.0, McpErrorCode(-32001).0, "Esperado erro de Autorização Falhou.");
    // -32001: Authorization Failed
    } else {
        panic!("Esperado McpErrorResponse (Authorization Failed) para create_database sem escopo.");
    }
    info!("Tentativa de create_database sem escopo falhou como esperado.");

    // 2. Cliente com escopo `typedb:manage_databases` para criar o banco.
    let mut client_manage_perms =
        test_env.mcp_client_with_auth(Some("typedb:manage_databases")).await?;
    create_test_db(&mut client_manage_perms, &db_name).await; // Deve ter sucesso

    // 3. Tentar deletar com escopo `typedb:manage_databases` (que é insuficiente).
    info!("Teste: Tentando delete_database com escopo 'typedb:manage_databases' (insuficiente).");
    let res_delete_manage_perms =
        client_manage_perms.call_tool("delete_database", Some(json!({"name": db_name}))).await;
    assert!(
        res_delete_manage_perms.is_err(),
        "delete_database com escopo manage_databases deveria falhar."
    );
    if let McpClientError::McpErrorResponse { code, .. } = res_delete_manage_perms.expect_err("delete_database deveria falhar baseado no assert") {
        assert_eq!(
            code.0,
            McpErrorCode(-32001).0,
            "Esperado erro de Autorização Falhou para delete."
        );
    } else {
        panic!("Esperado McpErrorResponse (Authorization Failed) para delete_database com escopo insuficiente.");
    }
    info!("Tentativa de delete_database com escopo manage_databases falhou como esperado.");

    // 4. Cliente com escopo `typedb:admin_databases` para deletar o banco.
    let mut client_admin_perms =
        test_env.mcp_client_with_auth(Some("typedb:admin_databases")).await?;
    delete_test_db(&mut client_admin_perms, &db_name).await; // Deve ter sucesso
    info!("Banco de dados deletado com sucesso usando escopo admin_databases.");
    info!("Teste test_db_admin_operations_require_correct_scopes concluído.");
    Ok(())
}
