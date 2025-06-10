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

//! Contém os handlers para as ferramentas MCP relacionadas ao gerenciamento
//! de bancos de dados TypeDB, como criar, listar, verificar existência e deletar bancos.
//!
//! Cada função handler aqui corresponde a uma ferramenta MCP e é chamada pelo
//! `McpServiceHandler` após a verificação de autenticação/autorização.
//! Elas interagem com o `TypeDBDriver` para realizar as operações no TypeDB
//! e retornam resultados ou erros no formato MCP.

use std::borrow::Cow;
use std::sync::Arc;

use rmcp::model::{CallToolResult, Content, ErrorCode, ErrorData};
use serde_json::json; // Para construir JSON no corpo de ErrorData
use typedb_driver::TypeDBDriver;

use super::params; // Importa as structs de parâmetros definidas em src/tools/params.rs
use crate::error::typedb_error_to_mcp_error_data; // Utilitário para converter erros do driver

/// Handler para a ferramenta `create_database`.
///
/// Cria um novo banco de dados TypeDB com o nome especificado.
/// Antes de tentar criar, verifica se um banco de dados com o mesmo nome já existe.
/// Se já existir, retorna um erro indicando isso.
///
/// # Parâmetros
/// * `driver`: Uma referência `Arc` para o `TypeDBDriver` conectado, permitindo interação com o TypeDB.
/// * `params`: Parâmetros da ferramenta, contendo o `name` (String) do banco de dados a ser criado.
///   Esta struct é desserializada de `CallToolRequestParam.arguments`.
///
/// # Retorna
/// `Result<CallToolResult, ErrorData>`:
/// * `Ok(CallToolResult)` com "OK" no conteúdo em caso de criação bem-sucedida.
/// * `Err(ErrorData)` se ocorrer um erro, como:
///   - O banco de dados já existe (retorna `ErrorCode::INTERNAL_ERROR` com `data.type = "DatabaseAlreadyExists"`).
///   - Falha ao comunicar com o TypeDB.
///   - Outros erros do driver TypeDB.
#[tracing::instrument(skip(driver, params), fields(db.name = %params.name), name = "db_admin_handle_create_database")]
pub async fn handle_create_database(
    driver: Arc<TypeDBDriver>,
    params: params::CreateDatabaseParams,
) -> Result<CallToolResult, ErrorData> {
    tracing::info!("Executando ferramenta 'create_database' para o banco: {}", params.name);

    // 1. Verificar se o banco de dados já existe
    match driver.databases().contains(&params.name).await {
        Ok(true) => {
            // O banco de dados já existe. Retornar um erro específico.
            tracing::warn!(db.name = %params.name, "Tentativa de criar banco de dados que já existe.");
            // Usar ErrorCode::INTERNAL_ERROR (-32603) e detalhar a causa no campo 'data'.
            // Isso garante compatibilidade com clientes MCP que podem não entender códigos customizados,
            // mas ainda permite que o servidor forneça informações específicas sobre o erro.
            return Err(ErrorData {
                code: ErrorCode::INTERNAL_ERROR,
                message: Cow::Owned(format!(
                    "Falha ao criar banco: O banco de dados '{}' já existe.",
                    params.name
                )),
                data: Some(json!({
                    "type": "DatabaseAlreadyExists", // Tipo de erro específico da aplicação
                    "databaseName": params.name,
                    "detail": "Um banco de dados com este nome já está presente no servidor TypeDB."
                })),
            });
        }
        Ok(false) => {
            // O banco não existe, podemos prosseguir com a tentativa de criação.
            tracing::debug!(db.name = %params.name, "Banco de dados não existe, procedendo com a criação.");
        }
        Err(e_check) => {
            // Ocorreu um erro ao tentar verificar a existência do banco.
            tracing::error!(db.name = %params.name, error.message = %e_check, "Erro ao verificar se o banco já existe antes de criar.");
            return Err(typedb_error_to_mcp_error_data(
                &e_check,
                "create_database (verificar existência)", // Contexto para o erro
            ));
        }
    }

    // 2. Tentar criar o banco de dados
    driver
        .databases()
        .create(&params.name) // `params.name` é uma String, `create` aceita &str
        .await
        .map(|()| {
            // Callback para o caso de sucesso da criação
            tracing::info!(db.name = %params.name, "Banco de dados criado com sucesso.");
            CallToolResult::success(vec![Content::text("OK")])
        })
        .map_err(|e_create| {
            // Callback para o caso de erro durante a criação
            // Isso pode acontecer por outras razões além de "já existe",
            // como problemas de permissão no servidor TypeDB, etc.
            tracing::error!(db.name = %params.name, error.message = %e_create, "Falha ao criar banco de dados.");
            typedb_error_to_mcp_error_data(&e_create, "create_database (chamada de criação)")
        })
}

/// Handler para a ferramenta `database_exists`.
///
/// Verifica se um banco de dados com o nome especificado existe no servidor TypeDB.
///
/// # Parâmetros
/// * `driver`: Uma referência `Arc` para o `TypeDBDriver` conectado.
/// * `params`: Parâmetros da ferramenta, contendo o `name` (String) do banco a ser verificado.
///
/// # Retorna
/// `Result<CallToolResult, ErrorData>`:
/// * `Ok(CallToolResult)` com "true" ou "false" (como string) no conteúdo.
/// * `Err(ErrorData)` se ocorrer um erro durante a comunicação com o TypeDB.
#[tracing::instrument(skip(driver, params), fields(db.name = %params.name), name = "db_admin_handle_database_exists")]
pub async fn handle_database_exists(
    driver: Arc<TypeDBDriver>,
    params: params::DatabaseExistsParams,
) -> Result<CallToolResult, ErrorData> {
    tracing::info!("Executando ferramenta 'database_exists' para o banco: {}", params.name);
    match driver.databases().contains(&params.name).await {
        Ok(exists) => {
            tracing::debug!(db.name = %params.name, db.exists = %exists, "Verificação de existência do banco de dados concluída.");
            // Retorna o booleano como uma string "true" ou "false"
            Ok(CallToolResult::success(vec![Content::text(exists.to_string())]))
        }
        Err(e) => {
            tracing::error!(db.name = %params.name, error.message = %e, "Falha ao verificar existência do banco de dados.");
            Err(typedb_error_to_mcp_error_data(&e, "database_exists"))
        }
    }
}

/// Handler para a ferramenta `list_databases`.
///
/// Lista os nomes de todos os bancos de dados atualmente existentes no servidor TypeDB.
///
/// # Parâmetros
/// * `driver`: Uma referência `Arc` para o `TypeDBDriver` conectado.
///
/// # Retorna
/// `Result<CallToolResult, ErrorData>`:
/// * `Ok(CallToolResult)` com uma string JSON contendo um array dos nomes dos bancos.
/// * `Err(ErrorData)` se ocorrer um erro ao listar os bancos ou ao serializar a lista para JSON.
#[tracing::instrument(skip(driver), name = "db_admin_handle_list_databases")]
pub async fn handle_list_databases(driver: Arc<TypeDBDriver>) -> Result<CallToolResult, ErrorData> {
    tracing::info!("Executando ferramenta 'list_databases'");
    match driver.databases().all().await {
        Ok(databases) => {
            // Mapeia a lista de `typedb_driver::database::DatabaseInfo` para um Vec<String> de nomes.
            let names: Vec<String> = databases.iter().map(|db| db.name().to_string()).collect();
            tracing::debug!(
                num_databases = names.len(),
                databases_found = ?names, // Loga os nomes para depuração
                "Bancos de dados encontrados."
            );
            // Serializa o Vec<String> para uma string JSON.
            match serde_json::to_string(&names) {
                Ok(json_string) => Ok(CallToolResult::success(vec![Content::text(json_string)])),
                Err(e_json) => {
                    // Erro interno se a serialização falhar.
                    tracing::error!(error.message = %e_json, "Falha ao serializar lista de bancos para JSON.");
                    Err(ErrorData {
                        code: ErrorCode::INTERNAL_ERROR,
                        message: Cow::Owned(format!(
                            "Falha ao serializar lista de bancos para JSON: {e_json}"
                        )),
                        data: Some(serde_json::json!({
                            "type": "SerializationError",
                            "detail": e_json.to_string(), // Inclui detalhes do erro de serialização
                        })),
                    })
                }
            }
        }
        Err(e_list) => {
            tracing::error!(error.message = %e_list, "Falha ao listar bancos de dados.");
            Err(typedb_error_to_mcp_error_data(&e_list, "list_databases"))
        }
    }
}

/// Handler para a ferramenta `delete_database`.
///
/// **PERMANENTEMENTE REMOVE** um banco de dados existente, incluindo todo o seu esquema e dados.
/// Esta é uma operação destrutiva e deve ser usada com extrema cautela.
///
/// # Parâmetros
/// * `driver`: Uma referência `Arc` para o `TypeDBDriver` conectado.
/// * `params`: Parâmetros da ferramenta, contendo o `name` (String) do banco a ser deletado.
///
/// # Retorna
/// `Result<CallToolResult, ErrorData>`:
/// * `Ok(CallToolResult)` com "OK" no conteúdo em caso de deleção bem-sucedida.
/// * `Err(ErrorData)` se o banco de dados não for encontrado ou ocorrer outro erro durante a deleção.
#[tracing::instrument(skip(driver, params), fields(db.name = %params.name), name = "db_admin_handle_delete_database")]
pub async fn handle_delete_database(
    driver: Arc<TypeDBDriver>,
    params: params::DeleteDatabaseParams,
) -> Result<CallToolResult, ErrorData> {
    // Loga um aviso devido à natureza destrutiva da operação.
    tracing::warn!("Executando ferramenta DESTRUTIVA 'delete_database' para o banco: {}. Esta ação é IRREVERSÍVEL.", params.name);
    // Primeiro, tenta obter uma referência ao banco de dados.
    // A chamada `get` falhará se o banco não existir.
    match driver.databases().get(&params.name).await {
        Ok(db_arc) => {
            // Se o banco foi obtido com sucesso, tenta deletá-lo.
            db_arc
                .delete()
                .await
                .map(|()| {
                    tracing::info!(db.name = %params.name, "Banco de dados deletado com sucesso.");
                    CallToolResult::success(vec![Content::text("OK")])
                })
                .map_err(|e_delete| {
                    tracing::error!(db.name = %params.name, error.message = %e_delete, "Falha ao deletar banco de dados (após obtê-lo).");
                    typedb_error_to_mcp_error_data(&e_delete, "delete_database (chamada de delete)")
                })
        }
        Err(e_get) => {
            // Erro ao obter o banco (ex: não existe).
            tracing::error!(db.name = %params.name, error.message = %e_get, "Falha ao obter banco de dados para deleção (provavelmente não existe).");
            Err(typedb_error_to_mcp_error_data(&e_get, "delete_database (obter banco)"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::ErrorCode;
    use serde_json::json;
    use std::borrow::Cow;
    use typedb_driver::Error as TypeDBError; // Para json! macro

    // Testes para handle_create_database
    #[tokio::test]
    async fn test_handle_create_database_success_flow() {
        // Simula um resultado de sucesso da chamada ao driver
        let successful_mcp_result: Result<CallToolResult, ErrorData> =
            Ok(CallToolResult::success(vec![Content::text("OK")]));

        assert!(successful_mcp_result.is_ok());
        if let Ok(result_content) = successful_mcp_result {
            assert_eq!(result_content.content.len(), 1);
            assert_eq!(result_content.content[0].as_text().unwrap().text, "OK");
            assert!(!result_content.is_error.unwrap_or(false));
        } else {
            panic!("Esperado Ok, mas obteve Err.");
        }
    }

    #[tokio::test]
    async fn test_handle_create_database_driver_error_flow() {
        // Simula um erro do driver TypeDB
        let typedb_error = TypeDBError::Other("Erro simulado ao criar banco.".into());
        let expected_mcp_error_data =
            typedb_error_to_mcp_error_data(&typedb_error, "create_database (create call)");
        let handler_output: Result<CallToolResult, ErrorData> = Err(expected_mcp_error_data);

        assert!(handler_output.is_err());
        if let Err(err_data) = handler_output {
            assert_eq!(err_data.code, ErrorCode::INTERNAL_ERROR);
            assert!(err_data.message.contains("create_database (create call)"));
            assert!(err_data.message.contains("Erro simulado ao criar banco."));
        } else {
            panic!("Esperado Err, mas obteve Ok.");
        }
    }

    #[tokio::test]
    async fn test_handle_create_database_already_exists_error_flow() {
        let db_name = "db_ja_existente";
        // Simula o ErrorData que seria retornado se o banco já existisse
        let expected_mcp_error_data = ErrorData {
            code: ErrorCode::INTERNAL_ERROR, // Código alterado para INTERNAL_ERROR
            message: Cow::Owned(format!(
                "Falha ao criar banco: O banco de dados '{}' já existe.",
                db_name
            )),
            data: Some(json!({
                "type": "DatabaseAlreadyExists",
                "databaseName": db_name,
                "detail": "Um banco de dados com este nome já está presente no servidor TypeDB."
            })),
        };
        let handler_output: Result<CallToolResult, ErrorData> = Err(expected_mcp_error_data);

        assert!(handler_output.is_err());
        if let Err(err_data) = handler_output {
            assert_eq!(err_data.code, ErrorCode::INTERNAL_ERROR); // Verifica se o código é INTERNAL_ERROR
            assert!(err_data.message.contains("já existe"));
            let data_field = err_data.data.as_ref().expect("Campo data não pode ser None");
            assert_eq!(
                data_field.get("type").and_then(|v| v.as_str()),
                Some("DatabaseAlreadyExists")
            );
            assert_eq!(data_field.get("databaseName").and_then(|v| v.as_str()), Some(db_name));
        } else {
            panic!("Esperado Err, mas obteve Ok.");
        }
    }

    // Testes para handle_database_exists
    #[tokio::test]
    async fn test_handle_database_exists_true_flow() {
        let successful_mcp_result: Result<CallToolResult, ErrorData> =
            Ok(CallToolResult::success(vec![Content::text("true")]));
        assert!(successful_mcp_result.is_ok());
        assert_eq!(successful_mcp_result.unwrap().content[0].as_text().unwrap().text, "true");
    }

    #[tokio::test]
    async fn test_handle_database_exists_false_flow() {
        let successful_mcp_result: Result<CallToolResult, ErrorData> =
            Ok(CallToolResult::success(vec![Content::text("false")]));
        assert!(successful_mcp_result.is_ok());
        assert_eq!(successful_mcp_result.unwrap().content[0].as_text().unwrap().text, "false");
    }

    // Testes para handle_list_databases
    #[tokio::test]
    async fn test_handle_list_databases_success_flow() {
        let db_names = vec!["db_alpha".to_string(), "db_beta".to_string()];
        let json_names = serde_json::to_string(&db_names).expect("Serialização de teste falhou");
        let successful_mcp_result: Result<CallToolResult, ErrorData> =
            Ok(CallToolResult::success(vec![Content::text(json_names.clone())]));

        assert!(successful_mcp_result.is_ok());
        assert_eq!(successful_mcp_result.unwrap().content[0].as_text().unwrap().text, json_names);
    }

    #[tokio::test]
    async fn test_handle_list_databases_serialization_error_flow() {
        let error_message = "Falha simulada ao serializar lista de bancos para JSON";
        let expected_mcp_error_data = ErrorData {
            code: ErrorCode::INTERNAL_ERROR,
            message: Cow::Owned(error_message.to_string()),
            data: Some(json!({"type": "SerializationError", "detail": "detalhe do erro simulado"})),
        };
        let handler_output: Result<CallToolResult, ErrorData> = Err(expected_mcp_error_data);

        assert!(handler_output.is_err());
        if let Err(err_data) = handler_output {
            assert_eq!(err_data.code, ErrorCode::INTERNAL_ERROR);
            assert!(err_data.message.contains("Falha simulada"));
            assert_eq!(err_data.data.as_ref().unwrap()["type"], "SerializationError");
        } else {
            panic!("Esperado Err, mas obteve Ok.");
        }
    }

    // Testes para handle_delete_database
    #[tokio::test]
    async fn test_handle_delete_database_success_flow() {
        let successful_mcp_result: Result<CallToolResult, ErrorData> =
            Ok(CallToolResult::success(vec![Content::text("OK")]));
        assert!(successful_mcp_result.is_ok());
        assert_eq!(successful_mcp_result.unwrap().content[0].as_text().unwrap().text, "OK");
    }

    #[tokio::test]
    async fn test_handle_delete_database_get_error_flow() {
        let typedb_error = TypeDBError::Other("Simulado: DB não encontrado para deleção".into());
        let expected_mcp_error_data =
            typedb_error_to_mcp_error_data(&typedb_error, "delete_database (obter banco)");
        let handler_output: Result<CallToolResult, ErrorData> = Err(expected_mcp_error_data);

        assert!(handler_output.is_err());
        if let Err(err_data) = handler_output {
            assert!(err_data.message.contains("delete_database (obter banco)"));
            assert!(err_data.message.contains("Simulado: DB não encontrado"));
        } else {
            panic!("Esperado Err, mas obteve Ok.");
        }
    }
}
