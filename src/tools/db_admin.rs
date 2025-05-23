// src/tools/db_admin.rs

// Licença Apache 2.0
// Copyright [ANO_ATUAL] [SEU_NOME_OU_ORGANIZACAO]
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Contém os handlers para as ferramentas MCP relacionadas ao gerenciamento
//! de bancos de dados TypeDB, como criar, listar, verificar existência e deletar bancos.

use std::borrow::Cow;
use std::sync::Arc;

use rmcp::model::{CallToolResult, Content, ErrorCode, ErrorData};
use typedb_driver::TypeDBDriver;

use super::params;
use crate::error::typedb_error_to_mcp_error_data;

/// Handler para a ferramenta `create_database`.
///
/// Cria um novo banco de dados TypeDB com o nome especificado.
///
/// # Parâmetros
/// * `driver`: Uma referência `Arc` para o `TypeDBDriver` conectado.
/// * `params`: Parâmetros da ferramenta, contendo o `name` do banco a ser criado.
///
/// # Retorna
/// `Ok(CallToolResult)` com "OK" em caso de sucesso, ou `Err(ErrorData)`
/// se ocorrer um erro durante a comunicação com o TypeDB ou se o banco já existir.
#[tracing::instrument(skip(driver, params), fields(db_name = %params.name))]
pub async fn handle_create_database(
    driver: Arc<TypeDBDriver>,
    params: params::CreateDatabaseParams,
) -> Result<CallToolResult, ErrorData> {
    // Usar %params.name na macro de log para usar a implementação Display e evitar move.
    tracing::info!("Executando ferramenta 'create_database' para o banco.");
    driver
        .databases()
        .create(params.name) // Passa referência &String, que AsRef<str> aceita.
        .await
        .map(|()| {
            // db_name já está no span do instrument.
            tracing::info!("Banco de dados criado com sucesso.");
            CallToolResult::success(vec![Content::text("OK")])
        })
        .map_err(|e| {
            // db_name já está no span do instrument.
            tracing::error!(error.message = %e, "Falha ao criar banco de dados.");
            typedb_error_to_mcp_error_data(&e, "create_database")
        })
}

/// Handler para a ferramenta `database_exists`.
///
/// Verifica se um banco de dados com o nome especificado existe no servidor TypeDB.
///
/// # Parâmetros
/// * `driver`: Uma referência `Arc` para o `TypeDBDriver` conectado.
/// * `params`: Parâmetros da ferramenta, contendo o `name` do banco a ser verificado.
///
/// # Retorna
/// `Ok(CallToolResult)` com "true" ou "false" em caso de sucesso, ou `Err(ErrorData)`
/// se ocorrer um erro durante a comunicação com o TypeDB.
#[tracing::instrument(skip(driver, params), fields(db_name = %params.name))]
pub async fn handle_database_exists(
    driver: Arc<TypeDBDriver>,
    params: params::DatabaseExistsParams,
) -> Result<CallToolResult, ErrorData> {
    tracing::info!("Executando ferramenta 'database_exists' para o banco.");
    match driver.databases().contains(params.name).await {
        Ok(exists) => {
            tracing::debug!(db.exists = %exists, "Verificação de existência do banco de dados concluída.");
            Ok(CallToolResult::success(vec![Content::text(exists.to_string())]))
        }
        Err(e) => {
            tracing::error!(error.message = %e, "Falha ao verificar existência do banco de dados.");
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
/// `Ok(CallToolResult)` com um array JSON de nomes de bancos em caso de sucesso,
/// ou `Err(ErrorData)` se ocorrer um erro.
#[tracing::instrument(skip(driver))]
pub async fn handle_list_databases(driver: Arc<TypeDBDriver>) -> Result<CallToolResult, ErrorData> {
    tracing::info!("Executando ferramenta 'list_databases'");
    match driver.databases().all().await {
        Ok(databases) => {
            let names: Vec<String> = databases.iter().map(|db| db.name().to_string()).collect();
            tracing::debug!(
                num_databases = names.len(),
                "Bancos de dados encontrados: {:?}",
                names
            );
            match serde_json::to_string(&names) {
                Ok(json_string) => Ok(CallToolResult::success(vec![Content::text(json_string)])),
                Err(e) => {
                    tracing::error!(error.message = %e, "Falha ao serializar lista de bancos para JSON.");
                    Err(ErrorData {
                        code: ErrorCode::INTERNAL_ERROR,
                        message: Cow::Owned(format!(
                            "Falha ao serializar lista de bancos para JSON: {e}"
                        )),
                        data: Some(serde_json::json!({
                            "type": "SerializationError",
                            "detail": e.to_string(),
                        })),
                    })
                }
            }
        }
        Err(e) => {
            tracing::error!(error.message = %e, "Falha ao listar bancos de dados.");
            Err(typedb_error_to_mcp_error_data(&e, "list_databases"))
        }
    }
}

/// Handler para a ferramenta `delete_database`.
///
/// **PERMANENTEMENTE REMOVE** um banco de dados existente, incluindo todo o seu esquema e dados.
///
/// # Parâmetros
/// * `driver`: Uma referência `Arc` para o `TypeDBDriver` conectado.
/// * `params`: Parâmetros da ferramenta, contendo o `name` do banco a ser deletado.
///
/// # Retorna
/// `Ok(CallToolResult)` com "OK" em caso de sucesso, ou `Err(ErrorData)` se o banco
/// não for encontrado ou ocorrer outro erro.
#[tracing::instrument(skip(driver, params), fields(db_name = %params.name))]
pub async fn handle_delete_database(
    driver: Arc<TypeDBDriver>,
    params: params::DeleteDatabaseParams,
) -> Result<CallToolResult, ErrorData> {
    tracing::warn!("Executando ferramenta DESTRUTIVA 'delete_database' para o banco. Esta ação é IRREVERSÍVEL.");
    match driver.databases().get(params.name).await {
        Ok(db_arc) => db_arc
            .delete()
            .await
            .map(|()| {
                tracing::info!("Banco de dados deletado com sucesso.");
                CallToolResult::success(vec![Content::text("OK")])
            })
            .map_err(|e| {
                tracing::error!(error.message = %e, "Falha ao deletar banco de dados (após obtê-lo).");
                typedb_error_to_mcp_error_data(&e, "delete_database (delete call)")
            }),
        Err(e) => {
            tracing::error!(error.message = %e, "Falha ao obter banco de dados para deleção.");
            Err(typedb_error_to_mcp_error_data(&e, "delete_database (get database)"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Não precisamos mais importar os params individualmente aqui, pois não são usados diretamente
    // use crate::tools::params::{
    //     CreateDatabaseParams, DatabaseExistsParams, DeleteDatabaseParams,
    // };
    use rmcp::model::ErrorCode; // Necessário para o teste de erro de serialização
    use std::borrow::Cow;
    use typedb_driver::Error as TypeDBError; // Necessário para o teste de erro de serialização

    #[tokio::test]
    async fn test_handle_create_database_success_flow() {
        let successful_mcp_result: Result<CallToolResult, ErrorData> =
            Ok(CallToolResult::success(vec![Content::text("OK")]));

        assert!(successful_mcp_result.is_ok());
        match successful_mcp_result {
            Ok(result_content) => {
                assert_eq!(result_content.content.len(), 1);
                match result_content.content[0].as_text() {
                    Some(text_content) => assert_eq!(text_content.text, "OK"),
                    None => panic!("Esperado Content::text no índice 0"),
                }
                assert!(!result_content.is_error.unwrap_or(false));
            }
            Err(e) => panic!("Esperado Ok, obteve Err: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_handle_create_database_driver_error_flow() {
        let typedb_error = TypeDBError::Other("Erro ao criar banco de dados".into());
        let expected_mcp_error_data =
            typedb_error_to_mcp_error_data(&typedb_error, "create_database");
        let handler_output: Result<CallToolResult, ErrorData> = Err(expected_mcp_error_data);

        assert!(handler_output.is_err());
        match handler_output {
            Err(err_data) => {
                assert_eq!(err_data.code, ErrorCode::INTERNAL_ERROR);
                assert!(err_data.message.contains("Erro na ferramenta MCP 'create_database'"));
                assert!(err_data.message.contains("Erro ao criar banco de dados"));
            }
            Ok(val) => panic!("Esperado Err, obteve Ok: {val:?}"),
        }
    }

    #[tokio::test]
    async fn test_handle_database_exists_true_flow() {
        let successful_mcp_result: Result<CallToolResult, ErrorData> =
            Ok(CallToolResult::success(vec![Content::text("true")]));

        assert!(successful_mcp_result.is_ok());
        match successful_mcp_result {
            Ok(result_content) => match result_content.content[0].as_text() {
                Some(text_content) => assert_eq!(text_content.text, "true"),
                None => panic!("Esperado Content::text no índice 0"),
            },
            Err(e) => panic!("Esperado Ok, obteve Err: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_handle_database_exists_false_flow() {
        let successful_mcp_result: Result<CallToolResult, ErrorData> =
            Ok(CallToolResult::success(vec![Content::text("false")]));

        assert!(successful_mcp_result.is_ok());
        match successful_mcp_result {
            Ok(result_content) => match result_content.content[0].as_text() {
                Some(text_content) => assert_eq!(text_content.text, "false"),
                None => panic!("Esperado Content::text no índice 0"),
            },
            Err(e) => panic!("Esperado Ok, obteve Err: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_handle_list_databases_success_flow() {
        let db_names = vec!["db1".to_string(), "db2".to_string()];
        let json_names = match serde_json::to_string(&db_names) {
            Ok(s) => s,
            Err(e) => panic!("Falha ao serializar db_names para JSON: {e}"),
        };
        let successful_mcp_result: Result<CallToolResult, ErrorData> =
            Ok(CallToolResult::success(vec![Content::text(json_names.clone())]));

        assert!(successful_mcp_result.is_ok());
        match successful_mcp_result {
            Ok(result_content) => match result_content.content[0].as_text() {
                Some(text_content) => assert_eq!(text_content.text, json_names),
                None => panic!("Esperado Content::text no índice 0"),
            },
            Err(e) => panic!("Esperado Ok, obteve Err: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_handle_list_databases_serialization_error_flow() {
        let error_message = "Falha ao serializar lista de bancos para JSON: mock serde error";
        let expected_mcp_error_data = ErrorData {
            code: ErrorCode::INTERNAL_ERROR,
            message: Cow::Owned(error_message.to_string()),
            data: Some(
                serde_json::json!({"type": "SerializationError", "detail": "mock serde error"}),
            ),
        };
        let handler_output: Result<CallToolResult, ErrorData> = Err(expected_mcp_error_data);

        assert!(handler_output.is_err());
        match handler_output {
            Err(err_data) => {
                assert_eq!(err_data.code, ErrorCode::INTERNAL_ERROR);
                assert!(err_data.message.contains("mock serde error"));
                match err_data.data {
                    Some(data) => assert_eq!(data["type"], "SerializationError"),
                    None => panic!("Esperado campo data no erro"),
                }
            }
            Ok(val) => panic!("Esperado Err, obteve Ok: {val:?}"),
        }
    }

    #[tokio::test]
    async fn test_handle_delete_database_success_flow() {
        let successful_mcp_result: Result<CallToolResult, ErrorData> =
            Ok(CallToolResult::success(vec![Content::text("OK")]));

        assert!(successful_mcp_result.is_ok());
        match successful_mcp_result {
            Ok(result_content) => match result_content.content[0].as_text() {
                Some(text_content) => assert_eq!(text_content.text, "OK"),
                None => panic!("Esperado Content::text no índice 0"),
            },
            Err(e) => panic!("Esperado Ok, obteve Err: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_handle_delete_database_get_error_flow() {
        let typedb_error = TypeDBError::Other("DB não encontrado para deleção".into());
        let expected_mcp_error_data =
            typedb_error_to_mcp_error_data(&typedb_error, "delete_database (get database)");
        let handler_output: Result<CallToolResult, ErrorData> = Err(expected_mcp_error_data);

        assert!(handler_output.is_err());
        match handler_output {
            Err(err_data) => {
                assert!(err_data.message.contains("DB não encontrado para deleção"));
            }
            Ok(val) => panic!("Esperado Err, obteve Ok: {val:?}"),
        }
    }
}
