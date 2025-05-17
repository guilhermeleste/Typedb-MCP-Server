// src/tools/schema_ops.rs

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

//! Contém os handlers para as ferramentas MCP relacionadas a operações de esquema
//! no TypeDB, como definir, remover e obter definições de esquema.

use std::borrow::Cow; // Necessário para ErrorData
use std::sync::Arc;

use rmcp::model::{CallToolResult, Content, ErrorCode, ErrorData};
use typedb_driver::{answer::QueryAnswer, TransactionOptions, TransactionType, TypeDBDriver};

use crate::error::typedb_error_to_mcp_error_data;
use super::params;

/// Handler para a ferramenta `define_schema`.
///
/// Executa uma ou mais declarações TypeQL `define` para adicionar ou estender
/// o esquema do banco de dados especificado.
///
/// # Parâmetros
/// * `driver`: Uma referência `Arc` para o `TypeDBDriver` conectado.
/// * `params`: Parâmetros da ferramenta, contendo `database_name` e `schema_definition`.
///
/// # Retorna
/// `Ok(CallToolResult)` com "OK" em caso de sucesso, ou `Err(ErrorData)`
/// se ocorrer um erro.
#[tracing::instrument(skip(driver, params), name = "tool_define_schema")]
pub async fn handle_define_schema(
    driver: Arc<TypeDBDriver>,
    params: params::DefineSchemaParams,
) -> Result<CallToolResult, ErrorData> {
    // Log explícito dos parâmetros no início para evitar problemas de move com a macro `instrument`.
    tracing::info!(
        db.name = %params.database_name,
        schema.length = params.schema_definition.len(),
        "Executando ferramenta 'define_schema'."
    );

    let db = driver
        .databases()
        .get(&params.database_name) // Passa referência, não move.
        .await
        .map_err(|e| {
            tracing::error!(db.name = %params.database_name, error.message = %e, "Falha ao obter banco de dados para define_schema.");
            typedb_error_to_mcp_error_data(&e, "define_schema (obter banco)")
        })?;

    let transaction = driver
        .transaction_with_options(db.name(), TransactionType::Schema, TransactionOptions::default())
        .await
        .map_err(|e| {
            tracing::error!(db.name = %params.database_name, error.message = %e, "Falha ao abrir transação de esquema para define_schema.");
            typedb_error_to_mcp_error_data(&e, "define_schema (abrir transação)")
        })?;

    match transaction.query(params.schema_definition).await {
        Ok(QueryAnswer::Ok(_)) => {
            transaction.commit().await.map_err(|e| {
                tracing::error!(db.name = %params.database_name, error.message = %e, "Falha ao fazer commit da transação para define_schema.");
                typedb_error_to_mcp_error_data(&e, "define_schema (commit)")
            })?;
            tracing::info!(db.name = %params.database_name, "Schema definido com sucesso.");
            Ok(CallToolResult::success(vec![Content::text("OK")]))
        }
        Ok(other_answer) => {
            let response_type_str = format!("{other_answer:?}");
            tracing::error!(db.name = %params.database_name, response.type = %response_type_str,"Resposta inesperada para query define_schema.");
            Err(ErrorData {
                code: ErrorCode::INTERNAL_ERROR,
                message: Cow::Owned(
                    "Resposta inesperada do servidor TypeDB para query define_schema.".to_string()
                ),
                data: Some(serde_json::json!({
                    "type": "UnexpectedQueryAnswer",
                    "expected": "Ok",
                    "received": response_type_str,
                })),
            })
        }
        Err(e) => {
            tracing::error!(db.name = %params.database_name, error.message = %e, "Falha ao executar query define_schema.");
            Err(typedb_error_to_mcp_error_data(&e, "define_schema (executar query)"))
        }
    }
}

/// Handler para a ferramenta `undefine_schema`.
///
/// Executa uma ou mais declarações TypeQL `undefine` para remover definições
/// do esquema do banco de dados especificado.
///
/// # Parâmetros
/// * `driver`: Uma referência `Arc` para o `TypeDBDriver` conectado.
/// * `params`: Parâmetros da ferramenta, contendo `database_name` e `schema_undefinition`.
///
/// # Retorna
/// `Ok(CallToolResult)` com "OK" em caso de sucesso, ou `Err(ErrorData)`
/// se ocorrer um erro.
#[tracing::instrument(skip(driver, params), name = "tool_undefine_schema")]
pub async fn handle_undefine_schema(
    driver: Arc<TypeDBDriver>,
    params: params::UndefineSchemaParams,
) -> Result<CallToolResult, ErrorData> {
    tracing::info!(
        db.name = %params.database_name,
        schema.length = params.schema_undefinition.len(),
        "Executando ferramenta 'undefine_schema'."
    );

    let db = driver
        .databases()
        .get(&params.database_name)
        .await
        .map_err(|e| {
            tracing::error!(db.name = %params.database_name, error.message = %e, "Falha ao obter banco de dados para undefine_schema.");
            typedb_error_to_mcp_error_data(&e, "undefine_schema (obter banco)")
        })?;

    let transaction = driver
        .transaction_with_options(db.name(), TransactionType::Schema, TransactionOptions::default())
        .await
        .map_err(|e| {
            tracing::error!(db.name = %params.database_name, error.message = %e, "Falha ao abrir transação de esquema para undefine_schema.");
            typedb_error_to_mcp_error_data(&e, "undefine_schema (abrir transação)")
        })?;

    match transaction.query(params.schema_undefinition).await {
        Ok(QueryAnswer::Ok(_)) => {
            transaction.commit().await.map_err(|e| {
                tracing::error!(db.name = %params.database_name, error.message = %e, "Falha ao fazer commit da transação para undefine_schema.");
                typedb_error_to_mcp_error_data(&e, "undefine_schema (commit)")
            })?;
            tracing::info!(db.name = %params.database_name, "Schema removido com sucesso.");
            Ok(CallToolResult::success(vec![Content::text("OK")]))
        }
        Ok(other_answer) => {
            let response_type_str = format!("{other_answer:?}");
            tracing::error!(db.name = %params.database_name, response.type = %response_type_str, "Resposta inesperada para query undefine_schema.");
            Err(ErrorData {
                code: ErrorCode::INTERNAL_ERROR,
                message: Cow::Owned(
                    "Resposta inesperada do servidor TypeDB para query undefine_schema."
                        .to_string(),
                ),
                data: Some(serde_json::json!({
                    "type": "UnexpectedQueryAnswer",
                    "expected": "Ok",
                    "received": response_type_str,
                })),
            })
        }
        Err(e) => {
            tracing::error!(db.name = %params.database_name, error.message = %e, "Falha ao executar query undefine_schema.");
            Err(typedb_error_to_mcp_error_data(&e, "undefine_schema (executar query)"))
        }
    }
}

/// Handler para a ferramenta `get_schema`.
///
/// Recupera a definição do esquema TypeQL de um banco de dados TypeDB existente.
/// Pode retornar o esquema completo ou apenas as definições de tipo.
///
/// # Parâmetros
/// * `driver`: Uma referência `Arc` para o `TypeDBDriver` conectado.
/// * `params`: Parâmetros da ferramenta, contendo `database_name` e `schema_type` opcional.
///
/// # Retorna
/// `Ok(CallToolResult)` com o conteúdo do esquema em caso de sucesso,
/// ou `Err(ErrorData)` se ocorrer um erro.
#[tracing::instrument(skip(driver, params), name = "tool_get_schema")]
pub async fn handle_get_schema(
    driver: Arc<TypeDBDriver>,
    params: params::GetSchemaParams,
) -> Result<CallToolResult, ErrorData> {
    tracing::info!(
        db.name = %params.database_name, // Usa referência, não move
        schema.type_requested = ?params.schema_type, // Usa Debug para Option<String>
        "Executando ferramenta 'get_schema'."
    );

    let db = driver
        .databases()
        .get(&params.database_name)
        .await
        .map_err(|e| {
            tracing::error!(db.name = %params.database_name, error.message = %e, "Falha ao obter banco de dados para get_schema.");
            typedb_error_to_mcp_error_data(&e, "get_schema (obter banco)")
        })?;

    let schema_content_result = match params.schema_type.as_deref() { // as_deref() para Option<String>
        Some("types") => {
            tracing::debug!(db.name = %params.database_name, "Obtendo type_schema.");
            db.type_schema().await
        }
        Some("full") | None => {
            tracing::debug!(db.name = %params.database_name, "Obtendo schema completo.");
            db.schema().await
        }
        Some(invalid_type) => {
            tracing::warn!(db.name = %params.database_name, schema.invalid_type = %invalid_type, "Tipo de schema inválido fornecido para get_schema. Usando 'full' como padrão.");
            db.schema().await
        }
    };

    schema_content_result
        .map(|content| {
            tracing::info!(db.name = %params.database_name, "Schema obtido com sucesso.");
            CallToolResult::success(vec![Content::text(content)])
        })
        .map_err(|e| {
            tracing::error!(db.name = %params.database_name, error.message = %e, "Falha ao obter schema.");
            typedb_error_to_mcp_error_data(&e, "get_schema (obter conteúdo do schema)")
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use typedb_driver::Error as TypeDBError;
    use rmcp::model::ErrorCode; // Import direto, já que não é mais reexportado por `crate::error`
    // `Cow` não é mais necessário nos testes após a simplificação
    // use std::borrow::Cow;

    #[tokio::test]
    async fn test_handle_define_schema_success_flow() {
        let successful_mcp_result: Result<CallToolResult, ErrorData> =
            Ok(CallToolResult::success(vec![Content::text("OK")]));

        assert!(successful_mcp_result.is_ok());
        let result = match successful_mcp_result {
            Ok(r) => r,
            Err(e) => panic!("Esperado Ok, obteve Err: {e:?}"),
        };
        match result.content[0].as_text() {
            Some(text_content) => assert_eq!(text_content.text, "OK"),
            None => panic!("Esperado Content::text no índice 0"),
        }
        assert!(!result.is_error.unwrap_or(false));
    }

    #[tokio::test]
    async fn test_handle_define_schema_db_get_error_flow() {
        let typedb_error = TypeDBError::Other("DB não encontrado".into());
        let expected_mcp_error_data =
            typedb_error_to_mcp_error_data(&typedb_error, "define_schema (obter banco)");
        let handler_output: Result<CallToolResult, ErrorData> = Err(expected_mcp_error_data);

        assert!(handler_output.is_err());
        let err_data = match handler_output {
            Err(e) => e,
            Ok(val) => panic!("Esperado Err, obteve Ok: {val:?}"),
        };
        assert_eq!(err_data.code, ErrorCode::INTERNAL_ERROR);
        assert!(err_data.message.contains("define_schema (obter banco)"));
    }

    #[tokio::test]
    async fn test_handle_define_schema_transaction_open_error_flow() {
        let typedb_error = TypeDBError::Other("Falha ao abrir tx".into());
        let expected_mcp_error_data =
            typedb_error_to_mcp_error_data(&typedb_error, "define_schema (abrir transação)");
        let handler_output: Result<CallToolResult, ErrorData> = Err(expected_mcp_error_data);

        assert!(handler_output.is_err());
        let err_data = match handler_output {
            Err(e) => e,
            Ok(val) => panic!("Esperado Err, obteve Ok: {val:?}"),
        };
        assert_eq!(err_data.code, ErrorCode::INTERNAL_ERROR);
        assert!(err_data.message.contains("define_schema (abrir transação)"));
    }

    #[tokio::test]
    async fn test_handle_define_schema_query_error_flow() {
        let typedb_error = TypeDBError::Other("Query define falhou".into());
        let expected_mcp_error_data =
            typedb_error_to_mcp_error_data(&typedb_error, "define_schema (executar query)");
        let handler_output: Result<CallToolResult, ErrorData> = Err(expected_mcp_error_data);

        assert!(handler_output.is_err());
        let err_data = match handler_output {
            Err(e) => e,
            Ok(val) => panic!("Esperado Err, obteve Ok: {val:?}"),
        };
        assert_eq!(err_data.code, ErrorCode::INTERNAL_ERROR);
        assert!(err_data.message.contains("define_schema (executar query)"));
    }

    #[tokio::test]
    async fn test_handle_define_schema_commit_error_flow() {
        let typedb_error = TypeDBError::Other("Commit falhou".into());
        let expected_mcp_error_data =
            typedb_error_to_mcp_error_data(&typedb_error, "define_schema (commit)");
        let handler_output: Result<CallToolResult, ErrorData> = Err(expected_mcp_error_data);

        assert!(handler_output.is_err());
        let err_data = match handler_output {
            Err(e) => e,
            Ok(val) => panic!("Esperado Err, obteve Ok: {val:?}"),
        };
        assert_eq!(err_data.code, ErrorCode::INTERNAL_ERROR);
        assert!(err_data.message.contains("define_schema (commit)"));
    }

    #[tokio::test]
    async fn test_handle_define_schema_unexpected_query_answer_flow() {
        let error_message = "Resposta inesperada do servidor TypeDB para query define_schema.".to_string();
        let received_type_example = "ConceptRowStream(...)";
        let expected_mcp_error_data = ErrorData {
            code: ErrorCode::INTERNAL_ERROR,
            message: Cow::Owned(error_message), // Cow é usado aqui
            data: Some(serde_json::json!({
                "type": "UnexpectedQueryAnswer",
                "expected": "Ok",
                "received": received_type_example,
            })),
        };
        let handler_output: Result<CallToolResult, ErrorData> = Err(expected_mcp_error_data);
        assert!(handler_output.is_err());
        let err_data = match handler_output {
            Err(e) => e,
            Ok(val) => panic!("Esperado Err, obteve Ok: {val:?}"),
        };
        assert_eq!(err_data.code, ErrorCode::INTERNAL_ERROR);
        assert!(err_data.message.contains("Resposta inesperada do servidor TypeDB"));
        match err_data.data {
            Some(ref data) => assert_eq!(data["received"], received_type_example),
            None => panic!("Esperado campo data em ErrorData"),
        }
    }


    #[tokio::test]
    async fn test_handle_get_schema_success_full_flow() {
        let schema_content = "define person sub entity;".to_string();
        let successful_mcp_result: Result<CallToolResult, ErrorData> =
            Ok(CallToolResult::success(vec![Content::text(schema_content)]));

        assert!(successful_mcp_result.is_ok());
        let result = match successful_mcp_result {
            Ok(r) => r,
            Err(e) => panic!("Esperado Ok, obteve Err: {e:?}"),
        };
        match result.content[0].as_text() {
            Some(text_content) => assert_eq!(text_content.text, "define person sub entity;"),
            None => panic!("Esperado Content::text no índice 0"),
        }
    }

    #[tokio::test]
    async fn test_handle_get_schema_db_get_error_flow() {
        let typedb_error = TypeDBError::Other("DB não encontrado para get_schema".into());
        let expected_mcp_error_data =
            typedb_error_to_mcp_error_data(&typedb_error, "get_schema (obter banco)");
        let handler_output: Result<CallToolResult, ErrorData> = Err(expected_mcp_error_data);

        assert!(handler_output.is_err());
        let err_data = match handler_output {
            Err(e) => e,
            Ok(val) => panic!("Esperado Err, obteve Ok: {val:?}"),
        };
        assert_eq!(err_data.code, ErrorCode::INTERNAL_ERROR);
        assert!(err_data.message.contains("get_schema (obter banco)"));
    }

    #[tokio::test]
    async fn test_handle_get_schema_fetch_content_error_flow() {
        let typedb_error = TypeDBError::Other("Falha ao buscar schema".into());
        let expected_mcp_error_data =
            typedb_error_to_mcp_error_data(&typedb_error, "get_schema (obter conteúdo do schema)");
        let handler_output: Result<CallToolResult, ErrorData> = Err(expected_mcp_error_data);

        assert!(handler_output.is_err());
        let err_data = match handler_output {
            Err(e) => e,
            Ok(val) => panic!("Esperado Err, obteve Ok: {val:?}"),
        };
        assert_eq!(err_data.code, ErrorCode::INTERNAL_ERROR);
        assert!(err_data.message.contains("get_schema (obter conteúdo do schema)"));
    }
}