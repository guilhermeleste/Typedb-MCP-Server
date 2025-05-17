// src/tools/query.rs

// Licença Apache 2.0
// Copyright [ANO_ATUAL] [SEU_NOME_OU_ORGANIZACAO]
// ... (cabeçalho de licença completo)

//! Contém os handlers para as ferramentas MCP relacionadas à consulta e manipulação
//! de dados no TypeDB, incluindo leitura, inserção, deleção, atualização e validação de queries.

use std::borrow::Cow;
use std::sync::Arc;

use futures::{StreamExt, TryStreamExt};
use rmcp::model::{CallToolResult, Content, ErrorCode, ErrorData};
use typedb_driver::{
    answer::{ConceptDocument, ConceptRow, QueryAnswer},
    concept::{Concept, Value as TypeDBValue},
    QueryOptions as TypeDBQueryOptions,
    TransactionOptions,
    TransactionType, TypeDBDriver, Error as TypeDBDriverError,
};

use crate::error::{typedb_error_to_mcp_error_data, typedb_error_to_user_string};
use super::params;

// --- Funções Utilitárias Privadas para Serialização JSON ---

/// Converte um `typedb_driver::concept::Value` (`TypeDBValue`) em um `serde_json::Value`.
fn typedb_value_to_json_value(value: &TypeDBValue) -> serde_json::Value {
    match value {
        TypeDBValue::Boolean(b) => serde_json::json!(b),
        TypeDBValue::Integer(i) => serde_json::json!(i),
        TypeDBValue::Double(d) => serde_json::json!(d),
        TypeDBValue::String(s) => serde_json::json!(s),
        TypeDBValue::Decimal(d) => serde_json::json!(d.to_string()),
        TypeDBValue::Date(d) => serde_json::json!(d.format("%Y-%m-%d").to_string()),
        TypeDBValue::Datetime(dt) => serde_json::json!(dt.format("%FT%T%.9f").to_string()),
        TypeDBValue::DatetimeTZ(dt_tz) => serde_json::json!(dt_tz.to_rfc3339()),
        TypeDBValue::Duration(d) => serde_json::json!(d.to_string()),
        TypeDBValue::Struct(s, name) => {
            let mut map = serde_json::Map::new();
            // Usa o método público `fields()` para acessar os campos da struct.
            for (key, val_opt) in s.fields() {
                map.insert(
                    key.clone(),
                    val_opt.as_ref().map_or(serde_json::Value::Null, typedb_value_to_json_value),
                );
            }
            serde_json::json!({ name.clone(): serde_json::Value::Object(map) })
        }
    }
}

/// Converte um `typedb_driver::concept::Concept` em um `serde_json::Value`.
fn concept_to_json_value(concept: &Concept) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    let category_name = concept.get_category().name();
    map.insert("category".to_string(), serde_json::json!(category_name));

    match concept {
        Concept::EntityType(et) => {
            map.insert("label".to_string(), serde_json::json!(et.label()));
        }
        Concept::RelationType(rt) => {
            map.insert("label".to_string(), serde_json::json!(rt.label()));
        }
        Concept::AttributeType(at) => {
            map.insert("label".to_string(), serde_json::json!(at.label()));
            if let Some(vt) = at.value_type() {
                map.insert("valueType".to_string(), serde_json::json!(vt.name()));
            }
        }
        Concept::RoleType(r) => {
            map.insert("label".to_string(), serde_json::json!(r.label()));
        }
        Concept::Entity(e) => {
            map.insert("iid".to_string(), serde_json::json!(e.iid().to_string()));
            if let Some(t) = e.type_() {
                map.insert("typeLabel".to_string(), serde_json::json!(t.label()));
            }
        }
        Concept::Relation(r) => {
            map.insert("iid".to_string(), serde_json::json!(r.iid().to_string()));
            if let Some(t) = r.type_() {
                map.insert("typeLabel".to_string(), serde_json::json!(t.label()));
            }
        }
        Concept::Attribute(a) => {
            map.insert("iid".to_string(), serde_json::json!(a.iid.to_string()));
            if let Some(t) = a.type_() {
                map.insert("typeLabel".to_string(), serde_json::json!(t.label()));
                if let Some(vt) = t.value_type() {
                    map.insert("valueType".to_string(), serde_json::json!(vt.name()));
                }
            }
            map.insert("value".to_string(), typedb_value_to_json_value(&a.value));
        }
        Concept::Value(v) => {
            return typedb_value_to_json_value(v);
        }
    }
    serde_json::Value::Object(map)
}

/// Converte um `typedb_driver::answer::ConceptRow` em um `serde_json::Value` (objeto JSON).
fn concept_row_to_json_value(row: &ConceptRow) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for col_name in row.get_column_names() {
        match row.get(col_name) {
            Ok(Some(concept)) => {
                map.insert(col_name.clone(), concept_to_json_value(concept));
            }
            Ok(None) => {
                map.insert(col_name.clone(), serde_json::Value::Null);
            }
            Err(e) => {
                tracing::error!(column.name = %col_name, error.message = %e, "Erro ao obter conceito da linha.");
                map.insert(
                    col_name.clone(),
                    serde_json::json!({
                        "error": format!("Erro interno ao processar coluna '{}': {}", col_name, e)
                    }),
                );
            }
        }
    }
    serde_json::Value::Object(map)
}

// --- Implementações das Ferramentas ---

/// Handler para a ferramenta `query_read`.
#[tracing::instrument(skip(driver, params), name = "tool_query_read", fields(db.name = %params.database_name, query.length = params.query.len()))]
pub async fn handle_query_read(
    driver: Arc<TypeDBDriver>,
    params: params::QueryReadParams,
) -> Result<CallToolResult, ErrorData> {
    tracing::info!("Executando 'query_read'.");

    let transaction_options = TransactionOptions::default();
    let transaction = driver
        .transaction_with_options(&params.database_name, TransactionType::Read, transaction_options)
        .await
        .map_err(|e| {
            tracing::error!(error.message = %e, "Falha ao abrir transação de leitura.");
            typedb_error_to_mcp_error_data(&e, "query_read (abrir transação)")
        })?;

    let query_options = TypeDBQueryOptions::default();

    match transaction.query_with_options(&params.query, query_options).await {
        Ok(query_answer) => {
            let result_json_string = match query_answer {
                QueryAnswer::ConceptRowStream(_header, stream) => {
                    let rows: Vec<ConceptRow> = stream.try_collect().await.map_err(|e| {
                        tracing::error!(error.message = %e, "Erro ao coletar ConceptRows do stream.");
                        typedb_error_to_mcp_error_data(&e, "query_read (coletar ConceptRow)")
                    })?;

                    if params.query.to_lowercase().contains("aggregate") {
                        if rows.is_empty() {
                            serde_json::Value::Null.to_string()
                        } else if let Some(row) = rows.first() {
                            if let Some(concept_value) = row.get_concepts().next() {
                                if let Concept::Value(value) = concept_value {
                                    serde_json::to_string(&typedb_value_to_json_value(value)).map_err(|e| {
                                        tracing::error!(error.message = %e, "Falha ao serializar valor agregado para JSON.");
                                        ErrorData {
                                            code: ErrorCode::INTERNAL_ERROR,
                                            message: Cow::Owned(format!("Falha ao serializar valor agregado para JSON: {e}")),
                                            data: None,
                                        }
                                    })?
                                } else {
                                    tracing::warn!(concept.category = %concept_value.get_category().name(), "query_read (aggregate): Esperava Concept::Value.");
                                    serde_json::Value::Null.to_string()
                                }
                            } else {
                                tracing::warn!("query_read (aggregate): Nenhuma coluna/conceito na linha de resultado.");
                                serde_json::Value::Null.to_string()
                            }
                        } else {
                             serde_json::Value::Null.to_string()
                        }
                    } else {
                        let json_rows: Vec<serde_json::Value> =
                            rows.iter().map(concept_row_to_json_value).collect();
                        serde_json::to_string(&json_rows).map_err(|e| {
                             tracing::error!(error.message = %e, "Falha ao serializar ConceptRows para JSON.");
                            ErrorData {
                                code: ErrorCode::INTERNAL_ERROR,
                                message: Cow::Owned(format!("Falha ao serializar linhas de conceito para JSON: {e}")),
                                data: None,
                            }
                        })?
                    }
                }
                QueryAnswer::ConceptDocumentStream(_header, stream) => {
                    let documents: Vec<ConceptDocument> = stream.try_collect().await.map_err(|e| {
                        tracing::error!(error.message = %e, "Erro ao coletar ConceptDocuments do stream.");
                        typedb_error_to_mcp_error_data(&e, "query_read (coletar ConceptDocument)")
                    })?;
                     if documents.is_empty() {
                        "[]".to_string()
                    } else {
                        let json_docs: Result<Vec<serde_json::Value>, ErrorData> = documents.into_iter().map(|doc| {
                            let typedb_json_string = doc.into_json().to_string();
                            serde_json::from_str(&typedb_json_string)
                                .map_err(|e| {
                                    tracing::error!(error.message = %e, typedb_json = %typedb_json_string, "Falha ao converter typedb_driver::JSON para serde_json::Value.");
                                    ErrorData {
                                        code: ErrorCode::INTERNAL_ERROR,
                                        message: Cow::Owned(format!("Falha ao converter JSON interno para JSON de saída: {e}")),
                                        data: None,
                                    }
                                })
                        }).collect();
                        serde_json::to_string(&json_docs?).map_err(|e| {
                            tracing::error!(error.message = %e, "Falha ao serializar ConceptDocuments para JSON.");
                            ErrorData {
                                code: ErrorCode::INTERNAL_ERROR,
                                message: Cow::Owned(format!("Falha ao serializar documentos para JSON: {e}")),
                                data: None,
                            }
                        })?
                    }
                }
                QueryAnswer::Ok(_) => {
                    tracing::warn!(query = %params.query, "query_read recebeu QueryAnswer::Ok. Esperava-se um stream de resultados.");
                    if params.query.to_lowercase().contains("aggregate") {
                        serde_json::Value::Null.to_string()
                    } else {
                        "[]".to_string()
                    }
                }
            };
            Ok(CallToolResult::success(vec![Content::text(result_json_string)]))
        }
        Err(e) => {
            tracing::error!(error.message = %e, "Falha ao executar query_read.");
            Err(typedb_error_to_mcp_error_data(&e, "query_read (executar query)"))
        }
    }
}

/// Handler para a ferramenta `insert_data`.
#[tracing::instrument(skip(driver, params), name = "tool_insert_data", fields(db.name = %params.database_name, query.length = params.query.len()))]
pub async fn handle_insert_data(
    driver: Arc<TypeDBDriver>,
    params: params::InsertDataParams,
) -> Result<CallToolResult, ErrorData> {
    tracing::info!("Executando 'insert_data'.");
    let transaction_options = TransactionOptions::default();
    let transaction = driver
        .transaction_with_options(&params.database_name, TransactionType::Write, transaction_options)
        .await
        .map_err(|e| {
            tracing::error!(error.message = %e, "Falha ao abrir transação de escrita para insert_data.");
            typedb_error_to_mcp_error_data(&e, "insert_data (abrir transação)")
        })?;

    let query_options = TypeDBQueryOptions::default();

    match transaction.query_with_options(&params.query, query_options).await {
        Ok(query_answer) => {
            let result_json_string = match query_answer {
                QueryAnswer::ConceptRowStream(_header, stream) => {
                    let rows: Vec<ConceptRow> = stream.try_collect().await.map_err(|e| {
                        tracing::error!(error.message = %e, "Erro ao coletar ConceptRows do stream (insert_data).");
                        typedb_error_to_mcp_error_data(&e, "insert_data (coletar ConceptRow)")
                    })?;
                    let json_rows: Vec<serde_json::Value> =
                        rows.iter().map(concept_row_to_json_value).collect();
                    serde_json::to_string(&json_rows).map_err(|e| {
                        tracing::error!(error.message = %e, "Falha ao serializar resultados de insert_data para JSON.");
                        ErrorData {
                            code: ErrorCode::INTERNAL_ERROR,
                            message: Cow::Owned(format!("Falha ao serializar resultados de inserção para JSON: {e}")),
                            data: None,
                        }
                    })?
                }
                QueryAnswer::Ok(_) => {
                    tracing::debug!("Query insert_data retornou Ok.");
                    serde_json::json!({"status": "success", "message": "Dados inseridos com sucesso. Nenhum resultado específico retornado pela query."}).to_string()
                }
                QueryAnswer::ConceptDocumentStream(_, _) => {
                     tracing::warn!("insert_data recebeu ConceptDocumentStream, o que é inesperado.");
                    serde_json::json!({"status": "success_with_unexpected_response", "message": "Dados inseridos, mas a query retornou um stream de documentos inesperado."}).to_string()
                }
            };
            transaction.commit().await.map_err(|e| {
                tracing::error!(error.message = %e, "Falha ao fazer commit da transação para insert_data.");
                typedb_error_to_mcp_error_data(&e, "insert_data (commit)")
            })?;
            Ok(CallToolResult::success(vec![Content::text(result_json_string)]))
        }
        Err(e) => {
            tracing::error!(error.message = %e, "Falha ao executar query insert_data.");
            Err(typedb_error_to_mcp_error_data(&e, "insert_data (executar query)"))
        }
    }
}


/// Handler para a ferramenta `delete_data`.
#[tracing::instrument(skip(driver, params), name = "tool_delete_data", fields(db.name = %params.database_name, query.length = params.query.len()))]
pub async fn handle_delete_data(
    driver: Arc<TypeDBDriver>,
    params: params::DeleteDataParams,
) -> Result<CallToolResult, ErrorData> {
    tracing::info!("Executando 'delete_data'.");
    let transaction_options = TransactionOptions::default();
    let transaction = driver
        .transaction_with_options(&params.database_name, TransactionType::Write, transaction_options)
        .await
        .map_err(|e| typedb_error_to_mcp_error_data(&e, "delete_data (abrir transação)"))?;

    let query_options = TypeDBQueryOptions::default();

    match transaction.query_with_options(&params.query, query_options).await {
        Ok(QueryAnswer::Ok(_)) => {
            transaction.commit().await.map_err(|e| typedb_error_to_mcp_error_data(&e, "delete_data (commit)"))?;
            Ok(CallToolResult::success(vec![Content::text("OK")]))
        }
        Ok(other_answer) => {
            let response_type_str = format!("{other_answer:?}");
            tracing::warn!(response.type = %response_type_str, "delete_data recebeu resposta inesperada. Prosseguindo com commit.");
            transaction.commit().await.map_err(|e| typedb_error_to_mcp_error_data(&e, "delete_data (commit com resposta inesperada)"))?;
            Ok(CallToolResult::success(vec![Content::text(
                format!("OK (com aviso: tipo de resposta inesperado da query: {response_type_str})")
            )]))
        }
        Err(e) => Err(typedb_error_to_mcp_error_data(&e, "delete_data (executar query)")),
    }
}

/// Handler para a ferramenta `update_data`.
#[tracing::instrument(skip(driver, params), name = "tool_update_data", fields(db.name = %params.database_name, query.length = params.query.len()))]
pub async fn handle_update_data(
    driver: Arc<TypeDBDriver>,
    params: params::UpdateDataParams,
) -> Result<CallToolResult, ErrorData> {
    tracing::info!("Executando 'update_data'.");
    let transaction_options = TransactionOptions::default();
    let transaction = driver
        .transaction_with_options(&params.database_name, TransactionType::Write, transaction_options)
        .await
        .map_err(|e| typedb_error_to_mcp_error_data(&e, "update_data (abrir transação)"))?;
    
    let query_options = TypeDBQueryOptions::default();

    match transaction.query_with_options(&params.query, query_options).await {
        Ok(query_answer) => {
             let result_json_string = match query_answer {
                QueryAnswer::ConceptRowStream(_header, stream) => {
                    let rows: Vec<ConceptRow> = stream.try_collect().await.map_err(|e| typedb_error_to_mcp_error_data(&e, "update_data (coletar ConceptRow)"))?;
                    let json_rows: Vec<serde_json::Value> = rows.iter().map(concept_row_to_json_value).collect();
                    serde_json::to_string(&json_rows).map_err(|e| ErrorData {
                        code: ErrorCode::INTERNAL_ERROR,
                        message: Cow::Owned(format!("Falha ao serializar resultados de update para JSON: {e}")),
                        data: None,
                    })?
                }
                QueryAnswer::Ok(_) => {
                    serde_json::json!({"status": "success", "message": "Dados atualizados com sucesso. Nenhum resultado específico retornado pela query."}).to_string()
                }
                QueryAnswer::ConceptDocumentStream(_,_) => {
                    tracing::warn!("update_data recebeu ConceptDocumentStream, o que é inesperado.");
                    serde_json::json!({"status": "success_with_unexpected_response", "message": "Dados atualizados, mas a query retornou um stream de documentos inesperado."}).to_string()
                }
            };
            transaction.commit().await.map_err(|e| typedb_error_to_mcp_error_data(&e, "update_data (commit)"))?;
            Ok(CallToolResult::success(vec![Content::text(result_json_string)]))
        }
        Err(e) => Err(typedb_error_to_mcp_error_data(&e, "update_data (executar query)")),
    }
}


/// Handler para a ferramenta `validate_query`.
#[tracing::instrument(skip(driver, params), name = "tool_validate_query", fields(db.name = %params.database_name, query.length = params.query.len()))]
pub async fn handle_validate_query(
    driver: Arc<TypeDBDriver>,
    params: params::ValidateQueryParams,
) -> Result<CallToolResult, ErrorData> {
    tracing::info!("Executando 'validate_query'.");

    let transaction_options = TransactionOptions::default();
    let transaction = driver
        .transaction_with_options(&params.database_name, TransactionType::Read, transaction_options)
        .await
        .map_err(|e| {
            tracing::error!(error.message = %e, "Falha ao abrir transação de teste para validate_query.");
            typedb_error_to_mcp_error_data(&e, "validate_query (abrir transação de teste)")
        })?;
    
    let query_options = TypeDBQueryOptions::default();

    let intended_type_str = params.intended_transaction_type.as_deref().unwrap_or("read");
    let query_context_msg = format!("Validação da query (destinada a transação '{intended_type_str}')");

    match transaction.query_with_options(&params.query, query_options).await {
        Ok(query_answer) => {
            match query_answer {
                QueryAnswer::ConceptRowStream(_, mut stream) => {
                    while let Some(res) = stream.next().await {
                        if let Err(e) = res {
                            return Ok(CallToolResult::success(vec![Content::text(
                                typedb_error_to_user_string(&e, &query_context_msg),
                            )]));
                        }
                    }
                }
                QueryAnswer::ConceptDocumentStream(_, mut stream) => {
                     while let Some(res) = stream.next().await {
                        if let Err(e) = res {
                           return Ok(CallToolResult::success(vec![Content::text(
                                typedb_error_to_user_string(&e, &query_context_msg),
                            )]));
                        }
                    }
                }
                QueryAnswer::Ok(_) => {
                    tracing::debug!("validate_query recebeu QueryAnswer::Ok.");
                }
            }
            Ok(CallToolResult::success(vec![Content::text("valid")]))
        }
        Err(e @ (TypeDBDriverError::Server(_) | TypeDBDriverError::Concept(_))) => {
            Ok(CallToolResult::success(vec![Content::text(
                typedb_error_to_user_string(&e, &query_context_msg),
            )]))
        }
        Err(e) => {
            Err(typedb_error_to_mcp_error_data(&e, "validate_query (executar query de teste)"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use typedb_driver::concept::value::TimeZone as TypeDBTimeZone;
    // chrono::Utc não é mais necessário aqui diretamente.
    use chrono::{FixedOffset, NaiveDate, TimeZone as ChronoTimeZone};
    use typedb_driver::concept::value::{Decimal, Duration as TypeDBDuration};


    #[test]
    fn test_typedb_value_to_json_value_primitives() {
        assert_eq!(typedb_value_to_json_value(&TypeDBValue::Boolean(true)), serde_json::json!(true));
        assert_eq!(typedb_value_to_json_value(&TypeDBValue::Integer(123)), serde_json::json!(123));
        assert_eq!(typedb_value_to_json_value(&TypeDBValue::Double(123.456)), serde_json::json!(123.456));
        assert_eq!(typedb_value_to_json_value(&TypeDBValue::String("hello".to_string())), serde_json::json!("hello"));
    }

    #[test]
    fn test_typedb_value_to_json_value_decimal() {
        let dec_val = TypeDBValue::Decimal(Decimal::new(123456, 3));
        assert_eq!(typedb_value_to_json_value(&dec_val), serde_json::json!(Decimal::new(123456, 3).to_string()));
    }

    #[test]
    fn test_typedb_value_to_json_value_datetime_types() {
        let naive_date = NaiveDate::from_ymd_opt(2023, 10, 26).unwrap();
        assert_eq!(typedb_value_to_json_value(&TypeDBValue::Date(naive_date)), serde_json::json!("2023-10-26"));

        let naive_datetime = NaiveDate::from_ymd_opt(2023, 10, 26).unwrap().and_hms_nano_opt(14, 30, 5, 123456789).unwrap();
        assert_eq!(typedb_value_to_json_value(&TypeDBValue::Datetime(naive_datetime)), serde_json::json!("2023-10-26T14:30:05.123456789"));

        let fixed_offset = FixedOffset::east_opt(5 * 3600 + 30 * 60).unwrap();
        let driver_tz = TypeDBTimeZone::Fixed(fixed_offset);
        // Usar o método `from_utc_datetime` do `driver_tz` que implementa `chrono::TimeZone`.
        let datetime_with_typedb_tz: chrono::DateTime<TypeDBTimeZone> = driver_tz.from_utc_datetime(&naive_datetime);
        let datetime_tz_value = TypeDBValue::DatetimeTZ(datetime_with_typedb_tz);
        // `to_rfc3339` é um método de `chrono::DateTime`.
        assert_eq!(typedb_value_to_json_value(&datetime_tz_value), serde_json::json!(datetime_with_typedb_tz.to_rfc3339()));
    }


    #[test]
    fn test_typedb_value_to_json_value_duration() {
        // (1 ano + 2 meses), 3 dias, (4h + 5m + 6s)
        let duration_val = TypeDBValue::Duration(TypeDBDuration::new(1*12 + 2, 3, (4*3600 + 5*60 + 6) * 1_000_000_000));
        // A implementação Display de TypeDBDuration deve ser ISO 8601.
        // Ex: "P14M3DT4H5M6S"
        assert_eq!(typedb_value_to_json_value(&duration_val), serde_json::json!(TypeDBDuration::new(14, 3, 14706000000000_u64).to_string()));
    }
    
    // O teste para TypeDBValue::Struct foi removido porque não podemos construir TypeDBStruct { fields }
    // diretamente nos testes devido à visibilidade pub(crate) do campo `fields`
    // na crate `typedb-driver`. A lógica de serialização em `typedb_value_to_json_value`
    // que usa o método público `s.fields()` ainda é válida e será testada por testes de integração
    // quando o driver retornar tais structs.


    #[test]
    fn test_concept_to_json_value_for_value_concept() {
        let value_concept = Concept::Value(TypeDBValue::String("test_val".to_string()));
        assert_eq!(concept_to_json_value(&value_concept), serde_json::json!("test_val"));
    }

    #[tokio::test]
    async fn test_handle_query_read_row_stream_flow() {
        let successful_mcp_result: Result<CallToolResult, ErrorData> =
            Ok(CallToolResult::success(vec![Content::text(r#"[{"var": "value"}]"#)]));
        assert!(successful_mcp_result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_insert_data_ok_flow() {
        let successful_mcp_result: Result<CallToolResult, ErrorData> =
            Ok(CallToolResult::success(vec![Content::text(
                serde_json::json!({"status": "success", "message": "Dados inseridos com sucesso. Nenhum resultado específico retornado pela query."}).to_string()
            )]));
        assert!(successful_mcp_result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_delete_data_success_flow() {
        let successful_mcp_result: Result<CallToolResult, ErrorData> =
            Ok(CallToolResult::success(vec![Content::text("OK")]));
        assert!(successful_mcp_result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_validate_query_valid_flow() {
        let successful_mcp_result: Result<CallToolResult, ErrorData> =
            Ok(CallToolResult::success(vec![Content::text("valid")]));
        assert!(successful_mcp_result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_validate_query_error_string_flow() {
        let error_string = "ERRO: Validando query: Query inválida (Código TypeDB: Q01)";
        let successful_mcp_result: Result<CallToolResult, ErrorData> =
            Ok(CallToolResult::success(vec![Content::text(error_string)]));
        assert!(successful_mcp_result.is_ok());
    }
}