// src/resources.rs

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

//! Define e fornece acesso aos recursos (estáticos e dinâmicos)
//! expostos pelo `Typedb-MCP-Server` através do protocolo MCP.

use std::borrow::Cow;
use std::sync::Arc;

use percent_encoding::percent_decode_str;
use rmcp::model::{
    AnnotateAble, ErrorCode, ErrorData, RawResource, RawResourceTemplate, Resource,
    ResourceTemplate,
};
use typedb_driver::TypeDBDriver;

use crate::error::typedb_error_to_mcp_error_data;

// --- Constantes para Recursos Estáticos ---

const QUERY_TYPES_URI: &str = "info://typeql/query_types";
const QUERY_TYPES_NAME: &str = "Guia Rápido: Tipos de Consulta TypeQL";
const QUERY_TYPES_DESCRIPTION: &str = "Um resumo conciso dos principais Tipos de Consulta TypeQL disponíveis no TypeDB (Define, Undefine, Insert, Delete, Update, Match-Get, Match-Fetch, Match-Aggregate) e suas finalidades básicas.";
const QUERY_TYPES_CONTENT: &str = r#"Guia Rápido dos Tipos de Consulta TypeQL:

1.  CONSULTAS DE ESQUEMA (modificam a estrutura do banco de dados):
    *   DEFINE: Adiciona novos tipos (entidade, relação, atributo), regras, ou estende tipos existentes (ex: 'person sub entity, owns name;'). Requer transação de ESQUEMA.
    *   UNDEFINE: Remove tipos, regras ou outras definições do esquema (ex: 'undefine person;'). Requer transação de ESQUEMA. Cuidado: pode falhar se o tipo tiver instâncias ou subtipos.

2.  CONSULTAS DE DADOS (modificam ou leem instâncias):
    *   INSERT: Adiciona novas instâncias de dados (entidades, relações, atributos) ao banco (ex: 'insert $p isa person, has name "Alice";'). Requer transação de ESCRITA.
    *   DELETE: Remove instâncias de dados existentes que correspondem a um padrão (ex: 'match $p isa person, has name "Alice"; delete $p;'). Requer transação de ESCRITA.
    *   UPDATE: Atomicamente remove dados antigos e insere novos dados baseados em um padrão (ex: 'match $p isa person, has name "Bob", has age $a; delete $p has age $a; insert $p has age 30;'). Requer transação de ESCRITA.
    *   MATCH ... GET;: Consulta dados existentes. Retorna um conjunto de 'Concept Maps'. Ideal para extrair valores e estruturas tabulares. Requer transação de LEITURA (ou Escrita).
    *   MATCH ... FETCH;: Consulta e recupera dados em uma estrutura JSON aninhada. Requer transação de LEITURA (ou Escrita).
    *   MATCH ... AGGREGATE;: Realiza agregações sobre os dados correspondentes (count, sum, etc.). Retorna um único valor. Requer transação de LEITURA (ou Escrita).

Use a ferramenta MCP apropriada para cada tipo de query.
"#;

const TRANSACTIONS_GUIDE_URI: &str = "info://typedb/transactions_and_tools";
const TRANSACTIONS_GUIDE_NAME: &str = "Guia: Transações TypeDB e Ferramentas MCP";
const TRANSACTIONS_GUIDE_DESCRIPTION: &str = "Explica os tipos de transação no TypeDB (Read, Write, Schema), quais operações TypeQL são permitidas em cada uma, e qual ferramenta MCP deve ser usada.";
const TRANSACTIONS_GUIDE_CONTENT: &str = r"Guia de Transações TypeDB e Ferramentas MCP:

O TypeDB utiliza diferentes tipos de transações para diferentes operações:

1.  TRANSAÇÃO DE LEITURA (TransactionType::Read):
    *   Operações TypeQL: `match...get;`, `match...fetch;`, `match...aggregate;`.
    *   Ferramenta MCP: `query_read`.

2.  TRANSAÇÃO DE ESCRITA (TransactionType::Write):
    *   Operações TypeQL: `insert`, `delete`, `update`. Permite também consultas de leitura.
    *   Ferramentas MCP: `insert_data`, `delete_data`, `update_data`.

3.  TRANSAÇÃO DE ESQUEMA (TransactionType::Schema):
    *   Operações TypeQL: `define`, `undefine`.
    *   Ferramentas MCP: `define_schema`, `undefine_schema`.

OPERAÇÕES ADMINISTRATIVAS (nível de banco de dados):
*   Criar/deletar/listar bancos: Ferramentas `create_database`, `delete_database`, etc.
*   Obter esquema: Ferramenta `get_schema`.

Escolha a ferramenta MCP correta para a tarefa, pois ela gerenciará o tipo de transação apropriado.
";

// --- Constantes para Templates de Recursos Dinâmicos ---

const SCHEMA_TEMPLATE_URI_TEMPLATE: &str = "schema://current/{database_name}?type={schema_type}";
const SCHEMA_TEMPLATE_NAME: &str = "Esquema Atual do Banco de Dados";
const SCHEMA_TEMPLATE_DESCRIPTION: &str = "Retorna o esquema TypeQL para o banco de dados '{database_name}'. Use o parâmetro 'type' ('full' ou 'types') para especificar o detalhe. O padrão é 'full'.";

/// Retorna uma lista de `Resource` para os recursos estáticos definidos.
///
/// Estes recursos fornecem informações gerais sobre `TypeQL` e o uso do servidor.
#[must_use]
pub fn list_static_resources() -> Vec<Resource> {
    // Campos de RawResource (uri, name, description, mime_type) são String em rmcp 0.1.5
    // Conversão explícita de usize para u32 para o campo size.
    // Se o conteúdo exceder u32::MAX, loga warning e omite o campo size (None).
    let query_types_size = u32::try_from(QUERY_TYPES_CONTENT.len()).map_or_else(
        |_| {
            tracing::warn!("Conteúdo QUERY_TYPES_CONTENT excede u32::MAX, omitindo campo size.");
            None
        },
        Some,
    );
    let tx_guide_size = u32::try_from(TRANSACTIONS_GUIDE_CONTENT.len()).map_or_else(
        |_| {
            tracing::warn!(
                "Conteúdo TRANSACTIONS_GUIDE_CONTENT excede u32::MAX, omitindo campo size."
            );
            None
        },
        Some,
    );
    vec![
        RawResource {
            uri: QUERY_TYPES_URI.to_string(),
            name: QUERY_TYPES_NAME.to_string(),
            description: Some(QUERY_TYPES_DESCRIPTION.to_string()),
            mime_type: Some("text/plain".to_string()),
            size: query_types_size,
        }
        .no_annotation(),
        RawResource {
            uri: TRANSACTIONS_GUIDE_URI.to_string(),
            name: TRANSACTIONS_GUIDE_NAME.to_string(),
            description: Some(TRANSACTIONS_GUIDE_DESCRIPTION.to_string()),
            mime_type: Some("text/plain".to_string()),
            size: tx_guide_size,
        }
        .no_annotation(),
    ]
}

/// Retorna uma lista de `ResourceTemplate` para os recursos dinâmicos.
///
/// Atualmente, inclui um template para obter o esquema de um banco de dados.
#[must_use]
pub fn list_resource_templates() -> Vec<ResourceTemplate> {
    // Campos de RawResourceTemplate são String em rmcp 0.1.5
    vec![RawResourceTemplate {
        uri_template: SCHEMA_TEMPLATE_URI_TEMPLATE.to_string(),
        name: SCHEMA_TEMPLATE_NAME.to_string(),
        description: Some(SCHEMA_TEMPLATE_DESCRIPTION.to_string()),
        mime_type: Some("text/plain".to_string()),
    }
    .no_annotation()]
}

/// Lê o conteúdo de um recurso estático com base na URI fornecida.
///
/// # Parâmetros
/// * `uri_str`: A URI do recurso estático a ser lido.
///
/// # Retorna
/// `Some(String)` com o conteúdo se a URI corresponder a um recurso estático conhecido,
/// ou `None` caso contrário.
#[must_use]
pub fn read_static_resource(uri_str: &str) -> Option<String> {
    if uri_str == QUERY_TYPES_URI {
        Some(QUERY_TYPES_CONTENT.to_string())
    } else if uri_str == TRANSACTIONS_GUIDE_URI {
        Some(TRANSACTIONS_GUIDE_CONTENT.to_string())
    } else {
        None
    }
}

/// Parseia a URI de um recurso de esquema dinâmico.
///
/// Extrai o nome do banco de dados e o tipo de esquema solicitado (full/types).
///
/// # Parâmetros
/// * `uri_str`: A URI do recurso de esquema (ex: "<schema://current/my_db?type=types>").
///
/// # Retorna
/// `Ok((database_name, schema_type_param))` ou `Err(ErrorData)` se a URI for malformada.
fn parse_schema_uri(uri_str: &str) -> Result<(String, String), ErrorData> {
    if !uri_str.starts_with("schema://current/") {
        return Err(ErrorData {
            code: ErrorCode::RESOURCE_NOT_FOUND,
            message: Cow::Owned(format!(
                // Cow::Owned para String dinâmica
                "URI de esquema inválida: '{uri_str}'. Deve começar com 'schema://current/'."
            )),
            data: None,
        });
    }

    let remainder = uri_str.trim_start_matches("schema://current/");
    let parts: Vec<&str> = remainder.splitn(2, '?').collect();
    let db_name_encoded = parts[0];

    if db_name_encoded.is_empty() {
        return Err(ErrorData {
            code: ErrorCode::RESOURCE_NOT_FOUND,
            message: Cow::Owned("Nome do banco de dados ausente na URI do esquema.".to_string()),
            data: None,
        });
    }

    // Verificação extra: rejeita '%' não seguido de dois dígitos hexadecimais
    let mut chars = db_name_encoded.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            let h1 = chars.peek().copied();
            let h2 = {
                if h1.is_some() {
                    chars.nth(0)
                } else {
                    None
                }
            };
            if !(h1.map(|x| x.is_ascii_hexdigit()).unwrap_or(false)
                && h2.map(|x| x.is_ascii_hexdigit()).unwrap_or(false))
            {
                return Err(ErrorData {
                    code: ErrorCode::INVALID_PARAMS,
                    message: Cow::Owned(format!(
                        "Nome do banco de dados malformado na URI do esquema: '%' não seguido de dois dígitos hexadecimais em '{db_name_encoded}'"
                    )),
                    data: None,
                });
            }
        }
    }

    let db_name = percent_decode_str(db_name_encoded)
        .decode_utf8()
        .map_err(|e| ErrorData {
            code: ErrorCode::INVALID_PARAMS,
            message: Cow::Owned(format!(
                "Nome do banco de dados malformado na URI do esquema (erro de decodificação UTF-8 '{db_name_encoded}'): {e}"
            )),
            data: None,
        })?
        .into_owned();

    let mut schema_type = "full".to_string();
    if parts.len() > 1 {
        let query_part = parts[1];
        for pair in query_part.split('&') {
            let mut kv = pair.splitn(2, '=');
            if let (Some(key), Some(value)) = (kv.next(), kv.next()) {
                if key == "type" {
                    if value == "full" || value == "types" {
                        schema_type = value.to_string();
                    } else {
                        tracing::warn!(
                            schema.uri_type_param.invalid_value = %value,
                            schema.uri_full = %uri_str,
                            schema.type_default_used = %schema_type,
                            "Valor inválido para o parâmetro 'type' na URI do esquema. Usando default."
                        );
                    }
                    break;
                }
            }
        }
    }
    Ok((db_name, schema_type))
}

/// Lê o conteúdo de um recurso de esquema dinâmico (o esquema de um banco de dados).
///
/// # Parâmetros
/// * `driver`: Referência `Arc` ao `TypeDBDriver`.
/// * `uri_str`: A URI completa do recurso de esquema.
///
/// # Retorna
/// `Ok(String)` com o conteúdo do esquema TypeQL, ou `Err(ErrorData)` se ocorrer um erro.
#[tracing::instrument(skip(driver), name = "read_dynamic_schema_resource", fields(uri = %uri_str))]
pub async fn read_dynamic_schema_resource(
    driver: Arc<TypeDBDriver>,
    uri_str: &str,
) -> Result<String, ErrorData> {
    tracing::debug!("Lendo recurso de esquema dinâmico.");
    match parse_schema_uri(uri_str) {
        Ok((db_name, schema_type_param)) => {
            tracing::debug!(db.name = %db_name, schema.type_requested = %schema_type_param, "Parâmetros da URI de schema parseados.");
            let db = driver
                .databases()
                .get(&db_name)
                .await
                .map_err(|e| {
                    tracing::warn!(db.name = %db_name, error.message = %e, "Erro ao obter banco de dados para recurso de esquema.");
                    ErrorData {
                        code: ErrorCode::RESOURCE_NOT_FOUND,
                        message: Cow::Owned(format!(
                            "Banco de dados '{db_name}' não encontrado ou inacessível para obter esquema." // db_name já é possuída aqui
                        )),
                        data: Some(serde_json::json!({"originalError": e.to_string()})),
                    }
                })?;

            let schema_fetch_result = if schema_type_param == "types" {
                db.type_schema().await
            } else {
                db.schema().await
            };

            schema_fetch_result.map_err(|e| {
                tracing::error!(db.name = %db_name, schema.type_requested = %schema_type_param, error.message = %e, "Erro ao obter conteúdo do schema do TypeDB.");
                typedb_error_to_mcp_error_data(&e, "read_dynamic_schema_resource (fetch schema content)")
            })
        }
        Err(parse_err) => Err(parse_err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::{ErrorCode, Resource, ResourceTemplate}; // ResourceContents não é usado diretamente nos testes.

    #[test]
    fn test_list_static_resources_content() {
        let resources: Vec<Resource> = list_static_resources();
        assert_eq!(resources.len(), 2);

        let query_types_res_opt = resources.iter().find(|r| r.uri == QUERY_TYPES_URI);
        match query_types_res_opt {
            Some(query_types_res) => {
                assert_eq!(query_types_res.name, QUERY_TYPES_NAME);
                assert_eq!(query_types_res.description.as_deref(), Some(QUERY_TYPES_DESCRIPTION));
                assert_eq!(query_types_res.mime_type.as_deref(), Some("text/plain"));
                assert_eq!(query_types_res.size, u32::try_from(QUERY_TYPES_CONTENT.len()).ok());
            }
            None => panic!("Recurso QUERY_TYPES_URI não encontrado."),
        }
    }

    #[test]
    fn test_list_resource_templates_content() {
        let templates: Vec<ResourceTemplate> = list_resource_templates();
        assert_eq!(templates.len(), 1);

        let schema_template = &templates[0];
        assert_eq!(schema_template.uri_template, SCHEMA_TEMPLATE_URI_TEMPLATE); // uri_template é String
        assert_eq!(schema_template.name, SCHEMA_TEMPLATE_NAME);
    }

    #[test]
    fn test_read_static_resource_contents() {
        assert_eq!(read_static_resource(QUERY_TYPES_URI), Some(QUERY_TYPES_CONTENT.to_string()));
        assert_eq!(read_static_resource("info://invalid/uri"), None);
    }

    #[test]
    fn test_parse_schema_uri_valid_cases() {
        let result1 = parse_schema_uri("schema://current/my_db");
        match result1 {
            Ok((db, stype)) => {
                assert_eq!(db, "my_db");
                assert_eq!(stype, "full");
            }
            Err(e) => panic!("Esperado Ok para schema://current/my_db, obteve Err: {e:?}"),
        }

        let result2 = parse_schema_uri("schema://current/db%20with%20spaces?type=types");
        match result2 {
            Ok((db, stype)) => {
                assert_eq!(db, "db with spaces");
                assert_eq!(stype, "types");
            },
            Err(e) => panic!("Esperado Ok para schema://current/db%20with%20spaces?type=types, obteve Err: {e:?}"),
        }

        let result3 = parse_schema_uri("schema://current/mydb?type=invalid_type_value");
        match result3 {
            Ok((db, stype)) => {
                assert_eq!(db, "mydb");
                assert_eq!(stype, "full");
            }
            Err(e) => panic!(
                "Esperado Ok para schema://current/mydb?type=invalid_type_value, obteve Err: {e:?}"
            ),
        }
    }

    #[test]
    fn test_parse_schema_uri_invalid_cases() {
        let result1 = parse_schema_uri("invalid://current/my_db");
        match result1 {
            Err(err1) => assert_eq!(err1.code, ErrorCode::RESOURCE_NOT_FOUND),
            Ok(val) => panic!("Esperado Err para invalid://current/my_db, obteve Ok: {val:?}"),
        }

        let result2 = parse_schema_uri("schema://current/");
        match result2 {
            Err(err2) => assert_eq!(err2.code, ErrorCode::RESOURCE_NOT_FOUND),
            Ok(val) => panic!("Esperado Err para schema://current/, obteve Ok: {val:?}"),
        }

        let result3 = parse_schema_uri("schema://current/%?type=full");
        match result3 {
            Err(err3) => assert_eq!(err3.code, ErrorCode::INVALID_PARAMS),
            Ok(val) => panic!("Esperado Err para schema://current/%?type=full, obteve Ok: {val:?}"),
        }
    }
}
