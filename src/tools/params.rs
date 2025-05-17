// src/tools/params.rs

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

//! Define as estruturas de parâmetros de entrada para cada ferramenta MCP
//! exposta pelo `Typedb-MCP-Server`.
//!
//! Cada struct aqui é desserializada a partir do JSON fornecido na chamada da
//! ferramenta (`CallToolRequestParam.arguments`) e também usada para gerar
//! o `input_schema` da ferramenta via `#[derive(JsonSchema)]`.
//! O atributo `#[serde(rename_all = "camelCase")]` garante que os campos
//! no JSON de entrada usem camelCase (ex: `databaseName`), enquanto no Rust
//! usamos snake_case (ex: `database_name`).

// rmcp v0.1.5 reexporta serde e schemars. Usamos estas reexportações.
use rmcp::{
    schemars::{self, JsonSchema}, // schemars v0.8.x
    serde::Deserialize,           // serde v1.0.x
};

/// Parâmetros para a ferramenta `query_read`.
#[derive(Deserialize, JsonSchema, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct QueryReadParams {
    /// O nome do banco de dados `TypeDB` alvo para a consulta.
    #[schemars(description = "O nome do banco de dados TypeDB alvo para a consulta.")]
    pub database_name: String,
    /// A consulta `TypeQL` completa de leitura.
    /// Exemplos: `match $x isa person; get;`, `match $p isa person; fetch $p { name, age };`, `match $p isa person; aggregate count;`.
    #[schemars(description = "A consulta TypeQL completa de leitura (ex: `match $x isa person; get;`, `match $p isa person; fetch $p { name, age };`, `match $p isa person; aggregate count;`).")]
    pub query: String,
}

/// Parâmetros para a ferramenta `insert_data`.
#[derive(Deserialize, JsonSchema, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InsertDataParams {
    /// O nome do banco de dados `TypeDB` alvo para a inserção.
    #[schemars(description = "O nome do banco de dados TypeDB alvo para a inserção.")]
    pub database_name: String,
    /// A consulta `TypeQL` de inserção completa.
    /// Exemplos: `insert $x isa person, has name 'Alice';`, `match $p isa person, has name 'Bob'; insert $p has age 30;`.
    #[schemars(description = "A consulta TypeQL de inserção completa (ex: `insert $x isa person, has name 'Alice';` ou `match $p isa person, has name 'Bob'; insert $p has age 30;`).")]
    pub query: String,
}

/// Parâmetros para a ferramenta `delete_data`.
#[derive(Deserialize, JsonSchema, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeleteDataParams {
    /// O nome do banco de dados `TypeDB` alvo para a deleção.
    #[schemars(description = "O nome do banco de dados TypeDB alvo para a deleção.")]
    pub database_name: String,
    /// A consulta `TypeQL` de deleção completa.
    /// Exemplo: `match $p isa person, has name 'Alice'; delete $p;`.
    #[schemars(description = "A consulta TypeQL de deleção completa (ex: `match $p isa person, has name 'Alice'; delete $p;`).")]
    pub query: String,
}

/// Parâmetros para a ferramenta `update_data`.
#[derive(Deserialize, JsonSchema, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UpdateDataParams {
    /// O nome do banco de dados `TypeDB` alvo para a atualização.
    #[schemars(description = "O nome do banco de dados TypeDB alvo para a atualização.")]
    pub database_name: String,
    /// A consulta `TypeQL` de atualização completa.
    /// Exemplo: `match $p isa person, has name 'Alice', has age $a; delete $p has age $a; insert $p has age 31;`.
    #[schemars(description = "A consulta TypeQL de atualização completa (ex: `match $p isa person, has name 'Alice', has age $a; delete $p has age $a; insert $p has age 31;`).")]
    pub query: String,
}

/// Parâmetros para a ferramenta `define_schema`.
#[derive(Deserialize, JsonSchema, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DefineSchemaParams {
    /// O nome do banco de dados `TypeDB` cujo esquema será modificado.
    #[schemars(description = "O nome do banco de dados TypeDB cujo esquema será modificado.")]
    pub database_name: String,
    /// Uma string contendo uma ou mais declarações `TypeQL` `define` válidas.
    /// Exemplo: `define person sub entity, owns name; name sub attribute, value string;`.
    #[schemars(description = "Uma string contendo uma ou mais declarações TypeQL `define` válidas (ex: `define person sub entity, owns name; name sub attribute, value string;`).")]
    pub schema_definition: String,
}

/// Parâmetros para a ferramenta `undefine_schema`.
#[derive(Deserialize, JsonSchema, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UndefineSchemaParams {
    /// O nome do banco de dados `TypeDB` cujo esquema será modificado.
    #[schemars(description = "O nome do banco de dados TypeDB cujo esquema será modificado.")]
    pub database_name: String,
    /// Uma string contendo uma ou mais declarações `TypeQL` `undefine` válidas.
    /// Exemplo: `undefine person plays employment;`.
    #[schemars(description = "Uma string contendo uma ou mais declarações TypeQL `undefine` válidas (ex: `undefine person plays employment;`).")]
    pub schema_undefinition: String,
}

/// Parâmetros para a ferramenta `get_schema`.
#[derive(Deserialize, JsonSchema, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GetSchemaParams {
    /// O nome do banco de dados `TypeDB` do qual o esquema será recuperado.
    #[schemars(description = "O nome do banco de dados TypeDB do qual o esquema será recuperado.")]
    pub database_name: String,
    /// Especifica o tipo de esquema a ser retornado: "full" para o esquema completo
    /// (incluindo regras) ou "types" para apenas as definições de tipo (entidades,
    /// relações, atributos). Se omitido, o padrão é "full".
    #[schemars(description = "Especifica o tipo de esquema a ser retornado: 'full' para o esquema completo (incluindo regras) ou 'types' para apenas as definições de tipo. Default: 'full'. Valores permitidos: \"full\", \"types\".")]
    pub schema_type: Option<String>,
}

/// Parâmetros para a ferramenta `create_database`.
#[derive(Deserialize, JsonSchema, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreateDatabaseParams {
    /// O nome para o novo banco de dados a ser criado.
    #[schemars(description = "O nome para o novo banco de dados a ser criado.")]
    pub name: String,
}

/// Parâmetros para a ferramenta `database_exists`.
#[derive(Deserialize, JsonSchema, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseExistsParams {
    /// O nome do banco de dados cuja existência será verificada.
    #[schemars(description = "O nome do banco de dados cuja existência será verificada.")]
    pub name: String,
}

// A ferramenta `list_databases` não possui parâmetros.

/// Parâmetros para a ferramenta `delete_database`.
#[derive(Deserialize, JsonSchema, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeleteDatabaseParams {
    /// O nome do banco de dados a ser permanentemente deletado.
    #[schemars(description = "O nome do banco de dados a ser permanentemente deletado.")]
    pub name: String,
}

/// Parâmetros para a ferramenta `validate_query`.
#[derive(Deserialize, JsonSchema, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ValidateQueryParams {
    /// O nome de um banco de dados `TypeDB` existente.
    /// O esquema deste banco será usado como contexto para a validação.
    #[schemars(description = "O nome de um banco de dados TypeDB existente. O esquema deste banco será usado como contexto para a validação.")]
    pub database_name: String,
    /// A consulta `TypeQL` a ser validada.
    #[schemars(description = "A consulta TypeQL a ser validada.")]
    pub query: String,
    /// O tipo de transação para o qual esta consulta se destina.
    /// Embora a validação use uma transação de leitura, esta informação pode ajudar
    /// a identificar erros contextuais. Se omitido, o padrão é "read".
    #[schemars(description = "O tipo de transação para o qual esta consulta se destina. Default: 'read'. Valores permitidos: \"read\", \"write\", \"schema\".")]
    pub intended_transaction_type: Option<String>,
}

// Testes unitários para as structs de parâmetros.
#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::schemars::schema_for; // Para gerar o schema JSON

    #[test]
    fn test_query_read_params_deserialize_and_schema() -> Result<(), Box<dyn std::error::Error>> {
        let json_data = r#"
        {
            "databaseName": "my_db",
            "query": "match $x isa person; get;"
        }
        "#;
        let params: QueryReadParams = serde_json::from_str(json_data)?;
        assert_eq!(params.database_name, "my_db");
        assert_eq!(params.query, "match $x isa person; get;");

        let schema = schema_for!(QueryReadParams);
        let schema_json = serde_json::to_value(&schema)?;
        assert_eq!(schema_json["type"], "object");
        assert!(schema_json["properties"]["databaseName"]["description"].is_string());
        assert!(schema_json["properties"]["query"]["description"].is_string());
        let required = schema_json["required"].as_array().ok_or("required não é array")?;
        assert!(required.contains(&serde_json::Value::String("databaseName".to_string())));
        assert!(required.contains(&serde_json::Value::String("query".to_string())));
        Ok(())
    }

    #[test]
    fn test_get_schema_params_deserialize_optional() -> Result<(), Box<dyn std::error::Error>> {
        let json_data_full = r#"
        {
            "databaseName": "my_db",
            "schemaType": "full"
        }
        "#;
        let params_full: GetSchemaParams = serde_json::from_str(json_data_full)?;
        assert_eq!(params_full.database_name, "my_db");
        assert_eq!(params_full.schema_type, Some("full".to_string()));

        let json_data_none = r#"
        {
            "databaseName": "my_other_db"
        }
        "#;
        let params_none: GetSchemaParams = serde_json::from_str(json_data_none)?;
        assert_eq!(params_none.database_name, "my_other_db");
        assert_eq!(params_none.schema_type, None);

        let schema = schema_for!(GetSchemaParams);
        let schema_json = serde_json::to_value(&schema)?;
        assert!(schema_json["properties"]["schemaType"]["description"].is_string());
        // "schemaType" não deve estar na lista de "required"
        let required = schema_json["required"].as_array().ok_or("required não é array")?;
        assert!(!required.iter().any(|v| v.as_str().unwrap_or("") == "schemaType"));
        Ok(())
    }

    #[test]
    fn test_validate_query_params_deserialize_optional() -> Result<(), Box<dyn std::error::Error>> {
        let json_data_full = r#"
        {
            "databaseName": "my_db",
            "query": "match $x isa person; get;",
            "intendedTransactionType": "write"
        }
        "#;
        let params_full: ValidateQueryParams = serde_json::from_str(json_data_full)?;
        assert_eq!(params_full.database_name, "my_db");
        assert_eq!(params_full.query, "match $x isa person; get;");
        assert_eq!(params_full.intended_transaction_type, Some("write".to_string()));
        Ok(())
    }

    // Teste de falha na desserialização se um campo obrigatório estiver faltando
    #[test]
    fn test_query_read_params_missing_required_field() -> Result<(), Box<dyn std::error::Error>> {
        let json_data = r#"
        {
            "query": "match $x isa person; get;"
        }
        "#; // Falta databaseName
        let result: Result<QueryReadParams, _> = serde_json::from_str(json_data);
        assert!(result.is_err(), "Desserialização deveria falhar por campo obrigatório ausente");
        Ok(())
    }

    // Teste para verificar se camelCase está funcionando
    #[test]
    fn test_camel_case_deserialization_for_all_structs() -> Result<(), Box<dyn std::error::Error>> {
        // Define um macro para reduzir a repetição
        macro_rules! test_camel_case {
            ($struct_type:ty, $json_field_name:expr, $rust_field_name:ident, $sample_value_json:expr, $sample_value_rust:expr) => {
                let json_data = format!(r#"{{ "{}": {} }}"#, $json_field_name, $sample_value_json);
                let params: $struct_type = serde_json::from_str(&json_data)?;
                assert_eq!(params.$rust_field_name, $sample_value_rust, "Campo {} não correspondeu para {}", stringify!($rust_field_name), stringify!($struct_type));
            };
            // Variante para quando todos os campos são obrigatórios e precisam ser fornecidos
            ($struct_type:ty, $json_field_name1:expr, $rust_field_name1:ident, $sample_value_json1:expr, $sample_value_rust1:expr,
                                $json_field_name2:expr, $rust_field_name2:ident, $sample_value_json2:expr, $sample_value_rust2:expr) => {
                let json_data = format!(r#"{{ "{}": {}, "{}": {} }}"#, $json_field_name1, $sample_value_json1, $json_field_name2, $sample_value_json2);
                let params: $struct_type = serde_json::from_str(&json_data)?;
                assert_eq!(params.$rust_field_name1, $sample_value_rust1, "Campo {} não correspondeu para {}", stringify!($rust_field_name1), stringify!($struct_type));
                assert_eq!(params.$rust_field_name2, $sample_value_rust2, "Campo {} não correspondeu para {}", stringify!($rust_field_name2), stringify!($struct_type));
            };
        }

        test_camel_case!(QueryReadParams, "databaseName", database_name, r#""test_db""#, "test_db".to_string(), "query", query, r#""match;""#, "match;".to_string());
        test_camel_case!(InsertDataParams, "databaseName", database_name, r#""test_db""#, "test_db".to_string(), "query", query, r#""insert;""#, "insert;".to_string());
        test_camel_case!(DeleteDataParams, "databaseName", database_name, r#""test_db""#, "test_db".to_string(), "query", query, r#""delete;""#, "delete;".to_string());
        test_camel_case!(UpdateDataParams, "databaseName", database_name, r#""test_db""#, "test_db".to_string(), "query", query, r#""update;""#, "update;".to_string());
        test_camel_case!(DefineSchemaParams, "databaseName", database_name, r#""test_db""#, "test_db".to_string(), "schemaDefinition", schema_definition, r#""define;""#, "define;".to_string());
        test_camel_case!(UndefineSchemaParams, "databaseName", database_name, r#""test_db""#, "test_db".to_string(), "schemaUndefinition", schema_undefinition, r#""undefine;""#, "undefine;".to_string());
        test_camel_case!(GetSchemaParams, "databaseName", database_name, r#""test_db""#, "test_db".to_string()); // schema_type é opcional
        test_camel_case!(CreateDatabaseParams, "name", name, r#""new_db""#, "new_db".to_string());
        test_camel_case!(DatabaseExistsParams, "name", name, r#""check_db""#, "check_db".to_string());
        test_camel_case!(DeleteDatabaseParams, "name", name, r#""del_db""#, "del_db".to_string());
        test_camel_case!(ValidateQueryParams, "databaseName", database_name, r#""valid_db""#, "valid_db".to_string(), "query", query, r#""validate;""#, "validate;".to_string()); // intended_transaction_type é opcional
        Ok(())
    }
}