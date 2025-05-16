// src/error.rs

// Licença Apache 2.0 (Conforme typedb-driver-rust)
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

//! Define os tipos de erro customizados para o `Typedb-MCP-Server` e utilitários
//! para conversão e tratamento de erros.
//!
//! Este módulo centraliza a lógica de erros da aplicação, facilitando a
//! tradução de erros de dependências (como `typedb_driver` ou `config`)
//! para erros significativos da aplicação e para o formato `ErrorData`
//! esperado pelo protocolo MCP.

use rmcp::model::{ErrorCode, ErrorData};
use serde_json::Value as JsonValue;
use std::borrow::Cow;
use thiserror::Error;
use typedb_driver::Error as TypeDBError;

// Códigos de erro MCP padrão não expostos como constantes nomeadas em rmcp 0.1.5
pub const MCP_ERROR_CODE_AUTHENTICATION_FAILED: i32 = -32000;
pub const MCP_ERROR_CODE_AUTHORIZATION_FAILED: i32 = -32001;

/// Enum principal para erros específicos da aplicação `Typedb-MCP-Server`.
///
/// Cada variante representa uma categoria de erro que pode ocorrer durante
/// a execução do servidor.
#[derive(Error, Debug)]
pub enum McpServerError {
    /// Erro originado durante a interação com o `typedb-driver`.
    #[error("Erro do TypeDB: {0}")]
    TypeDB(#[from] TypeDBErrorWrapper),

    /// Erro ao carregar ou processar as configurações da aplicação.
    #[error("Erro de configuração: {0}")]
    Configuration(#[from] config::ConfigError),

    /// Erro relacionado à autenticação ou autorização OAuth2.
    #[error("Erro de autenticação/autorização: {0}")]
    Auth(#[from] AuthErrorDetail),

    /// Erro genérico de I/O.
    #[error("Erro de I/O: {0}")]
    Io(#[from] std::io::Error),

    /// Erro ocorrido em um HTTP client (ex: ao buscar JWKS).
    #[error("Erro no cliente HTTP: {0}")]
    HttpClient(String),

    /// Erro específico ocorrido durante a execução de uma ferramenta MCP.
    #[error("Erro na execução da ferramenta '{tool_name}': {source}")]
    ToolExecution {
        tool_name: String,
        #[source]
        source: Box<McpServerError>,
    },

    /// Erro interno inesperado no servidor.
    #[error("Erro interno do servidor: {0}")]
    Internal(String),
}

/// Wrapper para `typedb_driver::Error` para permitir implementação de `From`
/// e para potencialmente adicionar contexto se necessário no futuro.
#[derive(Error, Debug)]
#[error("{0}")]
pub struct TypeDBErrorWrapper(#[from] TypeDBError);

/// Detalhes específicos para erros de autenticação e autorização OAuth2.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum AuthErrorDetail {
    #[error("Token de autenticação não fornecido ou malformado.")]
    TokenMissingOrMalformed,

    #[error("Token de autenticação inválido: {0}.")]
    TokenInvalid(String),

    #[error("Falha ao buscar o conjunto de chaves JWKS do Authorization Server: {0}.")]
    JwksFetchFailed(String),

    #[error("O 'kid' (Key ID) do token não foi encontrado no JWKS do Authorization Server.")]
    KidNotFoundInJwks,

    #[error("Assinatura do token inválida.")]
    SignatureInvalid,

    #[error("Token expirado.")]
    TokenExpired,

    #[error("Claim 'issuer' do token não corresponde ao esperado. Esperado um de: {expected:?}, Obtido: {found:?}.")]
    IssuerMismatch { expected: Vec<String>, found: Option<String> },

    #[error("Claim 'audience' do token não corresponde ao esperado. Esperado um de: {expected:?}, Token não continha o audience requerido. Audiences encontrados no token: {found:?}")]
    AudienceMismatch { expected: Vec<String>, found: Option<Vec<String>> },

    #[error("Escopos OAuth2 insuficientes. Requeridos: {required:?}, Possuídos: {possessed:?}.")]
    InsufficientScope { required: Vec<String>, possessed: Vec<String> },

    #[error("Configuração de autenticação inválida: {0}.")]
    InvalidAuthConfig(String),
}

/// Converte um erro originado no `typedb-driver` para uma estrutura `rmcp::model::ErrorData`.
///
/// # Parâmetros
/// * `err`: A referência ao erro do `typedb-driver` (`TypeDBError`).
/// * `tool_name`: O nome da ferramenta MCP que estava em execução.
///
/// # Retorna
/// Uma `ErrorData` configurada com `ErrorCode::INTERNAL_ERROR` e detalhes do erro TypeDB.
pub fn typedb_error_to_mcp_error_data(err: &TypeDBError, tool_name: &str) -> ErrorData {
    let typedb_message = err.message();
    let typedb_code = err.code();

    let mcp_message = format!(
        "Erro na ferramenta MCP '{}' ao interagir com TypeDB: {}",
        tool_name, typedb_message
    );

    tracing::error!(
        tool.name = tool_name,
        typedb.error.message = %typedb_message,
        typedb.error.code = %typedb_code,
        "Erro do TypeDB convertido para MCP ErrorData."
    );

    ErrorData {
        code: ErrorCode::INTERNAL_ERROR,
        message: Cow::Owned(mcp_message),
        data: Some(serde_json::json!({
            "type": "TypeDBError",
            "toolName": tool_name,
            "typedbErrorCode": typedb_code,
            "typedbErrorMessage": typedb_message,
        })),
    }
}

/// Converte um erro da aplicação (`McpServerError`) para uma estrutura `rmcp::model::ErrorData`.
///
/// # Parâmetros
/// * `err`: A referência ao erro da aplicação (`McpServerError`).
/// * `tool_name_opt`: Opcionalmente, o nome da ferramenta MCP que estava em execução.
///
/// # Retorna
/// Uma `ErrorData` configurada de acordo com o `McpServerError`.
pub fn app_error_to_mcp_error_data(
    err: &McpServerError,
    tool_name_opt: Option<&str>,
) -> ErrorData {
    let tool_name = tool_name_opt.unwrap_or("<desconhecido>");

    let mcp_code_val: i32;
    let mcp_message_str: String;
    let mut error_data_json_map = serde_json::Map::new();

    match err {
        McpServerError::TypeDB(TypeDBErrorWrapper(typedb_err)) => {
            return typedb_error_to_mcp_error_data(typedb_err, tool_name);
        }
        McpServerError::Configuration(config_err) => {
            mcp_code_val = ErrorCode::INTERNAL_ERROR.0;
            mcp_message_str = format!("Erro de configuração do servidor: {}", config_err);
            error_data_json_map.insert("type".to_string(), JsonValue::String("ConfigurationError".to_string()));
            error_data_json_map.insert("detail".to_string(), JsonValue::String(config_err.to_string()));
        }
        McpServerError::Auth(auth_err_detail) => {
            error_data_json_map.insert("type".to_string(), JsonValue::String("AuthError".to_string()));
            mcp_message_str = format!("Erro de autenticação/autorização: {}", auth_err_detail); // Mensagem principal
            error_data_json_map.insert("reason".to_string(), JsonValue::String(auth_err_detail.to_string())); // Mensagem de detalhe para 'reason'

            match auth_err_detail {
                AuthErrorDetail::TokenMissingOrMalformed
                | AuthErrorDetail::TokenInvalid(_)
                | AuthErrorDetail::JwksFetchFailed(_)
                | AuthErrorDetail::KidNotFoundInJwks
                | AuthErrorDetail::SignatureInvalid
                | AuthErrorDetail::TokenExpired => {
                    mcp_code_val = MCP_ERROR_CODE_AUTHENTICATION_FAILED;
                }
                AuthErrorDetail::IssuerMismatch { expected, found } => {
                    mcp_code_val = MCP_ERROR_CODE_AUTHORIZATION_FAILED;
                    error_data_json_map.insert("expectedIssuers".to_string(), serde_json::json!(expected));
                    error_data_json_map.insert("foundIssuer".to_string(), serde_json::json!(found));
                }
                AuthErrorDetail::AudienceMismatch { expected, found } => {
                    mcp_code_val = MCP_ERROR_CODE_AUTHORIZATION_FAILED;
                    error_data_json_map.insert("expectedAudiences".to_string(), serde_json::json!(expected));
                    error_data_json_map.insert("foundAudiences".to_string(), serde_json::json!(found));
                }
                AuthErrorDetail::InsufficientScope { required, possessed } => {
                    mcp_code_val = MCP_ERROR_CODE_AUTHORIZATION_FAILED;
                    error_data_json_map.insert("requiredScopes".to_string(), serde_json::json!(required));
                    error_data_json_map.insert("possessedScopes".to_string(), serde_json::json!(possessed));
                }
                AuthErrorDetail::InvalidAuthConfig(_) => {
                    mcp_code_val = ErrorCode::INTERNAL_ERROR.0;
                }
            };
        }
        McpServerError::Io(io_err) => {
            mcp_code_val = ErrorCode::INTERNAL_ERROR.0;
            mcp_message_str = format!("Erro de I/O: {}", io_err);
            error_data_json_map.insert("type".to_string(), JsonValue::String("IoError".to_string()));
            error_data_json_map.insert("detail".to_string(), JsonValue::String(io_err.to_string()));
        }
        McpServerError::HttpClient(http_err_msg) => {
            mcp_code_val = ErrorCode::INTERNAL_ERROR.0;
            mcp_message_str = format!("Erro no cliente HTTP: {}", http_err_msg);
            error_data_json_map.insert("type".to_string(), JsonValue::String("HttpClientError".to_string()));
            error_data_json_map.insert("detail".to_string(), JsonValue::String(http_err_msg.clone()));
        }
        McpServerError::ToolExecution { tool_name: current_tool_name, source } => {
            tracing::error!(
                tool.name = current_tool_name,
                root_cause = %source,
                "Erro na execução da ferramenta."
            );
            return app_error_to_mcp_error_data(source, Some(current_tool_name));
        }
        McpServerError::Internal(msg) => {
            mcp_code_val = ErrorCode::INTERNAL_ERROR.0;
            mcp_message_str = format!("Erro interno do servidor: {}", msg);
            error_data_json_map.insert("type".to_string(), JsonValue::String("InternalServerError".to_string()));
            error_data_json_map.insert("detail".to_string(), JsonValue::String(msg.clone()));
        }
    };

    let mcp_error_code = ErrorCode(mcp_code_val);
    tracing::error!(
        tool.name = tool_name,
        application_error = %err,
        mcp.error.code = %mcp_error_code.0,
        mcp.error.message = %mcp_message_str,
        "Erro da aplicação convertido para MCP ErrorData."
    );

    ErrorData {
        code: mcp_error_code,
        message: Cow::Owned(mcp_message_str),
        data: Some(JsonValue::Object(error_data_json_map)),
    }
}


/// Formata um erro do `typedb-driver` como uma string legível para o usuário.
///
/// Útil para cenários como a ferramenta `validate_query`.
///
/// # Parâmetros
/// * `err`: A referência ao erro do `typedb-driver` (`TypeDBError`).
/// * `query_context_msg`: Mensagem de contexto descrevendo a operação.
///
/// # Retorna
/// Uma `String` formatada, prefixada com "ERRO: ".
pub fn typedb_error_to_user_string(err: &TypeDBError, query_context_msg: &str) -> String {
    let typedb_full_message = err.message();

    let formatted_error = format!("ERRO: {}: {}", query_context_msg, typedb_full_message);

    tracing::warn!(
        context_message = query_context_msg,
        typedb.error.full_message = %typedb_full_message,
        "Erro TypeDB formatado para string de usuário (informativo)."
    );
    formatted_error
}

// Testes unitários
#[cfg(test)]
mod tests {
    use super::*;
    use config::ConfigError as LibConfigError;
    use typedb_driver::error::ConnectionError as TypeDBConnectionError;


    fn create_mock_typedb_server_error(code: &str, message: &str) -> TypeDBError {
        TypeDBError::Connection(TypeDBConnectionError::ServerConnectionFailedStatusError {
            error: format!("[{}] MOCK_DOMAIN. {}", code, message),
        })
    }

    #[test]
    fn test_typedb_error_to_mcp_error_data_conversion() {
        let tool_name = "test_tool_typedb";
        let original_message = "A test TypeDB error occurred.";
        let original_typedb_code_mock = "DBS06";

        let typedb_err = create_mock_typedb_server_error(original_typedb_code_mock, original_message);

        let error_data = typedb_error_to_mcp_error_data(&typedb_err, tool_name);

        assert_eq!(error_data.code, ErrorCode::INTERNAL_ERROR);

        let expected_mcp_message = format!(
            "Erro na ferramenta MCP '{}' ao interagir com TypeDB: {}",
            tool_name,
            typedb_err.message()
        );
        assert_eq!(error_data.message.as_ref(), expected_mcp_message);

        let data_json = error_data.data.expect("ErrorData should have data field");
        assert_eq!(data_json.get("type").and_then(|v| v.as_str()), Some("TypeDBError"));
        assert_eq!(data_json.get("toolName").and_then(|v| v.as_str()), Some(tool_name));
        assert_eq!(data_json.get("typedbErrorCode").and_then(|v| v.as_str()), Some("CXN04"));
        assert_eq!(data_json.get("typedbErrorMessage").and_then(|v| v.as_str()), Some(typedb_err.message().as_str()));
    }

    #[test]
    fn test_typedb_error_to_user_string_formatting() {
        let context_msg = "Validando consulta de teste";
        let original_message = "Syntax error in query for test.";
        let original_typedb_code_mock = "QSC01";
        let typedb_err = create_mock_typedb_server_error(original_typedb_code_mock, original_message);

        let user_string = typedb_error_to_user_string(&typedb_err, context_msg);

        let expected_string = format!(
            "ERRO: {}: {}",
            context_msg,
            typedb_err.message()
        );
        assert_eq!(user_string, expected_string);
    }

    #[test]
    fn test_app_error_to_mcp_error_data_for_auth_token_missing() {
        let app_err = McpServerError::Auth(AuthErrorDetail::TokenMissingOrMalformed);
        let error_data = app_error_to_mcp_error_data(&app_err, Some("any_tool"));

        assert_eq!(error_data.code, ErrorCode(MCP_ERROR_CODE_AUTHENTICATION_FAILED));
        assert!(error_data.message.contains("Erro de autenticação: Token de autenticação não fornecido ou malformado."));
        let data_json = error_data.data.as_ref().unwrap().as_object().unwrap();
        assert_eq!(data_json.get("type").and_then(|v| v.as_str()), Some("AuthError"));
        assert!(data_json.get("reason").unwrap().as_str().unwrap().contains("Token de autenticação não fornecido ou malformado."));
    }

    #[test]
    fn test_app_error_to_mcp_error_data_for_auth_insufficient_scope() {
        let required_scopes = vec!["write".to_string()];
        let possessed_scopes = vec!["read".to_string()];
        let app_err = McpServerError::Auth(AuthErrorDetail::InsufficientScope {
            required: required_scopes.clone(),
            possessed: possessed_scopes.clone(),
        });
        let error_data = app_error_to_mcp_error_data(&app_err, Some("tool_requiring_write"));

        assert_eq!(error_data.code, ErrorCode(MCP_ERROR_CODE_AUTHORIZATION_FAILED));
        let expected_message_detail = "Escopos OAuth2 insuficientes. Requeridos: [\"write\"], Possuídos: [\"read\"].";
        assert_eq!(error_data.message.as_ref(), format!("Erro de autorização: {}", expected_message_detail));

        let data_json = error_data.data.as_ref().unwrap().as_object().unwrap();
        assert_eq!(data_json.get("type").and_then(|v| v.as_str()), Some("AuthError"));
        assert_eq!(data_json.get("reason").unwrap().as_str().unwrap(), expected_message_detail);
        assert_eq!(data_json.get("requiredScopes").unwrap(), &serde_json::json!(required_scopes));
        assert_eq!(data_json.get("possessedScopes").unwrap(), &serde_json::json!(possessed_scopes));
    }

    #[test]
    fn test_app_error_to_mcp_error_data_for_config_error() {
        let config_err_instance = LibConfigError::NotFound("uma.chave.de.config".to_string());
        let app_err = McpServerError::Configuration(config_err_instance); // Não precisa de clone aqui
        let error_data = app_error_to_mcp_error_data(&app_err, None);

        assert_eq!(error_data.code, ErrorCode::INTERNAL_ERROR);
        assert!(error_data.message.contains("Erro de configuração do servidor"));
        assert!(error_data.message.contains("uma.chave.de.config not found"));
        let data_json = error_data.data.as_ref().unwrap().as_object().unwrap();
        assert_eq!(data_json.get("type").and_then(|v| v.as_str()), Some("ConfigurationError"));
        assert!(data_json.get("detail").unwrap().as_str().unwrap().contains("uma.chave.de.config not found"));
    }

    #[test]
    fn test_app_error_to_mcp_error_data_for_auth_issuer_mismatch() {
        let expected = vec!["https://expected.issuer".to_string()];
        let found = Some("https://actual.issuer".to_string());
        let app_err = McpServerError::Auth(AuthErrorDetail::IssuerMismatch {
            expected: expected.clone(),
            found: found.clone(),
        });
        let error_data = app_error_to_mcp_error_data(&app_err, Some("auth_tool"));

        assert_eq!(error_data.code, ErrorCode(MCP_ERROR_CODE_AUTHORIZATION_FAILED));
        let expected_message_detail = format!(
            "Claim 'issuer' do token não corresponde ao esperado. Esperado um de: {:?}, Obtido: {:?}.",
            expected, found
        );
        assert_eq!(error_data.message.as_ref(), format!("Erro de autorização: {}", expected_message_detail));

        let data_json = error_data.data.as_ref().unwrap().as_object().unwrap();
        assert_eq!(data_json.get("type").and_then(|v| v.as_str()), Some("AuthError"));
        assert_eq!(data_json.get("reason").unwrap().as_str().unwrap(), expected_message_detail);
        assert_eq!(data_json.get("expectedIssuers").unwrap(), &serde_json::json!(expected));
        assert_eq!(data_json.get("foundIssuer").unwrap(), &serde_json::json!(found));
    }
}