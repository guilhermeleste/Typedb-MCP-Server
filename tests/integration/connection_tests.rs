// tests/integration/connection_tests.rs

// Licença Apache 2.0
// Copyright 2025 Guilherme Leste
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

//! Testes de integração para conexão, TLS do servidor MCP, e autenticação OAuth2.

// Assume-se que `tests/common/mod.rs` existe e exporta os helpers necessários.
// O caminho exato para `common` pode variar dependendo de como o Cargo resolve
// os módulos de teste. Se `common` for um módulo dentro do crate de teste `connection_integration_tests`,
// seria `mod common;` e depois `use common::...`.
// Se for tratado como parte de um "super-crate" de teste (menos comum), o path seria diferente.
// Para um arquivo `tests/connection_integration_tests.rs`, `mod common;`
// esperaria `tests/connection_integration_tests/common.rs` ou `tests/connection_integration_tests/common/mod.rs`.
// A estrutura mais provável é ter `tests/common/` e usar um path relativo ou `crate::common`.
// Para testes de integração, `crate` refere-se ao crate principal, não ao crate de teste.
// Portanto, os helpers em `tests/common/` precisam ser acessados de uma forma que o compilador entenda
// que são parte da suíte de testes, mas não do crate principal.
// Uma maneira é ter um `tests/lib.rs` (ou `tests/main.rs` se não for uma lib) que declara `pub mod common;`
// e os outros arquivos de teste. Ou, cada arquivo de teste pode ter `#[path = "../common/mod.rs"] mod common;`

// Abordagem comum:
#[path = "../common/mod.rs"]
mod common;

use common::client::{TestMcpClient, McpClientError};
use common::auth_helpers::{generate_test_jwt, TestClaims, TEST_KID_RSA_GOOD, TEST_RSA_PRIVATE_KEY_PEM_GOOD}; // Assumindo nomes dos helpers
use common::docker_helpers::DockerComposeEnv; // Se os testes orquestram Docker

use rmcp::model::{ErrorData, ListToolsResult}; // Para uma chamada MCP simples
use serde_json::Value as JsonValue;
use std::time::Duration;

// --- Constantes para Endpoints de Teste ---
// Estas URLs devem corresponder ao que está exposto pelo docker-compose.test.yml
// e às portas internas configuradas no Typedb-MCP-Server
const MCP_SERVER_WS_URL_NO_TLS: &str = "ws://localhost:8788/mcp/ws"; // Porta mapeada do host
const MCP_SERVER_WSS_URL: &str = "wss://localhost:8789/mcp/ws";    // Porta mapeada diferente para TLS
const TEST_COMPOSE_FILE: &str = "docker-compose.test.yml";
const TYPEDB_SERVICE_NAME_IN_COMPOSE: &str = "typedb-server-it";
const MCP_SERVER_SERVICE_NAME_IN_COMPOSE: &str = "typedb-mcp-server-it";
const MOCK_AUTH_SERVICE_NAME_IN_COMPOSE: &str = "mock-auth-server-it";

// --- Funções Helper para este arquivo de teste ---

/// Configura o ambiente Docker Compose para uma suíte de testes.
/// Retorna o DockerComposeEnv para que o Drop seja chamado no final do escopo do teste.
/// Os testes precisam ser `#[serial]` se usarem o mesmo `project_name_prefix`.
async fn setup_test_environment(test_name: &str) -> DockerComposeEnv {
    let docker_env = DockerComposeEnv::new(TEST_COMPOSE_FILE, test_name);
    docker_env.down().unwrap_or_else(|e| eprintln!("Nota: falha no down inicial (pode ser a primeira execução): {}", e)); // Limpeza preventiva
    docker_env.up().expect("Falha ao iniciar ambiente Docker para teste de conexão");

    // Esperar pelos serviços essenciais
    docker_env.wait_for_service_healthy(TYPEDB_SERVICE_NAME_IN_COMPOSE, Duration::from_secs(90), Duration::from_secs(2))
        .await.unwrap_or_else(|e| panic!("TypeDB não ficou saudável: {:?}", e));
    docker_env.wait_for_service_healthy(MOCK_AUTH_SERVICE_NAME_IN_COMPOSE, Duration::from_secs(30), Duration::from_secs(1))
        .await.unwrap_or_else(|e| panic!("Mock Auth Server não ficou saudável: {:?}", e));
    docker_env.wait_for_service_healthy(MCP_SERVER_SERVICE_NAME_IN_COMPOSE, Duration::from_secs(30), Duration::from_secs(1))
        .await.unwrap_or_else(|e| panic!("Typedb-MCP-Server não ficou saudável: {:?}", e));
    docker_env
}

// --- Testes ---

#[tokio::test]
#[serial_test::serial] // Garante que este teste rode serialmente se modificar estado global ou Docker
async fn test_connect_ws_oauth_disabled_server_tls_disabled() {
    // Requer que o docker-compose.test.yml possa ser configurado para este cenário:
    // MCP_SERVER_TLS_ENABLED=false, MCP_AUTH_OAUTH_ENABLED=false
    // Isso pode ser feito com um arquivo .env específico para este teste ou múltiplas compose files.
    // Por simplicidade, vamos assumir que o docker-compose.test.yml é configurado
    // para este estado específico antes de rodar este teste.
    // Ou, melhor, que o setup_test_environment pode passar env vars para o `docker-compose up`.
    // TODO: Adaptar DockerComposeEnv para permitir passar variáveis de ambiente ao `up`.
    // Por agora, este teste é conceitual e depende da configuração manual do compose file.

    let _docker_env = setup_test_environment("connect_ws_no_oauth_no_tls").await; // Drop fará o down

    let mut client = TestMcpClient::connect(MCP_SERVER_WS_URL_NO_TLS, None)
        .await
        .expect("Deveria conectar via WS sem TLS e sem OAuth");

    // Fazer uma chamada MCP simples para verificar a conexão
    let result = client.call_tool_typed("tools/list", None).await;
    assert!(result.is_ok(), "Falha ao chamar tools/list: {:?}", result.err());
    let list_tools_result: ListToolsResult = result.unwrap().try_into().expect("Resultado de tools/list inválido");
    assert!(!list_tools_result.tools.is_empty(), "A lista de ferramentas não deveria estar vazia");

    client.close().await.expect("Falha ao fechar cliente");
}

#[tokio::test]
#[serial_test::serial]
async fn test_connect_wss_oauth_disabled_server_tls_enabled() {
    // Requer MCP_SERVER_TLS_ENABLED=true, MCP_AUTH_OAUTH_ENABLED=false no compose
    let _docker_env = setup_test_environment("connect_wss_no_oauth_tls").await;

    // O TestMcpClient::connect precisará de lógica para confiar no CA de teste
    // ou desabilitar a verificação de certificado para o cliente de teste.
    let mut client = TestMcpClient::connect(MCP_SERVER_WSS_URL, None)
        .await
        .expect("Deveria conectar via WSS com TLS e sem OAuth");

    let result = client.call_tool_typed("tools/list", None).await;
    assert!(result.is_ok(), "Falha ao chamar tools/list: {:?}", result.err());
    client.close().await.expect("Falha ao fechar cliente");
}


#[tokio::test]
#[serial_test::serial]
async fn test_connect_wss_oauth_enabled_no_token_fails_or_tool_call_fails() {
    // Requer MCP_SERVER_TLS_ENABLED=true, MCP_AUTH_OAUTH_ENABLED=true
    let _docker_env = setup_test_environment("connect_wss_oauth_no_token").await;

    // A conexão WebSocket pode ter sucesso, mas a primeira chamada de ferramenta deve falhar
    // ou o middleware Axum pode rejeitar o upgrade HTTP se TypedHeader falhar.
    match TestMcpClient::connect(MCP_SERVER_WSS_URL, None).await {
        Ok(mut client) => {
            // Conexão estabelecida, agora a chamada da ferramenta deve falhar
            let result = client.call_tool_typed("tools/list", None).await;
            assert!(matches!(result, Err(McpClientError::McpErrorResponse(ErrorData { code, .. })) if code.0 == rmcp::model::ErrorCode::AUTHENTICATION_REQUIRED.0 || code.0 == rmcp::model::ErrorCode(-32000).0 /* AUTHENTICATION_FAILED */ ));
            // O código exato pode depender de como o middleware Axum ou rmcp mapeia o erro de token ausente
            // Ou, se TypedHeader falhar, a conexão nem estabelece (o que é melhor).
            // Se a conexão falhar, o assert abaixo é mais apropriado.
            client.close().await.ok(); // Tenta fechar se abriu
        }
        Err(McpClientError::WebSocketError(ws_err)) => {
            // Se o middleware Axum rejeitar o upgrade devido à falha do TypedHeader (token ausente)
            // isso resultará em um erro de handshake WebSocket.
            tracing::info!("Conexão WebSocket falhou como esperado devido à ausência de token: {}", ws_err);
            // Um erro comum seria um HTTP 401 durante o handshake, que o cliente websocket interpreta como falha.
            assert!(ws_err.to_string().contains("Handshake failed") || ws_err.to_string().contains("401"));
        }
        Err(e) => {
            panic!("Erro inesperado ao tentar conectar sem token: {:?}", e);
        }
    }
}

#[tokio::test]
#[serial_test::serial]
async fn test_connect_wss_oauth_enabled_invalid_token_fails() {
    let _docker_env = setup_test_environment("connect_wss_oauth_invalid_token").await;
    let invalid_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImludmFsaWQifQ.eyJzdWIiOiJ0ZXN0In0.invalid_signature";

    match TestMcpClient::connect(MCP_SERVER_WSS_URL, Some(invalid_token.to_string())).await {
         Ok(mut client) => {
            let result = client.call_tool_typed("tools/list", None).await;
            assert!(matches!(result, Err(McpClientError::McpErrorResponse(ErrorData { code, .. })) if code.0 == rmcp::model::ErrorCode(-32000).0 /* AUTHENTICATION_FAILED */ ));
            client.close().await.ok();
        }
        Err(McpClientError::WebSocketError(ws_err)) => {
             tracing::info!("Conexão WebSocket falhou como esperado devido a token inválido: {}", ws_err);
             assert!(ws_err.to_string().contains("Handshake failed") || ws_err.to_string().contains("401"));
        }
        Err(e) => {
            panic!("Erro inesperado ao tentar conectar com token inválido: {:?}", e);
        }
    }
}

#[tokio::test]
#[serial_test::serial]
async fn test_connect_wss_oauth_enabled_expired_token_fails() {
    let _docker_env = setup_test_environment("connect_wss_oauth_expired_token").await;
    let now_ts = common::auth_helpers::current_timestamp_secs();
    let claims = TestClaims {
        sub: "expired_user".to_string(),
        exp: now_ts.saturating_sub(3600), // Expirou há 1 hora
        iat: Some(now_ts.saturating_sub(7200)),
        nbf: Some(now_ts.saturating_sub(7200)),
        iss: Some("test-issuer".to_string()), // Deve corresponder ao config.oauth.issuer
        aud: Some(serde_json::json!("test-audience")), // Deve corresponder ao config.oauth.audience
        scope: Some("typedb:read_data".to_string()),
        custom_claim: None,
    };
    let expired_token = generate_test_jwt(claims, jsonwebtoken::Algorithm::RS256, TEST_KID_RSA_GOOD, &TEST_RSA_PRIVATE_KEY_PEM_GOOD);

     match TestMcpClient::connect(MCP_SERVER_WSS_URL, Some(expired_token)).await {
         Ok(mut client) => {
            let result = client.call_tool_typed("tools/list", None).await;
            assert!(matches!(result, Err(McpClientError::McpErrorResponse(ErrorData { code, .. })) if code.0 == rmcp::model::ErrorCode(-32000).0 /* AUTHENTICATION_FAILED */ ));
            client.close().await.ok();
        }
        Err(McpClientError::WebSocketError(ws_err)) => {
             tracing::info!("Conexão WebSocket falhou como esperado devido a token expirado: {}", ws_err);
             assert!(ws_err.to_string().contains("Handshake failed") || ws_err.to_string().contains("401"));
        }
        Err(e) => {
            panic!("Erro inesperado ao tentar conectar com token expirado: {:?}", e);
        }
    }
}

#[tokio::test]
#[serial_test::serial]
async fn test_connect_wss_oauth_enabled_valid_token_succeeds() {
    let _docker_env = setup_test_environment("connect_wss_oauth_valid_token").await;
    let now_ts = common::auth_helpers::current_timestamp_secs();
    let claims = TestClaims {
        sub: "valid_user".to_string(),
        exp: now_ts + 3600, // Válido por 1 hora
        iat: Some(now_ts),
        nbf: Some(now_ts),
        iss: Some("test-issuer".to_string()),
        aud: Some(serde_json::json!("test-audience")),
        scope: Some("typedb:read_data mcp:access".to_string()), // Escopos necessários
        custom_claim: None,
    };
    // Assumir que config.oauth.required_scopes = ["mcp:access"] (ou similar)
    let valid_token = generate_test_jwt(claims, jsonwebtoken::Algorithm::RS256, TEST_KID_RSA_GOOD, &TEST_RSA_PRIVATE_KEY_PEM_GOOD);

    let mut client = TestMcpClient::connect(MCP_SERVER_WSS_URL, Some(valid_token))
        .await
        .expect("Deveria conectar com token válido");

    let result = client.call_tool_typed("tools/list", None).await;
    assert!(result.is_ok(), "Falha ao chamar tools/list com token válido: {:?}", result.err());
    client.close().await.expect("Falha ao fechar cliente");
}

#[tokio::test]
#[serial_test::serial]
async fn test_connect_wss_oauth_enabled_wrong_issuer_fails() {
    let _docker_env = setup_test_environment("connect_wss_oauth_wrong_issuer").await;
    let now_ts = common::auth_helpers::current_timestamp_secs();
    let claims = TestClaims {
        sub: "valid_user_wrong_issuer".to_string(),
        exp: now_ts + 3600,
        iat: Some(now_ts),
        nbf: Some(now_ts),
        iss: Some("wrong-issuer".to_string()), // Issuer incorreto
        aud: Some(serde_json::json!("test-audience")),
        scope: Some("typedb:read_data mcp:access".to_string()),
        custom_claim: None,
    };
    let token_wrong_issuer = generate_test_jwt(claims, jsonwebtoken::Algorithm::RS256, TEST_KID_RSA_GOOD, &TEST_RSA_PRIVATE_KEY_PEM_GOOD);

    match TestMcpClient::connect(MCP_SERVER_WSS_URL, Some(token_wrong_issuer)).await {
        Ok(mut client) => {
            // Se a conexão for estabelecida, a primeira chamada de ferramenta deve falhar.
            let result = client.call_tool_typed("tools/list", None).await;
            assert!(matches!(result, Err(McpClientError::McpErrorResponse(ErrorData { code, .. })) if code.0 == rmcp::model::ErrorCode(-32000).0 /* AUTHENTICATION_FAILED */ ),
                "A chamada da ferramenta deveria falhar devido ao issuer incorreto, mas retornou: {:?}", result);
            client.close().await.ok();
        }
        Err(McpClientError::WebSocketError(ws_err)) => {
            // Idealmente, a conexão WebSocket já falha devido ao issuer inválido.
            tracing::info!("Conexão WebSocket falhou como esperado devido ao issuer incorreto: {}", ws_err);
            assert!(ws_err.to_string().contains("Handshake failed") || ws_err.to_string().contains("401") || ws_err.to_string().contains("Forbidden"),
                "Erro WebSocket inesperado para issuer incorreto: {}", ws_err);
        }
        Err(e) => {
            panic!("Erro inesperado ao tentar conectar com issuer incorreto: {:?}", e);
        }
    }
}

#[tokio::test]
#[serial_test::serial]
async fn test_connect_wss_oauth_enabled_wrong_audience_fails() {
    let _docker_env = setup_test_environment("connect_wss_oauth_wrong_audience").await;
    let now_ts = common::auth_helpers::current_timestamp_secs();
    let claims = TestClaims {
        sub: "valid_user_wrong_audience".to_string(),
        exp: now_ts + 3600,
        iat: Some(now_ts),
        nbf: Some(now_ts),
        iss: Some("test-issuer".to_string()),
        aud: Some(serde_json::json!("wrong-audience")), // Audience incorreta
        scope: Some("typedb:read_data mcp:access".to_string()),
        custom_claim: None,
    };
    let token_wrong_audience = generate_test_jwt(claims, jsonwebtoken::Algorithm::RS256, TEST_KID_RSA_GOOD, &TEST_RSA_PRIVATE_KEY_PEM_GOOD);

    match TestMcpClient::connect(MCP_SERVER_WSS_URL, Some(token_wrong_audience)).await {
        Ok(mut client) => {
            let result = client.call_tool_typed("tools/list", None).await;
            assert!(matches!(result, Err(McpClientError::McpErrorResponse(ErrorData { code, .. })) if code.0 == rmcp::model::ErrorCode(-32000).0 /* AUTHENTICATION_FAILED */),
                "A chamada da ferramenta deveria falhar devido à audience incorreta, mas retornou: {:?}", result);
            client.close().await.ok();
        }
        Err(McpClientError::WebSocketError(ws_err)) => {
            tracing::info!("Conexão WebSocket falhou como esperado devido à audience incorreta: {}", ws_err);
            assert!(ws_err.to_string().contains("Handshake failed") || ws_err.to_string().contains("401") || ws_err.to_string().contains("Forbidden"),
                "Erro WebSocket inesperado para audience incorreta: {}", ws_err);
        }
        Err(e) => {
            panic!("Erro inesperado ao tentar conectar com audience incorreta: {:?}", e);
        }
    }
}

// TODO: Adicionar testes para:
// - Token válido mas com escopos insuficientes para uma ferramenta específica (quando a autorização por escopo for implementada).
// - Conexão ao TypeDB via TLS (se `typedb-server-it` estiver configurado com TLS).
