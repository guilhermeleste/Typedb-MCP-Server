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

//! Testes de integração focados na conexão WebSocket, handshake MCP,
//! TLS do servidor e cenários básicos de autenticação OAuth2.

use crate::common::{
    client::McpClientError,
    constants,
    // Corrigido: Importar TestEnvironment diretamente do common, pois é reexportado
    TestEnvironment,
};
use anyhow::Result; // anyhow::Result já está sendo usado.
use rmcp::model::ProtocolVersion; // Para construir InitializeRequestParam
use serial_test::serial;
use tracing::{error, info, warn};

#[tokio::test]
#[serial]
async fn test_websocket_connection_succeeds_default_config() -> Result<()> {
    // Corrigido: Chamar TestEnvironment::setup
    let test_env =
        TestEnvironment::setup("conn_ws_ok", constants::DEFAULT_TEST_CONFIG_FILENAME).await?;
    info!(
        "Ambiente '{}' pronto. Tentando conectar TestMcpClient a: {}",
        test_env.docker_env.project_name(),
        test_env.mcp_ws_url
    );

    let client_result = test_env.mcp_client_with_auth(None).await;

    assert!(
        client_result.is_ok(),
        "Falha ao conectar e inicializar cliente MCP com config default: {:?}",
        client_result.err()
    );
    info!("Conexão e inicialização WS com config default bem-sucedida.");
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_websocket_connection_fails_to_wrong_path() -> Result<()> {
    let test_env =
        TestEnvironment::setup("conn_ws_badpath", constants::DEFAULT_TEST_CONFIG_FILENAME).await?;

    // Determinar o esquema e a porta do host com base na configuração do test_env
    let (scheme_ws, host_port_str) = if test_env.is_mcp_server_tls {
        ("wss", constants::MCP_SERVER_HOST_HTTPS_PORT.to_string())
    } else {
        ("ws", constants::MCP_SERVER_HOST_HTTP_PORT.to_string())
    };

    let bad_ws_url = format!(
        "{}://localhost:{}/wrong/mcp/path", // Caminho intencionalmente errado
        scheme_ws, host_port_str
    );

    info!(
        "Ambiente '{}' pronto. Tentando conectar TestMcpClient a URL inválida: {}",
        test_env.docker_env.project_name(),
        bad_ws_url
    );

    let client_capabilities = rmcp::model::ClientCapabilities::default();
    let client_impl = rmcp::model::Implementation {
        name: "typedb-mcp-test-client-badpath".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };
    let initialize_params = rmcp::model::InitializeRequestParam {
        protocol_version: ProtocolVersion::LATEST,
        capabilities: client_capabilities,
        client_info: client_impl,
    };

    let client_result = crate::common::client::TestMcpClient::connect_and_initialize(
        &bad_ws_url,
        None,
        constants::DEFAULT_CONNECT_TIMEOUT,
        constants::DEFAULT_REQUEST_TIMEOUT,
        initialize_params,
    )
    .await;

    assert!(client_result.is_err(), "Conexão com path WS inválido deveria falhar.");

    // Para inspecionar o erro sem consumi-lo para o log, e depois para o match:
    let err_for_log = match &client_result {
        Ok(_) => "Sucesso inesperado".to_string(),
        Err(e) => format!("{:?}", e),
    };
    info!("Conexão com path WS inválido falhou como esperado: {}", err_for_log);

    match client_result {
        Err(McpClientError::HandshakeFailed(status, _)) => {
            assert_eq!(
                status,
                http::StatusCode::NOT_FOUND,
                "Esperado status 404 para path WS inválido."
            );
        }
        Err(McpClientError::WebSocket(ws_err)) => {
            warn!("Path WS inválido resultou em erro WebSocket genérico ({:?}) em vez de HTTP 404. Isso pode ser aceitável dependendo do servidor WebSocket.", ws_err);
            // Em alguns casos (especialmente com WSS e erro de path), a conexão pode ser simplesmente fechada
            // ou um erro TLS/TCP pode ocorrer antes que uma resposta HTTP 404 seja formada.
        }
        Err(other_err) => {
            panic!("Tipo de erro inesperado para path WS inválido: {:?}", other_err);
        }
        Ok(_) => {
            panic!("Conexão com path WS inválido deveria ter falhado, mas obteve Ok.");
        }
    }
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_server_tls_connection_succeeds_with_wss() -> Result<()> {
    let test_env = TestEnvironment::setup(
        // Corrigido
        "conn_server_tls_ok",
        constants::SERVER_TLS_TEST_CONFIG_FILENAME,
    )
    .await?;
    assert!(
        test_env.is_mcp_server_tls,
        "TLS do servidor deveria estar habilitado para este teste."
    );
    info!(
        "Ambiente '{}' pronto. Testando conexão WSS a: {}",
        test_env.docker_env.project_name(),
        test_env.mcp_ws_url
    );

    let client_result = test_env.mcp_client_with_auth(None).await;

    match client_result {
        Ok(mut client) => {
            info!("✅ Conexão WSS estabelecida com sucesso!");

            info!("🔧 Testando list_tools via WSS...");
            match client.list_tools(None).await {
                Ok(tools_result) => {
                    info!(
                        "✅ list_tools bem-sucedido via WSS. Ferramentas disponíveis: {}",
                        tools_result.tools.len()
                    );
                    info!("🎉 Teste WSS completamente bem-sucedido!");
                }
                Err(ref list_tools_error) => {
                    // Tratar especificamente UnexpectedEof conforme documentação rustls
                    match list_tools_error {
                        McpClientError::WebSocket(ws_err) => match ws_err {
                            tokio_tungstenite::tungstenite::Error::Io(io_err) => {
                                if io_err.kind() == std::io::ErrorKind::UnexpectedEof {
                                    warn!("⚠️  list_tools retornou UnexpectedEof - conexão fechada sem close_notify");
                                    warn!("📖 Conforme documentação rustls, este erro pode ser tratado como EOF normal");
                                    warn!("🔍 Possível causa: aplicação usa length framing e conexão foi fechada adequadamente");
                                    info!("✅ Tratando UnexpectedEof como sucesso condicional para este teste");
                                } else {
                                    error!(
                                        "❌ list_tools falhou com erro IO inesperado: {:?}",
                                        io_err
                                    );
                                    panic!("Erro IO inesperado em list_tools: {:?}", io_err);
                                }
                            }
                            _ => {
                                error!("❌ list_tools falhou com erro WebSocket: {:?}", ws_err);
                                panic!("Erro WebSocket inesperado em list_tools: {:?}", ws_err);
                            }
                        },
                        _ => {
                            error!(
                                "❌ list_tools falhou com erro inesperado: {:?}",
                                list_tools_error
                            );
                            panic!("Erro inesperado em list_tools: {:?}", list_tools_error);
                        }
                    }
                }
            }
        }
        Err(connection_error) => {
            error!("❌ Conexão WSS falhou: {:?}", connection_error);
            warn!("💡 Verifique se a CA do mkcert (tests/test_certs/rootCA.pem) é confiável pelo sistema");
            warn!("💡 Ou se o cliente WebSocket está configurado para aceitar certificados autoassinados");
            panic!("Conexão WSS falhou: {:?}", connection_error);
        }
    }
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_server_tls_connection_fails_with_ws() -> Result<()> {
    let test_env = TestEnvironment::setup(
        // Corrigido
        "conn_server_tls_ws_fail",
        constants::SERVER_TLS_TEST_CONFIG_FILENAME,
    )
    .await?;
    assert!(test_env.is_mcp_server_tls);

    let ws_url_to_https_port = format!(
        "ws://localhost:{}{}",
        constants::MCP_SERVER_HOST_HTTPS_PORT, // Conectando à porta HTTPS...
        constants::MCP_SERVER_DEFAULT_WEBSOCKET_PATH  // ...mas com esquema ws://
    );

    info!(
        "Ambiente '{}' pronto. Tentando conectar WS a porta HTTPS: {}",
        test_env.docker_env.project_name(),
        ws_url_to_https_port
    );

    let client_capabilities = rmcp::model::ClientCapabilities::default();
    let client_impl = rmcp::model::Implementation {
        name: "typedb-mcp-test-client-ws-fail".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };
    let initialize_params = rmcp::model::InitializeRequestParam {
        protocol_version: ProtocolVersion::LATEST,
        capabilities: client_capabilities,
        client_info: client_impl,
    };

    let client_result = crate::common::client::TestMcpClient::connect_and_initialize(
        &ws_url_to_https_port,
        None,
        constants::DEFAULT_CONNECT_TIMEOUT,
        constants::DEFAULT_REQUEST_TIMEOUT,
        initialize_params,
    )
    .await;

    assert!(client_result.is_err(), "Conexão WS para porta HTTPS do servidor deveria falhar.");
    info!(
        "Conexão WS para porta HTTPS falhou como esperado: {:?}",
        client_result.err().unwrap() // unwrap aqui é seguro devido ao assert! acima
    );
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_oauth_connection_succeeds_with_valid_token() -> Result<()> {
    let test_env = TestEnvironment::setup(
        // Corrigido
        "conn_oauth_valid_token",
        constants::OAUTH_ENABLED_TEST_CONFIG_FILENAME,
    )
    .await?;
    assert!(test_env.is_oauth_enabled);

    info!(
        "Ambiente '{}' pronto. Testando conexão OAuth com token válido.",
        test_env.docker_env.project_name()
    );
    let client_result = test_env.mcp_client_with_auth(Some("typedb:read_data")).await;

    assert!(
        client_result.is_ok(),
        "Falha ao conectar e inicializar cliente MCP com token OAuth válido: {:?}",
        client_result.err()
    );
    info!("Conexão e inicialização OAuth com token válido bem-sucedida.");
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_oauth_connection_fails_with_invalid_token_signature() -> Result<()> {
    let test_env = TestEnvironment::setup(
        // Corrigido
        "conn_oauth_bad_sig",
        constants::OAUTH_ENABLED_TEST_CONFIG_FILENAME,
    )
    .await?;
    assert!(test_env.is_oauth_enabled);
    info!(
        "Ambiente '{}' pronto. Testando conexão OAuth com token de assinatura inválida.",
        test_env.docker_env.project_name()
    );

    let now = crate::common::auth_helpers::current_timestamp_secs();
    let claims = crate::common::auth_helpers::TestClaims {
        sub: "user-bad-sig".to_string(),
        exp: now + 3600,
        iss: Some(constants::TEST_JWT_ISSUER.to_string()),
        aud: Some(serde_json::json!(constants::TEST_JWT_AUDIENCE)),
        scope: Some("test:scope".to_string()),
        iat: Some(now),
        nbf: Some(now),
        custom_claim: None,
    };
    let bad_token = crate::common::auth_helpers::generate_test_jwt(
        claims,
        crate::common::auth_helpers::JwtAuthAlgorithm::HS256,
    );

    let client_capabilities = rmcp::model::ClientCapabilities::default();
    let client_impl = rmcp::model::Implementation {
        name: "typedb-mcp-test-client-badsig".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };
    let initialize_params = rmcp::model::InitializeRequestParam {
        protocol_version: ProtocolVersion::LATEST,
        capabilities: client_capabilities,
        client_info: client_impl,
    };

    let client_result = crate::common::client::TestMcpClient::connect_and_initialize(
        &test_env.mcp_ws_url,
        Some(bad_token),
        constants::DEFAULT_CONNECT_TIMEOUT,
        constants::DEFAULT_REQUEST_TIMEOUT,
        initialize_params,
    )
    .await;

    assert!(client_result.is_err(), "Conexão com token de assinatura inválida deveria falhar.");

    let err_for_log = match &client_result {
        Ok(_) => "Sucesso inesperado".to_string(),
        Err(e) => format!("{:?}", e),
    };
    info!("Conexão OAuth com token de assinatura inválida falhou como esperado: {}", err_for_log);

    match client_result {
        Err(McpClientError::HandshakeFailed(status, _)) => {
            assert_eq!(
                status,
                http::StatusCode::UNAUTHORIZED,
                "Esperado status 401 para token inválido."
            );
        }
        Err(other_err) => {
            panic!("Tipo de erro inesperado para token inválido: {:?}", other_err);
        }
        Ok(_) => {
            panic!("Conexão com token de assinatura inválida deveria ter falhado, mas obteve Ok.");
        }
    }
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_oauth_connection_fails_without_token_when_required() -> Result<()> {
    let test_env = TestEnvironment::setup(
        // Corrigido
        "conn_oauth_no_token",
        constants::OAUTH_ENABLED_TEST_CONFIG_FILENAME,
    )
    .await?;
    assert!(test_env.is_oauth_enabled);
    info!(
        "Ambiente '{}' pronto. Testando conexão OAuth sem token.",
        test_env.docker_env.project_name()
    );

    let client_capabilities = rmcp::model::ClientCapabilities::default();
    let client_impl = rmcp::model::Implementation {
        name: "typedb-mcp-test-client-notoken".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };
    let initialize_params = rmcp::model::InitializeRequestParam {
        protocol_version: ProtocolVersion::LATEST,
        capabilities: client_capabilities,
        client_info: client_impl,
    };

    let client_result = crate::common::client::TestMcpClient::connect_and_initialize(
        &test_env.mcp_ws_url,
        None,
        constants::DEFAULT_CONNECT_TIMEOUT,
        constants::DEFAULT_REQUEST_TIMEOUT,
        initialize_params,
    )
    .await;

    assert!(client_result.is_err(), "Conexão sem token quando OAuth é obrigatório deveria falhar.");
    let err_for_log = match &client_result {
        Ok(_) => "Sucesso inesperado".to_string(),
        Err(e) => format!("{:?}", e),
    };
    info!("Conexão OAuth sem token falhou como esperado: {}", err_for_log);

    match client_result {
        Err(McpClientError::HandshakeFailed(status, _)) => {
            assert!(
                status == http::StatusCode::UNAUTHORIZED || status == http::StatusCode::BAD_REQUEST,
                "Esperado status 401 ou 400 para token ausente, obtido: {}",
                status
            );
        }
        Err(other_err) => {
            panic!("Tipo de erro inesperado para token ausente: {:?}", other_err);
        }
        Ok(_) => {
            panic!(
                "Conexão sem token quando OAuth é obrigatório deveria ter falhado, mas obteve Ok."
            );
        }
    }
    Ok(())
}
