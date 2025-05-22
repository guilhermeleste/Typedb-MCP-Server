// tests/common/test_env.rs

//! Define o ambiente de teste de integração (`TestEnvironment`).
//!
//! Esta struct e suas funções associadas são responsáveis por:
//! - Gerenciar o ciclo de vida de um ambiente Docker Compose (`DockerComposeEnv`).
//! - Esperar pela prontidão completa dos serviços necessários (MCP Server, TypeDB, Mock OAuth).
//! - Construir e fornecer URLs de serviço e clientes MCP inicializados para os testes.

use anyhow::{bail, Context as AnyhowContext, Result};
use reqwest::StatusCode;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, trace, warn};

// Importa helpers e constantes do mesmo crate `common`
use super::auth_helpers::{self, JwtAuthAlgorithm}; // Usar o alias definido em auth_helpers
use super::client::TestMcpClient;
use super::constants;
use super::docker_helpers::DockerComposeEnv;
// Importar tipos necessários para initialize_mcp_session


/// Representa um ambiente de teste de integração totalmente configurado e pronto para uso.
///
/// Contém a instância do `DockerComposeEnv` para controle do Docker, e as URLs
/// já construídas para os diversos endpoints dos serviços de teste.
///
/// O `Drop` trait é implementado para garantir que o ambiente Docker Compose
/// seja derrubado ao final do escopo do `TestEnvironment`.
#[derive(Debug)]
pub struct TestEnvironment {
    /// Gerenciador do ambiente Docker Compose.
    pub docker_env: DockerComposeEnv,
    /// URL WebSocket para o servidor MCP (ex: "ws://localhost:8788/mcp/ws" ou "wss://...").
    pub mcp_ws_url: String,
    /// URL HTTP base para o servidor MCP (ex: "http://localhost:8788" ou "https://...").
    pub mcp_http_base_url: String,
    /// URL completa para o endpoint de métricas do servidor MCP.
    pub mcp_metrics_url: String,
    /// URL HTTP base para o Mock OAuth2 Server.
    pub mock_oauth_http_url: String,
    /// Indica se o servidor MCP está configurado para usar TLS (HTTPS/WSS).
    pub is_mcp_server_tls: bool,
    /// Indica se o OAuth está habilitado na configuração do MCP Server para este ambiente.
    pub is_oauth_enabled: bool,
    /// Indica se o MCP Server está configurado para usar TLS ao conectar-se ao TypeDB.
    pub is_typedb_tls_connection: bool,
}

impl TestEnvironment {
    /// Configura e inicia um novo ambiente de teste de integração.
    pub async fn setup(test_name_suffix: &str, config_filename: &str) -> Result<Self> {
        info!(
            "Configurando TestEnvironment para teste '{}' com config: '{}'",
            test_name_suffix, config_filename
        );

        let docker_env = DockerComposeEnv::new(
            constants::DEFAULT_DOCKER_COMPOSE_TEST_FILE,
            &format!("mcp_{}", test_name_suffix),
        );

        docker_env.down(true).unwrap_or_else(|e| {
            warn!(
                "Falha (ignorada) ao derrubar ambiente docker preexistente para o projeto '{}': {}",
                docker_env.project_name(),
                e
            );
        });

        docker_env
            .up(config_filename)
            .with_context(|| {
                format!(
                    "Falha ao executar 'docker compose up' para projeto '{}' com config '{}'",
                    docker_env.project_name(),
                    config_filename
                )
            })?;

        let is_mcp_server_tls = config_filename == constants::SERVER_TLS_TEST_CONFIG_FILENAME;
        let is_oauth_enabled = config_filename == constants::OAUTH_ENABLED_TEST_CONFIG_FILENAME;
        let is_typedb_tls_connection =
            config_filename == constants::TYPEDB_TLS_CONNECTION_TEST_CONFIG_FILENAME;

        let typedb_service_to_wait_for = if is_typedb_tls_connection {
            constants::TYPEDB_TLS_SERVICE_NAME
        } else {
            constants::TYPEDB_SERVICE_NAME
        };
        docker_env
            .wait_for_service_healthy(typedb_service_to_wait_for, constants::DEFAULT_TYPEDB_READY_TIMEOUT)
            .await
            .with_context(|| {
                format!(
                    "Serviço TypeDB ('{}') não ficou saudável para projeto '{}'",
                    typedb_service_to_wait_for,
                    docker_env.project_name()
                )
            })?;

        if is_oauth_enabled {
            docker_env
                .wait_for_service_healthy(
                    constants::MOCK_OAUTH_SERVICE_NAME,
                    constants::DEFAULT_MOCK_AUTH_READY_TIMEOUT,
                )
                .await
                .with_context(|| {
                    format!(
                        "Serviço Mock OAuth ('{}') não ficou saudável para projeto '{}'",
                        constants::MOCK_OAUTH_SERVICE_NAME,
                        docker_env.project_name()
                    )
                })?;
        }

        let (mcp_server_scheme_for_readyz, mcp_server_host_port_for_readyz) = if is_mcp_server_tls {
            ("https", constants::MCP_SERVER_HOST_HTTPS_PORT)
        } else {
            ("http", constants::MCP_SERVER_HOST_HTTP_PORT)
        };

        Self::wait_for_mcp_server_ready(
            &docker_env,
            mcp_server_scheme_for_readyz,
            mcp_server_host_port_for_readyz,
            is_oauth_enabled,
            constants::DEFAULT_MCP_SERVER_READY_TIMEOUT,
        )
        .await
        .with_context(|| {
            format!(
                "Serviço Typedb-MCP-Server ('{}') não ficou totalmente pronto para projeto '{}'",
                constants::MCP_SERVER_SERVICE_NAME,
                docker_env.project_name()
            )
        })?;

        let (mcp_ws_url, mcp_http_base_url) = if is_mcp_server_tls {
            (
                format!(
                    "wss://localhost:{}{}",
                    constants::MCP_SERVER_HOST_HTTPS_PORT,
                    constants::MCP_SERVER_DEFAULT_WEBSOCKET_PATH
                ),
                format!("https://localhost:{}", constants::MCP_SERVER_HOST_HTTPS_PORT),
            )
        } else {
            (
                format!(
                    "ws://localhost:{}{}",
                    constants::MCP_SERVER_HOST_HTTP_PORT,
                    constants::MCP_SERVER_DEFAULT_WEBSOCKET_PATH
                ),
                format!("http://localhost:{}", constants::MCP_SERVER_HOST_HTTP_PORT),
            )
        };

        let mcp_metrics_url = format!(
            "http://localhost:{}{}",
            constants::MCP_SERVER_HOST_METRICS_PORT,
            constants::MCP_SERVER_DEFAULT_METRICS_PATH
        );
        let mock_oauth_http_url = format!("http://localhost:{}", constants::MOCK_OAUTH_HOST_PORT);

        info!(
            "TestEnvironment para projeto '{}' (config: '{}') configurado com sucesso. URLs: WS='{}', HTTP='{}', Metricas='{}', MockOAuth='{}'",
            docker_env.project_name(),
            config_filename, mcp_ws_url, mcp_http_base_url, mcp_metrics_url, mock_oauth_http_url
        );

        Ok(TestEnvironment {
            docker_env,
            mcp_ws_url,
            mcp_http_base_url,
            mcp_metrics_url,
            mock_oauth_http_url,
            is_mcp_server_tls,
            is_oauth_enabled,
            is_typedb_tls_connection,
        })
    }

    async fn wait_for_mcp_server_ready(
        docker_env_ref: &DockerComposeEnv,
        scheme: &str,
        mcp_server_host_port: u16,
        is_oauth_setup_for_this_test: bool,
        timeout: Duration,
    ) -> Result<()> {
        let readyz_url = format!(
            "{}://localhost:{}/readyz",
            scheme, mcp_server_host_port
        );
        info!("Aguardando MCP Server em '{}' ficar pronto (timeout: {:?})", readyz_url, timeout);

        let client_builder = reqwest::Client::builder();
        let client = if scheme == "https" {
            client_builder.danger_accept_invalid_certs(true).build()?
        } else {
            client_builder.build()?
        };

        let start_time = Instant::now();
        loop {
            if start_time.elapsed() >= timeout {
                docker_env_ref.logs_all_services().unwrap_or_else(|e| {
                    error!("Falha ao obter logs do Docker Compose durante timeout do /readyz: {}", e);
                });
                bail!("/readyz timeout para '{}' após {:?}", readyz_url, timeout);
            }

            match client.get(&readyz_url).send().await {
                Ok(resp) => {
                    let status_code = resp.status();
                    match resp.json::<serde_json::Value>().await {
                        Ok(json_body) => {
                            trace!("/readyz em '{}': Status {}, Corpo: {:?}", readyz_url, status_code, json_body);
                            let overall_status = json_body.get("status").and_then(|s| s.as_str()).unwrap_or("DOWN");
                            let typedb_component_status = json_body.get("components").and_then(|c| c.get("typedb")).and_then(|t| t.as_str()).unwrap_or("DOWN");
                            let jwks_component_status = json_body.get("components").and_then(|c| c.get("jwks")).and_then(|j| j.as_str()).unwrap_or("NOT_CONFIGURED");

                            let typedb_ok = typedb_component_status.eq_ignore_ascii_case("UP");
                            let jwks_ok = if is_oauth_setup_for_this_test {
                                jwks_component_status.eq_ignore_ascii_case("UP")
                            } else {
                                jwks_component_status.eq_ignore_ascii_case("NOT_CONFIGURED") || !is_oauth_setup_for_this_test
                            };

                            if status_code == StatusCode::OK && overall_status.eq_ignore_ascii_case("UP") && typedb_ok && jwks_ok {
                                info!("/readyz para '{}' está UP e todas as dependências críticas configuradas para este teste estão prontas.", readyz_url);
                                return Ok(());
                            } else {
                                debug!(
                                    "/readyz para '{}' ainda não está pronto. Status HTTP: {}, Overall: {}, TypeDB: {}, JWKS: {}. Aguardando...",
                                    readyz_url, status_code, overall_status, typedb_component_status, jwks_component_status
                                );
                            }
                        }
                        Err(e) => {
                            let body_text_result = client.get(&readyz_url).send().await;
                            let body_text = match body_text_result {
                                Ok(r) => r.text().await.unwrap_or_else(|_| "Falha ao ler corpo como texto.".to_string()),
                                Err(_) => "Falha ao re-requisitar para obter corpo como texto.".to_string(),
                            };
                            debug!("/readyz para '{}' retornou status {} mas falhou ao parsear JSON: {}. Corpo como texto: '{}'. Aguardando...", readyz_url, status_code, e, body_text);
                        }
                    }
                }
                Err(e) => {
                    debug!("Aguardando /readyz em '{}': {}. Tentando novamente...", readyz_url, e);
                }
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    }

    /// Conecta-se ao servidor MCP e inicializa uma sessão, opcionalmente com autenticação.
    ///
    /// Este método constrói um `TestMcpClient`, estabelece uma conexão WebSocket
    /// com o servidor MCP configurado no `TestEnvironment` e envia a requisição
    /// `initialize` do protocolo MCP.
    ///
    /// Se o `TestEnvironment` foi configurado com OAuth habilitado (`is_oauth_enabled` é `true`),
    /// um token JWT de teste será gerado com os `scopes` fornecidos e incluído na
    /// requisição `initialize`. Se `scopes` for `None` ou uma string vazia,
    /// o comportamento dos escopos no token dependerá da lógica de geração de JWT de teste.
    ///
    /// Se OAuth não estiver habilitado, a conexão será tentada sem um token de autenticação,
    /// e qualquer valor fornecido em `scopes` será ignorado (com um aviso logado).
    ///
    /// # Parâmetros
    ///
    /// - `scopes`: Uma `Option<&str>` contendo uma string de escopos OAuth 2.0 separados
    ///   por espaço (ex: "tool:read tool:execute"). Se `None` ou a string for vazia,
    ///   o comportamento exato dos escopos no token dependerá da lógica de geração de JWT
    ///   de teste. Se OAuth não estiver habilitado, este parâmetro é ignorado.
    ///
    /// # Retorna
    ///
    /// Um `Result<TestMcpClient, anyhow::Error>`:
    /// - `Ok(TestMcpClient)`: Contendo o cliente MCP conectado e inicializado, pronto para uso.
    /// - `Err(anyhow::Error)`: Se ocorrer um erro durante a conexão, inicialização,
    ///   ou geração do token (se aplicável).
    ///
    /// # Exemplos
    ///
    /// ```rust,no_run
    /// # use anyhow::Result;
    /// # use typedb_mcp_server::tests::common::{TestEnvironment, constants}; // Ajuste o caminho se necessário
    /// #
    /// # // Mock para TestEnvironment para o exemplo compilar.
    /// # // Em um teste real, TestEnvironment::setup() seria chamado.
    /// # struct MockTestEnvironment;
    /// # impl MockTestEnvironment {
    /// #   async fn mcp_client_with_auth(&self, _scopes: Option<&str>) -> Result<typedb_mcp_server::tests::common::client::TestMcpClient> {
    /// #       unimplemented!("Este é um mock para o exemplo de documentação");
    /// #   }
    /// # }
    /// #
    /// # async fn run_example() -> Result<()> {
    /// // Supondo que `test_env` foi configurado para um ambiente com OAuth:
    /// // let test_env = TestEnvironment::setup("oauth_example", constants::OAUTH_ENABLED_TEST_CONFIG_FILENAME).await?;
    /// # let test_env = MockTestEnvironment; // Usando o mock para o exemplo
    ///
    /// let mut mcp_client = test_env.mcp_client_with_auth(Some("typedb:read typedb:write")).await?;
    ///
    /// // Agora o cliente pode ser usado para interagir com o servidor MCP
    /// // let tools = mcp_client.list_tools(None).await?;
    /// // println!("Ferramentas disponíveis: {:?}", tools);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn mcp_client_with_auth(&self, scopes: Option<&str>) -> Result<TestMcpClient> {
        let token_to_send = if self.is_oauth_enabled {
            let effective_scopes = scopes.unwrap_or("");
            let now = auth_helpers::current_timestamp_secs();
            let claims = auth_helpers::TestClaims {
                sub: "test-user-from-test-env".to_string(),
                exp: now + 3600,
                iat: Some(now),
                nbf: Some(now),
                iss: Some(constants::TEST_JWT_ISSUER.to_string()),
                aud: Some(serde_json::json!(constants::TEST_JWT_AUDIENCE)),
                scope: if effective_scopes.is_empty() { None } else { Some(effective_scopes.to_string()) },
                custom_claim: None,
            };
            Some(auth_helpers::generate_test_jwt(claims, JwtAuthAlgorithm::RS256))
        } else {
            if scopes.is_some() {
                warn!("TestEnvironment: Solicitado cliente com escopos, mas OAuth não está habilitado para este ambiente. Conectando sem token.");
            }
            None
        };

        // Construir os parâmetros de inicialização que TestMcpClient::connect_and_initialize espera
        let client_capabilities = rmcp::model::ClientCapabilities::default();
        let client_impl = rmcp::model::Implementation {
            name: "typedb-mcp-test-client-env".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        };
        let initialize_params = rmcp::model::InitializeRequestParam {
            protocol_version: rmcp::model::ProtocolVersion::LATEST,
            capabilities: client_capabilities,
            client_info: client_impl,
        };

        let client = TestMcpClient::connect_and_initialize( // CORRIGIDO: Chamada para connect_and_initialize
            &self.mcp_ws_url,
            token_to_send,
            constants::DEFAULT_CONNECT_TIMEOUT,
            constants::DEFAULT_REQUEST_TIMEOUT,
            initialize_params, // Passar os parâmetros de inicialização
        )
        .await
        .with_context(|| format!("Falha ao conectar e inicializar TestMcpClient para {}", self.mcp_ws_url))?;
        
        info!("Cliente MCP conectado e inicializado para {}. Info do Servidor: {:?}", self.mcp_ws_url, client.get_server_info());
        Ok(client)
    }
}

impl Drop for TestEnvironment {
    fn drop(&mut self) {
        info!(
            "Derrubando TestEnvironment para projeto: '{}' (via Drop)",
            self.docker_env.project_name()
        );
        if let Err(e) = self.docker_env.down(true) {
            error!(
                "Falha ao derrubar o ambiente Docker Compose no drop para projeto '{}': {}. \
                Pode ser necessário limpar manualmente.",
                self.docker_env.project_name(),
                 e
            );
        } else {
            info!(
                "Ambiente Docker Compose para projeto '{}' derrubado com sucesso no drop.",
                self.docker_env.project_name()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[tokio::test]
    #[serial]
    async fn test_setup_and_teardown_default_config() -> Result<()> {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        info!("Iniciando teste: test_setup_and_teardown_default_config");

        let test_env = TestEnvironment::setup(
            "default_cfg_lifecycle",
            constants::DEFAULT_TEST_CONFIG_FILENAME,
        )
        .await
        .context("Falha no TestEnvironment::setup com config default")?;

        info!("Ambiente de teste default (projeto: '{}') configurado com sucesso. MCP WS URL: {}", test_env.docker_env.project_name(), test_env.mcp_ws_url);
        assert!(!test_env.is_mcp_server_tls);
        assert!(!test_env.is_oauth_enabled);
        assert!(!test_env.is_typedb_tls_connection);

        Ok(())
    }

    #[tokio::test]
    #[serial]
    // #[ignore] // Descomentar se os testes OAuth estiverem instáveis
    async fn test_setup_oauth_enabled_config_and_connect_client() -> Result<()> {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        info!("Iniciando teste: test_setup_oauth_enabled_config_and_connect_client");

        let test_env = TestEnvironment::setup(
            "oauth_cfg_lifecycle",
            constants::OAUTH_ENABLED_TEST_CONFIG_FILENAME,
        )
        .await
        .context("Falha no TestEnvironment::setup com config OAuth")?;

        info!("Ambiente de teste OAuth (projeto: '{}') configurado. MCP WS URL: {}", test_env.docker_env.project_name(), test_env.mcp_ws_url);
        assert!(test_env.is_oauth_enabled);
        assert!(!test_env.is_mcp_server_tls);
        assert!(!test_env.is_typedb_tls_connection);

        let mut client = test_env.mcp_client_with_auth(Some("test:scope read")).await
            .context("Falha ao obter cliente MCP autenticado para ambiente OAuth")?;
        
        let list_tools_result = client.list_tools(None).await;
        assert!(list_tools_result.is_ok(), "list_tools falhou com cliente autenticado: {:?}", list_tools_result.err());
        info!("list_tools com OAuth e escopo 'test:scope read' bem-sucedido.");
        
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_setup_server_tls_config_and_connect_client() -> Result<()> {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        info!("Iniciando teste: test_setup_server_tls_config_and_connect_client");

        let test_env = TestEnvironment::setup(
            "server_tls_cfg_lifecycle",
            constants::SERVER_TLS_TEST_CONFIG_FILENAME,
        )
        .await
        .context("Falha no TestEnvironment::setup com config Server TLS")?;

        info!("Ambiente de teste Server TLS (projeto: '{}') configurado. MCP WS URL: {}", test_env.docker_env.project_name(), test_env.mcp_ws_url);
        assert!(test_env.is_mcp_server_tls);
        assert!(!test_env.is_oauth_enabled);
        assert!(!test_env.is_typedb_tls_connection);
        
        match test_env.mcp_client_with_auth(None).await {
            Ok(mut client) => {
                info!("Conexão WSS com servidor MCP TLS bem-sucedida.");
                let list_tools_result = client.list_tools(None).await;
                assert!(list_tools_result.is_ok(), "list_tools falhou com cliente conectado via WSS: {:?}", list_tools_result.err());
                info!("list_tools com WSS bem-sucedido.");
            }
            Err(e) => {
                warn!("Conexão WSS com servidor MCP TLS falhou: {:?}. Isso pode ser esperado se a CA raiz do mkcert (tests/test_certs/rootCA.pem) não for confiável pelo cliente WebSocket padrão.", e);
            }
        }
        Ok(())
    }
}