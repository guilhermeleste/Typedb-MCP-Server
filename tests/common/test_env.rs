// tests/common/test_env.rs

//! Define o ambiente de teste de integração completo (`TestEnvironment`).
//!
//! Esta struct e suas funções associadas são responsáveis por:
//! - Gerenciar o ciclo de vida de um ambiente Docker Compose (`DockerComposeEnv`),
//!   ativando perfis específicos para iniciar apenas os serviços necessários.
//! - Esperar pela prontidão completa dos serviços Docker ativos (MCP Server, TypeDB, Mock OAuth).
//! - Construir e fornecer URLs de serviço e clientes MCP (`TestMcpClient`) inicializados
//!   e prontos para uso nos testes de integração.

use anyhow::{bail, Context as AnyhowContext, Result};
use reqwest::StatusCode;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, trace, warn};

// Importa helpers e constantes do mesmo crate `common`
use super::auth_helpers::{self, JwtAuthAlgorithm};
use super::client::TestMcpClient;
use super::constants;
use super::docker_helpers::DockerComposeEnv;


/// Representa um ambiente de teste de integração totalmente configurado e pronto para uso.
///
/// Contém a instância do `DockerComposeEnv` para controle do Docker, e as URLs
/// já construídas para os diversos endpoints dos serviços de teste.
///
/// O `Drop` trait é implementado para garantir que o ambiente Docker Compose
/// seja derrubado ao final do escopo do `TestEnvironment`, limpando os recursos.
#[derive(Debug)]
pub struct TestEnvironment {
    /// Gerenciador do ambiente Docker Compose. Permite interações como `up`, `down`, `logs`.
    pub docker_env: DockerComposeEnv,
    /// URL WebSocket completa para o servidor MCP (ex: "ws://localhost:8788/mcp/ws" ou "wss://...").
    pub mcp_ws_url: String,
    /// URL HTTP base para o servidor MCP (ex: "http://localhost:8788" ou "https://...").
    /// Usada para acessar endpoints como `/livez` e `/readyz`.
    pub mcp_http_base_url: String,
    /// URL completa para o endpoint de métricas Prometheus do servidor MCP.
    pub mcp_metrics_url: String,
    /// URL HTTP base para o Mock OAuth2 Server (usado para obter JWKS em testes OAuth).
    pub mock_oauth_http_url: String,
    /// Flag que indica se o servidor MCP está configurado para usar TLS (HTTPS/WSS) neste ambiente.
    pub is_mcp_server_tls: bool,
    /// Flag que indica se a autenticação OAuth está habilitada na configuração do MCP Server
    /// para este ambiente de teste.
    pub is_oauth_enabled: bool,
    /// Flag que indica se o MCP Server está configurado para usar TLS ao se conectar
    /// à instância do TypeDB neste ambiente.
    pub is_typedb_tls_connection: bool,
}

impl TestEnvironment {
    /// Configura e inicia um novo ambiente de teste de integração.
    ///
    /// Esta função realiza os seguintes passos:
    /// 1. Cria uma instância de `DockerComposeEnv` com um nome de projeto único.
    /// 2. Tenta derrubar qualquer ambiente Docker Compose preexistente com o mesmo nome de projeto.
    /// 3. Determina quais perfis do Docker Compose devem ser ativados com base no `config_filename`.
    ///    - Perfil `"typedb_default"`: Para TypeDB sem TLS.
    ///    - Perfil `"typedb_tls"`: Para TypeDB com TLS.
    ///    - Perfil `"oauth_mock"`: Para o mock servidor OAuth2.
    /// 4. Inicia o ambiente Docker Compose (`docker_env.up()`) com os perfis ativos e
    ///    passando o `config_filename` para o servidor MCP (via variável de ambiente
    ///    `MCP_CONFIG_PATH_FOR_TEST_CONTAINER_HOST_ENV` que o `docker-compose.test.yml` usa).
    /// 5. Espera pela prontidão (health checks Docker) dos serviços Docker que foram efetivamente iniciados
    ///    com base nos perfis.
    /// 6. Realiza uma verificação adicional do endpoint `/readyz` do servidor MCP para garantir
    ///    que ele e suas dependências internas (como conexão com TypeDB e JWKS) estejam operacionais.
    /// 7. Constrói as URLs de acesso para os serviços com base na configuração (TLS ou não).
    /// 8. Retorna uma instância de `TestEnvironment` pronta para uso.
    ///
    /// # Arguments
    /// * `test_name_suffix`: Um sufixo para o nome do teste, usado para criar um nome de projeto Docker Compose único.
    /// * `config_filename`: Nome do arquivo de configuração TOML (ex: "default.test.toml")
    ///   a ser usado pelo serviço MCP Server. Este arquivo determina o comportamento do servidor MCP
    ///   e influencia quais perfis de dependência são ativados.
    ///
    /// # Returns
    /// `Result<Self>` contendo o ambiente de teste configurado, ou um `anyhow::Error` em caso de falha.
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
                "Falha (ignorada) ao derrubar ambiente docker preexistente para o projeto '{}': {}. \
                Isso pode ser normal se for a primeira execução ou se a limpeza anterior falhou.",
                docker_env.project_name(),
                e
            );
        });

        // Determinar flags de configuração e perfis ativos
        let is_mcp_server_tls = config_filename == constants::SERVER_TLS_TEST_CONFIG_FILENAME;
        let is_oauth_enabled = config_filename == constants::OAUTH_ENABLED_TEST_CONFIG_FILENAME;
        let is_typedb_tls_connection =
            config_filename == constants::TYPEDB_TLS_CONNECTION_TEST_CONFIG_FILENAME;

        let mut active_profiles = Vec::new();
        let typedb_service_to_wait_for: &str;

        if is_typedb_tls_connection {
            active_profiles.push("typedb_tls".to_string());
            typedb_service_to_wait_for = constants::TYPEDB_TLS_SERVICE_NAME;
        } else {
            active_profiles.push("typedb_default".to_string());
            typedb_service_to_wait_for = constants::TYPEDB_SERVICE_NAME;
        }

        if is_oauth_enabled {
            active_profiles.push("oauth_mock".to_string());
        }
        // O `typedb-mcp-server-it` não precisa de um perfil explícito para ser iniciado;
        // ele será iniciado por padrão se estiver no arquivo compose base.

        // Iniciar o ambiente Docker Compose com os perfis selecionados
        docker_env.up(config_filename, Some(active_profiles.clone()))
            .with_context(|| {
                format!(
                    "Falha ao executar 'docker compose up' para projeto '{}' com config '{}' e perfis {:?}",
                    docker_env.project_name(),
                    config_filename,
                    active_profiles
                )
            })?;

        // Esperar pela prontidão dos serviços que foram efetivamente iniciados
        info!(
            "Aguardando serviço TypeDB ('{}') ficar saudável para projeto '{}'.",
            typedb_service_to_wait_for,
            docker_env.project_name()
        );
        docker_env
            .wait_for_service_healthy(
                typedb_service_to_wait_for,
                constants::DEFAULT_TYPEDB_READY_TIMEOUT,
            )
            .await
            .with_context(|| {
                format!(
                    "Serviço TypeDB ('{}') não ficou saudável para projeto '{}'",
                    typedb_service_to_wait_for,
                    docker_env.project_name()
                )
            })?;

        if active_profiles.contains(&"oauth_mock".to_string()) {
            info!(
                "Aguardando serviço Mock OAuth ('{}') ficar saudável para projeto '{}'.",
                constants::MOCK_OAUTH_SERVICE_NAME,
                docker_env.project_name()
            );
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
        
        // Determinar esquema e porta para o /readyz do MCP Server
        let (mcp_server_scheme_for_readyz, mcp_server_host_port_for_readyz) = if is_mcp_server_tls {
            ("https", constants::MCP_SERVER_HOST_HTTPS_PORT)
        } else {
            ("http", constants::MCP_SERVER_HOST_HTTP_PORT)
        };

        // Esperar pelo servidor MCP (que sempre é iniciado)
        Self::wait_for_mcp_server_ready(
            &docker_env,
            mcp_server_scheme_for_readyz,
            mcp_server_host_port_for_readyz,
            is_oauth_enabled, // Usado para checar o componente JWKS no /readyz
            is_typedb_tls_connection, // Usado para checar o componente TypeDB no /readyz
            constants::DEFAULT_MCP_SERVER_READY_TIMEOUT,
        )
        .await
        .with_context(|| {
            format!(
                "Serviço Typedb-MCP-Server ('{}') não ficou totalmente pronto para projeto '{}' com config '{}'",
                constants::MCP_SERVER_SERVICE_NAME,
                docker_env.project_name(),
                config_filename
            )
        })?;

        // Construir URLs de acesso aos serviços
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
            "TestEnvironment para projeto '{}' (config: '{}', perfis: {:?}) configurado com sucesso.\n  MCP WS URL: {}\n  MCP HTTP Base URL: {}\n  MCP Metrics URL: {}\n  Mock OAuth URL: {}",
            docker_env.project_name(),
            config_filename, active_profiles, mcp_ws_url, mcp_http_base_url, mcp_metrics_url, mock_oauth_http_url
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

    /// Aguarda até que o endpoint `/readyz` do Typedb-MCP-Server indique que o servidor
    /// e suas dependências críticas (TypeDB e JWKS, se aplicável) estão prontos.
    ///
    /// # Arguments
    /// * `docker_env_ref`: Referência ao `DockerComposeEnv` para logging em caso de timeout.
    /// * `scheme`: "http" ou "https".
    /// * `mcp_server_host_port`: A porta do host onde o servidor MCP está escutando.
    /// * `expect_jwks_up`: Se `true`, espera que o componente `jwks` no `/readyz` esteja "UP".
    ///                     Se `false`, espera que esteja "NOT_CONFIGURED" (indicando OAuth desabilitado).
    /// * `expect_typedb_tls`: Se `true`, indica que o MCP Server está configurado para usar TLS com TypeDB.
    ///                        (Atualmente, o /readyz não distingue isso, mas pode ser usado para verificações futuras).
    /// * `timeout`: A duração máxima de espera.
    async fn wait_for_mcp_server_ready(
        docker_env_ref: &DockerComposeEnv,
        scheme: &str,
        mcp_server_host_port: u16,
        expect_jwks_up: bool,
        _expect_typedb_tls: bool, // Parâmetro mantido para possível uso futuro, atualmente não afeta a lógica de /readyz
        timeout: Duration,
    ) -> Result<()> {
        let readyz_url = format!("{}://localhost:{}/readyz", scheme, mcp_server_host_port);
        info!("Aguardando MCP Server em '{}' ficar pronto (timeout: {:?}, esperar JWKS UP: {})", readyz_url, timeout, expect_jwks_up);

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
                    error!("Falha ao obter logs do Docker Compose durante timeout do /readyz para {}: {}", docker_env_ref.project_name(), e);
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
                            let typedb_comp_status = json_body.get("components").and_then(|c| c.get("typedb")).and_then(|t| t.as_str()).unwrap_or("DOWN");
                            let jwks_comp_status = json_body.get("components").and_then(|c| c.get("jwks")).and_then(|j| j.as_str()).unwrap_or("NOT_CONFIGURED");

                            let typedb_ok = typedb_comp_status.eq_ignore_ascii_case("UP");
                            let jwks_target_status_str = if expect_jwks_up { "UP" } else { "NOT_CONFIGURED" };
                            let jwks_ok = jwks_comp_status.eq_ignore_ascii_case(jwks_target_status_str);
                            
                            if status_code == StatusCode::OK && overall_status.eq_ignore_ascii_case("UP") && typedb_ok && jwks_ok {
                                info!("/readyz para '{}' está UP e todas as dependências críticas configuradas para este teste estão prontas.", readyz_url);
                                return Ok(());
                            }
                            debug!("/readyz para '{}' ainda não está pronto. HTTP: {}, Overall: {}, TypeDB: {}, JWKS: {} (esperado: {}). Aguardando...",
                                   readyz_url, status_code, overall_status, typedb_comp_status, jwks_comp_status, jwks_target_status_str);
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
            tokio::time::sleep(Duration::from_secs(2)).await;
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
    /// o token será gerado sem escopos específicos (comportamento padrão de `auth_helpers`).
    ///
    /// Se OAuth não estiver habilitado, a conexão será tentada sem um token de autenticação.
    ///
    /// # Parâmetros
    ///
    /// - `scopes`: Uma `Option<&str>` contendo uma string de escopos OAuth 2.0 separados
    ///   por espaço (ex: "tool:read tool:execute"). Se `None` ou a string for vazia,
    ///   nenhum escopo específico é solicitado/adicionado ao token de teste.
    ///
    /// # Retorna
    ///
    /// Um `Result<TestMcpClient, anyhow::Error>`:
    /// - `Ok(TestMcpClient)`: Contendo o cliente MCP conectado e inicializado, pronto para uso.
    /// - `Err(anyhow::Error)`: Se ocorrer um erro durante a conexão, inicialização,
    ///   ou geração do token (se aplicável).
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
            if scopes.is_some() && !scopes.unwrap_or("").is_empty() {
                warn!("TestEnvironment: Solicitado cliente com escopos ('{}'), mas OAuth não está habilitado para este ambiente (config: '{}'). Conectando sem token.", 
                      scopes.unwrap_or(""), 
                      self.determine_config_filename_from_flags() // Helper para obter o nome do config
                );
            }
            None
        };

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

        let client = TestMcpClient::connect_and_initialize(
            &self.mcp_ws_url,
            token_to_send,
            constants::DEFAULT_CONNECT_TIMEOUT,
            constants::DEFAULT_REQUEST_TIMEOUT,
            initialize_params,
        )
        .await
        .with_context(|| {
            format!(
                "Falha ao conectar e inicializar TestMcpClient para URL: {}. OAuth Habilitado: {}. Token com escopos ('{}') foi tentado: {}",
                self.mcp_ws_url, self.is_oauth_enabled, scopes.unwrap_or("<nenhum>"), if scopes.is_some() && self.is_oauth_enabled {"Sim"} else {"Não"}
            )
        })?;

        info!(
            "Cliente MCP conectado e inicializado para {}. Info do Servidor: {:?}",
            self.mcp_ws_url,
            client.get_server_info().map(|si| &si.server_info)
        );
        Ok(client)
    }

    /// Helper interno para determinar o nome do arquivo de configuração com base nas flags.
    /// Usado apenas para logging mais informativo.
    fn determine_config_filename_from_flags(&self) -> String {
        if self.is_typedb_tls_connection {
            constants::TYPEDB_TLS_CONNECTION_TEST_CONFIG_FILENAME.to_string()
        } else if self.is_oauth_enabled {
            constants::OAUTH_ENABLED_TEST_CONFIG_FILENAME.to_string()
        } else if self.is_mcp_server_tls {
            constants::SERVER_TLS_TEST_CONFIG_FILENAME.to_string()
        } else {
            constants::DEFAULT_TEST_CONFIG_FILENAME.to_string()
        }
    }
}

impl Drop for TestEnvironment {
    /// Garante que o ambiente Docker Compose seja derrubado quando `TestEnvironment` sai de escopo.
    fn drop(&mut self) {
        info!(
            "Derrubando TestEnvironment para projeto: '{}' (via Drop).",
            self.docker_env.project_name()
        );
        if let Err(e) = self.docker_env.down(true) { 
            error!(
                "Falha ao derrubar o ambiente Docker Compose no drop para projeto '{}': {}. \
                Pode ser necessário limpar manualmente os recursos Docker (contêineres, redes, volumes).",
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

// Testes unitários para `TestEnvironment` são limitados, pois sua principal função é orquestrar Docker.
// A validação principal ocorre nos testes de integração que usam `TestEnvironment::setup`.
#[cfg(test)]
mod tests {
    use super::*;
    // `serial_test::serial` não é necessário aqui, pois não estamos realmente manipulando Docker.

    #[test]
    fn test_url_construction_logic_no_tls_no_oauth() {
        // Este teste agora é mais conceitual, pois a construção real das URLs
        // aconteceria dentro de `TestEnvironment::setup` após obter as portas do Docker.
        // Aqui, simulamos os valores que `setup` construiria.

        // Cenário 1: Sem TLS no servidor MCP, sem OAuth, sem TypeDB TLS
        let mcp_http_port = constants::MCP_SERVER_HOST_HTTP_PORT;
        let mcp_ws_path = constants::MCP_SERVER_DEFAULT_WEBSOCKET_PATH;
        let metrics_port = constants::MCP_SERVER_HOST_METRICS_PORT;
        let metrics_path = constants::MCP_SERVER_DEFAULT_METRICS_PATH;
        let oauth_port = constants::MOCK_OAUTH_HOST_PORT;

        let expected_ws_url = format!("ws://localhost:{}{}", mcp_http_port, mcp_ws_path);
        let expected_http_base_url = format!("http://localhost:{}", mcp_http_port);
        let expected_metrics_url = format!("http://localhost:{}{}", metrics_port, metrics_path);
        let expected_oauth_url = format!("http://localhost:{}", oauth_port);

        // Verificação manual dos formatos esperados
        assert_eq!(expected_ws_url, "ws://localhost:8788/mcp/ws");
        assert_eq!(expected_http_base_url, "http://localhost:8788");
        assert_eq!(expected_metrics_url, "http://localhost:9091/metrics");
        assert_eq!(expected_oauth_url, "http://localhost:8089");
    }

    #[test]
    fn test_url_construction_logic_with_mcp_tls() {
        // Cenário 2: Com TLS no servidor MCP
        let mcp_https_port = constants::MCP_SERVER_HOST_HTTPS_PORT;
        let mcp_ws_path = constants::MCP_SERVER_DEFAULT_WEBSOCKET_PATH;
        
        let expected_wss_url = format!("wss://localhost:{}{}", mcp_https_port, mcp_ws_path);
        let expected_https_base_url = format!("https://localhost:{}", mcp_https_port);

        assert_eq!(expected_wss_url, "wss://localhost:8444/mcp/ws");
        assert_eq!(expected_https_base_url, "https://localhost:8444");
    }
}