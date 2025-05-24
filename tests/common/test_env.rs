// tests/common/test_env.rs

//! Define o ambiente de teste de integração completo (`TestEnvironment`).
//!
//! Esta struct e suas funções associadas são responsáveis por:
//! - Gerenciar o ciclo de vida de um ambiente Docker Compose (`DockerComposeEnv`),
//!   ativando perfis específicos para iniciar apenas os serviços necessários.
//! - Esperar pela prontidão completa dos serviços Docker ativos (MCP Server, TypeDB, Mock OAuth).
//! - Construir e fornecer URLs de serviço e clientes MCP (`TestMcpClient`) inicializados
//!   e prontos para uso nos testes de integração.

use anyhow::{Context as AnyhowContext, Result};
 // Usado nos testes unitários deste módulo.
use tracing::{error, info, warn}; // `debug` e `trace` não são mais usados diretamente aqui.

// Importa helpers e constantes do mesmo crate `common`
use super::auth_helpers::{self, JwtAuthAlgorithm};
use super::client::TestMcpClient;
use super::constants;
use super::docker_helpers::DockerComposeEnv;
// Importar a função de espera do `test_utils`
use super::test_utils::wait_for_mcp_server_ready_from_test_env;

/// Representa um ambiente de teste de integração totalmente configurado e pronto para uso.
#[derive(Debug)]
pub struct TestEnvironment {
    /// Gerenciador do ambiente Docker Compose.
    pub docker_env: DockerComposeEnv,
    /// URL WebSocket completa para o servidor MCP.
    pub mcp_ws_url: String,
    /// URL HTTP base para o servidor MCP.
    pub mcp_http_base_url: String,
    /// URL completa para o endpoint de métricas Prometheus do servidor MCP.
    pub mcp_metrics_url: String,
    /// URL HTTP base para o Mock OAuth2 Server.
    pub mock_oauth_http_url: String,
    /// Flag: servidor MCP usa TLS?
    pub is_mcp_server_tls: bool,
    /// Flag: OAuth está habilitado?
    pub is_oauth_enabled: bool,
    /// Flag: Conexão MCP Server -> TypeDB usa TLS?
    pub is_typedb_tls_connection: bool,
}

impl TestEnvironment {
    /// Configura e inicia um novo ambiente de teste de integração.
    pub async fn setup(test_name_suffix: &str, config_filename: &str) -> Result<Self> {
        info!(
            "Configurando TestEnvironment para teste '{}' com config MCP: '{}'",
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
        
        docker_env.up(config_filename, Some(active_profiles.clone()))
            .with_context(|| {
                format!(
                    "Falha ao executar 'docker compose up' para projeto '{}' com config MCP '{}' e perfis {:?}",
                    docker_env.project_name(),
                    config_filename,
                    active_profiles
                )
            })?;

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
        
        // Construir URLs ANTES de passá-las para wait_for_mcp_server_ready_from_test_env
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
        
        wait_for_mcp_server_ready_from_test_env(
            &docker_env,                  // Passa DockerComposeEnv
            &mcp_http_base_url,           // Passa a URL base HTTP/S construída
            is_mcp_server_tls,            // Flag TLS do servidor MCP
            is_oauth_enabled,             // Flag para expectativa do JWKS
            is_typedb_tls_connection,     // Flag para conexão TypeDB TLS
            constants::DEFAULT_MCP_SERVER_READY_TIMEOUT,
        )
        .await
        .with_context(|| {
            format!(
                "Serviço Typedb-MCP-Server ('{}') não ficou totalmente pronto para projeto '{}' com config MCP '{}'",
                constants::MCP_SERVER_SERVICE_NAME,
                docker_env.project_name(),
                config_filename
            )
        })?;

        let mcp_metrics_url = format!(
            "http://localhost:{}{}", 
            constants::MCP_SERVER_HOST_METRICS_PORT,
            constants::MCP_SERVER_DEFAULT_METRICS_PATH
        );
        let mock_oauth_http_url = format!("http://localhost:{}", constants::MOCK_OAUTH_HOST_PORT);

        info!(
            "TestEnvironment para projeto '{}' (config MCP: '{}', perfis ativos: {:?}) configurado com sucesso.\n  MCP WS URL: {}\n  MCP HTTP Base URL: {}\n  MCP Metrics URL: {}\n  Mock OAuth URL: {}",
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
    
    /// Conecta-se ao servidor MCP e inicializa uma sessão, opcionalmente com autenticação.
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
                      self.determine_config_filename_from_flags()
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
    fn drop(&mut self) {
        info!("Limpando TestEnvironment para projeto: '{}' (via Drop).", self.docker_env.project_name());
        if let Err(e) = self.docker_env.down(true) { 
            error!("Falha ao derrubar ambiente Docker Compose no drop para '{}': {}. Limpeza manual pode ser necessária.", self.docker_env.project_name(), e);
        } else {
            info!("Ambiente Docker Compose para projeto '{}' derrubado com sucesso no drop.", self.docker_env.project_name());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial; 
    use crate::common::constants; 
 // Importar Duration explicitamente para o teste

    #[tokio::test]
    #[serial]
    #[ignore] 
    async fn test_test_environment_setup_default_config() -> Result<()> {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        info!("Iniciando teste: test_test_environment_setup_default_config");
        let test_env = TestEnvironment::setup("setup_default", constants::DEFAULT_TEST_CONFIG_FILENAME).await?;
        
        assert!(!test_env.is_mcp_server_tls);
        assert!(!test_env.is_oauth_enabled);
        assert!(!test_env.is_typedb_tls_connection);
        assert!(test_env.mcp_ws_url.starts_with("ws://localhost:8788"));
        
        info!("TestEnvironment (default config) configurado com sucesso. WS URL: {}", test_env.mcp_ws_url);
        Ok(())
    }

    #[tokio::test]
    #[serial]
    #[ignore] 
    async fn test_test_environment_setup_oauth_config() -> Result<()> {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        info!("Iniciando teste: test_test_environment_setup_oauth_config");
        let test_env = TestEnvironment::setup("setup_oauth", constants::OAUTH_ENABLED_TEST_CONFIG_FILENAME).await?;
        
        assert!(!test_env.is_mcp_server_tls);
        assert!(test_env.is_oauth_enabled); 
        assert!(!test_env.is_typedb_tls_connection);
        assert!(test_env.mcp_ws_url.starts_with("ws://localhost:8788")); 
        
        info!("TestEnvironment (OAuth config) configurado com sucesso. OAuth habilitado: {}", test_env.is_oauth_enabled);
        Ok(())
    }

    #[tokio::test]
    #[serial]
    #[ignore]
    async fn test_test_environment_setup_server_tls_config() -> Result<()> {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        info!("Iniciando teste: test_test_environment_setup_server_tls_config");
        let test_env = TestEnvironment::setup("setup_servertls", constants::SERVER_TLS_TEST_CONFIG_FILENAME).await?;
        
        assert!(test_env.is_mcp_server_tls); 
        assert!(!test_env.is_oauth_enabled);
        assert!(!test_env.is_typedb_tls_connection);
        assert!(test_env.mcp_ws_url.starts_with("wss://localhost:8444")); 
        
        info!("TestEnvironment (Server TLS config) configurado com sucesso. MCP Server TLS: {}", test_env.is_mcp_server_tls);
        Ok(())
    }

    #[tokio::test]
    #[serial]
    #[ignore]
    async fn test_test_environment_setup_typedb_tls_config() -> Result<()> {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        info!("Iniciando teste: test_test_environment_setup_typedb_tls_config");
        let test_env = TestEnvironment::setup("setup_typedbtls", constants::TYPEDB_TLS_CONNECTION_TEST_CONFIG_FILENAME).await?;
        
        assert!(!test_env.is_mcp_server_tls);
        assert!(!test_env.is_oauth_enabled);
        assert!(test_env.is_typedb_tls_connection); 
        assert!(test_env.mcp_ws_url.starts_with("ws://localhost:8788"));
        
        info!("TestEnvironment (TypeDB TLS config) configurado com sucesso. TypeDB TLS Connection: {}", test_env.is_typedb_tls_connection);
        Ok(())
    }
}