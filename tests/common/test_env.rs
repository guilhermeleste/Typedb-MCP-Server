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
use std::time::Duration; // Adicionado para o delay
use tracing::{error, info, warn}; 

// Importa helpers e constantes do mesmo crate `common`
use super::auth_helpers::{self, JwtAuthAlgorithm};
use super::client::TestMcpClient;
use super::constants;
use super::docker_helpers::DockerComposeEnv;
// Importar a função de espera do `test_utils`
use super::test_utils::wait_for_mcp_server_ready_from_test_env;

/// Perfis Docker disponíveis para testes de integração.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TestProfile {
    /// TypeDB sem TLS (perfil "typedb_default")
    TypeDbDefault,
    /// TypeDB com TLS (perfil "typedb_tls") 
    TypeDbTls,
    /// Mock OAuth2 Server (perfil "oauth_mock")
    OAuthMock,
}

impl TestProfile {
    /// Converte o perfil para a string usada no docker-compose.
    pub fn as_compose_profile(&self) -> &'static str {
        match self {
            TestProfile::TypeDbDefault => "typedb_default",
            TestProfile::TypeDbTls => "typedb_tls", 
            TestProfile::OAuthMock => "oauth_mock",
        }
    }
    
    /// Retorna o nome do serviço TypeDB correspondente ao perfil, se aplicável.
    pub fn typedb_service_name(&self) -> Option<&'static str> {
        match self {
            TestProfile::TypeDbDefault => Some(constants::TYPEDB_SERVICE_NAME),
            TestProfile::TypeDbTls => Some(constants::TYPEDB_TLS_SERVICE_NAME),
            TestProfile::OAuthMock => None,
        }
    }
}

/// Configuração para setup do TestEnvironment com perfis explícitos.
#[derive(Debug, Clone)]
pub struct TestConfiguration {
    /// Perfis Docker a serem ativados.
    pub profiles: Vec<TestProfile>,
    /// Arquivo de configuração MCP a ser usado.
    pub config_filename: String,
    /// Se o servidor MCP deve usar TLS.
    pub mcp_server_tls: bool,
}

impl TestConfiguration {
    /// Cria uma configuração padrão (TypeDB default, sem OAuth, sem TLS).
    pub fn default(config_filename: &str) -> Self {
        Self {
            profiles: vec![TestProfile::TypeDbDefault],
            config_filename: config_filename.to_string(),
            mcp_server_tls: false,
        }
    }
    
    /// Cria uma configuração com TypeDB TLS.
    pub fn with_typedb_tls(config_filename: &str) -> Self {
        Self {
            profiles: vec![TestProfile::TypeDbTls],
            config_filename: config_filename.to_string(),
            mcp_server_tls: false,
        }
    }
    
    /// Cria uma configuração com OAuth Mock.
    pub fn with_oauth(config_filename: &str) -> Self {
        Self {
            profiles: vec![TestProfile::TypeDbDefault, TestProfile::OAuthMock],
            config_filename: config_filename.to_string(),
            mcp_server_tls: false,
        }
    }
    
    /// Cria uma configuração com servidor MCP TLS.
    pub fn with_mcp_server_tls(config_filename: &str) -> Self {
        Self {
            profiles: vec![TestProfile::TypeDbDefault],
            config_filename: config_filename.to_string(),
            mcp_server_tls: true,
        }
    }
    
    /// Cria uma configuração personalizada com perfis específicos.
    pub fn custom(profiles: Vec<TestProfile>, config_filename: &str, mcp_server_tls: bool) -> Self {
        Self {
            profiles,
            config_filename: config_filename.to_string(),
            mcp_server_tls,
        }
    }
    
    /// Adiciona um perfil à configuração.
    pub fn with_profile(mut self, profile: TestProfile) -> Self {
        if !self.profiles.contains(&profile) {
            self.profiles.push(profile);
        }
        self
    }
    
    /// Define se o servidor MCP deve usar TLS.
    pub fn with_mcp_tls(mut self, enable_tls: bool) -> Self {
        self.mcp_server_tls = enable_tls;
        self
    }
    
    /// Verifica se OAuth está habilitado (perfil OAuthMock presente).
    pub fn is_oauth_enabled(&self) -> bool {
        self.profiles.contains(&TestProfile::OAuthMock)
    }
    
    /// Verifica se TypeDB TLS está habilitado.
    pub fn is_typedb_tls_enabled(&self) -> bool {
        self.profiles.contains(&TestProfile::TypeDbTls)
    }
    
    /// Retorna o serviço TypeDB a ser aguardado baseado nos perfis.
    pub fn typedb_service_to_wait_for(&self) -> &'static str {
        if self.is_typedb_tls_enabled() {
            constants::TYPEDB_TLS_SERVICE_NAME
        } else {
            constants::TYPEDB_SERVICE_NAME
        }
    }
    
    /// Converte os perfis para strings usadas pelo docker-compose.
    pub fn as_compose_profiles(&self) -> Vec<String> {
        self.profiles.iter()
            .map(|p| p.as_compose_profile().to_string())
            .collect()
    }
}

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
    /// Configura e inicia um novo ambiente de teste de integração usando configuração explícita de perfis.
    pub async fn setup_with_profiles(test_name_suffix: &str, config: TestConfiguration) -> Result<Self> {
        info!(
            "Configurando TestEnvironment para teste '{}' com config MCP: '{}' e perfis: {:?}",
            test_name_suffix, config.config_filename, config.profiles
        );

        let docker_env = DockerComposeEnv::new(
            constants::DEFAULT_DOCKER_COMPOSE_TEST_FILE,
            &format!("mcp_{}", test_name_suffix),
        );

        // Garantir limpeza prévia
        docker_env.down(true).unwrap_or_else(|e| {
            warn!(
                "Falha (ignorada) ao derrubar ambiente docker preexistente para o projeto '{}': {}. \
                Isso pode ser normal se for a primeira execução ou se a limpeza anterior falhou.",
                docker_env.project_name(),
                e
            );
        });

        let is_mcp_server_tls = config.mcp_server_tls;
        let is_oauth_enabled = config.is_oauth_enabled();
        let is_typedb_tls_connection = config.is_typedb_tls_enabled();

        let active_profiles = config.as_compose_profiles();
        let typedb_service_to_wait_for = config.typedb_service_to_wait_for();
        
        // Não usar --wait do Docker Compose quando MCP server usar TLS, pois o healthcheck HTTP padrão falhará
        let should_wait_docker_compose_health = !is_mcp_server_tls;
        
        docker_env.up(&config.config_filename, Some(active_profiles.clone()), should_wait_docker_compose_health, is_mcp_server_tls)
            .with_context(|| {
                format!(
                    "Falha ao executar 'docker compose up' para projeto '{}' com config MCP '{}' e perfis {:?}",
                    docker_env.project_name(),
                    config.config_filename,
                    active_profiles
                )
            })?;

        // Espera pelo TypeDB primeiro, pois o MCP server sempre depende dele
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

        // Se OAuth estiver habilitado, espere pelo mock OAuth server
        if is_oauth_enabled {
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
            
            // MODIFICAÇÃO AQUI: Adicionado pequeno delay
            info!("Mock OAuth Server está 'healthy'. Adicionando pequeno delay de 2s para garantir que o Nginx sirva o JWKS.");
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        
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
        
        // Agora espera pelo MCP server, que pode depender do JWKS se OAuth estiver ativo
        wait_for_mcp_server_ready_from_test_env(
            &docker_env,
            &mcp_http_base_url,
            is_mcp_server_tls,
            is_oauth_enabled,
            is_typedb_tls_connection,
            constants::DEFAULT_MCP_SERVER_READY_TIMEOUT,
        )
        .await
        .with_context(|| {
            format!(
                "Serviço Typedb-MCP-Server ('{}') não ficou totalmente pronto para projeto '{}' com config MCP '{}'",
                constants::MCP_SERVER_SERVICE_NAME,
                docker_env.project_name(),
                config.config_filename
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
            config.config_filename, active_profiles, mcp_ws_url, mcp_http_base_url, mcp_metrics_url, mock_oauth_http_url
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

    /// Configura e inicia um novo ambiente de teste de integração (método de compatibilidade).
    /// 
    /// Este método mantém a compatibilidade com a API existente, convertendo internamente
    /// para usar o novo sistema de perfis baseado em `TestConfiguration`.
    pub async fn setup(test_name_suffix: &str, config_filename: &str) -> Result<Self> {
        let config = Self::derive_configuration_from_filename(config_filename);
        Self::setup_with_profiles(test_name_suffix, config).await
    }

    /// Deriva uma configuração baseada no nome do arquivo (para compatibilidade).
    fn derive_configuration_from_filename(config_filename: &str) -> TestConfiguration {
        if config_filename == constants::SERVER_TLS_TEST_CONFIG_FILENAME {
            TestConfiguration::with_mcp_server_tls(config_filename)
        } else if config_filename == constants::OAUTH_ENABLED_TEST_CONFIG_FILENAME {
            TestConfiguration::with_oauth(config_filename)
        } else if config_filename == constants::TYPEDB_TLS_CONNECTION_TEST_CONFIG_FILENAME {
            TestConfiguration::with_typedb_tls(config_filename)
        } else {
            TestConfiguration::default(config_filename)
        }
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
                      scopes.unwrap_or("<nenhum>"), 
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

    // === Testes da nova API de perfis (Fase 3) ===

    #[tokio::test]
    #[serial]
    #[ignore]
    async fn test_setup_with_custom_profiles_default() -> Result<()> {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        info!("🧪 Iniciando teste: test_setup_with_custom_profiles_default");

        let config = TestConfiguration::default(constants::DEFAULT_TEST_CONFIG_FILENAME);
        let test_env = TestEnvironment::setup_with_profiles("profiles_default", config).await?;
        
        assert!(!test_env.is_mcp_server_tls);
        assert!(!test_env.is_oauth_enabled);
        assert!(!test_env.is_typedb_tls_connection);
        assert!(test_env.mcp_ws_url.starts_with("ws://localhost:8788"));
        
        info!("✅ TestEnvironment com perfil padrão configurado com sucesso");
        Ok(())
    }

    #[tokio::test]
    #[serial]
    #[ignore]
    async fn test_setup_with_custom_profiles_oauth() -> Result<()> {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        info!("🧪 Iniciando teste: test_setup_with_custom_profiles_oauth");

        let config = TestConfiguration::with_oauth(constants::OAUTH_ENABLED_TEST_CONFIG_FILENAME);
        let test_env = TestEnvironment::setup_with_profiles("profiles_oauth", config).await?;
        
        assert!(!test_env.is_mcp_server_tls);
        assert!(test_env.is_oauth_enabled);
        assert!(!test_env.is_typedb_tls_connection);
        assert!(test_env.mcp_ws_url.starts_with("ws://localhost:8788"));
        
        info!("✅ TestEnvironment com OAuth Mock configurado com sucesso");
        Ok(())
    }

    #[tokio::test]
    #[serial]
    #[ignore]
    async fn test_setup_with_custom_profiles_typedb_tls() -> Result<()> {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        info!("🧪 Iniciando teste: test_setup_with_custom_profiles_typedb_tls");

        let config = TestConfiguration::with_typedb_tls(constants::TYPEDB_TLS_CONNECTION_TEST_CONFIG_FILENAME);
        let test_env = TestEnvironment::setup_with_profiles("profiles_typedb_tls", config).await?;
        
        assert!(!test_env.is_mcp_server_tls);
        assert!(!test_env.is_oauth_enabled);
        assert!(test_env.is_typedb_tls_connection);
        assert!(test_env.mcp_ws_url.starts_with("ws://localhost:8788"));
        
        info!("✅ TestEnvironment com TypeDB TLS configurado com sucesso");
        Ok(())
    }

    #[tokio::test]
    #[serial]
    #[ignore]
    async fn test_setup_with_custom_profiles_combined() -> Result<()> {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        info!("🧪 Iniciando teste: test_setup_with_custom_profiles_combined");

        // Configuração personalizada: TypeDB TLS + OAuth Mock + MCP Server TLS
        let config = TestConfiguration::custom(
            vec![TestProfile::TypeDbTls, TestProfile::OAuthMock],
            constants::OAUTH_ENABLED_TEST_CONFIG_FILENAME, // Ajuste o nome do arquivo conforme necessário para esta combinação
            true, // MCP Server TLS
        );
        
        let test_env = TestEnvironment::setup_with_profiles("profiles_combined", config).await?;
        
        assert!(test_env.is_mcp_server_tls);
        assert!(test_env.is_oauth_enabled);
        assert!(test_env.is_typedb_tls_connection);
        assert!(test_env.mcp_ws_url.starts_with("wss://localhost:8444"));
        
        info!("✅ TestEnvironment com perfis combinados configurado com sucesso");
        Ok(())
    }

    #[tokio::test]
    #[serial]
    #[ignore]
    async fn test_setup_with_fluent_api() -> Result<()> {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        info!("🧪 Iniciando teste: test_setup_with_fluent_api");

        // Usando API fluente para construir configuração
        let config = TestConfiguration::default(constants::DEFAULT_TEST_CONFIG_FILENAME)
            .with_profile(TestProfile::OAuthMock)
            .with_mcp_tls(false); // MCP server TLS desabilitado
        
        let test_env = TestEnvironment::setup_with_profiles("profiles_fluent", config).await?;
        
        assert!(!test_env.is_mcp_server_tls);
        assert!(test_env.is_oauth_enabled);
        assert!(!test_env.is_typedb_tls_connection); // TypeDB TLS não foi adicionado
        assert!(test_env.mcp_ws_url.starts_with("ws://localhost:8788"));
        
        info!("✅ TestEnvironment com API fluente configurado com sucesso");
        Ok(())
    }

    #[test]
    fn test_profile_conversions() {
        // Testa conversões de perfis
        assert_eq!(TestProfile::TypeDbDefault.as_compose_profile(), "typedb_default");
        assert_eq!(TestProfile::TypeDbTls.as_compose_profile(), "typedb_tls");
        assert_eq!(TestProfile::OAuthMock.as_compose_profile(), "oauth_mock");
        
        // Testa nomes de serviços TypeDB
        assert_eq!(TestProfile::TypeDbDefault.typedb_service_name(), Some(constants::TYPEDB_SERVICE_NAME));
        assert_eq!(TestProfile::TypeDbTls.typedb_service_name(), Some(constants::TYPEDB_TLS_SERVICE_NAME));
        assert_eq!(TestProfile::OAuthMock.typedb_service_name(), None);
    }

    #[test]
    fn test_configuration_helpers() {
        // Testa criação de configurações
        let default_config = TestConfiguration::default("test.toml");
        assert!(!default_config.is_oauth_enabled());
        assert!(!default_config.is_typedb_tls_enabled());
        assert!(!default_config.mcp_server_tls);
        assert_eq!(default_config.profiles, vec![TestProfile::TypeDbDefault]);
        
        let oauth_config = TestConfiguration::with_oauth("oauth.toml");
        assert!(oauth_config.is_oauth_enabled());
        assert!(!oauth_config.is_typedb_tls_enabled());
        assert_eq!(oauth_config.profiles, vec![TestProfile::TypeDbDefault, TestProfile::OAuthMock]);
        
        let tls_config = TestConfiguration::with_typedb_tls("tls.toml");
        assert!(!tls_config.is_oauth_enabled());
        assert!(tls_config.is_typedb_tls_enabled());
        assert_eq!(tls_config.profiles, vec![TestProfile::TypeDbTls]);
        
        // Testa conversão para profiles do compose
        let combined_config = TestConfiguration::custom(
            vec![TestProfile::TypeDbTls, TestProfile::OAuthMock],
            "combined.toml",
            true
        );
        let compose_profiles = combined_config.as_compose_profiles();
        assert_eq!(compose_profiles, vec!["typedb_tls", "oauth_mock"]);
        assert_eq!(combined_config.typedb_service_to_wait_for(), constants::TYPEDB_TLS_SERVICE_NAME);
    }
}