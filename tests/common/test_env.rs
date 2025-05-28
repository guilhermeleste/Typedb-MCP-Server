// tests/common/test_env.rs

//! Define o ambiente de teste de integração completo (`TestEnvironment`).
//!
//! Esta struct e suas funções associadas são responsáveis por:
//! - Gerenciar o ciclo de vida de um ambiente Docker Compose (`DockerComposeEnv`),
//!   ativando perfis específicos para iniciar apenas os serviços necessários.
//! - Esperar pela prontidão completa dos serviços Docker ativos (MCP Server, TypeDB, Mock OAuth).
//! - Construir e fornecer URLs de serviço e clientes MCP (`TestMcpClient`) inicializados
//!   e prontos para uso nos testes de integração.
//! - Lidar com a inicialização de provedores criptográficos para `rustls` quando necessário.

use anyhow::{Context as AnyhowContext, Result};
use rustls::crypto::CryptoProvider; // Adicionado para inicialização do provedor criptográfico
use std::time::Duration;
use tracing::{error, info, warn};

// Importa helpers e constantes do mesmo crate `common`
use super::auth_helpers::{self, JwtAuthAlgorithm};
use super::client::TestMcpClient;
use super::constants;
use super::docker_helpers::DockerComposeEnv;
// Importar a função de espera do `test_utils`
use super::test_utils::wait_for_mcp_server_ready_from_test_env;

/// Perfis Docker disponíveis para testes de integração.
/// Cada perfil ativa um conjunto específico de serviços no `docker-compose.test.yml`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TestProfile {
    /// Ativa o serviço TypeDB padrão (sem TLS). Perfil: "typedb_default".
    TypeDbDefault,
    /// Ativa o serviço TypeDB configurado com TLS. Perfil: "typedb_tls".
    TypeDbTls,
    /// Ativa o serviço Mock OAuth2 Server. Perfil: "oauth_mock".
    OAuthMock,
}

impl TestProfile {
    /// Converte o enum `TestProfile` para a string de perfil usada no Docker Compose.
    pub fn as_compose_profile(&self) -> &'static str {
        match self {
            TestProfile::TypeDbDefault => "typedb_default",
            TestProfile::TypeDbTls => "typedb_tls",
            TestProfile::OAuthMock => "oauth_mock",
        }
    }

    /// Retorna o nome do serviço TypeDB correspondente ao perfil, se aplicável.
    /// Usado para saber qual serviço TypeDB aguardar no `wait_for_service_healthy`.
    pub fn typedb_service_name(&self) -> Option<&'static str> {
        match self {
            TestProfile::TypeDbDefault => Some(constants::TYPEDB_SERVICE_NAME),
            TestProfile::TypeDbTls => Some(constants::TYPEDB_TLS_SERVICE_NAME),
            TestProfile::OAuthMock => {
                // OAuthMock por si só não implica um serviço TypeDB específico,
                // geralmente é combinado com TypeDbDefault.
                None
            }
        }
    }
}

/// Configuração para o setup do `TestEnvironment`.
///
/// Permite especificar os perfis Docker a serem ativados, o arquivo de configuração
/// TOML para o servidor MCP, e se o próprio servidor MCP deve usar TLS.
#[derive(Debug, Clone)]
pub struct TestConfiguration {
    /// Perfis Docker a serem ativados para este ambiente de teste.
    pub profiles: Vec<TestProfile>,
    /// Nome do arquivo de configuração TOML (localizado em `tests/test_configs/`)
    /// a ser usado pelo servidor MCP.
    pub config_filename: String,
    /// Indica se o servidor MCP deve ser configurado para usar TLS (HTTPS/WSS).
    pub mcp_server_tls: bool,
}

impl TestConfiguration {
    /// Cria uma configuração padrão: usa o perfil `TypeDbDefault`, o arquivo de configuração
    /// especificado, e o servidor MCP não usa TLS.
    pub fn default(config_filename: &str) -> Self {
        Self {
            profiles: vec![TestProfile::TypeDbDefault],
            config_filename: config_filename.to_string(),
            mcp_server_tls: false,
        }
    }

    /// Cria uma configuração para testar com o TypeDB usando TLS.
    /// Ativa o perfil `TypeDbTls`.
    pub fn with_typedb_tls(config_filename: &str) -> Self {
        Self {
            profiles: vec![TestProfile::TypeDbTls],
            config_filename: config_filename.to_string(),
            mcp_server_tls: false,
        }
    }

    /// Cria uma configuração para testar com o Mock OAuth2 Server.
    /// Ativa os perfis `TypeDbDefault` (assumindo que OAuth precisa de um TypeDB) e `OAuthMock`.
    pub fn with_oauth(config_filename: &str) -> Self {
        Self {
            profiles: vec![TestProfile::TypeDbDefault, TestProfile::OAuthMock],
            config_filename: config_filename.to_string(),
            mcp_server_tls: false,
        }
    }

    /// Cria uma configuração para testar com o servidor MCP usando TLS.
    /// Ativa o perfil `TypeDbDefault`.
    pub fn with_mcp_server_tls(config_filename: &str) -> Self {
        Self {
            profiles: vec![TestProfile::TypeDbDefault],
            config_filename: config_filename.to_string(),
            mcp_server_tls: true,
        }
    }

    /// Cria uma configuração totalmente personalizada.
    #[allow(dead_code)] // Pode ser útil para combinações mais complexas
    pub fn custom(
        profiles: Vec<TestProfile>,
        config_filename: &str,
        mcp_server_tls: bool,
    ) -> Self {
        Self { profiles, config_filename: config_filename.to_string(), mcp_server_tls }
    }

    /// Adiciona um perfil adicional à configuração existente, se ainda não estiver presente.
    #[allow(dead_code)] // Útil para construir configurações programaticamente
    pub fn with_profile(mut self, profile: TestProfile) -> Self {
        if !self.profiles.contains(&profile) {
            self.profiles.push(profile);
        }
        self
    }

    /// Define explicitamente se o servidor MCP deve usar TLS.
    #[allow(dead_code)] // Útil para modificar uma config existente
    pub fn with_mcp_tls(mut self, enable_tls: bool) -> Self {
        self.mcp_server_tls = enable_tls;
        self
    }

    /// Verifica se o perfil `OAuthMock` está ativo, indicando que OAuth está habilitado.
    pub fn is_oauth_enabled(&self) -> bool {
        self.profiles.contains(&TestProfile::OAuthMock)
    }

    /// Verifica se o perfil `TypeDbTls` está ativo.
    pub fn is_typedb_tls_enabled(&self) -> bool {
        self.profiles.contains(&TestProfile::TypeDbTls)
    }

    /// Determina o nome do serviço TypeDB a ser aguardado com base nos perfis ativos.
    /// Prioriza o `TypeDbTls` se ambos `TypeDbDefault` e `TypeDbTls` estiverem (embora
    /// essa combinação geralmente não seja usada).
    pub fn typedb_service_to_wait_for(&self) -> &'static str {
        if self.is_typedb_tls_enabled() {
            constants::TYPEDB_TLS_SERVICE_NAME
        } else {
            // Assume TypeDbDefault se TypeDbTls não estiver presente.
            // Se nenhum perfil TypeDB for especificado, pode levar a um erro
            // se `wait_for_service_healthy` for chamado para um serviço TypeDB.
            // A lógica de setup deve garantir que um perfil TypeDB esteja ativo se necessário.
            constants::TYPEDB_SERVICE_NAME
        }
    }

    /// Converte os `TestProfile`s para as strings de nome de perfil usadas pelo Docker Compose.
    pub fn as_compose_profiles(&self) -> Vec<String> {
        self.profiles.iter().map(|p| p.as_compose_profile().to_string()).collect()
    }
}

/// Representa um ambiente de teste de integração totalmente configurado e pronto para uso.
///
/// Gerencia o `DockerComposeEnv`, as URLs dos serviços e flags de configuração
/// para facilitar a escrita dos testes.
/// Implementa `Drop` para garantir a limpeza dos recursos Docker ao final do teste.
#[derive(Debug)]
pub struct TestEnvironment {
    /// Gerenciador do ambiente Docker Compose.
    pub docker_env: DockerComposeEnv,
    /// URL WebSocket completa para o servidor MCP (ex: "ws://localhost:8788/mcp/ws" ou "wss://...").
    pub mcp_ws_url: String,
    /// URL HTTP base para o servidor MCP (ex: "http://localhost:8788" ou "https://...").
    pub mcp_http_base_url: String,
    /// URL completa para o endpoint de métricas Prometheus do servidor MCP.
    pub mcp_metrics_url: String,
    /// URL HTTP base para o Mock OAuth2 Server (se ativo).
    pub mock_oauth_http_url: String,
    /// Indica se o servidor MCP está configurado para usar TLS.
    pub is_mcp_server_tls: bool,
    /// Indica se a autenticação OAuth2 está habilitada para o servidor MCP.
    pub is_oauth_enabled: bool,
    /// Indica se a conexão do servidor MCP com o TypeDB usa TLS.
    pub is_typedb_tls_connection: bool,
}

impl TestEnvironment {
    /// Configura e inicia um novo ambiente de teste de integração usando uma `TestConfiguration`.
    ///
    /// # Arguments
    /// * `test_name_suffix`: Um sufixo para o nome do projeto Docker Compose,
    ///   para ajudar a identificar os recursos Docker associados a este teste.
    /// * `config`: A `TestConfiguration` que define os perfis, arquivo de config MCP, e TLS do servidor MCP.
    ///
    /// # Returns
    /// `Result<Self>`: Uma instância de `TestEnvironment` pronta para uso, ou um erro se o setup falhar.
    ///
    /// # Panics
    /// Pode entrar em pânico se houver falhas críticas na configuração do Docker ou
    /// se a inicialização do provedor criptográfico falhar de forma irrecuperável.
    pub async fn setup_with_profiles(
        test_name_suffix: &str,
        config: TestConfiguration,
    ) -> Result<Self> {
        // **INÍCIO DA CORREÇÃO PARA CryptoProvider**
        // Instala o provedor criptográfico 'ring' como padrão para rustls, se nenhum
        // já estiver instalado globalmente. Isso é crucial porque o typedb-driver
        // (que pode ser ativado mesmo em testes que não usam TypeDB TLS devido à unificação
        // de features do Cargo) pode puxar 'aws-lc-rs' como provedor, enquanto o
        // tokio-tungstenite (usado pelo TestMcpClient) pode preferir 'ring'.
        // Se múltiplas features de provedores são ativadas para rustls, um padrão deve
        // ser explicitamente instalado para evitar pânicos.
        if CryptoProvider::get_default().is_none() {
            match rustls::crypto::ring::default_provider().install_default() {
                Ok(()) => {
                    info!("Provedor criptográfico Ring instalado como padrão para rustls (contexto de teste).");
                }
                Err(e) => {
                    // Se já estiver instalado por outro teste em paralelo (improvável com #[serial])
                    // ou se houver um problema na instalação.
                    warn!(
                        "Tentativa de instalar o provedor criptográfico Ring falhou (pode ser benigno se outro já estiver globalmente ativo): {:?}. Problemas TLS podem ocorrer.",
                        e
                    );
                }
            }
        } else {
            info!("Provedor criptográfico padrão para rustls já está instalado globalmente.");
        }
        // **FIM DA CORREÇÃO PARA CryptoProvider**

        info!(
            "Configurando TestEnvironment para teste '{}' com config MCP: '{}' e perfis: {:?}",
            test_name_suffix, config.config_filename, config.profiles
        );

        let docker_env = DockerComposeEnv::new(
            constants::DEFAULT_DOCKER_COMPOSE_TEST_FILE,
            &format!("mcp_{}", test_name_suffix),
        );

        // Garantir limpeza prévia de ambientes com o mesmo nome de projeto, se existirem.
        docker_env.down(true).unwrap_or_else(|e| {
            warn!(
                "Falha (ignorada) ao derrubar ambiente docker preexistente para o projeto '{}': {}. Isso pode ser normal se for a primeira execução ou se a limpeza anterior falhou.",
                docker_env.project_name(),
                e
            );
        });

        let is_mcp_server_tls = config.mcp_server_tls;
        let is_oauth_enabled = config.is_oauth_enabled();
        let is_typedb_tls_connection = config.is_typedb_tls_enabled();

        let active_profiles = config.as_compose_profiles();
        let typedb_service_to_wait_for = config.typedb_service_to_wait_for();

        // O healthcheck HTTP padrão no Dockerfile pode falhar se o servidor MCP usar TLS.
        // Portanto, desabilitamos o `--wait` do Docker Compose nesses casos e usamos
        // nossa própria lógica de espera (`wait_for_mcp_server_ready_from_test_env`).
        let should_wait_docker_compose_health = !is_mcp_server_tls;

        docker_env
            .up(
                &config.config_filename,
                Some(active_profiles.clone()),
                should_wait_docker_compose_health,
                is_mcp_server_tls, // Passa o flag TLS_ENABLED para o Dockerfile
            )
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

            info!(
                "Mock OAuth Server ('{}') está 'healthy'. Adicionando pequeno delay de 2s para garantir que o Nginx sirva o JWKS.",
                constants::MOCK_OAUTH_SERVICE_NAME
            );
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

        // Agora espera pelo MCP server, que pode depender do JWKS se OAuth estiver ativo.
        // Esta função verifica o /readyz, incluindo o status do TypeDB e JWKS (se aplicável).
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
                "Serviço Typedb-MCP-Server ('{}') não ficou totalmente pronto para projeto '{}' com config MCP '{}'. Verificar logs.",
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

    /// Configura e inicia um novo ambiente de teste de integração.
    ///
    /// Este é um método de conveniência que deriva a `TestConfiguration` com base
    /// no nome do arquivo de configuração fornecido, mantendo a compatibilidade
    /// com testes mais antigos. Para controle explícito de perfis,
    /// use `setup_with_profiles`.
    ///
    /// # Arguments
    /// * `test_name_suffix`: Um sufixo para o nome do projeto Docker Compose.
    /// * `config_filename`: O nome do arquivo de configuração TOML a ser usado
    ///   (ex: "default.test.toml", "oauth_enabled.test.toml").
    pub async fn setup(test_name_suffix: &str, config_filename: &str) -> Result<Self> {
        let config = Self::derive_configuration_from_filename(config_filename);
        Self::setup_with_profiles(test_name_suffix, config).await
    }

    /// Deriva uma `TestConfiguration` com base no nome do arquivo de configuração,
    /// para manter a compatibilidade com a API de setup antiga.
    fn derive_configuration_from_filename(config_filename: &str) -> TestConfiguration {
        if config_filename == constants::SERVER_TLS_TEST_CONFIG_FILENAME {
            TestConfiguration::with_mcp_server_tls(config_filename)
        } else if config_filename == constants::OAUTH_ENABLED_TEST_CONFIG_FILENAME {
            TestConfiguration::with_oauth(config_filename)
        } else if config_filename == constants::TYPEDB_TLS_CONNECTION_TEST_CONFIG_FILENAME {
            TestConfiguration::with_typedb_tls(config_filename)
        } else {
            // Assume default (TypeDB padrão, sem OAuth, sem TLS no servidor MCP)
            // para outros nomes de arquivo ou para "default.test.toml".
            TestConfiguration::default(config_filename)
        }
    }

    /// Conecta-se ao servidor MCP e inicializa uma sessão, opcionalmente com autenticação.
    ///
    /// # Arguments
    /// * `scopes`: Opcional. String contendo escopos OAuth2 separados por espaço
    ///   a serem incluídos no token JWT. Se `None` ou vazio, e OAuth estiver habilitado,
    ///   um token sem escopos específicos (além dos possivelmente padrão do provedor) será gerado.
    ///   Se OAuth estiver desabilitado, este parâmetro é ignorado.
    ///
    /// # Returns
    /// `Result<TestMcpClient>`: Um cliente MCP pronto para uso.
    pub async fn mcp_client_with_auth(&self, scopes: Option<&str>) -> Result<TestMcpClient> {
        let token_to_send = if self.is_oauth_enabled {
            let effective_scopes = scopes.unwrap_or("");
            let now = auth_helpers::current_timestamp_secs();
            let claims = auth_helpers::TestClaims {
                sub: "test-user-from-test-env".to_string(),
                exp: now + 3600, // Token válido por 1 hora
                iat: Some(now),
                nbf: Some(now),
                iss: Some(constants::TEST_JWT_ISSUER.to_string()),
                aud: Some(serde_json::json!(constants::TEST_JWT_AUDIENCE)),
                scope: if effective_scopes.is_empty() {
                    None
                } else {
                    Some(effective_scopes.to_string())
                },
                custom_claim: None,
            };
            Some(auth_helpers::generate_test_jwt(claims, JwtAuthAlgorithm::RS256))
        } else {
            if scopes.is_some() && !scopes.unwrap_or("").is_empty() {
                warn!(
                    "TestEnvironment: Solicitado cliente com escopos ('{}'), mas OAuth não está habilitado para este ambiente (config: '{}'). Conectando sem token.",
                    scopes.unwrap_or("<nenhum>"),
                    self.determine_config_filename_from_flags() // Helper para obter o nome da config
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

    /// Helper interno para determinar o nome do arquivo de configuração com base nas flags de `self`.
    /// Usado principalmente para logging e depuração.
    fn determine_config_filename_from_flags(&self) -> String {
        if self.is_typedb_tls_connection {
            constants::TYPEDB_TLS_CONNECTION_TEST_CONFIG_FILENAME.to_string()
        } else if self.is_oauth_enabled {
            // Assumindo que OAUTH_ENABLED_TEST_CONFIG_FILENAME é o representativo
            constants::OAUTH_ENABLED_TEST_CONFIG_FILENAME.to_string()
        } else if self.is_mcp_server_tls {
            constants::SERVER_TLS_TEST_CONFIG_FILENAME.to_string()
        } else {
            // Default para casos onde nenhuma flag específica de TLS/OAuth está ativa
            constants::DEFAULT_TEST_CONFIG_FILENAME.to_string()
        }
    }
}

impl Drop for TestEnvironment {
    /// Garante que o ambiente Docker Compose seja derrubado quando `TestEnvironment` sai de escopo.
    fn drop(&mut self) {
        info!(
            "Limpando TestEnvironment para projeto: '{}' (via Drop).",
            self.docker_env.project_name()
        );
        if let Err(e) = self.docker_env.down(true) {
            // `remove_volumes = true` para limpar completamente
            error!(
                "Falha ao derrubar ambiente Docker Compose no drop para '{}': {}. Limpeza manual pode ser necessária.",
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
    // constants já está no escopo via `super::*`
    // Duration já está no escopo via `std::time::Duration`

    #[tokio::test]
    #[serial]
    #[ignore] // Ignorar por padrão, pois são testes de setup de ambiente, podem ser lentos
    async fn test_test_environment_setup_default_config() -> Result<()> {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        info!("Iniciando teste: test_test_environment_setup_default_config");
        let test_env =
            TestEnvironment::setup("setup_default", constants::DEFAULT_TEST_CONFIG_FILENAME)
                .await?;

        assert!(!test_env.is_mcp_server_tls);
        assert!(!test_env.is_oauth_enabled);
        assert!(!test_env.is_typedb_tls_connection);
        assert!(test_env.mcp_ws_url.starts_with("ws://localhost:8788"));

        info!(
            "TestEnvironment (default config) configurado com sucesso. WS URL: {}",
            test_env.mcp_ws_url
        );
        Ok(())
    }

    #[tokio::test]
    #[serial]
    #[ignore] // Ignorar por padrão
    async fn test_test_environment_setup_oauth_config() -> Result<()> {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        info!("Iniciando teste: test_test_environment_setup_oauth_config");
        let test_env =
            TestEnvironment::setup("setup_oauth", constants::OAUTH_ENABLED_TEST_CONFIG_FILENAME)
                .await?;

        assert!(!test_env.is_mcp_server_tls);
        assert!(test_env.is_oauth_enabled);
        assert!(!test_env.is_typedb_tls_connection);
        assert!(test_env.mcp_ws_url.starts_with("ws://localhost:8788"));

        info!(
            "TestEnvironment (OAuth config) configurado com sucesso. OAuth habilitado: {}",
            test_env.is_oauth_enabled
        );
        Ok(())
    }

    #[tokio::test]
    #[serial]
    #[ignore] // Ignorar por padrão
    async fn test_test_environment_setup_server_tls_config() -> Result<()> {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        info!("Iniciando teste: test_test_environment_setup_server_tls_config");
        let test_env =
            TestEnvironment::setup("setup_servertls", constants::SERVER_TLS_TEST_CONFIG_FILENAME)
                .await?;

        assert!(test_env.is_mcp_server_tls);
        assert!(!test_env.is_oauth_enabled);
        assert!(!test_env.is_typedb_tls_connection);
        assert!(test_env.mcp_ws_url.starts_with("wss://localhost:8444"));

        info!(
            "TestEnvironment (Server TLS config) configurado com sucesso. MCP Server TLS: {}",
            test_env.is_mcp_server_tls
        );
        Ok(())
    }

    #[tokio::test]
    #[serial]
    #[ignore] // Ignorar por padrão
    async fn test_test_environment_setup_typedb_tls_config() -> Result<()> {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        info!("Iniciando teste: test_test_environment_setup_typedb_tls_config");
        let test_env = TestEnvironment::setup(
            "setup_typedbtls",
            constants::TYPEDB_TLS_CONNECTION_TEST_CONFIG_FILENAME,
        )
        .await?;

        assert!(!test_env.is_mcp_server_tls);
        assert!(!test_env.is_oauth_enabled);
        assert!(test_env.is_typedb_tls_connection);
        assert!(test_env.mcp_ws_url.starts_with("ws://localhost:8788"));

        info!(
            "TestEnvironment (TypeDB TLS config) configurado com sucesso. TypeDB TLS Connection: {}",
            test_env.is_typedb_tls_connection
        );
        Ok(())
    }

    // === Testes da nova API de perfis (usando setup_with_profiles) ===

    #[tokio::test]
    #[serial]
    #[ignore] // Ignorar por padrão
    async fn test_setup_with_custom_profiles_default() -> Result<()> {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        info!("🧪 Iniciando teste: test_setup_with_custom_profiles_default");

        let config = TestConfiguration::default(constants::DEFAULT_TEST_CONFIG_FILENAME);
        let test_env =
            TestEnvironment::setup_with_profiles("profiles_default", config.clone()).await?; // Clonar config

        assert!(!test_env.is_mcp_server_tls);
        assert!(!test_env.is_oauth_enabled);
        assert!(!test_env.is_typedb_tls_connection);
        assert!(test_env.mcp_ws_url.starts_with("ws://localhost:8788"));
        assert_eq!(config.config_filename, constants::DEFAULT_TEST_CONFIG_FILENAME);

        info!("✅ TestEnvironment com perfil padrão configurado com sucesso");
        Ok(())
    }

    #[tokio::test]
    #[serial]
    #[ignore] // Ignorar por padrão
    async fn test_setup_with_custom_profiles_oauth() -> Result<()> {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        info!("🧪 Iniciando teste: test_setup_with_custom_profiles_oauth");

        let config = TestConfiguration::with_oauth(constants::OAUTH_ENABLED_TEST_CONFIG_FILENAME);
        let test_env =
            TestEnvironment::setup_with_profiles("profiles_oauth", config.clone()).await?; // Clonar config

        assert!(!test_env.is_mcp_server_tls);
        assert!(test_env.is_oauth_enabled);
        assert!(!test_env.is_typedb_tls_connection);
        assert!(test_env.mcp_ws_url.starts_with("ws://localhost:8788"));
        assert_eq!(config.config_filename, constants::OAUTH_ENABLED_TEST_CONFIG_FILENAME);

        info!("✅ TestEnvironment com OAuth Mock configurado com sucesso");
        Ok(())
    }

    #[test]
    fn test_profile_conversions_and_configuration_helpers() {
        // Testes síncronos para TestProfile e TestConfiguration helpers
        assert_eq!(TestProfile::TypeDbDefault.as_compose_profile(), "typedb_default");
        assert_eq!(
            TestProfile::TypeDbDefault.typedb_service_name(),
            Some(constants::TYPEDB_SERVICE_NAME)
        );

        let default_config = TestConfiguration::default("test.toml");
        assert_eq!(default_config.profiles, vec![TestProfile::TypeDbDefault]);
        assert!(!default_config.is_oauth_enabled());

        let oauth_config = TestConfiguration::with_oauth("oauth.toml")
            .with_profile(TestProfile::TypeDbTls) // Adicionar outro perfil
            .with_mcp_tls(true);
        assert!(oauth_config.is_oauth_enabled());
        assert!(oauth_config.is_typedb_tls_enabled());
        assert!(oauth_config.mcp_server_tls);
        assert_eq!(oauth_config.profiles.len(), 3); // TypeDbDefault, OAuthMock, TypeDbTls
    }
}