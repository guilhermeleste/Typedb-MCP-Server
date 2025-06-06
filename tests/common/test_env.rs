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
use rustls::crypto::CryptoProvider;
use std::time::Duration;
use tracing::{error, info, warn};

// Importa helpers e constantes do mesmo crate `common`
use super::auth_helpers::{self, JwtAuthAlgorithm};
use super::client::TestMcpClient;
use super::constants;
use super::docker_helpers::DockerComposeEnv;
use super::test_utils::wait_for_mcp_server_ready_from_test_env;

/// Perfis Docker disponíveis para testes de integração.
///
/// Cada perfil ativa um conjunto específico de serviços no arquivo `docker-compose.test.yml`,
/// permitindo que os testes configurem apenas as dependências necessárias.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TestProfile {
    /// Ativa o serviço TypeDB padrão (sem TLS) para os testes.
    /// Corresponde ao perfil "typedb_default" no Docker Compose.
    TypeDbDefault,
    /// Ativa o serviço TypeDB configurado para usar TLS.
    /// Corresponde ao perfil "typedb_tls" no Docker Compose.
    TypeDbTls,
    /// Ativa o serviço Mock OAuth2 Server, que simula um provedor de identidade
    /// servindo um JWKS estático.
    /// Corresponde ao perfil "oauth_mock" no Docker Compose.
    OAuthMock,
}

impl TestProfile {
    /// Converte o enum `TestProfile` para a string de nome de perfil
    /// usada nos arquivos Docker Compose.
    pub fn as_compose_profile(&self) -> &'static str {
        match self {
            TestProfile::TypeDbDefault => "typedb_default",
            TestProfile::TypeDbTls => "typedb_tls",
            TestProfile::OAuthMock => "oauth_mock",
        }
    }

    /// Retorna o nome do serviço TypeDB principal associado a este perfil, se houver.
    ///
    /// Alguns perfis (como `OAuthMock`) podem não ter um serviço TypeDB diretamente
    /// associado a eles, mas podem ser combinados com outros perfis que o tenham.
    pub fn typedb_service_name(&self) -> Option<&'static str> {
        match self {
            TestProfile::TypeDbDefault => Some(constants::TYPEDB_SERVICE_NAME),
            TestProfile::TypeDbTls => Some(constants::TYPEDB_TLS_SERVICE_NAME),
            TestProfile::OAuthMock => None, // OAuthMock por si só não define um serviço TypeDB.
        }
    }
}

/// Configuração detalhada para o setup de um `TestEnvironment`.
///
/// Esta struct permite especificar quais perfis Docker devem ser ativados,
/// qual arquivo de configuração TOML o servidor MCP deve usar, e
/// configurações de TLS tanto para o servidor MCP quanto para sua conexão com o TypeDB.
#[derive(Debug, Clone)]
pub struct TestConfiguration {
    /// Uma lista de perfis [`TestProfile`] a serem ativados no Docker Compose.
    pub profiles: Vec<TestProfile>,
    /// O nome do arquivo de configuração TOML (ex: "default.test.toml")
    /// que o servidor MCP usará. Espera-se que este arquivo esteja em `tests/test_configs/`.
    pub config_filename: String,
    /// Indica se o servidor MCP em si deve usar TLS para seus endpoints (HTTPS/WSS).
    pub mcp_server_tls: bool,
    /// Indica se a conexão do servidor MCP para o TypeDB (conforme definido no arquivo
    /// de configuração TOML especificado por `config_filename`) deve usar TLS.
    pub typedb_connection_uses_tls: bool,
}

impl TestConfiguration {
    /// Cria uma configuração padrão.
    ///
    /// - Ativa o perfil `TypeDbDefault`.
    /// - Usa o `config_filename` fornecido.
    /// - O servidor MCP não usa TLS.
    /// - A conexão MCP -> TypeDB não usa TLS.
    pub fn default(config_filename: &str) -> Self {
        Self {
            profiles: vec![TestProfile::TypeDbDefault],
            config_filename: config_filename.to_string(),
            mcp_server_tls: false,
            typedb_connection_uses_tls: false,
        }
    }

    /// Cria uma configuração para testar cenários onde a conexão MCP -> TypeDB usa TLS.
    ///
    /// - Ativa o perfil `TypeDbTls` (que inicia o serviço `typedb-server-tls-it`).
    /// - Indica que a conexão TypeDB deve ser TLS.
    pub fn with_typedb_tls(config_filename: &str) -> Self {
        Self {
            profiles: vec![TestProfile::TypeDbTls],
            config_filename: config_filename.to_string(),
            mcp_server_tls: false,
            typedb_connection_uses_tls: true,
        }
    }

    /// Cria uma configuração para testar com autenticação OAuth2 habilitada.
    ///
    /// - Ativa os perfis `TypeDbDefault` (assumindo que um TypeDB é necessário) e `OAuthMock`.
    pub fn with_oauth(config_filename: &str) -> Self {
        Self {
            profiles: vec![TestProfile::TypeDbDefault, TestProfile::OAuthMock],
            config_filename: config_filename.to_string(),
            mcp_server_tls: false,
            typedb_connection_uses_tls: false,
        }
    }

    /// Cria uma configuração para testar com o servidor MCP usando TLS para seus próprios endpoints.
    ///
    /// - Ativa o perfil `TypeDbDefault`.
    /// - Define `mcp_server_tls` como `true`.
    pub fn with_mcp_server_tls(config_filename: &str) -> Self {
        Self {
            profiles: vec![TestProfile::TypeDbDefault],
            config_filename: config_filename.to_string(),
            mcp_server_tls: true,
            typedb_connection_uses_tls: false,
        }
    }

    /// Cria uma configuração totalmente personalizada com todos os parâmetros explícitos.
    #[allow(dead_code)]
    pub fn custom(
        profiles: Vec<TestProfile>,
        config_filename: &str,
        mcp_server_tls: bool,
        typedb_connection_uses_tls: bool,
    ) -> Self {
        Self {
            profiles,
            config_filename: config_filename.to_string(),
            mcp_server_tls,
            typedb_connection_uses_tls,
        }
    }

    /// Adiciona um perfil Docker adicional à configuração existente, se ainda não estiver presente.
    #[allow(dead_code)]
    pub fn with_profile(mut self, profile: TestProfile) -> Self {
        if !self.profiles.contains(&profile) {
            self.profiles.push(profile);
        }
        self
    }

    /// Define explicitamente se o servidor MCP deve usar TLS para seus endpoints.
    #[allow(dead_code)]
    pub fn with_mcp_tls(mut self, enable_tls: bool) -> Self {
        self.mcp_server_tls = enable_tls;
        self
    }

    /// Verifica se o perfil `OAuthMock` está ativo, indicando que a autenticação OAuth2
    /// deve estar habilitada no servidor MCP para os testes.
    pub fn is_oauth_enabled(&self) -> bool {
        self.profiles.contains(&TestProfile::OAuthMock)
    }

    /// Determina o nome do serviço TypeDB que o servidor MCP deve ser configurado para usar,
    /// com base se a conexão TypeDB deve ou não usar TLS.
    ///
    /// Este nome é usado para construir a variável `MCP_TYPEDB__ADDRESS`.
    pub fn mcp_target_typedb_service_name(&self) -> &'static str {
        if self.typedb_connection_uses_tls {
            constants::TYPEDB_TLS_SERVICE_NAME
        } else {
            constants::TYPEDB_SERVICE_NAME
        }
    }

    /// Determina qual serviço TypeDB (o padrão ou o TLS) deve ter seu healthcheck aguardado
    /// como a dependência TypeDB primária, com base nos perfis Docker que estão ativos.
    pub fn primary_typedb_service_to_wait_for_health(&self) -> &'static str {
        if self.profiles.contains(&TestProfile::TypeDbTls) {
            constants::TYPEDB_TLS_SERVICE_NAME
        } else if self.profiles.contains(&TestProfile::TypeDbDefault) {
            constants::TYPEDB_SERVICE_NAME
        } else {
            // Se nenhum perfil TypeDB específico estiver ativo, mas talvez OAuthMock esteja,
            // e a configuração do MCP ainda precise de um TypeDB,
            // retornamos o alvo que o MCP usaria.
            self.mcp_target_typedb_service_name()
        }
    }

    /// Converte os enums [`TestProfile`] para as strings de nome de perfil
    /// usadas nos comandos do Docker Compose.
    pub fn as_compose_profiles(&self) -> Vec<String> {
        self.profiles.iter().map(|p| p.as_compose_profile().to_string()).collect()
    }
}

/// Representa um ambiente de teste de integração completo, incluindo serviços Docker
/// e informações de conexão para o servidor MCP.
///
/// Esta struct gerencia o ciclo de vida do ambiente Docker através de `DockerComposeEnv`
/// e fornece URLs e flags convenientes para os testes.
/// Implementa `Drop` para garantir a limpeza dos recursos Docker.
#[derive(Debug)]
pub struct TestEnvironment {
    /// O gerenciador do ambiente Docker Compose para este teste.
    pub docker_env: DockerComposeEnv,
    /// A URL WebSocket completa (incluindo esquema `ws://` ou `wss://`) para o servidor MCP.
    pub mcp_ws_url: String,
    /// A URL HTTP base (incluindo esquema `http://` ou `https://`) para o servidor MCP
    /// (usada para endpoints como `/livez`, `/readyz`).
    pub mcp_http_base_url: String,
    /// A URL HTTP completa para o endpoint de métricas Prometheus do servidor MCP.
    pub mcp_metrics_url: String,
    /// A URL HTTP base para o Mock OAuth2 Server (se estiver ativo no perfil).
    pub mock_oauth_http_url: String,
    /// Indica se o servidor MCP está configurado para usar TLS para seus próprios endpoints.
    pub is_mcp_server_tls: bool,
    /// Indica se a autenticação OAuth2 está habilitada para o servidor MCP (baseado nos perfis).
    pub is_oauth_enabled: bool,
    /// Indica se a conexão do servidor MCP com o TypeDB está configurada para usar TLS.
    pub is_typedb_connection_tls: bool,
}

impl TestEnvironment {
    /// Configura e inicia um novo ambiente de teste de integração usando uma [`TestConfiguration`].
    ///
    /// Este é o método principal para criar um `TestEnvironment`. Ele orquestra o Docker Compose,
    /// espera os serviços ficarem prontos e configura as URLs de acesso.
    ///
    /// # Arguments
    /// * `test_name_suffix`: Um sufixo para o nome do projeto Docker Compose,
    ///   usado para isolar recursos Docker entre execuções de teste.
    /// * `config`: A [`TestConfiguration`] que define os perfis Docker, o arquivo de configuração
    ///   TOML para o servidor MCP, e as configurações de TLS.
    ///
    /// # Returns
    /// `Result<Self>`: Uma instância de `TestEnvironment` pronta para uso, ou um erro se o setup falhar.
    pub async fn setup_with_profiles(
        test_name_suffix: &str,
        config: TestConfiguration,
    ) -> Result<Self> {
        if CryptoProvider::get_default().is_none() {
            if let Err(e) = rustls::crypto::ring::default_provider().install_default() {
                warn!(
                    "[TEST_CRYPTO_PROVIDER] Falha ao instalar 'ring' como provedor criptográfico padrão: {:?}. Testes TLS podem ser instáveis.",
                    e
                );
            } else {
                info!("[TEST_CRYPTO_PROVIDER] Provedor 'ring' instalado como padrão para rustls nos testes.");
            }
        }

        info!(
            "Configurando TestEnvironment para teste '{}' com config MCP: '{}', perfis: {:?}, MCP Server TLS: {}, TypeDB Connection Uses TLS: {}",
            test_name_suffix, config.config_filename, config.profiles, config.mcp_server_tls, config.typedb_connection_uses_tls
        );

        let docker_env = DockerComposeEnv::new(
            constants::DEFAULT_DOCKER_COMPOSE_TEST_FILE,
            &format!("mcp_{}", test_name_suffix),
        );

        docker_env.down(true).unwrap_or_else(|e| {
            warn!(
                "Falha (ignorada) ao derrubar ambiente docker preexistente para o projeto '{}': {}.",
                docker_env.project_name(),
                e
            );
        });

        let active_profiles = config.as_compose_profiles();
        
        let mcp_target_typedb_svc_name = config.mcp_target_typedb_service_name();
        let typedb_address_for_mcp_container = format!(
            "{}:{}",
            mcp_target_typedb_svc_name,
            constants::TYPEDB_INTERNAL_PORT
        );

        let primary_typedb_to_await_health = config.primary_typedb_service_to_wait_for_health();
        let should_wait_docker_compose_health = !config.mcp_server_tls;

        docker_env
            .up(
                &config.config_filename,
                Some(active_profiles.clone()),
                should_wait_docker_compose_health,
                config.mcp_server_tls,
                typedb_address_for_mcp_container.clone(),
            )
            .with_context(|| {
                format!(
                    "Falha ao executar 'docker compose up' para projeto '{}' com config MCP '{}', perfis {:?}, e MCP server configurado para conectar a TypeDB em '{}'",
                    docker_env.project_name(),
                    config.config_filename,
                    active_profiles,
                    typedb_address_for_mcp_container
                )
            })?;
            
        // Se o typedb-server-it (padrão) for iniciado (devido ao depends_on ou perfis default/oauth/typedb_tls)
        // E não for o alvo principal do MCP, esperamos por ele também.
        // Isso garante que a condição `depends_on` do docker-compose.yml seja respeitada.
        if primary_typedb_to_await_health != constants::TYPEDB_SERVICE_NAME && 
           (config.profiles.contains(&TestProfile::TypeDbDefault) || 
            config.profiles.contains(&TestProfile::OAuthMock) ||
            config.profiles.contains(&TestProfile::TypeDbTls)) { 
            info!(
                "Aguardando serviço TypeDB padrão ('{}') ficar saudável (devido a depends_on/perfil) para projeto '{}'.",
                constants::TYPEDB_SERVICE_NAME,
                docker_env.project_name()
            );
            docker_env
                .wait_for_service_healthy(
                    constants::TYPEDB_SERVICE_NAME,
                    constants::DEFAULT_TYPEDB_READY_TIMEOUT,
                )
                .await
                .with_context(|| {
                    format!(
                        "Serviço TypeDB padrão ('{}') não ficou saudável para projeto '{}'",
                        constants::TYPEDB_SERVICE_NAME,
                        docker_env.project_name()
                    )
                })?;
        }

        // Agora espera pelo serviço TypeDB que o MCP server *realmente* usará.
        info!(
            "Aguardando serviço TypeDB alvo do MCP ('{}') ficar saudável para projeto '{}'.",
            mcp_target_typedb_svc_name,
            docker_env.project_name()
        );
        docker_env
            .wait_for_service_healthy(
                mcp_target_typedb_svc_name,
                constants::DEFAULT_TYPEDB_READY_TIMEOUT,
            )
            .await
            .with_context(|| {
                format!(
                    "Serviço TypeDB alvo do MCP ('{}') não ficou saudável para projeto '{}'",
                    mcp_target_typedb_svc_name,
                    docker_env.project_name()
                )
            })?;

        if config.is_oauth_enabled() {
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
                "Mock OAuth Server ('{}') está 'healthy'. Adicionando delay de 2s.",
                constants::MOCK_OAUTH_SERVICE_NAME
            );
            tokio::time::sleep(Duration::from_secs(2)).await;
        }

        let (mcp_ws_url, mcp_http_base_url) = if config.mcp_server_tls {
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
            &docker_env,
            &mcp_http_base_url,
            config.mcp_server_tls,
            config.is_oauth_enabled(),
            config.typedb_connection_uses_tls, // Passa a flag correta
            constants::DEFAULT_MCP_SERVER_READY_TIMEOUT,
        )
        .await
        .with_context(|| {
            format!(
                "Serviço Typedb-MCP-Server ('{}') não ficou totalmente pronto para projeto '{}' com config MCP '{}'. MCP Server estava configurado para conectar a TypeDB em '{}'. Verificar logs do contêiner MCP.",
                constants::MCP_SERVER_SERVICE_NAME,
                docker_env.project_name(),
                config.config_filename,
                typedb_address_for_mcp_container 
            )
        })?;

        let mcp_metrics_url = format!(
            "http://localhost:{}{}",
            constants::MCP_SERVER_HOST_HTTP_PORT, // Usa a porta do servidor MCP principal (endpoint /metrics é servido lá)
            constants::MCP_SERVER_DEFAULT_METRICS_PATH
        );
        let mock_oauth_http_url = format!("http://localhost:{}", constants::MOCK_OAUTH_HOST_PORT);

        info!(
            "TestEnvironment para projeto '{}' (config MCP: '{}', perfis ativos: {:?}, MCP Server TLS: {}, TypeDB Connection Uses TLS: {}) configurado com sucesso.\n  MCP WS URL: {}\n  MCP HTTP Base URL: {}\n  MCP Metrics URL: {}\n  Mock OAuth URL: {}",
            docker_env.project_name(),
            config.config_filename, active_profiles, config.mcp_server_tls, config.typedb_connection_uses_tls,
            mcp_ws_url, mcp_http_base_url, mcp_metrics_url, mock_oauth_http_url
        );

        Ok(TestEnvironment {
            docker_env,
            mcp_ws_url,
            mcp_http_base_url,
            mcp_metrics_url,
            mock_oauth_http_url,
            is_mcp_server_tls: config.mcp_server_tls,
            is_oauth_enabled: config.is_oauth_enabled(),
            is_typedb_connection_tls: config.typedb_connection_uses_tls,
        })
    }

    /// Configura e inicia um novo ambiente de teste de integração.
    ///
    /// Este é um método de conveniência que deriva a [`TestConfiguration`] com base
    /// no nome do arquivo de configuração fornecido, para manter a compatibilidade
    /// com testes mais antigos. Para controle explícito de perfis e configurações TLS,
    /// use [`TestEnvironment::setup_with_profiles`].
    ///
    /// # Arguments
    /// * `test_name_suffix`: Um sufixo para o nome do projeto Docker Compose.
    /// * `config_filename`: O nome do arquivo de configuração TOML a ser usado
    ///   (ex: "default.test.toml", "oauth_enabled.test.toml").
    pub async fn setup(test_name_suffix: &str, config_filename: &str) -> Result<Self> {
        let config = Self::derive_configuration_from_filename(config_filename);
        Self::setup_with_profiles(test_name_suffix, config).await
    }

    /// Deriva uma [`TestConfiguration`] com base no nome do arquivo de configuração.
    ///
    /// Usado internamente por `setup` para determinar as flags de TLS e perfis
    /// com base em convenções de nomenclatura de arquivos de configuração.
    fn derive_configuration_from_filename(config_filename: &str) -> TestConfiguration {
        match config_filename {
            constants::SERVER_TLS_TEST_CONFIG_FILENAME => {
                TestConfiguration::with_mcp_server_tls(config_filename)
            }
            constants::OAUTH_ENABLED_TEST_CONFIG_FILENAME => {
                TestConfiguration::with_oauth(config_filename)
            }
            constants::TYPEDB_TLS_CONNECTION_TEST_CONFIG_FILENAME => {
                TestConfiguration::with_typedb_tls(config_filename)
            }
            // Casos para os novos arquivos de teste que você mencionou
            "typedb_tls_wrong_ca.test.toml" => TestConfiguration {
                profiles: vec![TestProfile::TypeDbTls], // Precisa do TypeDB com TLS para tentar conectar
                config_filename: config_filename.to_string(),
                mcp_server_tls: false,
                typedb_connection_uses_tls: true, // MCP tentará TLS
            },
            "typedb_expect_tls_got_plain.test.toml" => TestConfiguration {
                profiles: vec![TestProfile::TypeDbDefault], // Precisa do TypeDB sem TLS
                config_filename: config_filename.to_string(),
                mcp_server_tls: false,
                typedb_connection_uses_tls: true, // MCP tentará TLS (mas o TypeDB não terá)
            },
            _ => TestConfiguration::default(config_filename),
        }
    }

    /// Conecta-se ao servidor MCP e inicializa uma sessão, opcionalmente com autenticação.
    ///
    /// # Arguments
    /// * `scopes`: Opcional. String contendo escopos OAuth2 separados por espaço
    ///   a serem incluídos no token JWT. Se `None` ou vazio, e OAuth estiver habilitado,
    ///   um token sem escopos específicos será gerado.
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
                warn!(
                    "TestEnvironment: Solicitado cliente com escopos ('{}'), mas OAuth não está habilitado para este ambiente (config: '{}'). Conectando sem token.",
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

        TestMcpClient::connect_and_initialize(
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
        })
    }

    /// Helper interno para determinar o nome do arquivo de configuração com base nas flags de `self`.
    /// Usado principalmente para logging e depuração.
    fn determine_config_filename_from_flags(&self) -> String {
        // Esta lógica é uma heurística e pode não cobrir todas as combinações exatas
        // se o config_filename for passado diretamente de forma customizada.
        // O ideal seria armazenar o config_filename em self.
        if self.is_typedb_connection_tls {
            // Se a conexão TypeDB é TLS, provavelmente é TYPEDB_TLS_CONNECTION_TEST_CONFIG_FILENAME
            // ou um dos arquivos de falha TLS do TypeDB.
            // Precisamos de mais contexto ou de armazenar o config_filename em TestEnvironment.
            // Por agora, vamos assumir o mais comum para esta flag.
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
            "Limpando TestEnvironment para projeto: '{}' (via Drop).",
            self.docker_env.project_name()
        );
        if let Err(e) = self.docker_env.down(true) { // remove_volumes = true
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

    #[tokio::test]
    #[serial]
    #[ignore] // Testes de setup podem ser lentos, ignorar por padrão.
    async fn test_test_environment_setup_default_config() -> Result<()> {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let config = TestConfiguration::default(constants::DEFAULT_TEST_CONFIG_FILENAME);
        let test_env = TestEnvironment::setup_with_profiles("setup_default_prof", config).await?;
        assert!(!test_env.is_mcp_server_tls && !test_env.is_oauth_enabled && !test_env.is_typedb_connection_tls);
        assert_eq!(test_env.determine_config_filename_from_flags(), constants::DEFAULT_TEST_CONFIG_FILENAME);
        Ok(())
    }

    #[tokio::test]
    #[serial]
    #[ignore]
    async fn test_test_environment_setup_oauth_config() -> Result<()> {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let config = TestConfiguration::with_oauth(constants::OAUTH_ENABLED_TEST_CONFIG_FILENAME);
        let test_env = TestEnvironment::setup_with_profiles("setup_oauth_prof", config).await?;
        assert!(!test_env.is_mcp_server_tls && test_env.is_oauth_enabled && !test_env.is_typedb_connection_tls);
        assert_eq!(test_env.determine_config_filename_from_flags(), constants::OAUTH_ENABLED_TEST_CONFIG_FILENAME);
        Ok(())
    }

    #[tokio::test]
    #[serial]
    #[ignore]
    async fn test_test_environment_setup_server_tls_config() -> Result<()> {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let config = TestConfiguration::with_mcp_server_tls(constants::SERVER_TLS_TEST_CONFIG_FILENAME);
        let test_env = TestEnvironment::setup_with_profiles("setup_servertls_prof", config).await?;
        assert!(test_env.is_mcp_server_tls && !test_env.is_oauth_enabled && !test_env.is_typedb_connection_tls);
        assert_eq!(test_env.determine_config_filename_from_flags(), constants::SERVER_TLS_TEST_CONFIG_FILENAME);
        Ok(())
    }

    #[tokio::test]
    #[serial]
    #[ignore]
    async fn test_test_environment_setup_typedb_tls_config() -> Result<()> {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let config = TestConfiguration::with_typedb_tls(constants::TYPEDB_TLS_CONNECTION_TEST_CONFIG_FILENAME);
        let test_env = TestEnvironment::setup_with_profiles("setup_typedbtls_prof", config).await?;
        assert!(!test_env.is_mcp_server_tls && !test_env.is_oauth_enabled && test_env.is_typedb_connection_tls);
        assert_eq!(test_env.determine_config_filename_from_flags(), constants::TYPEDB_TLS_CONNECTION_TEST_CONFIG_FILENAME);
        Ok(())
    }

    #[test]
    fn test_test_configuration_logic() {
        let default_cfg = TestConfiguration::default("default.toml");
        assert_eq!(default_cfg.mcp_target_typedb_service_name(), constants::TYPEDB_SERVICE_NAME);
        assert_eq!(default_cfg.primary_typedb_service_to_wait_for_health(), constants::TYPEDB_SERVICE_NAME);

        let typedb_tls_cfg = TestConfiguration::with_typedb_tls("typedb_tls.toml");
        assert_eq!(typedb_tls_cfg.mcp_target_typedb_service_name(), constants::TYPEDB_TLS_SERVICE_NAME);
        assert_eq!(typedb_tls_cfg.primary_typedb_service_to_wait_for_health(), constants::TYPEDB_TLS_SERVICE_NAME);

        let oauth_cfg = TestConfiguration::with_oauth("oauth.toml");
        assert_eq!(oauth_cfg.mcp_target_typedb_service_name(), constants::TYPEDB_SERVICE_NAME);
        assert_eq!(oauth_cfg.primary_typedb_service_to_wait_for_health(), constants::TYPEDB_SERVICE_NAME);

        let oauth_and_typedb_tls_cfg = TestConfiguration {
            profiles: vec![TestProfile::OAuthMock, TestProfile::TypeDbTls],
            config_filename: "custom.toml".to_string(),
            mcp_server_tls: false,
            typedb_connection_uses_tls: true,
        };
        assert_eq!(oauth_and_typedb_tls_cfg.mcp_target_typedb_service_name(), constants::TYPEDB_TLS_SERVICE_NAME);
        assert_eq!(oauth_and_typedb_tls_cfg.primary_typedb_service_to_wait_for_health(), constants::TYPEDB_TLS_SERVICE_NAME);
    }

    #[test]
    fn test_derive_configuration_from_filename_logic() {
        let cfg_default = TestEnvironment::derive_configuration_from_filename(constants::DEFAULT_TEST_CONFIG_FILENAME);
        assert!(!cfg_default.typedb_connection_uses_tls && !cfg_default.mcp_server_tls && !cfg_default.is_oauth_enabled());
        assert_eq!(cfg_default.profiles, vec![TestProfile::TypeDbDefault]);

        let cfg_typedb_tls = TestEnvironment::derive_configuration_from_filename(constants::TYPEDB_TLS_CONNECTION_TEST_CONFIG_FILENAME);
        assert!(cfg_typedb_tls.typedb_connection_uses_tls && !cfg_typedb_tls.mcp_server_tls && !cfg_typedb_tls.is_oauth_enabled());
        assert_eq!(cfg_typedb_tls.profiles, vec![TestProfile::TypeDbTls]);
        
        let cfg_wrong_ca = TestEnvironment::derive_configuration_from_filename("typedb_tls_wrong_ca.test.toml");
        assert!(cfg_wrong_ca.typedb_connection_uses_tls);
        assert_eq!(cfg_wrong_ca.profiles, vec![TestProfile::TypeDbTls]);

        let cfg_expect_tls_plain = TestEnvironment::derive_configuration_from_filename("typedb_expect_tls_got_plain.test.toml");
        assert!(cfg_expect_tls_plain.typedb_connection_uses_tls); // MCP Server *espera* TLS para TypeDB
        assert_eq!(cfg_expect_tls_plain.profiles, vec![TestProfile::TypeDbDefault]); // Mas o TypeDB ativado é o SEM TLS
    }
}