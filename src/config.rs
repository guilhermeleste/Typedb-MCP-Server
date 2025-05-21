// src/config.rs

//! Módulo de configuração para o Typedb-MCP-Server.
//!
//! Define as estruturas para carregar as configurações da aplicação a partir
//! de um arquivo TOML e/ou variáveis de ambiente. A precedência é:
//! 1. Valores padrão definidos no código.
//! 2. Valores do arquivo de configuração (ex: `typedb_mcp_server_config.toml`).
//! 3. Valores de variáveis de ambiente (prefixadas com `MCP_` e usando `__` como separador para aninhamento).

use serde::Deserialize;
use std::time::Duration;
use config::{Config, ConfigError, Environment, File as ConfigFile}; // Renomeado para ConfigFile para evitar conflito

/// Nome padrão do arquivo de configuração se `MCP_CONFIG_PATH` não estiver definida.
const DEFAULT_CONFIG_FILENAME: &str = "typedb_mcp_server_config.toml";
/// Prefixo para variáveis de ambiente que sobrescrevem as configurações do arquivo.
const ENV_PREFIX: &str = "MCP";
/// Separador usado em variáveis de ambiente para indicar aninhamento de configuração.
const ENV_SEPARATOR: &str = "__";

/// Estrutura principal que agrupa todas as configurações da aplicação.
#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    /// Configurações relacionadas à conexão com o `TypeDB`.
    #[serde(default = "default_typedb_settings")]
    pub typedb: TypeDB,

    /// Configurações do servidor MCP.
    #[serde(default = "default_server_settings")]
    pub server: Server,

    /// Configurações de autenticação `OAuth2` para clientes MCP.
    #[serde(default = "default_oauth_settings")]
    pub oauth: OAuth,

    /// Configurações de logging.
    #[serde(default = "default_logging_settings")]
    pub logging: Logging,

    /// Configurações de CORS (Cross-Origin Resource Sharing).
    #[serde(default = "default_cors_settings")]
    pub cors: Cors,

    /// Configurações de limitação de taxa (Rate Limiting).
    #[serde(default = "default_rate_limit_settings")]
    pub rate_limit: RateLimit,

    /// Configurações de tracing distribuído (OpenTelemetry).
    #[serde(default = "default_tracing_config_settings")]
    pub tracing: TracingConfig,
}

/// Configurações para a conexão com o servidor `TypeDB`.
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")] // Para o arquivo TOML
pub struct TypeDB {
    /// Endereço (host:porta) do servidor `TypeDB`.
    pub address: String,
    /// Nome de usuário para autenticação com `TypeDB`. Opcional.
    pub username: Option<String>,
    // A senha (TYPEDB_PASSWORD) é lida diretamente de variável de ambiente em main.rs
    // e não é armazenada nesta struct ou no arquivo de configuração por segurança.
    /// Habilita TLS para a conexão com `TypeDB`.
    pub tls_enabled: bool,
    /// Caminho para o arquivo PEM do certificado CA raiz para `TypeDB` TLS.
    /// Obrigatório se `tls_enabled` for true e o servidor `TypeDB` usar um CA não padrão.
    pub tls_ca_path: Option<String>,
}

fn default_typedb_settings() -> TypeDB {
    TypeDB {
        address: "localhost:1729".to_string(),
        username: Some("admin".to_string()),
        tls_enabled: false,
        tls_ca_path: None,
    }
}

/// Configurações para o servidor MCP.
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Server {
    /// Endereço de bind (IP:PORTA) para o servidor MCP.
    /// Ex: "0.0.0.0:8787" para HTTP, "0.0.0.0:8443" para HTTPS.
    pub bind_address: String,
    /// Habilita TLS (WSS) para o servidor MCP.
    pub tls_enabled: bool,
    /// Caminho para o arquivo PEM do certificado do servidor MCP (fullchain).
    /// Obrigatório se `tls_enabled` for true.
    pub tls_cert_path: Option<String>,
    /// Caminho para o arquivo PEM da chave privada do servidor MCP.
    /// Obrigatório se `tls_enabled` for true.
    pub tls_key_path: Option<String>,
    /// Número de threads worker para runtime Tokio.
    pub worker_threads: Option<usize>,
    /// Endereço para métricas Prometheus.
    pub metrics_bind_address: Option<String>,
    /// Path do endpoint WebSocket MCP.
    pub mcp_websocket_path: Option<String>,
    /// Path do endpoint de métricas.
    pub metrics_path: Option<String>,
}

fn default_server_settings() -> Server {
    // O bind_address default pode ser ajustado em main.rs com base em tls_enabled.
    Server {
        bind_address: "0.0.0.0:8787".to_string(),
        tls_enabled: false,
        tls_cert_path: None,
        tls_key_path: None,
        worker_threads: None,
        metrics_bind_address: None,
        mcp_websocket_path: None,
        metrics_path: None,
    }
}

/// Configurações de autenticação `OAuth2` para clientes MCP.
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct OAuth {
    /// Habilita la autenticación `OAuth2`.
    pub enabled: bool,
    /// URI del endpoint JWKS (JSON Web Key Set) del Authorization Server.
    /// Obligatorio si `enabled` es true.
    pub jwks_uri: Option<String>,
    /// Issuer(s) esperado(s) en el JWT. Si se define, el claim `iss` será validado.
    /// Puede ser una lista de strings en TOML: `issuer = ["https://auth1.example.com", "https://auth2.example.com"]`
    #[serde(default)]
    pub issuer: Option<Vec<String>>,
    /// Audience(s) esperado(s) en el JWT. Si se define, el claim `aud` será validado.
    /// Puede ser una lista de strings en TOML: `audience = ["api1", "typedb-mcp-server"]`
    #[serde(default)]
    pub audience: Option<Vec<String>>,
    /// Intervalo para recargar el JWKS. Ex: "1h", "30m", "3600s".
    #[serde(skip)] // Se salta a deserialização direta, se maneja manualmente.
    pub jwks_refresh_interval: Option<Duration>,
    /// Campo intermedio para deserialização del TOML/env. No usa default aquí.
    #[serde(rename = "jwks_refresh_interval")]
    pub jwks_refresh_interval_raw: Option<String>,
    /// Timeout para a requisición HTTP al buscar el JWKS. En segundos.
    pub jwks_request_timeout_seconds: Option<u64>,
    /// Escopos `OAuth2` que el token DEBE contener para acceso general.
    /// Ex: `required_scopes = ["mcp:access", "typedb:read"]` en TOML.
    #[serde(default)]
    pub required_scopes: Option<Vec<String>>,
}

fn default_oauth_settings() -> OAuth {
    OAuth {
        enabled: false,
        jwks_uri: None,
        issuer: None,
        audience: None,
        // Default para el campo Duration procesado
        jwks_refresh_interval: Some(Duration::from_secs(3600)),
        // Default para el campo raw String, usado si no hay valor en TOML/env
        jwks_refresh_interval_raw: Some("3600s".to_string()),
        jwks_request_timeout_seconds: Some(30),
        required_scopes: None,
    }
}

/// Configurações de logging.
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Logging {
    /// String de configuração para o `EnvFilter` do `tracing_subscriber`.
    /// Ex: "`info,typedb_mcp_server=debug,typedb_driver=warn`"
    pub rust_log: String,
}

fn default_logging_settings() -> Logging {
    Logging {
        rust_log: "info,typedb_mcp_server_lib=info,typedb_driver=info".to_string(),
    }
}

/// Configurações de CORS (Cross-Origin Resource Sharing).
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Cors {
    /// Lista de origens permitidas. Ex: `allowed_origins = ["http://localhost:3000", "https://app.example.com"]`.
    /// Usar `["*"]` para permitir todas as origens (não recomendado para produção).
    #[serde(default = "default_cors_allowed_origins")]
    pub allowed_origins: Vec<String>,
    // Outros campos como allowed_methods, allowed_headers, allow_credentials, max_age podem ser adicionados aqui.
    // Por enquanto, vamos manter simples e Axum pode ter defaults razoáveis ou podem ser configurados estaticamente.
}

fn default_cors_settings() -> Cors {
    Cors { allowed_origins: vec!["*".to_string()] }
}

fn default_cors_allowed_origins() -> Vec<String> {
    vec!["*".to_string()]
}

/// Configurações de limitação de taxa (Rate Limiting).
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RateLimit {
    /// Habilita o rate limiting.
    pub enabled: bool,
    /// Número de requisições permitidas por segundo.
    pub requests_per_second: Option<u64>,
    /// Número de requisições permitidas em um burst.
    pub burst_size: Option<u32>,
}

const fn default_rate_limit_settings() -> RateLimit {
    RateLimit {
        enabled: true,
        requests_per_second: Some(100), // Limite generoso
        burst_size: Some(200),
    }
}

/// Configurações para tracing distribuído (OpenTelemetry).
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TracingConfig {
    /// Habilita o tracing OpenTelemetry.
    pub enabled: bool,
    /// Endpoint do coletor OTLP (gRPC). Ex: "<http://localhost:4317>".
    /// Obrigatório se `enabled` for true.
    pub exporter_otlp_endpoint: Option<String>,
    /// Nome do serviço para OpenTelemetry.
    pub service_name: String,
    /// Estratégia de amostragem. Ex: "`always_on`", "`always_off`", "traceidratio".
    pub sampler: String,
    /// Argumento para o sampler. Ex: "1.0" para `always_on`, "0.1" para traceidratio.
    pub sampler_arg: String,
}

fn default_tracing_config_settings() -> TracingConfig {
    TracingConfig {
        enabled: false,
        exporter_otlp_endpoint: None,
        service_name: "typedb-mcp-server".to_string(),
        sampler: "always_on".to_string(),
        sampler_arg: "1.0".to_string(),
    }
}

impl Settings {
    /// Carrega as configurações da aplicação.
    ///
    /// A ordem de precedência é:
    /// 1. Valores padrão definidos no código.
    /// 2. Valores do arquivo de configuração (padrão: `typedb_mcp_server_config.toml`,
    ///    pode ser sobrescrito pela variável de ambiente `MCP_CONFIG_PATH`).
    /// 3. Valores de variáveis de ambiente (prefixo: `MCP_`, separador de aninhamento: `__`).
    ///
    /// # Retorna
    /// `Result<Self, ConfigError>` contendo as configurações carregadas ou um erro.
    ///
    /// # Errors
    ///
    /// Retorna `ConfigError` se houver um problema ao construir ou desserializar as configurações,
    /// como um arquivo de configuração malformado ou variáveis de ambiente inválidas.
    pub fn new() -> Result<Self, ConfigError> {
        // Log para depurar a variável de ambiente diretamente
        match std::env::var("MCP_TYPEDB__ADDRESS") {
            Ok(val) => tracing::info!("Variável de ambiente MCP_TYPEDB__ADDRESS encontrada: {}", val),
            Err(_) => tracing::warn!("Variável de ambiente MCP_TYPEDB__ADDRESS NÃO encontrada."),
        }
        match std::env::var("MCP_CONFIG_PATH") {
            Ok(val) => tracing::info!("Variável de ambiente MCP_CONFIG_PATH encontrada: {}", val),
            Err(_) => tracing::info!("Variável de ambiente MCP_CONFIG_PATH NÃO encontrada, usando default."),
        }

        let config_file_path = std::env::var("MCP_CONFIG_PATH")
            .unwrap_or_else(|_| DEFAULT_CONFIG_FILENAME.to_string());

        tracing::info!(
            "Carregando configurações. Arquivo: '{}', Prefixo Env: '{}', Separador Env: '{}'",
            config_file_path,
            ENV_PREFIX,
            ENV_SEPARATOR
        );

        let s = Config::builder()
            .add_source(
                ConfigFile::with_name(&config_file_path)
                    .required(false)
            )
            .add_source(
                Environment::with_prefix(ENV_PREFIX)
                    .separator(ENV_SEPARATOR)
                    .try_parsing(true)
                    .list_separator(",")
            )
            .build()?;

        let mut settings: Self = s.try_deserialize()?;
        // Workaround: Forçar precedência da variável de ambiente MCP_TYPEDB__ADDRESS
        if let Ok(addr_env) = std::env::var("MCP_TYPEDB__ADDRESS") {
            tracing::warn!("[WORKAROUND] Sobrescrevendo settings.typedb.address com valor da variável de ambiente MCP_TYPEDB__ADDRESS: {}", addr_env);
            settings.typedb.address = addr_env;
        }
        tracing::info!("[DEBUG MCP CONFIG] Valor final de settings.typedb.address: {}", settings.typedb.address);

        // Conversão manual del campo jwks_refresh_interval
        if let Some(ref raw_interval_str) = settings.oauth.jwks_refresh_interval_raw {
            match humantime::parse_duration(raw_interval_str) {
                Ok(duration) => settings.oauth.jwks_refresh_interval = Some(duration),
                Err(e) => {
                    return Err(ConfigError::Message(format!(
                        "Falha ao parsear jwks_refresh_interval ('{}'): {}",
                        raw_interval_str, e
                    )));
                }
            }
        } else {
            // Se jwks_refresh_interval_raw é None (não veio do TOML/Env),
            // usamos el default para jwks_refresh_interval (Duration).
            // El default para jwks_refresh_interval_raw en default_oauth_settings
            // asegura que si toda la sección oauth usa defaults, esto se maneje allí.
            // Este else es para el caso donde la sección oauth existe, pero el campo específico no.
            settings.oauth.jwks_refresh_interval = Some(Duration::from_secs(3600));
        }

        Ok(settings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    // Helper para criar um arquivo TOML temporário com conteúdo específico.
    fn create_temp_toml_config(content: &str) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut file = match tempfile::NamedTempFile::new() {
            Ok(f) => f,
            Err(e) => panic!("Failed to create temp file: {e}"),
        };
        if let Err(e) = write!(file, "{content}") {
            panic!("Failed to write to temp file: {e}");
        }
        if let Err(e) = file.flush() {
            panic!("Failed to flush temp file: {e}");
        }
        file
    }

    #[test]
    fn test_load_defaults_when_no_file_or_env_vars() {
        // Limpar/ignorar variáveis de ambiente para este teste, se possível,
        // ou garantir que não colidam com os nomes MCP_*.
        // A crate `config` usa os valores atuais do ambiente.
        // Para isolamento real, seria preciso mockar `std::env::var`.
        // Por ora, vamos assumir um ambiente limpo para este teste de default.

        // Simular ausência de MCP_CONFIG_PATH para usar o default (que não existirá)
        let original_mcp_config_path = env::var("MCP_CONFIG_PATH").ok();
        env::remove_var("MCP_CONFIG_PATH");
        // Simular ausência de outras variáveis MCP_*
        // (Isso é mais difícil de fazer de forma limpa sem afetar outros testes se rodados em paralelo)

        let settings = match Settings::new() {
            Ok(s) => s,
            Err(e) => panic!("Falha ao carregar configurações default: {e}"),
        };

        assert_eq!(settings.typedb.address, "localhost:1729");
        assert_eq!(settings.typedb.username, Some("admin".to_string()));
        assert!(!settings.typedb.tls_enabled);
        assert_eq!(settings.server.bind_address, "0.0.0.0:8787");
        assert!(!settings.oauth.enabled);
        assert_eq!(settings.logging.rust_log, "info,typedb_mcp_server_lib=info,typedb_driver=info");
        assert_eq!(settings.cors.allowed_origins, vec!["*".to_string()]);
        assert!(settings.rate_limit.enabled);
        assert_eq!(settings.rate_limit.requests_per_second, Some(100));
        assert!(!settings.tracing.enabled);
        assert_eq!(settings.tracing.service_name, "typedb-mcp-server");

        // Restaurar MCP_CONFIG_PATH se existia
        if let Some(path) = original_mcp_config_path {
            env::set_var("MCP_CONFIG_PATH", path);
        }
    }

    #[test]
    fn test_load_from_toml_file() {
        let toml_content = r#"
            [typedb]
            address = "my.typedb.host:1730"
            username = "test_user"
            tls_enabled = true
            tls_ca_path = "/path/to/ca.pem"

            [server]
            bind_address = "127.0.0.1:9000"

            [oauth]
            enabled = true
            jwks_uri = "http://jwks.local"
            issuer = ["issuer1", "issuer2"]
            audience = ["aud1"]
            jwks_refresh_interval = "30m"
            required_scopes = ["scope1", "scope2"]

            [logging]
            rust_log = "debug"

            [cors]
            allowed_origins = ["http://frontend.local"]

            [rate_limit]
            enabled = false

            [tracing]
            enabled = true
            exporter_otlp_endpoint = "http://otel.local:4317"
            service_name = "my-mcp-server"
            sampler = "traceidratio"
            sampler_arg = "0.5"
        "#;
        let temp_file = create_temp_toml_config(toml_content);
        env::set_var("MCP_CONFIG_PATH", temp_file.path());

        let settings = match Settings::new() {
            Ok(s) => s,
            Err(e) => panic!("Falha ao carregar config do TOML: {e}"),
        };

        assert_eq!(settings.typedb.address, "my.typedb.host:1730");
        assert_eq!(settings.typedb.username, Some("test_user".to_string()));
        assert!(settings.typedb.tls_enabled);
        assert_eq!(settings.typedb.tls_ca_path, Some("/path/to/ca.pem".to_string()));
        assert_eq!(settings.server.bind_address, "127.0.0.1:9000");
        assert!(settings.oauth.enabled);
        assert_eq!(settings.oauth.jwks_uri, Some("http://jwks.local".to_string()));
        assert_eq!(settings.oauth.issuer, Some(vec!["issuer1".to_string(), "issuer2".to_string()]));
        assert_eq!(settings.oauth.audience, Some(vec!["aud1".to_string()]));
        assert_eq!(settings.oauth.jwks_refresh_interval, Some(Duration::from_secs(30 * 60)));
        assert_eq!(settings.oauth.required_scopes, Some(vec!["scope1".to_string(), "scope2".to_string()]));
        assert_eq!(settings.logging.rust_log, "debug");
        assert_eq!(settings.cors.allowed_origins, vec!["http://frontend.local".to_string()]);
        assert!(!settings.rate_limit.enabled);
        assert!(settings.tracing.enabled);
        assert_eq!(settings.tracing.exporter_otlp_endpoint, Some("http://otel.local:4317".to_string()));
        assert_eq!(settings.tracing.service_name, "my-mcp-server");
        assert_eq!(settings.tracing.sampler, "traceidratio");
        assert_eq!(settings.tracing.sampler_arg, "0.5");

        env::remove_var("MCP_CONFIG_PATH"); // Limpeza
    }

    #[test]
    fn test_override_toml_with_env_vars() {
        let toml_content = r#"
                    [server]
                    # Valor do TOML
                    bind_address = "0.0.0.0:8080"
        
                    [oauth]
                    enabled = false
                    issuer = ["toml_issuer"]
                "#;
        let temp_file = create_temp_toml_config(toml_content);
        env::set_var("MCP_CONFIG_PATH", temp_file.path());

        // Variáveis de ambiente que devem sobrescrever o TOML
        env::set_var("MCP_SERVER__BIND_ADDRESS", "127.0.0.1:8888");
        env::set_var("MCP_OAUTH__ENABLED", "true");
        // Para Vec<String>, a crate config espera um formato como string JSON de array,
        // ou se `list_separator` for usado na fonte Environment, uma string separada por vírgula.
        // Vamos testar com o list_separator (vírgula por padrão, ou configurado).
        // Para Environment::list_separator(","), MCP_OAUTH__ISSUER="env_issuer1,env_issuer2"
        // Se não usar list_separator e quiser que o env var defina um array,
        // o valor do env var precisaria ser uma string que parece um array TOML/JSON:
        // MCP_OAUTH__ISSUER='["env_issuer1", "env_issuer2"]'
        // Para o nosso caso com `list_separator(",")` habilitado no `Environment::new()`:
        env::set_var("MCP_OAUTH__ISSUER", "env_issuer1,env_issuer2");


        let settings = match Settings::new() {
            Ok(s) => s,
            Err(e) => panic!("Falha ao carregar config com overrides de env: {e}"),
        };

        assert_eq!(settings.server.bind_address, "127.0.0.1:8888"); // Sobrescrito
        assert!(settings.oauth.enabled); // Sobrescrito
        assert_eq!(settings.oauth.issuer, Some(vec!["env_issuer1".to_string(), "env_issuer2".to_string()])); // Sobrescrito

        // Limpeza
        env::remove_var("MCP_CONFIG_PATH");
        env::remove_var("MCP_SERVER__BIND_ADDRESS");
        env::remove_var("MCP_OAUTH__ENABLED");
        env::remove_var("MCP_OAUTH__ISSUER");
    }

    #[test]
    fn test_partial_toml_uses_defaults() {
        let toml_content = r#"
            [typedb]
            address = "specific.typedb.host:1729"
            # Outros campos do typedb usarão default
        "#;
        let temp_file = create_temp_toml_config(toml_content);
        env::set_var("MCP_CONFIG_PATH", temp_file.path());

        let settings = match Settings::new() {
            Ok(s) => s,
            Err(e) => panic!("Falha ao carregar config parcial: {e}"),
        };

        // Valor do TOML
        assert_eq!(settings.typedb.address, "specific.typedb.host:1729");
        // Defaults do TypeDB
        assert_eq!(settings.typedb.username, default_typedb_settings().username);
        assert_eq!(settings.typedb.tls_enabled, default_typedb_settings().tls_enabled);
        // Defaults de outras seções
        assert_eq!(settings.server.bind_address, default_server_settings().bind_address);
        assert_eq!(settings.oauth.enabled, default_oauth_settings().enabled);

        env::remove_var("MCP_CONFIG_PATH");
    }

     #[test]
    fn test_humantime_duration_parsing() {
        let toml_content = r#"
            [oauth]
            enabled = false # necessário para que a seção [oauth] seja lida
            jwks_refresh_interval = "2h30m15s"
        "#;
        let temp_file = create_temp_toml_config(toml_content);
        env::set_var("MCP_CONFIG_PATH", temp_file.path());

        let settings = match Settings::new() {
            Ok(s) => s,
            Err(e) => panic!("Falha ao carregar config com duration: {e}"),
        };
        assert_eq!(
            settings.oauth.jwks_refresh_interval,
            Some(Duration::from_secs(2 * 3600 + 30 * 60 + 15))
        );

        env::remove_var("MCP_CONFIG_PATH");
    }

    #[test]
    fn test_humantime_duration_optional_field_not_present() {
        let toml_content = r#"
            [oauth]
            enabled = false
            # jwks_refresh_interval não está presente
        "#;
        let temp_file = create_temp_toml_config(toml_content);
        env::set_var("MCP_CONFIG_PATH", temp_file.path());

        let settings = match Settings::new() {
            Ok(s) => s,
            Err(e) => panic!("Falha ao carregar config sem duration opcional: {e}"),
        };
        // Verifica se o valor Duration processado é o default quando raw é None ou não parseável
        assert_eq!(settings.oauth.jwks_refresh_interval, Some(Duration::from_secs(3600)));

        env::remove_var("MCP_CONFIG_PATH");
    }

     #[test]
    fn test_vector_of_strings_from_toml_and_env() {
        let toml_content = r#"
            [oauth]
            enabled = false
            audience = ["aud_toml1", "aud_toml2"]
        "#;
        let temp_file = create_temp_toml_config(toml_content);
        env::set_var("MCP_CONFIG_PATH", temp_file.path());
        env::set_var("MCP_CORS__ALLOWED_ORIGINS", "http://env.origin1.com,http://env.origin2.com");

        let settings = match Settings::new() {
            Ok(s) => s,
            Err(e) => panic!("Falha ao carregar config com Vec<String>: {e}"),
        };

        assert_eq!(settings.oauth.audience, Some(vec!["aud_toml1".to_string(), "aud_toml2".to_string()]));
        assert_eq!(settings.cors.allowed_origins, vec!["http://env.origin1.com".to_string(), "http://env.origin2.com".to_string()]);

        env::remove_var("MCP_CONFIG_PATH");
        env::remove_var("MCP_CORS__ALLOWED_ORIGINS");
    }
}