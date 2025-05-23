// src/config.rs

// Licença Apache 2.0
// Copyright 2024 Guilherme Leste
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

//! Módulo de configuração para o Typedb-MCP-Server.
//!
//! Define as estruturas para carregar as configurações da aplicação a partir
//! de um arquivo TOML e/ou variáveis de ambiente. A precedência é:
//! 1. Valores padrão (definidos via `#[serde(default = "...")]` nas structs).
//! 2. Valores do arquivo de configuração (ex: `typedb_mcp_server_config.toml`).
//! 3. Valores de variáveis de ambiente (prefixadas com `MCP_` e usando `__` como separador para aninhamento).

use config::{Config, ConfigError, Environment, File as ConfigFile, FileFormat};
use serde::Deserialize;
#[allow(unused_imports)]
use serial_test::serial;
use std::{env, time::Duration};

/// Nome padrão do arquivo de configuração se `MCP_CONFIG_PATH` não estiver definida.
const DEFAULT_CONFIG_FILENAME: &str = "typedb_mcp_server_config.toml";
/// Prefixo para variáveis de ambiente que sobrescrevem as configurações do arquivo.
const ENV_PREFIX: &str = "MCP";
/// Separador usado em variáveis de ambiente para indicar aninhamento de configuração.
const ENV_SEPARATOR: &str = "__";

/// Estrutura principal que agrupa todas as configurações da aplicação.
///
/// Os valores são carregados de `Settings::new()`, respeitando a ordem de precedência.
/// Cada campo aqui representa uma seção no arquivo TOML e usa `#[serde(default = "...")]`
/// para garantir que uma estrutura padrão seja criada se a seção estiver ausente nas fontes.
#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    /// Configurações relacionadas à conexão com o servidor TypeDB.
    /// Corresponde à seção `[typedb]` no TOML.
    #[serde(default = "default_typedb_settings")]
    pub typedb: TypeDB,

    /// Configurações do servidor MCP (onde este servidor escuta e como opera).
    /// Corresponde à seção `[server]` no TOML.
    #[serde(default = "default_server_settings")]
    pub server: Server,

    /// Configurações de autenticação OAuth2 para clientes MCP.
    /// Corresponde à seção `[oauth]` no TOML.
    #[serde(default = "default_oauth_settings")]
    pub oauth: OAuth,

    /// Configurações de logging para a aplicação.
    /// Corresponde à seção `[logging]` no TOML.
    #[serde(default = "default_logging_settings")]
    pub logging: Logging,

    /// Configurações de CORS (Cross-Origin Resource Sharing).
    /// Corresponde à seção `[cors]` no TOML.
    #[serde(default = "default_cors_settings")]
    pub cors: Cors,

    /// Configurações de limitação de taxa (Rate Limiting).
    /// Corresponde à seção `[rate_limit]` no TOML.
    #[serde(default = "default_rate_limit_settings")]
    pub rate_limit: RateLimit,

    /// Configurações de tracing distribuído (OpenTelemetry).
    /// Corresponde à seção `[tracing]` no TOML.
    #[serde(default = "default_tracing_config_settings")]
    pub tracing: TracingConfig,
}

/// Configurações para a conexão com o servidor TypeDB.
/// Chaves TOML esperadas em `camelCase` (ex: `address`, `tlsEnabled`).
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TypeDB {
    /// Endereço (host:porta) do servidor TypeDB.
    /// Variável de Ambiente: `MCP_TYPEDB__ADDRESS`
    #[serde(default = "default_typedb_address")]
    pub address: String,
    /// Nome de usuário para autenticação com TypeDB. Opcional.
    /// Variável de Ambiente: `MCP_TYPEDB__USERNAME`
    #[serde(default = "default_typedb_username")]
    pub username: Option<String>,
    /// Habilita TLS para a conexão com TypeDB.
    /// Variável de Ambiente: `MCP_TYPEDB__TLS_ENABLED` (valor "true" ou "false")
    #[serde(default)] // Defaults para `false` se ausente
    pub tls_enabled: bool,
    /// Caminho para o arquivo PEM do certificado CA raiz para TypeDB TLS.
    /// Obrigatório se `tls_enabled` for true e o servidor TypeDB usar um CA não padrão.
    /// Variável de Ambiente: `MCP_TYPEDB__TLS_CA_PATH`
    #[serde(default)] // Defaults para `None` se ausente
    pub tls_ca_path: Option<String>,
}

fn default_typedb_address() -> String {
    "localhost:1729".to_string()
}
fn default_typedb_username() -> Option<String> {
    Some("admin".to_string())
}

/// Função para fornecer os valores padrão para a seção `TypeDB` se ela estiver ausente
/// no TOML/ENV ao desserializar `Settings`.
fn default_typedb_settings() -> TypeDB {
    TypeDB {
        address: default_typedb_address(),
        username: default_typedb_username(),
        tls_enabled: false,
        tls_ca_path: None,
    }
}

/// Configurações para o servidor MCP.
/// Chaves TOML esperadas em `camelCase` (ex: `bindAddress`, `tlsEnabled`).
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Server {
    /// Endereço de bind (IP:PORTA) para o servidor MCP.
    /// Variável de Ambiente: `MCP_SERVER__BIND_ADDRESS`
    #[serde(default = "default_server_bind_address", alias = "bind_address")]
    pub bind_address: String,
    /// Habilita TLS (HTTPS/WSS) para o servidor MCP.
    /// Variável de Ambiente: `MCP_SERVER__TLS_ENABLED`
    #[serde(default)]
    pub tls_enabled: bool,
    /// Caminho para o arquivo PEM do certificado do servidor MCP (fullchain).
    /// Obrigatório se `tls_enabled` for true.
    /// Variável de Ambiente: `MCP_SERVER__TLS_CERT_PATH`
    #[serde(default)]
    pub tls_cert_path: Option<String>,
    /// Caminho para o arquivo PEM da chave privada do servidor MCP.
    /// Obrigatório se `tls_enabled` for true.
    /// Variável de Ambiente: `MCP_SERVER__TLS_KEY_PATH`
    #[serde(default)]
    pub tls_key_path: Option<String>,
    /// Número de threads worker para o runtime Tokio. Se `None`, usa `num_cpus::get()`.
    /// Variável de Ambiente: `MCP_SERVER__WORKER_THREADS`
    #[serde(default)]
    pub worker_threads: Option<usize>,
    /// Endereço (IP:PORTA) para o endpoint de métricas Prometheus. Se `None`, `main.rs` usa "0.0.0.0:9090".
    /// Variável de Ambiente: `MCP_SERVER__METRICS_BIND_ADDRESS`
    #[serde(default)]
    pub metrics_bind_address: Option<String>,
    /// Path do endpoint WebSocket MCP. Se `None`, `main.rs` usa "/mcp/ws".
    /// Variável de Ambiente: `MCP_SERVER__MCP_WEBSOCKET_PATH`
    #[serde(default)]
    pub mcp_websocket_path: Option<String>,
    /// Path do endpoint de métricas. Se `None`, `main.rs` usa "/metrics".
    /// Variável de Ambiente: `MCP_SERVER__METRICS_PATH`
    #[serde(default)]
    pub metrics_path: Option<String>,
}

fn default_server_bind_address() -> String {
    "0.0.0.0:8787".to_string()
}

/// Função para fornecer os valores padrão para a seção `Server` se ela estiver ausente.
fn default_server_settings() -> Server {
    Server {
        bind_address: default_server_bind_address(),
        tls_enabled: false,
        tls_cert_path: None,
        tls_key_path: None,
        worker_threads: None,
        metrics_bind_address: None,
        mcp_websocket_path: None,
        metrics_path: None,
    }
}

/// Configurações de autenticação OAuth2 para clientes MCP.
/// Chaves TOML esperadas em `camelCase` (ex: `jwksUri`, `requiredScopes`).
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct OAuth {
    /// Habilita a autenticação OAuth2.
    /// Variável de Ambiente: `MCP_OAUTH__ENABLED`
    #[serde(default)]
    pub enabled: bool,
    /// URI do endpoint JWKS (JSON Web Key Set) do Authorization Server.
    /// Obrigatório se `enabled` for true.
    /// Variável de Ambiente: `MCP_OAUTH__JWKS_URI`
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// Issuer(s) esperado(s) no JWT. Pode ser uma lista.
    /// ENV: `MCP_OAUTH__ISSUER="https://auth1.example.com,https://auth2.example.com"`
    #[serde(default)]
    pub issuer: Option<Vec<String>>,
    /// Audience(s) esperado(s) no JWT. Pode ser uma lista.
    /// ENV: `MCP_OAUTH__AUDIENCE="api1,typedb-mcp-server"`
    #[serde(default)]
    pub audience: Option<Vec<String>>,
    /// Intervalo para recarregar o JWKS. Parsed de uma string `humantime`.
    /// Este campo é o resultado do parsing de `jwks_refresh_interval_raw`.
    #[serde(skip)]
    pub jwks_refresh_interval: Option<Duration>,
    /// Campo raw para `jwks_refresh_interval` lido do TOML/ENV (ex: "1h", "30m").
    /// Variável de Ambiente: `MCP_OAUTH__JWKS_REFRESH_INTERVAL`
    #[serde(rename = "jwksRefreshInterval", default = "default_oauth_jwks_refresh_interval_raw")]
    pub jwks_refresh_interval_raw: Option<String>,
    /// Timeout para a requisição HTTP ao buscar o JWKS, em segundos.
    /// Variável de Ambiente: `MCP_OAUTH__JWKS_REQUEST_TIMEOUT_SECONDS`
    #[serde(default = "default_oauth_jwks_request_timeout_seconds")]
    pub jwks_request_timeout_seconds: Option<u64>,
    /// Escopos OAuth2 que o token DEVE conter para acesso geral ao servidor.
    /// ENV: `MCP_OAUTH__REQUIRED_SCOPES="mcp:access,other:scope"`
    #[serde(default)]
    pub required_scopes: Option<Vec<String>>,
}

fn default_oauth_jwks_refresh_interval_raw() -> Option<String> {
    Some("1h".to_string())
}
fn default_oauth_jwks_request_timeout_seconds() -> Option<u64> {
    Some(30)
}

/// Função para fornecer os valores padrão para a seção `OAuth` se ela estiver ausente.
fn default_oauth_settings() -> OAuth {
    OAuth {
        enabled: false,
        jwks_uri: None,
        issuer: None,
        audience: None,
        jwks_refresh_interval: Some(Duration::from_secs(3600)),
        jwks_refresh_interval_raw: default_oauth_jwks_refresh_interval_raw(),
        jwks_request_timeout_seconds: default_oauth_jwks_request_timeout_seconds(),
        required_scopes: None,
    }
}

/// Configurações de logging da aplicação.
/// Chaves TOML esperadas em `camelCase` (ex: `rustLog`).
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Logging {
    /// String de configuração para o `EnvFilter` do `tracing_subscriber`.
    /// Variável de Ambiente: `MCP_LOGGING__RUST_LOG`
    #[serde(default = "default_logging_rust_log")]
    pub rust_log: String,
}

fn default_logging_rust_log() -> String {
    "info,typedb_mcp_server_lib=info,typedb_driver=info".to_string()
}

/// Função para fornecer os valores padrão para a seção `Logging` se ela estiver ausente.
fn default_logging_settings() -> Logging {
    Logging { rust_log: default_logging_rust_log() }
}

/// Configurações de CORS (Cross-Origin Resource Sharing).
/// Chaves TOML esperadas em `camelCase` (ex: `allowedOrigins`).
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Cors {
    /// Lista de origens permitidas. Usar `["*"]` para permitir todas.
    /// ENV: `MCP_CORS__ALLOWED_ORIGINS="http://localhost:3000,https://app.example.com"`
    #[serde(default = "default_cors_allowed_origins")]
    pub allowed_origins: Vec<String>,
}

fn default_cors_allowed_origins() -> Vec<String> {
    vec!["*".to_string()]
}

/// Função para fornecer os valores padrão para a seção `Cors` se ela estiver ausente.
fn default_cors_settings() -> Cors {
    Cors { allowed_origins: default_cors_allowed_origins() }
}

/// Configurações de limitação de taxa (Rate Limiting).
/// Chaves TOML esperadas em `camelCase` (ex: `requestsPerSecond`).
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RateLimit {
    /// Habilita o rate limiting.
    /// Variável de Ambiente: `MCP_RATE_LIMIT__ENABLED`
    #[serde(default = "default_rate_limit_enabled")]
    pub enabled: bool,
    /// Número de requisições permitidas por segundo, por IP.
    /// Variável de Ambiente: `MCP_RATE_LIMIT__REQUESTS_PER_SECOND`
    #[serde(default = "default_rate_limit_requests_per_second")]
    pub requests_per_second: Option<u64>,
    /// Número de requisições permitidas em um burst, por IP.
    /// Variável de Ambiente: `MCP_RATE_LIMIT__BURST_SIZE`
    #[serde(default = "default_rate_limit_burst_size")]
    pub burst_size: Option<u32>,
}

const fn default_rate_limit_enabled() -> bool {
    true
}
fn default_rate_limit_requests_per_second() -> Option<u64> {
    Some(100)
}
fn default_rate_limit_burst_size() -> Option<u32> {
    Some(200)
}

/// Função para fornecer os valores padrão para a seção `RateLimit` se ela estiver ausente.
fn default_rate_limit_settings() -> RateLimit {
    RateLimit {
        enabled: default_rate_limit_enabled(),
        requests_per_second: default_rate_limit_requests_per_second(),
        burst_size: default_rate_limit_burst_size(),
    }
}

/// Configurações para tracing distribuído (OpenTelemetry).
/// Chaves TOML esperadas em `camelCase` (ex: `exporterOtlpEndpoint`).
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TracingConfig {
    /// Habilita o tracing OpenTelemetry.
    /// Variável de Ambiente: `MCP_TRACING__ENABLED`
    #[serde(default)]
    pub enabled: bool,
    /// Endpoint do coletor OTLP (gRPC). Obrigatório se `enabled` for true.
    /// Variável de Ambiente: `MCP_TRACING__EXPORTER_OTLP_ENDPOINT`
    #[serde(default)]
    pub exporter_otlp_endpoint: Option<String>,
    /// Nome do serviço para OpenTelemetry.
    /// Variável de Ambiente: `MCP_TRACING__SERVICE_NAME`
    #[serde(default = "default_tracing_service_name")]
    pub service_name: String,
    /// Estratégia de amostragem. Ex: "always_on", "traceidratio".
    /// Variável de Ambiente: `MCP_TRACING__SAMPLER`
    #[serde(default = "default_tracing_sampler")]
    pub sampler: String,
    /// Argumento para o sampler. Ex: "0.1" para traceidratio.
    /// Variável de Ambiente: `MCP_TRACING__SAMPLER_ARG`
    #[serde(default = "default_tracing_sampler_arg")]
    pub sampler_arg: String,
}

fn default_tracing_service_name() -> String {
    "typedb-mcp-server".to_string()
}
fn default_tracing_sampler() -> String {
    "always_on".to_string()
}
fn default_tracing_sampler_arg() -> String {
    "1.0".to_string()
}

/// Função para fornecer os valores padrão para a seção `TracingConfig` se ela estiver ausente.
fn default_tracing_config_settings() -> TracingConfig {
    TracingConfig {
        enabled: false,
        exporter_otlp_endpoint: None,
        service_name: default_tracing_service_name(),
        sampler: default_tracing_sampler(),
        sampler_arg: default_tracing_sampler_arg(),
    }
}

impl Settings {
    /// Carrega as configurações da aplicação.
    ///
    /// A ordem de precedência é:
    /// 1. Defaults de `serde` (definidos nas structs).
    /// 2. Valores do arquivo de configuração (padrão: `typedb_mcp_server_config.toml`,
    ///    pode ser sobrescrito pela variável de ambiente `MCP_CONFIG_PATH`).
    /// 3. Valores de variáveis de ambiente (prefixo: `MCP_`, separador de aninhamento: `__`).
    ///
    /// # Retorna
    /// `Result<Self, ConfigError>` contendo as configurações carregadas ou um erro.
    pub fn new() -> Result<Self, ConfigError> {
        // (Removido: bloco duplicado de sobrescrita manual para Option<Vec<String>>: oauth.issuer)
        let config_file_path =
            env::var("MCP_CONFIG_PATH").unwrap_or_else(|_| DEFAULT_CONFIG_FILENAME.to_string());

        tracing::info!(
            "Carregando configurações. Arquivo de config: '{}', Prefixo Env: '{}', Separador Env: '{}'",
            config_file_path,
            ENV_PREFIX,
            ENV_SEPARATOR
        );

        // Construir a configuração a partir das fontes
        // A config-rs aplica os arquivos primeiro, depois as variáveis de ambiente.
        // A desserialização com `serde` então aplicará os `#[serde(default)]`
        // onde os campos não foram preenchidos por nenhuma fonte.
        let s = Config::builder()
            .add_source(
                ConfigFile::with_name(&config_file_path).format(FileFormat::Toml).required(false), // O arquivo é opcional
            )
            .add_source(
                Environment::with_prefix(ENV_PREFIX)
                    .separator(ENV_SEPARATOR)
                    .try_parsing(true) // Tenta parsear strings para bool/int/float
                    .list_separator(",") // Para `Vec<String>` de ENVs
                    .with_list_parse_key("oauth.issuer") // Especificar chaves que são listas
                    .with_list_parse_key("oauth.audience")
                    .with_list_parse_key("oauth.required_scopes")
                    .with_list_parse_key("cors.allowed_origins"),
            )
            .build()?;

        let mut settings: Self = s.try_deserialize()?;

        // Pós-processamento manual para garantir precedence ENV > TOML para campos sensíveis a case/alias
        // Só sobrescreve se a ENV estiver presente, não afeta defaults
        {
            // MCP_SERVER__BIND_ADDRESS ou MCP_SERVER__bindAddress
            if let Ok(val) = env::var("MCP_SERVER__BIND_ADDRESS") {
                tracing::info!("Sobrescrevendo server.bind_address via ENV: {}", val);
                settings.server.bind_address = val;
            } else if let Ok(val) = env::var("MCP_SERVER__bindAddress") {
                tracing::info!("Sobrescrevendo server.bind_address via ENV (camelCase): {}", val);
                settings.server.bind_address = val;
            }
            // MCP_OAUTH__ENABLED ou MCP_OAUTH__enabled
            if let Ok(val) = env::var("MCP_OAUTH__ENABLED") {
                let parsed = val == "true" || val == "1";
                tracing::info!("Sobrescrevendo oauth.enabled via ENV: {}", parsed);
                settings.oauth.enabled = parsed;
            } else if let Ok(val) = env::var("MCP_OAUTH__enabled") {
                let parsed = val == "true" || val == "1";
                tracing::info!("Sobrescrevendo oauth.enabled via ENV (camelCase): {}", parsed);
                settings.oauth.enabled = parsed;
            }
            // MCP_OAUTH__ISSUER ou MCP_OAUTH__issuer
            if let Ok(val) = env::var("MCP_OAUTH__ISSUER") {
                let parsed: Vec<String> = val
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                tracing::info!("Sobrescrevendo oauth.issuer via ENV: {:?}", parsed);
                settings.oauth.issuer = Some(parsed);
            } else if let Ok(val) = env::var("MCP_OAUTH__issuer") {
                let parsed: Vec<String> = val
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                tracing::info!("Sobrescrevendo oauth.issuer via ENV (camelCase): {:?}", parsed);
                settings.oauth.issuer = Some(parsed);
            }
        }

        // Sobrescrita manual para Option<Vec<String>>: oauth.issuer
        if let Ok(val) = env::var("MCP_OAUTH__ISSUER") {
            let parsed: Vec<String> =
                val.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
            tracing::info!("Sobrescrevendo oauth.issuer via ENV: {:?}", parsed);
            settings.oauth.issuer = Some(parsed);
        } else if let Ok(val) = env::var("MCP_OAUTH__issuer") {
            let parsed: Vec<String> =
                val.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
            tracing::info!("Sobrescrevendo oauth.issuer via ENV (camelCase): {:?}", parsed);
            settings.oauth.issuer = Some(parsed);
        }

        // Processamento manual para `jwks_refresh_interval_raw` -> `jwks_refresh_interval`
        // Este valor já deve ter sido populado pelo TOML, ENV ou o default raw string
        // que está em `default_oauth_settings` e é aplicado por `#[serde(default)]`.
        if let Some(ref raw_interval_str) = settings.oauth.jwks_refresh_interval_raw {
            match humantime::parse_duration(raw_interval_str) {
                Ok(duration) => settings.oauth.jwks_refresh_interval = Some(duration),
                Err(e) => {
                    // Se um valor raw foi fornecido (não o default da struct), e falha ao parsear, é um erro.
                    // Se settings.oauth.jwks_refresh_interval_raw == default_oauth_jwks_refresh_interval_raw()
                    // então já estamos usando o default, e o jwks_refresh_interval (Duration) já terá o seu default.
                    if Some(raw_interval_str.clone()) != default_oauth_jwks_refresh_interval_raw() {
                        return Err(ConfigError::Message(format!(
                            "Falha ao parsear 'oauth.jwksRefreshInterval' (valor: '{}'): {}",
                            raw_interval_str, e
                        )));
                    }
                    // Caso contrário, o default de Duration já foi setado por default_oauth_settings
                }
            }
        }
        // Se jwks_refresh_interval_raw é None, o jwks_refresh_interval (Option<Duration>)
        // já foi setado para o default pela função default_oauth_settings.

        tracing::info!("Configurações carregadas com sucesso.");
        tracing::debug!(config = ?settings, "Configurações finais da aplicação.");
        Ok(settings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn create_temp_toml_config(content: &str) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().expect("Failed to create temp file");
        write!(file, "{}", content).expect("Failed to write to temp file");
        file.flush().expect("Failed to flush temp file");
        file
    }

    // Limpar variáveis de ambiente de teste para isolamento

    /// Remove todas as variantes camelCase, snake_case e maiúsculas/minúsculas relevantes das variáveis de ambiente usadas nos testes de configuração.
    fn clear_test_env_vars() {
        let vars = [
            "MCP_CONFIG_PATH",
            "MCP_TYPEDB__ADDRESS",
            "MCP_TYPEDB__USERNAME",
            "MCP_TYPEDB__TLS_ENABLED",
            "MCP_TYPEDB__tlsEnabled",
            "MCP_SERVER__BIND_ADDRESS",
            "MCP_SERVER__bindAddress",
            "MCP_SERVER__TLS_ENABLED",
            "MCP_SERVER__tlsEnabled",
            "MCP_SERVER__TLS_CERT_PATH",
            "MCP_SERVER__TLS_KEY_PATH",
            "MCP_SERVER__WORKER_THREADS",
            "MCP_SERVER__METRICS_BIND_ADDRESS",
            "MCP_SERVER__MCP_WEBSOCKET_PATH",
            "MCP_OAUTH__ENABLED",
            "MCP_OAUTH__enabled",
            "MCP_OAUTH__ISSUER",
            "MCP_OAUTH__issuer",
            "MCP_OAUTH__JWKS_URI",
            "MCP_OAUTH__jwksUri",
            "MCP_OAUTH__JWKS_REFRESH_INTERVAL",
            "MCP_OAUTH__jwksRefreshInterval",
            "MCP_OAUTH__AUDIENCE",
            "MCP_OAUTH__audience",
            "MCP_OAUTH__REQUIRED_SCOPES",
            "MCP_OAUTH__requiredScopes",
            "MCP_CORS__ALLOWED_ORIGINS",
            "MCP_CORS__allowedOrigins",
            "MCP_LOGGING__RUST_LOG",
            "MCP_LOGGING__rustLog",
            "MCP_RATE_LIMIT__ENABLED",
            "MCP_RATE_LIMIT__enabled",
            "MCP_TRACING__ENABLED",
            "MCP_TRACING__enabled",
            "MCP_TRACING__EXPORTER_OTLP_ENDPOINT",
            "MCP_TRACING__exporterOtlpEndpoint",
            "MCP_TRACING__SERVICE_NAME",
            "MCP_TRACING__serviceName",
            "MCP_TRACING__SAMPLER",
            "MCP_TRACING__sampler",
            "MCP_TRACING__SAMPLER_ARG",
            "MCP_TRACING__samplerArg",
        ];
        for v in vars.iter() {
            env::remove_var(v);
        }
    }

    /// Guard RAII para garantir limpeza das variáveis de ambiente ao final do teste.
    struct EnvCleaner;
    impl EnvCleaner {
        fn new() -> Self {
            clear_test_env_vars();
            EnvCleaner
        }
    }
    impl Drop for EnvCleaner {
        fn drop(&mut self) {
            clear_test_env_vars();
        }
    }

    #[test]
    #[serial]
    fn test_load_defaults_when_no_file_or_env_vars() {
        let _env_cleaner = EnvCleaner::new();
        let settings = Settings::new().expect("Falha ao carregar configurações default");

        assert_eq!(settings.typedb.address, default_typedb_address());
        assert_eq!(settings.typedb.username, default_typedb_username());
        assert_eq!(settings.typedb.tls_enabled, false);
        assert_eq!(settings.server.bind_address, default_server_bind_address());
        assert_eq!(settings.oauth.enabled, false);
        assert_eq!(settings.oauth.jwks_refresh_interval, Some(Duration::from_secs(3600)));
        assert_eq!(
            settings.oauth.jwks_refresh_interval_raw,
            default_oauth_jwks_refresh_interval_raw()
        );
        assert_eq!(settings.logging.rust_log, default_logging_rust_log());
        assert_eq!(settings.cors.allowed_origins, default_cors_allowed_origins());
        assert_eq!(settings.rate_limit.enabled, default_rate_limit_enabled());
        assert_eq!(
            settings.rate_limit.requests_per_second,
            default_rate_limit_requests_per_second()
        );
        assert_eq!(settings.tracing.enabled, false);
        assert_eq!(settings.tracing.service_name, default_tracing_service_name());
    }

    #[test]
    #[serial]
    fn test_load_from_toml_file_with_camel_case_keys() {
        let _env_cleaner = EnvCleaner::new();
        let toml_content = r#"
            [typedb]
            address = "my.typedb.host:1730"
            username = "test_user"
            tlsEnabled = true
            tlsCaPath = "/path/to/ca.pem"

            [server]
            bindAddress = "127.0.0.1:9000"

            [oauth]
            enabled = true
            jwksUri = "http://jwks.local"
            issuer = ["issuer1", "issuer2"]
            audience = ["aud1"]
            jwksRefreshInterval = "30m"
            requiredScopes = ["scope1", "scope2"]

            [logging]
            rustLog = "debug"

            [cors]
            allowedOrigins = ["http://frontend.local"]

            [rate_limit]
            enabled = false

            [tracing]
            enabled = true
            exporterOtlpEndpoint = "http://otel.local:4317"
            serviceName = "my-mcp-server"
            sampler = "traceidratio"
            samplerArg = "0.5"
        "#;
        let temp_file = create_temp_toml_config(toml_content);
        env::set_var("MCP_CONFIG_PATH", temp_file.path());

        let settings = Settings::new().expect("Falha ao carregar config do TOML");

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
        assert_eq!(
            settings.oauth.required_scopes,
            Some(vec!["scope1".to_string(), "scope2".to_string()])
        );
        assert_eq!(settings.logging.rust_log, "debug");
        assert_eq!(settings.cors.allowed_origins, vec!["http://frontend.local".to_string()]);
        assert!(!settings.rate_limit.enabled);
        assert!(settings.tracing.enabled);
        assert_eq!(
            settings.tracing.exporter_otlp_endpoint,
            Some("http://otel.local:4317".to_string())
        );
        assert_eq!(settings.tracing.service_name, "my-mcp-server");
        assert_eq!(settings.tracing.sampler, "traceidratio");
        assert_eq!(settings.tracing.sampler_arg, "0.5");
    }

    #[test]
    #[serial]
    fn test_override_toml_with_env_vars_respects_camel_case_in_struct() {
        clear_test_env_vars();
        let toml_content = r#"
            [server]
            bindAddress = "0.0.0.0:8080" # TOML key em camelCase

            [oauth]
            enabled = false
            issuer = ["toml_issuer"]
        "#;
        let temp_file = create_temp_toml_config(toml_content);
        env::set_var("MCP_CONFIG_PATH", temp_file.path());

        env::set_var("MCP_SERVER__BIND_ADDRESS", "127.0.0.1:8888");
        env::set_var("MCP_SERVER__bindAddress", "127.0.0.1:8888");
        env::set_var("MCP_OAUTH__ENABLED", "true");
        env::set_var("MCP_OAUTH__ISSUER", "env_issuer1,env_issuer2");

        let settings = Settings::new().expect("Falha ao carregar config com overrides de env");

        assert_eq!(settings.server.bind_address, "127.0.0.1:8888");
        assert!(settings.oauth.enabled);
        assert_eq!(
            settings.oauth.issuer,
            Some(vec!["env_issuer1".to_string(), "env_issuer2".to_string()])
        );
    }

    #[test]
    #[serial]
    fn test_partial_toml_uses_defaults_and_respects_camel_case() {
        let _env_cleaner = EnvCleaner::new();
        let toml_content = r#"
            [typedb]
            address = "specific.typedb.host:1729" # Chave TOML em camelCase (indireto, via rename_all)
            # username não definido, deve usar default_typedb_username
            # tlsEnabled não definido, deve usar default (false)
        "#;
        let temp_file = create_temp_toml_config(toml_content);
        env::set_var("MCP_CONFIG_PATH", temp_file.path());

        let settings = Settings::new().expect("Falha ao carregar config parcial");

        assert_eq!(settings.typedb.address, "specific.typedb.host:1729");
        assert_eq!(settings.typedb.username, default_typedb_username());
        assert_eq!(settings.typedb.tls_enabled, false);
        assert_eq!(settings.server.bind_address, default_server_bind_address());
    }

    #[test]
    #[serial]
    fn test_jwks_refresh_interval_parsing_from_raw_string() {
        let _env_cleaner = EnvCleaner::new();
        let toml_content = r#"
            [oauth]
            jwksRefreshInterval = "15m"
        "#;
        let temp_file = create_temp_toml_config(toml_content);
        env::set_var("MCP_CONFIG_PATH", temp_file.path());

        let settings = Settings::new().expect("Falha ao carregar config com jwksRefreshInterval");
        assert_eq!(settings.oauth.jwks_refresh_interval, Some(Duration::from_secs(15 * 60)));
        assert_eq!(settings.oauth.jwks_refresh_interval_raw, Some("15m".to_string()));
    }

    #[test]
    #[serial]
    fn test_jwks_refresh_interval_uses_default_if_raw_is_absent_in_toml_and_env() {
        let _env_cleaner = EnvCleaner::new();
        let toml_content = r#"
            [oauth]
            enabled = false 
            # jwksRefreshInterval (ou jwks_refresh_interval_raw) não está presente
        "#;
        let temp_file = create_temp_toml_config(toml_content);
        env::set_var("MCP_CONFIG_PATH", temp_file.path());

        let settings =
            Settings::new().expect("Falha ao carregar config sem jwksRefreshInterval raw");

        assert_eq!(
            settings.oauth.jwks_refresh_interval,
            default_oauth_settings().jwks_refresh_interval
        );
        assert_eq!(
            settings.oauth.jwks_refresh_interval_raw,
            default_oauth_settings().jwks_refresh_interval_raw
        );
    }

    #[test]
    #[serial]
    fn test_jwks_refresh_interval_parsing_error_from_invalid_raw_string_in_toml() {
        let _env_cleaner = EnvCleaner::new();
        let toml_content = r#"
            [oauth]
            jwksRefreshInterval = "invalid-duration"
        "#;
        let temp_file = create_temp_toml_config(toml_content);
        env::set_var("MCP_CONFIG_PATH", temp_file.path());

        let result = Settings::new();
        assert!(result.is_err(), "Esperado erro ao parsear 'invalid-duration', mas Settings::new() retornou Ok. Detalhe: {:?}", result.ok());
        if let Err(ConfigError::Message(msg)) = result {
            assert!(msg.contains("Falha ao parsear 'oauth.jwksRefreshInterval'"));
            assert!(msg.contains("invalid-duration"));
        } else {
            panic!(
                "Esperado ConfigError::Message para duration inválida, obteve {:?}",
                result.err()
            );
        }
    }
}
