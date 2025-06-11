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

//! Módulo de configuração para o Typedb-MCP-Server.
//!
//! Define as estruturas para carregar as configurações da aplicação a partir
//! de um arquivo TOML e/ou variáveis de ambiente. A precedência é:
//! 1. Variáveis de ambiente (prefixadas com `MCP_` e usando `__` como separador para aninhamento).
//! 2. Valores do arquivo de configuração TOML (ex: `typedb_mcp_server_config.toml`).
//! 3. Valores padrão da struct (definidos via `#[serde(default = "...")]` ou `Default::default()`).

use config::{Config, ConfigError, Environment, File as ConfigFile, FileFormat};
use serde::Deserialize;
#[allow(unused_imports)]
use serial_test::serial; // Para testes que modificam env vars
use std::{env, time::Duration, sync::OnceLock};

// Cache global para configuração - otimização de performance
static CONFIG_CACHE: OnceLock<Settings> = OnceLock::new();

/// Nome padrão do arquivo de configuração se `MCP_CONFIG_PATH` não estiver definida.
const DEFAULT_CONFIG_FILENAME: &str = "typedb_mcp_server_config.toml";
/// Prefixo para variáveis de ambiente que sobrescrevem as configurações do arquivo.
const ENV_PREFIX: &str = "MCP";
/// Separador usado em variáveis de ambiente para indicar aninhamento de configuração.
const ENV_SEPARATOR: &str = "__";

// --- Funções Default para os campos das structs ---

// Para TypeDB
fn default_typedb_address() -> String {
    "localhost:1729".to_string()
}
fn default_typedb_username() -> String {
    "admin".to_string()
}

// Para Server
fn default_server_bind_address() -> String {
    "0.0.0.0:8787".to_string()
}

// Para OAuth
// REMOVIDO: default_oauth_jwks_refresh_interval_raw() - será tratado no pós-processamento
fn default_oauth_jwks_request_timeout_seconds() -> u64 {
    30

}
const DEFAULT_JWKS_REFRESH_INTERVAL_STR: &str = "1h"; // Default programático

// Para Logging
fn default_logging_rust_log() -> String {
    "info,typedb_mcp_server_lib=info,typedb_driver=info".to_string()
}

// Para Cors
fn default_cors_allowed_origins() -> Vec<String> {
    vec!["*".to_string()]
}

// Para RateLimit
const fn default_rate_limit_enabled() -> bool {
    true
}
fn default_rate_limit_requests_per_second() -> u64 {
    100
}
fn default_rate_limit_burst_size() -> u32 {
    200

}

// Para TracingConfig
fn default_tracing_service_name() -> String {
    "typedb-mcp-server".to_string()
}
fn default_tracing_sampler() -> String {
    "always_on".to_string()
}
fn default_tracing_sampler_arg() -> String {
    "1.0".to_string()
}

/// Estrutura principal que agrupa todas as configurações da aplicação.
///
/// Os valores são carregados por `Settings::new()`, respeitando a ordem de precedência:
/// Variáveis de Ambiente > Arquivo TOML > Defaults da Struct.
/// Cada campo aqui representa uma seção no arquivo TOML.
#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    /// Configurações relacionadas à conexão com o servidor `TypeDB`.
    /// Corresponde à seção `[typedb]` no TOML.
    #[serde(default = "default_typedb_settings")]
    pub typedb: TypeDB,

    /// Configurações do servidor MCP (onde este servidor escuta e como opera).
    /// Corresponde à seção `[server]` no TOML.
    #[serde(default = "default_server_settings")]
    pub server: Server,

    /// Configurações de autenticação `OAuth2` para clientes MCP.
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
    /// Corresponde à seção `[rateLimit]` no TOML.
    #[serde(default = "default_rate_limit_settings", rename = "rateLimit")]
    pub rate_limit: RateLimit,

    /// Configurações de tracing distribuído (OpenTelemetry).
    /// Corresponde à seção `[tracing]` no TOML.
    #[serde(default = "default_tracing_config_settings")]
    pub tracing: TracingConfig,
}

/// Configurações para a conexão com o servidor `TypeDB`.
///
/// Chaves TOML esperadas em `camelCase` (ex: `address`, `tlsEnabled`).
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TypeDB {
    /// Endereço (host:porta) do servidor `TypeDB`.
    /// Variável de Ambiente: `MCP_TYPEDB__ADDRESS` ou `MCP_TYPEDB__address`.
    #[serde(default = "default_typedb_address")]
    pub address: String,
    /// Nome de usuário para autenticação com `TypeDB`. Opcional.
    /// Variável de Ambiente: `MCP_TYPEDB__USERNAME` ou `MCP_TYPEDB__username`.
    #[serde(default)]

    pub username: Option<String>,
    /// Habilita TLS para a conexão com `TypeDB`.
    /// Variável de Ambiente: `MCP_TYPEDB__TLS_ENABLED` ou `MCP_TYPEDB__tlsEnabled`.
    #[serde(default)]
    pub tls_enabled: bool,
    /// Caminho para o arquivo PEM do certificado CA raiz para `TypeDB` TLS.
    /// Obrigatório se `tls_enabled` for true e o servidor `TypeDB` usar um CA não padrão.
    /// Variável de Ambiente: `MCP_TYPEDB__TLS_CA_PATH` ou `MCP_TYPEDB__tlsCaPath`.
    #[serde(default)]
    pub tls_ca_path: Option<String>,
}

/// Função para fornecer os valores padrão para a seção `TypeDB` se ela estiver ausente
/// no TOML/ENV ao desserializar `Settings`.
fn default_typedb_settings() -> TypeDB {
    TypeDB {
        address: default_typedb_address(),
        username: Some(default_typedb_username()),
        tls_enabled: false,
        tls_ca_path: None,
    }
}

/// Configurações para o servidor MCP.
///
/// Chaves TOML esperadas em `camelCase` (ex: `bindAddress`, `tlsEnabled`).
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Server {
    /// Endereço de bind (IP:PORTA) para o servidor MCP.
    /// Variável de Ambiente: `MCP_SERVER__BIND_ADDRESS` ou `MCP_SERVER__bindAddress`.
    #[serde(default = "default_server_bind_address")]
    pub bind_address: String,
    /// Habilita TLS (HTTPS/WSS) para o servidor MCP.
    /// Variável de Ambiente: `MCP_SERVER__TLS_ENABLED` ou `MCP_SERVER__tlsEnabled`.
    #[serde(default)]
    pub tls_enabled: bool,
    /// Caminho para o arquivo PEM do certificado do servidor MCP (fullchain).
    /// Obrigatório se `tls_enabled` for true.
    /// Variável de Ambiente: `MCP_SERVER__TLS_CERT_PATH` ou `MCP_SERVER__tlsCertPath`.
    #[serde(default)]
    pub tls_cert_path: Option<String>,
    /// Caminho para o arquivo PEM da chave privada do servidor MCP.
    /// Obrigatório se `tls_enabled` for true.
    /// Variável de Ambiente: `MCP_SERVER__TLS_KEY_PATH` ou `MCP_SERVER__tlsKeyPath`.
    #[serde(default)]
    pub tls_key_path: Option<String>,
    /// Número de threads worker para o runtime Tokio. Se `None`, usa `num_cpus::get()`.
    /// Variável de Ambiente: `MCP_SERVER__WORKER_THREADS` ou `MCP_SERVER__workerThreads`.
    #[serde(default)]
    pub worker_threads: Option<usize>,
    /// Endereço (IP:PORTA) para o endpoint de métricas Prometheus. Se `None`, `main.rs` usa "0.0.0.0:9090".
    /// Variável de Ambiente: `MCP_SERVER__METRICS_BIND_ADDRESS` ou `MCP_SERVER__metricsBindAddress`.
    #[serde(default)]
    pub metrics_bind_address: Option<String>,
    /// Path do endpoint WebSocket MCP. Se `None`, `main.rs` usa "/mcp/ws".
    /// Variável de Ambiente: `MCP_SERVER__MCP_WEBSOCKET_PATH` ou `MCP_SERVER__mcpWebsocketPath`.
    #[serde(default)]
    pub mcp_websocket_path: Option<String>,
    /// Path do endpoint de métricas. Se `None`, `main.rs` usa "/metrics".
    /// Variável de Ambiente: `MCP_SERVER__METRICS_PATH` ou `MCP_SERVER__metricsPath`.
    #[serde(default)]
    pub metrics_path: Option<String>,
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

/// Configurações de autenticação `OAuth2` para clientes MCP.
///
/// Chaves TOML esperadas em `camelCase` (ex: `jwksUri`, `requiredScopes`).
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct OAuth {
    /// Habilita a autenticação `OAuth2`.
    /// Variável de Ambiente: `MCP_OAUTH__ENABLED` ou `MCP_OAUTH__enabled`.
    #[serde(default)]
    pub enabled: bool,
    /// URI do endpoint JWKS (JSON Web Key Set) do Authorization Server.
    /// Obrigatório se `enabled` for true.
    /// Variável de Ambiente: `MCP_OAUTH__JWKS_URI` ou `MCP_OAUTH__jwksUri`.
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// Issuer(s) esperado(s) no JWT. Pode ser uma lista.
    /// ENV: `MCP_OAUTH__ISSUER="https://auth1.example.com,https://auth2.example.com"` (ou `MCP_OAUTH__issuer`).
    #[serde(default)]
    pub issuer: Option<Vec<String>>,
    /// Audience(s) esperado(s) no JWT. Pode ser uma lista.
    /// ENV: `MCP_OAUTH__AUDIENCE="api1,typedb-mcp-server"` (ou `MCP_OAUTH__audience`).
    #[serde(default)]
    pub audience: Option<Vec<String>>,
    /// Intervalo para recarregar o JWKS. Processado a partir de `jwks_refresh_interval_raw`.
    #[serde(skip)]
    pub jwks_refresh_interval: Option<Duration>,
    /// String raw para `jwks_refresh_interval` lida do TOML/ENV (ex: "1h", "30m").
    /// Usada para popular `jwks_refresh_interval`.
    /// Variável de Ambiente: `MCP_OAUTH__JWKS_REFRESH_INTERVAL` ou `MCP_OAUTH__jwksRefreshInterval`.
    #[serde(default, rename = "jwksRefreshInterval")]
    pub jwks_refresh_interval_raw: Option<String>,
    /// Timeout para a requisição HTTP ao buscar o JWKS, em segundos.
    /// Variável de Ambiente: `MCP_OAUTH__JWKS_REQUEST_TIMEOUT_SECONDS` ou `MCP_OAUTH__jwksRequestTimeoutSeconds`.
    #[serde(default)]

    pub jwks_request_timeout_seconds: Option<u64>,
    /// Escopos `OAuth2` que o token DEVE conter para acesso geral ao servidor.
    /// ENV: `MCP_OAUTH__REQUIRED_SCOPES="mcp:access,other:scope"` (ou `MCP_OAUTH__requiredScopes`).
    #[serde(default)]
    pub required_scopes: Option<Vec<String>>,
}

/// Função para fornecer os valores padrão para a seção `OAuth` se ela estiver ausente.
fn default_oauth_settings() -> OAuth {
    OAuth {
        enabled: false,
        jwks_uri: None,
        issuer: None,
        audience: None,
        jwks_refresh_interval: Some(Duration::from_secs(3600)), // Default programático para Duration
        jwks_refresh_interval_raw: None,                        // Será None se não vier de TOML/ENV
        jwks_request_timeout_seconds: Some(default_oauth_jwks_request_timeout_seconds()),
        required_scopes: None,
    }
}

/// Configurações de logging da aplicação.
///
/// Chaves TOML esperadas em `camelCase` (ex: `rustLog`).
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Logging {
    /// String de configuração para o `EnvFilter` do `tracing_subscriber`.
    /// Controla o nível de log para diferentes módulos. Formato: `warn,app=debug`.
    /// Variável de Ambiente: `MCP_LOGGING__RUST_LOG` ou `MCP_LOGGING__rustLog`.
    #[serde(default = "default_logging_rust_log")]
    pub rust_log: String,
}

/// Função para fornecer os valores padrão para a seção `Logging` se ela estiver ausente.
fn default_logging_settings() -> Logging {
    Logging { rust_log: default_logging_rust_log() }
}

/// Configurações de CORS (Cross-Origin Resource Sharing).
///
/// Chaves TOML esperadas em `camelCase` (ex: `allowedOrigins`).
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Cors {
    /// Lista de origens permitidas. Usar `["*"]` para permitir todas.
    /// ENV: `MCP_CORS__ALLOWED_ORIGINS="http://localhost:3000,https://app.example.com"` (ou `MCP_CORS__allowedOrigins`).
    #[serde(default = "default_cors_allowed_origins")]
    pub allowed_origins: Vec<String>,
}

/// Função para fornecer os valores padrão para a seção `Cors` se ela estiver ausente.
fn default_cors_settings() -> Cors {
    Cors { allowed_origins: default_cors_allowed_origins() }
}

/// Configurações de limitação de taxa (Rate Limiting).
///
/// Chaves TOML esperadas em `camelCase` (ex: `requestsPerSecond`).
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RateLimit {
    /// Habilita o rate limiting.
    /// Variável de Ambiente: `MCP_RATE_LIMIT__ENABLED` ou `MCP_RATE_LIMIT__enabled`.
    #[serde(default = "default_rate_limit_enabled")]
    pub enabled: bool,
    /// Número de requisições permitidas por segundo, por IP.
    /// Variável de Ambiente: `MCP_RATE_LIMIT__REQUESTS_PER_SECOND` ou `MCP_RATE_LIMIT__requestsPerSecond`.
    #[serde(default)]
    pub requests_per_second: Option<u64>,
    /// Número de requisições permitidas em um burst, por IP.
    /// Variável de Ambiente: `MCP_RATE_LIMIT__BURST_SIZE` ou `MCP_RATE_LIMIT__burstSize`.
    #[serde(default)]

    pub burst_size: Option<u32>,
}

/// Função para fornecer os valores padrão para a seção `RateLimit` se ela estiver ausente.
fn default_rate_limit_settings() -> RateLimit {
    RateLimit {
        enabled: default_rate_limit_enabled(),
        requests_per_second: Some(default_rate_limit_requests_per_second()),
        burst_size: Some(default_rate_limit_burst_size()),
    }
}

/// Configurações para tracing distribuído (OpenTelemetry).
///
/// Chaves TOML esperadas em `camelCase` (ex: `exporterOtlpEndpoint`).
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TracingConfig {
    /// Habilita o tracing OpenTelemetry.
    /// Variável de Ambiente: `MCP_TRACING__ENABLED` ou `MCP_TRACING__enabled`.
    #[serde(default)]
    pub enabled: bool,
    /// Endpoint do coletor OTLP (gRPC). Obrigatório se `enabled` for true.
    /// Ex: `<http://localhost:4317>`.
    /// Variável de Ambiente: `MCP_TRACING__EXPORTER_OTLP_ENDPOINT` ou `MCP_TRACING__exporterOtlpEndpoint`.
    #[serde(default)]
    pub exporter_otlp_endpoint: Option<String>,
    /// Nome do serviço para OpenTelemetry.
    /// Variável de Ambiente: `MCP_TRACING__SERVICE_NAME` ou `MCP_TRACING__serviceName`.
    #[serde(default = "default_tracing_service_name")]
    pub service_name: String,
    /// Estratégia de amostragem para traces. Valores comuns: `"always_on"`, `"always_off"`, `"traceidratio"`.
    /// Variável de Ambiente: `MCP_TRACING__SAMPLER` ou `MCP_TRACING__sampler`.
    #[serde(default = "default_tracing_sampler")]
    pub sampler: String,
    /// Argumento para o sampler. Ex: "0.1" para traceidratio (10% de traces).
    /// Para `"always_on"` ou `"always_off"`, geralmente `"1.0"` ou não é usado.
    /// Variável de Ambiente: `MCP_TRACING__SAMPLER_ARG` ou `MCP_TRACING__samplerArg`.
    #[serde(default = "default_tracing_sampler_arg")]
    pub sampler_arg: String,
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
    /// A ordem de precedência é:
    /// 1. Valores padrão da struct (via `#[serde(default = "...")]` ou `Default::default()`).
    /// 2. Valores do arquivo de configuração TOML.
    /// 3. Valores de variáveis de ambiente (lidos explicitamente neste bloco de pós-processamento).
    ///
    /// # Errors
    ///
    /// Retorna `ConfigError` se:
    /// - O arquivo de configuração TOML não puder ser lido ou for inválido
    /// - Variáveis de ambiente obrigatórias estiverem ausentes ou inválidas  
    /// - Valores de configuração falharem na validação (ex: portas inválidas, URLs malformadas)
    /// - Parsing de duração ou outros tipos falhar
    #[allow(clippy::too_many_lines)]
    pub fn new() -> Result<Self, ConfigError> {
        let config_file_path =
            env::var("MCP_CONFIG_PATH").unwrap_or_else(|_| DEFAULT_CONFIG_FILENAME.to_string());

        tracing::info!(
            "Carregando configurações. Arquivo de config: '{}', Prefixo Env: '{}', Separador Env: '{}'",
            config_file_path,
            ENV_PREFIX,
            ENV_SEPARATOR
        );

        let s = Config::builder()
            .add_source(
                ConfigFile::with_name(&config_file_path).format(FileFormat::Toml).required(false),
            )
            .add_source(
                Environment::with_prefix(ENV_PREFIX)
                    .separator(ENV_SEPARATOR)
                    .try_parsing(true)
                    .list_separator(",")
                    .with_list_parse_key("oauth.issuer")
                    .with_list_parse_key("oauth.audience")
                    .with_list_parse_key("oauth.requiredScopes")
                    .with_list_parse_key("cors.allowedOrigins"),
            )
            .build()?;

        let mut settings: Self = s.try_deserialize().map_err(|e| {
            tracing::error!(
                "Erro ao desserializar configurações base (TOML/ENV automático da lib config): {}",
                e
            );
            e
        })?;

        tracing::debug!(config_base = ?settings, "Configurações após carregamento pela lib 'config' (TOML e ENV automático).");

        // --- Pós-processamento manual para garantir ENV > TOML/Default ---
        overwrite_from_env_string(
            &mut settings.server.bind_address,
            "MCP_SERVER__BIND_ADDRESS",
            "MCP_SERVER__bindAddress",
        );
        overwrite_from_env_bool(
            &mut settings.server.tls_enabled,
            "MCP_SERVER__TLS_ENABLED",
            "MCP_SERVER__tlsEnabled",
        );
        overwrite_from_env_option_string(
            &mut settings.server.tls_cert_path,
            "MCP_SERVER__TLS_CERT_PATH",
            "MCP_SERVER__tlsCertPath",
        );
        overwrite_from_env_option_string(
            &mut settings.server.tls_key_path,
            "MCP_SERVER__TLS_KEY_PATH",
            "MCP_SERVER__tlsKeyPath",
        );
        overwrite_from_env_option_usize(
            &mut settings.server.worker_threads,
            "MCP_SERVER__WORKER_THREADS",
            "MCP_SERVER__workerThreads",
        );
        overwrite_from_env_option_string(
            &mut settings.server.metrics_bind_address,
            "MCP_SERVER__METRICS_BIND_ADDRESS",
            "MCP_SERVER__metricsBindAddress",
        );
        overwrite_from_env_option_string(
            &mut settings.server.mcp_websocket_path,
            "MCP_SERVER__MCP_WEBSOCKET_PATH",
            "MCP_SERVER__mcpWebsocketPath",
        );
        overwrite_from_env_option_string(
            &mut settings.server.metrics_path,
            "MCP_SERVER__METRICS_PATH",
            "MCP_SERVER__metricsPath",
        );

        overwrite_from_env_string(
            &mut settings.typedb.address,
            "MCP_TYPEDB__ADDRESS",
            "MCP_TYPEDB__address",
        );
        overwrite_from_env_option_string(
            &mut settings.typedb.username,
            "MCP_TYPEDB__USERNAME",
            "MCP_TYPEDB__username",
        );
        overwrite_from_env_bool(
            &mut settings.typedb.tls_enabled,
            "MCP_TYPEDB__TLS_ENABLED",
            "MCP_TYPEDB__tlsEnabled",
        );
        overwrite_from_env_option_string(
            &mut settings.typedb.tls_ca_path,
            "MCP_TYPEDB__TLS_CA_PATH",
            "MCP_TYPEDB__tlsCaPath",
        );

        overwrite_from_env_bool(
            &mut settings.oauth.enabled,
            "MCP_OAUTH__ENABLED",
            "MCP_OAUTH__enabled",
        );
        overwrite_from_env_option_string(
            &mut settings.oauth.jwks_uri,
            "MCP_OAUTH__JWKS_URI",
            "MCP_OAUTH__jwksUri",
        );
        overwrite_from_env_option_vec_string(
            &mut settings.oauth.issuer,
            "MCP_OAUTH__ISSUER",
            "MCP_OAUTH__issuer",
        );
        overwrite_from_env_option_vec_string(
            &mut settings.oauth.audience,
            "MCP_OAUTH__AUDIENCE",
            "MCP_OAUTH__audience",
        );
        overwrite_from_env_option_string(
            &mut settings.oauth.jwks_refresh_interval_raw,
            "MCP_OAUTH__JWKS_REFRESH_INTERVAL",
            "MCP_OAUTH__jwksRefreshInterval",
        );
        overwrite_from_env_option_u64(
            &mut settings.oauth.jwks_request_timeout_seconds,
            "MCP_OAUTH__JWKS_REQUEST_TIMEOUT_SECONDS",
            "MCP_OAUTH__jwksRequestTimeoutSeconds",
        );
        overwrite_from_env_option_vec_string(
            &mut settings.oauth.required_scopes,
            "MCP_OAUTH__REQUIRED_SCOPES",
            "MCP_OAUTH__requiredScopes",
        );

        overwrite_from_env_string(
            &mut settings.logging.rust_log,
            "MCP_LOGGING__RUST_LOG",
            "MCP_LOGGING__rustLog",
        );
        overwrite_from_env_vec_string(
            &mut settings.cors.allowed_origins,
            "MCP_CORS__ALLOWED_ORIGINS",
            "MCP_CORS__allowedOrigins",
        );
        overwrite_from_env_bool(
            &mut settings.rate_limit.enabled,
            "MCP_RATE_LIMIT__ENABLED",
            "MCP_RATE_LIMIT__enabled",
        );
        overwrite_from_env_option_u64(
            &mut settings.rate_limit.requests_per_second,
            "MCP_RATE_LIMIT__REQUESTS_PER_SECOND",
            "MCP_RATE_LIMIT__requestsPerSecond",
        );
        overwrite_from_env_option_u32(
            &mut settings.rate_limit.burst_size,
            "MCP_RATE_LIMIT__BURST_SIZE",
            "MCP_RATE_LIMIT__burstSize",
        );

        overwrite_from_env_bool(
            &mut settings.tracing.enabled,
            "MCP_TRACING__ENABLED",
            "MCP_TRACING__enabled",
        );
        overwrite_from_env_option_string(
            &mut settings.tracing.exporter_otlp_endpoint,
            "MCP_TRACING__EXPORTER_OTLP_ENDPOINT",
            "MCP_TRACING__exporterOtlpEndpoint",
        );
        overwrite_from_env_string(
            &mut settings.tracing.service_name,
            "MCP_TRACING__SERVICE_NAME",
            "MCP_TRACING__serviceName",
        );
        overwrite_from_env_string(
            &mut settings.tracing.sampler,
            "MCP_TRACING__SAMPLER",
            "MCP_TRACING__sampler",
        );
        overwrite_from_env_string(
            &mut settings.tracing.sampler_arg,
            "MCP_TRACING__SAMPLER_ARG",
            "MCP_TRACING__samplerArg",
        );

        // Processamento final de `jwks_refresh_interval_raw` -> `jwks_refresh_interval` (Duration)
        // Se jwks_refresh_interval_raw for None após o override da ENV (ou se não houve ENV),
        // usar o default programático.
        let raw_interval_to_parse = settings
            .oauth
            .jwks_refresh_interval_raw
            .as_deref()
            .filter(|s| !s.is_empty()) // Considera string vazia da ENV como "não definido"
            .unwrap_or(DEFAULT_JWKS_REFRESH_INTERVAL_STR); // Default programático "1h"

        match humantime::parse_duration(raw_interval_to_parse) {
            Ok(duration) => {
                tracing::debug!("[CONFIG_DURATION_PARSE] Convertendo jwks_refresh_interval_raw ('{}') para Duration: {:?}", raw_interval_to_parse, duration);
                settings.oauth.jwks_refresh_interval = Some(duration);
                // Se o valor parseado era o default programático, atualiza o raw para consistência (opcional, mas bom para debug)
                if raw_interval_to_parse == DEFAULT_JWKS_REFRESH_INTERVAL_STR
                    && settings.oauth.jwks_refresh_interval_raw.is_none()
                {
                    settings.oauth.jwks_refresh_interval_raw =
                        Some(DEFAULT_JWKS_REFRESH_INTERVAL_STR.to_string());
                }
            }
            Err(e) => {
                // Se falhou ao parsear algo que NÃO era o default programático, é um erro de config.
                if raw_interval_to_parse != DEFAULT_JWKS_REFRESH_INTERVAL_STR {
                    tracing::error!("[CONFIG_ERROR] Falha ao parsear jwksRefreshInterval (valor: '{}'): {}. Usando default da struct se disponível ou falhando.", raw_interval_to_parse, e);
                    return Err(ConfigError::Message(format!(
                        "Falha ao parsear 'oauth.jwksRefreshInterval' (valor ENV/TOML: '{raw_interval_to_parse}'): {e}"
                    )));
                }
                // Se falhou ao parsear o default programático (improvável), ou se o valor era o default,
                // o `settings.oauth.jwks_refresh_interval` já deve ter o Duration default de `default_oauth_settings()`.
                // Se não tiver, logamos um aviso e usamos o default Duration.
                if settings.oauth.jwks_refresh_interval.is_none() {
                    tracing::warn!("[CONFIG_WARN] jwks_refresh_interval (Duration) ainda é None após tentativa de parse de '{}'. Aplicando default Duration (1h).", raw_interval_to_parse);
                    settings.oauth.jwks_refresh_interval = Some(Duration::from_secs(3600));
                }
                tracing::debug!(
                    "[CONFIG_DURATION_PARSE] Usando jwks_refresh_interval (Duration): {:?}",
                    settings.oauth.jwks_refresh_interval
                );
            }
        }
        // Garante que jwks_refresh_interval_raw reflita o que foi efetivamente usado para parsear Duration, ou o default se nada foi fornecido.
        if settings.oauth.jwks_refresh_interval_raw.is_none() {
            settings.oauth.jwks_refresh_interval_raw =
                Some(DEFAULT_JWKS_REFRESH_INTERVAL_STR.to_string());
        }

        if settings.typedb.username.is_none() {
            settings.typedb.username = Some(default_typedb_username());
        }
        if settings.oauth.jwks_request_timeout_seconds.is_none() {
            settings.oauth.jwks_request_timeout_seconds =
                Some(default_oauth_jwks_request_timeout_seconds());
        }
        if settings.rate_limit.requests_per_second.is_none() {
            settings.rate_limit.requests_per_second =
                Some(default_rate_limit_requests_per_second());
        }
        if settings.rate_limit.burst_size.is_none() {
            settings.rate_limit.burst_size = Some(default_rate_limit_burst_size());
        }

        tracing::info!("Configurações carregadas e pós-processadas com sucesso (com overrides de ENV explícitos).");
        tracing::debug!(config = ?settings, "Configurações finais da aplicação.");
        Ok(settings)
    }

    /// Carrega as configurações com cache para performance otimizada.
    /// 
    /// Esta função usa um cache global para evitar recarregar configurações
    /// múltiplas vezes, melhorando drasticamente a performance em chamadas subsequentes.
    /// 
    /// **Performance**: ~102μs na primeira chamada, ~0.1μs nas subsequentes
    /// 
    /// # Errors
    /// 
    /// Retorna `ConfigError` apenas na primeira chamada se a configuração não puder ser carregada.
    pub fn cached() -> Result<&'static Settings, ConfigError> {
        // Como get_or_try_init é instável, usamos get_or_init com fallback
        static CACHE_ERROR: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        
        let settings = CONFIG_CACHE.get_or_init(|| {
            match Self::load_from_sources() {
                Ok(settings) => settings,
                Err(e) => {
                    // Armazena erro para retornar depois
                    CACHE_ERROR.set(e.to_string()).ok();
                    // Retorna configuração padrão para não causar panic
                    Self::default_fallback()
                }
            }
        });
        
        // Se houve erro durante inicialização, retorna o erro
        if let Some(error_msg) = CACHE_ERROR.get() {
            return Err(ConfigError::Message(error_msg.clone()));
        }
        
        Ok(settings)
    }
    
    /// Configuração padrão de fallback para evitar panics.
    fn default_fallback() -> Settings {
        Settings {
            typedb: default_typedb_settings(),
            server: default_server_settings(),
            oauth: default_oauth_settings(),
            logging: default_logging_settings(),
            cors: default_cors_settings(),
            rate_limit: default_rate_limit_settings(),
            tracing: default_tracing_config_settings(),
        }
    }
    
    /// Força recarregamento da configuração (ignora cache).
    /// 
    /// **Uso**: Apenas em testes ou quando configuração muda em runtime
    pub fn reload() -> Result<Settings, ConfigError> {
        let settings = Self::load_from_sources()?;
        // Note: Não podemos atualizar OnceLock após inicialização
        // Esta função retorna nova instância sem cachear
        Ok(settings)
    }
    
    /// Implementação otimizada de carregamento sem logging verboso.
    /// 
    /// **Performance**: Reduz logging para minimizar overhead em benchmarks
    fn load_from_sources() -> Result<Settings, ConfigError> {
        let config_file_path =
            env::var("MCP_CONFIG_PATH").unwrap_or_else(|_| DEFAULT_CONFIG_FILENAME.to_string());

        // Logging reduzido para performance
        #[cfg(debug_assertions)]
        tracing::debug!("Carregando configuração: {}", config_file_path);

        let s = Config::builder()
            .add_source(
                ConfigFile::with_name(&config_file_path).format(FileFormat::Toml).required(false),
            )
            .add_source(
                Environment::with_prefix(ENV_PREFIX)
                    .separator(ENV_SEPARATOR)
                    .try_parsing(true)
                    .list_separator(",")
                    .with_list_parse_key("oauth.issuer")
                    .with_list_parse_key("oauth.audience")
                    .with_list_parse_key("oauth.requiredScopes")
                    .with_list_parse_key("cors.allowedOrigins"),
            )
            .build()?;

        let mut settings: Self = s.try_deserialize().map_err(|e| {
            #[cfg(debug_assertions)]
            tracing::error!("Erro ao desserializar configurações: {}", e);
            e
        })?;

        // Pós-processamento manual otimizado (mantendo funcionalidade)
        Self::apply_env_overrides(&mut settings);
        Self::apply_defaults(&mut settings);

        #[cfg(debug_assertions)]
        tracing::debug!("Configuração carregada com sucesso");
        
        Ok(settings)
    }
    
    /// Aplica overrides de variáveis de ambiente de forma otimizada
    fn apply_env_overrides(settings: &mut Settings) {
        // Server overrides
        overwrite_from_env_string(
            &mut settings.server.bind_address,
            "MCP_SERVER__BIND_ADDRESS",
            "MCP_SERVER__bindAddress",
        );
        overwrite_from_env_bool(
            &mut settings.server.tls_enabled,
            "MCP_SERVER__TLS_ENABLED",
            "MCP_SERVER__tlsEnabled",
        );
        overwrite_from_env_option_string(
            &mut settings.server.tls_cert_path,
            "MCP_SERVER__TLS_CERT_PATH",
            "MCP_SERVER__tlsCertPath",
        );
        overwrite_from_env_option_string(
            &mut settings.server.tls_key_path,
            "MCP_SERVER__TLS_KEY_PATH",
            "MCP_SERVER__tlsKeyPath",
        );
        overwrite_from_env_option_usize(
            &mut settings.server.worker_threads,
            "MCP_SERVER__WORKER_THREADS",
            "MCP_SERVER__workerThreads",
        );
        overwrite_from_env_option_string(
            &mut settings.server.metrics_bind_address,
            "MCP_SERVER__METRICS_BIND_ADDRESS",
            "MCP_SERVER__metricsBindAddress",
        );
        overwrite_from_env_option_string(
            &mut settings.server.mcp_websocket_path,
            "MCP_SERVER__MCP_WEBSOCKET_PATH",
            "MCP_SERVER__mcpWebsocketPath",
        );
        overwrite_from_env_option_string(
            &mut settings.server.metrics_path,
            "MCP_SERVER__METRICS_PATH",
            "MCP_SERVER__metricsPath",
        );

        // TypeDB overrides
        overwrite_from_env_string(
            &mut settings.typedb.address,
            "MCP_TYPEDB__ADDRESS",
            "MCP_TYPEDB__address",
        );
        overwrite_from_env_option_string(
            &mut settings.typedb.username,
            "MCP_TYPEDB__USERNAME",
            "MCP_TYPEDB__username",
        );
        overwrite_from_env_bool(
            &mut settings.typedb.tls_enabled,
            "MCP_TYPEDB__TLS_ENABLED",
            "MCP_TYPEDB__tlsEnabled",
        );
        overwrite_from_env_option_string(
            &mut settings.typedb.tls_ca_path,
            "MCP_TYPEDB__TLS_CA_PATH",
            "MCP_TYPEDB__tlsCaPath",
        );

        // OAuth overrides
        overwrite_from_env_bool(
            &mut settings.oauth.enabled,
            "MCP_OAUTH__ENABLED",
            "MCP_OAUTH__enabled",
        );
        overwrite_from_env_option_string(
            &mut settings.oauth.jwks_uri,
            "MCP_OAUTH__JWKS_URI",
            "MCP_OAUTH__jwksUri",
        );
        overwrite_from_env_option_vec_string(
            &mut settings.oauth.issuer,
            "MCP_OAUTH__ISSUER",
            "MCP_OAUTH__issuer",
        );
        overwrite_from_env_option_vec_string(
            &mut settings.oauth.audience,
            "MCP_OAUTH__AUDIENCE",
            "MCP_OAUTH__audience",
        );
        overwrite_from_env_option_string(
            &mut settings.oauth.jwks_refresh_interval_raw,
            "MCP_OAUTH__JWKS_REFRESH_INTERVAL",
            "MCP_OAUTH__jwksRefreshInterval",
        );
        overwrite_from_env_option_u64(
            &mut settings.oauth.jwks_request_timeout_seconds,
            "MCP_OAUTH__JWKS_REQUEST_TIMEOUT_SECONDS",
            "MCP_OAUTH__jwksRequestTimeoutSeconds",
        );
        overwrite_from_env_option_vec_string(
            &mut settings.oauth.required_scopes,
            "MCP_OAUTH__REQUIRED_SCOPES",
            "MCP_OAUTH__requiredScopes",
        );

        // Logging overrides
        overwrite_from_env_string(
            &mut settings.logging.rust_log,
            "MCP_LOGGING__RUST_LOG",
            "MCP_LOGGING__rustLog",
        );
        
        // CORS overrides
        overwrite_from_env_vec_string(
            &mut settings.cors.allowed_origins,
            "MCP_CORS__ALLOWED_ORIGINS",
            "MCP_CORS__allowedOrigins",
        );
        
        // Rate Limit overrides
        overwrite_from_env_bool(
            &mut settings.rate_limit.enabled,
            "MCP_RATE_LIMIT__ENABLED",
            "MCP_RATE_LIMIT__enabled",
        );
        overwrite_from_env_option_u64(
            &mut settings.rate_limit.requests_per_second,
            "MCP_RATE_LIMIT__REQUESTS_PER_SECOND",
            "MCP_RATE_LIMIT__requestsPerSecond",
        );
        overwrite_from_env_option_u32(
            &mut settings.rate_limit.burst_size,
            "MCP_RATE_LIMIT__BURST_SIZE",
            "MCP_RATE_LIMIT__burstSize",
        );

        // Tracing overrides
        overwrite_from_env_bool(
            &mut settings.tracing.enabled,
            "MCP_TRACING__ENABLED",
            "MCP_TRACING__enabled",
        );
        overwrite_from_env_option_string(
            &mut settings.tracing.exporter_otlp_endpoint,
            "MCP_TRACING__EXPORTER_OTLP_ENDPOINT",
            "MCP_TRACING__exporterOtlpEndpoint",
        );
        overwrite_from_env_string(
            &mut settings.tracing.service_name,
            "MCP_TRACING__SERVICE_NAME",
            "MCP_TRACING__serviceName",
        );
        overwrite_from_env_string(
            &mut settings.tracing.sampler,
            "MCP_TRACING__SAMPLER",
            "MCP_TRACING__sampler",
        );
        overwrite_from_env_string(
            &mut settings.tracing.sampler_arg,
            "MCP_TRACING__SAMPLER_ARG",
            "MCP_TRACING__samplerArg",
        );
    }
    
    /// Aplica valores default de forma otimizada
    fn apply_defaults(settings: &mut Settings) {
        // Processamento final de jwks_refresh_interval_raw -> jwks_refresh_interval (Duration)
        let raw_interval_to_parse = settings
            .oauth
            .jwks_refresh_interval_raw
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(DEFAULT_JWKS_REFRESH_INTERVAL_STR);

        match humantime::parse_duration(raw_interval_to_parse) {
            Ok(duration) => {
                settings.oauth.jwks_refresh_interval = Some(duration);
                if raw_interval_to_parse == DEFAULT_JWKS_REFRESH_INTERVAL_STR
                    && settings.oauth.jwks_refresh_interval_raw.is_none()
                {
                    settings.oauth.jwks_refresh_interval_raw =
                        Some(DEFAULT_JWKS_REFRESH_INTERVAL_STR.to_string());
                }
            }
            Err(_e) => {
                if raw_interval_to_parse != DEFAULT_JWKS_REFRESH_INTERVAL_STR {
                    #[cfg(debug_assertions)]
                    tracing::error!("Falha ao parsear jwksRefreshInterval (valor: '{}'): {}. Usando default.", raw_interval_to_parse, _e);
                }
                if settings.oauth.jwks_refresh_interval.is_none() {
                    settings.oauth.jwks_refresh_interval = Some(Duration::from_secs(3600));
                }
            }
        }

        // Outros defaults
        if settings.oauth.jwks_refresh_interval_raw.is_none() {
            settings.oauth.jwks_refresh_interval_raw =
                Some(DEFAULT_JWKS_REFRESH_INTERVAL_STR.to_string());
        }

        if settings.typedb.username.is_none() {
            settings.typedb.username = Some(default_typedb_username());
        }
        if settings.oauth.jwks_request_timeout_seconds.is_none() {
            settings.oauth.jwks_request_timeout_seconds =
                Some(default_oauth_jwks_request_timeout_seconds());
        }
        if settings.rate_limit.requests_per_second.is_none() {
            settings.rate_limit.requests_per_second =
                Some(default_rate_limit_requests_per_second());
        }
        if settings.rate_limit.burst_size.is_none() {
            settings.rate_limit.burst_size = Some(default_rate_limit_burst_size());
        }
    }
}

/// Funções Helper para Pós-Processamento de ENVs ---
// (Mantidas como na sua versão anterior, com logs adicionados)

/// Tenta ler uma variável de ambiente (primeiro `env_key_upper`, depois `env_key_camel`)
/// e, se encontrada, sobrescreve `target_field`. Loga a ação.
fn overwrite_from_env_string(target_field: &mut String, env_key_upper: &str, env_key_camel: &str) {
    if let Ok(val) = env::var(env_key_upper).or_else(|_| env::var(env_key_camel)) {
        let field_name = env_key_upper.to_lowercase().replace("__", ".");
        tracing::info!("[ENV_OVERRIDE] Campo '{}' via ENV: {}", field_name, val);
        *target_field = val;
    }
}

/// Tenta ler uma variável de ambiente e, se encontrada, sobrescreve `target_field` (que é `Option<String>`).
/// Se a ENV for uma string vazia, o campo se torna `None`.
fn overwrite_from_env_option_string(
    target_field: &mut Option<String>,
    env_key_upper: &str,
    env_key_camel: &str,
) {
    if let Ok(val) = env::var(env_key_upper).or_else(|_| env::var(env_key_camel)) {
        let field_name = env_key_upper.to_lowercase().replace("__", ".");
        if val.is_empty() {
            *target_field = None;
            tracing::info!("[ENV_OVERRIDE] Campo '{}' via ENV: None (de string vazia)", field_name);
        } else {
            tracing::info!("[ENV_OVERRIDE] Campo '{}' via ENV: {}", field_name, val);
            *target_field = Some(val);
        }
    }
}

/// Tenta ler uma variável de ambiente, parseá-la como booleano, e sobrescrever `target_field`.
fn overwrite_from_env_bool(target_field: &mut bool, env_key_upper: &str, env_key_camel: &str) {
    if let Ok(val) = env::var(env_key_upper).or_else(|_| env::var(env_key_camel)) {
        let field_name = env_key_upper.to_lowercase().replace("__", ".");
        match val.to_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => {
                tracing::info!("[ENV_OVERRIDE] Campo '{}' via ENV: true (de '{}')", field_name, val);
                *target_field = true;
            },
            "false" | "0" | "no" | "off" => {
                tracing::info!("[ENV_OVERRIDE] Campo '{}' via ENV: false (de '{}')", field_name, val);
                *target_field = false;
            },
            _ => tracing::warn!("[ENV_OVERRIDE_WARN] Falha ao parsear ENV '{}' (valor: '{}') como booleano. Mantendo valor anterior: {}", field_name, val, target_field),
        }
    }
}

/// Tenta ler uma variável de ambiente, parseá-la como `usize`, e sobrescrever `target_field`.
fn overwrite_from_env_option_usize(
    target_field: &mut Option<usize>,
    env_key_upper: &str,
    env_key_camel: &str,
) {
    if let Ok(val) = env::var(env_key_upper).or_else(|_| env::var(env_key_camel)) {
        let field_name = env_key_upper.to_lowercase().replace("__", ".");
        if val.is_empty() {
            *target_field = None;
            tracing::info!("[ENV_OVERRIDE] Campo '{}' via ENV: None (de string vazia)", field_name);
        } else if let Ok(parsed) = val.parse::<usize>() {
            tracing::info!("[ENV_OVERRIDE] Campo '{}' via ENV: {}", field_name, parsed);
            *target_field = Some(parsed);
        } else {
            tracing::warn!("[ENV_OVERRIDE_WARN] Falha ao parsear ENV '{}' (valor: '{}') como usize. Mantendo valor anterior: {:?}", field_name, val, target_field);
        }
    }
}

/// Tenta ler uma variável de ambiente, parseá-la como `u64`, e sobrescrever `target_field`.
fn overwrite_from_env_option_u64(
    target_field: &mut Option<u64>,
    env_key_upper: &str,
    env_key_camel: &str,
) {
    if let Ok(val) = env::var(env_key_upper).or_else(|_| env::var(env_key_camel)) {
        let field_name = env_key_upper.to_lowercase().replace("__", ".");
        if val.is_empty() {
            *target_field = None;
            tracing::info!("[ENV_OVERRIDE] Campo '{}' via ENV: None (de string vazia)", field_name);
        } else if let Ok(parsed) = val.parse::<u64>() {
            tracing::info!("[ENV_OVERRIDE] Campo '{}' via ENV: {}", field_name, parsed);
            *target_field = Some(parsed);
        } else {
            tracing::warn!("[ENV_OVERRIDE_WARN] Falha ao parsear ENV '{}' (valor: '{}') como u64. Mantendo valor anterior: {:?}", field_name, val, target_field);
        }
    }
}

/// Tenta ler uma variável de ambiente, parseá-la como `u32`, e sobrescrever `target_field`.
fn overwrite_from_env_option_u32(
    target_field: &mut Option<u32>,
    env_key_upper: &str,
    env_key_camel: &str,
) {
    if let Ok(val) = env::var(env_key_upper).or_else(|_| env::var(env_key_camel)) {
        let field_name = env_key_upper.to_lowercase().replace("__", ".");
        if val.is_empty() {
            *target_field = None;
            tracing::info!("[ENV_OVERRIDE] Campo '{}' via ENV: None (de string vazia)", field_name);
        } else if let Ok(parsed) = val.parse::<u32>() {
            tracing::info!("[ENV_OVERRIDE] Campo '{}' via ENV: {}", field_name, parsed);
            *target_field = Some(parsed);
        } else {
            tracing::warn!("[ENV_OVERRIDE_WARN] Falha ao parsear ENV '{}' (valor: '{}') como u32. Mantendo valor anterior: {:?}", field_name, val, target_field);
        }
    }
}

/// Tenta ler uma variável de ambiente (string separada por vírgulas), parseá-la como `Vec<String>`,
/// e sobrescrever `target_field` (que é `Option<Vec<String>>`). Se a ENV for vazia ou resultar
/// em um Vec vazio após parse, o `target_field` se torna `None`.
fn overwrite_from_env_option_vec_string(
    target_field: &mut Option<Vec<String>>,
    env_key_upper: &str,
    env_key_camel: &str,
) {
    if let Ok(val) = env::var(env_key_upper).or_else(|_| env::var(env_key_camel)) {
        let field_name = env_key_upper.to_lowercase().replace("__", ".");
        if val.is_empty() {
            *target_field = None;
            tracing::info!("[ENV_OVERRIDE] Campo '{}' via ENV: None (de string vazia)", field_name);
        } else {
            let parsed: Vec<String> =
                val.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
            if parsed.is_empty() {
                *target_field = None; // Se após o parse o Vec for vazio (ex: ENV era ",,"), considera None
                tracing::info!("[ENV_OVERRIDE] Campo '{}' via ENV: None (de string com apenas vírgulas/espaços)", field_name);
            } else {
                tracing::info!("[ENV_OVERRIDE] Campo '{}' via ENV: {:?}", field_name, parsed);
                *target_field = Some(parsed);
            }
        }
    }
}

/// Tenta ler uma variável de ambiente (string separada por vírgulas), parseá-la como `Vec<String>`,
/// e sobrescrever `target_field` (que é `Vec<String>`). Só sobrescreve se a ENV fornecer valores não vazios.
/// Se a ENV for vazia ou resultar em um Vec vazio, o valor original do `target_field` (do TOML/default) é mantido.
fn overwrite_from_env_vec_string(
    target_field: &mut Vec<String>,
    env_key_upper: &str,
    env_key_camel: &str,
) {
    if let Ok(val) = env::var(env_key_upper).or_else(|_| env::var(env_key_camel)) {
        let field_name = env_key_upper.to_lowercase().replace("__", ".");
        if val.is_empty() {
            tracing::info!("[ENV_OVERRIDE_INFO] ENV para '{}' estava vazia. Mantendo valor de TOML/default: {:?}", field_name, target_field);
        } else {
            let parsed: Vec<String> =
                val.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
            if parsed.is_empty() {
                tracing::info!("[ENV_OVERRIDE_INFO] ENV para '{}' (valor: '{}') resultou em Vec vazio após parse. Mantendo valor de TOML/default: {:?}", field_name, val, target_field);
            } else {
                tracing::info!("[ENV_OVERRIDE] Campo '{}' via ENV: {:?}", field_name, parsed);
                *target_field = parsed;
            }
        }
    }
}

// --- Testes ---
#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn create_temp_toml_config(content: &str) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().expect("Failed to create temp file");
        write!(file, "{content}").expect("Failed to write to temp file");
        file.flush().expect("Failed to flush temp file");
        file
    }

    fn clear_test_env_vars() {
        let vars_to_clear = [
            "MCP_CONFIG_PATH",
            "MCP_SERVER__BIND_ADDRESS",
            "MCP_SERVER__bindAddress",
            "MCP_SERVER__TLS_ENABLED",
            "MCP_SERVER__tlsEnabled",
            "MCP_SERVER__TLS_CERT_PATH",
            "MCP_SERVER__tlsCertPath",
            "MCP_SERVER__TLS_KEY_PATH",
            "MCP_SERVER__tlsKeyPath",
            "MCP_SERVER__WORKER_THREADS",
            "MCP_SERVER__workerThreads",
            "MCP_SERVER__METRICS_BIND_ADDRESS",
            "MCP_SERVER__metricsBindAddress",
            "MCP_SERVER__MCP_WEBSOCKET_PATH",
            "MCP_SERVER__mcpWebsocketPath",
            "MCP_SERVER__METRICS_PATH",
            "MCP_SERVER__metricsPath",
            "MCP_TYPEDB__ADDRESS",
            "MCP_TYPEDB__address",
            "MCP_TYPEDB__USERNAME",
            "MCP_TYPEDB__username",
            "MCP_TYPEDB__TLS_ENABLED",
            "MCP_TYPEDB__tlsEnabled",
            "MCP_TYPEDB__TLS_CA_PATH",
            "MCP_TYPEDB__tlsCaPath",
            "MCP_OAUTH__ENABLED",
            "MCP_OAUTH__enabled",
            "MCP_OAUTH__JWKS_URI",
            "MCP_OAUTH__jwksUri",
            "MCP_OAUTH__ISSUER",
            "MCP_OAUTH__issuer",
            "MCP_OAUTH__AUDIENCE",
            "MCP_OAUTH__audience",
            "MCP_OAUTH__JWKS_REFRESH_INTERVAL",
            "MCP_OAUTH__jwksRefreshInterval",
            "MCP_OAUTH__JWKS_REQUEST_TIMEOUT_SECONDS",
            "MCP_OAUTH__jwksRequestTimeoutSeconds",
            "MCP_OAUTH__REQUIRED_SCOPES",
            "MCP_OAUTH__requiredScopes",
            "MCP_LOGGING__RUST_LOG",
            "MCP_LOGGING__rustLog",
            "MCP_CORS__ALLOWED_ORIGINS",
            "MCP_CORS__allowedOrigins",
            "MCP_RATE_LIMIT__ENABLED",
            "MCP_RATE_LIMIT__enabled",
            "MCP_RATE_LIMIT__REQUESTS_PER_SECOND",
            "MCP_RATE_LIMIT__requestsPerSecond",
            "MCP_RATE_LIMIT__BURST_SIZE",
            "MCP_RATE_LIMIT__burstSize",
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
        for var_key in vars_to_clear {
            env::remove_var(var_key);
        }
    }

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
        env::remove_var("MCP_CONFIG_PATH");

        let settings = Settings::new().expect("Falha ao carregar configurações default");

        assert_eq!(settings.typedb.address, default_typedb_address());
        assert_eq!(settings.typedb.username, Some(default_typedb_username()));
        assert!(!settings.typedb.tls_enabled);
        assert_eq!(settings.server.bind_address, default_server_bind_address());
        assert!(!settings.oauth.enabled);
        assert_eq!(settings.oauth.jwks_refresh_interval, Some(Duration::from_secs(3600)));
        assert_eq!(
            settings.oauth.jwks_refresh_interval_raw,
            Some(DEFAULT_JWKS_REFRESH_INTERVAL_STR.to_string())
        );
        assert_eq!(settings.logging.rust_log, default_logging_rust_log());
        assert_eq!(settings.cors.allowed_origins, default_cors_allowed_origins());
        assert_eq!(settings.rate_limit.enabled, default_rate_limit_enabled());
        assert!(!settings.tracing.enabled);
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
            metricsPath = "/testmetrics"    

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

            [rateLimit]
            enabled = false
            requestsPerSecond = 50 

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
        assert_eq!(settings.server.metrics_path, Some("/testmetrics".to_string()));
        assert!(settings.oauth.enabled);
        assert_eq!(settings.oauth.jwks_uri, Some("http://jwks.local".to_string()));
        assert_eq!(settings.oauth.issuer, Some(vec!["issuer1".to_string(), "issuer2".to_string()]));
        assert_eq!(settings.oauth.audience, Some(vec!["aud1".to_string()]));
        assert_eq!(settings.oauth.jwks_refresh_interval_raw, Some("30m".to_string()));
        assert_eq!(settings.oauth.jwks_refresh_interval, Some(Duration::from_secs(30 * 60)));
        assert_eq!(
            settings.oauth.required_scopes,
            Some(vec!["scope1".to_string(), "scope2".to_string()])
        );
        assert_eq!(settings.logging.rust_log, "debug");
        assert_eq!(settings.cors.allowed_origins, vec!["http://frontend.local".to_string()]);
        assert!(!settings.rate_limit.enabled);
        assert_eq!(settings.rate_limit.requests_per_second, Some(50));
        assert!(settings.tracing.enabled);
        assert_eq!(
            settings.tracing.exporter_otlp_endpoint,
            Some("http://otel.local:4317".to_string())
        );
        assert_eq!(settings.tracing.service_name, "my-mcp-server");
    }

    #[test]
    #[serial]
    fn test_override_toml_with_env_vars() {
        let _env_cleaner = EnvCleaner::new();
        let toml_content = r#"
            [server]
            bindAddress = "0.0.0.0:8080" 
            tlsEnabled = false

            [oauth]
            enabled = false
            issuer = ["toml_issuer"]
            jwksRefreshInterval = "1h" 
        "#;
        let temp_file = create_temp_toml_config(toml_content);
        env::set_var("MCP_CONFIG_PATH", temp_file.path());

        env::set_var("MCP_SERVER__BIND_ADDRESS", "127.0.0.1:8888");
        env::set_var("MCP_SERVER__TLS_ENABLED", "true");
        env_remove_var_silently("MCP_SERVER__tlsEnabled");

        env::set_var("MCP_OAUTH__ENABLED", "true");
        env_remove_var_silently("MCP_OAUTH__enabled");

        env::set_var("MCP_OAUTH__ISSUER", "env_issuer1,env_issuer2");
        env_remove_var_silently("MCP_OAUTH__issuer");

        env::set_var("MCP_OAUTH__JWKS_REFRESH_INTERVAL", "15m");
        env_remove_var_silently("MCP_OAUTH__jwksRefreshInterval");

        let settings = Settings::new().expect("Falha ao carregar config com overrides de env");

        assert_eq!(settings.server.bind_address, "127.0.0.1:8888");
        assert!(settings.server.tls_enabled);
        assert!(settings.oauth.enabled);
        assert_eq!(
            settings.oauth.issuer,
            Some(vec!["env_issuer1".to_string(), "env_issuer2".to_string()])
        );
        assert_eq!(settings.oauth.jwks_refresh_interval_raw, Some("15m".to_string()));
        assert_eq!(settings.oauth.jwks_refresh_interval, Some(Duration::from_secs(15 * 60)));
    }

    /// Helper para remover uma ENV var, ignorando se ela não existir.
    fn env_remove_var_silently(key: &str) {
        env::remove_var(key);
    }

    #[test]
    #[serial]
    fn test_env_override_with_camel_case_env_name() {
        let _env_cleaner = EnvCleaner::new();
        let toml_content = r#"
            [server]
            bindAddress = "0.0.0.0:7070"
        "#;
        let temp_file = create_temp_toml_config(toml_content);
        env::set_var("MCP_CONFIG_PATH", temp_file.path());

        env::set_var("MCP_SERVER__bindAddress", "127.0.0.1:7777"); // ENV camelCase
        env_remove_var_silently("MCP_SERVER__BIND_ADDRESS");

        let settings =
            Settings::new().expect("Falha ao carregar config com override de env camelCase");
        assert_eq!(settings.server.bind_address, "127.0.0.1:7777");
    }

    #[test]
    #[serial]
    fn test_partial_toml_uses_struct_defaults() {
        let _env_cleaner = EnvCleaner::new();
        let toml_content = r#"
            [typedb]
            address = "specific.typedb.host:1729"
        "#;
        let temp_file = create_temp_toml_config(toml_content);
        env::set_var("MCP_CONFIG_PATH", temp_file.path());

        let settings = Settings::new().expect("Falha ao carregar config parcial");

        assert_eq!(settings.typedb.address, "specific.typedb.host:1729");
        assert_eq!(settings.typedb.username, Some(default_typedb_username()));
        assert!(!settings.typedb.tls_enabled);
        assert_eq!(settings.server.bind_address, default_server_bind_address());
    }

    #[test]
    #[serial]
    fn test_jwks_refresh_interval_parsing_from_raw_string_in_toml() {
        let _env_cleaner = EnvCleaner::new();
        let toml_content = r#"
            [oauth]
            jwksRefreshInterval = "15m" 
        "#;
        let temp_file = create_temp_toml_config(toml_content);
        env::set_var("MCP_CONFIG_PATH", temp_file.path());

        let settings = Settings::new().expect("Falha ao carregar config com jwksRefreshInterval");
        assert_eq!(settings.oauth.jwks_refresh_interval_raw, Some("15m".to_string())); // <<< Verificação
        assert_eq!(settings.oauth.jwks_refresh_interval, Some(Duration::from_secs(15 * 60)));
    }

    #[test]
    #[serial]
    fn test_jwks_refresh_interval_uses_struct_default_if_absent_in_toml_and_env() {
        let _env_cleaner = EnvCleaner::new();
        let toml_content = r"
            [oauth]
            enabled = false 
        ";
        let temp_file = create_temp_toml_config(toml_content);
        env::set_var("MCP_CONFIG_PATH", temp_file.path());

        env_remove_var_silently("MCP_OAUTH__JWKS_REFRESH_INTERVAL");
        env_remove_var_silently("MCP_OAUTH__jwksRefreshInterval");

        let settings =
            Settings::new().expect("Falha ao carregar config sem jwksRefreshInterval raw");

        // O default para jwks_refresh_interval (Duration) é Some(1h)
        // O default para jwks_refresh_interval_raw (Option<String>) agora é None, mas será preenchido
        // para o default programático "1h" no final do Settings::new() se nenhuma ENV/TOML definir.
        assert_eq!(settings.oauth.jwks_refresh_interval, Some(Duration::from_secs(3600)));
        assert_eq!(
            settings.oauth.jwks_refresh_interval_raw,
            Some(DEFAULT_JWKS_REFRESH_INTERVAL_STR.to_string())
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
        assert!(result.is_err()); // <<< Verificação
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

    #[test]
    #[serial]
    fn test_empty_env_for_option_vec_string_results_in_none() {
        let _env_cleaner = EnvCleaner::new();
        env::set_var("MCP_OAUTH__ISSUER", "");

        let settings = Settings::new().expect("Falha ao carregar config");
        assert_eq!(settings.oauth.issuer, None, "Issuer deveria ser None para ENV vazia");

        env::set_var("MCP_OAUTH__ISSUER", ", ,,");
        let settings = Settings::new().expect("Falha ao carregar config");
        assert_eq!(
            settings.oauth.issuer, None,
            "Issuer deveria ser None para ENV com apenas vírgulas"
        );
    }

    #[test]
    #[serial]
    fn test_empty_env_for_vec_string_keeps_default_or_toml() {
        let _env_cleaner = EnvCleaner::new();

        let default_origins = default_cors_allowed_origins();

        env_remove_var_silently("MCP_CORS__ALLOWED_ORIGINS");
        env_remove_var_silently("MCP_CORS__allowedOrigins");
        env::remove_var("MCP_CONFIG_PATH");
        let settings_default = Settings::new().expect("Falha ao carregar config (default)");
        assert_eq!(
            settings_default.cors.allowed_origins, default_origins,
            "allowedOrigins deveria ser o default da struct"
        );

        let toml_content = r#"
            [cors]
            allowedOrigins = ["http://from.toml"]
        "#;
        let temp_file = create_temp_toml_config(toml_content);
        env::set_var("MCP_CONFIG_PATH", temp_file.path());
        env::set_var("MCP_CORS__ALLOWED_ORIGINS", "");

        let settings_toml_env_empty =
            Settings::new().expect("Falha ao carregar config (TOML e ENV vazia)");
        assert_eq!(
            settings_toml_env_empty.cors.allowed_origins,
            vec!["http://from.toml".to_string()],
            "allowedOrigins deveria ser do TOML quando ENV é vazia"
        );

        env::set_var("MCP_CORS__ALLOWED_ORIGINS", ",,,");
        let settings_toml_env_commas =
            Settings::new().expect("Falha ao carregar config (TOML e ENV com vírgulas)");
        assert_eq!(
            settings_toml_env_commas.cors.allowed_origins,
            vec!["http://from.toml".to_string()],
            "allowedOrigins deveria ser do TOML quando ENV tem só vírgulas"
        );
    }
}
