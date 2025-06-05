// src/main.rs

// Copyright 2025 Guilherme Leste
//
// Licensed under the MIT License <LICENSE or https://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed
// except according to those terms.

//! Ponto de entrada principal para o Typedb-MCP-Server.
//!
//! Este binário é responsável por:
//! 1. Carregar as configurações da aplicação.
//! 2. Configurar o sistema de logging (tracing) e, opcionalmente, o tracing distribuído (OpenTelemetry).
//! 3. Inicializar o exportador de métricas Prometheus e seu endpoint HTTP.
//! 4. Estabelecer a conexão com o servidor TypeDB.
//! 5. Se OAuth2 estiver habilitado, inicializar o cache de chaves JWKS.
//! 6. Construir e iniciar o servidor web Axum, que lida com:
//!    - Endpoints HTTP para health checks (`/livez`, `/readyz`).
//!    - O endpoint HTTP para métricas Prometheus (ex: `/metrics`).
//!    - O endpoint WebSocket para comunicação MCP (ex: `/mcp/ws`), aplicando middleware OAuth2 se configurado.
//! 7. Gerenciar o desligamento gracioso (graceful shutdown) da aplicação ao receber sinais SIGINT/SIGTERM.

// std imports
use std::{error::Error as StdError, net::SocketAddr, sync::Arc, time::Duration};

// axum imports
use axum::{
    extract::{ws::WebSocketUpgrade, ConnectInfo, Extension, State},
    http::StatusCode,
    middleware::from_fn_with_state, // Para aplicar middleware com estado
    response::{IntoResponse, Response as AxumResponse},
    routing::get,
    Router,
};
use axum_server::{tls_rustls::RustlsConfig, Handle as AxumServerHandle}; // Para TLS e graceful shutdown
use tokio_util::sync::CancellationToken; // Para graceful shutdown coordenado

// typedb_mcp_server_lib imports
use typedb_mcp_server_lib::{
    auth::{oauth_middleware, ClientAuthContext, JwksCache}, // Componentes de autenticação
    config::{Server as AppServerConfig, Settings},          // Configurações da aplicação
    db::connect as connect_to_typedb,                       // Função de conexão com TypeDB
    mcp_service_handler::McpServiceHandler, // Handler principal do serviço MCP
    metrics,                                // Módulo de métricas
    telemetry,                              // Módulo de tracing OpenTelemetry
    transport::WebSocketTransport,          // Adaptador WebSocket para MCP
    AuthErrorDetail,                        // Tipos de erro
    McpServerError,
};

// Crates de Observabilidade e Utilitários
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use reqwest::Client as ReqwestClient; // Cliente HTTP para buscar JWKS
use rmcp::service::{
    RoleServer, RunningService, ServerInitializeError, ServiceExt as RmcpServiceExt,
};
use tracing::{debug, error, info, warn, Instrument, Dispatch}; // Macros de logging/tracing
use tracing_subscriber::{fmt, prelude::*, EnvFilter, Registry}; // Configuração do tracing
use typedb_driver::TypeDBDriver; // Driver TypeDB

// Crates para informações de build e criptografia
use rustc_version_runtime; // Para obter a versão do Rustc em tempo de execução
use rustls::crypto::CryptoProvider; // Para configurar o provedor criptográfico do Rustls

/// Estrutura para o estado da aplicação compartilhado com os handlers Axum.
///
/// Contém recursos que são imutáveis ou thread-safe e podem ser clonados
/// para cada handler Axum ou tarefa Tokio. O `McpServiceHandler` não é mais
/// armazenado aqui globalmente, pois será instanciado por conexão para permitir
/// que o `auth_context` seja específico da conexão.
#[derive(Clone)]
struct AppState {
    /// Driver `TypeDB` compartilhado, usado para criar conexões e transações.
    typedb_driver_ref: Arc<TypeDBDriver>,
    /// Configurações da aplicação, carregadas na inicialização.
    settings: Arc<Settings>,
    /// Cache de chaves JWKS, presente se OAuth2 estiver habilitado.
    jwks_cache: Option<Arc<JwksCache>>,
    /// Token de cancelamento global para coordenar o desligamento gracioso.
    global_shutdown_token: CancellationToken,
}

/// Configura o sistema global de logging e tracing.
///
/// Utiliza `tracing_subscriber` para configurar um `EnvFilter` (baseado em `RUST_LOG`
/// ou `settings.logging.rust_log`), um formatador JSON para os logs, e,
/// se habilitado nas configurações, um pipeline OpenTelemetry para exportar traces.
///
/// # Parâmetros
/// * `settings`: As configurações carregadas da aplicação.
///
/// # Retorna
/// `Result` indicando sucesso ou um erro se a configuração do dispatcher global falhar.
fn setup_global_logging_and_tracing(
    settings: &Settings,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    // Tenta carregar o filtro de log do ambiente (RUST_LOG) ou usa o valor da configuração.
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(settings.logging.rust_log.clone()));

    // Configura a camada de formatação para logs JSON.
    // Inclui informações de span, target, arquivo e linha para logs detalhados.
    let formatting_layer = fmt::layer()
        .json() // Formato JSON para logs estruturados
        .with_current_span(true) // Inclui o span atual no log
        .with_span_list(true) // Inclui a lista de spans pai
        .with_target(true) // Inclui o target (módulo) do log
        .with_file(true) // Inclui o nome do arquivo fonte
        .with_line_number(true); // Inclui o número da linha

    // Constrói o subscriber base com o filtro e o formatador.
    let subscriber_builder = Registry::default().with(env_filter).with(formatting_layer);

    // Se o tracing OpenTelemetry estiver habilitado nas configurações:
    if settings.tracing.enabled {
        match telemetry::init_tracing_pipeline(&settings.tracing) {
            Ok(()) => {
                // Adiciona a camada OpenTelemetry ao subscriber.
                let telemetry_layer = tracing_opentelemetry::layer();
                let subscriber = subscriber_builder.with(telemetry_layer);
                // Define o subscriber configurado como o dispatcher global de tracing.
                tracing::dispatcher::set_global_default(Dispatch::new(subscriber))?;
                info!(
                    "OpenTelemetry tracing habilitado e configurado para exportar para: {:?}",
                    settings.tracing.exporter_otlp_endpoint
                );
            }
            Err(e) => {
                // Se a inicialização do OTLP falhar, usa apenas o logging JSON.
                let subscriber = subscriber_builder;
                tracing::dispatcher::set_global_default(Dispatch::new(subscriber))?;
                warn!(
                    "Falha ao inicializar OpenTelemetry pipeline: {}. Tracing distribuído desabilitado.",
                    e
                );
            }
        }
    } else {
        // Se OTLP estiver desabilitado, usa apenas o logging JSON.
        let subscriber = subscriber_builder;
        tracing::dispatcher::set_global_default(Dispatch::new(subscriber))?;
        info!("OpenTelemetry tracing desabilitado.");
    }
    Ok(())
}

/// Configura e instala o recorder de métricas Prometheus.
///
/// Registra as descrições das métricas customizadas da aplicação.
/// O endpoint HTTP para servir estas métricas é configurado separadamente no router Axum.
///
/// # Parâmetros
/// * `_server_settings`: Configurações do servidor (atualmente não usadas para o recorder em si).
///
/// # Retorna
/// `Result<PrometheusHandle>` contendo o handle para o recorder, ou um erro se a instalação falhar.
fn setup_metrics_recorder(
    _server_settings: &AppServerConfig, // Parâmetro pode ser usado no futuro se necessário
) -> Result<PrometheusHandle, Box<dyn StdError + Send + Sync>> {
    // Registra descrições de todas as métricas customizadas definidas em `src/metrics.rs`.
    metrics::register_metrics_descriptions();
    info!("Descrições de métricas Prometheus registradas.");

    // Instala o recorder Prometheus. Não inicia o listener HTTP aqui,
    // pois o Axum será responsável por expor o endpoint /metrics.
    PrometheusBuilder::new().install_recorder().map_err(|e| {
        let err_msg =
            format!("Não foi possível instalar o recorder de métricas Prometheus: {}", e);
        error!("[METRICS_SETUP_ERROR] {}", err_msg);
        Box::new(std::io::Error::other(err_msg)) as Box<dyn StdError + Send + Sync>
    })
}

/// Inicializa os serviços principais dos quais o servidor MCP depende.
///
/// Especificamente, estabelece a conexão com o TypeDB e, se OAuth2 estiver habilitado,
/// inicializa o cache de chaves JWKS e realiza um primeiro refresh.
///
/// # Parâmetros
/// * `settings`: As configurações carregadas da aplicação.
///
/// # Retorna
/// `Result` contendo uma tupla com o `Arc<TypeDBDriver>` e `Option<Arc<JwksCache>>`,
/// ou um erro se a inicialização de um serviço crítico falhar.
async fn initialize_core_services(
    settings: &Arc<Settings>,
) -> Result<(Arc<TypeDBDriver>, Option<Arc<JwksCache>>), Box<dyn StdError + Send + Sync>> {
    info!(
        "Tentando conectar ao TypeDB. Configurado em: {} (TLS: {})",
        settings.typedb.address, settings.typedb.tls_enabled
    );
    // Obtém a senha do TypeDB da variável de ambiente.
    let typedb_password_from_env = std::env::var("TYPEDB_PASSWORD").ok();

    // Conecta ao TypeDB.
    let typedb_driver_instance = match connect_to_typedb(
        Some(settings.typedb.address.clone()),
        settings.typedb.username.clone(),
        typedb_password_from_env,
        settings.typedb.tls_enabled,
        settings.typedb.tls_ca_path.clone(),
    )
    .await
    {
        Ok(driver) => {
            info!("Conexão com TypeDB estabelecida com sucesso.");
            Arc::new(driver)
        }
        Err(e) => {
            // Se a conexão com TypeDB falhar, é um erro fatal para o servidor.
            let mcp_error =
                McpServerError::from(typedb_mcp_server_lib::error::TypeDBErrorWrapper::from(e));
            error!("Falha fatal ao conectar com TypeDB: {}", mcp_error);
            return Err(Box::new(mcp_error));
        }
    };

    // Inicializa o cache JWKS se OAuth2 estiver habilitado.
    let jwks_cache_option = if settings.oauth.enabled {
        let jwks_uri = settings.oauth.jwks_uri.as_ref().ok_or_else(|| {
            let msg = "OAuth2 habilitado, mas oauth.jwks_uri não configurado.";
            error!("{}", msg);
            Box::new(McpServerError::Auth(AuthErrorDetail::InvalidAuthConfig(msg.to_string())))
                as Box<dyn StdError + Send + Sync>
        })?;

        // Configura o timeout para o cliente HTTP que busca o JWKS.
        let http_client_timeout =
            settings.oauth.jwks_request_timeout_seconds.map_or_else(
                || {
                    warn!("oauth.jwks_request_timeout_seconds não configurado, usando default de 10s.");
                    Duration::from_secs(10)
                },
                Duration::from_secs,
            );

        let http_client = ReqwestClient::builder().timeout(http_client_timeout).build().map_err(
            |e| {
                Box::new(McpServerError::Internal(format!(
                    "Falha ao construir HTTP client para JWKS: {}",
                    e
                )))
            },
        )?;

        // Obtém o intervalo de refresh do JWKS.
        let jwks_refresh_interval = settings.oauth.jwks_refresh_interval.unwrap_or_else(|| {
            warn!("oauth.jwks_refresh_interval não pôde ser parseado ou estava ausente, usando default de 1 hora para o cache.");
            Duration::from_secs(3600) // Default de 1 hora
        });

        let cache = Arc::new(JwksCache::new(
            jwks_uri.clone(),
            jwks_refresh_interval,
            http_client,
        ));

        // Tenta um refresh inicial do JWKS. Se falhar, o servidor não deve iniciar
        // se OAuth2 for uma dependência crítica para a autenticação.
        match cache.refresh_keys().await {
            Ok(()) => {
                info!("JWKS cache inicializado e populado com sucesso de {}.", jwks_uri);
                Some(cache)
            }
            Err(e) => {
                let err_msg = format!("Falha crítica no refresh inicial do JWKS de {}: {}. O servidor não pode iniciar com OAuth habilitado sem acesso ao JWKS.", jwks_uri, e);
                error!("{}", err_msg);
                return Err(Box::new(McpServerError::Auth(AuthErrorDetail::JwksFetchFailed(
                    err_msg,
                ))));
            }
        }
    } else {
        None // OAuth2 desabilitado, nenhum cache JWKS necessário.
    };

    Ok((typedb_driver_instance, jwks_cache_option))
}

/// Cria e retorna o estado da aplicação (`AppState`) compartilhado.
///
/// # Parâmetros
/// * `typedb_driver`: `Arc` para o driver TypeDB.
/// * `settings`: `Arc` para as configurações da aplicação.
/// * `jwks_cache`: `Option<Arc<JwksCache>>` para o cache JWKS.
/// * `global_shutdown_token`: O token de cancelamento global.
///
/// # Retorna
/// Uma instância de `AppState`.
fn create_app_state(
    typedb_driver: Arc<TypeDBDriver>,
    settings: Arc<Settings>,
    jwks_cache: Option<Arc<JwksCache>>,
    global_shutdown_token: CancellationToken,
) -> AppState {
    AppState {
        typedb_driver_ref: typedb_driver,
        settings,
        jwks_cache,
        global_shutdown_token,
    }
}

/// Constrói o router Axum principal com todas as rotas e middlewares.
///
/// # Parâmetros
/// * `app_state`: O estado da aplicação a ser compartilhado com os handlers.
/// * `settings`: As configurações da aplicação, usadas para configurar o middleware OAuth, etc.
/// * `metrics_handle_opt`: Opcional `PrometheusHandle` para o endpoint de métricas.
///
/// # Retorna
/// O `Router` Axum configurado.
fn build_axum_router(
    app_state: AppState,
    settings: &Arc<Settings>, // Passado para que o middleware OAuth possa acessar config.oauth
    metrics_handle_opt: Option<PrometheusHandle>,
) -> Router {
    // Determina os paths para os endpoints MCP e de métricas.
    let mcp_ws_path_str = settings
        .server
        .mcp_websocket_path
        .clone()
        .unwrap_or_else(|| "/mcp/ws".to_string()); // Padrão se não configurado
    let metrics_path_str =
        settings.server.metrics_path.clone().unwrap_or_else(|| "/metrics".to_string()); // Padrão

    // Router base para endpoints HTTP (health checks, métricas)
    let mut base_router = Router::new()
        .route("/livez", get(livez_handler)) // Endpoint Liveness
        .route("/readyz", get(readyz_handler).with_state(app_state.clone())); // Endpoint Readiness, com estado

    // Adiciona rota de métricas se o handle estiver disponível
    if let Some(metrics_h) = metrics_handle_opt {
        info!("Configurando endpoint de métricas Axum em: {}", metrics_path_str);
        base_router =
            base_router.route(&metrics_path_str, get(metrics_handler).with_state(metrics_h));
    } else {
        warn!("PrometheusHandle não disponível. Endpoint de métricas via Axum não será configurado.");
    }

    // Router para o endpoint WebSocket MCP
    let mut mcp_ws_router = Router::new().route(&mcp_ws_path_str, get(websocket_handler));

    // Aplica middleware OAuth2 à rota MCP se estiver habilitado
    if settings.oauth.enabled {
        if let Some(jwks_cache_for_middleware) = app_state.jwks_cache.clone() {
            // O middleware precisa do JwksCache e da configuração OAuth
            let oauth_config_for_middleware = Arc::new(settings.oauth.clone());
            info!("Middleware OAuth2 habilitado para WebSocket em: {}", mcp_ws_path_str);
            mcp_ws_router = mcp_ws_router.route_layer(from_fn_with_state(
                (jwks_cache_for_middleware, oauth_config_for_middleware),
                oauth_middleware,
            ));
        } else {
            // Este é um estado inconsistente: OAuth habilitado mas sem cache JWKS.
            // Deveria ter sido capturado durante initialize_core_services.
            error!("Erro crítico de configuração: OAuth habilitado, mas JwksCache ausente no AppState. A autenticação para WebSockets falhará.");
        }
    } else {
        info!("Autenticação OAuth2 desabilitada para WebSockets.");
    }

    // Mergeia o router MCP (com seu estado) ao router base.
    // O AppState é clonado e passado para os handlers do router mcp_ws_router.
    base_router.merge(mcp_ws_router.with_state(app_state))
}

/// Executa o servidor Axum.
///
/// Configura o bind de rede, TLS (se habilitado), e o graceful shutdown.
///
/// # Parâmetros
/// * `router`: O `Router` Axum a ser servido.
/// * `settings`: As configurações da aplicação.
/// * `global_shutdown_token`: O token de cancelamento para graceful shutdown.
async fn run_axum_server(
    router: Router,
    settings: &Arc<Settings>,
    global_shutdown_token: CancellationToken,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    let bind_address_str = settings.server.bind_address.clone();
    let bind_addr: SocketAddr = bind_address_str
        .parse()
        .map_err(|e| format!("Endereço de bind inválido '{bind_address_str}': {e}"))?;

    // Cria um handle para o servidor Axum para permitir o graceful shutdown.
    let server_handle = AxumServerHandle::new();
    let shutdown_task_handle_clone = server_handle.clone(); // Clone para a task de shutdown
    let shutdown_token_for_axum_server = global_shutdown_token.clone(); // Clone para a task de shutdown

    // Task que escuta pelo token de cancelamento e inicia o graceful shutdown do Axum.
    tokio::spawn(async move {
        shutdown_token_for_axum_server.cancelled().await;
        info!(
            "Sinal de desligamento recebido, iniciando graceful shutdown do servidor Axum..."
        );
        // Inicia o graceful shutdown, permitindo 30s para conexões existentes terminarem.
        shutdown_task_handle_clone.graceful_shutdown(Some(Duration::from_secs(30)));
    });

    if settings.server.tls_enabled {
        // Configura TLS se habilitado.
        let cert_path_str = settings.server.tls_cert_path.as_ref().ok_or_else(|| {
            // Retorna um McpServerError que pode ser convertido para Box<dyn StdError>
            McpServerError::Auth(AuthErrorDetail::InvalidAuthConfig(
                "server.tls_cert_path não configurado com TLS habilitado".to_string(),
            ))
        })?;
        let key_path_str = settings.server.tls_key_path.as_ref().ok_or_else(|| {
            McpServerError::Auth(AuthErrorDetail::InvalidAuthConfig(
                "server.tls_key_path não configurado com TLS habilitado".to_string(),
            ))
        })?;

        info!("Servidor MCP (HTTPS/WSS) escutando em {}", bind_addr);
        info!("Usando certificado TLS de: {}", cert_path_str);
        info!("Usando chave privada TLS de: {}", key_path_str);

        // Carrega a configuração Rustls a partir dos arquivos PEM.
        let tls_config = RustlsConfig::from_pem_file(cert_path_str, key_path_str)
            .await
            .map_err(|e| format!("Erro ao carregar certificado/chave PEM TLS: {e}"))?;

        // Inicia o servidor Axum com TLS.
        axum_server::bind_rustls(bind_addr, tls_config)
            .handle(server_handle)
            .serve(router.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    } else {
        // Inicia o servidor Axum sem TLS (HTTP/WS).
        info!("Servidor MCP (HTTP/WS) escutando em {}", bind_addr);
        axum_server::bind(bind_addr)
            .handle(server_handle)
            .serve(router.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    }
    Ok(())
}

/// Realiza a limpeza de recursos antes do servidor terminar.
///
/// # Parâmetros
/// * `typedb_driver`: O driver TypeDB para fechar a conexão.
/// * `settings`: As configurações, para verificar se o tracing precisa ser desligado.
async fn cleanup_resources(
    typedb_driver: Arc<TypeDBDriver>,
    settings: &Arc<Settings>,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    info!("Graceful shutdown: Iniciando limpeza de recursos...");

    // Força o fechamento da conexão com TypeDB.
    if let Err(e) = typedb_driver.force_close() {
        error!("Erro ao fechar conexão com TypeDB: {}", e);
    } else {
        info!("Conexão com TypeDB fechada.");
    }

    // Desliga o provider de tracing OpenTelemetry, se habilitado.
    if settings.tracing.enabled {
        telemetry::shutdown_tracer_provider();
    }
    info!("Typedb-MCP-Server desligado graciosamente.");
    Ok(())
}

/// Ponto de entrada síncrono da aplicação.
///
/// Configura um logger temporário, carrega configurações, inicializa o logger/tracing global definitivo,
/// e então bloqueia na execução da lógica principal assíncrona (`async_main`).
fn main() -> Result<(), Box<dyn StdError + Send + Sync>> {
    // --- INÍCIO DA INICIALIZAÇÃO DO CRYPTO PROVIDER ---
    // Garante que um provedor criptográfico (Ring) esteja instalado para Rustls.
    // Isso é necessário se o servidor for usar TLS (HTTPS/WSS).
    if CryptoProvider::get_default().is_none() {
        match rustls::crypto::ring::default_provider().install_default() {
            Ok(()) => {
                // Usar println! aqui pois o logger principal ainda não está configurado.
                println!("[CRYPTO_PROVIDER_SETUP] Provedor criptográfico Ring instalado como padrão para rustls.");
            }
            Err(e) => {
                // Erro fatal se não conseguir instalar, pois TLS pode ser necessário.
                eprintln!("[CRYPTO_PROVIDER_FATAL] Falha crítica ao instalar o provedor criptográfico Ring: {:?}. O servidor não pode continuar se TLS for usado.", e);
                // Para simplificar, saímos. Uma aplicação mais robusta poderia tentar continuar
                // se soubesse que TLS não será usado.
                std::process::exit(1);
            }
        }
    } else {
        println!("[CRYPTO_PROVIDER_SETUP] Provedor criptográfico padrão para rustls já está instalado globalmente.");
    }
    // --- FIM DA INICIALIZAÇÃO DO CRYPTO PROVIDER ---

    // Tenta carregar variáveis de ambiente de um arquivo .env.
    // Falhar em carregar (ex: arquivo .env não existe) não é um erro fatal.
    if dotenvy::dotenv().is_err() {
        println!("[SETUP_INFO] Arquivo .env não encontrado ou falha ao carregar. Usando variáveis de ambiente do sistema se disponíveis.");
    }

    // Bloco para controlar o tempo de vida do logger temporário.
    {
        // Logger temporário para a fase de inicialização da configuração e do logger principal.
        // Isso garante que tenhamos logs mesmo se a configuração do logger principal falhar.
        let temp_env_filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        let temp_subscriber = fmt::Subscriber::builder()
            .with_env_filter(temp_env_filter)
            .with_writer(std::io::stderr) // Loga para stderr durante o setup inicial
            .json() // Mantém JSON para consistência
            .finish();
        // `set_default` retorna um `DefaultGuard`. Mantê-lo (_temp_guard) até que o logger principal seja configurado.
        // Quando _temp_guard sai de escopo, o dispatcher anterior é restaurado.
        let _temp_guard = tracing::dispatcher::set_default(&Dispatch::new(temp_subscriber));

        info!("Iniciando Typedb-MCP-Server versão {}...", env!("CARGO_PKG_VERSION"));
        info!("Carregando configurações...");

        // Carrega as configurações da aplicação.
        let settings = match Settings::new() {
            Ok(s) => Arc::new(s), // Envolve em Arc para compartilhamento seguro
            Err(config_err) => {
                error!("Erro fatal ao carregar a configuração: {}", config_err);
                if let Some(source) = config_err.source() {
                    error!("   Fonte do erro de configuração: {}", source);
                }
                // Panic aqui é aceitável, pois sem configurações válidas, o servidor não pode operar.
                panic!("Falha ao carregar configurações: {}", config_err);
            }
        };

        // Agora que `Settings` está carregado, configura o logger/tracing global definitivo.
        // O `_temp_guard` do logger temporário sairá de escopo após esta chamada,
        // e o novo dispatcher global tomará efeito.
        if let Err(e) = setup_global_logging_and_tracing(&settings) {
            // Se a configuração do logger global falhar, logamos um erro crítico para stderr
            // (já que o logger principal pode não estar funcionando) e consideramos sair.
            eprintln!(
                "[SETUP_FATAL] Falha crítica ao configurar o sistema de logging/tracing global: {}. Observabilidade severamente comprometida.",
                e
            );
            // Dependendo da criticidade do logging, pode-se decidir sair:
            // std::process::exit(1);
        }
        
        info!("Configurações carregadas e sistema de logging/tracing global inicializado.");
        debug!(config = ?settings, "Configurações da aplicação carregadas e prontas para uso.");

        // Configura o número de threads worker para o runtime Tokio.
        let worker_threads = settings.server.worker_threads.unwrap_or_else(|| {
            let cores = num_cpus::get(); // Usa o número de CPUs lógicas como padrão
            info!("server.worker_threads não configurado, usando default: {}", cores);
            cores
        });
        info!("Usando {} threads de worker para o runtime Tokio.", worker_threads);

        // Constrói e inicia o runtime Tokio.
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all() // Habilita todas as features do Tokio (I/O, time)
            .worker_threads(worker_threads)
            .thread_name("typedb-mcp-worker") // Nome para as threads worker
            .build()?;

        // Executa a lógica principal assíncrona e bloqueia até que ela termine.
        // O `async_main` retorna um `Result`, que é propagado para `main`.
        return rt.block_on(async_main(settings));
    } // _temp_guard é dropado aqui.
}

/// Lógica principal assíncrona da aplicação.
///
/// Esta função orquestra a inicialização dos serviços, a configuração do router Axum,
/// e a execução do servidor. Também lida com o graceful shutdown.
///
/// # Parâmetros
/// * `settings`: As configurações da aplicação carregadas.
async fn async_main(settings: Arc<Settings>) -> Result<(), Box<dyn StdError + Send + Sync>> {
    // Token de cancelamento global para coordenar o graceful shutdown.
    let global_shutdown_token = CancellationToken::new();
    // Configura handlers de sinal (SIGINT, SIGTERM) para ativar o token de shutdown.
    setup_signal_handler(global_shutdown_token.clone());

    // Configura o recorder de métricas Prometheus.
    let metrics_handle_opt = match setup_metrics_recorder(&settings.server) {
        Ok(handle) => {
            info!("Exportador de métricas Prometheus configurado com sucesso (será servido via Axum).");
            // Registra métricas de informação do servidor (versão, etc.)
            let app_version = env!("CARGO_PKG_VERSION");
            let rust_version_val = rustc_version_runtime::version().to_string();
            
            let startup_counter_name = format!("{}{}", metrics::METRIC_PREFIX, "server_startup_total");
            let info_gauge_name = format!("{}{}", metrics::METRIC_PREFIX, metrics::SERVER_INFO_GAUGE);

            ::metrics::counter!(startup_counter_name).increment(1);
            ::metrics::gauge!(
                info_gauge_name,
                metrics::LABEL_VERSION => app_version.to_string(),
                metrics::LABEL_RUST_VERSION => rust_version_val
            )
            .set(1.0);
            info!("Métricas de diagnóstico iniciais registradas.");
            Some(handle)
        }
        Err(e) => {
            error!(
                "Falha ao configurar o exportador de métricas Prometheus: {}. As métricas podem não estar disponíveis.",
                e
            );
            None
        }
    };

    info!("Inicializando serviços principais (TypeDB, JWKS)...");
    // Inicializa a conexão com TypeDB e o cache JWKS (se OAuth2 habilitado).
    let (typedb_driver, jwks_cache) = match initialize_core_services(&settings).await {
        Ok(services) => {
            info!("Serviços principais (TypeDB, JWKS) inicializados com sucesso.");
            services
        }
        Err(e) => {
            error!("Falha na inicialização dos serviços principais (TypeDB ou JWKS): {}. O servidor será encerrado.", e);
            // Se a inicialização falhar, cancela o token para que o signal_handler também termine.
            if !global_shutdown_token.is_cancelled() {
                 global_shutdown_token.cancel();
            }
            return Err(e); // Propaga o erro, encerrando a aplicação.
        }
    };

    // Cria o estado da aplicação compartilhado.
    let app_state = create_app_state(
        typedb_driver.clone(), // Passa o Arc clonado
        settings.clone(),      // Passa o Arc clonado
        jwks_cache,
        global_shutdown_token.clone(),
    );

    // Constrói o router Axum com todas as rotas e middlewares.
    let router = build_axum_router(app_state.clone(), &settings, metrics_handle_opt);

    info!("Iniciando servidor Axum (MCP)...");
    // Executa o servidor Axum. Esta chamada bloqueia até o servidor ser desligado.
    if let Err(e) = run_axum_server(router, &settings, global_shutdown_token.clone()).await {
        error!("Erro fatal ao executar o servidor Axum: {}", e);
        if !global_shutdown_token.is_cancelled() {
            global_shutdown_token.cancel(); // Garante que outros componentes desliguem
        }
        return Err(e); // Propaga o erro
    }

    // Aguarda o sinal de desligamento global ser ativado (pelo handler de sinal ou por outra falha).
    info!("Servidor Axum (MCP) encerrou. Aguardando sinal de desligamento global para limpeza final...");
    global_shutdown_token.cancelled().await;
    info!("Sinal de desligamento global recebido, procedendo com a limpeza de recursos...");

    // Realiza a limpeza de recursos (conexão TypeDB, provider de tracing).
    cleanup_resources(typedb_driver, &settings).await?;

    info!("async_main concluído com sucesso.");
    Ok(())
}

/// Handler para o endpoint de liveness (`/livez`).
/// Retorna `StatusCode::OK` se o servidor estiver minimamente funcional.
async fn livez_handler() -> StatusCode {
    tracing::trace!("Recebida requisição /livez");
    StatusCode::OK
}

/// Handler para o endpoint de readiness (`/readyz`).
/// Verifica a saúde do servidor e de suas dependências críticas (TypeDB, JWKS).
/// Retorna `StatusCode::OK` e um corpo JSON com status "UP" se tudo estiver pronto,
/// ou `StatusCode::SERVICE_UNAVAILABLE` e status "DOWN" caso contrário.
async fn readyz_handler(State(app_state): State<AppState>) -> impl IntoResponse {
    tracing::debug!("Verificando prontidão do servidor para /readyz...");
    let mut ready_components = serde_json::Map::new();
    let mut overall_ready = true;

    // Verifica a conexão com TypeDB
    match app_state.typedb_driver_ref.databases().all().await {
        Ok(_) => {
            if app_state.typedb_driver_ref.is_open() {
                ready_components.insert("typedb".to_string(), serde_json::json!("UP"));
            } else {
                // Se o driver respondeu mas se considera fechado, é um estado degradado.
                warn!("/readyz: TypeDB respondeu, mas driver reporta-se como fechado.");
                ready_components.insert("typedb".to_string(), serde_json::json!("DEGRADED"));
                overall_ready = false;
            }
        }
        Err(e) => {
            warn!("/readyz: Falha ao verificar saúde do TypeDB: {}", e);
            ready_components.insert("typedb".to_string(), serde_json::json!("DOWN"));
            overall_ready = false;
        }
    }

    // Verifica o cache JWKS se OAuth2 estiver habilitado
    if app_state.settings.oauth.enabled {
        if let Some(cache) = &app_state.jwks_cache {
            if cache.check_health_for_readyz().await {
                ready_components.insert("jwks".to_string(), serde_json::json!("UP"));
            } else {
                warn!("/readyz: Componente JWKS não está saudável.");
                ready_components.insert("jwks".to_string(), serde_json::json!("DOWN"));
                overall_ready = false;
            }
        } else {
            // Estado inconsistente: OAuth habilitado mas sem cache.
            error!("/readyz: OAuth habilitado mas JwksCache ausente. Erro de config interna.");
            ready_components.insert("jwks".to_string(), serde_json::json!("CONFIG_ERROR"));
            overall_ready = false;
        }
    } else {
        ready_components.insert("jwks".to_string(), serde_json::json!("NOT_CONFIGURED"));
    }

    let response_body = serde_json::json!({
        "status": if overall_ready { "UP" } else { "DOWN" },
        "components": ready_components
    });

    let status_code = if overall_ready {
        info!("/readyz: Servidor pronto.");
        StatusCode::OK
    } else {
        warn!("/readyz: Servidor não está pronto. Detalhes: {}", response_body);
        StatusCode::SERVICE_UNAVAILABLE
    };
    // Retorna o status HTTP e o corpo JSON.
    (status_code, axum::Json(response_body)).into_response()
}

/// Handler para o endpoint de métricas Prometheus (ex: `/metrics`).
/// Renderiza e retorna as métricas coletadas.
async fn metrics_handler(State(prometheus_handle): State<PrometheusHandle>) -> AxumResponse {
    tracing::trace!("[METRICS_HANDLER_AXUM] Recebida requisição para /metrics");
    let metrics_data = prometheus_handle.render(); // Renderiza as métricas para o formato de texto Prometheus
    tracing::trace!("[METRICS_HANDLER_AXUM] Métricas renderizadas com sucesso");
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")], // Headers corretos para Prometheus
        metrics_data,
    )
        .into_response()
}

/// Handler para conexões WebSocket MCP.
///
/// Realiza o upgrade da conexão HTTP para WebSocket. Se OAuth2 estiver habilitado,
/// espera que o `oauth_middleware` já tenha validado o token e injetado
/// `ClientAuthContext` nas extensões da requisição.
/// Cria uma instância de `McpServiceHandler` específica para esta conexão,
/// passando o contexto de autenticação, e inicia o serviço MCP.
#[tracing::instrument(
    name = "websocket_connection_upgrade",
    skip_all, // Não logar o `ws` (WebSocketUpgrade) ou `app_state` inteiros automaticamente
    fields(
        client.addr = %addr, // Loga o endereço do cliente
        // client.user_id será preenchido dinamicamente abaixo
    )
)]
async fn websocket_handler(
    ws: WebSocketUpgrade, // Extrator Axum para o upgrade WebSocket
    State(app_state): State<AppState>, // Estado da aplicação compartilhado
    maybe_auth_context: Option<Extension<Arc<ClientAuthContext>>>, // Contexto de autenticação, se presente
    ConnectInfo(addr): ConnectInfo<SocketAddr>, // Informações da conexão, como o IP do cliente
) -> impl IntoResponse {
    // Obtém o user_id do contexto de autenticação para logging, ou "<não_autenticado>"
    let user_id_for_log = maybe_auth_context
        .as_ref() // Pega uma referência ao Option
        .map_or_else(|| "<não_autenticado>".to_string(), |Extension(ctx)| ctx.user_id.clone());

    // Adiciona o user_id ao span de tracing atual.
    tracing::Span::current().record("client.user_id", &tracing::field::display(&user_id_for_log));
    info!("Nova tentativa de conexão WebSocket MCP.");

    // Se OAuth estiver habilitado globalmente, mas o `oauth_middleware` não conseguiu
    // validar e injetar um `ClientAuthContext` (ex: token ausente ou inválido),
    // a conexão é rejeitada aqui. O middleware já deve ter retornado um erro HTTP,
    // mas esta é uma verificação adicional de segurança.
    if app_state.settings.oauth.enabled && maybe_auth_context.is_none() {
        warn!("OAuth habilitado, mas ClientAuthContext ausente no websocket_handler. Rejeitando upgrade WebSocket. O middleware deveria ter tratado isso.");
        return (StatusCode::UNAUTHORIZED, "Autenticação OAuth2 falhou ou está ausente.")
            .into_response();
    }

    // Extrai o ClientAuthContext do Extension, se presente.
    let auth_context_for_this_connection = maybe_auth_context.map(|Extension(ctx)| ctx);
    
    // Cria uma instância do McpServiceHandler específica para esta conexão,
    // passando o driver TypeDB, settings, e o contexto de autenticação (se houver).
    let mcp_handler_for_this_connection = Arc::new(
        McpServiceHandler::new_for_connection(
            app_state.typedb_driver_ref.clone(),
            app_state.settings.clone(),
            auth_context_for_this_connection, // Passa o contexto desta conexão
        )
    );
    
    // Clona o token de shutdown global para esta conexão.
    let global_shutdown_token_clone = app_state.global_shutdown_token.clone();

    // Realiza o upgrade para WebSocket e passa o socket para uma nova task Tokio.
    ws.on_upgrade(move |socket| {
        async move {
            // Cria um token de shutdown específico para esta conexão, filho do global.
            // Se o global for cancelado, este também será.
            let connection_specific_shutdown_token = global_shutdown_token_clone.child_token();
            info!("Conexão WebSocket MCP estabelecida.");
            
            // Cria o adaptador de transporte MCP sobre o socket WebSocket.
            let adapter = WebSocketTransport::new(socket);

            // Clona o user_id para uso na task e no span.
            let user_id_for_inner_task_log = user_id_for_log; 
            // Cria um span de tracing para a task que manipula esta conexão MCP.
            let connection_span = tracing::info_span!(
                "mcp_connection_task",
                client.user_id = %user_id_for_inner_task_log, // Loga o user_id
                client.addr = %addr // Loga o endereço do cliente
            );

            // Gera uma nova task Tokio para lidar com a sessão MCP desta conexão.
            tokio::spawn(
                async move {
                    // Clona o Arc do handler específico da conexão para a task.
                    let mcp_handler_instance = (*mcp_handler_for_this_connection).clone();
                    let token_for_serve = connection_specific_shutdown_token.clone();

                    info!(
                        "Iniciando handshake e serviço MCP (serve_with_ct). Token is_cancelled: {}",
                        token_for_serve.is_cancelled()
                    );

                    // Inicia o serviço MCP, que lida com o handshake e o processamento de mensagens.
                    // `serve_with_ct` respeita o token de cancelamento.
                    let running_service_result: Result<
                        RunningService<RoleServer, McpServiceHandler>, 
                        ServerInitializeError<std::io::Error>, // Tipo de erro do rmcp
                    > = mcp_handler_instance.serve_with_ct(adapter, token_for_serve).await;

                    match running_service_result {
                        Ok(running_service) => {
                            // Handshake bem-sucedido.
                            info!(
                                client.user_id = %user_id_for_inner_task_log,
                                "Handshake MCP bem-sucedido. Aguardando conclusão do serviço."
                            );
                            // Aguarda a conclusão do serviço (ex: cliente desconecta, erro, shutdown).
                            match running_service.waiting().await {
                                Ok(quit_reason) => {
                                    info!(
                                        client.user_id = %user_id_for_inner_task_log,
                                        "Serviço MCP para WebSocket encerrado: {:?}",
                                        quit_reason
                                    );
                                }
                                Err(join_error) => {
                                    // Erro na task do serviço MCP.
                                    error!(
                                        client.user_id = %user_id_for_inner_task_log,
                                        error.message = %join_error,
                                        "Task do serviço MCP falhou (JoinError)."
                                    );
                                }
                            }
                        }
                        Err(init_err) => {
                            // Falha no handshake MCP.
                            error!(
                                client.user_id = %user_id_for_inner_task_log,
                                error.message = %init_err.to_string(),
                                "Falha na inicialização (handshake) do serviço MCP."
                            );
                        }
                    }
                    info!(
                        "Task de conexão MCP para user '{}' finalizada. Token (conn) is_cancelled: {}",
                        user_id_for_inner_task_log,
                        connection_specific_shutdown_token.is_cancelled()
                    );
                }
                .instrument(connection_span), // Associa a task ao span de tracing da conexão
            );
        }
    })
}

/// Configura handlers de sinal (SIGINT, SIGTERM) para iniciar o graceful shutdown.
///
/// Ao receber um sinal, cancela o `CancellationToken` global, que é observado
/// por outros componentes (como o servidor Axum) para iniciar seu próprio desligamento.
///
/// # Parâmetros
/// * `token`: O `CancellationToken` global a ser cancelado ao receber um sinal.
fn setup_signal_handler(token: CancellationToken) {
    tokio::spawn(async move {
        // Configura handlers específicos para Unix (SIGINT, SIGTERM)
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigint = match signal(SignalKind::interrupt()) { // Ctrl+C
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[FATAL_ERROR] Falha ao instalar handler SIGINT: {}. Encerrando.", e);
                    std::process::exit(1);
                }
            };
            let mut sigterm = match signal(SignalKind::terminate()) { // kill
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[FATAL_ERROR] Falha ao instalar handler SIGTERM: {}. Encerrando.", e);
                    std::process::exit(1);
                }
            };

            // Aguarda por um dos sinais ou pelo cancelamento do token.
            tokio::select! {
                biased; // Prioriza o token.cancelled() se já estiver cancelado.
                _ = token.cancelled() => {
                    debug!("Handler de sinal: Token global já cancelado.");
                },
                _ = sigint.recv() => {
                    info!("Recebido SIGINT (Ctrl+C), iniciando desligamento...");
                    if !token.is_cancelled() { token.cancel(); }
                },
                _ = sigterm.recv() => {
                    info!("Recebido SIGTERM, iniciando desligamento...");
                    if !token.is_cancelled() { token.cancel(); }
                },
            }
        }
        // Configura handler para Windows (Ctrl+C)
        #[cfg(windows)]
        {
            tokio::select! {
                biased;
                _ = token.cancelled() => {
                    debug!("Handler de sinal: Token global já cancelado.");
                },
                _ = tokio::signal::ctrl_c() => {
                    info!("Recebido Ctrl-C (Windows), iniciando desligamento...");
                    if !token.is_cancelled() { token.cancel(); }
                }
            }
        }
        // Garante que o token seja cancelado se o handler de sinal sair por outro motivo.
        if !token.is_cancelled() {
            warn!("Handler de sinal terminou sem cancelamento por sinal. Cancelando agora.");
            token.cancel();
        }
        debug!("Handler de sinal encerrado.");
    });
}