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

//! Ponto de entrada principal para o Typedb-MCP-Server.

use anyhow::Context;
use axum::{
    extract::{ws::WebSocketUpgrade, ConnectInfo, Extension, State},
    http::StatusCode,
    middleware::from_fn_with_state,
    response::{IntoResponse, Response as AxumResponse},
    routing::get,
    Router,
};
use axum_server::{tls_rustls::RustlsConfig, Handle as AxumServerHandle};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use reqwest::Client as ReqwestClient;
use rmcp::service::{
    RoleServer, RunningService, ServerInitializeError, ServiceExt as RmcpServiceExt,
};
use rustls::crypto::CryptoProvider;
use std::{error::Error as StdError, net::SocketAddr, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn, Dispatch, Instrument};
use tracing_subscriber::{fmt, prelude::*, EnvFilter, Registry};
use typedb_driver::TypeDBDriver;
use typedb_mcp_server_lib::{
    auth::{oauth_middleware, ClientAuthContext, JwksCache},
    config::{Server as AppServerConfig, Settings},
    db::connect as connect_to_typedb,
    mcp_service_handler::McpServiceHandler,
    metrics, telemetry,
    transport::WebSocketTransport,
    AuthErrorDetail, McpServerError,
};

/// Estrutura para o estado da aplicação compartilhado com os handlers Axum.
#[derive(Clone)]
struct AppState {
    typedb_driver_ref: Arc<TypeDBDriver>,
    settings: Arc<Settings>,
    jwks_cache: Option<Arc<JwksCache>>,
    global_shutdown_token: CancellationToken,
}

/// Configura o sistema global de logging e tracing.
fn setup_global_logging_and_tracing(
    settings: &Settings,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(settings.logging.rust_log.clone()));

    let formatting_layer = fmt::layer()
        .json()
        .with_current_span(true)
        .with_span_list(true)
        .with_target(true)
        .with_file(true)
        .with_line_number(true);

    let subscriber_builder = Registry::default().with(env_filter).with(formatting_layer);

    if settings.tracing.enabled {
        if let Err(e) = telemetry::init_tracing_pipeline(&settings.tracing) {
            let subscriber = subscriber_builder;
            tracing::dispatcher::set_global_default(Dispatch::new(subscriber))?;
            warn!(
                "Falha ao inicializar OpenTelemetry pipeline: {}. Tracing distribuído desabilitado.",
                e
            );
        } else {
            let telemetry_layer = tracing_opentelemetry::layer();
            let subscriber = subscriber_builder.with(telemetry_layer);
            tracing::dispatcher::set_global_default(Dispatch::new(subscriber))?;
            info!(
                "OpenTelemetry tracing habilitado e configurado para exportar para: {:?}",
                settings.tracing.exporter_otlp_endpoint
            );
        }
    } else {
        let subscriber = subscriber_builder;
        tracing::dispatcher::set_global_default(Dispatch::new(subscriber))?;
        info!("OpenTelemetry tracing desabilitado.");
    }
    Ok(())
}

/// Configura e instala o recorder de métricas Prometheus, retornando o handle.
fn setup_metrics_recorder(
    _server_settings: &AppServerConfig,
) -> Result<PrometheusHandle, Box<dyn StdError + Send + Sync>> {
    metrics::register_metrics_descriptions();
    info!("Descrições de métricas Prometheus registradas.");

    PrometheusBuilder::new().install_recorder().map_err(|e| {
        let err_msg = format!("Não foi possível instalar o recorder de métricas Prometheus: {e}");
        error!("[METRICS_SETUP_ERROR] {}", err_msg);
        Box::new(std::io::Error::other(err_msg)) as Box<dyn StdError + Send + Sync>
    })
}

/// Inicializa os serviços principais dos quais o servidor MCP depende.
async fn initialize_core_services(
    settings: &Arc<Settings>,
) -> Result<(Arc<TypeDBDriver>, Option<Arc<JwksCache>>), Box<dyn StdError + Send + Sync>> {
    info!("Buscando senha do TypeDB do caminho de arquivo especificado...");

    let password_file_path = std::env::var("TYPEDB_PASSWORD_FILE")
        .context("A variável de ambiente TYPEDB_PASSWORD_FILE não foi definida. O entrypoint script deve configurá-la.")?;

    let typedb_password_from_vault =
        std::fs::read_to_string(&password_file_path).with_context(|| {
            format!("Não foi possível ler o arquivo de senha do TypeDB em '{password_file_path}'")
        })?;


    info!(
        "Tentando conectar ao TypeDB. Configurado em: {} (TLS: {})",
        settings.typedb.address, settings.typedb.tls_enabled
    );

    let typedb_driver_instance = match connect_to_typedb(
        Some(settings.typedb.address.clone()),
        settings.typedb.username.clone(),
        Some(typedb_password_from_vault.trim().to_string()),
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
            let mcp_error =
                McpServerError::from(typedb_mcp_server_lib::error::TypeDBErrorWrapper::from(e));
            error!("Falha fatal ao conectar com TypeDB: {}", mcp_error);
            return Err(Box::new(mcp_error));
        }
    };

    let jwks_cache_option = if settings.oauth.enabled {
        let jwks_uri = settings.oauth.jwks_uri.as_ref().ok_or_else(|| {
            let msg = "OAuth2 habilitado, mas oauth.jwks_uri não configurado.";
            error!("{}", msg);
            Box::new(McpServerError::Auth(AuthErrorDetail::InvalidAuthConfig(msg.to_string())))
                as Box<dyn StdError + Send + Sync>
        })?;

        let http_client_timeout = settings.oauth.jwks_request_timeout_seconds.map_or_else(
            || {
                warn!("oauth.jwks_request_timeout_seconds não configurado, usando default de 10s.");
                Duration::from_secs(10)
            },
            Duration::from_secs,
        );

        let http_client =
            ReqwestClient::builder().timeout(http_client_timeout).build().map_err(|e| {
                Box::new(McpServerError::Internal(format!(
                    "Falha ao construir HTTP client para JWKS: {e}"
                )))
            })?;

        let jwks_refresh_interval = settings.oauth.jwks_refresh_interval.unwrap_or_else(|| {
            warn!("oauth.jwks_refresh_interval não pôde ser parseado ou estava ausente, usando default de 1 hora para o cache.");
            Duration::from_secs(3600)
        });

        let cache = Arc::new(JwksCache::new(jwks_uri.clone(), jwks_refresh_interval, http_client));

        match cache.refresh_keys().await {
            Ok(()) => {
                info!("JWKS cache inicializado e populado com sucesso de {}.", jwks_uri);
                Some(cache)
            }
            Err(e) => {
                let err_msg = format!("Falha crítica no refresh inicial do JWKS de {jwks_uri}: {e}. O servidor não pode iniciar com OAuth habilitado sem acesso ao JWKS.");
                error!("{}", err_msg);
                return Err(Box::new(McpServerError::Auth(AuthErrorDetail::JwksFetchFailed(
                    err_msg,
                ))));
            }
        }
    } else {
        None
    };

    Ok((typedb_driver_instance, jwks_cache_option))
}

/// Cria e retorna o estado da aplicação (`AppState`) compartilhado.
fn create_app_state(
    typedb_driver: Arc<TypeDBDriver>,
    settings: Arc<Settings>,
    jwks_cache: Option<Arc<JwksCache>>,
    global_shutdown_token: CancellationToken,
) -> AppState {
    AppState { typedb_driver_ref: typedb_driver, settings, jwks_cache, global_shutdown_token }
}

/// Constrói o router Axum principal com todas as rotas e middlewares.
fn build_axum_router(
    app_state: AppState,
    settings: &Arc<Settings>,
    metrics_handle_opt: Option<PrometheusHandle>,
) -> Router {
    let mcp_ws_path_str =
        settings.server.mcp_websocket_path.clone().unwrap_or_else(|| "/mcp/ws".to_string());
    let metrics_path_str =
        settings.server.metrics_path.clone().unwrap_or_else(|| "/metrics".to_string());

    let mut base_router = Router::new()
        .route("/livez", get(livez_handler))
        .route("/readyz", get(readyz_handler).with_state(app_state.clone()));

    if let Some(metrics_h) = metrics_handle_opt {
        info!("Configurando endpoint de métricas Axum em: {}", metrics_path_str);
        // CORREÇÃO APLICADA: A rota de métricas é adicionada ao `base_router` existente.
        base_router =
            base_router.route(&metrics_path_str, get(metrics_handler).with_state(metrics_h));
    } else {
        warn!(
            "PrometheusHandle não disponível. Endpoint de métricas via Axum não será configurado."
        );
    }

    let mut mcp_ws_router = Router::new().route(&mcp_ws_path_str, get(websocket_handler));

    if settings.oauth.enabled {
        if let Some(jwks_cache_for_middleware) = app_state.jwks_cache.clone() {
            let oauth_config_for_middleware = Arc::new(settings.oauth.clone());
            info!("Middleware OAuth2 habilitado para WebSocket em: {}", mcp_ws_path_str);
            mcp_ws_router = mcp_ws_router.route_layer(from_fn_with_state(
                (jwks_cache_for_middleware, oauth_config_for_middleware),
                oauth_middleware,
            ));
        } else {
            error!("Erro crítico de configuração: OAuth habilitado, mas JwksCache ausente no AppState.");
        }
    } else {
        info!("Autenticação OAuth2 desabilitada para WebSockets.");
    }

    base_router.merge(mcp_ws_router.with_state(app_state))
}

/// Executa o servidor Axum.
async fn run_axum_server(
    router: Router,
    settings: &Arc<Settings>,
    global_shutdown_token: CancellationToken,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    let bind_address_str = settings.server.bind_address.clone();
    let bind_addr: SocketAddr = bind_address_str
        .parse()
        .map_err(|e| format!("Endereço de bind inválido '{bind_address_str}': {e}"))?;

    let server_handle = AxumServerHandle::new();
    let shutdown_task_handle_clone = server_handle.clone();
    let shutdown_token_for_axum_server = global_shutdown_token.clone();

    tokio::spawn(async move {
        shutdown_token_for_axum_server.cancelled().await;
        info!("Sinal de desligamento recebido, iniciando graceful shutdown do servidor Axum...");
        shutdown_task_handle_clone.graceful_shutdown(Some(Duration::from_secs(30)));
    });

    if settings.server.tls_enabled {
        let cert_path_str = settings.server.tls_cert_path.as_ref().ok_or_else(|| {
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

        let tls_config = RustlsConfig::from_pem_file(cert_path_str, key_path_str)
            .await
            .map_err(|e| format!("Erro ao carregar certificado/chave PEM TLS: {e}"))?;

        axum_server::bind_rustls(bind_addr, tls_config)
            .handle(server_handle)
            .serve(router.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    } else {
        info!("Servidor MCP (HTTP/WS) escutando em {}", bind_addr);
        axum_server::bind(bind_addr)
            .handle(server_handle)
            .serve(router.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    }
    Ok(())
}

/// Realiza a limpeza de recursos antes do servidor terminar.
async fn cleanup_resources(
    typedb_driver: Arc<TypeDBDriver>,
    settings: &Arc<Settings>,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    info!("Graceful shutdown: Iniciando limpeza de recursos...");

    if let Err(e) = typedb_driver.force_close() {
        error!("Erro ao fechar conexão com TypeDB: {}", e);
    } else {
        info!("Conexão com TypeDB fechada.");
    }

    if settings.tracing.enabled {
        telemetry::shutdown_tracer_provider();
    }
    info!("Typedb-MCP-Server desligado graciosamente.");
    Ok(())
}

/// Ponto de entrada síncrono da aplicação.
fn main() -> Result<(), Box<dyn StdError + Send + Sync>> {
    if CryptoProvider::get_default().is_none() {
        if let Err(e) = rustls::crypto::ring::default_provider().install_default() {
            eprintln!("[CRYPTO_PROVIDER_FATAL] Falha crítica ao instalar o provedor criptográfico Ring: {e:?}. O servidor não pode continuar se TLS for usado.");
            std::process::exit(1);
        } else {
            println!("[CRYPTO_PROVIDER_SETUP] Provedor criptográfico Ring instalado como padrão para rustls.");
        }
    } else {
        println!("[CRYPTO_PROVIDER_SETUP] Provedor criptográfico padrão para rustls já está instalado globalmente.");
    }

    if dotenvy::dotenv().is_err() {
        println!("[SETUP_INFO] Arquivo .env não encontrado ou falha ao carregar. Usando variáveis de ambiente do sistema se disponíveis.");
    }

    {
        let temp_env_filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        let temp_subscriber = fmt::Subscriber::builder()
            .with_env_filter(temp_env_filter)
            .with_writer(std::io::stderr)
            .json()
            .finish();
        let _temp_guard = tracing::dispatcher::set_default(&Dispatch::new(temp_subscriber));

        info!("Iniciando Typedb-MCP-Server versão {}...", env!("CARGO_PKG_VERSION"));
        info!("Carregando configurações...");

        let settings = match Settings::new() {
            Ok(s) => Arc::new(s),
            Err(config_err) => {
                error!("Erro fatal ao carregar a configuração: {}", config_err);
                if let Some(source) = config_err.source() {
                    error!("   Fonte do erro de configuração: {}", source);
                }
                panic!("Falha ao carregar configurações: {config_err}");
            }
        };

        if let Err(e) = setup_global_logging_and_tracing(&settings) {
            eprintln!(
                "[SETUP_FATAL] Falha crítica ao configurar o sistema de logging/tracing global: {e}. Observabilidade severamente comprometida."
            );
        }

        info!("Configurações carregadas e sistema de logging/tracing global inicializado.");
        debug!(config = ?settings, "Configurações da aplicação carregadas e prontas para uso.");

        let worker_threads = settings.server.worker_threads.unwrap_or_else(|| {
            let cores = num_cpus::get();
            info!("server.worker_threads não configurado, usando default: {}", cores);
            cores
        });
        info!("Usando {} threads de worker para o runtime Tokio.", worker_threads);

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(worker_threads)
            .thread_name("typedb-mcp-worker")
            .build()?;

        rt.block_on(async_main(settings))
    }
}

/// Lógica principal assíncrona da aplicação.
async fn async_main(settings: Arc<Settings>) -> Result<(), Box<dyn StdError + Send + Sync>> {
    let global_shutdown_token = CancellationToken::new();
    setup_signal_handler(global_shutdown_token.clone());

    let metrics_handle_opt = match setup_metrics_recorder(&settings.server) {
        Ok(handle) => {
            info!("Exportador de métricas Prometheus configurado com sucesso (será servido via Axum).");
            let app_version = env!("CARGO_PKG_VERSION");
            let rust_version_val = rustc_version_runtime::version().to_string();

            let startup_counter_name =
                format!("{}{}", metrics::METRIC_PREFIX, "server_startup_total");
            let info_gauge_name =
                format!("{}{}", metrics::METRIC_PREFIX, metrics::SERVER_INFO_GAUGE);

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
    let (typedb_driver, jwks_cache) = match initialize_core_services(&settings).await {
        Ok(services) => {
            info!("Serviços principais (TypeDB, JWKS) inicializados com sucesso.");
            services
        }
        Err(e) => {
            error!("Falha na inicialização dos serviços principais (TypeDB ou JWKS): {}. O servidor será encerrado.", e);
            if !global_shutdown_token.is_cancelled() {
                global_shutdown_token.cancel();
            }
            return Err(e);
        }
    };

    let app_state = create_app_state(
        typedb_driver.clone(),
        settings.clone(),
        jwks_cache,
        global_shutdown_token.clone(),
    );

    let router = build_axum_router(app_state.clone(), &settings, metrics_handle_opt);

    info!("Iniciando servidor Axum (MCP)...");
    if let Err(e) = run_axum_server(router, &settings, global_shutdown_token.clone()).await {
        error!("Erro fatal ao executar o servidor Axum: {}", e);
        if !global_shutdown_token.is_cancelled() {
            global_shutdown_token.cancel();
        }
        return Err(e);
    }

    info!("Servidor Axum (MCP) encerrou. Aguardando sinal de desligamento global para limpeza final...");
    global_shutdown_token.cancelled().await;
    info!("Sinal de desligamento global recebido, procedendo com a limpeza de recursos...");

    cleanup_resources(typedb_driver, &settings).await?;

    info!("async_main concluído com sucesso.");
    Ok(())
}

/// Handler para o endpoint de liveness (`/livez`).
async fn livez_handler() -> StatusCode {
    tracing::trace!("Recebida requisição /livez");
    StatusCode::OK
}

/// Handler para o endpoint de readiness (`/readyz`).
async fn readyz_handler(State(app_state): State<AppState>) -> impl IntoResponse {
    tracing::debug!("Verificando prontidão do servidor para /readyz...");
    let mut ready_components = serde_json::Map::new();
    let mut overall_ready = true;

    match app_state.typedb_driver_ref.databases().all().await {
        Ok(_) => {
            if app_state.typedb_driver_ref.is_open() {
                ready_components.insert("typedb".to_string(), serde_json::json!("UP"));
            } else {
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
    (status_code, axum::Json(response_body)).into_response()
}

/// Handler para o endpoint de métricas Prometheus (ex: `/metrics`).
async fn metrics_handler(State(prometheus_handle): State<PrometheusHandle>) -> AxumResponse {
    tracing::trace!("[METRICS_HANDLER_AXUM] Recebida requisição para /metrics");
    let metrics_data = prometheus_handle.render();
    tracing::trace!("[METRICS_HANDLER_AXUM] Métricas renderizadas com sucesso");
    (StatusCode::OK, [("content-type", "text/plain; version=0.0.4; charset=utf-8")], metrics_data)
        .into_response()
}

/// Handler para conexões WebSocket MCP.
#[tracing::instrument(
    name = "websocket_connection_upgrade",
    skip_all,
    fields(
        client.addr = %addr,
    )
)]
async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(app_state): State<AppState>,
    maybe_auth_context: Option<Extension<Arc<ClientAuthContext>>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    let user_id_for_log = maybe_auth_context
        .as_ref()
        .map_or_else(|| "<não_autenticado>".to_string(), |Extension(ctx)| ctx.user_id.clone());

    tracing::Span::current().record("client.user_id", tracing::field::display(&user_id_for_log));
    info!("Nova tentativa de conexão WebSocket MCP.");

    if app_state.settings.oauth.enabled && maybe_auth_context.is_none() {
        warn!("OAuth habilitado, mas ClientAuthContext ausente no websocket_handler. Rejeitando upgrade WebSocket.");
        return (StatusCode::UNAUTHORIZED, "Autenticação OAuth2 falhou ou está ausente.")
            .into_response();
    }

    let auth_context_for_this_connection = maybe_auth_context.map(|Extension(ctx)| ctx);

    let mcp_handler_for_this_connection = Arc::new(McpServiceHandler::new_for_connection(
        app_state.typedb_driver_ref.clone(),
        app_state.settings.clone(),
        auth_context_for_this_connection,
    ));

    let global_shutdown_token_clone = app_state.global_shutdown_token.clone();

    ws.on_upgrade(move |socket| async move {
        let connection_specific_shutdown_token = global_shutdown_token_clone.child_token();
        info!("Conexão WebSocket MCP estabelecida.");
        let adapter = WebSocketTransport::new(socket);

        let user_id_for_inner_task_log = user_id_for_log;
        let connection_span = tracing::info_span!(
            "mcp_connection_task",
            client.user_id = %user_id_for_inner_task_log,
            client.addr = %addr
        );

        tokio::spawn(
            async move {
                let mcp_handler_instance = (*mcp_handler_for_this_connection).clone();
                let token_for_serve = connection_specific_shutdown_token.clone();

                info!(
                    "Iniciando handshake e serviço MCP (serve_with_ct). Token is_cancelled: {}",
                    token_for_serve.is_cancelled()
                );

                let running_service_result: Result<
                    RunningService<RoleServer, McpServiceHandler>,
                    ServerInitializeError<std::io::Error>,
                > = mcp_handler_instance.serve_with_ct(adapter, token_for_serve).await;

                match running_service_result {
                    Ok(running_service) => {
                        info!(
                            client.user_id = %user_id_for_inner_task_log,
                            "Handshake MCP bem-sucedido. Aguardando conclusão do serviço."
                        );
                        match running_service.waiting().await {
                            Ok(quit_reason) => {
                                info!(
                                    client.user_id = %user_id_for_inner_task_log,
                                    "Serviço MCP para WebSocket encerrado: {:?}",
                                    quit_reason
                                );
                            }
                            Err(join_error) => {
                                error!(
                                    client.user_id = %user_id_for_inner_task_log,
                                    error.message = %join_error,
                                    "Task do serviço MCP falhou (JoinError)."
                                );
                            }
                        }
                    }
                    Err(init_err) => {
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
            .instrument(connection_span),
        );
    })
}

/// Configura handlers de sinal (SIGINT, SIGTERM) para iniciar o graceful shutdown.
fn setup_signal_handler(token: CancellationToken) {
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigint = match signal(SignalKind::interrupt()) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[FATAL_ERROR] Falha ao instalar handler SIGINT: {e}. Encerrando.");
                    std::process::exit(1);
                }
            };
            let mut sigterm = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!(
                        "[FATAL_ERROR] Falha ao instalar handler SIGTERM: {e}. Encerrando."
                    );
                    std::process::exit(1);
                }
            };

            tokio::select! {
                biased;
                () = token.cancelled() => {
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
        if !token.is_cancelled() {
            warn!("Handler de sinal terminou sem cancelamento por sinal. Cancelando agora.");
            token.cancel();
        }
        debug!("Handler de sinal encerrado.");
    });
}
