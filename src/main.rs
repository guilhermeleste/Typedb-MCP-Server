// src/main.rs

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

//! Ponto de entrada principal para o Typedb-MCP-Server.
//!
//! Configura e inicia o servidor MCP, que escuta por conexões WebSocket,
//! lida com autenticação `OAuth2`, e despacha requisições de ferramentas
//! para o `McpServiceHandler`. Também configura logging, métricas e tracing.

// std imports
use std::{
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

// axum imports
use axum::{
    extract::{
        ws::WebSocketUpgrade, 
        Extension, State,
    },
    http::StatusCode,
    middleware::from_fn_with_state,
    response::{IntoResponse, Response as AxumResponse},
    routing::get, Router,
};

// tokio imports
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

// TLS agora é feito via axum_server::RustlsConfig

use typedb_mcp_server_lib::{
    auth::{ClientAuthContext, JwksCache, oauth_middleware},
    config::Settings, 
    db,
    error::{McpServerError, AuthErrorDetail}, 
    mcp_service_handler::McpServiceHandler,
    metrics, telemetry,
    transport::WebSocketTransport,
};

// Crates de Observabilidade
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use reqwest::Client as ReqwestClient;
use rmcp::service::ServiceExt as RmcpServiceExt; 
use tracing_subscriber::{
    fmt as tracing_fmt, EnvFilter,
    prelude::*,
};
use typedb_driver::TypeDBDriver;


/// Estrutura para o estado da aplicação compartilhado com os handlers Axum.
#[derive(Clone)]
struct AppState {
    mcp_handler: Arc<McpServiceHandler>,
    settings: Arc<Settings>,
    jwks_cache: Option<Arc<JwksCache>>,
    typedb_driver_ref: Arc<TypeDBDriver>,
    global_shutdown_token: CancellationToken,
}

/// Ponto de entrada principal da aplicação.
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if dotenvy::dotenv().is_err() {
        println!("Arquivo .env não encontrado ou falha ao carregar. Usando variáveis de ambiente do sistema se disponíveis.");
    }

    let settings = match Settings::new() {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("Erro fatal ao carregar a configuração: {e}. Encerrando.");
            return Err(Box::new(std::io::Error::other(e.to_string())));
        }
    };

    setup_logging_and_tracing(&settings);

    tracing::info!("Iniciando Typedb-MCP-Server versão {}", env!("CARGO_PKG_VERSION"));
    tracing::debug!(config = ?settings, "Configurações carregadas.");

    let worker_threads = settings.server.worker_threads.unwrap_or_else(|| {
        let cores = num_cpus::get();
        tracing::info!("Número de server.worker_threads não configurado, usando default: {}", cores);
        cores
    });
    tracing::info!("Usando {} threads de worker para o runtime Tokio.", worker_threads);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(worker_threads)
        .thread_name("typedb-mcp-worker")
        .build()?;

    rt.block_on(async_main(settings))
}

/// Função principal assíncrona que configura e executa o servidor.
#[tracing::instrument(name="server_main_async_logic", skip_all)]
async fn async_main(settings: Arc<Settings>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let global_shutdown_token = CancellationToken::new();
    setup_signal_handler(global_shutdown_token.clone());

    let metrics_bind_addr_str = settings.server.metrics_bind_address
        .clone()
        .unwrap_or_else(|| "0.0.0.0:9090".to_string());

    let metrics_handle_opt: Option<PrometheusHandle> = match setup_metrics(&metrics_bind_addr_str) {
        Ok(handle) => Some(handle),
        Err(e) => {
            tracing::error!("Falha ao iniciar o servidor de métricas Prometheus em {}: {}. Métricas não estarão disponíveis.", metrics_bind_addr_str, e);
            None
        }
    };

    tracing::info!(
        "Conectando ao TypeDB em: {} (TLS: {})",
        settings.typedb.address,
        settings.typedb.tls_enabled
    );
    let typedb_password_from_env = std::env::var("TYPEDB_PASSWORD").ok();

    let typedb_driver = match db::connect(
        Some(settings.typedb.address.clone()),
        settings.typedb.username.clone(),
        typedb_password_from_env,
        settings.typedb.tls_enabled,
        settings.typedb.tls_ca_path.clone(),
    )
    .await
    {
        Ok(driver) => {
            tracing::info!("Conexão com TypeDB estabelecida com sucesso.");
            Arc::new(driver)
        }
        Err(e) => {
            tracing::error!("Falha fatal ao conectar com TypeDB: {}", e.message());
            return Err(Box::new(e));
        }
    };

    let jwks_cache = if settings.oauth.enabled {
        let jwks_uri = settings.oauth.jwks_uri.as_ref().ok_or_else(|| {
            let msg = "OAuth2 habilitado, mas oauth.jwks_uri não configurado.";
            tracing::error!("{}", msg);
            McpServerError::Auth(AuthErrorDetail::InvalidAuthConfig(msg.to_string()))
        })?;
        let client = ReqwestClient::builder()
            .timeout(settings.oauth.jwks_request_timeout_seconds.map_or(Duration::from_secs(10), Duration::from_secs))
            .build()?;
        let cache = Arc::new(JwksCache::new(
            jwks_uri.clone(),
            settings.oauth.jwks_refresh_interval.unwrap_or(Duration::from_secs(3600)),
            client,
        ));
        if let Err(e) = cache.refresh_keys().await {
            tracing::warn!("Falha no refresh inicial do JWKS (servidor continuará tentando em background): {}", e);
        } else {
            tracing::info!("JWKS cache inicializado e chaves buscadas (ou tentativa).");
        }
        Some(cache)
    } else {
        None
    };

    let mcp_handler = Arc::new(McpServiceHandler::new(
        typedb_driver.clone(),
        settings.clone(),
    ));

    let app_state = AppState {
        mcp_handler,
        settings: settings.clone(),
        jwks_cache: jwks_cache.clone(),
        typedb_driver_ref: typedb_driver.clone(),
        global_shutdown_token: global_shutdown_token.clone(),
    };

    let mcp_ws_path_str = settings.server.mcp_websocket_path.clone().unwrap_or_else(|| "/mcp/ws".to_string());
    let metrics_path_str = settings.server.metrics_path.clone().unwrap_or_else(|| "/metrics".to_string());

    let mut base_router = Router::new()
        .route("/livez", get(livez_handler))
        .route("/readyz", get(readyz_handler).with_state(app_state.clone()));


    if let Some(metrics_h) = metrics_handle_opt {
        base_router = base_router.route(&metrics_path_str, get(metrics_handler).with_state(metrics_h));
    }
    
    let mut mcp_ws_router = Router::new().route(&mcp_ws_path_str, get(websocket_handler));

    if settings.oauth.enabled {
        if let Some(jwks_cache_for_middleware) = app_state.jwks_cache.clone() { 
            let oauth_config_for_middleware = Arc::new(settings.oauth.clone());
            tracing::info!("Middleware OAuth2 habilitado para o endpoint MCP WebSocket: {}", mcp_ws_path_str);
            mcp_ws_router = mcp_ws_router.route_layer(from_fn_with_state(
                (jwks_cache_for_middleware, oauth_config_for_middleware),
                oauth_middleware,
            ));
        } else {
            tracing::error!("OAuth está habilitado, mas JwksCache não inicializado. Auth falhará.");
        }
    } else {
        tracing::info!("Autenticação OAuth2 desabilitada.");
    }
    let router_with_mcp_and_app_state = mcp_ws_router.with_state(app_state.clone()); 
    
    let final_router = base_router.merge(router_with_mcp_and_app_state);

    let bind_address_str = settings.server.bind_address.clone();
    let bind_addr: SocketAddr = bind_address_str.parse().map_err(|e| {
        format!("Endereço de bind inválido '{bind_address_str}': {e}")
    })?;

    if settings.server.tls_enabled {
        let cert_path_str = settings.server.tls_cert_path.as_ref().ok_or_else(|| {
            McpServerError::Auth(AuthErrorDetail::InvalidAuthConfig("server.tls_cert_path não configurado com TLS habilitado".to_string()))
        })?;
        let key_path_str = settings.server.tls_key_path.as_ref().ok_or_else(|| {
             McpServerError::Auth(AuthErrorDetail::InvalidAuthConfig("server.tls_key_path não configurado com TLS habilitado".to_string()))
        })?;

        tracing::info!("Servidor MCP (HTTPS/WSS) escutando em {}", bind_addr);
        tracing::info!("Usando certificado: {}", cert_path_str);
        tracing::info!("Usando chave privada: {}", key_path_str);

        use axum_server::tls_rustls::RustlsConfig;
        let config = RustlsConfig::from_pem_file(cert_path_str, key_path_str).await
            .map_err(|e| format!("Erro ao carregar certificado/chave PEM: {e}"))?;
        axum_server::bind_rustls(bind_addr, config)
            .serve(final_router.into_make_service())
            .await?;

    } else {
        tracing::info!("Servidor MCP (HTTP/WS) escutando em {}", bind_addr);
        let listener = TcpListener::bind(bind_addr).await?;
        axum::serve(listener, final_router)
            .with_graceful_shutdown(global_shutdown_token.cancelled_owned())
            .await?;
    }

    tracing::info!("Graceful shutdown: Aguardando finalização de tasks pendentes...");
    
    typedb_driver.force_close()?;
    tracing::info!("Conexão com TypeDB fechada.");

    if settings.tracing.enabled {
        telemetry::shutdown_tracer_provider();
    }

    tracing::info!("Typedb-MCP-Server desligado graciosamente.");
    Ok(())
}

/// Handler para o endpoint de liveness (`/livez`).
/// Indica se a aplicação está rodando.
async fn livez_handler() -> StatusCode {
    StatusCode::OK
}

/// Handler para o endpoint de readiness (`/readyz`).
/// Indica se a aplicação está pronta para receber tráfego.
async fn readyz_handler(State(app_state): State<AppState>) -> Result<StatusCode, StatusCode> {
    if !app_state.typedb_driver_ref.is_open() {
        tracing::warn!("/readyz: Conexão com TypeDB não está aberta.");
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }

    if app_state.settings.oauth.enabled {
        if let Some(cache) = &app_state.jwks_cache {
            if !cache.is_cache_ever_populated().await { 
                 tracing::warn!("/readyz: Cache JWKS ainda não foi populado ou falhou no refresh inicial.");
                 return Err(StatusCode::SERVICE_UNAVAILABLE);
            }
        } else {
            tracing::error!("/readyz: OAuth habilitado mas JwksCache não está presente no estado da aplicação. Isto é um erro de configuração interna.");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }
    Ok(StatusCode::OK)
}

/// Handler para o endpoint de métricas (`/metrics`).
/// Retorna as métricas no formato Prometheus.
async fn metrics_handler(State(prom_handle): State<PrometheusHandle>) -> AxumResponse {
    prom_handle.render().into_response()
}


/// Handler para conexões WebSocket MCP.
///
/// Realiza o upgrade da conexão para WebSocket e inicia o serviço MCP
/// usando o `McpServiceHandler` e `WebSocketTransport`.
#[tracing::instrument(skip_all, name = "mcp_websocket_handler", fields(client.user_id))]
async fn websocket_handler(
    ws: WebSocketUpgrade, 
    State(app_state): State<AppState>,
    maybe_auth_context: Option<Extension<Arc<ClientAuthContext>>>,
) -> impl IntoResponse {
    let user_id_for_log = maybe_auth_context
        .as_ref().map_or_else(|| "não_autenticado".to_string(), |Extension(ctx)| ctx.user_id.clone());
    
    tracing::Span::current().record("client.user_id", tracing::field::display(&user_id_for_log));
    tracing::info!("Nova tentativa de conexão WebSocket MCP.");

    if app_state.settings.oauth.enabled && maybe_auth_context.is_none() {
        tracing::error!("OAuth habilitado, mas ClientAuthContext ausente. Rejeitando WebSocket.");
        return (StatusCode::UNAUTHORIZED, "Autenticação OAuth2 falhou ou está ausente.").into_response();
    }
    
    let conn_cancellation_token = app_state.global_shutdown_token.child_token();
    let service_shutdown_token = conn_cancellation_token.clone(); 
    let _adapter_shutdown_token = conn_cancellation_token;

    ws.on_upgrade(move |socket| async move { 
        tracing::info!("Conexão WebSocket MCP estabelecida.");
        
        let mcp_handler_instance = (*app_state.mcp_handler).clone(); 
        let adapter = WebSocketTransport::new(socket);

        tokio::spawn(async move {
            if let Err(e) = mcp_handler_instance.serve_with_ct(adapter, service_shutdown_token).await { 
                let error_string = e.to_string();
                if error_string.contains("operação cancelada") || 
                     error_string.contains("Connection reset by peer") ||
                     error_string.contains("Broken pipe") ||
                     error_string.to_lowercase().contains("connection closed") ||
                     error_string.to_lowercase().contains("channel closed") ||
                     error_string.contains("IO error: Connection reset by peer") ||
                     error_string.contains("IO error: Broken pipe") {
                    tracing::info!(client.user_id = %user_id_for_log, "Serviço MCP para conexão WebSocket encerrado (cancelado ou desconectado): {}", e);
                } else {
                    tracing::error!(client.user_id = %user_id_for_log, error.message = %e, "Erro no serviço MCP para a conexão WebSocket.");
                }
            }
            tracing::info!(client.user_id = %user_id_for_log, "Serviço MCP para conexão WebSocket finalizado.");
        });
    })
}


/// Configura o logging estruturado e o tracing OpenTelemetry.
fn setup_logging_and_tracing(settings: &Settings) {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(settings.logging.rust_log.clone()));

    let formatting_layer = tracing_fmt::layer()
        .json()
        .with_current_span(true)
        .with_span_list(true)
        .with_target(true)
        .with_file(true)
        .with_line_number(true);

    if settings.tracing.enabled {
        if telemetry::init_tracing_pipeline(&settings.tracing).is_ok() {
            let telemetry_layer = tracing_opentelemetry::layer();
            tracing_subscriber::registry()
                .with(env_filter)
                .with(formatting_layer)
                .with(telemetry_layer)
                .init();
            tracing::info!(
                "OpenTelemetry tracing habilitado e configurado para exportar para: {:?}",
                settings.tracing.exporter_otlp_endpoint
            );
        } else {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(formatting_layer)
                .init();
            tracing::warn!(
                "Falha ao inicializar OpenTelemetry pipeline (verifique a configuração do endpoint OTLP). Tracing distribuído desabilitado."
            );
        }
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(formatting_layer)
            .init();
        tracing::info!("OpenTelemetry tracing desabilitado.");
    }
}


/// Configura e inicia o servidor de métricas Prometheus.
fn setup_metrics(metrics_bind_address_str: &str) -> Result<PrometheusHandle, Box<dyn std::error::Error + Send + Sync>> {
    metrics::register_metrics_descriptions();

    let metrics_socket_addr: SocketAddr = metrics_bind_address_str.parse().map_err(|e| {
        format!("Endereço de bind inválido para métricas '{metrics_bind_address_str}': {e}")
    })?;

    PrometheusBuilder::new()
        .with_http_listener(metrics_socket_addr)
        .install_recorder()
        .inspect(|_handle| { // Adicionado sublinhado para indicar variável não utilizada
            tracing::info!("Servidor de métricas Prometheus escutando em {}", metrics_socket_addr);
        })
        .map_err(|e| {
            let err_msg = format!("Não foi possível iniciar o servidor de métricas Prometheus em {metrics_socket_addr}: {e}. As métricas não estarão disponíveis.");
            tracing::error!("{}", err_msg);
            Box::new(std::io::Error::other(err_msg)) as Box<dyn std::error::Error + Send + Sync>
        })
}

/// Configura os handlers de sinal para o graceful shutdown.
fn setup_signal_handler(token: CancellationToken) {
    tokio::spawn(async move { 
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigint = signal(SignalKind::interrupt()).expect("Falha ao instalar handler SIGINT");
            let mut sigterm = signal(SignalKind::terminate()).expect("Falha ao instalar handler SIGTERM");

            tokio::select! {
                biased;
                () = token.cancelled() => {},
                _ = sigint.recv() => tracing::info!("Recebido SIGINT, iniciando desligamento..."),
                _ = sigterm.recv() => tracing::info!("Recebido SIGTERM, iniciando desligamento..."),
            }
        }
        #[cfg(windows)]
        {
            tokio::select! {
                biased;
                _ = token.cancelled() => {},
                _ = tokio::signal::ctrl_c() => { 
                    tracing::info!("Recebido Ctrl-C, iniciando desligamento...");
                }
            }
        }
        if !token.is_cancelled() {
            token.cancel();
        }
    });
}

