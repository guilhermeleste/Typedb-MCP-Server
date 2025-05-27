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
use std::{error::Error as StdError, net::SocketAddr, sync::Arc, time::Duration};

// axum imports
use axum::{
    extract::{ws::WebSocketUpgrade, ConnectInfo, Extension, State},
    http::StatusCode,
    middleware::from_fn_with_state,
    response::{IntoResponse, Response as AxumResponse},
    routing::get,
    Router,
};
use axum_server::{tls_rustls::RustlsConfig, Handle as AxumServerHandle};
use tokio_util::sync::CancellationToken;
// typedb_mcp_server_lib imports
use typedb_mcp_server_lib::{
    auth::{oauth_middleware, ClientAuthContext, JwksCache},
    config::{Server as AppServerConfig, Settings},
    db::connect as connect_to_typedb,
    mcp_service_handler::McpServiceHandler,
    metrics, telemetry,
    transport::WebSocketTransport,
    AuthErrorDetail, McpServerError, // McpServerError para erros locais
};
// Crates de Observabilidade
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use reqwest::Client as ReqwestClient;
use rmcp::service::ServiceExt as RmcpServiceExt;
use tracing::{warn, Dispatch, Instrument}; // Instrument e warn importados
use tracing_subscriber::{fmt, prelude::*, EnvFilter, Registry};
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

/// Configura o logging estruturado global e o tracing OpenTelemetry.
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
        match telemetry::init_tracing_pipeline(&settings.tracing) {
            Ok(()) => {
                let telemetry_layer = tracing_opentelemetry::layer();
                let subscriber = subscriber_builder.with(telemetry_layer);
                tracing::dispatcher::set_global_default(Dispatch::new(subscriber))?;
                tracing::info!(
                    "OpenTelemetry tracing habilitado e configurado para exportar para: {:?}",
                    settings.tracing.exporter_otlp_endpoint
                );
            }
            Err(e) => {
                let subscriber = subscriber_builder;
                tracing::dispatcher::set_global_default(Dispatch::new(subscriber))?;
                tracing::warn!(
                    "Falha ao inicializar OpenTelemetry pipeline: {}. Tracing distribuído desabilitado.", e
                );
            }
        }
    } else {
        let subscriber = subscriber_builder;
        tracing::dispatcher::set_global_default(Dispatch::new(subscriber))?;
        tracing::info!("OpenTelemetry tracing desabilitado.");
    }
    Ok(())
}

/// Configura e inicia o servidor de métricas Prometheus.
fn setup_metrics_server(
    server_settings: &AppServerConfig,
) -> Result<PrometheusHandle, Box<dyn StdError + Send + Sync>> {
    metrics::register_metrics_descriptions();
    let metrics_bind_addr_str =
        server_settings.metrics_bind_address.clone().unwrap_or_else(|| "0.0.0.0:9090".to_string());
    let metrics_socket_addr: SocketAddr = metrics_bind_addr_str.parse().map_err(|e| {
        format!("Endereço de bind inválido para métricas '{metrics_bind_addr_str}': {e}")
    })?;
    PrometheusBuilder::new()
        .with_http_listener(metrics_socket_addr)
        .install_recorder()
        .map_err(|e| {
            let err_msg = format!(
                "Não foi possível iniciar o servidor de métricas Prometheus em {metrics_socket_addr}: {e}"
            );
            eprintln!("[ERROR] {}", err_msg);
            Box::new(std::io::Error::other(err_msg)) as Box<dyn StdError + Send + Sync>
        })
}

/// Inicializa os serviços principais.
async fn initialize_core_services(
    settings: &Arc<Settings>,
) -> Result<(Arc<TypeDBDriver>, Option<Arc<JwksCache>>), Box<dyn StdError + Send + Sync>> {
    tracing::info!(
        "Tentando conectar ao TypeDB. Configurado em: {} (TLS: {})",
        settings.typedb.address,
        settings.typedb.tls_enabled
    );
    let typedb_password_from_env = std::env::var("TYPEDB_PASSWORD").ok();
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
            tracing::info!("Conexão com TypeDB estabelecida com sucesso.");
            Arc::new(driver)
        }
        Err(e) => {
            let mcp_error =
                McpServerError::from(typedb_mcp_server_lib::error::TypeDBErrorWrapper::from(e));
            tracing::error!("Falha fatal ao conectar com TypeDB: {}", mcp_error);
            // Retorna o erro para impedir a inicialização
            return Err(Box::new(mcp_error));
        }
    };

    let jwks_cache_option = if settings.oauth.enabled {
        let jwks_uri = settings.oauth.jwks_uri.as_ref().ok_or_else(|| {
            let msg = "OAuth2 habilitado, mas oauth.jwks_uri não configurado.";
            tracing::error!("{}", msg);
            // Envolve em Box<dyn StdError ...>
            Box::new(McpServerError::Auth(AuthErrorDetail::InvalidAuthConfig(msg.to_string())))
                as Box<dyn StdError + Send + Sync>
        })?;

        let http_client_timeout = settings
            .oauth
            .jwks_request_timeout_seconds
            .map_or_else(
                || {
                    warn!("oauth.jwks_request_timeout_seconds não configurado, usando default de 10s.");
                    Duration::from_secs(10)
                },
                Duration::from_secs,
            );
        
        let http_client = ReqwestClient::builder()
            .timeout(http_client_timeout)
            .build()
            .map_err(|e| Box::new(McpServerError::Internal(format!("Falha ao construir HTTP client para JWKS: {}", e))))?;
            
        let jwks_refresh_interval = settings.oauth.jwks_refresh_interval.unwrap_or_else(|| {
            warn!("oauth.jwks_refresh_interval não pôde ser parseado ou estava ausente, usando default de 1 hora para o cache.");
            Duration::from_secs(3600) // 1 hora
        });

        let cache = Arc::new(JwksCache::new(
            jwks_uri.clone(),
            jwks_refresh_interval,
            http_client,
        ));

        // Tratar falha no refresh inicial do JWKS como erro fatal
        match cache.refresh_keys().await {
            Ok(()) => {
                tracing::info!("JWKS cache inicializado e populado com sucesso de {}.", jwks_uri);
                Some(cache)
            }
            Err(e) => {
                let err_msg = format!("Falha crítica no refresh inicial do JWKS de {}: {}. O servidor não pode iniciar com OAuth habilitado sem acesso ao JWKS.", jwks_uri, e);
                tracing::error!("{}", err_msg);
                // Retorna o erro para impedir a inicialização
                return Err(Box::new(McpServerError::Auth(AuthErrorDetail::JwksFetchFailed(err_msg))));
            }
        }
    } else {
        None // OAuth desabilitado, sem cache JWKS
    };
    
    Ok((typedb_driver_instance, jwks_cache_option))
}


/// Cria o estado da aplicação compartilhado.
fn create_app_state(
    typedb_driver: Arc<TypeDBDriver>,
    settings: Arc<Settings>,
    jwks_cache: Option<Arc<JwksCache>>,
    global_shutdown_token: CancellationToken,
) -> AppState {
    let mcp_handler = Arc::new(McpServiceHandler::new(typedb_driver.clone(), settings.clone()));
    AppState {
        mcp_handler,
        settings,
        jwks_cache,
        typedb_driver_ref: typedb_driver,
        global_shutdown_token,
    }
}

/// Constrói o router Axum.
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
        base_router =
            base_router.route(&metrics_path_str, get(metrics_handler).with_state(metrics_h));
    }

    let mut mcp_ws_router = Router::new().route(&mcp_ws_path_str, get(websocket_handler));

    if settings.oauth.enabled {
        if let Some(jwks_cache_for_middleware) = app_state.jwks_cache.clone() {
            let oauth_config_for_middleware = Arc::new(settings.oauth.clone());
            tracing::info!("Middleware OAuth2 habilitado para: {}", mcp_ws_path_str);
            mcp_ws_router = mcp_ws_router.route_layer(from_fn_with_state(
                (jwks_cache_for_middleware, oauth_config_for_middleware),
                oauth_middleware,
            ));
        } else {
            // Este caso não deveria ser alcançado se initialize_core_services falhar em caso de erro no JWKS
            tracing::error!("OAuth habilitado, mas JwksCache ausente. Autenticação falhará. Isso é um erro de lógica interna.");
        }
    } else {
        tracing::info!("Autenticação OAuth2 desabilitada.");
    }

    base_router.merge(mcp_ws_router.with_state(app_state))
}

/// Inicia o servidor Axum.
async fn run_axum_server(
    router: Router,
    settings: &Arc<Settings>,
    global_shutdown_token: CancellationToken,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    let bind_address_str = settings.server.bind_address.clone();
    let bind_addr: SocketAddr = bind_address_str
        .parse()
        .map_err(|e| format!("Endereço de bind inválido '{bind_address_str}': {e}"))?;

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

        tracing::info!("Servidor MCP (HTTPS/WSS) escutando em {}", bind_addr);
        tracing::info!("Usando certificado: {}", cert_path_str);
        tracing::info!("Usando chave privada: {}", key_path_str);

        let tls_config = RustlsConfig::from_pem_file(cert_path_str, key_path_str)
            .await
            .map_err(|e| format!("Erro ao carregar certificado/chave PEM: {e}"))?;

        let server_handle = AxumServerHandle::new();
        let shutdown_task_handle = server_handle.clone();

        let shutdown_token_for_server = global_shutdown_token.clone();
        tokio::spawn(async move {
            shutdown_token_for_server.cancelled().await;
            shutdown_task_handle.graceful_shutdown(Some(Duration::from_secs(30)));
            tracing::info!("Graceful shutdown do servidor HTTP/TLS solicitado via token.");
        });

        axum_server::bind_rustls(bind_addr, tls_config)
            .handle(server_handle)
            .serve(router.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    } else {
        tracing::info!("Servidor MCP (HTTP/WS) escutando em {}", bind_addr);
        axum_server::bind(bind_addr)
            .serve(router.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    }
    Ok(())
}

/// Executa a limpeza de recursos.
async fn cleanup_resources(
    typedb_driver: Arc<TypeDBDriver>,
    settings: &Arc<Settings>,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    tracing::info!("Graceful shutdown: Iniciando limpeza de recursos...");
    if let Err(e) = typedb_driver.force_close() {
        tracing::error!("Erro ao fechar conexão com TypeDB: {}", e);
    } else {
        tracing::info!("Conexão com TypeDB fechada.");
    }

    if settings.tracing.enabled {
        telemetry::shutdown_tracer_provider();
    }
    tracing::info!("Typedb-MCP-Server desligado graciosamente.");
    Ok(())
}

/// Ponto de entrada principal da aplicação.
fn main() -> Result<(), Box<dyn StdError + Send + Sync>> {
    if dotenvy::dotenv().is_err() {
        println!("[INFO] Arquivo .env não encontrado ou falha ao carregar. Usando variáveis de ambiente do sistema se disponíveis.");
    }

    // Escopo para garantir drop do guard temporário ANTES de qualquer nova inicialização
    {
        let temp_env_filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        let temp_subscriber = fmt::Subscriber::builder()
            .with_env_filter(temp_env_filter)
            .with_writer(std::io::stderr) // Logar para stderr
            .json()
            .finish();
        let _temp_guard = tracing::dispatcher::set_default(&Dispatch::new(temp_subscriber));

        tracing::info!("Iniciando Typedb-MCP-Server versão {}...", env!("CARGO_PKG_VERSION"));
        tracing::info!("Carregando configurações...");

        // Carrega as configurações dentro do escopo temporário
        let settings = match Settings::new() {
            Ok(s) => Arc::new(s),
            Err(config_err) => {
                tracing::error!("Erro fatal ao carregar a configuração: {}", config_err);
                if let Some(source) = config_err.source() {
                    tracing::error!("   Fonte do erro de configuração: {}", source);
                }
                panic!("Falha ao carregar configurações: {}", config_err);
            }
        };

        // O guard é dropado aqui, antes de qualquer nova inicialização

        // Inicializa o sistema de logging/tracing global completo
        if let Err(e) = setup_global_logging_and_tracing(&settings) {
            eprintln!("[AVISO] Falha ao configurar o sistema de logging/tracing global completo: {}. O servidor pode ter observabilidade limitada.", e);
        }

        tracing::info!(
            "Configurações carregadas e sistema de logging/tracing global inicializado."
        );
        tracing::debug!(config = ?settings, "Configurações da aplicação carregadas e prontas para uso.");

        let worker_threads = settings.server.worker_threads.unwrap_or_else(|| {
            let cores = num_cpus::get();
            tracing::info!("server.worker_threads não configurado, usando default: {}", cores);
            cores
        });
        tracing::info!("Usando {} threads de worker para o runtime Tokio.", worker_threads);

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(worker_threads)
            .thread_name("typedb-mcp-worker")
            .build()?;

        return rt.block_on(async_main(settings));
    }
}

/// Função principal assíncrona.
async fn async_main(settings: Arc<Settings>) -> Result<(), Box<dyn StdError + Send + Sync>> {
    let global_shutdown_token = CancellationToken::new();
    setup_signal_handler(global_shutdown_token.clone());

    let metrics_handle_opt = match setup_metrics_server(&settings.server) {
        Ok(handle) => {
            tracing::info!(
                "Servidor de métricas Prometheus iniciado com sucesso em {}.",
                settings.server.metrics_bind_address.as_deref().unwrap_or("0.0.0.0:9090")
            );
            Some(handle)
        }
        Err(e) => {
            tracing::error!("Falha ao iniciar o servidor de métricas Prometheus: {}. Métricas não estarão disponíveis.", e);
            None
        }
    };
    
    tracing::info!("Chamando initialize_core_services...");
    let core_services_result = initialize_core_services(&settings).await;

    let (typedb_driver, jwks_cache) = match core_services_result {
        Ok(services) => {
            tracing::info!("initialize_core_services retornou Ok.");
            services
        }
        Err(e) => {
            tracing::error!("Falha na inicialização dos serviços principais (TypeDB ou JWKS): {}", e);
            return Err(e); 
        }
    };

    let app_state = create_app_state(
        typedb_driver.clone(),
        settings.clone(),
        jwks_cache,
        global_shutdown_token.clone(),
    );

    let router = build_axum_router(app_state, &settings, metrics_handle_opt);

    tracing::info!("Iniciando servidor Axum...");
    if let Err(e) = run_axum_server(router, &settings, global_shutdown_token.clone()).await {
        tracing::error!("Erro fatal ao executar o servidor Axum: {}", e);
        if !global_shutdown_token.is_cancelled() {
            global_shutdown_token.cancel();
        }
        return Err(e);
    }

    global_shutdown_token.cancelled().await;
    tracing::info!("Token de desligamento global recebido após axum_server, iniciando limpeza de recursos...");

    cleanup_resources(typedb_driver, &settings).await?;

    tracing::info!("async_main concluído com sucesso.");
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

    if !app_state.typedb_driver_ref.is_open() {
        tracing::warn!("/readyz: Conexão com TypeDB não está aberta.");
        ready_components.insert("typedb".to_string(), serde_json::json!("DOWN"));
        overall_ready = false;
    } else {
        ready_components.insert("typedb".to_string(), serde_json::json!("UP"));
    }

    if app_state.settings.oauth.enabled {
        if let Some(cache) = &app_state.jwks_cache {
            if !cache.is_cache_ever_populated().await {
                tracing::warn!("/readyz: Cache JWKS ainda não foi populado (OAuth habilitado).");
                ready_components.insert("jwks".to_string(), serde_json::json!("DOWN"));
                overall_ready = false;
            } else {
                ready_components.insert("jwks".to_string(), serde_json::json!("UP"));
            }
        } else {
            // Este caso deveria ser evitado pela falha na inicialização do JWKS.
            tracing::error!(
                "/readyz: OAuth habilitado mas JwksCache ausente. Erro de configuração fatal."
            );
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
        tracing::info!("/readyz: Servidor pronto.");
        StatusCode::OK
    } else {
        tracing::warn!("/readyz: Servidor não está pronto. Detalhes: {}", response_body);
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status_code, axum::Json(response_body)).into_response()
}

/// Handler para o endpoint de métricas (`/metrics`).
async fn metrics_handler(State(prom_handle): State<PrometheusHandle>) -> AxumResponse {
    prom_handle.render().into_response()
}

/// Handler para conexões WebSocket MCP.
async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(app_state): State<AppState>,
    maybe_auth_context: Option<Extension<Arc<ClientAuthContext>>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    let user_id_for_log = maybe_auth_context
        .as_ref()
        .map_or_else(|| "<não_autenticado>".to_string(), |Extension(ctx)| ctx.user_id.clone());

    // Clonar para usar no span, pois o original será movido para a task
    let user_id_for_span = user_id_for_log.clone();
    let addr_for_span = addr; // SocketAddr é Copy

    tracing::Span::current().record("client.user_id", &tracing::field::display(&user_id_for_span));
    tracing::Span::current().record("client.addr", &tracing::field::display(&addr_for_span));
    tracing::info!("Nova tentativa de conexão WebSocket MCP.");

    if app_state.settings.oauth.enabled && maybe_auth_context.is_none() {
        tracing::warn!("OAuth habilitado, mas ClientAuthContext ausente. Rejeitando WebSocket.");
        return (StatusCode::UNAUTHORIZED, "Autenticação OAuth2 falhou ou está ausente.")
            .into_response();
    }

    // Clonar os Arcs e o token que serão movidos para a closure on_upgrade
    let mcp_handler_clone = app_state.mcp_handler.clone();
    let global_shutdown_token_clone = app_state.global_shutdown_token.clone();

    ws.on_upgrade(move |socket| {
        // user_id_for_log (String) é movido para esta closure externa
        // addr (SocketAddr) também é movido
        async move {
            // Criar o child_token AQUI, dentro da closure que vive com a conexão.
            // Ele será dropado (e cancelado) apenas quando esta task 'on_upgrade' terminar.
            let connection_specific_shutdown_token = global_shutdown_token_clone.child_token();
            
            tracing::info!("Conexão WebSocket MCP estabelecida.");
            let adapter = WebSocketTransport::new(socket);
            // user_id_for_log já é uma String possuída aqui.
            // Movê-la diretamente para a task interna.
            let user_id_for_inner_task = user_id_for_log; 

            tokio::spawn(async move {
                // Clone do McpServiceHandler para mover ownership para a task
                let mcp_handler_instance = (*mcp_handler_clone).clone();
                let service_result = mcp_handler_instance.serve_with_ct(adapter, connection_specific_shutdown_token).await;
                if let Err(e) = service_result {
                    let error_string = e.to_string();
                    if error_string.contains("operação cancelada")
                        || error_string.contains("Connection reset by peer")
                        || error_string.contains("Broken pipe")
                        || error_string.to_lowercase().contains("connection closed")
                        || error_string.to_lowercase().contains("channel closed")
                    {
                        tracing::info!(client.user_id = %user_id_for_inner_task, "Serviço MCP para conexão WebSocket encerrado (cancelado ou desconectado): {}", e);
                    } else {
                        tracing::error!(client.user_id = %user_id_for_inner_task, error.message = %e, "Erro no serviço MCP para a conexão WebSocket.");
                    }
                } else {
                     tracing::info!(client.user_id = %user_id_for_inner_task, "Serviço MCP para conexão WebSocket finalizado sem erro explícito do serve_with_ct.");
                }
            }.instrument(tracing::info_span!( // O span é criado aqui, antes da task ser executada
                "mcp_connection_task",
                client.user_id = %user_id_for_span, // Usa o user_id_for_span (clone)
                client.addr = %addr_for_span     // Usa o addr_for_span (clone/copy)
            )));
        }
    })
}

/// Configura os handlers de sinal para o graceful shutdown.
fn setup_signal_handler(token: CancellationToken) {
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigint = match signal(SignalKind::interrupt()) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!(
                        "[ERROR] Falha crítica ao instalar handler SIGINT: {}. Encerrando.",
                        e
                    );
                    std::process::exit(1);
                }
            };
            let mut sigterm = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!(
                        "[ERROR] Falha crítica ao instalar handler SIGTERM: {}. Encerrando.",
                        e
                    );
                    std::process::exit(1);
                }
            };

            tokio::select! {
                biased;
                _ = token.cancelled() => {
                    tracing::debug!("Handler de sinal: Token de cancelamento global já ativo.");
                },
                _ = sigint.recv() => {
                    tracing::info!("Recebido SIGINT (Ctrl+C), iniciando desligamento...");
                    if !token.is_cancelled() { token.cancel(); }
                },
                _ = sigterm.recv() => {
                    tracing::info!("Recebido SIGTERM, iniciando desligamento...");
                    if !token.is_cancelled() { token.cancel(); }
                },
            }
        }
        #[cfg(windows)]
        {
            tokio::select! {
                biased;
                _ = token.cancelled() => {
                    tracing::debug!("Handler de sinal: Token de cancelamento global já ativo.");
                },
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("Recebido Ctrl-C, iniciando desligamento...");
                    if !token.is_cancelled() { token.cancel(); }
                }
            }
        }
        if !token.is_cancelled() {
            tracing::warn!("Handler de sinal terminou sem que o token global fosse cancelado. Cancelando agora.");
            token.cancel();
        }
        tracing::debug!("Handler de sinal encerrado.");
    });
}