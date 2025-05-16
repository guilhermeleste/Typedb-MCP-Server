// src/main.rs

// Licença Apache 2.0
// Copyright [ANO_ATUAL] [SEU_NOME_OU_ORGANIZACAO]
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
//! lida com autenticação OAuth2, e despacha requisições de ferramentas
//! para o `McpServiceHandler`. Também configura logging, métricas e tracing.

// std imports
use std::{
    fs::File as StdFile,
    io::BufReader,
    net::SocketAddr,
    path::Path,
    sync::Arc,
    time::Duration,
};

// axum imports
use axum::{
    body::Body as AxumBody, // Usado como tipo genérico B em Request<B>
    extract::{
        ws::{WebSocket, WebSocketUpgrade},
        Extension, State,
    },
    http::StatusCode,
    middleware,
    response::{IntoResponse, Response as AxumResponse},
    routing::get,
    BoxError, Router,
};
// axum-extra imports
use axum_extra::{
    extract::TypedHeader, // Corrigido
    headers::{authorization::Bearer, Authorization},
    typed_header::TypedHeaderRejection, // Import direto
};

// tokio imports
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

// TLS imports
use rustls_pemfile::{certs, private_key};
use tokio_rustls::{
    rustls::{pki_types::{CertificateDer, PrivateKeyDer}, ServerConfig as RustlsServerConfig},
    TlsAcceptor,
};

// Crates do projeto
use typedb_mcp_server_lib::{
    auth::{self, ClientAuthContext, JwksCache},
    config::{self, Settings},
    db,
    error::McpServerError,
    mcp_service_handler::McpServiceHandler,
    metrics, telemetry,
    transport::WebSocketTransport,
};

// Crates de Observabilidade
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use reqwest::Client as ReqwestClient;
use rmcp::service::ServiceExt;
use tower::Service as TowerService; // Importar Service para router.call()
use tracing_subscriber::{
    fmt as tracing_fmt, EnvFilter, Layer, // Adicionado Layer
    prelude::*, // Necessário para .with() e .init()
    util::SubscriberInitExt,
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
        // Não é fatal se .env não existir.
        println!("Arquivo .env não encontrado ou falha ao carregar. Usando variáveis de ambiente do sistema se disponíveis.");
    }

    let settings = match Settings::new() {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("Erro fatal ao carregar a configuração: {}. Encerrando.", e);
            // Converter config::ConfigError para um erro que main pode retornar.
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())));
        }
    };

    setup_logging_and_tracing(&settings);

    tracing::info!("Iniciando Typedb-MCP-Server versão {}", env!("CARGO_PKG_VERSION"));
    tracing::debug!(config = ?settings, "Configurações carregadas.");

    let worker_threads = settings.server.worker_threads.unwrap_or_else(|| {
        let cores = num_cpus::get(); // num_cpus crate
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
            McpServerError::Internal(msg.to_string()) // Usar nosso tipo de erro
        })?;
        let client = ReqwestClient::builder()
            .timeout(settings.oauth.jwks_request_timeout_seconds.map_or(Duration::from_secs(10), Duration::from_secs))
            .build()?;
        let cache = Arc::new(JwksCache::new(
            jwks_uri.clone(),
            settings.oauth.jwks_refresh_interval.unwrap_or(Duration::from_secs(3600)),
            client,
        ));
        if let Err(e) = cache.refresh_keys().await { // Assumindo que refresh_keys é pub
            tracing::warn!("Falha no refresh inicial do JWKS (servidor continuará tentando em background): {}", e);
        } else {
            tracing::info!("JWKS cache inicializado e chaves buscadas (ou tentativa).");
        }
        Some(cache)
    } else {
        None
    };

    // McpServiceHandler::new agora espera (Arc<TypeDBDriver>, Arc<Settings>)
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
        .route("/readyz", get(readyz_handler)); // State será adicionado depois

    if let Some(metrics_h) = metrics_handle_opt { // Renomeado para evitar shadowing
        base_router = base_router.route(&metrics_path_str, get(metrics_handler).with_state(metrics_h));
    }
    
    let mcp_ws_router = Router::new().route(&mcp_ws_path_str, get(websocket_handler));

    let router_with_mcp_state = if settings.oauth.enabled {
        if let Some(jwks_c) = app_state.jwks_cache.clone() { // Renomeado
            tracing::info!("Middleware OAuth2 habilitado para o endpoint MCP WebSocket: {}", mcp_ws_path_str);
            mcp_ws_router.layer(middleware::from_fn_with_state(
                (jwks_c, settings.oauth.clone()),
                auth::oauth_middleware,
            )).with_state(app_state.clone()) // Adiciona AppState ao router *depois* do layer
        } else {
            tracing::error!("OAuth está habilitado, mas JwksCache não inicializado. Auth falhará.");
            mcp_ws_router.with_state(app_state.clone())
        }
    } else {
        tracing::info!("Autenticação OAuth2 desabilitada.");
        mcp_ws_router.with_state(app_state.clone())
    };
    
    let final_router = base_router.merge(router_with_mcp_state);

    let bind_address_str = settings.server.bind_address.clone();
    let bind_addr: SocketAddr = bind_address_str.parse().map_err(|e| {
        format!("Endereço de bind inválido '{}': {}", bind_address_str, e)
    })?;

    if settings.server.tls_enabled {
        let cert_path_str = settings.server.tls_cert_path.as_ref().ok_or_else(|| {
            McpServerError::Internal("server.tls_cert_path não configurado com TLS habilitado".to_string())
        })?;
        let key_path_str = settings.server.tls_key_path.as_ref().ok_or_else(|| {
             McpServerError::Internal("server.tls_key_path não configurado com TLS habilitado".to_string())
        })?;

        tracing::info!("Servidor MCP (HTTPS/WSS) escutando em {}", bind_addr);
        tracing::info!("Usando certificado: {}", cert_path_str);
        tracing::info!("Usando chave privada: {}", key_path_str);

        let cert_file = StdFile::open(Path::new(cert_path_str)).map_err(|e| format!("Falha ao abrir arquivo de certificado '{}': {}", cert_path_str, e))?;
        let mut cert_reader = BufReader::new(cert_file);
        let cert_chain_ders: Vec<CertificateDer<'static>> = certs(&mut cert_reader)
            .collect::<Result<_, _>>()
            .map_err(|e| format!("Erro ao ler ou parsear certificados PEM: {}", e))?;
        
        if cert_chain_ders.is_empty() {
            return Err("Nenhum certificado PEM encontrado no arquivo de certificado".into());
        }

        let key_file = StdFile::open(Path::new(key_path_str)).map_err(|e| format!("Falha ao abrir arquivo de chave privada '{}': {}", key_path_str, e))?;
        let mut key_reader = BufReader::new(key_file);
        
        let key_der: PrivateKeyDer<'static> = private_key(&mut key_reader)?
            .ok_or_else(|| "Nenhuma chave privada PEM encontrada no arquivo de chave".to_string())?;
        
        let tls_config = RustlsServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain_ders, key_der)
            .map_err(|e| format!("Erro ao criar configuração TLS do servidor: {}", e))?;
        
        let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
        let listener = TcpListener::bind(bind_addr).await?;

        loop {
            tokio::select! {
                biased; 
                _ = global_shutdown_token.cancelled() => {
                    tracing::info!("Servidor HTTPS parando de aceitar novas conexões devido ao sinal de shutdown.");
                    break;
                }
                conn_result = listener.accept() => {
                    match conn_result {
                        Ok((socket, remote_addr)) => {
                            tracing::debug!("Nova conexão TCP (potencialmente TLS) de: {}", remote_addr);
                            let mut router_for_conn = final_router.clone(); // Clonar para cada task
                            let acceptor_for_conn = tls_acceptor.clone();
                            let conn_shutdown_token_for_hyper = global_shutdown_token.child_token(); 

                            tokio::spawn(async move {
                                let graceful = hyper_util::server::graceful::GracefulShutdown::new();
                                // O watcher é obtido chamando watch() no token de cancelamento que o GracefulShutdown usará.
                                // No entanto, GracefulShutdown::watch() não existe mais ou mudou.
                                // A forma correta de usar GracefulShutdown é passar o token de cancelamento para ele
                                // e depois usar o próprio GracefulShutdown no método `.graceful()` do servidor.

                                // Vamos simplificar e usar o token de shutdown global diretamente com o servidor.
                                // A lógica de graceful shutdown por conexão individual pode ser complexa de implementar
                                // corretamente com a versão atual de hyper-util e axum.
                                // A abordagem mais comum é um shutdown graceful global.

                                // Se precisarmos de controle fino por conexão, teríamos que investigar mais a fundo
                                // a API de hyper_util::server::graceful ou usar um token por conexão.

                                // Por agora, vamos focar no shutdown global que já está parcialmente implementado.
                                // A chamada original `graceful.watch()` não é mais necessária aqui se simplificarmos.

                                tokio::select! {
                                    biased;
                                     _ = conn_shutdown_token_for_hyper.cancelled() => {
                                        tracing::debug!("Conexão com {} cancelada (shutdown do servidor).", remote_addr);
                                        // Não precisamos chamar graceful.shutdown() explicitamente aqui se o servidor
                                        // estiver usando o token de cancelamento corretamente.
                                    }
                                    tls_res = acceptor_for_conn.accept(socket) => {
                                        match tls_res {
                                            Ok(tls_stream) => {
                                                tracing::debug!("Handshake TLS bem-sucedido com: {}", remote_addr);
                                                let io = hyper_util::rt::TokioIo::new(tls_stream);
                                                
                                                // Criar um clone do router para este service_fn
                                                let router_clone_for_service = router_for_conn.clone();
                                                let service = tower::service_fn(move |req: axum::extract::Request<AxumBody>| {
                                                    // Precisamos que router_clone_for_service seja `Service`
                                                    let mut router_service = router_clone_for_service.clone();
                                                    async move {
                                                        router_service.call(req).await
                                                    }
                                                });

                                                // O token de shutdown para a conexão individual.
                                                let connection_shutdown_token = conn_shutdown_token_for_hyper.clone();

                                                if let Err(err) = hyper_util::server::conn::auto::Builder::new(
                                                        hyper_util::rt::tokio::TokioExecutor::new()
                                                    )
                                                    .serve_connection_with_upgrades(io, service) // Usar _with_upgrades para WebSockets
                                                    .graceful(async { // O graceful agora espera um Future
                                                        connection_shutdown_token.cancelled().await;
                                                        tracing::debug!("Graceful shutdown para conexão com {} ativado.", remote_addr);
                                                    })
                                                    .await
                                                {
                                                    if !is_hyper_shutdown_error(&err) {
                                                        tracing::error!("Erro ao servir conexão HTTPS de {}: {}", remote_addr, err);
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                tracing::error!("Erro no handshake TLS de {}: {}", remote_addr, e);
                                            }
                                        }
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            if global_shutdown_token.is_cancelled() { break; }
                            tracing::error!("Erro ao aceitar conexão TCP: {}", e);
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
            }
        }

    } else {
        tracing::info!("Servidor MCP (HTTP/WS) escutando em {}", bind_addr);
        let listener = TcpListener::bind(bind_addr).await?;
        axum::serve(listener, final_router.into_make_service())
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
async fn livez_handler() -> StatusCode {
    StatusCode::OK
}

/// Handler para o endpoint de readiness (`/readyz`).
async fn readyz_handler(State(app_state): State<AppState>) -> Result<StatusCode, StatusCode> {
    if !app_state.typedb_driver_ref.is_open() {
        tracing::warn!("/readyz: Conexão com TypeDB não está aberta.");
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }

    if app_state.settings.oauth.enabled {
        if let Some(cache) = &app_state.jwks_cache {
            if !cache.is_cache_ever_populated().await { // Método adicionado a JwksCache
                 tracing::warn!("/readyz: Cache JWKS ainda não foi populado ou falhou no refresh inicial.");
                 return Err(StatusCode::SERVICE_UNAVAILABLE);
            }
        } else {
            // Se OAuth está habilitado, o cache DEVE estar presente.
            tracing::error!("/readyz: OAuth habilitado mas JwksCache não está presente no estado da aplicação. Isto é um erro de configuração interna.");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }
    Ok(StatusCode::OK)
}

/// Handler para o endpoint de métricas (`/metrics`).
async fn metrics_handler(State(prom_handle): State<PrometheusHandle>) -> AxumResponse {
    prom_handle.render().into_response()
}


/// Handler para conexões WebSocket MCP.
#[tracing::instrument(skip_all, name = "mcp_websocket_handler", fields(client.user_id))]
async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(app_state): State<AppState>,
    maybe_auth_context: Option<Extension<Arc<ClientAuthContext>>>,
) -> impl IntoResponse {
    let user_id_for_log = maybe_auth_context
        .as_ref()
        .map(|Extension(ctx)| ctx.user_id.clone())
        .unwrap_or_else(|| "não_autenticado".to_string());
    
    tracing::Span::current().record("client.user_id", &tracing::field::display(&user_id_for_log));
    tracing::info!("Nova tentativa de conexão WebSocket MCP.");

    if app_state.settings.oauth.enabled && maybe_auth_context.is_none() {
        tracing::error!("OAuth habilitado, mas ClientAuthContext ausente. Rejeitando WebSocket.");
        return (StatusCode::UNAUTHORIZED, "Autenticação OAuth2 falhou ou está ausente.").into_response();
    }
    
    // Token de cancelamento específico para esta conexão WebSocket
    let conn_cancellation_token = app_state.global_shutdown_token.child_token();
    let service_shutdown_token = conn_cancellation_token.clone(); // Para o serviço rmcp
    let adapter_shutdown_token = conn_cancellation_token.clone(); // Para o adaptador WS

    ws.on_upgrade(move |socket| async move {
        tracing::info!("Conexão WebSocket MCP estabelecida.");
        
        // McpServiceHandler DEVE implementar Clone
        let mcp_handler_instance = (*app_state.mcp_handler).clone(); 
        // WebSocketTransport não precisa mais do token, pois o serve_with_ct o recebe.
        let adapter = WebSocketTransport::new(socket);

        tokio::spawn(async move {
            // rmcp::ServiceExt::serve_with_ct
            if let Err(e) = mcp_handler_instance.serve_with_ct(adapter, service_shutdown_token).await {
                let error_string = e.to_string();
                // Filtra erros que são esperados durante o shutdown normal de uma conexão
                if !(error_string.contains("operação cancelada") || 
                     error_string.contains("Connection reset by peer") ||
                     error_string.contains("Broken pipe") ||
                     error_string.to_lowercase().contains("connection closed") ||
                     error_string.to_lowercase().contains("channel closed") ||
                     // Adicionar erro específico de Axum WebSocket quando o cliente desconecta
                     error_string.contains("IO error: Connection reset by peer") ||
                     error_string.contains("IO error: Broken pipe") 
                    ) {
                    tracing::error!(client.user_id = %user_id_for_log, error.message = %e, "Erro no serviço MCP para a conexão WebSocket.");
                } else {
                    tracing::info!(client.user_id = %user_id_for_log, "Serviço MCP para conexão WebSocket encerrado (cancelado ou desconectado): {}", e);
                }
            }
            tracing::info!(client.user_id = %user_id_for_log, "Serviço MCP para conexão WebSocket finalizado.");
            // Sinaliza que esta task de conexão específica terminou, o que pode ser usado pelo graceful shutdown do hyper se necessário.
            // No entanto, o CancellationToken já deve ter sido cancelado pelo shutdown global ou pelo fim do stream.
            // conn_cancellation_token.cancel(); // Redundante se service_shutdown_token for o mesmo.
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

    let subscriber_builder = tracing_subscriber::registry().with(env_filter);

    if settings.tracing.enabled {
        match telemetry::init_tracing_pipeline(&settings.tracing) {
            Ok(_) => {
                let telemetry_layer = tracing_opentelemetry::layer();
                // Corrigido: aplicar a formatting_layer após a telemetry_layer
                subscriber_builder.with(telemetry_layer).with(formatting_layer).init();
                tracing::info!(
                    "OpenTelemetry tracing habilitado e configurado para exportar para: {:?}",
                    settings.tracing.exporter_otlp_endpoint
                );
            }
            Err(e) => {
                subscriber_builder.with(formatting_layer).init();
                tracing::warn!(
                    "Falha ao inicializar OpenTelemetry tracer: {}. Tracing distribuído estará desabilitado.",
                    e
                );
            }
        }
    } else {
        subscriber_builder.with(formatting_layer).init();
        tracing::info!("OpenTelemetry tracing desabilitado.");
    }
}

/// Configura e inicia o servidor de métricas Prometheus.
fn setup_metrics(metrics_bind_address_str: &str) -> Result<PrometheusHandle, Box<dyn std::error::Error + Send + Sync>> {
    metrics::register_metrics_descriptions();

    let metrics_socket_addr: SocketAddr = metrics_bind_address_str.parse().map_err(|e| {
        format!("Endereço de bind inválido para métricas '{}': {}", metrics_bind_address_str, e)
    })?;

    match PrometheusBuilder::new().with_http_listener(metrics_socket_addr).install() {
        Ok(handle) => {
            tracing::info!("Servidor de métricas Prometheus escutando em {}", metrics_socket_addr);
            Ok(handle)
        }
        Err(e) => {
            let err_msg = format!("Não foi possível iniciar o servidor de métricas Prometheus em {}: {}. As métricas não estarão disponíveis.", metrics_socket_addr, e);
            tracing::error!("{}", err_msg);
            Err(err_msg.into()) // Converte String para Box<dyn Error...>
        }
    }
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
                _ = token.cancelled() => {},
                _ = sigint.recv() => tracing::info!("Recebido SIGINT, iniciando desligamento..."),
                _ = sigterm.recv() => tracing::info!("Recebido SIGTERM, iniciando desligamento..."),
            }
        }
        #[cfg(windows)]
        {
            tokio::select! {
                biased;
                _ = token.cancelled() => {},
                _ = tokio::signal::ctrl_c() => { // Retorna Result<(), Error>
                    tracing::info!("Recebido Ctrl-C, iniciando desligamento...");
                }
            }
        }
        if !token.is_cancelled() {
            token.cancel();
        }
    });
}

/// Verifica se um erro hyper é um erro de "shutdown" ou "cancelamento" que pode ser ignorado em logs.
fn is_hyper_shutdown_error(err: &BoxError) -> bool {
    // Tenta fazer downcast para erros específicos de hyper ou IO que indicam um shutdown normal.
    if err.is::<hyper::Error>() {
        let hyper_err = err.downcast_ref::<hyper::Error>().unwrap(); // Seguro pois acabamos de verificar
        if hyper_err.is_canceled() || hyper_err.is_closed() || hyper_err.is_incomplete_message() {
            return true;
        }
        // Verificar causas internas do hyper::Error se possível
        if let Some(cause) = std::error::Error::source(hyper_err) {
            if let Some(io_err) = cause.downcast_ref::<std::io::Error>() {
                match io_err.kind() {
                    std::io::ErrorKind::BrokenPipe 
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::ConnectionReset => return true,
                    _ => {}
                }
            }
        }
    } else if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
        match io_err.kind() {
            std::io::ErrorKind::BrokenPipe 
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset => return true,
            _ => {}
        }
    }
    
    // Verificações baseadas em string como fallback
    let err_string = err.to_string().to_lowercase();
    err_string.contains("unexpected eof") ||
    err_string.contains("connection closed normally") ||
    err_string.contains("protocol error") || // Erros de protocolo TLS durante shutdown
    err_string.contains("application data after close notify") || // TLS close_notify
    err_string.contains("connection reset by peer") || // Comum
    err_string.contains("broken pipe") // Comum
}