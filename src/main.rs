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
    AuthErrorDetail, McpServerError,
};

// Crates de Observabilidade
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use reqwest::Client as ReqwestClient;
// rmcp imports
use rmcp::service::{RoleServer, RunningService, ServerInitializeError, ServiceExt as RmcpServiceExt};
use tracing::{debug, error, info, warn, Instrument, Dispatch};
use tracing_subscriber::{fmt, prelude::*, EnvFilter, Registry};
use typedb_driver::TypeDBDriver;

/// Estrutura para o estado da aplicação compartilhado com os handlers Axum.
#[derive(Clone)]
struct AppState {
    /// Handler principal para o serviço MCP.
    mcp_handler: Arc<McpServiceHandler>,
    /// Configurações da aplicação.
    settings: Arc<Settings>,
    /// Cache para chaves JWKS, se OAuth2 estiver habilitado.
    jwks_cache: Option<Arc<JwksCache>>,
    /// Referência ao driver TypeDB para verificações de saúde.
    typedb_driver_ref: Arc<TypeDBDriver>,
    /// Token global para sinalizar o desligamento gracioso.
    global_shutdown_token: CancellationToken,
}

/// Configura o logging estruturado global (JSON) e o tracing OpenTelemetry.
///
/// O nível de log é controlado pela configuração `logging.rust_log` ou pela
/// variável de ambiente `RUST_LOG`. O tracing OpenTelemetry é habilitado
/// e configurado se `tracing.enabled` for `true`.
fn setup_global_logging_and_tracing(
    settings: &Settings,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(settings.logging.rust_log.clone()));

    let formatting_layer = fmt::layer()
        .json() // Emite logs em formato JSON
        .with_current_span(true) // Inclui o span atual nos logs
        .with_span_list(true) // Inclui a lista de spans pai
        .with_target(true) // Inclui o target (módulo) do log
        .with_file(true) // Inclui o nome do arquivo fonte
        .with_line_number(true); // Inclui o número da linha

    let subscriber_builder = Registry::default().with(env_filter).with(formatting_layer);

    if settings.tracing.enabled {
        match telemetry::init_tracing_pipeline(&settings.tracing) {
            Ok(()) => {
                // Adiciona a camada OpenTelemetry ao subscriber se o pipeline foi inicializado.
                let telemetry_layer = tracing_opentelemetry::layer();
                let subscriber = subscriber_builder.with(telemetry_layer);
                tracing::dispatcher::set_global_default(Dispatch::new(subscriber))?;
                info!(
                    "OpenTelemetry tracing habilitado e configurado para exportar para: {:?}",
                    settings.tracing.exporter_otlp_endpoint
                );
            }
            Err(e) => {
                // Se falhar ao inicializar o pipeline OTLP, continua com logging normal.
                let subscriber = subscriber_builder;
                tracing::dispatcher::set_global_default(Dispatch::new(subscriber))?;
                warn!(
                    "Falha ao inicializar OpenTelemetry pipeline: {}. Tracing distribuído desabilitado.",
                    e
                );
            }
        }
    } else {
        // Se tracing estiver desabilitado, usa apenas as camadas de logging.
        let subscriber = subscriber_builder;
        tracing::dispatcher::set_global_default(Dispatch::new(subscriber))?;
        info!("OpenTelemetry tracing desabilitado.");
    }
    Ok(())
}

/// Configura e inicia o servidor de métricas Prometheus.
///
/// O servidor HTTP para métricas escuta no endereço especificado por
/// `server_settings.metrics_bind_address`.
///
/// # Returns
/// `Ok(PrometheusHandle)` se bem-sucedido, ou um erro se o servidor de métricas
/// não puder ser iniciado.
fn setup_metrics_server(
    server_settings: &AppServerConfig,
) -> Result<PrometheusHandle, Box<dyn StdError + Send + Sync>> {
    metrics::register_metrics_descriptions(); // Descreve as métricas customizadas

    let metrics_bind_addr_str = server_settings
        .metrics_bind_address
        .clone()
        .unwrap_or_else(|| "0.0.0.0:9090".to_string()); // Default se não configurado

    let metrics_socket_addr: SocketAddr = metrics_bind_addr_str.parse().map_err(|e| {
        format!("Endereço de bind inválido para métricas '{metrics_bind_addr_str}': {e}")
    })?;

    PrometheusBuilder::new()
        .with_http_listener(metrics_socket_addr)
        .install_recorder() // Instala o recorder e inicia o listener HTTP
        .map_err(|e| {
            let err_msg = format!(
                "Não foi possível iniciar o servidor de métricas Prometheus em {metrics_socket_addr}: {e}"
            );
            error!("[METRICS_SETUP_ERROR] {}", err_msg); // Usar macro de log
            Box::new(std::io::Error::other(err_msg)) as Box<dyn StdError + Send + Sync>
        })
}

/// Inicializa os serviços principais: conexão com TypeDB e cache JWKS (se OAuth habilitado).
///
/// Esta função é crítica para a inicialização do servidor. Uma falha aqui
/// geralmente impede o servidor de iniciar.
async fn initialize_core_services(
    settings: &Arc<Settings>,
) -> Result<(Arc<TypeDBDriver>, Option<Arc<JwksCache>>), Box<dyn StdError + Send + Sync>> {
    info!(
        "Tentando conectar ao TypeDB. Configurado em: {} (TLS: {})",
        settings.typedb.address, settings.typedb.tls_enabled
    );
    // A senha do TypeDB é obtida exclusivamente de variável de ambiente.
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
            info!("Conexão com TypeDB estabelecida com sucesso.");
            Arc::new(driver)
        }
        Err(e) => {
            // Envolve o erro do driver TypeDB no nosso tipo de erro de aplicação.
            let mcp_error =
                McpServerError::from(typedb_mcp_server_lib::error::TypeDBErrorWrapper::from(e));
            error!("Falha fatal ao conectar com TypeDB: {}", mcp_error);
            return Err(Box::new(mcp_error)); // Retorna erro para impedir inicialização
        }
    };

    let jwks_cache_option = if settings.oauth.enabled {
        let jwks_uri = settings.oauth.jwks_uri.as_ref().ok_or_else(|| {
            let msg = "OAuth2 habilitado, mas oauth.jwks_uri não configurado.";
            error!("{}", msg);
            Box::new(McpServerError::Auth(AuthErrorDetail::InvalidAuthConfig(msg.to_string())))
                as Box<dyn StdError + Send + Sync>
        })?;

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

        let jwks_refresh_interval = settings.oauth.jwks_refresh_interval.unwrap_or_else(|| {
            warn!("oauth.jwks_refresh_interval não pôde ser parseado ou estava ausente, usando default de 1 hora para o cache.");
            Duration::from_secs(3600) // 1 hora
        });

        let cache = Arc::new(JwksCache::new(
            jwks_uri.clone(),
            jwks_refresh_interval,
            http_client,
        ));

        // Tentativa inicial de popular o cache JWKS. Se falhar, é um erro fatal.
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
        None // OAuth desabilitado, sem cache JWKS.
    };

    Ok((typedb_driver_instance, jwks_cache_option))
}

/// Cria o estado da aplicação (`AppState`) que será compartilhado com os handlers Axum.
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

/// Constrói o roteador Axum principal, montando todos os endpoints e middlewares.
fn build_axum_router(
    app_state: AppState,
    settings: &Arc<Settings>,
    metrics_handle_opt: Option<PrometheusHandle>,
) -> Router {
    let mcp_ws_path_str = settings
        .server
        .mcp_websocket_path
        .clone()
        .unwrap_or_else(|| "/mcp/ws".to_string());
    let metrics_path_str =
        settings.server.metrics_path.clone().unwrap_or_else(|| "/metrics".to_string());

    // Endpoints base para health checks
    let mut base_router = Router::new()
        .route("/livez", get(livez_handler))
        .route("/readyz", get(readyz_handler).with_state(app_state.clone()));

    // Adiciona endpoint de métricas se o handle estiver disponível
    if let Some(metrics_h) = metrics_handle_opt {
        base_router =
            base_router.route(&metrics_path_str, get(metrics_handler).with_state(metrics_h));
    }

    // Router para o endpoint WebSocket MCP
    let mut mcp_ws_router = Router::new().route(&mcp_ws_path_str, get(websocket_handler));

    // Aplica middleware OAuth2 se habilitado
    if settings.oauth.enabled {
        if let Some(jwks_cache_for_middleware) = app_state.jwks_cache.clone() {
            let oauth_config_for_middleware = Arc::new(settings.oauth.clone());
            info!("Middleware OAuth2 habilitado para: {}", mcp_ws_path_str);
            mcp_ws_router = mcp_ws_router.route_layer(from_fn_with_state(
                (jwks_cache_for_middleware, oauth_config_for_middleware),
                oauth_middleware,
            ));
        } else {
            // Este estado indica um erro de lógica interna, pois initialize_core_services
            // deveria ter falhado se OAuth estivesse habilitado sem um cache JWKS.
            error!("OAuth habilitado, mas JwksCache ausente no AppState. Autenticação falhará. Erro crítico de configuração interna.");
        }
    } else {
        info!("Autenticação OAuth2 desabilitada.");
    }

    // Merge dos routers, aplicando o AppState ao router MCP
    base_router.merge(mcp_ws_router.with_state(app_state))
}

/// Inicia o servidor Axum, configurando TLS se habilitado.
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
        // Configuração para HTTPS/WSS
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
        info!("Usando certificado: {}", cert_path_str);
        info!("Usando chave privada: {}", key_path_str);

        let tls_config = RustlsConfig::from_pem_file(cert_path_str, key_path_str)
            .await
            .map_err(|e| format!("Erro ao carregar certificado/chave PEM TLS: {e}"))?;

        let server_handle = AxumServerHandle::new(); // Handle para graceful shutdown do servidor HTTP/TLS
        let shutdown_task_handle_clone = server_handle.clone();

        // Task para escutar o token de cancelamento global e iniciar o shutdown do servidor Axum
        let shutdown_token_for_axum_server = global_shutdown_token.clone();
        tokio::spawn(async move {
            shutdown_token_for_axum_server.cancelled().await;
            info!("Sinal de desligamento recebido, iniciando graceful shutdown do servidor Axum/TLS...");
            shutdown_task_handle_clone.graceful_shutdown(Some(Duration::from_secs(30)));
        });

        axum_server::bind_rustls(bind_addr, tls_config)
            .handle(server_handle)
            .serve(router.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    } else {
        // Configuração para HTTP/WS (sem TLS)
        info!("Servidor MCP (HTTP/WS) escutando em {}", bind_addr);
        let server_handle = AxumServerHandle::new(); // Handle para graceful shutdown
        let shutdown_task_handle_clone = server_handle.clone();

        let shutdown_token_for_axum_server = global_shutdown_token.clone();
        tokio::spawn(async move {
            shutdown_token_for_axum_server.cancelled().await;
            info!("Sinal de desligamento recebido, iniciando graceful shutdown do servidor Axum/HTTP...");
            shutdown_task_handle_clone.graceful_shutdown(Some(Duration::from_secs(30)));
        });
        
        axum_server::bind(bind_addr)
            .handle(server_handle)
            .serve(router.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    }
    Ok(())
}

/// Executa a limpeza de recursos durante o graceful shutdown.
async fn cleanup_resources(
    typedb_driver: Arc<TypeDBDriver>,
    settings: &Arc<Settings>,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    info!("Graceful shutdown: Iniciando limpeza de recursos...");

    // Fecha a conexão com o TypeDB.
    if let Err(e) = typedb_driver.force_close() {
        error!("Erro ao fechar conexão com TypeDB: {}", e);
    } else {
        info!("Conexão com TypeDB fechada.");
    }

    // Desliga o provider de tracing OpenTelemetry, se habilitado.
    if settings.tracing.enabled {
        telemetry::shutdown_tracer_provider();
        // Mensagem de log já está em shutdown_tracer_provider.
    }
    info!("Typedb-MCP-Server desligado graciosamente.");
    Ok(())
}

/// Ponto de entrada principal da aplicação.
///
/// Carrega `.env` (se existir), configura logging/tracing inicial, carrega as
/// configurações principais, e então inicia o runtime Tokio para executar `async_main`.
fn main() -> Result<(), Box<dyn StdError + Send + Sync>> {
    // Tenta carregar variáveis de ambiente de um arquivo .env. Falha silenciosamente se não encontrar.
    if dotenvy::dotenv().is_err() {
        // Usar println! aqui, pois o logger ainda não foi totalmente configurado
        // com os níveis finais baseados na configuração da aplicação.
        println!("[SETUP_INFO] Arquivo .env não encontrado ou falha ao carregar. Usando variáveis de ambiente do sistema se disponíveis.");
    }

    // Escopo para logging temporário inicial antes da configuração completa.
    // Isso garante que qualquer erro durante o carregamento de Settings seja logado.
    {
        // Filtro de log inicial, pode ser sobrescrito após carregar Settings.
        let temp_env_filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        let temp_subscriber = fmt::Subscriber::builder()
            .with_env_filter(temp_env_filter)
            .with_writer(std::io::stderr) // Logar para stderr
            .json() // Logs iniciais também em JSON
            .finish();
        // Guard para o dispatcher temporário. Será substituído após carregar as configs.
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
                // Pânico aqui é apropriado, pois o servidor não pode operar sem config.
                panic!("Falha ao carregar configurações: {}", config_err);
            }
        };

        // O dispatcher temporário (_temp_guard) sai de escopo aqui.
        // O `setup_global_logging_and_tracing` abaixo irá instalar o dispatcher definitivo.

        if let Err(e) = setup_global_logging_and_tracing(&settings) {
            // Usar eprintln! pois o logger pode não estar totalmente funcional.
            eprintln!(
                "[SETUP_WARN] Falha ao configurar o sistema de logging/tracing global completo: {}. Observabilidade pode ser limitada.",
                e
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

        // Constrói o runtime Tokio.
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all() // Habilita todos os drivers do Tokio (I/O, time, etc.)
            .worker_threads(worker_threads)
            .thread_name("typedb-mcp-worker")
            .build()?;

        // Executa a lógica principal assíncrona no runtime Tokio.
        return rt.block_on(async_main(settings));
    }
}

/// Lógica principal assíncrona da aplicação.
///
/// Configura e inicia todos os componentes do servidor e aguarda o sinal de desligamento.
async fn async_main(settings: Arc<Settings>) -> Result<(), Box<dyn StdError + Send + Sync>> {
    let global_shutdown_token = CancellationToken::new();
    setup_signal_handler(global_shutdown_token.clone()); // Configura handlers para SIGINT/SIGTERM

    // Inicia o servidor de métricas
    let metrics_handle_opt = match setup_metrics_server(&settings.server) {
        Ok(handle) => {
            info!(
                "Servidor de métricas Prometheus iniciado com sucesso em {}.",
                settings.server.metrics_bind_address.as_deref().unwrap_or("0.0.0.0:9090")
            );
            Some(handle)
        }
        Err(e) => {
            error!(
                "Falha ao iniciar o servidor de métricas Prometheus: {}. Métricas não estarão disponíveis.",
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
            // Não precisa cancelar o token global aqui, pois o retorno de Err fará async_main terminar.
            return Err(e);
        }
    };

    let app_state = create_app_state(
        typedb_driver.clone(), // Clonar Arc para AppState
        settings.clone(),      // Clonar Arc para AppState
        jwks_cache,            // Mover Option<Arc<JwksCache>>
        global_shutdown_token.clone(),
    );

    let router = build_axum_router(app_state, &settings, metrics_handle_opt);

    info!("Iniciando servidor Axum (MCP)...");
    if let Err(e) = run_axum_server(router, &settings, global_shutdown_token.clone()).await {
        error!("Erro fatal ao executar o servidor Axum: {}", e);
        // Se o servidor Axum falhar, cancela o token global para garantir que outras partes desliguem.
        if !global_shutdown_token.is_cancelled() {
            global_shutdown_token.cancel();
        }
        return Err(e);
    }

    // Aguarda o token de desligamento global ser cancelado (ex: por sinal do SO).
    info!("Servidor Axum (MCP) encerrou. Aguardando sinal de desligamento global para limpeza final...");
    global_shutdown_token.cancelled().await;
    info!("Sinal de desligamento global recebido, procedendo com a limpeza de recursos...");

    cleanup_resources(typedb_driver, &settings).await?; // Passar o Arc original do driver

    info!("async_main concluído com sucesso.");
    Ok(())
}

/// Handler para o endpoint de liveness (`/livez`). Simplesmente retorna `200 OK`.
async fn livez_handler() -> StatusCode {
    tracing::trace!("Recebida requisição /livez");
    StatusCode::OK
}

/// Handler para o endpoint de readiness (`/readyz`).
///
/// Verifica o estado da conexão com TypeDB e, se OAuth2 estiver habilitado,
/// o estado do cache JWKS. Retorna `200 OK` se tudo estiver pronto,
/// ou `503 Service Unavailable` caso contrário, com um corpo JSON detalhando o status.
async fn readyz_handler(State(app_state): State<AppState>) -> impl IntoResponse {
    tracing::debug!("Verificando prontidão do servidor para /readyz...");
    let mut ready_components = serde_json::Map::new();
    let mut overall_ready = true;

    // Verifica conexão com TypeDB
    // Tenta uma operação leve para verificar a saúde real da conexão.
    // `databases().all()` é uma boa candidata, pois não modifica dados e é simples.
    match app_state.typedb_driver_ref.databases().all().await {
        Ok(_) => {
            // A query foi bem-sucedida, então o TypeDB está acessível.
            // Podemos também verificar o `is_open()` do driver como uma checagem secundária,
            // embora a query bem-sucedida seja um indicador mais forte.
            if app_state.typedb_driver_ref.is_open() {
                ready_components.insert("typedb".to_string(), serde_json::json!("UP"));
            } else {
                // Caso incomum: query bem-sucedida, mas o driver se reporta como não aberto.
                warn!("/readyz: TypeDB respondeu à consulta 'all databases', mas o driver reporta-se como fechado.");
                ready_components.insert("typedb".to_string(), serde_json::json!("DEGRADED"));
                overall_ready = false;
            }
        }
        Err(e) => {
            warn!("/readyz: Falha ao verificar a saúde do TypeDB (ex: listando bancos): {}", e);
            ready_components.insert("typedb".to_string(), serde_json::json!("DOWN"));
            overall_ready = false;
        }
    }


    // Verifica cache JWKS se OAuth2 estiver habilitado
    if app_state.settings.oauth.enabled {
        if let Some(cache) = &app_state.jwks_cache {
            if !cache.is_cache_ever_populated().await {
                warn!("/readyz: Cache JWKS ainda não foi populado (OAuth habilitado).");
                ready_components.insert("jwks".to_string(), serde_json::json!("DOWN"));
                overall_ready = false;
            } else {
                ready_components.insert("jwks".to_string(), serde_json::json!("UP"));
            }
        } else {
            // Este estado indica um erro de lógica na inicialização.
            error!("/readyz: OAuth habilitado mas JwksCache ausente no AppState. Erro crítico de configuração interna.");
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

/// Handler para o endpoint de métricas (`/metrics`), servindo dados do `PrometheusHandle`.
async fn metrics_handler(State(prom_handle): State<PrometheusHandle>) -> AxumResponse {
    prom_handle.render().into_response()
}

/// Handler para conexões WebSocket MCP.
///
/// Realiza o upgrade da conexão HTTP para WebSocket e, em seguida, inicia uma nova task
/// para servir as requisições MCP sobre esta conexão usando `McpServiceHandler`.
/// A task da conexão é gerenciada com um `ChildToken` para permitir o cancelamento
/// individual da conexão ou o cancelamento global via `global_shutdown_token`.
#[tracing::instrument(
    name = "websocket_connection_upgrade",
    skip_all, 
    fields(
        client.addr = %addr,
        // client.user_id será adicionado abaixo se autenticado
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

    tracing::Span::current().record("client.user_id", &tracing::field::display(&user_id_for_log));
    info!("Nova tentativa de conexão WebSocket MCP."); 

    if app_state.settings.oauth.enabled && maybe_auth_context.is_none() {
        warn!("OAuth habilitado, mas ClientAuthContext ausente (autenticação falhou ou token não fornecido). Rejeitando upgrade WebSocket.");
        return (StatusCode::UNAUTHORIZED, "Autenticação OAuth2 falhou ou está ausente.")
            .into_response();
    }

    let mcp_handler_clone = app_state.mcp_handler.clone();
    let global_shutdown_token_clone = app_state.global_shutdown_token.clone();

    ws.on_upgrade(move |socket| {
        async move {
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
                    let mcp_handler_instance = (*mcp_handler_clone).clone();
                    let token_for_serve = connection_specific_shutdown_token.clone();

                    info!(
                        "Iniciando handshake e serviço MCP (serve_with_ct). Token is_cancelled: {}",
                        token_for_serve.is_cancelled()
                    );
                    
                    let running_service_result: Result<
                        RunningService<RoleServer, McpServiceHandler>,
                        ServerInitializeError<std::io::Error> 
                    > = mcp_handler_instance
                        .serve_with_ct(adapter, token_for_serve)
                        .await;

                    match running_service_result {
                        Ok(running_service) => {
                            info!(
                                client.user_id = %user_id_for_inner_task_log,
                                "Handshake MCP bem-sucedido. Aguardando conclusão do serviço MCP (running_service.waiting())."
                            );
                            match running_service.waiting().await {
                                Ok(quit_reason) => {
                                    info!(
                                        client.user_id = %user_id_for_inner_task_log,
                                        "Serviço MCP para conexão WebSocket encerrado: {:?}",
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
                        "Task de conexão MCP para user '{}' finalizada. Token de cancelamento da conexão is_cancelled: {}",
                        user_id_for_inner_task_log,
                        connection_specific_shutdown_token.is_cancelled()
                    );
                }
                .instrument(connection_span),
            );
        }
    })
}

/// Configura os handlers de sinal do sistema operacional (SIGINT, SIGTERM no Unix; Ctrl-C no Windows)
/// para acionar o `global_shutdown_token`, iniciando o processo de graceful shutdown.
fn setup_signal_handler(token: CancellationToken) {
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigint = match signal(SignalKind::interrupt()) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[FATAL_ERROR] Falha crítica ao instalar handler SIGINT: {}. Encerrando.", e);
                    std::process::exit(1);
                }
            };
            let mut sigterm = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[FATAL_ERROR] Falha crítica ao instalar handler SIGTERM: {}. Encerrando.", e);
                    std::process::exit(1);
                }
            };

            tokio::select! {
                biased;
                _ = token.cancelled() => {
                    debug!("Handler de sinal: Token de cancelamento global já ativo. Nenhuma ação de sinal necessária.");
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
                    debug!("Handler de sinal: Token de cancelamento global já ativo.");
                },
                _ = tokio::signal::ctrl_c() => {
                    info!("Recebido Ctrl-C (Windows), iniciando desligamento...");
                    if !token.is_cancelled() { token.cancel(); }
                }
            }
        }

        if !token.is_cancelled() {
            warn!("Handler de sinal terminou sem que o token global fosse cancelado por um sinal. Cancelando agora para garantir o shutdown.");
            token.cancel();
        }
        debug!("Handler de sinal encerrado.");
    });
}