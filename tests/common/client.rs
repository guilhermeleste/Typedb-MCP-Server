// tests/common/client.rs

//! Define um cliente MCP de teste (`TestMcpClient`) para interagir com o
//! `Typedb-MCP-Server` durante os testes de integração.
//! Este cliente lida com a conexão WebSocket, o handshake de inicialização MCP,
//! o envio de requisições de ferramentas e o recebimento de respostas.

use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use http::{header::AUTHORIZATION, Request as HttpRequest, StatusCode as HttpStatus};
use rmcp::model::{
    CallToolRequestMethod, CallToolRequestParam, CallToolResult, CancelledNotificationMethod,
    CancelledNotificationParam, ClientJsonRpcMessage, ClientNotification, ClientRequest,
    Extensions, InitializeRequestParam, InitializeResult, InitializeResultMethod,
    InitializedNotificationMethod, JsonRpcError, JsonRpcNotification, JsonRpcRequest,
    JsonRpcResponse, JsonRpcVersion2_0, ListResourceTemplatesRequestMethod,
    ListResourceTemplatesResult, ListResourcesRequestMethod, ListResourcesResult,
    ListToolsRequestMethod, ListToolsResult, NotificationNoParam, PaginatedRequestParam,
    ReadResourceRequestMethod, ReadResourceRequestParam, ReadResourceResult, RequestId, ServerInfo,
    ServerJsonRpcMessage, ServerResult,
};
use serde::de::DeserializeOwned;
use serde_json::Value as JsonValue;
use std::fmt::Debug;
use std::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::{
    connect_async, tungstenite::protocol::Message as TungsteniteWsMessage,
    tungstenite::Error as WsError, MaybeTlsStream, WebSocketStream,
};
use tracing::{debug, error, info, trace, warn};
use url::Url;

// JwtAuthAlgorithm não é usado diretamente aqui, mas em auth_helpers.
// Se for necessário para construir tokens *dentro* deste arquivo, deveria ser importado.

/// Próximo ID para requisições JSON-RPC.
static NEXT_JSON_RPC_ID: AtomicU32 = AtomicU32::new(1);

/// Gera um novo ID de requisição JSON-RPC numérico.
fn new_req_id() -> RequestId {
    RequestId::Number(NEXT_JSON_RPC_ID.fetch_add(1, AtomicOrdering::SeqCst))
}

/// Erros que podem ocorrer ao usar o `TestMcpClient`.
#[derive(Debug, thiserror::Error)]
pub enum McpClientError {
    /// Erro originado na camada WebSocket (ex: falha de conexão, I/O).
    #[error("Erro WebSocket: {0}")]
    WebSocket(#[from] WsError),

    /// Erro durante a serialização ou desserialização JSON.
    #[error("Erro JSON: {0}")]
    Json(#[from] serde_json::Error),

    /// Erro ao parsear uma URL, geralmente a URL do servidor MCP.
    #[error("Erro ao parsear URL: {0}")]
    UrlParse(#[from] url::ParseError),

    /// Erro na construção ou envio da requisição HTTP durante o handshake WebSocket.
    #[error("Erro na requisição HTTP (handshake): {0}")]
    HttpRequest(#[from] http::Error),

    /// Falha no handshake WebSocket, indicado por um status HTTP não-101.
    /// Contém o status HTTP e, opcionalmente, o corpo da resposta.
    #[error("Falha no handshake WebSocket: Status {0}, Body: {1:?}")]
    HandshakeFailed(HttpStatus, Option<String>),

    /// Erro retornado pelo servidor MCP em uma resposta JSON-RPC.
    #[error("Erro MCP do Servidor: code={code:?}, message='{message}', data={data:?}")]
    McpErrorResponse {
        /// O código de erro JSON-RPC/MCP.
        code: rmcp::model::ErrorCode,
        /// A mensagem de erro descritiva.
        message: String,
        /// Dados adicionais opcionais sobre o erro.
        data: Option<JsonValue>,
    },

    /// Timeout ocorrido ao esperar uma resposta do servidor.
    #[error("Timeout esperando resposta do servidor")]
    Timeout,

    /// A conexão WebSocket foi fechada inesperadamente pelo peer ou pela rede.
    #[error("Conexão fechada inesperadamente")]
    ConnectionClosed,

    /// Uma resposta inesperada ou malformada foi recebida do servidor.
    #[error("Resposta inesperada do servidor: {0}")]
    UnexpectedResponse(String),
}

/// Cliente de teste para interagir com o `Typedb-MCP-Server`.
///
/// Este cliente encapsula a lógica de conexão WebSocket, o handshake de inicialização MCP,
/// o envio de chamadas de ferramentas e o recebimento de respostas.
/// É projetado para ser usado em testes de integração.
#[derive(Debug)]
pub struct TestMcpClient {
    ws_stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
    default_request_timeout: Duration,
    server_info: Option<ServerInfo>,
}

impl TestMcpClient {
    /// Conecta-se ao servidor MCP na URL especificada e realiza o handshake de inicialização MCP.
    ///
    /// # Arguments
    /// * `server_ws_url`: A URL completa do endpoint WebSocket do servidor MCP (ex: "ws://localhost:8788/mcp/ws").
    /// * `auth_token`: Opcional. Token JWT para autenticação Bearer.
    /// * `connect_timeout`: Duração do timeout para estabelecer a conexão WebSocket.
    /// * `default_request_timeout`: Timeout padrão para esperar respostas MCP do servidor após a conexão.
    /// * `client_init_params`: Parâmetros de inicialização que o cliente envia ao servidor.
    pub async fn connect_and_initialize(
        server_ws_url: &str,
        auth_token: Option<String>,
        connect_timeout: Duration,
        default_request_timeout: Duration,
        client_init_params: InitializeRequestParam,
    ) -> Result<Self, McpClientError> {
        let mut client = Self::connect_websocket(
            server_ws_url,
            auth_token,
            connect_timeout,
            default_request_timeout,
        )
        .await?;

        client.initialize_mcp_session(client_init_params).await?;
        Ok(client)
    }

    /// Estabelece apenas a conexão WebSocket com o servidor.
    ///
    /// O método `initialize_mcp_session` deve ser chamado explicitamente após esta função
    /// para completar o handshake MCP.
    /// Este método é privado e usado internamente por `connect_and_initialize`.
    async fn connect_websocket(
        server_ws_url: &str,
        auth_token: Option<String>,
        connect_timeout: Duration,
        default_request_timeout: Duration,
    ) -> Result<Self, McpClientError> {
        let url = Url::parse(server_ws_url)?;
        let host_header = url.host_str().unwrap_or("localhost").to_string();
        let port_suffix = url.port().map_or_else(String::new, |p| format!(":{}", p));
        let effective_host_header = format!("{}{}", host_header, port_suffix);

        let mut request_builder = HttpRequest::builder()
            .method("GET")
            .uri(url.as_str())
            .header("Host", effective_host_header)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header(
                "Sec-WebSocket-Key",
                tokio_tungstenite::tungstenite::handshake::client::generate_key(),
            );

        if let Some(token) = auth_token {
            let auth_value = format!("Bearer {}", token);
            match http::HeaderValue::from_str(&auth_value) {
                Ok(header_val) => {
                    request_builder = request_builder.header(AUTHORIZATION, header_val);
                }
                Err(e) => return Err(McpClientError::HttpRequest(http::Error::from(e))),
            }
        }

        let request = request_builder.body(())?;

        info!("TestMcpClient: Tentando conectar WebSocket a: {}", server_ws_url);
        trace!(
            "TestMcpClient: Cabeçalhos da requisição de handshake WebSocket: {:?}",
            request.headers()
        );

        match timeout(connect_timeout, connect_async(request)).await {
            Ok(Ok((ws_stream, response))) => {
                let status = response.status();
                debug!("TestMcpClient: Handshake WebSocket. Resposta do servidor: {}", status);
                if status != HttpStatus::SWITCHING_PROTOCOLS {
                    let body_string = response.into_body().and_then(|b| String::from_utf8(b).ok());
                    warn!(
                        "TestMcpClient: Resposta HTTP inesperada no handshake WebSocket: {}. Corpo: {:?}",
                        status, body_string
                    );
                    return Err(McpClientError::HandshakeFailed(status, body_string));
                }
                info!("TestMcpClient: Conectado com sucesso via WebSocket a: {}", server_ws_url);
                Ok(TestMcpClient { ws_stream, default_request_timeout, server_info: None })
            }
            Ok(Err(WsError::Http(response))) => {
                let status = response.status();
                let body_string = response.into_body().and_then(|b| String::from_utf8(b).ok());
                warn!(
                    "TestMcpClient: Falha no handshake HTTP WebSocket: {}. Corpo: {:?}",
                    status, body_string
                );
                Err(McpClientError::HandshakeFailed(status, body_string))
            }
            Ok(Err(e)) => {
                error!("TestMcpClient: Falha ao conectar (erro WebSocket não-HTTP): {}", e);
                Err(McpClientError::WebSocket(e))
            }
            Err(_) => {
                error!("TestMcpClient: Timeout ao tentar conectar WebSocket a: {}", server_ws_url);
                Err(McpClientError::Timeout)
            }
        }
    }

    /// Envia a requisição `initialize` para o servidor MCP e processa a resposta.
    /// Armazena o `ServerInfo` recebido e envia a notificação `initialized`.
    ///
    /// # Arguments
    /// * `params`: Os parâmetros para a requisição `initialize` (protocol version, capabilities, client info).
    pub async fn initialize_mcp_session(
        &mut self,
        params: InitializeRequestParam,
    ) -> Result<InitializeResult, McpClientError> {
        info!("TestMcpClient: Enviando requisição 'initialize' para o servidor.");
        let client_request_payload = ClientRequest::InitializeRequest(rmcp::model::Request {
            method: InitializeResultMethod::default(),
            params,
            extensions: Extensions::default(),
        });

        let init_result = self
            .send_request_and_get_response(client_request_payload, |server_result| {
                if let ServerResult::InitializeResult(res) = server_result {
                    Ok(res)
                } else {
                    Err(McpClientError::UnexpectedResponse(format!(
                        "Esperado InitializeResult, obtido {:?}",
                        server_result
                    )))
                }
            })
            .await?;

        self.server_info = Some(ServerInfo {
            protocol_version: init_result.protocol_version.clone(),
            capabilities: init_result.capabilities.clone(),
            server_info: init_result.server_info.clone(),
            instructions: init_result.instructions.clone(),
        });

        self.send_initialized_notification().await?;

        info!(
            "TestMcpClient: Sessão MCP inicializada com sucesso. ServerInfo: {:?}",
            self.server_info.as_ref().map(|si| si.server_info.name.clone())
        );
        Ok(init_result)
    }

    /// Envia a notificação `initialized` para o servidor.
    /// Chamado internamente por `initialize_mcp_session`.
    async fn send_initialized_notification(&mut self) -> Result<(), McpClientError> {
        let notification_payload =
            ClientNotification::InitializedNotification(NotificationNoParam {
                method: InitializedNotificationMethod::default(),
                extensions: Extensions::default(),
            });

        let rpc_notification = JsonRpcNotification {
            jsonrpc: JsonRpcVersion2_0::default(),
            notification: notification_payload,
        };
        let client_message = ClientJsonRpcMessage::Notification(rpc_notification);

        let json_payload = serde_json::to_string(&client_message)?;
        debug!("TestMcpClient: Enviando notificação Initialized: {}", json_payload);
        self.ws_stream.send(TungsteniteWsMessage::Text(json_payload.into())).await?;
        Ok(())
    }

    /// Envia uma requisição MCP genérica e aguarda a resposta correspondente.
    /// Este é um método interno usado por funções de chamada de ferramenta mais específicas.
    async fn send_request_and_get_response<R, F>(
        &mut self,
        client_request_payload: ClientRequest,
        expected_server_result_variant_fn: F,
    ) -> Result<R, McpClientError>
    where
        R: DeserializeOwned + Debug,
        F: FnOnce(ServerResult) -> Result<R, McpClientError>,
    {
        let req_id = new_req_id();
        let rpc_request = JsonRpcRequest {
            jsonrpc: JsonRpcVersion2_0::default(),
            id: req_id.clone(),
            request: client_request_payload,
        };
        let client_message = ClientJsonRpcMessage::Request(rpc_request);

        let json_payload = serde_json::to_string(&client_message)?;
        let request_id_for_log = match &client_message {
            ClientJsonRpcMessage::Request(req) => Some(&req.id),
            _ => None,
        };
        debug!("TestMcpClient: Enviando (ID: {:?}): {}", request_id_for_log, json_payload);

        self.ws_stream.send(TungsteniteWsMessage::Text(json_payload.into())).await?;

        let op_start_time = Instant::now();
        loop {
            if op_start_time.elapsed() > self.default_request_timeout {
                error!("TestMcpClient: Timeout esperando resposta para requisição ID {:?}", req_id);
                return Err(McpClientError::Timeout);
            }

            match timeout(Duration::from_millis(500), self.ws_stream.next()).await {
                Ok(Some(Ok(TungsteniteWsMessage::Text(text)))) => {
                    trace!("TestMcpClient: Recebido (esperando ID: {:?}): {}", req_id, text);
                    match serde_json::from_str::<ServerJsonRpcMessage>(&text) {
                        Ok(ServerJsonRpcMessage::Response(JsonRpcResponse {
                            id: resp_id,
                            result,
                            ..
                        })) if resp_id == req_id => {
                            debug!(
                                "TestMcpClient: Resposta MCP recebida para ID {:?}: {:?}",
                                resp_id, result
                            );
                            return expected_server_result_variant_fn(result);
                        }
                        Ok(ServerJsonRpcMessage::Error(JsonRpcError {
                            id: err_id, error, ..
                        })) if err_id == req_id => {
                            error!(
                                "TestMcpClient: Erro MCP recebido do servidor para ID {:?}: {:?}",
                                err_id, error
                            );
                            return Err(McpClientError::McpErrorResponse {
                                code: error.code,
                                message: error.message.into_owned(),
                                data: error.data,
                            });
                        }
                        Ok(ServerJsonRpcMessage::Notification(notification)) => {
                            debug!("TestMcpClient: Recebida notificação (ignorando enquanto espera resposta para ID {:?}): {:?}", req_id, notification);
                        }
                        Ok(other_message_type) => {
                            let received_msg_id_for_log: Option<&RequestId> =
                                other_message_type.message_id_for_logging();
                            if received_msg_id_for_log.map_or(true, |id| id != &req_id) {
                                trace!("TestMcpClient: Recebida mensagem (ID {:?}) não relacionada à requisição pendente (ID {:?}). Mensagem: {:?}", received_msg_id_for_log, req_id, other_message_type);
                            } else {
                                warn!("TestMcpClient: Recebido tipo de mensagem inesperado ({:?}) enquanto esperava resposta para {:?}: {:?}", received_msg_id_for_log, req_id, other_message_type);
                            }
                        }
                        Err(e) => {
                            warn!("TestMcpClient: Erro ao desserializar mensagem do servidor (esperando ID {:?}): {}. Conteúdo: '{}'", req_id, e, text);
                        }
                    }
                }
                Ok(Some(Ok(TungsteniteWsMessage::Close(close_frame)))) => {
                    info!("TestMcpClient: Conexão WebSocket fechada pelo servidor (esperando ID {:?}): {:?}", req_id, close_frame);
                    return Err(McpClientError::ConnectionClosed);
                }
                Ok(Some(Ok(other_ws_msg))) => {
                    trace!("TestMcpClient: Recebida mensagem WebSocket não-texto (esperando ID {:?}): {:?}", req_id, other_ws_msg);
                }
                Ok(Some(Err(e))) => {
                    error!(
                        "TestMcpClient: Erro na stream WebSocket (esperando ID {:?}): {}",
                        req_id, e
                    );
                    return Err(McpClientError::WebSocket(e));
                }
                Ok(None) => {
                    error!("TestMcpClient: Stream WebSocket terminou inesperadamente (esperando ID {:?})", req_id);
                    return Err(McpClientError::ConnectionClosed);
                }
                Err(_) => {
                    trace!("TestMcpClient: Timeout de leitura individual para ID {:?}, continuando espera.", req_id);
                }
            }
        }
    }

    /// Envia uma requisição `tools/call` para o servidor.
    ///
    /// # Arguments
    /// * `tool_name`: O nome da ferramenta a ser chamada.
    /// * `arguments`: Opcional. Argumentos para a ferramenta no formato `serde_json::Value` (geralmente um objeto JSON).
    pub async fn call_tool(
        &mut self,
        tool_name: impl Into<String>,
        arguments: Option<JsonValue>,
    ) -> Result<CallToolResult, McpClientError> {
        let params = CallToolRequestParam {
            name: tool_name.into().into(),
            arguments: arguments.and_then(|v| v.as_object().cloned()),
        };
        let client_request = ClientRequest::CallToolRequest(rmcp::model::Request {
            method: CallToolRequestMethod::default(),
            params,
            extensions: Extensions::default(),
        });

        self.send_request_and_get_response(client_request, |server_result| {
            if let ServerResult::CallToolResult(res) = server_result {
                Ok(res)
            } else {
                Err(McpClientError::UnexpectedResponse(format!(
                    "Esperado CallToolResult, obtido {:?}",
                    server_result
                )))
            }
        })
        .await
    }

    /// Envia uma requisição `tools/list` para o servidor.
    ///
    /// # Arguments
    /// * `params`: Opcional. Parâmetros de paginação.
    pub async fn list_tools(
        &mut self,
        params: Option<PaginatedRequestParam>,
    ) -> Result<ListToolsResult, McpClientError> {
        let client_request = ClientRequest::ListToolsRequest(rmcp::model::RequestOptionalParam {
            method: ListToolsRequestMethod::default(),
            params,
            extensions: Extensions::default(),
        });
        self.send_request_and_get_response(client_request, |server_result| {
            if let ServerResult::ListToolsResult(res) = server_result {
                Ok(res)
            } else {
                Err(McpClientError::UnexpectedResponse(format!(
                    "Esperado ListToolsResult, obtido {:?}",
                    server_result
                )))
            }
        })
        .await
    }

    /// Envia uma requisição `resources/read` para o servidor.
    ///
    /// # Arguments
    /// * `uri`: A URI do recurso a ser lido.
    pub async fn read_resource(
        &mut self,
        uri: impl Into<String>,
    ) -> Result<ReadResourceResult, McpClientError> {
        let params = ReadResourceRequestParam { uri: uri.into().into() };
        let client_request = ClientRequest::ReadResourceRequest(rmcp::model::Request {
            method: ReadResourceRequestMethod::default(),
            params,
            extensions: Extensions::default(),
        });
        self.send_request_and_get_response(client_request, |server_result| {
            if let ServerResult::ReadResourceResult(res) = server_result {
                Ok(res)
            } else {
                Err(McpClientError::UnexpectedResponse(format!(
                    "Esperado ReadResourceResult, obtido {:?}",
                    server_result
                )))
            }
        })
        .await
    }

    /// Envia uma requisição `resources/list` para o servidor.
    ///
    /// # Arguments
    /// * `params`: Opcional. Parâmetros de paginação.
    pub async fn list_resources(
        &mut self,
        params: Option<PaginatedRequestParam>,
    ) -> Result<ListResourcesResult, McpClientError> {
        let client_request =
            ClientRequest::ListResourcesRequest(rmcp::model::RequestOptionalParam {
                method: ListResourcesRequestMethod::default(),
                params,
                extensions: Extensions::default(),
            });
        self.send_request_and_get_response(client_request, |server_result| {
            if let ServerResult::ListResourcesResult(res) = server_result {
                Ok(res)
            } else {
                Err(McpClientError::UnexpectedResponse(format!(
                    "Esperado ListResourcesResult, obtido {:?}",
                    server_result
                )))
            }
        })
        .await
    }

    /// Envia uma requisição `resources/templates/list` para o servidor.
    ///
    /// # Arguments
    /// * `params`: Opcional. Parâmetros de paginação.
    pub async fn list_resource_templates(
        &mut self,
        params: Option<PaginatedRequestParam>,
    ) -> Result<ListResourceTemplatesResult, McpClientError> {
        let client_request =
            ClientRequest::ListResourceTemplatesRequest(rmcp::model::RequestOptionalParam {
                method: ListResourceTemplatesRequestMethod::default(),
                params,
                extensions: Extensions::default(),
            });
        self.send_request_and_get_response(client_request, |server_result| {
            if let ServerResult::ListResourceTemplatesResult(res) = server_result {
                Ok(res)
            } else {
                Err(McpClientError::UnexpectedResponse(format!(
                    "Esperado ListResourceTemplatesResult, obtido {:?}",
                    server_result
                )))
            }
        })
        .await
    }

    /// Envia uma notificação `notifications/cancelled` para o servidor.
    ///
    /// # Arguments
    /// * `request_id_to_cancel`: O ID da requisição original que está sendo cancelada.
    /// * `reason`: Opcional. Uma razão textual para o cancelamento.
    pub async fn cancel_request(
        &mut self,
        request_id_to_cancel: RequestId,
        reason: Option<String>,
    ) -> Result<(), McpClientError> {
        let params =
            CancelledNotificationParam { request_id: request_id_to_cancel.clone(), reason };
        let notification_payload =
            ClientNotification::CancelledNotification(rmcp::model::Notification {
                method: CancelledNotificationMethod::default(),
                params,
                extensions: Extensions::default(),
            });

        let rpc_notification = JsonRpcNotification {
            jsonrpc: JsonRpcVersion2_0::default(),
            notification: notification_payload,
        };
        let client_message = ClientJsonRpcMessage::Notification(rpc_notification);

        let json_payload = serde_json::to_string(&client_message)?;
        debug!(
            "TestMcpClient: Enviando notificação Cancelled (para ID: {:?}): {}",
            request_id_to_cancel, json_payload
        );

        self.ws_stream.send(TungsteniteWsMessage::Text(json_payload.into())).await?;
        Ok(())
    }

    /// Fecha a conexão WebSocket de forma limpa.
    pub async fn close(mut self) -> Result<(), McpClientError> {
        info!("TestMcpClient: Fechando conexão.");
        self.ws_stream.close(None).await?;
        Ok(())
    }

    /// Retorna as informações do servidor (`ServerInfo`) recebidas durante a inicialização.
    /// Retorna `None` se a sessão não foi inicializada ou se a inicialização falhou.
    pub fn get_server_info(&self) -> Option<&ServerInfo> {
        self.server_info.as_ref()
    }
}

/// Trait helper para extrair o ID de uma `ServerJsonRpcMessage` para fins de logging, se existir.
trait MessageIdLogger {
    fn message_id_for_logging(&self) -> Option<&RequestId>;
}

impl MessageIdLogger for ServerJsonRpcMessage {
    fn message_id_for_logging(&self) -> Option<&RequestId> {
        match self {
            ServerJsonRpcMessage::Request(req) => Some(&req.id),
            ServerJsonRpcMessage::Response(resp) => Some(&resp.id),
            ServerJsonRpcMessage::Error(err) => Some(&err.id),
            _ => None, // Notificações não têm ID no mesmo nível da estrutura JSON-RPC
        }
    }
}
