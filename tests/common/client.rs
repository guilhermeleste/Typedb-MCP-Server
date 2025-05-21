// tests/common/client.rs

// Licença Apache 2.0
// Copyright 2025 Guilherme Leste
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

//! Define um cliente MCP de teste para interagir com o `Typedb-MCP-Server`
//! durante os testes de integração.

// std imports
use std::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};
use std::time::Duration;

// Tokio e networking imports
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::{
    connect_async, MaybeTlsStream,
    tungstenite::protocol::Message as WsMessage,
    tungstenite::Error as WsError,
    WebSocketStream,
    tungstenite::protocol::frame::Utf8Bytes, // Importação para Utf8Bytes
};

// futures imports
use futures_util::{StreamExt, SinkExt};

// HTTP types import
use http::{Request as HttpRequest, header::AUTHORIZATION, StatusCode as HttpStatus};
use axum::BoxError as AxumBoxError;

// URL parsing import
use url::Url;

// Serde e RMCP imports
use serde::de::DeserializeOwned;
use serde_json::Value as JsonValue;
use rmcp::model::{
    ClientJsonRpcMessage, ServerJsonRpcMessage, RequestId, NumberOrString,
    JsonRpcRequest, JsonRpcResponse, JsonRpcError, JsonRpcVersion2_0,
    ClientRequest, ServerResult, ErrorCode,
    CallToolRequestParam, CallToolResult, CallToolRequestMethod, // Adicionado
    ListToolsResult, ListToolsRequestMethod,
    ReadResourceRequestParam, ReadResourceResult, ReadResourceRequestMethod,
    InitializeRequestParam, InitializeResult, InitializeResultMethod,
    ListResourcesResult, ListResourcesRequestMethod,
    ListResourceTemplatesResult, ListResourceTemplatesRequestMethod,
    ClientNotification,
    CancelledNotificationParam, CancelledNotificationMethod,
    PaginatedRequestParam, Extensions, InitializedNotificationMethod,
};

// Tracing import
use tracing::{debug, error, info, trace, warn};

/// Próximo ID para requisições JSON-RPC.
static NEXT_JSON_RPC_ID: AtomicU32 = AtomicU32::new(1);

/// Gera um novo ID de requisição JSON-RPC numérico.
fn new_req_id() -> RequestId {
    NumberOrString::Number(NEXT_JSON_RPC_ID.fetch_add(1, AtomicOrdering::SeqCst))
}

/// Erros que podem ocorrer ao usar o `TestMcpClient`.
#[derive(Debug, thiserror::Error)]
pub enum McpClientError {
    /// Erro originado na camada WebSocket.
    #[error("Erro WebSocket: {0}")]
    WebSocket(#[from] WsError),

    /// Erro durante a serialização ou desserialização JSON.
    #[error("Erro JSON: {0}")]
    Json(#[from] serde_json::Error),

    /// Erro ao parsear uma URL, geralmente a URL do servidor.
    #[error("Erro ao parsear URL: {0}")]
    UrlParse(#[from] url::ParseError),

    /// Erro na construção ou envio da requisição HTTP durante o handshake WebSocket.
    #[error("Erro na requisição HTTP (handshake): {0}")]
    HttpRequest(#[from] http::Error),

    /// Falha no handshake WebSocket, indicado por um status HTTP não-101.
    #[error("Falha no handshake WebSocket: Status {0}, Body: {1:?}")]
    HandshakeFailed(HttpStatus, Option<String>),

    /// Erro retornado pelo servidor MCP em uma resposta JSON-RPC.
    #[error("Erro MCP do Servidor: code={code:?}, message='{message}', data={data:?}")]
    McpErrorResponse {
        /// O código de erro JSON-RPC.
        code: ErrorCode,
        /// A mensagem de erro descritiva.
        message: String,
        /// Dados adicionais opcionais sobre o erro.
        data: Option<JsonValue>,
    },

    /// Timeout ocorrido ao esperar uma resposta do servidor.
    #[error("Timeout esperando resposta do servidor")]
    Timeout,

    /// A conexão WebSocket foi fechada inesperadamente.
    #[error("Conexão fechada inesperadamente")]
    ConnectionClosed,

    /// Uma resposta inesperada ou malformada foi recebida do servidor.
    #[error("Resposta inesperada do servidor: {0}")]
    UnexpectedResponse(String),

    /// Erro ao converter o corpo da resposta HTTP (geralmente durante o handshake).
    #[error("Erro ao converter corpo da resposta HTTP: {0}")]
    BodyConversionError(AxumBoxError),
}

/// Cliente de teste para interagir com o `Typedb-MCP-Server`.
#[derive(Debug)]
pub struct TestMcpClient {
    ws_stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
    default_timeout: Duration,
}

impl TestMcpClient {
    /// Conecta-se ao servidor MCP no `server_url_str`.
    pub async fn connect(
        server_url_str: &str,
        auth_token: Option<String>,
        connect_timeout_duration: Duration,
        default_request_timeout: Duration,
    ) -> Result<Self, McpClientError> {

        let url = Url::parse(server_url_str)?;

        // Extrai o host (e porta, se houver) para o header Host
        let host_header = match url.port() {
            Some(port) => format!("{}:{}", url.host_str().unwrap_or("localhost"), port),
            None => url.host_str().unwrap_or("localhost").to_string(),
        };

        let mut request_builder = HttpRequest::builder()
            .method("GET")
            .uri(url.as_str())
            .header("Host", host_header.clone());

        if let Some(token) = auth_token {
            let auth_value = format!("Bearer {}", token);
            match http::HeaderValue::from_str(&auth_value) {
                Ok(header_val) => { request_builder = request_builder.header(AUTHORIZATION, header_val); }
                Err(e) => return Err(McpClientError::HttpRequest(http::Error::from(e))),
            }
        }

        request_builder = request_builder
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", tokio_tungstenite::tungstenite::handshake::client::generate_key());

        let request = request_builder.body(())?;

        info!("Tentando conectar cliente MCP de teste a: {}", server_url_str);
        // Log dos cabeçalhos da requisição
        info!("Cabeçalhos da requisição de handshake WebSocket:");
        for (name, value) in request.headers() {
            info!("  {}: {:?}", name, value);
        }

        match timeout(connect_timeout_duration, connect_async(request)).await {
            Ok(Ok((ws_stream, response))) => {
                let status = response.status();
                debug!("Handshake WebSocket. Resposta do servidor: {}", status);
                if status != HttpStatus::SWITCHING_PROTOCOLS {
                    let body_option_vec_u8 = response.into_body();
                    let body_string = body_option_vec_u8.and_then(|bytes| String::from_utf8(bytes).ok());
                    
                    warn!("Resposta HTTP inesperada no handshake WebSocket: {}. Corpo: {:?}", status, body_string);
                    return Err(McpClientError::HandshakeFailed(status, body_string));
                }
                info!("Cliente MCP de teste conectado com sucesso a: {}", server_url_str);
                Ok(TestMcpClient { ws_stream, default_timeout: default_request_timeout })
            }
            Ok(Err(e)) => {
                error!("Falha ao conectar cliente MCP (erro WebSocket): {}", e);
                Err(McpClientError::WebSocket(e))
            }
            Err(_) => {
                error!("Timeout ao tentar conectar cliente MCP a: {}", server_url_str);
                Err(McpClientError::Timeout)
            }
        }
    }

    async fn send_request_and_get_response<R, F>(
        &mut self,
        client_request_payload: ClientRequest,
        expected_server_result_variant_fn: F,
    ) -> Result<R, McpClientError>
    where
        R: DeserializeOwned + std::fmt::Debug,
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
        debug!("Cliente MCP enviando (ID: {:?}): {}", request_id_for_log, json_payload);

        // CORRIGIDO: Convertido para Utf8Bytes
        self.ws_stream.send(WsMessage::Text(Utf8Bytes::from(json_payload))).await?;


        let op_start_time = std::time::Instant::now();
        loop {
            if op_start_time.elapsed() > self.default_timeout {
                error!("Timeout esperando resposta do servidor para requisição ID {:?}", req_id);
                return Err(McpClientError::Timeout);
            }
            match timeout(Duration::from_millis(200), self.ws_stream.next()).await {
                Ok(Some(Ok(WsMessage::Text(text)))) => {
                    trace!("Cliente MCP recebeu (esperando ID: {:?}): {}", req_id, text);
                    match serde_json::from_str::<ServerJsonRpcMessage>(&text) {
                        Ok(ServerJsonRpcMessage::Response(JsonRpcResponse { id: resp_id, result, .. })) if resp_id == req_id => {
                            debug!("Resposta MCP recebida para ID {:?}: {:?}", resp_id, result);
                            return expected_server_result_variant_fn(result);
                        }
                        Ok(ServerJsonRpcMessage::Error(JsonRpcError { id: err_id, error, .. })) if err_id == req_id => {
                            error!("Erro MCP recebido do servidor para ID {:?}: {:?}", err_id, error);
                            return Err(McpClientError::McpErrorResponse {
                                code: error.code,
                                message: error.message.into_owned(),
                                data: error.data,
                            });
                        }
                        Ok(ServerJsonRpcMessage::Notification(notification)) => {
                            debug!("Cliente MCP recebeu notificação (ignorando enquanto espera resposta para {:?}): {:?}", req_id, notification);
                        }
                        Ok(other_message_type) => {
                            let received_msg_id_for_log: Option<&RequestId> = other_message_type.message_id_for_logging();
                            if received_msg_id_for_log.map_or(true, |id| id != &req_id) {
                                trace!("Cliente MCP recebeu mensagem (ID {:?}) não relacionada à requisição pendente (ID {:?}). Mensagem: {:?}", received_msg_id_for_log, req_id, other_message_type);
                            } else {
                                warn!("Cliente MCP recebeu tipo de mensagem inesperado ({:?}) enquanto esperava resposta para {:?}: {:?}", received_msg_id_for_log, req_id, other_message_type);
                            }
                        }
                        Err(e) => {
                            warn!("Erro ao desserializar mensagem do servidor (esperando ID {:?}): {}. Conteúdo: '{}'", req_id, e, text);
                        }
                    }
                }
                Ok(Some(Ok(WsMessage::Close(close_frame)))) => {
                    info!("Conexão WebSocket fechada pelo servidor (esperando ID {:?}): {:?}", req_id, close_frame);
                    return Err(McpClientError::ConnectionClosed);
                }
                Ok(Some(Ok(other_ws_msg))) => {
                    trace!("Cliente MCP recebeu mensagem WebSocket não-texto (esperando ID {:?}): {:?}", req_id, other_ws_msg);
                }
                Ok(Some(Err(e))) => {
                    error!("Erro na stream WebSocket (esperando ID {:?}): {}", req_id, e);
                    return Err(McpClientError::WebSocket(e));
                }
                Ok(None) => {
                    error!("Stream WebSocket terminou inesperadamente (esperando ID {:?})", req_id);
                    return Err(McpClientError::ConnectionClosed);
                }
                Err(_) => { 
                    trace!("Timeout de leitura individual (200ms) para ID {:?}, continuando espera.", req_id);
                }
            }
        }
    }

    /// Envia a requisição `initialize`.
    pub async fn initialize(
        &mut self,
        params: InitializeRequestParam,
    ) -> Result<InitializeResult, McpClientError> {
        let client_request = ClientRequest::InitializeRequest(rmcp::model::Request {
            method: InitializeResultMethod::default(),
            params,
            extensions: Extensions::default(),
        });
        self.send_request_and_get_response(client_request, |server_result| {
            if let ServerResult::InitializeResult(res) = server_result {
                Ok(res)
            } else {
                Err(McpClientError::UnexpectedResponse(format!("Esperado InitializeResult, obtido {:?}", server_result)))
            }
        }).await
    }

    /// Envia a notificação `initialized` para o servidor.
    pub async fn initialized(&mut self) -> Result<(), McpClientError> {
        let notification_payload_no_param = rmcp::model::NotificationNoParam {
            method: InitializedNotificationMethod::default(),
            extensions: Extensions::default(),
        };
        let client_notification_enum_variant = ClientNotification::InitializedNotification(notification_payload_no_param);

        let rpc_notification_wrapper = rmcp::model::JsonRpcNotification {
            jsonrpc: JsonRpcVersion2_0::default(),
            notification: client_notification_enum_variant,
        };
        let client_message = ClientJsonRpcMessage::Notification(rpc_notification_wrapper);

        let json_payload = serde_json::to_string(&client_message)?;
        debug!("Cliente MCP enviando notificação Initialized: {}", json_payload);
        // CORRIGIDO: Convertido para Utf8Bytes
        self.ws_stream.send(WsMessage::Text(Utf8Bytes::from(json_payload))).await?;
        Ok(())
    }

    /// Chama uma ferramenta MCP genérica.
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
            method: CallToolRequestMethod::default(), // CORRIGIDO (era ListToolsRequestMethod)
            params,
            extensions: Extensions::default(),
        });

        self.send_request_and_get_response(client_request, |server_result| {
            if let ServerResult::CallToolResult(res) = server_result {
                Ok(res)
            } else {
                Err(McpClientError::UnexpectedResponse(format!("Esperado CallToolResult, obtido {:?}", server_result)))
            }
        }).await
    }

    /// Lista as ferramentas disponíveis no servidor.
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
                Err(McpClientError::UnexpectedResponse(format!("Esperado ListToolsResult, obtido {:?}", server_result)))
            }
        }).await
    }

    /// Lê um recurso do servidor.
    pub async fn read_resource(
        &mut self,
        uri: impl Into<String>,
    ) -> Result<ReadResourceResult, McpClientError> {
        let params = ReadResourceRequestParam {
            uri: uri.into().into(),
        };
        let client_request = ClientRequest::ReadResourceRequest(rmcp::model::Request {
            method: ReadResourceRequestMethod::default(),
            params,
            extensions: Extensions::default(),
        });
        self.send_request_and_get_response(client_request, |server_result| {
            if let ServerResult::ReadResourceResult(res) = server_result {
                Ok(res)
            } else {
                Err(McpClientError::UnexpectedResponse(format!("Esperado ReadResourceResult, obtido {:?}", server_result)))
            }
        }).await
    }

    /// Lista os recursos disponíveis no servidor.
    pub async fn list_resources(
        &mut self,
        params: Option<PaginatedRequestParam>,
    ) -> Result<ListResourcesResult, McpClientError> {
        let client_request = ClientRequest::ListResourcesRequest(rmcp::model::RequestOptionalParam {
            method: ListResourcesRequestMethod::default(),
            params,
            extensions: Extensions::default(),
        });
        self.send_request_and_get_response(client_request, |server_result| {
            if let ServerResult::ListResourcesResult(res) = server_result {
                Ok(res)
            } else {
                Err(McpClientError::UnexpectedResponse(format!("Esperado ListResourcesResult, obtido {:?}", server_result)))
            }
        }).await
    }

    /// Lista os templates de recursos disponíveis no servidor.
    pub async fn list_resource_templates(
        &mut self,
        params: Option<PaginatedRequestParam>,
    ) -> Result<ListResourceTemplatesResult, McpClientError> {
        let client_request = ClientRequest::ListResourceTemplatesRequest(rmcp::model::RequestOptionalParam {
            method: ListResourceTemplatesRequestMethod::default(),
            params,
            extensions: Extensions::default(),
        });
        self.send_request_and_get_response(client_request, |server_result| {
            if let ServerResult::ListResourceTemplatesResult(res) = server_result {
                Ok(res)
            } else {
                Err(McpClientError::UnexpectedResponse(format!("Esperado ListResourceTemplatesResult, obtido {:?}", server_result)))
            }
        }).await
    }


    /// Envia uma notificação `notifications/cancelled` para o servidor.
    pub async fn cancel_request(&mut self, request_id_to_cancel: RequestId, reason: Option<String>) -> Result<(), McpClientError> {
        let params = CancelledNotificationParam {
            request_id: request_id_to_cancel.clone(),
            reason,
        };
        let notification_payload_inner = rmcp::model::Notification {
            method: CancelledNotificationMethod::default(),
            params,
            extensions: Extensions::default(),
        };
        let client_notification_enum_variant = ClientNotification::CancelledNotification(notification_payload_inner);

        let rpc_notification_wrapper = rmcp::model::JsonRpcNotification {
            jsonrpc: JsonRpcVersion2_0::default(),
            notification: client_notification_enum_variant,
        };
        let client_message = ClientJsonRpcMessage::Notification(rpc_notification_wrapper);

        let json_payload = serde_json::to_string(&client_message)?;
        debug!("Cliente MCP enviando notificação Cancelled (para ID: {:?}): {}", request_id_to_cancel, json_payload);

        // CORRIGIDO: Convertido para Utf8Bytes
        self.ws_stream.send(WsMessage::Text(Utf8Bytes::from(json_payload))).await?;
        Ok(())
    }
    
    /// Fecha a conexão WebSocket de forma limpa.
    pub async fn close(mut self) -> Result<(), McpClientError> {
        info!("Fechando conexão do cliente MCP de teste.");
        self.ws_stream.close(None).await?;
        Ok(())
    }
}

/// Trait helper para extrair ID de `ServerJsonRpcMessage` para logging, se existir.
trait MessageIdLogger {
    fn message_id_for_logging(&self) -> Option<&RequestId>;
}

impl MessageIdLogger for ServerJsonRpcMessage {
    fn message_id_for_logging(&self) -> Option<&RequestId> {
        match self {
            ServerJsonRpcMessage::Request(req) => Some(&req.id),
            ServerJsonRpcMessage::Response(resp) => Some(&resp.id),
            ServerJsonRpcMessage::Error(err) => Some(&err.id),
            _ => None,
        }
    }
}