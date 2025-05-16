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
//! durante os testes de integração e BDD.

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
};

// futures imports
use futures_util::{StreamExt, SinkExt};

// HTTP types import
use http::{Request as HttpRequest, header::AUTHORIZATION};

// URL parsing import
use url::Url;

// Serde e RMCP imports
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value as JsonValue;
use rmcp::model::{
    ClientJsonRpcMessage, ServerJsonRpcMessage, RequestId, NumberOrString,
    JsonRpcRequest, JsonRpcResponse, JsonRpcError, JsonRpcVersion,
    ClientRequest, ServerResult,
    CallToolRequestParam, CallToolResult, ErrorData, ErrorCode,
    ListToolsRequestParam, ListToolsResult,
    ReadResourceRequestParam, ReadResourceResult,
    InitializeRequestParam, InitializeResult,
    // Adicionar novos tipos para as requisições e notificações
    ShutdownRequestMethod, // Assumindo que existe para `ClientRequest::ShutdownRequest`
    WriteResourceRequestParam, WriteResourceResult, WriteResourceRequestMethod,
    DeleteResourceRequestParam, DeleteResourceResult, DeleteResourceRequestMethod,
    ListResourcesRequestParam, ListResourcesResult, ListResourcesRequestMethod,
    WatchResourceRequestParam, WatchResourceResult, WatchResourceRequestMethod,
    UnwatchResourceRequestParam, UnwatchResourceResult, UnwatchResourceRequestMethod,
    ClientNotification, ClientNotificationMethod, CancelRequestParams, CancelRequestMethod,
    Method, // Para ter acesso a CallToolRequestMethod, etc.
};

// Tracing import
use tracing::{debug, error, info, warn};

/// Próximo ID para requisições JSON-RPC.
static NEXT_JSON_RPC_ID: AtomicU32 = AtomicU32::new(1);

/// Gera um novo ID de requisição JSON-RPC.
fn new_req_id() -> RequestId {
    NumberOrString::Number(NEXT_JSON_RPC_ID.fetch_add(1, AtomicOrdering::SeqCst).into())
}

/// Erros que podem ocorrer ao usar o `TestMcpClient`.
#[derive(Debug, thiserror::Error)]
pub enum McpClientError {
    /// Erro originado na camada WebSocket (tokio-tungstenite).
    #[error("Erro WebSocket: {0}")]
    WebSocket(#[from] WsError),

    /// Erro de serialização ou desserialização JSON.
    #[error("Erro JSON: {0}")]
    Json(#[from] serde_json::Error),

    /// Erro ao parsear a URL do servidor.
    #[error("Erro ao parsear URL: {0}")]
    UrlParse(#[from] url::ParseError),

    /// Erro ao construir a requisição HTTP para o handshake WebSocket.
    #[error("Erro na requisição HTTP: {0}")]
    HttpRequest(#[from] http::Error),

    /// O servidor MCP retornou uma resposta de erro.
    #[error("Erro MCP do Servidor: code={code}, message='{message}', data={data:?}")]
    McpErrorResponse {
        code: ErrorCode,
        message: String,
        data: Option<JsonValue>,
    },

    /// Timeout esperando por uma resposta do servidor.
    #[error("Timeout esperando resposta do servidor")]
    Timeout,

    /// A conexão foi fechada inesperadamente.
    #[error("Conexão fechada inesperadamente")]
    ConnectionClosed,

    /// Resposta inesperada do servidor (ex: tipo de resultado não correspondente).
    #[error("Resposta inesperada do servidor: {0}")]
    UnexpectedResponse(String),
}

/// Cliente de teste para interagir com o `Typedb-MCP-Server`.
#[derive(Debug)]
pub struct TestMcpClient {
    ws_stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
    default_timeout: Duration,
}

impl TestMcpClient {
    /// Conecta-se ao servidor MCP no `server_url_str`.
    ///
    /// # Argumentos
    /// * `server_url_str`: A URL completa do endpoint WebSocket do servidor (ex: "ws://localhost:8787/mcp/ws").
    /// * `auth_token`: Opcional. Um token JWT para incluir no header `Authorization`.
    /// * `connect_timeout`: Timeout para a tentativa de conexão.
    /// * `default_request_timeout`: Timeout padrão para esperar respostas do servidor.
    pub async fn connect(
        server_url_str: &str,
        auth_token: Option<String>,
        connect_timeout_duration: Duration,
        default_request_timeout: Duration,
    ) -> Result<Self, McpClientError> {
        let url = Url::parse(server_url_str)?;

        let mut request_builder = HttpRequest::builder()
            .method("GET") // Método padrão para handshake WebSocket
            .uri(url.as_str());

        if let Some(token) = auth_token {
            request_builder = request_builder.header(
                AUTHORIZATION,
                format!("Bearer {}", token)
            );
        }
        
        // Adiciona headers padrão para WebSocket
        request_builder = request_builder
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", tokio_tungstenite::tungstenite::handshake::client::generate_key()); // Chave aleatória

        let request = request_builder.body(())?;

        info!("Tentando conectar cliente MCP de teste a: {}", server_url_str);

        match timeout(connect_timeout_duration, connect_async(request)).await {
            Ok(Ok((ws_stream, response))) => {
                debug!("Handshake WebSocket bem-sucedido. Resposta do servidor: {:?}", response.status());
                if !response.status().is_informational() && !response.status().is_success() {
                    // O status 101 Switching Protocols é o esperado. Outros podem indicar erro.
                    // A biblioteca tokio-tungstenite geralmente lida com isso, mas uma verificação extra pode ser útil.
                    warn!("Resposta HTTP inesperada no handshake WebSocket: {}", response.status());
                    // Mesmo com um status não-101, connect_async pode ter sucesso se o upgrade ocorrer.
                    // Se for um erro real (ex: 401), connect_async deve falhar.
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

    /// Envia uma mensagem JSON-RPC e aguarda a resposta correspondente.
    ///
    /// Este é um método genérico. Para maior segurança de tipo, use os métodos específicos
    /// como `call_tool`, `list_tools`, etc.
    ///
    /// # Argumentos
    /// * `method_name`: O nome do método JSON-RPC (ex: "tools/call").
    /// * `params`: Os parâmetros para o método, que devem ser serializáveis para JSON.
    /// * `expected_server_result_variant_fn`: Uma função que tenta converter o `ServerResult` genérico
    ///   para o tipo de resultado específico esperado (`RespResult`).
    async fn send_request_and_get_response<R, F>(
        &mut self,
        client_request_payload: rmcp::model::ClientRequest,
        expected_server_result_variant_fn: F,
    ) -> Result<R, McpClientError>
    where
        // rmcp::model::ClientRequest deve implementar Serialize e Debug.
        R: DeserializeOwned + std::fmt::Debug,
        F: FnOnce(ServerResult) -> Result<R, McpClientError>,
    {
        let req_id = new_req_id();
        let rpc_request = JsonRpcRequest {
            jsonrpc: JsonRpcVersion::V2_0,
            id: req_id.clone(),
            request: client_request_payload,
        };
        let client_message = ClientJsonRpcMessage::Request(rpc_request);

        let json_payload = serde_json::to_string(&client_message)?;
        debug!("Cliente MCP enviando (ID: {:?}): {}", req_id, json_payload);

        self.ws_stream.send(WsMessage::Text(json_payload)).await?;

        loop {
            match timeout(self.default_timeout, self.ws_stream.next()).await {
                Ok(Some(Ok(WsMessage::Text(text)))) => {
                    debug!("Cliente MCP recebeu (tentando ID: {:?}): {}", req_id, text);
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
                            debug!("Cliente MCP recebeu notificação (ignorando ao esperar resposta para {:?}): {:?}", req_id, notification);
                            // Continuar esperando pela resposta da requisição
                        }
                        Ok(other_message_type) => {
                             warn!("Cliente MCP recebeu tipo de mensagem inesperado (ID {:?}) enquanto esperava resposta para {:?}: {:?}", other_message_type.message_id(), req_id, other_message_type);
                            // Continuar esperando
                        }
                        Err(e) => {
                            error!("Erro ao desserializar mensagem do servidor (esperando ID {:?}): {}. Conteúdo: {}", req_id, e, text);
                            // Não necessariamente um erro fatal para *esta* requisição, pode ser uma mensagem malformada não relacionada.
                            // Mas se persistir, pode indicar um problema.
                            // Por simplicidade, continuamos, mas em um cliente robusto, pode haver lógica de retentativa ou erro.
                        }
                    }
                }
                Ok(Some(Ok(WsMessage::Close(close_frame)))) => {
                    info!("Conexão WebSocket fechada pelo servidor (esperando ID {:?}): {:?}", req_id, close_frame);
                    return Err(McpClientError::ConnectionClosed);
                }
                Ok(Some(Ok(other_ws_msg))) => {
                    debug!("Cliente MCP recebeu mensagem WebSocket não-texto (esperando ID {:?}): {:?}", req_id, other_ws_msg);
                    // Ignorar Ping, Pong, Binary, etc.
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
                    error!("Timeout esperando resposta do servidor para requisição ID {:?}", req_id);
                    return Err(McpClientError::Timeout);
                }
            }
        }
    }

    /// Chama a ferramenta `initialize`.
    pub async fn initialize(
        &mut self,
        params: InitializeRequestParam,
    ) -> Result<InitializeResult, McpClientError> {
        let client_request = ClientRequest::InitializeRequest(rmcp::model::Request {
            method: Method::InitializeRequestMethod(rmcp::model::InitializeRequestMethod::default()),
            params,
            extensions: Default::default(),
        });
        self.send_request_and_get_response(client_request, |server_result| {
            if let ServerResult::InitializeResult(res) = server_result {
                Ok(res)
            } else {
                Err(McpClientError::UnexpectedResponse(format!("Esperado InitializeResult, obtido {:?}", server_result)))
            }
        }).await
    }

    /// Envia a requisição `shutdown` para o servidor.
    pub async fn shutdown(&mut self) -> Result<(), McpClientError> {
        let client_request = ClientRequest::ShutdownRequest(rmcp::model::Request {
            method: Method::ShutdownRequestMethod(ShutdownRequestMethod::default()),
            params: (), // Shutdown não tem parâmetros
            extensions: Default::default(),
        });
        self.send_request_and_get_response(client_request, |server_result| {
            if let ServerResult::ShutdownResult(_res) = server_result { // _res é ()
                Ok(())
            } else {
                Err(McpClientError::UnexpectedResponse(format!("Esperado ShutdownResult, obtido {:?}", server_result)))
            }
        }).await
    }

    /// Chama a ferramenta `tools/call`.
    pub async fn call_tool(
        &mut self,
        tool_name: impl Into<String>,
        arguments: Option<JsonValue>,
    ) -> Result<CallToolResult, McpClientError> {
        let params = CallToolRequestParam {
            name: tool_name.into().into(), // String -> Cow<'static, str>
            arguments: arguments.and_then(|v| v.as_object().cloned()), // JsonValue -> Option<JsonObject>
        };
        let client_request = ClientRequest::CallToolRequest(rmcp::model::Request {
            method: Method::CallToolRequestMethod(rmcp::model::CallToolRequestMethod::default()),
            params,
            extensions: Default::default(),
        });

        self.send_request_and_get_response(client_request, |server_result| {
            if let ServerResult::CallToolResult(res) = server_result {
                Ok(res)
            } else {
                Err(McpClientError::UnexpectedResponse(format!("Esperado CallToolResult, obtido {:?}", server_result)))
            }
        }).await
    }

    /// Chama a ferramenta `tools/list`.
    pub async fn list_tools(
        &mut self,
        params: Option<ListToolsRequestParam>,
    ) -> Result<ListToolsResult, McpClientError> {
        let client_request = ClientRequest::ListToolsRequest(rmcp::model::Request {
            method: Method::ListToolsRequestMethod(rmcp::model::ListToolsRequestMethod::default()),
            params: params.unwrap_or_default(), // ListToolsRequestParam tem Default
            extensions: Default::default(),
        });
        self.send_request_and_get_response(client_request, |server_result| {
            if let ServerResult::ListToolsResult(res) = server_result {
                Ok(res)
            } else {
                Err(McpClientError::UnexpectedResponse(format!("Esperado ListToolsResult, obtido {:?}", server_result)))
            }
        }).await
    }

    /// Chama a ferramenta `resources/read`.
    pub async fn read_resource(
        &mut self,
        uri: impl Into<String>,
    ) -> Result<ReadResourceResult, McpClientError> {
        let params = ReadResourceRequestParam {
            uri: uri.into().into(), // String -> Cow<'static, str>
        };
        let client_request = ClientRequest::ReadResourceRequest(rmcp::model::Request {
            method: Method::ReadResourceRequestMethod(rmcp::model::ReadResourceRequestMethod::default()),
            params,
            extensions: Default::default(),
        });
        self.send_request_and_get_response(client_request, |server_result| {
            if let ServerResult::ReadResourceResult(res) = server_result {
                Ok(res)
            } else {
                Err(McpClientError::UnexpectedResponse(format!("Esperado ReadResourceResult, obtido {:?}", server_result)))
            }
        }).await
    }

    /// Chama a ferramenta `resources/write`.
    pub async fn write_resource(
        &mut self,
        params: WriteResourceRequestParam,
    ) -> Result<WriteResourceResult, McpClientError> {
        let client_request = ClientRequest::WriteResourceRequest(rmcp::model::Request {
            method: Method::WriteResourceRequestMethod(WriteResourceRequestMethod::default()),
            params,
            extensions: Default::default(),
        });
        self.send_request_and_get_response(client_request, |server_result| {
            if let ServerResult::WriteResourceResult(res) = server_result {
                Ok(res)
            } else {
                Err(McpClientError::UnexpectedResponse(format!("Esperado WriteResourceResult, obtido {:?}", server_result)))
            }
        }).await
    }

    /// Chama a ferramenta `resources/delete`.
    pub async fn delete_resource(
        &mut self,
        params: DeleteResourceRequestParam,
    ) -> Result<DeleteResourceResult, McpClientError> {
        let client_request = ClientRequest::DeleteResourceRequest(rmcp::model::Request {
            method: Method::DeleteResourceRequestMethod(DeleteResourceRequestMethod::default()),
            params,
            extensions: Default::default(),
        });
        self.send_request_and_get_response(client_request, |server_result| {
            if let ServerResult::DeleteResourceResult(res) = server_result {
                Ok(res)
            } else {
                Err(McpClientError::UnexpectedResponse(format!("Esperado DeleteResourceResult, obtido {:?}", server_result)))
            }
        }).await
    }

    /// Chama a ferramenta `resources/list`.
    pub async fn list_resources(
        &mut self,
        params: Option<ListResourcesRequestParam>,
    ) -> Result<ListResourcesResult, McpClientError> {
        let client_request = ClientRequest::ListResourcesRequest(rmcp::model::Request {
            method: Method::ListResourcesRequestMethod(ListResourcesRequestMethod::default()),
            params: params.unwrap_or_default(),
            extensions: Default::default(),
        });
        self.send_request_and_get_response(client_request, |server_result| {
            if let ServerResult::ListResourcesResult(res) = server_result {
                Ok(res)
            } else {
                Err(McpClientError::UnexpectedResponse(format!("Esperado ListResourcesResult, obtido {:?}", server_result)))
            }
        }).await
    }

    /// Chama a ferramenta `resources/watch`.
    pub async fn watch_resource(
        &mut self,
        params: WatchResourceRequestParam,
    ) -> Result<WatchResourceResult, McpClientError> {
        let client_request = ClientRequest::WatchResourceRequest(rmcp::model::Request {
            method: Method::WatchResourceRequestMethod(WatchResourceRequestMethod::default()),
            params,
            extensions: Default::default(),
        });
        self.send_request_and_get_response(client_request, |server_result| {
            if let ServerResult::WatchResourceResult(res) = server_result {
                Ok(res)
            } else {
                Err(McpClientError::UnexpectedResponse(format!("Esperado WatchResourceResult, obtido {:?}", server_result)))
            }
        }).await
    }

    /// Chama a ferramenta `resources/unwatch`.
    pub async fn unwatch_resource(
        &mut self,
        params: UnwatchResourceRequestParam,
    ) -> Result<UnwatchResourceResult, McpClientError> {
        let client_request = ClientRequest::UnwatchResourceRequest(rmcp::model::Request {
            method: Method::UnwatchResourceRequestMethod(UnwatchResourceRequestMethod::default()),
            params,
            extensions: Default::default(),
        });
        self.send_request_and_get_response(client_request, |server_result| {
            if let ServerResult::UnwatchResourceResult(res) = server_result {
                Ok(res)
            } else {
                Err(McpClientError::UnexpectedResponse(format!("Esperado UnwatchResourceResult, obtido {:?}", server_result)))
            }
        }).await
    }

    /// Envia uma notificação `$/cancelRequest` para o servidor.
    ///
    /// Esta notificação instrui o servidor a cancelar uma requisição em andamento.
    /// Não há resposta direta a esta notificação.
    pub async fn cancel_request(&mut self, request_id_to_cancel: RequestId) -> Result<(), McpClientError> {
        let params = CancelRequestParams {
            id: request_id_to_cancel,
        };
        let notification = ClientNotification::CancelRequest(rmcp::model::Notification {
            method: ClientNotificationMethod::CancelRequestMethod(CancelRequestMethod::default()),
            params,
        });
        let client_message = ClientJsonRpcMessage::Notification(notification);

        let json_payload = serde_json::to_string(&client_message)?;
        debug!("Cliente MCP enviando notificação CancelRequest (para ID: {:?}): {}", client_message.params_id_for_logging(), json_payload);

        self.ws_stream.send(WsMessage::Text(json_payload)).await?;
        Ok(())
    }
    

    /// Fecha a conexão WebSocket de forma limpa.
    pub async fn close(mut self) -> Result<(), McpClientError> {
        info!("Fechando conexão do cliente MCP de teste.");
        self.ws_stream.close(None).await?;
        Ok(())
    }
}

// Nota: Este cliente de teste é simplificado. Um cliente de produção ou mais robusto
// lidaria com:
// - Reconexão.
// - Gerenciamento de múltiplas requisições concorrentes de forma mais explícita (ex: com um HashMap de `req_id` para `oneshot::Sender`).
// - Processamento de notificações não solicitadas de forma mais elaborada.
// - Configuração TLS mais detalhada (ex: aceitar certificados autoassinados para teste).
// - Heartbeating (Ping/Pong) para manter a conexão viva, se necessário.
