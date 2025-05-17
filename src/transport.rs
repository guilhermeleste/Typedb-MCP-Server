// src/transport.rs

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

//! Define o transporte WebSocket para a comunicação MCP.
//!
//! Esta struct `WebSocketTransport` adapta um `axum::extract::ws::WebSocket`
//! para ser compatível com as traits `futures::stream::Stream` e `futures::sink::Sink`
//! esperadas pelo `rmcp::ServiceExt::serve_with_ct`, utilizando os tipos de mensagem
//! `ClientJsonRpcMessage` e `ServerJsonRpcMessage` do RMCP.

use axum::extract::ws::{Message as AxumMessage, WebSocket};
use futures_util::{
    sink::Sink,
    stream::{Stream},
    // SinkExt as FuturesSinkExt, // Removido, métodos de SinkExt são geralmente acessados via trait
};
use pin_project_lite::pin_project;
use rmcp::model::{ClientJsonRpcMessage, ServerJsonRpcMessage};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

pin_project! {
    /// Um adaptador de transporte que envolve um `axum::extract::ws::WebSocket` para
    /// implementar as traits `Stream` e `Sink` para mensagens MCP.
    #[derive(Debug)]
    pub struct WebSocketTransport {
        #[pin]
        ws_socket: WebSocket,
    }
}

impl WebSocketTransport {
    /// Cria um novo `WebSocketTransport` a partir de um `axum::extract::ws::WebSocket`.
    #[allow(clippy::missing_const_for_fn)]
    pub fn new(ws_socket: WebSocket) -> Self {
        Self { ws_socket }
    }
}

impl Stream for WebSocketTransport {
    type Item = ClientJsonRpcMessage; // Corrigido

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        loop {
            match Stream::poll_next(this.ws_socket.as_mut(), cx) {
                Poll::Ready(Some(Ok(axum_message))) => {
                    match axum_message {
                        AxumMessage::Text(ref text_bytes) => {
                            if let Some(msg) = Self::handle_text(text_bytes) {
                                return Poll::Ready(Some(msg));
                            }
                            // Se inválido, continua o loop
                        }
                        AxumMessage::Binary(ref bin) => {
                            Self::handle_binary(bin);
                        }
                        AxumMessage::Ping(ref ping_data) => {
                            Self::handle_ping(ping_data);
                        }
                        AxumMessage::Pong(_) => {
                            Self::handle_pong();
                        }
                        AxumMessage::Close(ref close_frame) => {
                            return Self::handle_close(close_frame.as_ref());
                        }
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    tracing::error!("WebSocketTransport: Erro no stream WebSocket: {}. Encerrando stream.", e);
                    return Poll::Ready(None);
                }
                Poll::Ready(None) => {
                    tracing::debug!("WebSocketTransport: Stream WebSocket encerrado pelo peer. Encerrando stream.");
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl WebSocketTransport {
    fn handle_text(text_bytes: &axum::extract::ws::Utf8Bytes) -> Option<ClientJsonRpcMessage> {
        let text = text_bytes.as_str();
        tracing::trace!("WebSocketTransport: Recebido frame Text de {} bytes.", text.len());
        match serde_json::from_str::<ClientJsonRpcMessage>(text) {
            Ok(mcp_message) => Some(mcp_message),
            Err(e) => {
                tracing::warn!(
                    "WebSocketTransport: Falha ao desserializar ClientJsonRpcMessage: {}. Payload: '{}'. Mensagem ignorada.",
                    e,
                    text
                );
                None
            }
        }
    }

    fn handle_binary(bin: &bytes::Bytes) {
        tracing::warn!("WebSocketTransport: Recebido frame Binary ({} bytes), que não é suportado e será ignorado.", bin.len());
    }

    fn handle_ping(_ping_data: &bytes::Bytes) {
        tracing::trace!("WebSocketTransport: Recebido Ping WebSocket.");
    }

    fn handle_pong() {
        tracing::trace!("WebSocketTransport: Recebido Pong WebSocket.");
    }

    fn handle_close(close_frame: Option<&axum::extract::ws::CloseFrame>) -> Poll<Option<ClientJsonRpcMessage>> {
        tracing::debug!("WebSocketTransport: Recebido frame Close WebSocket do peer: {:?}. Encerrando stream.", close_frame);
        Poll::Ready(None)
    }
}

impl Sink<ServerJsonRpcMessage> for WebSocketTransport {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project()
            .ws_socket
            .poll_ready(cx) // Este método vem da trait Sink implementada para WebSocket
            .map_err(|e| {
                tracing::warn!(error.message = %e, "Erro em poll_ready do WebSocket Sink.");
                io::Error::new(io::ErrorKind::ConnectionAborted, e.to_string())
            })
    }

    fn start_send(self: Pin<&mut Self>, item: ServerJsonRpcMessage) -> Result<(), Self::Error> {
        tracing::debug!("WebSocketTransport: Preparando para enviar ServerJsonRpcMessage...");
        match serde_json::to_string(&item) {
            Ok(text_payload) => {
                // AxumMessage::Text espera Utf8Bytes
                let utf8_bytes = axum::extract::ws::Utf8Bytes::from(text_payload.as_str());
                self.project()
                    .ws_socket
                    .start_send(AxumMessage::Text(utf8_bytes))
                    .map_err(|e| {
                        tracing::warn!(error.message = %e, "Erro ao iniciar envio no WebSocket Sink.");
                        io::Error::new(io::ErrorKind::BrokenPipe, e.to_string())
                    })
            }
            Err(e) => {
                tracing::error!("WebSocketTransport: Falha ao serializar ServerJsonRpcMessage para JSON: {}", e);
                Err(io::Error::new(io::ErrorKind::InvalidInput, format!("Falha ao serializar JSON-RPC para envio: {e}")))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project()
            .ws_socket
            .poll_flush(cx) // Este método vem da trait Sink
            .map_err(|e| {
                tracing::warn!(error.message = %e, "Erro em poll_flush do WebSocket Sink.");
                io::Error::new(io::ErrorKind::BrokenPipe, e.to_string())
            })
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project()
            .ws_socket
            .poll_close(cx) // Este método vem da trait Sink
            .map_err(|e| {
                tracing::warn!(error.message = %e, "Erro em poll_close do WebSocket Sink.");
                io::Error::new(io::ErrorKind::ConnectionReset, e.to_string())
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        extract::{ws::WebSocketUpgrade, State as AxumState},
        response::IntoResponse as AxumIntoResponse,
        routing::get,
        Router,
    };
    use futures_util::SinkExt; // Manter para os testes, para chamar os métodos no client_socket
    use bytes::Bytes;
    use tokio_tungstenite::tungstenite::protocol::frame::Utf8Bytes;
    use futures_util::stream::StreamExt as FuturesStreamExt;
    use rmcp::model::{JsonRpcNotification, NotificationNoParam, InitializedNotificationMethod};
    use tokio::net::TcpListener;
    use tokio_tungstenite::{connect_async, tungstenite::Message as TungsteniteMessage};

    async fn test_ws_handler(
        ws: WebSocketUpgrade,
        AxumState(sender): AxumState<tokio::sync::mpsc::Sender<WebSocket>>,
    ) -> impl AxumIntoResponse {
        ws.on_upgrade(move |socket| async move {
            if sender.send(socket).await.is_err(){
                 tracing::error!("Falha ao enviar socket WebSocket para o canal de teste.");
            }
        })
    }

    async fn connected_pair() -> (
        WebSocketTransport,
        tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    ) {
        let (socket_tx, mut socket_rx) = tokio::sync::mpsc::channel::<WebSocket>(1);
        let app = Router::new().route("/ws_test", get(test_ws_handler)).with_state(socket_tx);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app.into_make_service()).await.unwrap(); });
        let client_uri = format!("ws://{addr}/ws_test");
        let (client_socket, _) = connect_async(&client_uri).await.expect("Falha ao conectar cliente WebSocket de teste");
        let server_ws_from_handler = socket_rx.recv().await.expect("Servidor de teste não recebeu o WebSocket do handler Axum");
        (WebSocketTransport::new(server_ws_from_handler), client_socket)
    }

    #[tokio::test]
    async fn test_websocket_transport_sends_server_message_and_receives_client_message() {
        let (mut transport_server_side, mut client_socket) = connected_pair().await;

        let server_msg_payload = rmcp::model::ServerNotification::ToolListChangedNotification(
            NotificationNoParam { method: rmcp::model::ToolListChangedNotificationMethod, extensions: Default::default() }
        );
        let server_msg = ServerJsonRpcMessage::Notification(JsonRpcNotification {
            jsonrpc: rmcp::model::JsonRpcVersion2_0,
            notification: server_msg_payload,
        });

        // Usar SinkExt::send para o transport_server_side
        transport_server_side.send(server_msg.clone()).await.expect("Envio do servidor falhou");

        match FuturesStreamExt::next(&mut client_socket).await {
            Some(Ok(TungsteniteMessage::Text(text_bytes))) => {
                let text = text_bytes;
                let received_msg_on_client: ServerJsonRpcMessage = serde_json::from_str(&text).expect("Cliente falhou ao desserializar mensagem do servidor");
                assert_eq!(serde_json::to_string(&received_msg_on_client).unwrap(), serde_json::to_string(&server_msg).unwrap());
            }
            other => panic!("Cliente não recebeu mensagem de texto ou recebeu tipo de frame inesperado: {other:?}"),
        }

        let client_msg_payload = rmcp::model::ClientNotification::InitializedNotification(
            NotificationNoParam { method: InitializedNotificationMethod, extensions: Default::default() }
        );
        let client_rpc_msg = ClientJsonRpcMessage::Notification(JsonRpcNotification {
            jsonrpc: rmcp::model::JsonRpcVersion2_0,
            notification: client_msg_payload,
        });
        let client_msg_str = serde_json::to_string(&client_rpc_msg).unwrap();
        
        // Usar SinkExt::send para o client_socket (que é um WebSocketStream de tokio-tungstenite)
        client_socket.send(TungsteniteMessage::Text(Utf8Bytes::from(client_msg_str.as_str()))).await.expect("Envio do cliente falhou");

        match FuturesStreamExt::next(&mut transport_server_side).await {
            Some(received_on_server) => {
                 assert_eq!(serde_json::to_string(&received_on_server).unwrap(), serde_json::to_string(&client_rpc_msg).unwrap());
            }
            other => panic!("Servidor não recebeu mensagem de texto ou stream terminou prematuramente: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_websocket_transport_handles_client_close() {
        let (mut transport_server_side, mut client_socket) = connected_pair().await;
        client_socket.close(None).await.expect("Cliente falhou ao fechar conexão");
        assert!(FuturesStreamExt::next(&mut transport_server_side).await.is_none(), "Stream do servidor deveria terminar após o cliente fechar");
    }

    #[tokio::test]
    async fn test_websocket_transport_handles_server_initiated_close() {
        let (mut transport_server_side, mut client_socket) = connected_pair().await;
        transport_server_side.close().await.expect("Servidor falhou ao fechar o Sink do transporte");
        
        match FuturesStreamExt::next(&mut client_socket).await {
            Some(Ok(TungsteniteMessage::Close(_))) => { /* esperado */ }
            other => panic!("Cliente não recebeu frame de Close, obteve: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_websocket_transport_ignores_invalid_json_from_client_and_continues() {
        let (mut transport_server_side, mut client_socket) = connected_pair().await;
        
        let invalid_json = "{\"jsonrpc\": \"2.0\", \"method\": \"foo\", \"params\": {"; 
        client_socket.send(TungsteniteMessage::Text(Utf8Bytes::from(invalid_json))).await.expect("Envio do cliente (JSON inválido) falhou");
        
        let client_msg_payload = rmcp::model::ClientNotification::InitializedNotification(
            NotificationNoParam { method: InitializedNotificationMethod, extensions: Default::default() }
        );
        let client_rpc_msg_valid = ClientJsonRpcMessage::Notification(JsonRpcNotification {
            jsonrpc: rmcp::model::JsonRpcVersion2_0,
            notification: client_msg_payload,
        });
        let client_msg_str_valid = serde_json::to_string(&client_rpc_msg_valid).unwrap();
        client_socket.send(TungsteniteMessage::Text(Utf8Bytes::from(client_msg_str_valid.as_str()))).await.expect("Envio do cliente (JSON válido) falhou");

        match FuturesStreamExt::next(&mut transport_server_side).await {
            Some(received_on_server) => {
                 assert_eq!(serde_json::to_string(&received_on_server).unwrap(), client_msg_str_valid);
            }
            other => panic!("Esperava uma mensagem válida após JSON inválido, obteve {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_websocket_transport_ignores_binary_message_from_client() {
        let (mut transport_server_side, mut client_socket) = connected_pair().await;
        
        client_socket.send(TungsteniteMessage::Binary(Bytes::from(vec![1u8,2u8,3u8]))).await.expect("Envio binário do cliente falhou");
        
        let client_msg_payload = rmcp::model::ClientNotification::InitializedNotification(
            NotificationNoParam { method: InitializedNotificationMethod, extensions: Default::default() }
        );
        let client_rpc_msg_valid = ClientJsonRpcMessage::Notification(JsonRpcNotification {
            jsonrpc: rmcp::model::JsonRpcVersion2_0,
            notification: client_msg_payload,
        });
        let client_msg_str_valid = serde_json::to_string(&client_rpc_msg_valid).unwrap();
        client_socket.send(TungsteniteMessage::Text(Utf8Bytes::from(client_msg_str_valid.as_str()))).await.expect("Envio de texto do cliente falhou");

        match FuturesStreamExt::next(&mut transport_server_side).await {
            Some(received_on_server) => {
                 assert_eq!(serde_json::to_string(&received_on_server).unwrap(), client_msg_str_valid);
            }
            other => panic!("Esperava uma mensagem de texto válida após mensagem binária, obteve {other:?}"),
        }
    }
}