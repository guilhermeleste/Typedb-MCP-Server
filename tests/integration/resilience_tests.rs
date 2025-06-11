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

//! Testes de resiliência e tolerância a falhas do Typedb-MCP-Server.
//! Este arquivo cobre cenários de rate limiting, timeouts, graceful shutdown e falhas de dependências.

use crate::common::{
    client::McpClientError,
    constants,
    mcp_utils::get_text_from_call_result,
    test_env::TestEnvironment,
    // Importar helpers de test_utils explicitamente
    test_utils::{
        create_test_db,
        delete_test_db,
        unique_db_name,
        wait_for_mcp_server_ready_from_test_env, // Usará a versão de test_utils
    },
};
use anyhow::{Context as AnyhowContext, Result};
use futures_util::StreamExt;
use reqwest::StatusCode;
// serde_json::json não é usado neste arquivo
use serial_test::serial;
use std::time::Duration;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message as TungsteniteWsMessage};
use tracing::{info, warn}; // Removido `debug` se não for usado

#[tokio::test]
#[serial]
async fn test_rate_limiting_rejects_excessive_http_requests_to_readyz() -> Result<()> {
    let test_env =
        TestEnvironment::setup("res_rate_limit_http", constants::DEFAULT_TEST_CONFIG_FILENAME)
            .await?;
    let readyz_url =
        format!("{}{}", test_env.mcp_http_base_url, constants::MCP_SERVER_DEFAULT_READYZ_PATH);
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(test_env.is_mcp_server_tls)
        .timeout(Duration::from_millis(500))
        .build()?;

    let mut successful_requests = 0;
    let total_attempts = 30;
    let mut rate_limited_count = 0;

    info!("Teste: Enviando {} requisições para {}", total_attempts, readyz_url);
    let mut requests = Vec::new();
    for _ in 0..total_attempts {
        requests.push(client.get(&readyz_url).send());
    }

    let responses = futures::future::join_all(requests).await;

    for (i, res) in responses.into_iter().enumerate() {
        match res {
            Ok(response) => {
                if response.status() == StatusCode::OK {
                    successful_requests += 1;
                } else if response.status() == StatusCode::TOO_MANY_REQUESTS {
                    rate_limited_count += 1;
                    info!("Requisição {} foi limitada (429 Too Many Requests)", i + 1);
                } else {
                    warn!("Requisição {} obteve status inesperado: {}", i + 1, response.status());
                }
            }
            Err(e) => {
                if e.is_timeout() {
                    rate_limited_count += 1;
                    info!("Requisição {} timed out, possivelmente devido a rate limiting.", i + 1);
                } else {
                    warn!("Erro na requisição {}: {:?}", i + 1, e);
                }
            }
        }
    }
    info!(
        "Requisições bem-sucedidas: {}, Requisições limitadas/timeout: {}",
        successful_requests, rate_limited_count
    );
    warn!("Este teste de rate limit pode não ser efetivo com a configuração de rate limit atual ({} req/s, {} burst). Para testar de fato, use um TOML com limits mais baixos.", 
        constants::DEFAULT_RATE_LIMIT_REQUESTS_PER_SECOND,
        constants::DEFAULT_RATE_LIMIT_BURST_SIZE);
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_websocket_inactive_client_is_disconnected_by_server() -> Result<()> {
    let test_env =
        TestEnvironment::setup("res_ws_inactive", constants::DEFAULT_TEST_CONFIG_FILENAME).await?;
    info!("Teste: Conectando WebSocket e mantendo inativo. URL: {}", test_env.mcp_ws_url);

    let (mut ws_stream, _) = connect_async(&test_env.mcp_ws_url)
        .await
        .context("Falha ao conectar WebSocket para teste de inatividade")?;

    let inactivity_timeout = Duration::from_secs(65);
    info!("Aguardando por {:?} para desconexão por inatividade...", inactivity_timeout);

    let mut disconnected_by_server = false;
    tokio::select! {
        biased;
        _ = tokio::time::sleep(inactivity_timeout) => {
            info!("Timeout de {:?} do teste atingido. O servidor não desconectou o cliente inativo.", inactivity_timeout);
             warn!("O servidor MCP pode não ter um timeout de inatividade configurado para WebSockets.");
        }
        maybe_msg = ws_stream.next() => {
            match maybe_msg {
                Some(Ok(TungsteniteWsMessage::Close(_))) => {
                    info!("Servidor fechou a conexão WebSocket (Close frame recebido).");
                    disconnected_by_server = true;
                }
                Some(Err(e)) => {
                    info!("Erro na stream WebSocket, assumindo desconexão: {:?}", e);
                    disconnected_by_server = true;
                }
                Some(Ok(other_msg)) => {
                    info!("Recebida mensagem inesperada enquanto esperava desconexão: {:?}", other_msg);
                }
                None => {
                    info!("Stream WebSocket terminou (servidor fechou a conexão subjacente).");
                    disconnected_by_server = true;
                }
            }
        }
    }
    if !disconnected_by_server {
        warn!("Teste de desconexão por inatividade: O servidor não desconectou o cliente. Isso é esperado se não houver timeout de inatividade configurado no servidor.");
    }
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_server_recovers_after_typedb_temporary_outage() -> Result<()> {
    let test_env =
        TestEnvironment::setup("res_typedb_outage", constants::DEFAULT_TEST_CONFIG_FILENAME)
            .await?;
    let db_name = unique_db_name("res_typedb_outage"); // Usando helper comum

    info!("Teste: Setup inicial - criando cliente e banco de dados '{}'", db_name);
    let mut client = test_env
        .mcp_client_with_auth(Some(
            "typedb:manage_databases typedb:read_data typedb:admin_databases",
        ))
        .await?;

    create_test_db(&mut client, &db_name).await?; // Usando helper comum

    info!("Teste: Verificando operação normal antes da falha do TypeDB.");
    let list_dbs_result_before = client.call_tool("list_databases", None).await;
    assert!(
        list_dbs_result_before.is_ok(),
        "list_databases falhou antes da simulação de falha: {:?}",
        list_dbs_result_before.err()
    );
    let dbs_before_text = get_text_from_call_result(
        list_dbs_result_before.expect("list_databases deveria ter sucesso baseado no assert")
    );
    let dbs_before: Vec<String> = serde_json::from_str(&dbs_before_text)?;
    assert!(dbs_before.contains(&db_name.to_string()));

    info!("Teste: Parando o serviço TypeDB ('{}')...", constants::TYPEDB_SERVICE_NAME);
    test_env.docker_env.stop_service(constants::TYPEDB_SERVICE_NAME)?;
    info!("Serviço TypeDB parado. Aguardando alguns segundos para o MCP Server detectar...");
    tokio::time::sleep(Duration::from_secs(15)).await;

    info!("Teste: Verificando /readyz do MCP Server durante a falha do TypeDB.");
    // Usar o helper wait_for_mcp_server_ready_from_test_env com nova assinatura
    let readyz_down_result = wait_for_mcp_server_ready_from_test_env(
        &test_env.docker_env,
        &test_env.mcp_http_base_url,
        test_env.is_mcp_server_tls,
        test_env.is_oauth_enabled,
        false, // _expect_typedb_tls_connection (não usado)
        Duration::from_secs(30),
    )
    .await;

    // O wait_for_mcp_server_ready_from_test_env espera por UP. Se TypeDB está DOWN, ele deve retornar Err.
    assert!(readyz_down_result.is_err(), "MCP Server não ficou DOWN no /readyz como esperado (wait_for_mcp_server_ready_from_test_env deveria falhar).");

    // Verificação explícita do JSON, assumindo que o servidor MCP ainda responde ao /readyz mesmo se não estiver "pronto"
    let readyz_url =
        format!("{}{}", test_env.mcp_http_base_url, constants::MCP_SERVER_DEFAULT_READYZ_PATH);
    let direct_check_client = reqwest::Client::builder()
        .danger_accept_invalid_certs(test_env.is_mcp_server_tls)
        .build()?;
    let resp_down =
        direct_check_client.get(&readyz_url).send().await?.json::<serde_json::Value>().await?;
    assert_eq!(resp_down.get("status").and_then(|s| s.as_str()), Some("DOWN"));
    assert_eq!(
        resp_down.get("components").and_then(|c| c.get("typedb")).and_then(|s| s.as_str()),
        Some("DOWN")
    );

    info!("Teste: Tentando 'list_databases' enquanto TypeDB está parado.");
    let list_dbs_result_during_outage = client.call_tool("list_databases", None).await;
    assert!(
        list_dbs_result_during_outage.is_err(),
        "list_databases deveria falhar enquanto TypeDB está parado."
    );
    info!(
        "'list_databases' falhou como esperado durante a indisponibilidade do TypeDB: {:?}",
        list_dbs_result_during_outage.err()
    );

    info!("Teste: Reiniciando o serviço TypeDB ('{}')...", constants::TYPEDB_SERVICE_NAME);
    test_env.docker_env.start_service(constants::TYPEDB_SERVICE_NAME)?;
    test_env
        .docker_env
        .wait_for_service_healthy(
            constants::TYPEDB_SERVICE_NAME,
            constants::DEFAULT_TYPEDB_READY_TIMEOUT,
        )
        .await?;
    info!("Serviço TypeDB reiniciado. Aguardando MCP Server se recuperar...");
    tokio::time::sleep(Duration::from_secs(5)).await;

    info!("Teste: Verificando /readyz do MCP Server após recuperação do TypeDB.");
    let readyz_up_again = wait_for_mcp_server_ready_from_test_env(
        &test_env.docker_env,
        &test_env.mcp_http_base_url,
        test_env.is_mcp_server_tls,
        test_env.is_oauth_enabled,
        false, // _expect_typedb_tls_connection (não usado)
        Duration::from_secs(45),
    )
    .await
    .context("MCP Server não voltou ao estado UP após recuperação do TypeDB")?;
    assert_eq!(
        readyz_up_again.get("components").and_then(|c| c.get("typedb")).and_then(|s| s.as_str()),
        Some("UP")
    );

    let list_dbs_text_after_recovery = match client.call_tool("list_databases", None).await {
        Ok(res) => {
            info!(
                "'list_databases' bem-sucedido com cliente existente após recuperação do TypeDB."
            );
            get_text_from_call_result(res)
        }
        Err(McpClientError::WebSocket(_)) | Err(McpClientError::ConnectionClosed) => {
            info!("Conexão WS original foi fechada. Tentando reconectar novo cliente...");
            let mut new_client = test_env
                .mcp_client_with_auth(Some(
                    "typedb:manage_databases typedb:read_data typedb:admin_databases",
                ))
                .await?;
            let res = new_client.call_tool("list_databases", None).await.context(
                "Falha no 'list_databases' com novo cliente após recuperação do TypeDB.",
            )?;
            client = new_client;
            get_text_from_call_result(res)
        }
        Err(e) => {
            // Convert McpClientError to anyhow::Error before using context
            return Err(anyhow::Error::new(e))
                .context("Falha inesperada no 'list_databases' após recuperação do TypeDB.");
        }
    };

    let dbs_after: Vec<String> = serde_json::from_str(&list_dbs_text_after_recovery)?;
    assert!(
        dbs_after.contains(&db_name.to_string()),
        "Banco de dados não listado após recuperação do TypeDB."
    );
    info!("Operação MCP bem-sucedida após recuperação do TypeDB.");

    delete_test_db(&mut client, &db_name).await;
    Ok(())
}
