// tests/integration/resilience_tests.rs
// Testes de integração de resiliência e tolerância a falhas do Typedb-MCP-Server.
// Copyright 2025 Guilherme Leste
// Licença Apache 2.0

//! Testes de resiliência e tolerância a falhas do Typedb-MCP-Server.
//! Este arquivo cobre cenários de rate limiting, timeouts, graceful shutdown e falhas de dependências.

use std::time::Duration;
use reqwest::StatusCode;
use tests::common::docker_helpers::DockerComposeEnv;
use tokio_tungstenite::connect_async;
use futures_util::{SinkExt, StreamExt};
use serde_json::json;

const DOCKER_COMPOSE_FILE: &str = "docker-compose.test.yml";
const PROJECT_PREFIX: &str = "resilience";
const MCP_HTTP_PORT: u16 = 8788;
const MCP_METRICS_PORT: u16 = 9090;
const MCP_SERVER_SERVICE: &str = "typedb-mcp-server-it";
const TYPEDB_SERVICE: &str = "typedb-server-it";
const MOCK_AUTH_SERVICE: &str = "mock-auth-server-it";

fn mcp_base_url() -> String {
    format!("http://localhost:{}", MCP_HTTP_PORT)
}
fn mcp_metrics_url() -> String {
    format!("http://localhost:{}/metrics", MCP_METRICS_PORT)
}

async fn setup_env_with_envs(envs: Option<&[(&str, &str)]>) -> DockerComposeEnv {
    let env = DockerComposeEnv::new(DOCKER_COMPOSE_FILE, PROJECT_PREFIX);
    env.down(false).ok();
    if let Some(env_vars) = envs {
        let mut cmd_env: Vec<(&str, &str)> = env_vars.to_vec();
        env.run_command_with_env(&["up", "-d", "--build", "--remove-orphans"], &cmd_env).expect("Falha ao subir ambiente docker-compose com envs");
    } else {
        env.up().expect("Falha ao subir ambiente docker-compose");
    }
    env.wait_for_service_healthy(TYPEDB_SERVICE, Duration::from_secs(60), Duration::from_secs(2)).await.expect("TypeDB não saudável");
    env.wait_for_service_healthy(MCP_SERVER_SERVICE, Duration::from_secs(60), Duration::from_secs(2)).await.expect("MCP Server não saudável");
    env
}

async fn setup_env() -> DockerComposeEnv {
    setup_env_with_envs(None).await
}

async fn stop_service(env: &DockerComposeEnv, service: &str) {
    let _ = env.run_command(&["stop", service]);
}

async fn pause_service(env: &DockerComposeEnv, service: &str) {
    let _ = env.run_command(&["pause", service]);
}

async fn unpause_service(env: &DockerComposeEnv, service: &str) {
    let _ = env.run_command(&["unpause", service]);
}

#[tokio::test]
async fn test_rate_limiting_rejects_excessive_connections() {
    let _env = setup_env().await;
    let ws_url = format!("ws://localhost:{}/mcp", MCP_HTTP_PORT);
    let max_connections = 10; // Ajuste conforme configuração real do servidor
    let mut clients = vec![];
    for _ in 0..max_connections {
        let conn = connect_async(&ws_url).await;
        assert!(conn.is_ok(), "Conexão WebSocket dentro do limite deveria ser aceita");
        clients.push(conn.unwrap());
    }
    // Próxima conexão deve ser rejeitada (rate limit)
    let conn = connect_async(&ws_url).await;
    assert!(conn.is_err(), "Conexão WebSocket excedente deveria ser rejeitada por rate limiting");
}

#[tokio::test]
async fn test_websocket_inactive_client_is_disconnected() {
    let _env = setup_env().await;
    let ws_url = format!("ws://localhost:{}/mcp", MCP_HTTP_PORT);
    let (mut ws_stream, _) = connect_async(&ws_url).await.expect("Falha ao conectar WebSocket");
    // Não envia nada, apenas espera pelo timeout de inatividade
    let timeout = Duration::from_secs(65); // Ajuste conforme configuração do servidor
    let mut disconnected = false;
    let mut stream = ws_stream.next();
    tokio::select! {
        _ = tokio::time::sleep(timeout) => {
            // Timeout atingido, conexão não foi fechada
        }
        msg = &mut stream => {
            if msg.is_none() {
                disconnected = true;
            }
        }
    }
    assert!(disconnected, "Conexão WebSocket inativa não foi desconectada após timeout");
}

#[tokio::test]
async fn test_graceful_shutdown_allows_in_flight_requests_to_complete() {
    let env = setup_env().await;
    let ws_url = format!("ws://localhost:{}/mcp", MCP_HTTP_PORT);
    let (mut ws_stream, _) = connect_async(&ws_url).await.expect("Falha ao conectar WebSocket");
    // Envia uma operação MCP longa (simulada)
    let long_op = json!({"op": "long_running", "duration_ms": 30000});
    ws_stream.send(tokio_tungstenite::tungstenite::Message::Text(long_op.to_string())).await.expect("Falha ao enviar operação longa");
    // Envia sinal de término ao servidor
    let _ = env.run_command(&["kill", "-s", "SIGTERM", MCP_SERVER_SERVICE]);
    // Espera resposta ou fechamento
    let mut completed = false;
    let mut stream = ws_stream.next();
    tokio::select! {
        msg = &mut stream => {
            if let Some(Ok(tokio_tungstenite::tungstenite::Message::Text(txt))) = msg {
                if txt.contains("completed") {
                    completed = true;
                }
            }
        }
        _ = tokio::time::sleep(Duration::from_secs(35)) => {}
    }
    assert!(completed, "Operação em andamento não foi concluída durante graceful shutdown");
}

#[tokio::test]
async fn test_server_recovers_after_typedb_temporary_outage() {
    let env = setup_env().await;
    let ws_url = format!("ws://localhost:{}/mcp", MCP_HTTP_PORT);
    let (mut ws_stream, _) = connect_async(&ws_url).await.expect("Falha ao conectar WebSocket");
    // Envia uma operação MCP que depende do TypeDB
    let op = json!({"op": "query_read", "query": "match $x isa thing; limit 1;"});
    ws_stream.send(tokio_tungstenite::tungstenite::Message::Text(op.to_string())).await.expect("Falha ao enviar query");
    // Pausa o TypeDB
    pause_service(&env, TYPEDB_SERVICE).await;
    // Espera resposta de erro
    let mut errored = false;
    let mut stream = ws_stream.next();
    tokio::select! {
        msg = &mut stream => {
            if let Some(Ok(tokio_tungstenite::tungstenite::Message::Text(txt))) = msg {
                if txt.contains("error") {
                    errored = true;
                }
            }
        }
        _ = tokio::time::sleep(Duration::from_secs(10)) => {}
    }
    assert!(errored, "Operação MCP não falhou após TypeDB ficar indisponível");
    // Verifica /readyz
    let readyz = reqwest::get(&format!("{}/readyz", mcp_base_url())).await.expect("Falha na requisição /readyz");
    let body = readyz.text().await.expect("Falha ao ler corpo /readyz");
    assert!(body.contains("DOWN") || body.contains("down"), "/readyz deveria indicar DOWN");
    // Retoma o TypeDB
    unpause_service(&env, TYPEDB_SERVICE).await;
    // Aguarda recuperação
    tokio::time::sleep(Duration::from_secs(10)).await;
    let readyz = reqwest::get(&format!("{}/readyz", mcp_base_url())).await.expect("Falha na requisição /readyz após recovery");
    let body = readyz.text().await.expect("Falha ao ler corpo /readyz após recovery");
    assert!(body.contains("UP") || body.contains("up"), "/readyz deveria indicar UP após recovery");
}

// Testes adicionais para JWKS, shutdown imediato e panics podem ser implementados conforme suporte do ambiente de teste.

// --- JWKS e Shutdown Imediato ---

/// Testa resiliência do servidor MCP ao perder o JWKS (Mock Authorization Server) durante operação.
/// Requer helpers para manipular JWKS e autenticação de tokens.
#[tokio::test]
#[ignore = "Depende de helpers/mocks para JWKS e autenticação de tokens"]
async fn test_server_handles_jwks_outage_using_cached_keys() {
    // TODO: Implementar quando helpers de autenticação e manipulação de JWKS estiverem disponíveis.
    // 1. Sobe ambiente com OAuth e JWKS ativo.
    // 2. Autentica cliente MCP com token válido (chave no cache).
    // 3. Para o mock-auth-server-it.
    // 4. Tenta autenticar novamente com token cacheado (deve funcionar).
    // 5. Tenta autenticar com token novo (kid não cacheado, deve falhar).
    // 6. Reinicia mock-auth-server-it, verifica recuperação.
    unimplemented!("Implementar quando helpers JWKS estiverem disponíveis");
}

/// Testa shutdown imediato do servidor MCP (força encerramento após timeout de graceful shutdown).
/// Requer helper para obter código de saída do processo/container.
#[tokio::test]
async fn test_graceful_shutdown_forces_exit_after_timeout() {
    // 1. Sobe ambiente e inicia operação longa
    let env = setup_env().await;
    let ws_url = format!("ws://localhost:{}/mcp", MCP_HTTP_PORT);
    let (mut ws_stream, _) = connect_async(&ws_url).await.expect("Falha ao conectar WebSocket");
    let long_op = json!({"op": "long_running", "duration_ms": 60000});
    ws_stream.send(tokio_tungstenite::tungstenite::Message::Text(long_op.to_string())).await.expect("Falha ao enviar operação longa");

    // 2. Envia SIGTERM para iniciar graceful shutdown
    let _ = env.run_command(&["kill", "-s", "SIGTERM", MCP_SERVER_SERVICE]);
    // Aguarda tempo menor que o timeout de graceful shutdown (simula operação pendente)
    tokio::time::sleep(Duration::from_secs(5)).await;

    // 3. Envia SIGKILL para forçar encerramento imediato
    let _ = env.run_command(&["kill", "-s", "SIGKILL", MCP_SERVER_SERVICE]);

    // Aguarda o container realmente parar
    let mut tentativas = 0;
    let exit_code = loop {
        match env.get_service_exit_code(MCP_SERVER_SERVICE) {
            Ok(code) => break code,
            Err(_) if tentativas < 10 => {
                tokio::time::sleep(Duration::from_secs(1)).await;
                tentativas += 1;
            }
            Err(e) => panic!("Falha ao obter exit code do serviço: {:?}", e),
        }
    };

    // 4. Verifica que o código de saída é diferente de zero (encerramento forçado)
    assert_ne!(exit_code, 0, "Código de saída deveria ser diferente de zero após SIGKILL (foi {})", exit_code);

    // Opcional: inspeciona logs para garantir que shutdown forçado foi registrado
    let logs = env.get_service_logs(MCP_SERVER_SERVICE).unwrap_or_else(|_| String::from("[Logs indisponíveis]"));
    assert!(logs.contains("SIGKILL") || logs.contains("killed") || logs.contains("forçado"),
        "Logs não indicam shutdown forçado. Logs:\n{}", logs);
}

/// Refina asserts para logs e códigos de saída do processo, se helpers estiverem disponíveis.
/// Exemplo de uso condicional:
fn assert_logs_contain(env: &DockerComposeEnv, service: &str, expected: &str) {
    // Se helper de logs existir, faz assert; senão, loga aviso.
    #[allow(unused_variables)]
    {
        // if let Some(logs) = env.get_logs(service) {
        //     assert!(logs.contains(expected), "Logs do serviço {} não contêm '{}':\n{}", service, expected, logs);
        // } else {
        //     eprintln!("[AVISO] Helper de logs não disponível, assert ignorado.");
        // }
    }
}

fn assert_exit_code(env: &DockerComposeEnv, service: &str, expected: i32) {
    #[allow(unused_variables)]
    {
        // if let Some(code) = env.get_exit_code(service) {
        //     assert_eq!(code, expected, "Código de saída inesperado para {}: {}", service, code);
        // } else {
        //     eprintln!("[AVISO] Helper de exit code não disponível, assert ignorado.");
        // }
    }
}
