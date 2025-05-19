// tests/integration/resilience_tests.rs
// Testes de integração de resiliência e tolerância a falhas do Typedb-MCP-Server.
// Copyright 2025 Guilherme Leste
// Licença Apache 2.0

//! Testes de resiliência e tolerância a falhas do Typedb-MCP-Server.
//! Este arquivo cobre cenários de rate limiting, timeouts, graceful shutdown e falhas de dependências.

use std::time::Duration;
use reqwest::StatusCode;
// Ajustado para usar o caminho correto para DockerComposeEnv e Result
use crate::common::docker_helpers::DockerComposeEnv;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::protocol::frame::Utf8Bytes;
use futures_util::{SinkExt, StreamExt};
use serde_json::json;

const DOCKER_COMPOSE_FILE: &str = "docker-compose.test.yml";
const PROJECT_PREFIX: &str = "resilience";
const MCP_HTTP_PORT: u16 = 8788; // Assumindo que o MCP Server está exposto nesta porta no host
const MCP_METRICS_PORT: u16 = 9090; // Assumindo que as métricas estão expostas nesta porta no host
const MCP_SERVER_SERVICE: &str = "typedb-mcp-server-it";
const TYPEDB_SERVICE: &str = "typedb-server-it";
// Removido: const MOCK_AUTH_SERVICE: &str = "mock-auth-server-it"; // Não usado diretamente aqui

fn mcp_base_url() -> String {
    format!("http://localhost:{}", MCP_HTTP_PORT)
}

// Removido: fn mcp_metrics_url() -> String { ... } // Não usado nos testes atuais

// A função setup_env_with_envs e as funções de controle de serviço (stop, pause, unpause)
// dependem de métodos em DockerComposeEnv que não existem no placeholder atual
// (run_command_with_env, run_command). Estes testes precisarão ser adaptados
// ou a implementação de DockerComposeEnv precisará ser expandida.
// Por agora, vamos focar nos testes que podem funcionar com o DockerComposeEnv atual.

async fn setup_env() -> DockerComposeEnv {
    let env = DockerComposeEnv::new(DOCKER_COMPOSE_FILE, PROJECT_PREFIX);
    env.down(true).expect("Falha ao derrubar ambiente docker-compose pré-existente");
    env.up().expect("Falha ao subir ambiente docker-compose");
    env.wait_for_service_healthy(TYPEDB_SERVICE, Duration::from_secs(60))
        .await
        .expect("TypeDB não saudável");
    env.wait_for_service_healthy(MCP_SERVER_SERVICE, Duration::from_secs(60))
        .await
        .expect("MCP Server não saudável");
    env
}

// As funções `pause_service` e `unpause_service` precisam ser implementadas em `DockerComposeEnv`
// ou os testes que as utilizam precisam ser adaptados.
// Para o placeholder, vamos assumir que estas operações não são suportadas diretamente
// e os testes que dependem delas serão marcados como `#[ignore]` ou simplificados.

#[tokio::test]
#[serial_test::serial] // Adicionado para consistência
async fn test_rate_limiting_rejects_excessive_connections() {
    let docker_env = setup_env().await;
    let ws_url = format!("ws://localhost:{}/mcp/ws", MCP_HTTP_PORT); // Corrigido para /mcp/ws
    let max_connections = 10; // Ajuste conforme configuração real do servidor
    let mut clients = vec![];
    for i in 0..max_connections {
        match connect_async(&ws_url).await {
            Ok(conn_tuple) => clients.push(conn_tuple),
            Err(e) => panic!("Conexão WebSocket {} dentro do limite falhou: {:?}", i + 1, e),
        }
    }
    // Próxima conexão deve ser rejeitada (rate limit)
    let conn_result = connect_async(&ws_url).await;
    assert!(conn_result.is_err(), "Conexão WebSocket excedente deveria ser rejeitada por rate limiting, mas foi: {:?}", conn_result.ok());
    docker_env.down(true).expect("Falha ao derrubar ambiente");
}

#[tokio::test]
#[serial_test::serial]
async fn test_websocket_inactive_client_is_disconnected() {
    let docker_env = setup_env().await;
    let ws_url = format!("ws://localhost:{}/mcp/ws", MCP_HTTP_PORT); // Corrigido para /mcp/ws
    let (ws_stream, _) = connect_async(&ws_url).await.expect("Falha ao conectar WebSocket");
    
    // Não envia nada, apenas espera pelo timeout de inatividade
    let timeout = Duration::from_secs(65); // Ajuste conforme configuração do servidor (ex: `connection_idle_timeout`)
    
    let mut stream = ws_stream;
    let mut disconnected_by_server = false;

    tokio::select! {
        biased;
        _ = tokio::time::sleep(timeout) => {
            // Timeout atingido no teste, a conexão deveria ter sido fechada pelo servidor antes disso.
            // Se chegarmos aqui, o servidor NÃO fechou a conexão como esperado.
        }
        // Tentamos ler da stream. Se o servidor fechar, `next()` retornará `None`.
        maybe_msg = stream.next() => {
            if maybe_msg.is_none() {
                // O servidor fechou a conexão (stream terminou)
                disconnected_by_server = true;
            } else if let Some(Err(_)) = maybe_msg {
                // Ocorreu um erro na stream, que pode indicar desconexão
                disconnected_by_server = true;
            }
        }
    }
    assert!(disconnected_by_server, "Conexão WebSocket inativa não foi desconectada pelo servidor após timeout");
    docker_env.down(true).expect("Falha ao derrubar ambiente");
}


#[tokio::test]
#[serial_test::serial]
#[ignore = "Requer implementação de `run_command` em DockerComposeEnv para enviar SIGTERM/SIGKILL e simular operações longas no MCP Server"]
async fn test_graceful_shutdown_allows_in_flight_requests_to_complete() {
    let docker_env = setup_env().await;
    let ws_url = format!("ws://localhost:{}/mcp/ws", MCP_HTTP_PORT);
    let (mut ws_stream, _) = connect_async(&ws_url).await.expect("Falha ao conectar WebSocket");
    
    // Envia uma operação MCP longa (simulada)
    // Esta operação "long_running" precisaria ser implementada no MCP server para este teste.
    let long_op = json!({"tool_name": "debug/long_operation", "input": {"duration_ms": 30000}});
    ws_stream.send(tokio_tungstenite::tungstenite::Message::Text(Utf8Bytes::from(long_op.to_string().as_str()))).await.expect("Falha ao enviar operação longa");
    
    // Simula envio de sinal de término ao servidor (requer `run_command`)
    // let _ = docker_env.run_command(&["kill", "-s", "SIGTERM", MCP_SERVER_SERVICE]);
    println!("Simulando SIGTERM para {}", MCP_SERVER_SERVICE);
    tokio::time::sleep(Duration::from_secs(1)).await; // Pequena pausa para o sinal ser processado

    let mut completed = false;
    let mut received_error = false;

    // Espera resposta ou fechamento
    // O timeout aqui deve ser maior que a duração da operação longa + tempo de graceful shutdown.
    match tokio::time::timeout(Duration::from_secs(40), ws_stream.next()).await {
        Ok(Some(Ok(tokio_tungstenite::tungstenite::Message::Text(txt)))) => {
            // Idealmente, o MCP server responderia com o resultado da operação longa.
            println!("Recebido do MCP: {}", txt);
            if txt.contains("long_operation_completed") { // Supondo uma resposta específica
                completed = true;
            } else if txt.contains("error") {
                received_error = true;
            }
        }
        Ok(Some(Ok(_))) => { /* Outras mensagens */ }
        Ok(Some(Err(e))) => {
            println!("Erro na stream WebSocket: {:?}", e);
            received_error = true; 
        }
        Ok(None) => { // Stream fechada
            println!("Stream WebSocket fechada pelo servidor.");
        }
        Err(_) => { // Timeout do `tokio::time::timeout`
            println!("Timeout esperando resposta da operação longa.");
        }
    }
    
    // Se o graceful shutdown funcionou e a operação completou, `completed` deve ser true.
    // Se o servidor desligou antes, `completed` será false, e `received_error` pode ser true ou a stream pode ter sido fechada.
    assert!(completed, "Operação em andamento não foi concluída durante graceful shutdown. Erro recebido: {}", received_error);
    docker_env.down(true).expect("Falha ao derrubar ambiente");
}


#[tokio::test]
#[serial_test::serial]
#[ignore = "Requer implementação de `pause_service` e `unpause_service` em DockerComposeEnv ou uma forma de simular a indisponibilidade do TypeDB"]
async fn test_server_recovers_after_typedb_temporary_outage() {
    let docker_env = setup_env().await;
    let ws_url = format!("ws://localhost:{}/mcp/ws", MCP_HTTP_PORT);
    let (mut ws_stream, _) = connect_async(&ws_url).await.expect("Falha ao conectar WebSocket inicial");

    // Envia uma operação MCP que depende do TypeDB
    let op = json!({"tool_name": "typedb/query_read", "input": {"query": "match $x isa entity; get; limit 1;", "database_name": "test_db_resilience"}});
    // Criar database primeiro (se não existir)
    let create_db_op = json!({"tool_name": "typedb/db_create", "input": {"database_name": "test_db_resilience"}});
    ws_stream.send(tokio_tungstenite::tungstenite::Message::Text(Utf8Bytes::from(create_db_op.to_string().as_str()))).await.expect("Falha ao enviar create_db");
    if let Some(Ok(tokio_tungstenite::tungstenite::Message::Text(txt))) = ws_stream.next().await {
        println!("Resposta create_db: {}", txt);
        assert!(!txt.contains("error"), "Falha ao criar database para o teste");
    } else {
        panic!("Não recebeu resposta para create_db");
    }

    ws_stream.send(tokio_tungstenite::tungstenite::Message::Text(Utf8Bytes::from(op.to_string().as_str()))).await.expect("Falha ao enviar query inicial");
    if let Some(Ok(tokio_tungstenite::tungstenite::Message::Text(txt))) = ws_stream.next().await {
        println!("Resposta query inicial: {}", txt);
        assert!(!txt.contains("error"), "Query inicial falhou inesperadamente: {}", txt);
    } else {
        panic!("Não recebeu resposta para query inicial");
    }

    // Simula pausa do TypeDB (requer `pause_service`)
    // pause_service(&docker_env, TYPEDB_SERVICE).await;
    println!("Simulando pausa do serviço TypeDB: {}", TYPEDB_SERVICE);
    tokio::time::sleep(Duration::from_secs(5)).await; // Simula tempo para o serviço parar

    // Tenta enviar a mesma operação novamente, deve falhar
    ws_stream.send(tokio_tungstenite::tungstenite::Message::Text(Utf8Bytes::from(op.to_string().as_str()))).await.expect("Falha ao enviar query durante outage simulado");
    
    let mut errored_during_outage = false;
    if let Some(Ok(tokio_tungstenite::tungstenite::Message::Text(txt))) = ws_stream.next().await {
        println!("Resposta query durante outage: {}", txt);
        if txt.contains("error") || txt.contains("Failed to connect to TypeDB") {
            errored_during_outage = true;
        }
    } else {
        println!("Não recebeu resposta para query durante outage, ou stream fechada.");
        // Se a stream for fechada, também consideramos um tipo de erro/falha.
        errored_during_outage = true; 
    }
    assert!(errored_during_outage, "Operação MCP não falhou como esperado após TypeDB ficar indisponível");

    // Verifica /readyz (deve indicar DOWN ou problemas com TypeDB)
    let readyz_resp = reqwest::get(&format!("{}/readyz", mcp_base_url())).await.expect("Falha na requisição /readyz durante outage");
    let readyz_status = readyz_resp.status();
    let readyz_body = readyz_resp.text().await.expect("Falha ao ler corpo /readyz durante outage");
    println!("/readyz durante outage: Status {}, Body: {}", readyz_status, readyz_body);
    assert!(readyz_status == StatusCode::SERVICE_UNAVAILABLE || readyz_body.to_lowercase().contains("typedb: down"),
            "/readyz deveria indicar TypeDB DOWN ou retornar 503. Status: {}, Body: {}", readyz_status, readyz_body);

    // Simula retomada do TypeDB (requer `unpause_service`)
    // unpause_service(&docker_env, TYPEDB_SERVICE).await;
    println!("Simulando retomada do serviço TypeDB: {}", TYPEDB_SERVICE);
    tokio::time::sleep(Duration::from_secs(15)).await; // Simula tempo para o serviço recuperar e MCP reconectar

    // Verifica /readyz novamente (deve indicar UP)
    let readyz_resp_after_recovery = reqwest::get(&format!("{}/readyz", mcp_base_url())).await.expect("Falha na requisição /readyz após recovery");
    let readyz_status_after_recovery = readyz_resp_after_recovery.status();
    let readyz_body_after_recovery = readyz_resp_after_recovery.text().await.expect("Falha ao ler corpo /readyz após recovery");
    println!("/readyz após recovery: Status {}, Body: {}", readyz_status_after_recovery, readyz_body_after_recovery);
    assert!(readyz_status_after_recovery == StatusCode::OK && readyz_body_after_recovery.to_lowercase().contains("typedb: up"),
            "/readyz deveria indicar UP e TypeDB UP após recovery. Status: {}, Body: {}", readyz_status_after_recovery, readyz_body_after_recovery);

    // Tenta a operação novamente, deve funcionar
    // Pode ser necessário reconectar se a stream anterior foi fechada
    let (mut ws_stream_after_recovery, _) = connect_async(&ws_url).await.expect("Falha ao reconectar WebSocket após recovery");
    ws_stream_after_recovery.send(tokio_tungstenite::tungstenite::Message::Text(Utf8Bytes::from(op.to_string().as_str()))).await.expect("Falha ao enviar query após recovery");
    if let Some(Ok(tokio_tungstenite::tungstenite::Message::Text(txt))) = ws_stream_after_recovery.next().await {
        println!("Resposta query após recovery: {}", txt);
        assert!(!txt.contains("error"), "Query após recovery falhou inesperadamente: {}", txt);
    } else {
        panic!("Não recebeu resposta para query após recovery");
    }

    ws_stream_after_recovery.close(None).await.ok();
    docker_env.down(true).expect("Falha ao derrubar ambiente");
}


// --- JWKS e Shutdown Imediato ---

#[tokio::test]
#[serial_test::serial]
#[ignore = "Depende de helpers/mocks para JWKS e autenticação de tokens, e `run_command` em DockerComposeEnv"]
async fn test_server_handles_jwks_outage_using_cached_keys() {
    // TODO: Implementar quando helpers de autenticação e manipulação de JWKS estiverem disponíveis.
    // 1. Sobe ambiente com OAuth e JWKS ativo.
    // 2. Autentica cliente MCP com token válido (chave no cache).
    // 3. Para o mock-auth-server-it.
    // 4. Tenta autenticar novamente com token cacheado (deve funcionar).
    // 5. Tenta autenticar com token novo (kid não cacheado, deve falhar).
    // 6. Reinicia mock-auth-server-it, verifica recuperação.
    unimplemented!("Implementar quando helpers JWKS estiverem disponíveis e DockerComposeEnv suportar controle de serviços individuais");
}

#[tokio::test]
#[serial_test::serial]
#[ignore = "Requer implementação de `run_command` em DockerComposeEnv para enviar SIGKILL e obter status do container"]
async fn test_graceful_shutdown_forces_exit_after_timeout() {
    let docker_env = setup_env().await;
    let ws_url = format!("ws://localhost:{}/mcp/ws", MCP_HTTP_PORT);
    let (mut ws_stream, _) = connect_async(&ws_url).await.expect("Falha ao conectar WebSocket");
    // Esta operação "long_running" precisaria ser implementada no MCP server para este teste.
    let long_op = json!({"tool_name": "debug/long_operation", "input": {"duration_ms": 60000}});
    ws_stream.send(tokio_tungstenite::tungstenite::Message::Text(Utf8Bytes::from(long_op.to_string().as_str()))).await.expect("Falha ao enviar operação longa");

    // Simula envio de SIGTERM (requer `run_command`)
    println!("Simulando SIGTERM para {}", MCP_SERVER_SERVICE);
    // let _ = docker_env.run_command(&["kill", "-s", "SIGTERM", MCP_SERVER_SERVICE]);
    tokio::time::sleep(Duration::from_secs(5)).await; // Simula tempo para SIGTERM e início do graceful shutdown

    // Simula envio de SIGKILL (requer `run_command`)
    println!("Simulando SIGKILL para {}", MCP_SERVER_SERVICE);
    // let _ = docker_env.run_command(&["kill", "-s", "SIGKILL", MCP_SERVER_SERVICE]);

    // Aguarda o container realmente parar.
    // A verificação de que o container parou e o código de saída precisaria de `docker_compose.ps()`
    // ou similar, que não está no placeholder DockerComposeEnv.
    tokio::time::sleep(Duration::from_secs(10)).await; // Espera para o container parar

    // A asserção real aqui seria verificar se o container MCP_SERVER_SERVICE não está mais rodando
    // e, idealmente, verificar seu código de saída (que seria != 0 após SIGKILL).
    // Por ora, o teste apenas executa os passos simulados.
    println!("Teste 'test_graceful_shutdown_forces_exit_after_timeout' executado (passos simulados).");
    docker_env.down(true).expect("Falha ao derrubar ambiente");
}
