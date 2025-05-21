// tests/integration/observability_tests.rs
// Testes de integração para endpoints de observabilidade do Typedb-MCP-Server.
// Valida /livez, /readyz e /metrics sob diferentes condições.
// Copyright 2025 Guilherme Leste
// Licença Apache 2.0

use std::time::Duration;
use reqwest::StatusCode;
use crate::common::docker_helpers::DockerComposeEnv; // Corrigido
use serde_json::Value as JsonValue;
use tracing::info; // Adicionado para usar info!

const DOCKER_COMPOSE_FILE: &str = "docker-compose.test.yml";
const PROJECT_PREFIX: &str = "observabilitytest"; // Alterado para evitar conflito de nome de projeto Docker muito longo
const MCP_SERVER_PORT_VAR: &str = "MCP_SERVER_TEST_PORT"; // Usar a variável do compose para a porta
const MCP_SERVER_DEFAULT_PORT: u16 = 8788; // Porta padrão se a variável não estiver definida
const MCP_METRICS_PORT: u16 = 9090; // Assumindo que as métricas estão expostas nesta porta no host
const MCP_SERVER_SERVICE: &str = "typedb-mcp-server-it";
const TYPEDB_SERVICE: &str = "typedb-server-it";
const MOCK_AUTH_SERVICE: &str = "mock-oauth2-server"; // Corrigido para o nome do serviço no docker-compose.test.yml

fn get_mcp_server_port() -> u16 {
    std::env::var(MCP_SERVER_PORT_VAR)
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(MCP_SERVER_DEFAULT_PORT)
}

fn mcp_base_url() -> String {
    format!("http://localhost:{}", get_mcp_server_port())
}
fn mcp_metrics_url() -> String {
    // MCP_METRICS_PORT parece ser fixo no compose para o host,
    // mas dentro do container MCP pode ser diferente se MCP_SERVER_METRICS_PORT_HTTP for usado.
    // Por simplicidade, vamos assumir que a porta 9090 do host está mapeada para a porta de métricas do container.
    // Se o `metrics_bind_address` no `config.test.toml` for diferente, este URL precisa refletir isso.
    // A porta 9090 é o default do `metrics_bind_address` no código `src/config.rs`.
    // E o `docker-compose.test.yml` não parece sobrescrever `MCP_METRICS_PORT` para `typedb-mcp-server-it`.
    // O `docker-compose.yml` principal expõe `MCP_METRICS_PORT:-9090}:9090`.
    // Se `config.test.toml` define `metrics_port = 9090` para o servidor, então `mcp_metrics_url`
    // deve apontar para a porta do *host* que mapeia para a porta de métricas do *container*.
    // O `typedb-mcp-server-it` no `docker-compose.test.yml` NÃO expõe a porta de métricas para o host,
    // então este teste pode precisar de ajustes se as métricas forem testadas por fora.
    // Se testadas de DENTRO da rede docker, seria `http://typedb-mcp-server-it:CONFIGURADA_NO_MCP_SERVER/metrics`
    // Para este teste, vamos assumir que o MCP_SERVER_SERVICE está configurado para expor métricas
    // em uma porta que o `reqwest` pode acessar (geralmente localhost se o teste rodar no host).
    // O `docker-compose.test.yml` não expõe a porta 9090 do `typedb-mcp-server-it`.
    // Isso precisa ser ajustado no `docker-compose.test.yml` se quisermos testar /metrics via localhost.
    // Adicionando a exposição da porta de métricas ao `docker-compose.test.yml` para `typedb-mcp-server-it`:
    // ports:
    //   - "${MCP_SERVER_TEST_PORT:-8788}:8787"
    //   - "${MCP_SERVER_TEST_METRICS_PORT:-9091}:9090"  <-- Adicionar algo assim e definir MCP_SERVER_TEST_METRICS_PORT
    // Por enquanto, manteremos a porta 9090, assumindo que o `config.test.toml` usa `metrics_port = 9090`
    // e que o docker-compose.test.yml foi ajustado para expor essa porta.
    // Se não, este teste de métricas falhará na conexão.
    format!("http://localhost:{}/metrics", MCP_METRICS_PORT)
}

/// Setup do ambiente docker-compose com suporte a variáveis de ambiente customizadas.
async fn setup_env_with_envs(test_name_suffix: &str, envs: Option<&[(&str, &str)]>) -> DockerComposeEnv {
    let project_name = format!("{}_{}", PROJECT_PREFIX, test_name_suffix);
    let env = DockerComposeEnv::new(DOCKER_COMPOSE_FILE, &project_name);
    env.down(true).ok(); // Ignora erro se o ambiente não existir
    if let Some(env_vars) = envs {
        env.up_with_envs(env_vars).expect("Falha ao subir ambiente docker-compose com envs");
    } else {
        env.up().expect("Falha ao subir ambiente docker-compose");
    }
    env.wait_for_service_healthy(TYPEDB_SERVICE, Duration::from_secs(90))
        .await
        .expect("TypeDB não saudável");
    env.wait_for_service_healthy(MCP_SERVER_SERVICE, Duration::from_secs(60))
        .await
        .expect("MCP Server não saudável");
    
    // Garante que o mock auth server também esteja saudável se estiver sendo usado (OAuth habilitado)
    if envs.map_or(false, |vars| vars.iter().any(|(k,v)| *k == "MCP_AUTH_OAUTH_ENABLED" && *v == "true")) {
        env.wait_for_service_healthy(MOCK_AUTH_SERVICE, Duration::from_secs(30))
            .await
            .expect("Mock Auth Server não saudável");
    }
    env
}

async fn setup_env(test_name_suffix: &str) -> DockerComposeEnv {
    setup_env_with_envs(test_name_suffix, None).await
}

async fn stop_service(env: &DockerComposeEnv, service: &str) {
    info!("Parando serviço: {}", service);
    env.stop_service(service).expect("Falha ao parar serviço");
}

/// Aguarda até que o endpoint /readyz retorne o status esperado (UP ou DOWN), com timeout adaptativo.
async fn wait_for_readyz_status(base_url: &str, expected_overall_status: &str, timeout: Duration) -> Option<JsonValue> {
    let url = format!("{}/readyz", base_url);
    info!("Aguardando /readyz em {} para ser {}", url, expected_overall_status);
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        match reqwest::get(&url).await {
            Ok(resp) => {
                let status_code = resp.status();
                match resp.text().await {
                    Ok(body) => {
                        info!("/readyz: Status {}, Corpo: {}", status_code, body);
                        if let Ok(json) = serde_json::from_str::<JsonValue>(&body) {
                            if json["status"].as_str().map_or(false, |s| s.eq_ignore_ascii_case(expected_overall_status)) {
                                return Some(json);
                            }
                        } else {
                            info!("/readyz: Falha ao parsear corpo JSON: {}", body);
                        }
                    }
                    Err(e) => info!("/readyz: Falha ao ler corpo da resposta: {}", e),
                }
            }
            Err(e) => info!("/readyz: Falha na requisição GET: {}", e),
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    info!("/readyz: Timeout esperando por status {}", expected_overall_status);
    None
}

#[tokio::test]
#[serial_test::serial]
async fn test_liveness_probe_returns_ok() {
    let docker_env = setup_env("live_ok").await;
    let url = format!("{}livez", mcp_base_url());
    let resp = reqwest::get(&url).await.expect("Falha na requisição livez");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.text().await.expect("Falha ao ler corpo livez");
    // O corpo exato pode variar, verificamos a presença de um status OK.
    // O handler em `main.rs` apenas retorna StatusCode::OK, então o corpo pode ser vazio ou default do Axum.
    // Para ser mais robusto, o handler livez poderia retornar um JSON `{"status": "OK"}`.
    // Por enquanto, o status HTTP 200 é a principal verificação.
    info!("livez body: {}", body); // Logar o corpo para inspeção
    docker_env.down(true).expect("Falha ao derrubar docker_env");
}

#[tokio::test]
#[serial_test::serial]
async fn test_readiness_probe_returns_service_unavailable_when_typedb_is_down() {
    let docker_env = setup_env("ready_typedb_down").await;
    stop_service(&docker_env, TYPEDB_SERVICE).await;
    let json = wait_for_readyz_status(&mcp_base_url(), "DOWN", Duration::from_secs(30))
        .await
        .expect("/readyz não ficou DOWN a tempo");
    assert_eq!(json["components"]["typedb"].as_str().map(|s| s.to_lowercase()), Some("down".to_string()), "Componente typedb deveria estar DOWN: {:?}", json);
    docker_env.down(true).expect("Falha ao derrubar docker_env");
}

#[tokio::test]
#[serial_test::serial]
async fn test_readiness_probe_returns_ok_when_all_dependencies_are_healthy() {
    let docker_env = setup_env("ready_all_healthy").await;
    let json = wait_for_readyz_status(&mcp_base_url(), "UP", Duration::from_secs(30))
        .await
        .expect("/readyz não ficou UP a tempo");
    assert_eq!(json["components"]["typedb"].as_str().map(|s| s.to_lowercase()), Some("up".to_string()), "Componente typedb deveria estar UP: {:?}", json);
    // Verifica JWKS como NOT_CONFIGURED se OAuth estiver desabilitado (default)
    assert_eq!(json["components"]["jwks"].as_str().map(|s| s.to_lowercase()), Some("not_configured".to_string()), "Componente jwks deveria estar NOT_CONFIGURED: {:?}", json);
    docker_env.down(true).expect("Falha ao derrubar docker_env");
}

#[tokio::test]
#[serial_test::serial]
async fn test_readiness_probe_returns_service_unavailable_when_jwks_is_down_and_oauth_enabled() {
    let docker_env = setup_env_with_envs("ready_jwks_down_oauth", Some(&[
        ("MCP_AUTH_OAUTH_ENABLED", "true"),
        // Aponta para o mock auth server na rede Docker, porta 80 (padrão do Nginx)
        ("MCP_AUTH_OAUTH_JWKS_URI", "http://mock-oauth2-server:80/.well-known/jwks.json"),
    ])).await;

    // Garante que tudo está saudável primeiro
    let json_up = wait_for_readyz_status(&mcp_base_url(), "UP", Duration::from_secs(30))
        .await
        .expect("/readyz não ficou UP a tempo inicialmente");
    assert_eq!(json_up["components"]["jwks"].as_str().map(|s| s.to_lowercase()), Some("up".to_string()), "Componente jwks deveria estar UP: {:?}", json_up);

    stop_service(&docker_env, MOCK_AUTH_SERVICE).await;

    let json_down = wait_for_readyz_status(&mcp_base_url(), "DOWN", Duration::from_secs(30))
        .await
        .expect("/readyz não ficou DOWN a tempo após JWKS cair");
    assert_eq!(json_down["components"]["jwks"].as_str().map(|s| s.to_lowercase()), Some("down".to_string()), "Componente jwks deveria estar DOWN: {:?}", json_down);
    docker_env.down(true).expect("Falha ao derrubar docker_env");
}

#[tokio::test]
#[serial_test::serial]
async fn test_readiness_probe_returns_service_unavailable_when_jwks_uri_is_invalid_and_oauth_enabled() {
    let docker_env = setup_env_with_envs("ready_jwks_invalid_oauth", Some(&[
        ("MCP_AUTH_OAUTH_ENABLED", "true"),
        ("MCP_AUTH_OAUTH_JWKS_URI", "http://invalid-jwks-uri-that-will-fail:12345/jwks.json"),
    ])).await;

    // O MCP server pode levar um tempo para tentar buscar o JWKS e falhar.
    let json_down = wait_for_readyz_status(&mcp_base_url(), "DOWN", Duration::from_secs(30))
        .await
        .expect("/readyz não ficou DOWN a tempo com JWKS URI inválido");
    assert_eq!(json_down["components"]["jwks"].as_str().map(|s| s.to_lowercase()), Some("down".to_string()), "Componente jwks deveria estar DOWN com URI inválida: {:?}", json_down);
    docker_env.down(true).expect("Falha ao derrubar docker_env");
}


#[tokio::test]
#[serial_test::serial]
async fn test_metrics_endpoint_is_accessible_and_has_prometheus_format() {
    // Este teste requer que a porta de métricas do typedb-mcp-server-it seja exposta para o host.
    // Exemplo de adição ao docker-compose.test.yml para o serviço typedb-mcp-server-it:
    //    ports:
    //      - "${MCP_SERVER_TEST_PORT:-8788}:8787"
    //      - "9099:9090" # Mapeia a porta 9090 do container (padrão de métricas) para 9099 do host
    // E então mude MCP_METRICS_PORT para 9099
    // Por agora, este teste pode falhar se a porta não estiver exposta.

    let _docker_env = setup_env("metrics_access").await; // Variável mantida
    let url = format!("http://localhost:{}", MCP_METRICS_PORT); // Usando MCP_METRICS_PORT
                                                                // que é a porta exposta no host
    
    let resp = match reqwest::get(&url).await {
        Ok(r) => r,
        Err(e) => {
            // Se a conexão falhar, pode ser porque a porta de métricas não está exposta no Docker Compose.
            // Logar o erro e falhar o teste de forma informativa.
            panic!("Falha ao conectar ao endpoint de métricas em {}: {}. Verifique a exposição da porta no docker-compose.test.yml.", url, e);
        }
    };

    assert_eq!(resp.status(), StatusCode::OK, "Falha ao acessar /metrics. Status: {}", resp.status());
    let content_type = resp.headers().get("content-type").map(|v| v.to_str().unwrap_or("")).unwrap_or("");
    assert!(content_type.starts_with("text/plain"), "Content-Type inesperado para /metrics: {}", content_type);
    
    let body = resp.text().await.expect("Falha ao ler corpo /metrics");
    info!("/metrics body (primeiros 500 chars): {:.500}", body); // Logar parte do corpo

    // Validação básica de formato Prometheus
    let mut found_ws_metric = false;
    let mut found_info_metric = false;
    for line in body.lines() {
        if line.starts_with('#') || line.trim().is_empty() { continue; }
        let parts: Vec<_> = line.split_whitespace().collect();
        assert!(parts.len() >= 2, "Linha de métrica inválida (menos de 2 partes): '{}'", line); // Pode ter timestamp
        let metric_name_with_labels = parts[0];
        let value_str = parts[1];
        
        assert!(value_str.parse::<f64>().is_ok(), "Valor de métrica não numérico: '{}' na linha '{}'", value_str, line);
        
        if metric_name_with_labels.starts_with("typedb_mcp_server_websocket_connections_total") {
            found_ws_metric = true;
        }
        if metric_name_with_labels.starts_with("typedb_mcp_server_info") {
            found_info_metric = true;
        }
    }
    assert!(found_ws_metric, "Métrica typedb_mcp_server_websocket_connections_total ausente no output de /metrics");
    assert!(found_info_metric, "Métrica typedb_mcp_server_info ausente no output de /metrics");
    // _docker_env.down(true).expect(...); // O Drop já faz isso
}