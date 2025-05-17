// tests/integration/observability_tests.rs
// Testes de integração para endpoints de observabilidade do Typedb-MCP-Server.
// Valida /livez, /readyz e /metrics sob diferentes condições.
// Copyright 2025 Guilherme Leste
// Licença Apache 2.0

use std::time::Duration;
use reqwest::StatusCode;
use tests::common::docker_helpers::DockerComposeEnv;

use serde_json::Value as JsonValue;

const DOCKER_COMPOSE_FILE: &str = "docker-compose.test.yml";
const PROJECT_PREFIX: &str = "observability";
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

/// Setup do ambiente docker-compose com suporte a variáveis de ambiente customizadas.
async fn setup_env_with_envs(envs: Option<&[(&str, &str)]>) -> DockerComposeEnv {
    let env = DockerComposeEnv::new(DOCKER_COMPOSE_FILE, PROJECT_PREFIX);
    env.down(false).ok();
    if let Some(env_vars) = envs {
        // Passa as variáveis de ambiente para o processo docker-compose up
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
    // Para o container do serviço
    let _ = env.run_command(&["stop", service]);
}

/// Aguarda até que o endpoint /readyz retorne o status esperado (UP ou DOWN), com timeout adaptativo.
async fn wait_for_readyz_status(base_url: &str, expected_status: &str, timeout: Duration) -> Option<JsonValue> {
    let url = format!("{}/readyz", base_url);
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if let Ok(resp) = reqwest::get(&url).await {
            if let Ok(body) = resp.text().await {
                if let Ok(json) = serde_json::from_str::<JsonValue>(&body) {
                    if json["status"].as_str().map(|s| s.eq_ignore_ascii_case(expected_status)).unwrap_or(false) {
                        return Some(json);
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    None
}

#[tokio::test]
async fn test_liveness_probe_returns_ok() {
    let _env = setup_env().await;
    let url = format!("{}/livez", mcp_base_url());
    let resp = reqwest::get(&url).await.expect("Falha na requisição /livez");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.text().await.expect("Falha ao ler corpo /livez");
    assert!(body.contains("OK") || body.contains("status"), "Corpo inesperado: {}", body);
}

#[tokio::test]
async fn test_readiness_probe_returns_service_unavailable_when_typedb_is_down() {
    let env = setup_env().await;
    stop_service(&env, TYPEDB_SERVICE).await;
    // Aguarda até 30s para o MCP detectar a dependência DOWN
    let json = wait_for_readyz_status(&mcp_base_url(), "DOWN", Duration::from_secs(30)).await.expect("/readyz não ficou DOWN a tempo");
    assert!(json["components"]["typedb"] == "DOWN" || json["components"]["typedb"] == "down", "Componente typedb deveria estar DOWN: {:?}", json);
}

#[tokio::test]
async fn test_readiness_probe_returns_service_unavailable_during_shutdown() {
    let env = setup_env().await;
    stop_service(&env, MCP_SERVER_SERVICE).await;
    // O container MCP Server vai parar, mas pode demorar para o endpoint sumir. Testa até 10s.
    let url = format!("{}/readyz", mcp_base_url());
    let mut found_503 = false;
    for _ in 0..10 {
        let resp = reqwest::get(&url).await;
        if let Ok(resp) = resp {
            if resp.status() == StatusCode::SERVICE_UNAVAILABLE {
                found_503 = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    assert!(found_503, "/readyz não retornou 503 durante shutdown do MCP Server");
}

#[tokio::test]
async fn test_readiness_probe_returns_ok_when_all_dependencies_are_healthy() {
    let _env = setup_env().await;
    // Aguarda até 30s para o MCP ficar UP
    let json = wait_for_readyz_status(&mcp_base_url(), "UP", Duration::from_secs(30)).await.expect("/readyz não ficou UP a tempo");
    assert!(json["components"]["typedb"] == "UP" || json["components"]["typedb"] == "up", "Componente typedb deveria estar UP: {:?}", json);
    // Pode validar outros componentes se existirem
}

#[tokio::test]
async fn test_readiness_probe_returns_service_unavailable_when_jwks_is_down_and_oauth_enabled() {
    // Sobe o ambiente com OAuth habilitado e JWKS apontando para o mock-auth-server-it
    let env = setup_env_with_envs(Some(&[
        ("MCP_AUTH_OAUTH_ENABLED", "true"),
        ("MCP_AUTH_OAUTH_JWKS_URI", "http://mock-auth-server-it:8080/jwks"),
    ])).await;
    // Garante que tudo está saudável primeiro
    let json_up = wait_for_readyz_status(&mcp_base_url(), "UP", Duration::from_secs(30)).await.expect("/readyz não ficou UP a tempo");
    assert!(json_up["components"]["jwks"] == "UP" || json_up["components"]["jwks"] == "up", "Componente jwks deveria estar UP: {:?}", json_up);
    // Para o mock-auth-server (JWKS)
    stop_service(&env, MOCK_AUTH_SERVICE).await;
    // Aguarda até 30s para o MCP detectar JWKS DOWN
    let json = wait_for_readyz_status(&mcp_base_url(), "DOWN", Duration::from_secs(30)).await.expect("/readyz não ficou DOWN a tempo após JWKS cair");
    assert!(json["components"]["jwks"] == "DOWN" || json["components"]["jwks"] == "down", "Componente jwks deveria estar DOWN: {:?}", json);
}

#[tokio::test]
async fn test_readiness_probe_returns_service_unavailable_when_jwks_returns_invalid_response() {
    // Sobe o ambiente com OAuth habilitado e JWKS apontando para um endpoint inválido (ex: porta errada ou serviço que responde 500)
    let env = setup_env_with_envs(Some(&[
        ("MCP_AUTH_OAUTH_ENABLED", "true"),
        ("MCP_AUTH_OAUTH_JWKS_URI", "http://mock-auth-server-it:8081/jwks"), // Porta errada proposital
    ])).await;
    // Aguarda até 30s para o MCP detectar JWKS DOWN
    let json = wait_for_readyz_status(&mcp_base_url(), "DOWN", Duration::from_secs(30)).await.expect("/readyz não ficou DOWN a tempo após JWKS inválido");
    assert!(json["components"]["jwks"] == "DOWN" || json["components"]["jwks"] == "down", "Componente jwks deveria estar DOWN: {:?}", json);
}


#[tokio::test]
async fn test_metrics_endpoint_is_accessible_and_has_prometheus_format() {
    let _env = setup_env().await;
    let url = mcp_metrics_url();
    let resp = reqwest::get(&url).await.expect("Falha na requisição /metrics");
    assert_eq!(resp.status(), StatusCode::OK);
    let content_type = resp.headers().get("content-type").map(|v| v.to_str().unwrap_or("")).unwrap_or("");
    assert!(content_type.starts_with("text/plain"), "Content-Type inesperado: {}", content_type);
    let body = resp.text().await.expect("Falha ao ler corpo /metrics");
    // Validação básica de formato Prometheus
    let mut found_ws_metric = false;
    let mut found_info_metric = false;
    for line in body.lines() {
        if line.starts_with('#') || line.trim().is_empty() { continue; }
        // Exemplo: nome_metrica{...} valor OU nome_metrica valor
        let parts: Vec<_> = line.split_whitespace().collect();
        assert!(parts.len() == 2, "Linha de métrica inválida: {}", line);
        let metric = parts[0];
        let value = parts[1];
        assert!(value.parse::<f64>().is_ok(), "Valor de métrica não numérico: {}", value);
        if metric.starts_with("typedb_mcp_server_websocket_connections_total") {
            found_ws_metric = true;
        }
        if metric.starts_with("typedb_mcp_server_info") {
            found_info_metric = true;
        }
    }
    assert!(found_ws_metric, "Métrica websocket_connections_total ausente");
    assert!(found_info_metric, "Métrica info ausente");
}
