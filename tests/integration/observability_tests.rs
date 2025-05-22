// tests/integration/observability_tests.rs
// Testes de integração para endpoints de observabilidade do Typedb-MCP-Server.
// Valida /livez, /readyz e /metrics sob diferentes condições.
// Copyright 2025 Guilherme Leste
// Licença Apache 2.0

//! Testes de integração para os endpoints de observabilidade (`/livez`, `/readyz`, `/metrics`)
//! do Typedb-MCP-Server.

use crate::common::{
    constants,
    // docker_helpers::DockerComposeEnv, // Removido se TestEnvironment já o expõe via test_env.docker_env
                                        // No entanto, mantê-lo não prejudica se for para clareza de tipo.
                                        // O erro de unused deve sumir se o código compilar após stop_service ser adicionado.
    test_env::TestEnvironment,
};
use anyhow::Result;
use reqwest::StatusCode;
use serde_json::Value as JsonValue;
use serial_test::serial;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Helper para aguardar o status específico do /readyz.
/// Retorna o corpo JSON se o status esperado for alcançado.
async fn wait_for_readyz_status(
    readyz_url: &str,
    expected_overall_status: &str,
    is_mcp_server_tls: bool,
    timeout: Duration,
) -> Result<Option<JsonValue>> {
    info!(
        "Aguardando /readyz em {} para ser '{}' (timeout: {:?})",
        readyz_url, expected_overall_status, timeout
    );

    let client_builder = reqwest::Client::builder();
    let client = if is_mcp_server_tls {
        client_builder.danger_accept_invalid_certs(true).build()?
    } else {
        client_builder.build()?
    };

    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        match client.get(readyz_url).send().await {
            Ok(resp) => {
                let status_code = resp.status();
                match resp.json::<JsonValue>().await {
                    Ok(json_body) => {
                        debug!("/readyz: Status {}, Corpo: {}", status_code, json_body);
                        if json_body
                            .get("status")
                            .and_then(|s| s.as_str())
                            .map_or(false, |s| {
                                s.eq_ignore_ascii_case(expected_overall_status)
                            })
                        {
                            // Verificar também o status HTTP correspondente
                            if (expected_overall_status.eq_ignore_ascii_case("UP") && status_code == StatusCode::OK) ||
                               (expected_overall_status.eq_ignore_ascii_case("DOWN") && status_code == StatusCode::SERVICE_UNAVAILABLE) {
                                return Ok(Some(json_body));
                            }
                            debug!("/readyz: Status do corpo é '{}', mas HTTP status é {}. Continuando espera.", expected_overall_status, status_code);
                        }
                    }
                    Err(e) => {
                        debug!("/readyz: Falha ao parsear corpo JSON (Status {}): {}. Tentando ler como texto...", status_code, e);
                        if let Ok(resp_text) = client.get(readyz_url).send().await?.text().await {
                            debug!("/readyz corpo como texto: {}", resp_text);
                        }
                    }
                }
            }
            Err(e) => debug!("/readyz: Falha na requisição GET a '{}': {}. Tentando novamente...", readyz_url, e),
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    warn!("/readyz: Timeout esperando por status '{}' em '{}'", expected_overall_status, readyz_url);
    Ok(None)
}

#[tokio::test]
#[serial]
async fn test_liveness_probe_returns_ok_default_config() -> Result<()> {
    let test_env = TestEnvironment::setup(
        "obs_live_ok_def",
        constants::DEFAULT_TEST_CONFIG_FILENAME,
    )
    .await?;
    let livez_url = format!("{}{}", test_env.mcp_http_base_url, constants::MCP_SERVER_DEFAULT_LIVEZ_PATH);

    info!("Teste: Verificando /livez em {}", livez_url);
    let resp = reqwest::get(&livez_url).await?;
    assert_eq!(resp.status(), StatusCode::OK, "/livez deveria retornar 200 OK");
    info!("/livez retornou status OK.");
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_liveness_probe_returns_ok_server_tls_config() -> Result<()> {
    let test_env = TestEnvironment::setup(
        "obs_live_ok_tls",
        constants::SERVER_TLS_TEST_CONFIG_FILENAME,
    )
    .await?;
    assert!(test_env.is_mcp_server_tls);
    let livez_url = format!("{}{}", test_env.mcp_http_base_url, constants::MCP_SERVER_DEFAULT_LIVEZ_PATH);

    info!("Teste: Verificando /livez (HTTPS) em {}", livez_url);
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    let resp = client.get(&livez_url).send().await?;
    assert_eq!(resp.status(), StatusCode::OK, "/livez (HTTPS) deveria retornar 200 OK");
    info!("/livez (HTTPS) retornou status OK.");
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_readiness_probe_all_healthy_default_config() -> Result<()> {
    let test_env = TestEnvironment::setup(
        "obs_ready_ok_def",
        constants::DEFAULT_TEST_CONFIG_FILENAME,
    )
    .await?;
    let readyz_url = format!("{}{}", test_env.mcp_http_base_url, constants::MCP_SERVER_DEFAULT_READYZ_PATH);

    info!("Teste: Verificando /readyz com todas as dependências saudáveis (config default). URL: {}", readyz_url);
    let json_response =
        wait_for_readyz_status(&readyz_url, "UP", test_env.is_mcp_server_tls, Duration::from_secs(30))
            .await?
            .expect("/readyz não atingiu o estado UP esperado a tempo.");

    assert_eq!(json_response.get("status").and_then(|s| s.as_str()), Some("UP"));
    let components = json_response.get("components").expect("Campo 'components' ausente no /readyz.");
    assert_eq!(components.get("typedb").and_then(|s| s.as_str()), Some("UP"));
    assert_eq!(components.get("jwks").and_then(|s| s.as_str()), Some("NOT_CONFIGURED"));
    info!("/readyz com config default está UP e componentes OK.");
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_readiness_probe_all_healthy_oauth_enabled() -> Result<()> {
    let test_env = TestEnvironment::setup(
        "obs_ready_ok_oauth",
        constants::OAUTH_ENABLED_TEST_CONFIG_FILENAME,
    )
    .await?;
    assert!(test_env.is_oauth_enabled);
    let readyz_url = format!("{}{}", test_env.mcp_http_base_url, constants::MCP_SERVER_DEFAULT_READYZ_PATH);

    info!("Teste: Verificando /readyz com OAuth habilitado e dependências saudáveis. URL: {}", readyz_url);
    let json_response =
        wait_for_readyz_status(&readyz_url, "UP", test_env.is_mcp_server_tls, Duration::from_secs(45))
            .await?
            .expect("/readyz não atingiu o estado UP esperado com OAuth a tempo.");

    assert_eq!(json_response.get("status").and_then(|s| s.as_str()), Some("UP"));
    let components = json_response.get("components").expect("Campo 'components' ausente.");
    assert_eq!(components.get("typedb").and_then(|s| s.as_str()), Some("UP"));
    assert_eq!(components.get("jwks").and_then(|s| s.as_str()), Some("UP"));
    info!("/readyz com OAuth habilitado está UP e componentes OK.");
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_readiness_probe_typedb_down() -> Result<()> {
    let test_env = TestEnvironment::setup(
        "obs_ready_typedb_down",
        constants::DEFAULT_TEST_CONFIG_FILENAME,
    )
    .await?;
    let readyz_url = format!("{}{}", test_env.mcp_http_base_url, constants::MCP_SERVER_DEFAULT_READYZ_PATH);

    info!("Teste: Parando serviço TypeDB ('{}') para testar /readyz.", constants::TYPEDB_SERVICE_NAME);
    test_env.docker_env.stop_service(constants::TYPEDB_SERVICE_NAME)?; // ASSUME que stop_service existe
    tokio::time::sleep(Duration::from_secs(10)).await;

    info!("Teste: Verificando /readyz após TypeDB ser parado. URL: {}", readyz_url);
    let json_response =
        wait_for_readyz_status(&readyz_url, "DOWN", test_env.is_mcp_server_tls, Duration::from_secs(30))
            .await?
            .expect("/readyz não atingiu o estado DOWN esperado após TypeDB ser parado.");

    assert_eq!(json_response.get("status").and_then(|s| s.as_str()), Some("DOWN"));
    let components = json_response.get("components").expect("Campo 'components' ausente.");
    assert_eq!(components.get("typedb").and_then(|s| s.as_str()), Some("DOWN"));
    info!("/readyz com TypeDB parado está DOWN como esperado.");
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_readiness_probe_jwks_down_when_oauth_enabled() -> Result<()> {
    let test_env = TestEnvironment::setup(
        "obs_ready_jwks_down",
        constants::OAUTH_ENABLED_TEST_CONFIG_FILENAME,
    )
    .await?;
    assert!(test_env.is_oauth_enabled);
    let readyz_url = format!("{}{}", test_env.mcp_http_base_url, constants::MCP_SERVER_DEFAULT_READYZ_PATH);

    let json_up = wait_for_readyz_status(&readyz_url, "UP", test_env.is_mcp_server_tls, Duration::from_secs(30)).await?.expect("Readyz não ficou UP inicialmente");
    assert_eq!(json_up.get("components").and_then(|c| c.get("jwks")).and_then(|s| s.as_str()), Some("UP"));

    info!("Teste: Parando serviço Mock OAuth ('{}') para testar /readyz com OAuth.", constants::MOCK_OAUTH_SERVICE_NAME);
    test_env.docker_env.stop_service(constants::MOCK_OAUTH_SERVICE_NAME)?; // ASSUME que stop_service existe
    tokio::time::sleep(Duration::from_secs(10)).await;

    info!("Teste: Verificando /readyz após Mock OAuth ser parado. URL: {}", readyz_url);
    let json_response_down =
        wait_for_readyz_status(&readyz_url, "DOWN", test_env.is_mcp_server_tls, Duration::from_secs(35))
            .await?
            .expect("/readyz não atingiu o estado DOWN esperado após Mock OAuth ser parado.");

    assert_eq!(json_response_down.get("status").and_then(|s| s.as_str()), Some("DOWN"));
    let components_down = json_response_down.get("components").expect("Campo 'components' ausente.");
    assert_eq!(components_down.get("jwks").and_then(|s| s.as_str()), Some("DOWN"));
    info!("/readyz com Mock OAuth parado (e OAuth habilitado) está DOWN como esperado.");
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_metrics_endpoint_returns_prometheus_format() -> Result<()> {
    let test_env = TestEnvironment::setup(
        "obs_metrics_fmt",
        constants::DEFAULT_TEST_CONFIG_FILENAME,
    )
    .await?;
    
    info!("Teste: Verificando /metrics em {}", test_env.mcp_metrics_url);
    let resp = reqwest::get(&test_env.mcp_metrics_url).await?;

    assert_eq!(resp.status(), StatusCode::OK, "/metrics deveria retornar 200 OK");
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.starts_with("text/plain"),
        "Content-Type de /metrics inesperado: '{}'",
        content_type
    );

    let body = resp.text().await?;
    debug!("/metrics body (primeiras 500 chars): {:.500}", body);

    assert!(
        body.contains("typedb_mcp_server_websocket_connections_total"),
        "Métrica 'typedb_mcp_server_websocket_connections_total' ausente."
    );
    assert!(
        body.contains("typedb_mcp_server_info{app_version="),
        "Métrica 'typedb_mcp_server_info' com label 'app_version' ausente."
    );
    assert!(
        body.contains("process_cpu_seconds_total"),
        "Métrica padrão 'process_cpu_seconds_total' ausente."
    );
    info!("/metrics retornou formato Prometheus esperado.");
    Ok(())
}