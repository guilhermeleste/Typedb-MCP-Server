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

//! Testes de integração para os endpoints de observabilidade (`/livez`, `/readyz`, `/metrics`)
//! do Typedb-MCP-Server.
//!
//! Esta suíte de testes verifica se:
//! - O endpoint `/livez` responde corretamente.
//! - O endpoint `/readyz` reflete com precisão o estado do servidor e de suas dependências
//!   (TypeDB, JWKS) em vários cenários (saudável, com falha).
//! - O endpoint `/metrics` é acessível e expõe métricas no formato Prometheus.

use crate::common::{constants, helper_wait_for_metrics_endpoint, test_env::TestEnvironment};
use anyhow::{Context as AnyhowContext, Result};
use reqwest::StatusCode;
use serde_json::Value as JsonValue;
use serial_test::serial;
use std::time::Duration;
use tracing::{debug, info, warn};

// IMPORTS CORRIGIDOS: Importar constantes diretamente da biblioteca principal
use typedb_mcp_server_lib::metrics::{METRIC_PREFIX, SERVER_INFO_GAUGE};

/// Helper para aguardar por um status específico do `/readyz` e retornar o corpo JSON.
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
                let body_bytes_result = resp.bytes().await;

                let body_text_for_log = match &body_bytes_result {
                    Ok(b) => String::from_utf8_lossy(b).to_string(),
                    Err(e) => format!("<corpo não pôde ser lido: {}>", e),
                };

                let expected_status_code = if expected_overall_status.eq_ignore_ascii_case("UP") {
                    StatusCode::OK
                } else {
                    StatusCode::SERVICE_UNAVAILABLE
                };

                if status_code != expected_status_code {
                    info!(
                        "/readyz em '{}': Status HTTP {} (esperado {}). Corpo: '{}'. Aguardando...",
                        readyz_url, status_code, expected_status_code, body_text_for_log
                    );
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }

                match body_bytes_result {
                    Ok(b) => match serde_json::from_slice::<JsonValue>(&b) {
                        Ok(json_body) => {
                            debug!("/readyz: Status {}, Corpo JSON: {:?}", status_code, json_body);
                            if json_body
                                .get("status")
                                .and_then(|s| s.as_str())
                                .map_or(false, |s| s.eq_ignore_ascii_case(expected_overall_status))
                            {
                                info!(
                                    "Estado esperado '{}' alcançado para /readyz.",
                                    expected_overall_status
                                );
                                return Ok(Some(json_body));
                            }
                        }
                        Err(e) => {
                            warn!(
                                "/readyz para '{}' retornou status {} mas falhou ao parsear JSON: {}. Corpo: '{}'. Aguardando...",
                                readyz_url, status_code, e, body_text_for_log
                            );
                        }
                    },
                    Err(e) => {
                        warn!(
                            "/readyz para '{}' retornou status {} mas falhou ao ler o corpo de bytes: {}. Aguardando...",
                            readyz_url, status_code, e
                        );
                    }
                }
            }
            Err(e) => debug!(
                "/readyz: Falha na requisição GET a '{}': {}. Tentando novamente...",
                readyz_url, e
            ),
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    warn!(
        "/readyz: Timeout esperando por status '{}' em '{}'",
        expected_overall_status, readyz_url
    );
    Ok(None)
}

#[tokio::test]
#[serial]
async fn test_liveness_probe_returns_ok_default_config() -> Result<()> {
    info!("Iniciando teste: test_liveness_probe_returns_ok_default_config");
    let test_env =
        TestEnvironment::setup("obs_live_ok_def", constants::DEFAULT_TEST_CONFIG_FILENAME).await?;
    let livez_url =
        format!("{}{}", test_env.mcp_http_base_url, constants::MCP_SERVER_DEFAULT_LIVEZ_PATH);

    info!("Teste: Verificando /livez em {}", livez_url);
    let resp = reqwest::get(&livez_url).await?;
    assert_eq!(resp.status(), StatusCode::OK, "/livez deveria retornar 200 OK");
    info!("/livez retornou status OK.");
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_liveness_probe_returns_ok_server_tls_config() -> Result<()> {
    info!("Iniciando teste: test_liveness_probe_returns_ok_server_tls_config");
    let test_env =
        TestEnvironment::setup("obs_live_ok_tls", constants::SERVER_TLS_TEST_CONFIG_FILENAME)
            .await?;
    assert!(test_env.is_mcp_server_tls, "TLS do servidor deveria estar habilitado.");
    let livez_url =
        format!("{}{}", test_env.mcp_http_base_url, constants::MCP_SERVER_DEFAULT_LIVEZ_PATH);

    info!("Teste: Verificando /livez (HTTPS) em {}", livez_url);
    let client = reqwest::Client::builder().danger_accept_invalid_certs(true).build()?;
    let resp = client.get(&livez_url).send().await?;
    assert_eq!(resp.status(), StatusCode::OK, "/livez (HTTPS) deveria retornar 200 OK");
    info!("/livez (HTTPS) retornou status OK.");
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_readiness_probe_all_healthy_default_config() -> Result<()> {
    info!("Iniciando teste: test_readiness_probe_all_healthy_default_config");
    let test_env =
        TestEnvironment::setup("obs_ready_ok_def", constants::DEFAULT_TEST_CONFIG_FILENAME).await?;

    let readyz_url =
        format!("{}{}", test_env.mcp_http_base_url, constants::MCP_SERVER_DEFAULT_READYZ_PATH);
    let client = reqwest::Client::new();
    let resp = client.get(&readyz_url).send().await?.json::<JsonValue>().await?;

    info!("Verificando corpo da resposta de /readyz: {:?}", resp);
    assert_eq!(resp.get("status").and_then(|s| s.as_str()), Some("UP"));
    let components = resp.get("components").expect("Campo 'components' ausente.");
    assert_eq!(components.get("typedb").and_then(|s| s.as_str()), Some("UP"));
    assert_eq!(components.get("jwks").and_then(|s| s.as_str()), Some("NOT_CONFIGURED"));
    info!("/readyz com config default está UP e componentes OK.");
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_readiness_probe_all_healthy_oauth_enabled() -> Result<()> {
    info!("Iniciando teste: test_readiness_probe_all_healthy_oauth_enabled");
    let test_env =
        TestEnvironment::setup("obs_ready_ok_oauth", constants::OAUTH_ENABLED_TEST_CONFIG_FILENAME)
            .await?;
    assert!(test_env.is_oauth_enabled, "OAuth deveria estar habilitado.");

    let readyz_url =
        format!("{}{}", test_env.mcp_http_base_url, constants::MCP_SERVER_DEFAULT_READYZ_PATH);
    let client = reqwest::Client::new();
    let resp = client.get(&readyz_url).send().await?.json::<JsonValue>().await?;

    info!("Verificando corpo da resposta de /readyz com OAuth: {:?}", resp);
    assert_eq!(resp.get("status").and_then(|s| s.as_str()), Some("UP"));
    let components = resp.get("components").expect("Campo 'components' ausente.");
    assert_eq!(components.get("typedb").and_then(|s| s.as_str()), Some("UP"));
    assert_eq!(components.get("jwks").and_then(|s| s.as_str()), Some("UP"));
    info!("/readyz com OAuth habilitado está UP e componentes OK.");
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_readiness_probe_typedb_down() -> Result<()> {
    info!("Iniciando teste: test_readiness_probe_typedb_down");
    let test_env =
        TestEnvironment::setup("obs_ready_typedb_down", constants::DEFAULT_TEST_CONFIG_FILENAME)
            .await?;
    let readyz_url =
        format!("{}{}", test_env.mcp_http_base_url, constants::MCP_SERVER_DEFAULT_READYZ_PATH);

    info!(
        "Teste: Parando serviço TypeDB ('{}') para testar /readyz.",
        constants::TYPEDB_SERVICE_NAME
    );
    test_env.docker_env.stop_service(constants::TYPEDB_SERVICE_NAME)?;

    let json_response = wait_for_readyz_status(
        &readyz_url,
        "DOWN",
        test_env.is_mcp_server_tls,
        Duration::from_secs(30),
    )
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
    info!("Iniciando teste: test_readiness_probe_jwks_down_when_oauth_enabled");
    let test_env = TestEnvironment::setup(
        "obs_ready_jwks_down",
        constants::OAUTH_ENABLED_TEST_CONFIG_FILENAME,
    )
    .await?;
    assert!(test_env.is_oauth_enabled, "OAuth deveria estar habilitado.");
    let readyz_url =
        format!("{}{}", test_env.mcp_http_base_url, constants::MCP_SERVER_DEFAULT_READYZ_PATH);

    let json_up = wait_for_readyz_status(
        &readyz_url,
        "UP",
        test_env.is_mcp_server_tls,
        Duration::from_secs(30),
    )
    .await?
    .expect("Readyz não ficou UP inicialmente (esperado para verificar transição para DOWN).");
    assert_eq!(
        json_up.get("components").and_then(|c| c.get("jwks")).and_then(|s| s.as_str()),
        Some("UP")
    );

    info!(
        "Teste: Parando serviço Mock OAuth ('{}') para testar /readyz com OAuth.",
        constants::MOCK_OAUTH_SERVICE_NAME
    );
    test_env.docker_env.stop_service(constants::MOCK_OAUTH_SERVICE_NAME)?;

    let json_response_down = wait_for_readyz_status(
        &readyz_url,
        "DOWN",
        test_env.is_mcp_server_tls,
        Duration::from_secs(35),
    )
    .await?
    .expect("/readyz não atingiu o estado DOWN esperado após Mock OAuth ser parado.");

    assert_eq!(json_response_down.get("status").and_then(|s| s.as_str()), Some("DOWN"));
    let components_down =
        json_response_down.get("components").expect("Campo 'components' ausente.");
    assert_eq!(components_down.get("jwks").and_then(|s| s.as_str()), Some("DOWN"));
    info!("/readyz com Mock OAuth parado (e OAuth habilitado) está DOWN como esperado.");
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_metrics_endpoint_returns_prometheus_format() -> Result<()> {
    info!("Iniciando teste: test_metrics_endpoint_returns_prometheus_format");
    let test_env =
        TestEnvironment::setup("obs_metrics_fmt", constants::DEFAULT_TEST_CONFIG_FILENAME).await?;

    info!("Teste: Verificando /metrics em {}", test_env.mcp_metrics_url);

    // Aguarda que o endpoint de métricas esteja disponível
    helper_wait_for_metrics_endpoint(&test_env.mcp_metrics_url, 10)
        .await
        .context("Endpoint de métricas não ficou disponível no tempo esperado")?;

    let resp = reqwest::get(&test_env.mcp_metrics_url)
        .await
        .context("Falha na requisição GET para o endpoint /metrics")?;

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

    let expected_info_metric = format!("{}{}", METRIC_PREFIX, SERVER_INFO_GAUGE);
    assert!(
        body.contains(&expected_info_metric),
        "A métrica de informação ('{}') não foi encontrada no corpo da resposta /metrics. Corpo recebido:\n{}",
        expected_info_metric,
        body
    );

    info!("Endpoint /metrics acessível e contém métricas esperadas.");
    Ok(())
}
