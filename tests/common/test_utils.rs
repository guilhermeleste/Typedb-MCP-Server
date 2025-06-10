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

//! Utilitários e helpers comuns para os testes de integração do Typedb-MCP-Server.
//! Este módulo centraliza funções repetitivas usadas em múltiplas suítes de teste.

use anyhow::{bail, Context as AnyhowContext, Result};
use serde_json::json;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, trace, warn};
use uuid::Uuid;

// Importar tipos do mesmo crate `common`
use super::client::TestMcpClient;
use super::constants;
use super::docker_helpers::DockerComposeEnv;

/// Gera um nome de banco de dados único prefixado para evitar conflitos entre testes.
///
/// # Arguments
/// * `prefix`: Um prefixo descritivo para o nome do banco de dados.
pub fn unique_db_name(prefix: &str) -> String {
    format!("{}_{}", prefix, Uuid::new_v4().as_simple())
}

/// Cria um banco de dados de teste usando um cliente MCP já inicializado.
///
/// Entra em pânico se a criação do banco de dados falhar, pois geralmente é um pré-requisito
/// para o teste que o chama.
///
/// # Arguments
/// * `client`: Uma referência mutável para um `TestMcpClient` conectado e inicializado.
/// * `db_name`: O nome do banco de dados a ser criado.
pub async fn create_test_db(client: &mut TestMcpClient, db_name: &str) -> Result<()> {
    info!("Helper Comum: Criando banco de dados de teste: '{}'", db_name);
    let result =
        client.call_tool("create_database", Some(json!({ "name": db_name }))).await.with_context(
            || format!("Helper Comum: Falha ao chamar create_database para '{}'", db_name),
        )?;

    let response_text = super::mcp_utils::get_text_from_call_result(result);
    if response_text != "OK" {
        bail!(
            "Helper Comum: Resposta inesperada ao criar banco de dados '{}': {}",
            db_name,
            response_text
        );
    }
    info!("Helper Comum: Banco de dados de teste '{}' criado com sucesso.", db_name);
    Ok(())
}

/// Deleta um banco de dados de teste usando um cliente MCP (melhor esforço).
///
/// Loga um aviso se a deleção falhar, mas não entra em pânico para não
/// interromper o teardown de outros testes.
///
/// # Arguments
/// * `client`: Uma referência mutável para um `TestMcpClient` conectado e inicializado.
/// * `db_name`: O nome do banco de dados a ser deletado.
pub async fn delete_test_db(client: &mut TestMcpClient, db_name: &str) {
    info!("Helper Comum: Deletando banco de dados de teste: '{}'", db_name);
    match client.call_tool("delete_database", Some(json!({ "name": db_name }))).await {
        Ok(result) => {
            let response_text = super::mcp_utils::get_text_from_call_result(result);
            if response_text == "OK" {
                info!("Helper Comum: Banco de dados de teste '{}' deletado com sucesso.", db_name);
            } else {
                warn!(
                    "Helper Comum: Resposta inesperada ao deletar banco de dados '{}': {}",
                    db_name, response_text
                );
            }
        }
        Err(e) => {
            warn!("Helper Comum: Falha ao deletar banco de dados de teste '{}': {:?}", db_name, e);
        }
    }
}

/// Define um esquema base comum em um banco de dados de teste existente.
///
/// Entra em pânico se a definição do esquema falhar.
///
/// # Arguments
/// * `client`: Uma referência mutável para um `TestMcpClient`.
/// * `db_name`: O nome do banco de dados onde o esquema será definido.
pub async fn define_test_db_schema(client: &mut TestMcpClient, db_name: &str) -> Result<()> {
    let schema = r#"
        define
            entity person,
                owns name,
                owns age,
                plays employment:employee;
            entity company,
                owns company-name,
                plays employment:employer;
            relation employment,
                relates employee,
                relates employer,
                owns salary;
            attribute name, value string;
            attribute company-name, value string;
            attribute age, value integer;
            attribute salary, value double;
            attribute note, value string;
            attribute timestamp, value datetime;
    "#;
    info!("Helper Comum: Definindo esquema base para o banco: '{}'", db_name);
    let define_result = client
        .call_tool(
            "define_schema",
            Some(json!({ "databaseName": db_name, "schemaDefinition": schema })),
        )
        .await
        .with_context(|| {
            format!("Helper Comum: Falha ao definir esquema base para '{}'", db_name)
        })?;

    let response_text = super::mcp_utils::get_text_from_call_result(define_result);
    if response_text != "OK" {
        bail!(
            "Helper Comum: Resposta inesperada ao definir esquema para '{}': {}",
            db_name,
            response_text
        );
    }
    info!("Helper Comum: Esquema base definido para '{}'.", db_name);
    Ok(())
}

/// Aguarda até que o endpoint `/readyz` do Typedb-MCP-Server indique que o servidor
/// e suas dependências críticas (TypeDB e JWKS, se aplicável) estão prontos.
///
/// # Arguments
/// * `docker_env_ref`: Referência ao `DockerComposeEnv` para logging em caso de timeout.
/// * `mcp_http_base_url`: A URL base HTTP ou HTTPS do servidor MCP (ex: "http://localhost:8788").
/// * `is_mcp_server_tls`: `true` se o servidor MCP estiver usando TLS (HTTPS).
/// * `expect_oauth_jwks_up`: `true` se o teste espera que o componente JWKS no `/readyz` esteja "UP".
///                           Se `false`, espera que esteja "NOT_CONFIGURED" (indicando OAuth desabilitado).
/// * `_expect_typedb_tls_connection`: (Atualmente não usado ativamente na lógica de checagem do /readyz)
///                                   Flag indicando se o MCP Server está configurado para usar TLS com o TypeDB.
/// * `timeout_duration`: A duração máxima de espera.
///
/// # Returns
/// `Result<serde_json::Value>` contendo o corpo JSON da resposta `/readyz` bem-sucedida,
/// ou um erro se o timeout_duration for atingido ou ocorrer outra falha.
pub async fn wait_for_mcp_server_ready_from_test_env(
    docker_env_ref: &DockerComposeEnv,
    mcp_http_base_url: &str,
    is_mcp_server_tls: bool,
    expect_oauth_jwks_up: bool,
    _expect_typedb_tls_connection: bool,
    timeout_duration: Duration,
) -> Result<serde_json::Value> {
    let readyz_url = format!("{}{}", mcp_http_base_url, constants::MCP_SERVER_DEFAULT_READYZ_PATH);
    info!(
        "Aguardando MCP Server em '{}' ficar pronto (timeout: {:?}, esperar JWKS UP: {})",
        readyz_url, timeout_duration, expect_oauth_jwks_up
    );

    let client_builder = reqwest::Client::builder();
    let client = if is_mcp_server_tls {
        client_builder.danger_accept_invalid_certs(true).build()?
    } else {
        client_builder.build()?
    };

    let start_time = Instant::now();
    loop {
        if start_time.elapsed() >= timeout_duration {
            error!(
                "Timeout ({:?}) atingido esperando /readyz em '{}'. Projeto Docker: '{}'.",
                timeout_duration, readyz_url, docker_env_ref.project_name()
            );
            // Tentar logar os logs do docker_env no erro de timeout
            if let Err(e) = docker_env_ref.logs_all_services() {
                error!("Falha ao obter logs do Docker Compose durante timeout do /readyz para {}: {}", docker_env_ref.project_name(), e);
            }
            bail!("/readyz timeout para '{}' após {:?}", readyz_url, timeout_duration);
        }

        match client.get(&readyz_url).send().await {
            Ok(resp) => {
                let status_code = resp.status();
                // Tentar obter o corpo como texto primeiro para logging em caso de falha de parse JSON
                let body_bytes_result = resp.bytes().await;

                let body_text_for_log = match &body_bytes_result {
                    Ok(b) => String::from_utf8_lossy(b).to_string(),
                    Err(e) => format!("<corpo não pôde ser lido: {}>", e),
                };

                if status_code != reqwest::StatusCode::OK {
                    info!( // Nível INFO para garantir visibilidade no --show-output
                        "/readyz em '{}': Recebido status HTTP não-OK: {}. Corpo: '{}'. Aguardando...",
                        readyz_url, status_code, body_text_for_log
                    );
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }

                // Se o status for OK, então tentamos parsear como JSON
                match body_bytes_result {
                    Ok(b) => match serde_json::from_slice::<serde_json::Value>(&b) {
                        Ok(json_body) => {
                            trace!(
                                "/readyz em '{}': Status {}, Corpo JSON: {:?}",
                                readyz_url,
                                status_code, // Já sabemos que é OK aqui
                                json_body
                            );
                            let overall_status =
                                json_body.get("status").and_then(|s| s.as_str()).unwrap_or("DOWN");
                            let typedb_comp_status = json_body
                                .get("components")
                                .and_then(|c| c.get("typedb"))
                                .and_then(|t| t.as_str())
                                .unwrap_or("DOWN");
                            let jwks_comp_status = json_body
                                .get("components")
                                .and_then(|c| c.get("jwks"))
                                .and_then(|j| j.as_str())
                                .unwrap_or("NOT_CONFIGURED");

                            let typedb_ok = typedb_comp_status.eq_ignore_ascii_case("UP");
                            let jwks_target_status_str =
                                if expect_oauth_jwks_up { "UP" } else { "NOT_CONFIGURED" };
                            let jwks_ok = jwks_comp_status.eq_ignore_ascii_case(jwks_target_status_str);

                            if overall_status.eq_ignore_ascii_case("UP")
                                && typedb_ok
                                && jwks_ok
                            {
                                info!("/readyz para '{}' está UP e todas as dependências configuradas estão prontas. Corpo: {}", readyz_url, serde_json::to_string(&json_body).unwrap_or_default());
                                return Ok(json_body);
                            }
                            info!(
                                "/readyz para '{}' ainda não está pronto. Status HTTP: {}, Overall: {}, TypeDB: {}, JWKS: {} (esperado JWKS: {}). Corpo: {}. Aguardando...",
                                readyz_url, status_code, overall_status, typedb_comp_status, jwks_comp_status, jwks_target_status_str, body_text_for_log
                            );
                        }
                        Err(e) => {
                            warn!(
                                "/readyz para '{}' retornou status {} mas falhou ao parsear JSON: {}. Corpo como texto: '{}'. Aguardando...",
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
            Err(e) => {
                debug!("Aguardando /readyz em '{}': {}. Tentando novamente...", readyz_url, e);
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_unique_db_name_creates_different_names() {
        let name1 = unique_db_name("prefix");
        let name2 = unique_db_name("prefix");
        assert_ne!(
            name1, name2,
            "unique_db_name deveria gerar nomes diferentes com o mesmo prefixo."
        );
        assert!(name1.starts_with("prefix"));
    }

    #[test]
    fn test_wait_for_mcp_server_ready_signature_check() {
        // Apenas para verificar a assinatura da função (teste de compilação)
        type WaitFnSig = for<'a> fn(
            &'a DockerComposeEnv,
            &'a str,
            bool,
            bool,
            bool,
            Duration,
        ) -> futures_util::future::BoxFuture<'a, Result<serde_json::Value>>; // Removido Box dyn error

        let _fn_ptr: WaitFnSig = |env, url, tls_mcp, oauth_up, typedb_tls_conn, timeout_duration| {
            Box::pin(async move {
                wait_for_mcp_server_ready_from_test_env(
                    env,
                    url,
                    tls_mcp,
                    oauth_up,
                    typedb_tls_conn,
                    timeout_duration, // Corrigido para usar timeout_duration
                )
                .await
                // map_err desnecessário se o tipo de erro já for anyhow::Error
            })
        };
    }
}

/// Aguarda que o endpoint de métricas esteja disponível e respondendo.
///
/// Realiza polling ativo tentando conectar ao endpoint até que esteja disponível
/// ou até o timeout ser atingido.
///
/// # Arguments
/// * `url`: URL completa do endpoint de métricas (ex: "http://localhost:9091/metrics")
/// * `timeout_secs`: Timeout em segundos para aguardar o endpoint
///
/// # Returns
/// * `Ok(())` se o endpoint estiver disponível
/// * `Err` se timeout ou falha na conexão
///
/// # Example
/// ```rust
/// helper_wait_for_metrics_endpoint("http://localhost:9091/metrics", 10).await?;
/// ```
pub async fn helper_wait_for_metrics_endpoint(url: &str, timeout_secs: u64) -> Result<()> {
    let timeout_duration = Duration::from_secs(timeout_secs);
    let start_time = Instant::now();
    let retry_interval = Duration::from_millis(100);

    info!("Aguardando endpoint de métricas estar disponível: {}", url);

    loop {
        if start_time.elapsed() >= timeout_duration {
            bail!("Timeout aguardando endpoint de métricas {} ({}s)", url, timeout_secs);
        }

        match reqwest::get(url).await {
            Ok(response) => {
                if response.status().is_success() {
                    info!("Endpoint de métricas disponível: {} ({})", url, response.status());
                    return Ok(());
                } else {
                    debug!("Endpoint retornou status não-sucesso: {}", response.status());
                }
            }
            Err(err) => {
                trace!("Tentativa de conexão falhou: {}", err);
            }
        }

        tokio::time::sleep(retry_interval).await;
    }
}