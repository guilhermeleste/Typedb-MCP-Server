// tests/common/test_utils.rs

//! Utilitários e helpers comuns para os testes de integração do Typedb-MCP-Server.
//! Este módulo centraliza funções repetitivas usadas em múltiplas suítes de teste.

use anyhow::{bail, Context as AnyhowContext, Result};
use serde_json::json; // Necessário para `create_test_db` e `define_test_db_schema`
use std::time::{Duration, Instant};
use tracing::{debug, error, info, trace, warn}; // Adicionando trace
use uuid::Uuid;

// Importar tipos do mesmo crate `common`
use super::client::TestMcpClient;
use super::constants; // Para MCP_SERVER_DEFAULT_READYZ_PATH
use super::docker_helpers::DockerComposeEnv; // Para logging no wait_for_mcp_server_ready

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
            person sub entity,
                owns name,
                owns age,
                plays employment:employee;
            company sub entity,
                owns company-name,
                plays employment:employer;
            employment sub relation,
                relates employee,
                relates employer,
                owns salary;
            name sub attribute, value string;
            company-name sub attribute, value string;
            age sub attribute, value long;
            salary sub attribute, value double;
            note sub attribute, value string;
            timestamp sub attribute, value datetime;
    "#;
    info!("Helper Comum: Definindo esquema base para o banco: '{}'", db_name);
    let define_result = client
        .call_tool(
            "define_schema",
            Some(json!({ "database_name": db_name, "schema_definition": schema })),
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
/// * `timeout`: A duração máxima de espera.
///
/// # Returns
/// `Result<serde_json::Value>` contendo o corpo JSON da resposta `/readyz` bem-sucedida,
/// ou um erro se o timeout for atingido ou ocorrer outra falha.
pub async fn wait_for_mcp_server_ready_from_test_env(
    docker_env_ref: &DockerComposeEnv, // Mudança: Recebe &DockerComposeEnv para logs
    mcp_http_base_url: &str,           // Mudança: Recebe URL base
    is_mcp_server_tls: bool,           // Mudança: Recebe flag TLS do servidor MCP
    expect_oauth_jwks_up: bool,        // Mudança: Recebe flag de expectativa do JWKS
    _expect_typedb_tls_connection: bool, // Mantido, mas não usado ativamente na checagem do JSON /readyz
    timeout: Duration,
) -> Result<serde_json::Value> {
    let readyz_url = format!("{}{}", mcp_http_base_url, constants::MCP_SERVER_DEFAULT_READYZ_PATH);
    info!(
        "Aguardando MCP Server em '{}' ficar pronto (timeout: {:?}, esperar JWKS UP: {})",
        readyz_url, timeout, expect_oauth_jwks_up
    );

    let client_builder = reqwest::Client::builder();
    let client = if is_mcp_server_tls {
        client_builder.danger_accept_invalid_certs(true).build()?
    } else {
        client_builder.build()?
    };

    let start_time = Instant::now();
    loop {
        if start_time.elapsed() >= timeout {
            docker_env_ref.logs_all_services().unwrap_or_else(|e| {
                error!(
                    "Falha ao obter logs do Docker Compose durante timeout do /readyz para {}: {}",
                    docker_env_ref.project_name(),
                    e
                );
            });
            bail!("/readyz timeout para '{}' após {:?}", readyz_url, timeout);
        }

        match client.get(&readyz_url).send().await {
            Ok(resp) => {
                let status_code = resp.status();
                match resp.json::<serde_json::Value>().await {
                    Ok(json_body) => {
                        trace!(
                            "/readyz em '{}': Status {}, Corpo: {:?}",
                            readyz_url,
                            status_code,
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

                        if status_code == reqwest::StatusCode::OK
                            && overall_status.eq_ignore_ascii_case("UP")
                            && typedb_ok
                            && jwks_ok
                        {
                            info!("/readyz para '{}' está UP e todas as dependências configuradas estão prontas.", readyz_url);
                            return Ok(json_body);
                        }
                        debug!(
                            "/readyz para '{}' ainda não está pronto. Status HTTP: {}, Overall: {}, TypeDB: {}, JWKS: {} (esperado JWKS: {}). Aguardando...",
                            readyz_url, status_code, overall_status, typedb_comp_status, jwks_comp_status, jwks_target_status_str
                        );
                    }
                    Err(e) => {
                        let body_text_result = client.get(&readyz_url).send().await; // Re-request para obter corpo
                        let body_text = match body_text_result {
                            Ok(r) => r.text().await.unwrap_or_else(|_| "Falha ao ler corpo como texto.".to_string()),
                            Err(_) => "Falha ao re-requisitar para obter corpo como texto.".to_string(),
                        };
                        debug!("/readyz para '{}' retornou status {} mas falhou ao parsear JSON: {}. Corpo como texto: '{}'. Aguardando...", readyz_url, status_code, e, body_text);
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
        // A assinatura agora recebe 6 argumentos.
        type WaitFnSig = for<'a> fn(
            &'a DockerComposeEnv,
            &'a str, // mcp_http_base_url
            bool,    // is_mcp_server_tls
            bool,    // expect_oauth_jwks_up
            bool,    // expect_typedb_tls_connection
            Duration,
        ) -> futures_util::future::BoxFuture<'a, Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>>>;

        let _fn_ptr: WaitFnSig = |env, url, tls_mcp, oauth_up, typedb_tls_conn, timeout| {
            Box::pin(async move {
                wait_for_mcp_server_ready_from_test_env(
                    env,
                    url,
                    tls_mcp,
                    oauth_up,
                    typedb_tls_conn,
                    timeout,
                )
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })
            })
        };
    }
}