// tests/common/test_utils.rs

//! Utilitários e helpers comuns para os testes de integração do Typedb-MCP-Server.
//! Este módulo visa centralizar funções repetitivas usadas em múltiplas suítes de teste.

use anyhow::{bail, Context as AnyhowContext, Result}; // Adicionado bail
use serde_json::json;
use std::time::{Duration, Instant}; // Adicionado Instant
use tracing::{debug, error, info, trace, warn}; // Adicionado error, trace, debug
use uuid::Uuid;

use super::{client::TestMcpClient, test_env::TestEnvironment};
use reqwest::StatusCode;

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
    let result = client
        .call_tool("create_database", Some(json!({ "name": db_name })))
        .await
        .with_context(|| format!("Helper Comum: Falha ao chamar create_database para '{}'", db_name))?;

    let response_text = super::mcp_utils::get_text_from_call_result(result);
    if response_text != "OK" {
        bail!( // Usar bail! de anyhow
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
    match client
        .call_tool("delete_database", Some(json!({ "name": db_name })))
        .await
    {
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
            warn!(
                "Helper Comum: Falha ao deletar banco de dados de teste '{}': {:?}",
                db_name, e
            );
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
        .with_context(|| format!("Helper Comum: Falha ao definir esquema base para '{}'", db_name))?;

    let response_text = super::mcp_utils::get_text_from_call_result(define_result);
    if response_text != "OK" {
        bail!( // Usar bail!
            "Helper Comum: Resposta inesperada ao definir esquema para '{}': {}",
            db_name,
            response_text
        );
    }
    info!("Helper Comum: Esquema base definido para '{}'.", db_name);
    Ok(())
}


/// Aguarda até que o endpoint `/readyz` do Typedb-MCP-Server (acessado via `TestEnvironment`)
/// indique que o servidor e suas dependências críticas estão prontos.
///
/// # Arguments
/// * `test_env`: Uma referência ao `TestEnvironment` que contém as URLs e flags de configuração.
/// * `timeout`: A duração máxima de espera.
///
/// # Returns
/// `Result<serde_json::Value>` contendo o corpo JSON da resposta `/readyz` bem-sucedida,
/// ou um erro se o timeout for atingido ou ocorrer outra falha.
pub async fn wait_for_mcp_server_ready_from_test_env(
    test_env: &TestEnvironment,
    timeout: Duration,
) -> Result<serde_json::Value> {
    let readyz_url = format!(
        "{}{}",
        test_env.mcp_http_base_url,
        super::constants::MCP_SERVER_DEFAULT_READYZ_PATH
    );
    info!(
        "Helper Comum: Aguardando MCP Server em '{}' ficar pronto (timeout: {:?})",
        readyz_url, timeout
    );

    let client_builder = reqwest::Client::builder();
    let client = if test_env.is_mcp_server_tls {
        client_builder.danger_accept_invalid_certs(true).build()?
    } else {
        client_builder.build()?
    };

    let start_time = Instant::now(); // Corrigido: Instant importado
    loop {
        if start_time.elapsed() >= timeout {
            test_env.docker_env.logs_all_services().unwrap_or_else(|e| {
                error!("Helper Comum: Falha ao obter logs do Docker Compose durante timeout do /readyz: {}", e); // Corrigido: error!
            });
            bail!("Helper Comum: /readyz timeout para '{}' após {:?}", readyz_url, timeout); // Corrigido: bail!
        }

        match client.get(&readyz_url).send().await {
            Ok(resp) => {
                let status_code = resp.status();
                match resp.json::<serde_json::Value>().await {
                    Ok(json_body) => {
                        trace!("Helper Comum: /readyz em '{}': Status {}, Corpo: {:?}", readyz_url, status_code, json_body); // Corrigido: trace!
                        let overall_status = json_body.get("status").and_then(|s| s.as_str()).unwrap_or("DOWN");
                        let typedb_component_status = json_body.get("components").and_then(|c| c.get("typedb")).and_then(|t| t.as_str()).unwrap_or("DOWN");
                        let jwks_component_status = json_body.get("components").and_then(|c| c.get("jwks")).and_then(|j| j.as_str()).unwrap_or("NOT_CONFIGURED");

                        let typedb_ok = typedb_component_status.eq_ignore_ascii_case("UP");
                        let jwks_ok = if test_env.is_oauth_enabled {
                            jwks_component_status.eq_ignore_ascii_case("UP")
                        } else {
                            jwks_component_status.eq_ignore_ascii_case("NOT_CONFIGURED") || !test_env.is_oauth_enabled
                        };

                        if status_code == StatusCode::OK && overall_status.eq_ignore_ascii_case("UP") && typedb_ok && jwks_ok {
                            info!("Helper Comum: /readyz para '{}' está UP e todas as dependências configuradas estão prontas.", readyz_url);
                            return Ok(json_body);
                        } else {
                            debug!( // debug! já estava importado
                                "Helper Comum: /readyz para '{}' ainda não está pronto. Status HTTP: {}, Overall: {}, TypeDB: {}, JWKS: {}. Aguardando...",
                                readyz_url, status_code, overall_status, typedb_component_status, jwks_component_status
                            );
                        }
                    }
                    Err(e) => {
                        if let Ok(resp_text_fallback_result) = client.get(&readyz_url).send().await {
                            if let Ok(resp_text_fallback) = resp_text_fallback_result.text().await {
                                debug!("Helper Comum: /readyz para '{}' retornou status {} mas falhou ao parsear JSON: {}. Corpo como texto: '{}'. Aguardando...", readyz_url, status_code, e, resp_text_fallback);
                            } else {
                                 debug!("Helper Comum: /readyz para '{}' retornou status {} mas falhou ao parsear JSON: {}. Falha também ao ler corpo como texto. Aguardando...", readyz_url, status_code, e);
                            }
                        } else {
                             debug!("Helper Comum: /readyz para '{}' retornou status {} mas falhou ao parsear JSON: {}. Falha também ao re-requisitar para ler corpo como texto. Aguardando...", readyz_url, status_code, e);
                        }
                    }
                }
            }
            Err(e) => {
                debug!("Helper Comum: Aguardando /readyz em '{}': {}. Tentando novamente...", readyz_url, e);
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::constants;
    use serial_test::serial;

    #[test]
    fn test_unique_db_name_creates_different_names() {
        let name1 = unique_db_name("prefix");
        let name2 = unique_db_name("prefix");
        assert_ne!(name1, name2, "unique_db_name deveria gerar nomes diferentes para o mesmo prefixo.");
        assert!(name1.starts_with("prefix_"));
    }

    #[tokio::test]
    #[serial]
    #[ignore]
    async fn test_wait_for_readyz_helper_example_usage() -> Result<()> {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        
        let test_env = TestEnvironment::setup(
            "wait_readyz_helper_usage",
            constants::DEFAULT_TEST_CONFIG_FILENAME,
        ).await?;
        
        let readyz_json = wait_for_mcp_server_ready_from_test_env(
            &test_env,
            constants::DEFAULT_MCP_SERVER_READY_TIMEOUT
        ).await?;

        assert_eq!(readyz_json.get("status").and_then(|s| s.as_str()), Some("UP"));
        info!("Exemplo de uso wait_for_readyz_helper: /readyz está UP.");

        Ok(())
    }
}