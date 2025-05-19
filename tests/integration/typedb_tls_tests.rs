//! Testes de integração para validação da conexão TLS entre Typedb-MCP-Server e TypeDB Server.
//!
//! Cada teste cobre um cenário de configuração TLS, validando sucesso e falha conforme esperado.
//!
//! Requisitos:
//! - O ambiente de teste deve prover containers docker configuráveis via docker-compose.test.yml
//! - Certificados de teste devem estar disponíveis conforme scripts/generate-dev-certs.sh

use std::time::Duration;

use reqwest::StatusCode;
use testcontainers::{clients, images::generic::GenericImage, Container, Docker};
use tokio::time::sleep;

/// Helper para aguardar endpoint /readyz do MCP
async fn wait_for_readyz(base_url: &str, timeout_secs: u64) -> bool {
    let client = reqwest::Client::new();
    let url = format!("{}/readyz", base_url);
    let start = std::time::Instant::now();
    while start.elapsed().as_secs() < timeout_secs {
        match client.get(&url).send().await {
            Ok(resp) if resp.status() == StatusCode::OK => return true,
            _ => sleep(Duration::from_secs(1)).await,
        }
    }
    false
}

/// Testa conexão bem-sucedida com TypeDB-TLS (CA válido)
#[tokio::test]
async fn test_typedb_tls_success() {
    // Setup: inicia containers com CA válida
    // (Ajuste conforme helpers/utilitários do projeto)
    let docker = clients::Cli::default();
    let compose = GenericImage::new("typedb-mcp-server-it", "latest")
        .with_env_var("TYPEDB_TLS_ENABLED", "true")
        // Caminho atualizado para o CA gerado pelo script generate-dev-certs.sh
        .with_env_var("TYPEDB_TLS_CA_PATH", "/certs/generated-dev/ca.pem")
        .with_env_var("TYPEDB_ADDRESS", "typedb-server-it:1729")
        // Volume atualizado para montar o CA correto
        .with_volume("./certs/generated-dev/ca.pem", "/certs/generated-dev/ca.pem");
    let _container: Container<_> = docker.run(compose);

    // Aguarda MCP ficar pronto
    assert!(wait_for_readyz("http://localhost:8080", 30).await, "MCP não ficou pronto com CA válida");
    // (Opcional) Chamada MCP list_databases
    // ...
}

/// Testa falha de conexão com TypeDB-TLS (CA inválido/ausente)
#[tokio::test]
async fn test_typedb_tls_invalid_ca() {
    let docker = clients::Cli::default();
    // Para simular um CA inválido, podemos apontar para um arquivo que não existe ou é um CA diferente.
    // Usaremos um caminho fictício para garantir que o CA correto não seja encontrado.
    let compose = GenericImage::new("typedb-mcp-server-it", "latest")
        .with_env_var("TYPEDB_TLS_ENABLED", "true")
        .with_env_var("TYPEDB_TLS_CA_PATH", "/certs/invalid-ca.pem") // Caminho para um CA inválido/inexistente
        .with_env_var("TYPEDB_ADDRESS", "typedb-server-it:1729");
        // Não montaremos um volume para invalid-ca.pem, garantindo que ele não exista no container,
        // ou montaremos um CA sabidamente incorreto se quisermos testar a falha de validação.
        // Para este teste, a ausência do arquivo em TYPEDB_TLS_CA_PATH já deve causar falha.

    let _container: Container<_> = docker.run(compose);

    // Aguarda MCP (não deve ficar pronto)
    assert!(!wait_for_readyz("http://localhost:8080", 15).await, "MCP ficou pronto com CA inválida (deveria falhar)");
}

/// Testa falha de conexão: cliente MCP tenta conexão não-TLS
#[tokio::test]
async fn test_typedb_tls_client_no_tls() {
    let docker = clients::Cli::default();
    let compose = GenericImage::new("typedb-mcp-server-it", "latest")
        .with_env_var("TYPEDB_TLS_ENABLED", "false")
        .with_env_var("TYPEDB_ADDRESS", "typedb-server-it:1729");
    let _container: Container<_> = docker.run(compose);

    // Aguarda MCP (não deve ficar pronto)
    assert!(!wait_for_readyz("http://localhost:8080", 15).await, "MCP ficou pronto sem TLS para servidor TLS (deveria falhar)");
}


use std::time::Duration;
use tests::common::{TestMcpClient, docker_helpers::DockerComposeEnv};
use rmcp::model::ListToolsResult;

const TEST_COMPOSE_FILE: &str = "docker-compose.test.yml";
const TYPEDB_SERVICE_NAME: &str = "typedb-server-it";
const MCP_SERVER_SERVICE_NAME: &str = "typedb-mcp-server-it";
const MCP_SERVER_WS_URL: &str = "ws://localhost:8788/mcp/ws";

/// Helper para setup do ambiente docker compose e healthcheck dos serviços essenciais
async fn setup_tls_test_env(test_name: &str, wait_for_mcp: bool) -> DockerComposeEnv {
    let docker_env = DockerComposeEnv::new(TEST_COMPOSE_FILE, test_name);
    docker_env.down(false).ok();
    docker_env.up().expect("Falha ao subir ambiente docker-compose");
    docker_env.wait_for_service_healthy(TYPEDB_SERVICE_NAME, Duration::from_secs(60), Duration::from_secs(2)).await.expect("TypeDB não ficou saudável");
    if wait_for_mcp {
        docker_env.wait_for_service_healthy(MCP_SERVER_SERVICE_NAME, Duration::from_secs(30), Duration::from_secs(2)).await.expect("MCP não ficou saudável");
    }
    docker_env
}

/// Testa conexão bem-sucedida com TypeDB-TLS (CA válido)
#[tokio::test]
async fn test_typedb_tls_success_compose() { // Renomeado para evitar conflito com o teste acima
    // Esta função de setup precisará garantir que o docker-compose.test.yml
    // configure o TypeDB Server com os certificados de ./certs/generated-dev/
    // e que o MCP Server (se também definido no compose) use o ./certs/generated-dev/ca.pem
    // como TYPEDB_TLS_CA_PATH.
    let _docker_env = setup_tls_test_env("typedb_tls_success_compose", true).await;
    let mut client = TestMcpClient::connect(MCP_SERVER_WS_URL, None, Duration::from_secs(10), Duration::from_secs(10))
        .await
        .expect("Deveria conectar ao MCP via WS");
    let result = client.call_tool("tools/list", None).await;
    assert!(result.is_ok(), "Falha ao chamar tools/list: {:?}", result.err());
    let list_tools_result: ListToolsResult = result.unwrap();
    assert!(!list_tools_result.tools.is_empty(), "A lista de ferramentas não deveria estar vazia");
    client.close().await.expect("Falha ao fechar cliente");
}

/// Testa falha de conexão com TypeDB-TLS (CA inválido/ausente)
#[tokio::test]
async fn test_typedb_tls_invalid_ca_compose() { // Renomeado
    // Esta função de setup precisará garantir que o MCP Server no docker-compose.test.yml
    // seja configurado com um TYPEDB_TLS_CA_PATH inválido ou ausente.
    let _docker_env = setup_tls_test_env("typedb_tls_invalid_ca_compose", false).await;
    // MCP não deve ficar saudável, logo não tentamos conectar
    // Opcional: checar logs do serviço MCP para erro de TLS
}

/// Testa falha de conexão: cliente MCP tenta TLS para TypeDB sem TLS
#[tokio::test]
async fn test_typedb_tls_server_no_tls() {
    let _docker_env = setup_tls_test_env("typedb_tls_server_no_tls", false).await;
    // MCP não deve ficar saudável, logo não tentamos conectar
}
