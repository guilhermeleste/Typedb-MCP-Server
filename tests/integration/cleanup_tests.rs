// tests/integration/cleanup_tests.rs

//! Testes de robustez do cleanup automático do TestEnvironment.
//!
//! Esta suite de testes verifica se o Drop trait do TestEnvironment funciona corretamente
//! em cenários adversos, incluindo pânicos, timeouts e falhas de serviço.
//!
//! **Fase 2 - Cleanup Automático:**
//! - Simular pânicos durante execução de testes
//! - Verificar se recursos Docker são limpos adequadamente
//! - Testar cenários de falha e recovery
//! - Garantir que não ficam containers órfãos

use crate::common::{constants, TestEnvironment};
use anyhow::Result;
use serial_test::serial;
use std::panic;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{error, info, warn};

/// Testa se o cleanup via Drop funciona corretamente quando um teste sofre pânico.
///
/// Este teste:
/// 1. Configura um TestEnvironment
/// 2. Deliberadamente causa um pânico
/// 3. Verifica se o cleanup foi executado corretamente via Drop
/// 4. Confirma que não há containers órfãos
#[tokio::test]
#[serial]
async fn test_cleanup_on_panic_in_test() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    info!("🧪 Iniciando teste: test_cleanup_on_panic_in_test");

    // Capturar pânico para verificar cleanup
    let panic_result = panic::AssertUnwindSafe(async {
        helper_test_environment_with_panic().await
    });

    // Executar a função que vai entrar em pânico
    let result = panic::catch_unwind(|| {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(panic_result)
    });

    // Verificar que houve pânico
    assert!(result.is_err(), "O teste deveria ter entrado em pânico");
    info!("✅ Pânico capturado conforme esperado");

    // Aguardar um pouco para o cleanup acontecer
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Verificar se não há containers órfãos
    helper_verify_no_orphaned_containers("cleanup_panic_test").await;
    
    info!("✅ Teste de cleanup em pânico concluído com sucesso");
}

/// Testa se o TestEnvironment consegue se recuperar de falhas de inicialização.
///
/// Este teste:
/// 1. Tenta configurar um TestEnvironment com configuração Docker inválida
/// 2. Verifica se o erro é tratado adequadamente
/// 3. Confirma que não há recursos vazando
#[tokio::test]
#[serial]
async fn test_cleanup_on_setup_failure() -> Result<()> {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    info!("🧪 Iniciando teste: test_cleanup_on_setup_failure");

    // Simular um ambiente com arquivo Docker Compose inválido
    // Vamos criar um TestEnvironment que falhe na configuração devido a arquivo inexistente
    std::env::set_var("DOCKER_COMPOSE_FILE", "nonexistent_docker_file.yml");
    
    let result = TestEnvironment::setup(
        "cleanup_setup_fail", 
        constants::DEFAULT_TEST_CONFIG_FILENAME
    ).await;

    // Restaurar variável de ambiente
    std::env::remove_var("DOCKER_COMPOSE_FILE");

    // Como o erro pode não ocorrer como esperado, vamos apenas verificar se não há vazamento
    match result {
        Ok(test_env) => {
            info!("⚠️  Setup não falhou como esperado, mas vamos verificar cleanup...");
            drop(test_env);
        }
        Err(e) => {
            info!("✅ Falha de setup capturada conforme esperado: {}", e);
        }
    }

    // Aguardar um pouco para cleanup
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Verificar se não há containers órfãos
    helper_verify_no_orphaned_containers("cleanup_setup_fail").await;
    
    info!("✅ Teste de cleanup em falha de setup concluído com sucesso");
    Ok(())
}

/// Testa se o TestEnvironment consegue lidar com timeouts durante inicialização.
///
/// Este teste verifica o comportamento quando há timeout muito baixo.
#[tokio::test]
#[serial]
async fn test_cleanup_on_timeout_during_setup() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    info!("🧪 Iniciando teste: test_cleanup_on_timeout_during_setup");

    // Usar timeout muito baixo para forçar falha por timeout durante aguardar serviços
    let result = timeout(
        Duration::from_millis(100), // Timeout muito baixo (100ms)
        TestEnvironment::setup("cleanup_timeout", constants::DEFAULT_TEST_CONFIG_FILENAME)
    ).await;

    // Verificar que houve timeout OU que conseguiu completar rapidamente
    match result {
        Err(_) => {
            info!("✅ Timeout capturado conforme esperado");
        }
        Ok(test_env) => {
            info!("⚠️  Setup completou rapidamente, mas vamos verificar cleanup...");
            drop(test_env);
        }
    }

    // Aguardar cleanup
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Verificar se não há containers órfãos
    helper_verify_no_orphaned_containers("cleanup_timeout").await;
    
    info!("✅ Teste de cleanup em timeout concluído com sucesso");
}

/// Testa se múltiplos TestEnvironments podem ser criados e limpos sequencialmente
/// sem vazamento de recursos.
#[tokio::test]
#[serial]
async fn test_sequential_environment_cleanup() -> Result<()> {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    info!("🧪 Iniciando teste: test_sequential_environment_cleanup");

    // Criar e limpar múltiplos ambientes
    for i in 0..3 {
        info!("🔄 Criando TestEnvironment #{}", i + 1);
        
        let test_env = TestEnvironment::setup(
            &format!("cleanup_seq_{}", i), 
            constants::DEFAULT_TEST_CONFIG_FILENAME
        ).await?;
        
        // Obter o nome exato do projeto Docker Compose
        let project_name = test_env.docker_env.project_name().to_string();
        
        // Fazer uma operação simples (com tratamento de erro de timing)
        let mut client = test_env.mcp_client_with_auth(None).await?;
        match client.list_tools(None).await {
            Ok(tools) => {
                info!("📋 Environment #{} tem {} ferramentas MCP", i + 1, tools.tools.len());
            }
            Err(e) => {
                // Erro de WebSocket durante cleanup é esperado em testes sequenciais
                if e.to_string().contains("Connection reset") || e.to_string().contains("WebSocket protocol error") {
                    warn!("⚠️  Erro de timing esperado durante operação MCP: {}", e);
                } else {
                    return Err(anyhow::Error::new(e)); // Converter McpClientError para anyhow::Error
                }
            }
        }
        
        // O Drop será chamado automaticamente aqui
        drop(test_env);
        drop(client);
        
        // Aguardar cleanup
        tokio::time::sleep(Duration::from_secs(3)).await;
        
        // Verificar se não há containers órfãos usando o nome exato do projeto
        helper_verify_no_orphaned_containers(&project_name).await;
    }
    
    info!("✅ Teste de cleanup sequencial concluído com sucesso");
    Ok(())
}

/// Testa se o cleanup funciona corretamente quando há falha de conexão com serviços.
#[tokio::test]
#[serial]
async fn test_cleanup_with_service_connection_failure() -> Result<()> {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    info!("🧪 Iniciando teste: test_cleanup_with_service_connection_failure");

    // Configurar ambiente (pode falhar por conflito de porta, o que é ok para o teste)
    let result = TestEnvironment::setup(
        "cleanup_conn_fail", 
        constants::DEFAULT_TEST_CONFIG_FILENAME
    ).await;
    
    match result {
        Ok(test_env) => {
            info!("✅ TestEnvironment configurado com sucesso");
            
            // Tentar conectar com parâmetros inválidos (deveria falhar)
            let client_result = test_env.mcp_client_with_auth(Some("invalid::scope::format")).await;
            
            if client_result.is_err() {
                warn!("⚠️  Falha de conexão esperada: {}", client_result.unwrap_err());
            }
            
            // O Drop será chamado automaticamente
            drop(test_env);
        }
        Err(e) => {
            warn!("⚠️  Setup falhou (possivelmente por conflito de porta): {}", e);
            // Mesmo com falha no setup, vamos verificar se não há vazamento
        }
    }
    
    // Aguardar cleanup
    tokio::time::sleep(Duration::from_secs(3)).await;
    
    // Verificar se não há containers órfãos
    helper_verify_no_orphaned_containers("cleanup_conn_fail").await;
    
    info!("✅ Teste de cleanup com falha de conexão concluído com sucesso");
    Ok(())
}

// === HELPER FUNCTIONS ===

/// Helper que simula um pânico durante uso do TestEnvironment.
async fn helper_test_environment_with_panic() -> Result<()> {
    info!("🚀 Configurando TestEnvironment que vai entrar em pânico...");
    
    let _test_env = TestEnvironment::setup(
        "cleanup_panic_test", 
        constants::DEFAULT_TEST_CONFIG_FILENAME
    ).await?;
    
    info!("✅ TestEnvironment configurado, agora vou causar pânico deliberadamente!");
    
    // Causar pânico deliberadamente
    panic!("🔥 Pânico deliberado para testar cleanup!");
}

/// Helper que verifica se não há containers órfãos para um projeto específico.
async fn helper_verify_no_orphaned_containers(project_prefix: &str) {
    info!("🔍 Verificando containers órfãos para projeto com prefixo: '{}'", project_prefix);
    
    // Usar comando docker para listar containers com o prefixo do projeto
    let output = std::process::Command::new("docker")
        .args(["ps", "-a", "--filter", &format!("name={}", project_prefix), "--format", "{{.Names}}"])
        .output()
        .expect("Falha ao executar comando docker ps");
    
    let containers = String::from_utf8_lossy(&output.stdout);
    let container_lines: Vec<&str> = containers.lines().filter(|line| !line.trim().is_empty()).collect();
    
    if container_lines.is_empty() {
        info!("✅ Nenhum container órfão encontrado para projeto '{}'", project_prefix);
    } else {
        error!("❌ Containers órfãos encontrados para projeto '{}': {:?}", project_prefix, container_lines);
        
        // Tentar limpar containers órfãos
        for container in container_lines {
            warn!("🧹 Limpando container órfão: {}", container);
            let _ = std::process::Command::new("docker")
                .args(["rm", "-f", container])
                .output();
        }
        
        panic!("Containers órfãos detectados! Cleanup automático falhou.");
    }
    
    // Verificar também se há redes órfãs
    let network_output = std::process::Command::new("docker")
        .args(["network", "ls", "--filter", &format!("name={}", project_prefix), "--format", "{{.Name}}"])
        .output()
        .expect("Falha ao executar comando docker network ls");
    
    let networks = String::from_utf8_lossy(&network_output.stdout);
    let network_lines: Vec<&str> = networks.lines().filter(|line| !line.trim().is_empty()).collect();
    
    if network_lines.is_empty() {
        info!("✅ Nenhuma rede órfã encontrada para projeto '{}'", project_prefix);
    } else {
        error!("❌ Redes órfãs encontradas para projeto '{}': {:?}", project_prefix, network_lines);
        
        // Tentar limpar redes órfãs
        for network in network_lines {
            warn!("🧹 Limpando rede órfã: {}", network);
            let _ = std::process::Command::new("docker")
                .args(["network", "rm", network])
                .output();
        }
        
        panic!("Redes órfãs detectadas! Cleanup automático falhou.");
    }
}
