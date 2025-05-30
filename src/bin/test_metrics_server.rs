//! Teste isolado do servidor de métricas
//! 
//! Este binário testa apenas o `metrics-exporter-prometheus` com `with_http_listener`
//! para isolar problemas de compatibilidade com hyper/tokio.

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::net::SocketAddr;
use std::time::Duration;
use tracing::{info, error};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configurar logging básico
    tracing_subscriber::fmt::init();

    let metrics_addr: SocketAddr = "0.0.0.0:9090".parse()?;
    info!("🔧 [ISOLATED_TEST] Iniciando servidor de métricas isolado em {}", metrics_addr);

    // Tentar criar o servidor de métricas com listener HTTP
    let _handle: PrometheusHandle = match PrometheusBuilder::new()
        .with_http_listener(metrics_addr)
        .install_recorder()
    {
        Ok(handle) => {
            info!("✅ [ISOLATED_TEST] Servidor de métricas iniciado com sucesso!");
            handle
        }
        Err(e) => {
            error!("❌ [ISOLATED_TEST] Falha ao iniciar servidor de métricas: {}", e);
            return Err(e.into());
        }
    };

    info!("⏳ [ISOLATED_TEST] Servidor rodando. Aguardando por 60 segundos para testes...");
    info!("🌐 [ISOLATED_TEST] Teste: curl http://localhost:9090/metrics (de dentro do container)");
    info!("🌐 [ISOLATED_TEST] Teste: curl http://localhost:9091/metrics (do host)");

    // Registrar uma métrica simples para testar
    metrics::counter!("test_isolated_metrics_counter").increment(1);
    info!("📊 [ISOLATED_TEST] Métrica de teste registrada: test_isolated_metrics_counter");

    // Aguardar para permitir testes manuais
    std::thread::sleep(Duration::from_secs(60));
    
    info!("🔚 [ISOLATED_TEST] Finalizando teste isolado.");
    Ok(())
}
