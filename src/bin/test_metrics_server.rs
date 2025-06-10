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

//! Teste isolado do servidor de métricas
//!
//! Este binário testa apenas o `metrics-exporter-prometheus` com `with_http_listener`
//! para isolar problemas de compatibilidade com hyper/tokio.

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::net::SocketAddr;
use std::time::Duration;
use tracing::{error, info};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configurar logging básico
    tracing_subscriber::fmt::init();

    let metrics_addr: SocketAddr = "0.0.0.0:9090".parse()?;
    info!("🔧 [ISOLATED_TEST] Iniciando servidor de métricas isolado em {}", metrics_addr);

    // Tentar criar o servidor de métricas com listener HTTP
    let _handle: PrometheusHandle =
        match PrometheusBuilder::new().with_http_listener(metrics_addr).install_recorder() {
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
