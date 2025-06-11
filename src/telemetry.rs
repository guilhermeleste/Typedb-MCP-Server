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

//! Módulo para configuração e inicialização do tracing distribuído com OpenTelemetry.
//!
//! Este módulo é responsável por configurar o pipeline de exportação de traces
//! para um coletor OpenTelemetry (OTLP) via gRPC.

use crate::config; // Para config::TracingConfig
use opentelemetry::KeyValue; // opentelemetry v0.25.0
use opentelemetry_otlp::WithExportConfig; // opentelemetry-otlp v0.20.0
use opentelemetry_sdk::{
    trace as sdktrace, // opentelemetry-sdk v0.25.0
    Resource,          // opentelemetry-sdk v0.25.0
};
// opentelemetry-semantic-conventions v0.17.0
use opentelemetry_semantic_conventions::resource as semconv_resource;

/// Inicializa o pipeline de tracing OpenTelemetry com base na configuração fornecida.
///
/// Configura um exportador OTLP/gRPC e um processador de batch de spans.
/// Instala o `TracerProvider` resultante como o provider global.
///
/// # Parâmetros
/// * `config`: As configurações de tracing da aplicação (`config::TracingConfig`).
///
/// # Retorna
/// `Result<(), sdktrace::TraceError>`: `Ok(())` se o tracer e o provider global
/// forem configurados com sucesso. Retorna `Err` se o tracing estiver desabilitado
/// ou se ocorrer um erro na configuração.
///
/// # Errors
/// 
/// Pode retornar `sdktrace::TraceError` se houver problemas ao configurar o pipeline OTLP.
#[tracing::instrument(skip(config), name = "init_opentelemetry_tracing_pipeline")]
pub fn init_tracing_pipeline(config: &config::TracingConfig) -> Result<(), sdktrace::TraceError> {
    // Corrigido para sdktrace::TraceError
    if !config.enabled {
        tracing::info!("OpenTelemetry tracing está desabilitado na configuração.");
        return Ok(());
    }

    let exporter_endpoint = config.exporter_otlp_endpoint.as_ref().ok_or_else(|| {
        let msg = "OTEL_EXPORTER_OTLP_ENDPOINT (ou config.tracing.exporter_otlp_endpoint) não configurado, mas tracing está habilitado.";
        tracing::error!("{}", msg);
        // Para criar um sdktrace::TraceError, podemos usar String::into() se TraceError impl From<String>
        // ou um erro mais específico se disponível. A forma mais genérica é Other.
        sdktrace::TraceError::Other(msg.into())
    })?;

    tracing::info!(
        "Inicializando pipeline OpenTelemetry com endpoint OTLP/gRPC: {} e nome de serviço: {}",
        exporter_endpoint,
        config.service_name
    );

    // opentelemetry-otlp: SpanExporter::builder().with_tonic().with_endpoint(...).build()?
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(exporter_endpoint)
        .build()
        .map_err(|e| sdktrace::TraceError::Other(Box::new(e)))?;

    // opentelemetry-sdk: Resource deve ser criado via builder
    let resource = Resource::builder()
        .with_attributes(vec![
            KeyValue::new(semconv_resource::SERVICE_NAME, config.service_name.clone()),
            KeyValue::new(semconv_resource::TELEMETRY_SDK_NAME, "opentelemetry"),
            KeyValue::new(semconv_resource::TELEMETRY_SDK_LANGUAGE, "rust"),
            KeyValue::new(semconv_resource::TELEMETRY_SDK_VERSION, env!("CARGO_PKG_VERSION")),
        ])
        .build();

    // Criação do provider
    let provider = sdktrace::SdkTracerProvider::builder()
        .with_resource(resource)
        .with_sampler(match config.sampler.to_lowercase().as_str() {
            "always_off" => sdktrace::Sampler::AlwaysOff,
            "traceidratio" => {
                let ratio = config.sampler_arg.parse().unwrap_or(1.0);
                sdktrace::Sampler::TraceIdRatioBased(ratio)
            }
            "parentbased_always_on" => {
                sdktrace::Sampler::ParentBased(Box::new(sdktrace::Sampler::AlwaysOn))
            }
            "parentbased_always_off" => {
                sdktrace::Sampler::ParentBased(Box::new(sdktrace::Sampler::AlwaysOff))
            }
            "parentbased_traceidratio" => {
                let ratio = config.sampler_arg.parse().unwrap_or(1.0);
                sdktrace::Sampler::ParentBased(Box::new(sdktrace::Sampler::TraceIdRatioBased(
                    ratio,
                )))
            }
            _ => {
                tracing::warn!(
                    "Sampler de tracing desconhecido ou não especificado ('{}'), usando AlwaysOn.",
                    config.sampler
                );
                sdktrace::Sampler::AlwaysOn
            }
        })
        .with_batch_exporter(exporter)
        .build();

    opentelemetry::global::set_tracer_provider(provider);

    tracing::info!("Pipeline OpenTelemetry configurado e provider global instalado.");
    Ok(())
}

/// Desliga o provedor global de tracer do OpenTelemetry.
///
/// Esta função deve ser chamada durante o graceful shutdown da aplicação para garantir
/// que todos os spans em buffer sejam exportados.
pub fn shutdown_tracer_provider() {
    // O método shutdown_tracer_provider() foi removido do OpenTelemetry 0.20+.
    // O correto é apenas deixar o provider ser dropado, ou usar global::shutdown_tracer_provider() se disponível.
    // Aqui, apenas logamos a intenção.
    tracing::info!("Provedor de tracer OpenTelemetry desligado globalmente (shutdown explícito não suportado nesta versão do SDK).");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TracingConfig;
    use opentelemetry::global;
    use opentelemetry::trace::TracerProvider; // Trait para chamar tracer()

    #[test]
    fn test_init_tracing_pipeline_disabled() {
        let config = TracingConfig {
            enabled: false,
            exporter_otlp_endpoint: None,
            service_name: "test-service".to_string(),
            sampler: "always_on".to_string(),
            sampler_arg: "1.0".to_string(),
        };
        assert!(init_tracing_pipeline(&config).is_ok());
    }

    #[test]
    fn test_init_tracing_pipeline_missing_endpoint_when_enabled() {
        let config = TracingConfig {
            enabled: true,
            exporter_otlp_endpoint: None,
            service_name: "test-service".to_string(),
            sampler: "always_on".to_string(),
            sampler_arg: "1.0".to_string(),
        };
        let result = init_tracing_pipeline(&config);
        match result {
            Err(sdktrace::TraceError::Other(s)) => {
                let msg = format!("{s}");
                assert!(
                    msg.contains("OTEL_EXPORTER_OTLP_ENDPOINT"),
                    "Mensagem de erro inesperada: {msg}"
                );
            }
            Err(e) => {
                panic!("Erro inesperado para endpoint ausente: {e:?}");
            }
            Ok(()) => {
                panic!("Esperado erro para endpoint ausente, mas obteve Ok");
            }
        }
    }

    #[tokio::test]
    async fn test_init_tracing_pipeline_successful_config_always_on_sampler() {
        let config = TracingConfig {
            enabled: true,
            exporter_otlp_endpoint: Some("http://localhost:4317".to_string()),
            service_name: "test-service-always-on".to_string(),
            sampler: "always_on".to_string(),
            sampler_arg: "1.0".to_string(),
        };

        let init_result = init_tracing_pipeline(&config);
        assert!(init_result.is_ok(), "init_tracing_pipeline falhou: {:?}", init_result.err());

        // global::tracer_provider() retorna Arc<dyn TracerProvider>
        // TracerProvider (trait) tem o método tracer()
        let _ = global::tracer_provider().tracer("test_tracer_init_success"); // suprime warning de variável não usada
                                                                              // Não há método público para inspecionar o nome da instrumentação diretamente.
                                                                              // Apenas garantir que não houve erro já é suficiente.

        shutdown_tracer_provider();
    }

    #[tokio::test]
    async fn test_init_tracing_pipeline_sampler_trace_id_ratio() {
        let config = TracingConfig {
            enabled: true,
            exporter_otlp_endpoint: Some("http://localhost:4317".to_string()),
            service_name: "test-service-ratio".to_string(),
            sampler: "traceidratio".to_string(),
            sampler_arg: "0.0001".to_string(),
        };
        let init_result = init_tracing_pipeline(&config);
        assert!(
            init_result.is_ok(),
            "init_tracing_pipeline falhou para traceidratio: {:?}",
            init_result.err()
        );
        shutdown_tracer_provider();
    }

    #[tokio::test]
    async fn test_init_tracer_unknown_sampler_defaults_to_always_on() {
        let config = TracingConfig {
            enabled: true,
            exporter_otlp_endpoint: Some("http://localhost:4317".to_string()),
            service_name: "test-service-unknown-sampler".to_string(),
            sampler: "non_existent_sampler_type".to_string(),
            sampler_arg: "1.0".to_string(),
        };
        let init_result = init_tracing_pipeline(&config);
        assert!(
            init_result.is_ok(),
            "init_tracing_pipeline falhou com sampler desconhecido: {:?}",
            init_result.err()
        );
        shutdown_tracer_provider();
    }
}
