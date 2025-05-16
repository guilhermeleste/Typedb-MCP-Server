// src/metrics.rs

// Licença Apache 2.0
// Copyright [ANO_ATUAL] [SEU_NOME_OU_ORGANIZACAO]
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Módulo para definição e registro de métricas da aplicação.
//!
//! Este módulo utiliza a crate `metrics` como uma fachada para a instrumentação
//! e define todas as métricas que serão expostas pelo `Typedb-MCP-Server`,
//! tipicamente via um exportador Prometheus.
//!
//! As métricas são prefixadas com `typedb_mcp_server_` para fácil identificação.
//! É crucial que `register_metrics_descriptions()` seja chamado uma única vez durante a
//! inicialização da aplicação para que os tipos e descrições das métricas
//! sejam corretamente estabelecidos antes de seu primeiro uso.

// metrics v0.24.2: APIs validadas
use metrics::{
    describe_counter, describe_gauge, describe_histogram, SharedString, Unit,
};

/// Prefixo global para todos os nomes de métricas expostas por esta aplicação.
pub const METRIC_PREFIX: &str = "typedb_mcp_server_";

// --- Nomes de Métricas (Constantes para consistência) ---
// Contadores
pub const WEBSOCKET_CONNECTIONS_TOTAL: &str = "websocket_connections_total";
pub const TOOL_CALLS_TOTAL: &str = "tool_calls_total";
pub const OAUTH_TOKENS_VALIDATED_TOTAL: &str = "oauth_tokens_validated_total";
pub const TYPEDB_REQUESTS_TOTAL: &str = "typedb_requests_total";
pub const JWKS_FETCH_TOTAL: &str = "jwks_fetch_total";
pub const CONFIG_LOAD_ATTEMPTS_TOTAL: &str = "config_load_attempts_total";
// Gauges
pub const WEBSOCKET_ACTIVE_CONNECTIONS: &str = "websocket_active_connections";
pub const JWKS_KEYS_CACHED_COUNT: &str = "jwks_keys_cached_count";
pub const SERVER_INFO_GAUGE: &str = "info";
pub const SERVER_READY_STATUS: &str = "ready_status";
// Histogramas
pub const TOOL_CALL_DURATION_SECONDS: &str = "tool_call_duration_seconds";
pub const OAUTH_TOKEN_VALIDATION_DURATION_SECONDS: &str =
    "oauth_token_validation_duration_seconds";
pub const TYPEDB_REQUEST_DURATION_SECONDS: &str = "typedb_request_duration_seconds";
pub const JWKS_FETCH_DURATION_SECONDS: &str = "jwks_fetch_duration_seconds";

// --- Labels Comuns ---
pub const LABEL_TOOL_NAME: &str = "tool_name";
pub const LABEL_STATUS: &str = "status";
pub const LABEL_OPERATION_TYPE: &str = "operation_type";
pub const LABEL_VERSION: &str = "app_version";
pub const LABEL_RUST_VERSION: &str = "rust_version";

/// Registra as descrições de todas as métricas da aplicação.
///
/// Esta função deve ser chamada uma única vez durante a inicialização do servidor.
/// A chamada a esta função é idempotente em termos de registro no `metrics` global,
/// mas chamá-la múltiplas vezes pode ter um pequeno custo de performance desnecessário.
/// O `metrics` crate internamente lida com registros duplicados de forma graciosa (ignora).
#[tracing::instrument(name = "register_metric_descriptions")]
pub fn register_metrics_descriptions() {
    // Contadores
    // metrics v0.24.2: describe_counter!(key_name, unit, description)
    // Unit e SharedString são usados conforme a API.
    describe_counter!(
        format!("{}{}", METRIC_PREFIX, WEBSOCKET_CONNECTIONS_TOTAL),
        Unit::Count, // metrics v0.24.2: Unit::Count
        SharedString::from("Número total de conexões WebSocket estabelecidas desde o início do servidor.") // metrics v0.24.2: SharedString::from
    );
    describe_counter!(
        format!("{}{}", METRIC_PREFIX, TOOL_CALLS_TOTAL),
        Unit::Count,
        SharedString::from("Número total de chamadas de ferramentas MCP, com labels para nome da ferramenta e status.")
    );
    describe_counter!(
        format!("{}{}", METRIC_PREFIX, OAUTH_TOKENS_VALIDATED_TOTAL),
        Unit::Count,
        SharedString::from("Número total de tokens OAuth2 processados para validação, com label de status.")
    );
    describe_counter!(
        format!("{}{}", METRIC_PREFIX, TYPEDB_REQUESTS_TOTAL),
        Unit::Count,
        SharedString::from("Número total de requisições diretas ao TypeDB, com labels para tipo de operação e status.")
    );
    describe_counter!(
        format!("{}{}", METRIC_PREFIX, JWKS_FETCH_TOTAL),
        Unit::Count,
        SharedString::from("Número total de tentativas de buscar o JWKS, com label de status.")
    );
    describe_counter!(
        format!("{}{}", METRIC_PREFIX, CONFIG_LOAD_ATTEMPTS_TOTAL),
        Unit::Count,
        SharedString::from("Número total de tentativas de carregar a configuração, com label de status ('success' ou 'failure').")
    );

    // Gauges
    // metrics v0.24.2: describe_gauge!(key_name, unit, description)
    describe_gauge!(
        format!("{}{}", METRIC_PREFIX, WEBSOCKET_ACTIVE_CONNECTIONS),
        Unit::Count,
        SharedString::from("Número de conexões WebSocket atualmente ativas.")
    );
    describe_gauge!(
        format!("{}{}", METRIC_PREFIX, JWKS_KEYS_CACHED_COUNT),
        Unit::Count,
        SharedString::from("Número de chaves atualmente em cache do JWKS.")
    );
    describe_gauge!(
        format!("{}{}", METRIC_PREFIX, SERVER_INFO_GAUGE),
        Unit::Count, // Embora seja 'info', um gauge com valor '1' e labels é uma prática comum.
        SharedString::from("Informações sobre o servidor, como versão da aplicação e versão do Rust (expostas via labels).")
    );
    describe_gauge!(
        format!("{}{}", METRIC_PREFIX, SERVER_READY_STATUS),
        Unit::Count, // 1 para pronto, 0 para não pronto.
        SharedString::from("Status de prontidão do servidor (1 se pronto para receber tráfego, 0 caso contrário).")
    );

    // Histogramas
    // metrics v0.24.2: describe_histogram!(key_name, unit, description)
    describe_histogram!(
        format!("{}{}", METRIC_PREFIX, TOOL_CALL_DURATION_SECONDS),
        Unit::Seconds, // metrics v0.24.2: Unit::Seconds
        SharedString::from("Distribuição da duração das chamadas de ferramentas MCP.")
    );
    describe_histogram!(
        format!("{}{}", METRIC_PREFIX, OAUTH_TOKEN_VALIDATION_DURATION_SECONDS),
        Unit::Seconds,
        SharedString::from("Distribuição da duração da validação de tokens OAuth2.")
    );
    describe_histogram!(
        format!("{}{}", METRIC_PREFIX, TYPEDB_REQUEST_DURATION_SECONDS),
        Unit::Seconds,
        SharedString::from("Distribuição da duração das requisições ao TypeDB.")
    );
    describe_histogram!(
        format!("{}{}", METRIC_PREFIX, JWKS_FETCH_DURATION_SECONDS),
        Unit::Seconds,
        SharedString::from("Distribuição da duração das buscas ao JWKS.")
    );

    tracing::info!("Descrições de métricas registradas com o prefixo: {}", METRIC_PREFIX);
}

#[cfg(test)]
mod tests {
    use super::*;
    use metrics::{Counter, Gauge, Histogram, Key, KeyName, Metadata, Recorder, Unit, set_global_recorder}; // metrics v0.24.2
    use serial_test::serial; // serial_test v3.1.1
    use std::sync::{Arc, Mutex};

    // MockRecorder para capturar chamadas de descrição de métricas.
    #[derive(Default, Clone, Debug)]
    struct MockMetricsRecorder {
        descriptions: Arc<Mutex<Vec<MetricDescriptionCall>>>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MetricDescriptionCall {
        name: String,
        unit: Option<Unit>,
        description: String,
    }

    impl Recorder for MockMetricsRecorder {
        fn describe_counter(&self, key: KeyName, unit: Option<Unit>, description: SharedString) {
            self.descriptions.lock().unwrap().push(MetricDescriptionCall {
                name: key.as_str().to_string(),
                unit,
                description: description.into_owned(), // SharedString para String
            });
        }

        fn describe_gauge(&self, key: KeyName, unit: Option<Unit>, description: SharedString) {
            self.descriptions.lock().unwrap().push(MetricDescriptionCall {
                name: key.as_str().to_string(),
                unit,
                description: description.into_owned(),
            });
        }

        fn describe_histogram(&self, key: KeyName, unit: Option<Unit>, description: SharedString) {
            self.descriptions.lock().unwrap().push(MetricDescriptionCall {
                name: key.as_str().to_string(),
                unit,
                description: description.into_owned(),
            });
        }

        // Implementações No-op para os métodos de registro de métricas reais.
        fn register_counter(&self, _key: &Key, _metadata: &Metadata<'_>) -> Counter { Counter::noop() }
        fn register_gauge(&self, _key: &Key, _metadata: &Metadata<'_>) -> Gauge { Gauge::noop() }
        fn register_histogram(&self, _key: &Key, _metadata: &Metadata<'_>) -> Histogram { Histogram::noop() }
    }
    
    // Helper para instalar o recorder de teste.
    // Retorna true se foi instalado nesta chamada, false se um recorder já existia.
    fn install_test_recorder(recorder: Arc<MockMetricsRecorder>) -> bool {
        // metrics v0.24.2: set_global_recorder
        match set_global_recorder(recorder) {
            Ok(_) => {
                tracing::info!("MockMetricsRecorder instalado globalmente para o teste.");
                true
            }
            Err(e) => {
                tracing::warn!("Falha ao instalar o MockMetricsRecorder global (pode já existir um): {}. Este teste pode capturar descrições de execuções anteriores se o recorder não for este mock.", e);
                false
            }
        }
    }

    #[test]
    fn test_metric_names_are_correct_and_prefixed() {
        // Verifica se as constantes geram os nomes completos corretamente.
        assert_eq!(
            format!("{}{}", METRIC_PREFIX, WEBSOCKET_CONNECTIONS_TOTAL),
            "typedb_mcp_server_websocket_connections_total"
        );
        assert_eq!(
            format!("{}{}", METRIC_PREFIX, TOOL_CALLS_TOTAL),
            "typedb_mcp_server_tool_calls_total"
        );
        assert_eq!(
            format!("{}{}", METRIC_PREFIX, OAUTH_TOKENS_VALIDATED_TOTAL),
            "typedb_mcp_server_oauth_tokens_validated_total"
        );
        assert_eq!(
            format!("{}{}", METRIC_PREFIX, TYPEDB_REQUESTS_TOTAL),
            "typedb_mcp_server_typedb_requests_total"
        );
        assert_eq!(
            format!("{}{}", METRIC_PREFIX, JWKS_FETCH_TOTAL),
            "typedb_mcp_server_jwks_fetch_total"
        );
        assert_eq!(
            format!("{}{}", METRIC_PREFIX, CONFIG_LOAD_ATTEMPTS_TOTAL),
            "typedb_mcp_server_config_load_attempts_total"
        );
        assert_eq!(
            format!("{}{}", METRIC_PREFIX, WEBSOCKET_ACTIVE_CONNECTIONS),
            "typedb_mcp_server_websocket_active_connections"
        );
        assert_eq!(
            format!("{}{}", METRIC_PREFIX, JWKS_KEYS_CACHED_COUNT),
            "typedb_mcp_server_jwks_keys_cached_count"
        );
        assert_eq!(
            format!("{}{}", METRIC_PREFIX, SERVER_INFO_GAUGE),
            "typedb_mcp_server_info"
        );
         assert_eq!(
            format!("{}{}", METRIC_PREFIX, SERVER_READY_STATUS),
            "typedb_mcp_server_ready_status"
        );
        assert_eq!(
            format!("{}{}", METRIC_PREFIX, TOOL_CALL_DURATION_SECONDS),
            "typedb_mcp_server_tool_call_duration_seconds"
        );
        assert_eq!(
            format!("{}{}", METRIC_PREFIX, OAUTH_TOKEN_VALIDATION_DURATION_SECONDS),
            "typedb_mcp_server_oauth_token_validation_duration_seconds"
        );
        assert_eq!(
            format!("{}{}", METRIC_PREFIX, TYPEDB_REQUEST_DURATION_SECONDS),
            "typedb_mcp_server_typedb_request_duration_seconds"
        );
        assert_eq!(
            format!("{}{}", METRIC_PREFIX, JWKS_FETCH_DURATION_SECONDS),
            "typedb_mcp_server_jwks_fetch_duration_seconds"
        );
    }

    #[test]
    #[serial] // Necessário devido ao set_global_recorder
    fn test_register_metrics_descriptions_registers_all_metrics() {
        // Inicializa o tracing para que os logs dentro da função de teste sejam visíveis.
        // Isso pode ser configurado globalmente para todos os testes, se desejado.
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();

        let mock_recorder = Arc::new(MockMetricsRecorder::default());
        // Tentamos instalar. Se já houver um (de um teste anterior que não limpou ou rodou em paralelo sem #[serial]),
        // este teste ainda pode funcionar, mas pode ter dados de descrições antigas se o mock não for o global.
        let _installed_this_run = install_test_recorder(mock_recorder.clone());

        register_metrics_descriptions();

        let descriptions = mock_recorder.descriptions.lock().unwrap();
        
        // Número total de chamadas describe_* na função
        let num_expected_metrics = 4 + 4 + 6; // gauges + histogramas + contadores
        
        assert_eq!(
            descriptions.len(),
            num_expected_metrics,
            "Número incorreto de descrições de métricas registradas. Esperado: {}, Obtido: {}. Descrições: {:?}",
            num_expected_metrics,
            descriptions.len(),
            descriptions
        );

        // Verificar algumas descrições específicas
        let expected_websocket_total = MetricDescriptionCall {
            name: format!("{}{}", METRIC_PREFIX, WEBSOCKET_CONNECTIONS_TOTAL),
            unit: Some(Unit::Count),
            description: "Número total de conexões WebSocket estabelecidas desde o início do servidor.".to_string(),
        };
        assert!(
            descriptions.contains(&expected_websocket_total),
            "Descrição para WEBSOCKET_CONNECTIONS_TOTAL não encontrada ou incorreta. Detalhe: {:?}",
            descriptions.iter().find(|d|d.name == expected_websocket_total.name)
        );

        let expected_tool_duration = MetricDescriptionCall {
            name: format!("{}{}", METRIC_PREFIX, TOOL_CALL_DURATION_SECONDS),
            unit: Some(Unit::Seconds),
            description: "Distribuição da duração das chamadas de ferramentas MCP.".to_string(),
        };
        assert!(
            descriptions.contains(&expected_tool_duration),
            "Descrição para TOOL_CALL_DURATION_SECONDS não encontrada ou incorreta. Detalhe: {:?}",
            descriptions.iter().find(|d|d.name == expected_tool_duration.name)
        );

        let expected_server_info = MetricDescriptionCall {
            name: format!("{}{}", METRIC_PREFIX, SERVER_INFO_GAUGE),
            unit: Some(Unit::Count),
            description: "Informações sobre o servidor, como versão da aplicação e versão do Rust (expostas via labels).".to_string(),
        };
        assert!(
            descriptions.contains(&expected_server_info),
            "Descrição para SERVER_INFO_GAUGE não encontrada ou incorreta. Detalhe: {:?}",
            descriptions.iter().find(|d|d.name == expected_server_info.name)
        );
    }
}