// src/lib.rs

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

//! Typedb-MCP-Server
//!
//! Este crate define a lógica central do servidor, incluindo a manipulação
//! do protocolo MCP, interação com o `TypeDB`, autenticação, configuração,
//! e as ferramentas expostas. O binário em `src/main.rs` utiliza esta
//! biblioteca para construir e executar o servidor.
//!
//! Módulos expostos:
//! - `config`: Carregamento e gerenciamento de configurações.
//! - `db`: Conectividade com o banco de dados `TypeDB`.
//! - `error`: Tipos de erro customizados e utilitários.
//! - `mcp_service_handler`: Implementação do `ServerHandler` do RMCP e lógica das ferramentas.
//! - `auth`: Autenticação `OAuth2`.
//! - `metrics`: Definição de métricas.
//! - `telemetry`: Configuração de tracing OpenTelemetry.
//! - `resources`: Gerenciamento de recursos MCP.
//! - `tools`: Submódulos para cada categoria de ferramenta MCP.

// Validação: `pub mod <nome>;` é a sintaxe padrão para declarar um módulo público
// que reside em `<nome>.rs` ou `<nome>/mod.rs`.
// Fonte: https://doc.rust-lang.org/book/ch07-02-defining-modules-to-control-scope-and-privacy.html

/// Módulo para carregamento e gerenciamento de configurações da aplicação.
pub mod config;

/// Módulo para interação e conectividade com o banco de dados TypeDB.
pub mod db;

/// Módulo para definições de erro customizadas e utilitários de tratamento de erro.
pub mod error;

/// Módulo contendo o handler principal do serviço MCP e a lógica de despacho de ferramentas.
pub mod mcp_service_handler;

/// Módulo para lógica de autenticação OAuth 2.0 e autorização.
pub mod auth;

/// Módulo para definição e registro de métricas da aplicação (Prometheus).
pub mod metrics;

/// Módulo para configuração e inicialização do tracing distribuído (OpenTelemetry).
pub mod telemetry;

/// Módulo para gerenciamento de recursos estáticos e dinâmicos expostos via MCP.
pub mod resources;

/// Módulo agregador para todas as ferramentas MCP e seus parâmetros.
pub mod tools;
pub mod transport;


#[cfg(test)]
mod tests {
    // Testes unitários para `lib.rs` geralmente não são necessários se ele apenas
    // declara módulos. A compilação bem-sucedida da biblioteca já é um teste
    // de que os módulos foram declarados corretamente e podem ser encontrados.
    // No entanto, para cumprir a regra de "testes em cada arquivo", um teste trivial:
    #[test]
    fn test_library_compiles() {
        // Esta asserção foi removida porque `assert!(true)` não tem efeito prático
        // e causa um aviso do clippy::assertions_on_constants.
        // O propósito do teste, "garantir que a biblioteca compila", 
        // é inerentemente verificado pela compilação bem-sucedida do próprio teste.
    }

    // Exemplo de teste mais elaborado que poderia ser usado se os submódulos já estivessem
    // definidos com itens públicos. Manter comentado como referência.
    /*
    // Para que este teste funcione, cada módulo precisaria de um item público para referência.
    // Por exemplo, em `src/config.rs`: `pub struct Settings {}`
    // Em `src/db.rs`: `pub async fn connect(...) {}` (precisaria de mock para não conectar de verdade)

    // Importar os módulos para usar seus itens no teste.
    use super::{config, db, error, mcp_service_handler, auth, metrics, telemetry, resources, tools};

    #[test]
    fn test_public_modules_are_accessible_and_basic_placeholder_exists() {
        // Apenas verifica se conseguimos nomear um tipo/função de cada módulo,
        // o que prova que o módulo está visível e exporta algo.
        // Isso não testa a funcionalidade, apenas a estrutura e visibilidade.

        // Exemplo para config (supondo que Settings::new() é pública)
        // Para evitar executar a lógica de Settings::new(), podemos apenas referenciar o tipo.
        let _config_settings_type: Option<config::Settings> = None;

        // Exemplo para db (supondo que db::connect é pública)
        // Apenas referenciar a função.
        let _db_connect_fn_ptr: fn(Option<String>, Option<String>, Option<String>, bool, Option<String>) -> Pin<Box<dyn Future<Output = Result<TypeDBDriver, TypeDBError>> + Send>> = db::connect;


        // Para error (supondo que McpServerError é público)
        let _error_type: Option<error::McpServerError> = None;

        // Para mcp_service_handler (supondo que McpServiceHandler é público)
        // let _mcp_handler_type: Option<mcp_service_handler::McpServiceHandler> = None; // Precisa de TypeDBDriver etc.

        // Para auth (supondo que ClientAuthContext é público)
        let _auth_context_type: Option<auth::ClientAuthContext> = None;

        // Para metrics (supondo que register_metrics_descriptions é público)
        let _metrics_fn_ptr: fn() = metrics::register_metrics_descriptions;

        // Para telemetry (supondo que init_tracing_pipeline é público)
        // let _telemetry_fn_ptr: fn(&config::TracingConfig) -> Result<(), opentelemetry_sdk::trace::TraceError> = telemetry::init_tracing_pipeline;

        // Para resources (supondo que list_static_resources é público)
        let _resources_fn_ptr: fn() -> Vec<rmcp::model::Resource> = resources::list_static_resources;

        // Para tools (o tools/mod.rs em si não tem itens, mas seus submódulos sim)
        // let _tools_params_type: Option<tools::params::QueryReadParams> = None; // Exemplo

        assert!(true, "Módulos públicos parecem acessíveis (teste placeholder).");
    }
    */
}