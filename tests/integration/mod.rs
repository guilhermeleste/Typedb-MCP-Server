// Copyright 2025 The Typedb-MCP-Server Contributors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Módulo raiz para os arquivos de teste de integração do Typedb-MCP-Server.
//!
//! Este arquivo é tipicamente o `mod.rs` para um diretório `integration` que faz parte
//! de um crate de teste de integração (por exemplo, definido em `tests/integration.rs`).
//! Ele declara os diferentes arquivos de suíte de teste e módulos comuns como submódulos,
//! permitindo que o Cargo os descubra e compile como parte desse crate de teste.
//!
//! Os arquivos de teste reais (ex: `connection_tests.rs`) e o módulo `common`
//! devem residir no mesmo diretório que este arquivo (`tests/integration/`).

/// Módulo de helpers comuns para os testes de integração.
// Validação: Declara o submódulo `common` que deve residir em `tests/integration/common/mod.rs`.
pub mod common;

/// Suíte de testes de integração para conexões e autenticação.
// Validação: Declara o submódulo `connection_tests` que deve residir em `tests/integration/connection_tests.rs`.
pub mod connection_tests;

/// Suíte de testes de integração para as ferramentas de administração de banco de dados (db_admin_tool).
// Validação: Declara o submódulo `db_admin_tool_tests` que deve residir em `tests/integration/db_admin_tool_tests.rs`.
pub mod db_admin_tool_tests;

/// Suíte de testes de integração para as ferramentas de operações de esquema (schema_ops_tool).
// Validação: Declara o submódulo `schema_ops_tool_tests` que deve residir em `tests/integration/schema_ops_tool_tests.rs`.
pub mod schema_ops_tool_tests;

/// Suíte de testes de integração para as ferramentas de consulta (query_tool).
// Validação: Declara o submódulo `query_tool_tests` que deve residir em `tests/integration/query_tool_tests.rs`.
pub mod query_tool_tests;

/// Suíte de testes de integração para os recursos MCP.
// Validação: Declara o submódulo `resource_tests` que deve residir em `tests/integration/resource_tests.rs`.
pub mod resource_tests;

/// Suíte de testes de integração para TLS com TypeDB.
// Validação: Declara o submódulo `typedb_tls_tests` que deve residir em `tests/integration/typedb_tls_tests.rs`.
pub mod typedb_tls_tests;

/// Suíte de testes de integração para observabilidade (endpoints /metrics, /livez, /readyz).
// Validação: Declara o submódulo `observability_tests` que deve residir em `tests/integration/observability_tests.rs`.
pub mod observability_tests;

/// Suíte de testes de integração para resiliência e tratamento de falhas.
// Validação: Declara o submódulo `resilience_tests` que deve residir em `tests/integration/resilience_tests.rs`.
pub mod resilience_tests;

#[cfg(test)]
mod tests {
    /// Testa se o módulo `integration::mod.rs` compila corretamente.
    ///
    /// A compilação bem-sucedida deste arquivo implica que as declarações `pub mod`
    /// estão sintaticamente corretas. O compilador Rust tentará resolver
    /// os caminhos para os submódulos declarados (ex: `common.rs` ou `common/mod.rs`,
    /// `connection_tests.rs`, etc.) no mesmo diretório que este arquivo.
    ///
    /// Se os arquivos dos submódulos não existirem, o `cargo check` ou `cargo build`
    /// do crate de teste de integração falhará na resolução, o que é o comportamento
    /// esperado até que esses elementos sejam criados.
    #[test]
    fn test_integration_mod_structure_compiles() {
        assert!(
            true,
            "Este teste apenas confirma que a estrutura de tests/integration/mod.rs (declarações de submódulo) é sintaticamente válida."
        );
    }
}
