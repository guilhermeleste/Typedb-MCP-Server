// tests/common/mod.rs

// Licença Apache 2.0
// Copyright 2025 Guilherme Leste
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

//! Módulo raiz para código utilitário compartilhado entre testes.
//!
//! Este módulo agrega e reexporta funcionalidades comuns usadas nos testes
//! de integração e comportamentais (BDD) do `Typedb-MCP-Server`.
//! O objetivo é evitar a duplicação de código e centralizar lógica auxiliar
//! que é comum a múltiplos cenários de teste.

/// Utilitários para criar clientes de teste MCP e interagir com o servidor.
// Validação: Declara o submódulo `client` que deve residir em `tests/common/client.rs`.
pub mod client;

/// Funções auxiliares para gerar tokens JWT de teste e lidar com autenticação.
// Validação: Declara o submódulo `auth_helpers` que deve residir em `tests/common/auth_helpers.rs`.
pub mod auth_helpers;

/// Funções auxiliares para gerenciar contêineres Docker (ex: via docker-compose) para testes.
// Validação: Declara o submódulo `docker_helpers` que deve residir em `tests/common/docker_helpers.rs`.
pub mod docker_helpers;

// Reexportações para conveniência de uso nos módulos de teste.
// Permite `use typedb_mcp_server_lib::tests::common::TestMcpClient;`
// em vez de `use typedb_mcp_server_lib::tests::common::client::TestMcpClient;`.
// NOTA: Estas reexportações causarão erros de compilação até que os itens
// correspondentes sejam definidos nos submódulos (`client.rs`, `auth_helpers.rs`, etc.).

pub use client::TestMcpClient;
pub use auth_helpers::generate_test_jwt;
pub use docker_helpers::{docker_compose_up, docker_compose_down, wait_for_service_healthy};


#[cfg(test)]
mod tests {
    // Importa os itens reexportados para verificar se os `pub use` estão corretos
    // em termos de sintaxe e visibilidade. O teste real da funcionalidade
    // desses itens ocorreria nos testes dos submódulos ou nos testes de integração.
    // Para que este bloco compile sem erros (além da não existência dos submódulos),
    // os itens reexportados devem ser publicamente acessíveis.
    #[allow(unused_imports)]
    use super::{
        TestMcpClient, generate_test_jwt, docker_compose_up, docker_compose_down,
        wait_for_service_healthy,
    };

    /// Testa se o módulo `common::mod.rs` compila corretamente.
    ///
    /// A compilação bem-sucedida deste arquivo implica que as declarações `pub mod`
    /// e `pub use` estão sintaticamente corretas. O compilador Rust tentará resolver
    /// os caminhos para `client.rs`, `auth_helpers.rs`, e `docker_helpers.rs`
    /// (ou seus equivalentes de diretório com `mod.rs` dentro) no mesmo diretório
    /// que este arquivo, e também os itens reexportados.
    ///
    /// Se os arquivos dos submódulos ou os itens reexportados não existirem/forem privados,
    /// o `cargo check` ou `cargo build` do projeto como um todo falhará na resolução,
    /// o que é o comportamento esperado até que esses elementos sejam criados.
    #[test]
    fn test_common_mod_structure_compiles() {
        assert!(
            true,
            "Este teste apenas confirma que a estrutura de tests/common/mod.rs (declarações e reexportações) é sintaticamente válida."
        );
    }
}
