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
//! de integração. Para usar esses utilitários em um módulo de teste
//! (ex: `tests/integration/meu_teste.rs`), adicione:
//! `use crate::common::nome_do_submodulo;` ou `use crate::common::ItemEspecifico;`.

pub mod auth_helpers;
pub mod client;
pub mod docker_helpers;

// Reexportar itens frequentemente usados pode ser conveniente, mas opcional.
// Exemplo: `pub use client::TestMcpClient;`

#[cfg(test)]
mod tests {
    // Importa os itens reexportados para verificar se os `pub use` estão corretos
    // em termos de sintaxe e visibilidade. O teste real da funcionalidade
    // desses itens ocorreria nos testes dos submódulos ou nos testes de integração.
    // Para que este bloco compile sem erros (além da não existência dos submódulos),
    // os itens reexportados devem ser publicamente acessíveis.
    #[allow(unused_imports)]
    use super::{
        TestMcpClient, generate_test_jwt, 
        // docker_compose_up, docker_compose_down, // Comentado
        // wait_for_service_healthy, // Comentado
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
