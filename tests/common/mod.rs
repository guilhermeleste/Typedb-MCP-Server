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

//! Módulo raiz para código utilitário compartilhado entre os testes de integração
//! do Typedb-MCP-Server.
//!
//! Este módulo declara e organiza os submódulos contendo helpers para:
//! - Clientes MCP de teste (`client`).
//! - Geração e manipulação de tokens JWT para testes de autenticação (`auth_helpers`).
//! - Gerenciamento de ambientes Docker Compose (`docker_helpers`).
//! - Utilitários específicos do MCP, como parsing de respostas (`mcp_utils`).
//!
//! Itens frequentemente usados são reexportados para facilitar o acesso a partir
//! dos módulos de teste de integração (ex: `use crate::common::TestMcpClient;`).

// Declaração dos submódulos públicos que compõem `common`.
// Cada um reside em seu próprio arquivo (ex: `tests/common/client.rs`).
pub mod auth_helpers;
pub mod client;
pub mod docker_helpers;
pub mod mcp_utils;

// Reexportações para facilitar o acesso aos tipos e funções mais comuns.
// Isso permite que os módulos de teste usem `crate::common::TestMcpClient`
// em vez de `crate::common::client::TestMcpClient`.
pub use client::{McpClientError, TestMcpClient};
pub use auth_helpers::{
    current_timestamp_secs, generate_test_jwt, Algorithm, TestClaims, TEST_KID,
    TEST_RSA_PRIVATE_KEY_PEM,
    // TEST_RSA_PUBLIC_KEY_PEM, // Descomentar se for usado diretamente em outros testes
};
pub use docker_helpers::DockerComposeEnv;
pub use mcp_utils::get_text_from_call_result;

#[cfg(test)]
mod tests {
    // Importa os itens reexportados pelo módulo `super` (que é `common`).
    use super::{
        TestMcpClient, generate_test_jwt, get_text_from_call_result,
        // Para os tipos de parâmetros de generate_test_jwt, precisamos do caminho completo
        // se eles não foram reexportados individualmente.
        auth_helpers::TestClaims as AuthTestClaims, // Alias para evitar colisão se TestClaims fosse definido aqui
        auth_helpers::Algorithm as AuthAlgorithm,   // Alias para evitar colisão
    };
    use rmcp::model::CallToolResult; // Necessário para o tipo de get_text_from_call_result

    /// Testa se a estrutura do módulo `common` está correta e se os
    /// principais itens reexportados são acessíveis em tempo de compilação.
    #[test]
    fn test_common_mod_structure_and_reexports_are_accessible() {
        // A simples compilação destas linhas já verifica a acessibilidade dos tipos.
        // Não é necessário instanciar ou chamar, apenas garantir que os nomes resolvem.

        // Verifica TestMcpClient (do submódulo client)
        let _client_type_check: Option<TestMcpClient> = None;

        // Verifica generate_test_jwt (do submódulo auth_helpers) e seus tipos de parâmetro
        let _jwt_fn_signature_check: fn(AuthTestClaims, AuthAlgorithm) -> String = generate_test_jwt;

        // Verifica get_text_from_call_result (do submódulo mcp_utils)
        let _get_text_fn_signature_check: fn(CallToolResult) -> String = get_text_from_call_result;
        
        // DockerComposeEnv é reexportado, mas não facilmente testável aqui sem mais setup.
        // A acessibilidade do tipo é verificada pela compilação do import.

        assert!(
            true,
            "O módulo common e suas reexportações principais são acessíveis."
        );
    }
}