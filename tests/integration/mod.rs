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
//! - Utilitários específicos do protocolo MCP, como parsing de respostas (`mcp_utils`).
//! - Constantes de teste (`constants`).
//! - Gerenciamento do ambiente de teste completo (`test_env`).
//! - Utilitários de teste gerais (`test_utils`).
//!
//! Itens frequentemente usados são reexportados para facilitar o acesso a partir
//! dos módulos de teste de integração (ex: `use crate::common::TestMcpClient;`).

// Declaração dos submódulos públicos que compõem `common`.
// Cada um reside em seu próprio arquivo (ex: `tests/common/client.rs`).

/// Helpers para autenticação e geração de tokens JWT de teste.
pub mod auth_helpers;
/// Cliente MCP de teste para interagir com o servidor.
pub mod client;
/// Constantes usadas em toda a suíte de testes de integração.
pub mod constants;
/// Gerenciador de ambiente Docker Compose para os testes.
pub mod docker_helpers;
/// Utilitários específicos do protocolo MCP para auxiliar nos testes.
pub mod mcp_utils;
/// Gerenciador do ambiente de teste completo, incluindo Docker e URLs de serviço.
pub mod test_env;
/// Utilitários de teste gerais (ex: criação/deleção de DBs de teste).
pub mod test_utils;

// Reexportações para facilitar o acesso aos tipos e funções mais comuns
// a partir dos módulos de teste de integração (ex: `tests/integration/*_tests.rs`).

// De `client.rs`
pub use client::{McpClientError, TestMcpClient};

// De `auth_helpers.rs`
pub use auth_helpers::{
    current_timestamp_secs, generate_test_jwt, JwtAuthAlgorithm, TestClaims,
    TEST_RSA_PRIVATE_KEY_PEM, TEST_RSA_PUBLIC_KEY_PEM, TEST_HS256_SECRET,
};

// De `docker_helpers.rs`
pub use docker_helpers::DockerComposeEnv;

// De `mcp_utils.rs`
pub use mcp_utils::get_text_from_call_result;

// De `test_env.rs`
pub use test_env::TestEnvironment; // TestEnvironment::setup é um método associado

// De `test_utils.rs`
pub use test_utils::{
    create_test_db, define_test_db_schema, delete_test_db, unique_db_name,
    wait_for_mcp_server_ready_from_test_env, // Renomeado e agora usa TestEnvironment
};


#[cfg(test)]
mod tests {
    // Importa os itens reexportados pelo módulo `super` (que é `common`).
    use super::{
        TestMcpClient, // de client.rs
        generate_test_jwt, JwtAuthAlgorithm, // de auth_helpers.rs
        DockerComposeEnv, // de docker_helpers.rs
        get_text_from_call_result, // de mcp_utils.rs
        TestEnvironment, // de test_env.rs
        unique_db_name, create_test_db, delete_test_db, define_test_db_schema, // de test_utils.rs
        wait_for_mcp_server_ready_from_test_env,
    };
    use rmcp::model::CallToolResult;
    use crate::common::auth_helpers::TestClaims as AuthHelperTestClaims;
    use std::time::Duration; // Para wait_for_mcp_server_ready_from_test_env
    use anyhow::Result; // Para o tipo de retorno de algumas funções async

    /// Testa se a estrutura do módulo `common` está correta e se os
    /// principais itens reexportados são acessíveis em tempo de compilação.
    #[test]
    fn test_common_mod_structure_and_reexports_are_accessible() {
        let _client_type_check: Option<TestMcpClient> = None;
        let _jwt_fn_signature_check: fn(AuthHelperTestClaims, JwtAuthAlgorithm) -> String = generate_test_jwt;
        let _docker_env_type_check: Option<DockerComposeEnv> = None;
        let _get_text_fn_signature_check: fn(CallToolResult) -> String = get_text_from_call_result;
        let _test_env_type_check: Option<TestEnvironment> = None;
        
        type SetupFn = for<'a, 'b> fn(&'a str, &'b str) -> futures_util::future::BoxFuture<'static, Result<TestEnvironment>>;
        let _setup_fn_check: SetupFn = |s1, s2| Box::pin(TestEnvironment::setup(s1, s2));

        type UniqueDbNameFn = fn(&str) -> String;
        let _unique_db_name_fn_check: UniqueDbNameFn = unique_db_name;

        // Para funções async em `test_utils`, precisamos de um contexto async para verificar a assinatura
        // mas para um teste de compilação, apenas garantir que o nome resolve é suficiente.
        // O compilador verificaria os tipos se tentássemos chamá-las de forma incorreta.
        
        // Exemplo de verificação de assinatura para uma das funções async de test_utils:
        type CreateTestDbFn = for<'a, 'b> fn(&'a mut TestMcpClient, &'b str) -> futures_util::future::BoxFuture<'a, Result<()>>;
        let _create_db_fn_check: CreateTestDbFn = |client, name| Box::pin(create_test_db(client, name));
        
        type DefineSchemaFn = for<'a, 'b> fn(&'a mut TestMcpClient, &'b str) -> futures_util::future::BoxFuture<'a, Result<()>>;
        let _define_schema_fn_check: DefineSchemaFn = |client, name| Box::pin(define_test_db_schema(client, name));

        type DeleteTestDbFn = for<'a,'b> fn(&'a mut TestMcpClient, &'b str) -> futures_util::future::BoxFuture<'a, ()>;
        let _delete_db_fn_check: DeleteTestDbFn = |client, name| Box::pin(delete_test_db(client, name));

        type WaitForReadyFn = for<'a> fn(&'a TestEnvironment, Duration) -> futures_util::future::BoxFuture<'a, Result<serde_json::Value>>;
        let _wait_ready_fn_check: WaitForReadyFn = |env, dur| Box::pin(wait_for_mcp_server_ready_from_test_env(env, dur));


        assert_eq!(super::constants::MCP_SERVER_SERVICE_NAME, "typedb-mcp-server-it");
        println!("O módulo common e suas reexportações principais são acessíveis e compilam.");
        assert!(true);
    }
}