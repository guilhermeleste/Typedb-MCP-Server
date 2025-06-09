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

//! Módulo raiz para código utilitário compartilhado ... (descrição) ...

pub mod auth_helpers;
pub mod client;
pub mod constants;
pub mod docker_helpers;
/// Utilitários específicos para interações e manipulações relacionadas ao protocolo MCP.
pub mod infrastructure_helpers;
/// Utilitários para manipulação de protocolos MCP e estruturas de dados relacionadas.
pub mod mcp_utils;
pub mod test_env;
pub mod test_utils;

// Reexportações
pub use auth_helpers::{
    current_timestamp_secs, generate_test_jwt, JwtAuthAlgorithm, TestClaims, TEST_HS256_SECRET,
    TEST_RSA_PRIVATE_KEY_PEM, TEST_RSA_PUBLIC_KEY_PEM,
};
pub use client::{McpClientError, TestMcpClient};
pub use docker_helpers::DockerComposeEnv;
pub use infrastructure_helpers::{
    cleanup_orphaned_test_containers, ensure_clean_test_environment, 
    is_port_available, robust_cleanup_and_verify, verify_critical_ports_available
};
pub use mcp_utils::get_text_from_call_result;
pub use test_env::TestEnvironment;
pub use test_utils::{
    create_test_db, define_test_db_schema, delete_test_db, helper_wait_for_metrics_endpoint,
    unique_db_name, wait_for_mcp_server_ready_from_test_env,
};

#[cfg(test)]
mod tests {
    use super::*; // Importa as reexportações do módulo `common`
    use rmcp::model::CallToolResult;
    // Usar o caminho completo para TestClaims de auth_helpers para evitar ambiguidade se houvesse outro
    use crate::common::auth_helpers::TestClaims as AuthHelperTestClaims;
    use anyhow::Result; // Para os tipos de retorno das funções async
    use futures_util::future::BoxFuture;
    use std::time::Duration; // Para anotações de tipo explícitas

    #[test]
    fn test_common_mod_structure_and_reexports_are_accessible() {
        // Testes de acessibilidade de tipo
        let _client_type_check: Option<TestMcpClient> = None;
        let _docker_env_type_check: Option<DockerComposeEnv> = None;
        let _test_env_type_check: Option<TestEnvironment> = None;

        // Teste de assinatura de função síncrona
        let _jwt_fn_signature_check: fn(AuthHelperTestClaims, JwtAuthAlgorithm) -> String =
            generate_test_jwt;
        let _get_text_fn_signature_check: fn(CallToolResult) -> String = get_text_from_call_result;
        let _unique_db_name_fn_check: fn(&str) -> String = unique_db_name;

        // Para funções async, podemos testar se elas podem ser atribuídas a um tipo de função
        // que espera os parâmetros corretos e retorna um Future apropriado.
        // O lifetime 'aqui é importante para mostrar que elas pegam referências.
        // O 'static no BoxFuture indica que o Future em si não empresta nada que viva menos que 'static,
        // o que é verdade se os async blocks usarem `async move` e moverem/clonarem os dados necessários.

        // fn setup(test_name_suffix: &str, config_filename: &str) -> Result<Self>
        type SetupFnType =
            for<'a, 'b> fn(&'a str, &'b str) -> BoxFuture<'static, Result<TestEnvironment>>;
        let _setup_fn_check: SetupFnType = |s1, s2| {
            let s1_owned = s1.to_string();
            let s2_owned = s2.to_string();
            Box::pin(async move { TestEnvironment::setup(&s1_owned, &s2_owned).await })
        };

        // async fn create_test_db(client: &mut TestMcpClient, db_name: &str) -> Result<()>
        // A anotação de tipo para uma função que pega &mut pode ser mais complexa devido ao lifetime do &mut.
        // Para este teste de compilação, podemos simplificar ou focar na chamada.
        // Se create_test_db for chamada, o compilador verificará os tipos.
        // Vamos testar que podemos *referenciar* a função.
        let _create_db_fn_ptr = create_test_db;

        // async fn define_test_db_schema(client: &mut TestMcpClient, db_name: &str) -> Result<()>
        let _define_schema_fn_ptr = define_test_db_schema;

        // async fn delete_test_db(client: &mut TestMcpClient, db_name: &str)
        // (não retorna Result)
        let _delete_db_fn_ptr = delete_test_db;

        // async fn wait_for_mcp_server_ready_from_test_env com nova assinatura
        type WaitForReadyFnType = for<'a> fn(
            &'a DockerComposeEnv,
            &'a str,
            bool,
            bool,
            bool,
            Duration,
        ) -> BoxFuture<'a, Result<serde_json::Value>>;
        let _wait_ready_fn_check: WaitForReadyFnType = |docker_env, url, tls, oauth, typedb_tls, dur| {
            Box::pin(wait_for_mcp_server_ready_from_test_env(
                docker_env, url, tls, oauth, typedb_tls, dur,
            ))
        };

        // Acessar constante
        assert_eq!(super::constants::MCP_SERVER_SERVICE_NAME, "typedb-mcp-server-it");

        println!("O módulo common e suas reexportações principais são acessíveis e compilam (com verificações de tipo leves para funções async).");
        assert!(true);
    }
}
