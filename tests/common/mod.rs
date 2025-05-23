// tests/common/mod.rs

// Licença Apache 2.0
// Copyright 2025 Guilherme Leste
// ... (cabeçalho de licença) ...

//! Módulo raiz para código utilitário compartilhado ... (descrição) ...

pub mod auth_helpers;
pub mod client;
pub mod constants;
pub mod docker_helpers;
/// Utilitários específicos para interações e manipulações relacionadas ao protocolo MCP.
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
pub use mcp_utils::get_text_from_call_result;
pub use test_env::TestEnvironment;
pub use test_utils::{
    create_test_db, define_test_db_schema, delete_test_db, unique_db_name,
    wait_for_mcp_server_ready_from_test_env,
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

        // async fn wait_for_mcp_server_ready_from_test_env(test_env: &TestEnvironment, timeout: Duration) -> Result<serde_json::Value>
        type WaitForReadyFnType =
            for<'a> fn(&'a TestEnvironment, Duration) -> BoxFuture<'a, Result<serde_json::Value>>;
        let _wait_ready_fn_check: WaitForReadyFnType =
            |env, dur| Box::pin(wait_for_mcp_server_ready_from_test_env(env, dur));

        // Acessar constante
        assert_eq!(super::constants::MCP_SERVER_SERVICE_NAME, "typedb-mcp-server-it");

        println!("O módulo common e suas reexportações principais são acessíveis e compilam (com verificações de tipo leves para funções async).");
        assert!(true);
    }
}
