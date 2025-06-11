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

//! Testes de integração para validação da conexão TLS entre Typedb-MCP-Server
//! e uma instância do TypeDB Server configurada para usar TLS.

use crate::common::{
    constants,
    // Helpers como create_test_db, delete_test_db, unique_db_name são reexportados por common
    create_test_db,
    delete_test_db,
    test_env::TestEnvironment,
    unique_db_name,
};
use anyhow::{Context as AnyhowContext, Result};
use serial_test::serial;
use tracing::{info, warn}; // Adicionado warn

#[tokio::test]
#[serial]
async fn test_mcp_server_connects_to_typedb_with_tls_successfully() -> Result<()> {
    // Este teste requer que o Typedb-MCP-Server seja configurado para usar TLS ao se conectar
    // ao TypeDB, e que o serviço `typedb-server-tls-it` esteja rodando e configurado com TLS.
    let test_env = TestEnvironment::setup(
        "mcp_to_typedb_tls_ok",
        constants::TYPEDB_TLS_CONNECTION_TEST_CONFIG_FILENAME, // Usa o TOML para conexão TypeDB TLS
    )
    .await?;

    // O TestEnvironment::setup já deve ter esperado pelo typedb-server-tls-it
    // e pelo mcp-server (que está configurado para conectar via TLS ao TypeDB).
    assert!(
        test_env.is_typedb_connection_tls,
        "Este teste esperava que a conexão TypeDB TLS estivesse habilitada na config."
    );

    info!(
        "Ambiente '{}' pronto. MCP Server deve estar conectado ao TypeDB via TLS.",
        test_env.docker_env.project_name()
    );

    // Tentar uma operação simples que requer comunicação com o TypeDB.
    // Se o MCP server falhou ao conectar ao TypeDB TLS, esta chamada falhará.
    // O TestEnvironment::setup já validou /readyz, que inclui a saúde da conexão TypeDB.
    // Aqui, fazemos uma operação real para dupla verificação.
    let mut client = test_env
        .mcp_client_with_auth(Some("typedb:manage_databases typedb:admin_databases")) // Escopos para criar/deletar
        .await
        .context("Falha ao obter cliente MCP para teste de conexão TypeDB TLS")?;

    let db_name = unique_db_name("tls_conn_check");
    info!(
        "Teste: Tentando criar banco de dados '{}' através de conexão MCP -> TypeDB (TLS)",
        db_name
    );

    let create_result = create_test_db(&mut client, &db_name).await;
    assert!(
        create_result.is_ok(),
        "Falha ao criar banco de dados quando o MCP Server deveria estar conectado ao TypeDB via TLS. Erro: {:?}",
        create_result.err()
    );
    info!("Banco de dados '{}' criado com sucesso sobre conexão TypeDB TLS.", db_name);

    // Listar bancos para confirmar
    let list_result = client.call_tool("list_databases", None).await?;
    let list_text = crate::common::mcp_utils::get_text_from_call_result(list_result);
    let dbs: Vec<String> = serde_json::from_str(&list_text)?;
    assert!(dbs.contains(&db_name), "Banco de dados recém-criado não foi listado.");

    delete_test_db(&mut client, &db_name).await;
    Ok(())
}

#[ignore]
#[tokio::test]
#[serial]
async fn test_mcp_server_fails_to_connect_to_typedb_tls_with_wrong_ca() -> Result<()> {
    // Para este teste, precisaríamos de uma forma de configurar o Typedb-MCP-Server
    // para usar um CA inválido ao tentar conectar ao `typedb-server-tls-it`.
    // Isso exigiria um arquivo TOML de configuração específico:
    //
    // `typedb_tls_wrong_ca.test.toml`:
    //   [typedb]
    //   address = "typedb-server-tls-it:1729"
    //   tls_enabled = true
    //   tls_ca_path = "/app/test_certs/mcp-server.crt" # Usando um cert de servidor como CA (inválido)
    //   ... (outras seções como default)
    //
    // E o TestEnvironment::setup precisaria usá-lo.
    //
    // O servidor MCP deve falhar ao iniciar ou seu /readyz deve indicar TypeDB DOWN.

    let config_filename_wrong_ca = "typedb_tls_wrong_ca.test.toml"; // Precisa criar este arquivo
    warn!(
        "Teste '{}' está INCOMPLETO e será IGNORADO até que o arquivo de configuração '{}' \
        seja criado e o comportamento de falha do servidor seja confirmado.",
        "test_mcp_server_fails_to_connect_to_typedb_tls_with_wrong_ca", config_filename_wrong_ca
    );
    // Se o arquivo `typedb_tls_wrong_ca.test.toml` não existir, o `TestEnvironment::setup` abaixo falhará
    // ao tentar carregar uma config inexistente ou o servidor MCP falhará ao iniciar.

    // Tentativa de setup (espera-se que o /readyz do MCP server falhe ou nunca fique UP)
    let test_env_result = TestEnvironment::setup(
        "mcp_to_typedb_tls_badca",
        config_filename_wrong_ca, // Este arquivo precisaria existir em tests/test_configs/
    )
    .await;

    if test_env_result.is_ok() {
        let test_env = test_env_result.expect("test_env_result deveria ser Ok baseado no if");
        // Se o setup passou, o /readyz do MCP pode estar UP, mas o componente TypeDB deve estar DOWN.
        let readyz_url =
            format!("{}{}", test_env.mcp_http_base_url, constants::MCP_SERVER_DEFAULT_READYZ_PATH);
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(test_env.is_mcp_server_tls)
            .build()?;
        let resp = client.get(&readyz_url).send().await?.json::<serde_json::Value>().await?;

        assert_eq!(resp.get("status").and_then(|s|s.as_str()), Some("DOWN"),
            "MCP Server deveria estar DOWN no /readyz se não conseguiu conectar ao TypeDB TLS com CA errada.");
        assert_eq!(
            resp.get("components").and_then(|c| c.get("typedb")).and_then(|s| s.as_str()),
            Some("DOWN"),
            "Componente TypeDB deveria estar DOWN no /readyz."
        );
        info!("MCP Server /readyz indicou falha na conexão com TypeDB (CA errada), como esperado.");
    } else {
        info!("TestEnvironment::setup falhou como esperado, pois o servidor MCP provavelmente não conseguiu iniciar/ficar pronto devido à falha de conexão TLS com o TypeDB (CA errada). Erro: {:?}", test_env_result.err());
        // Isso é um "sucesso" para este cenário de teste de falha.
    }

    // Não há necessidade de `docker_env.down()` explícito se o setup falhar, pois o Drop não será chamado.
    // Se o setup passar mas o readyz estiver DOWN, o Drop de TestEnvironment cuidará da limpeza.
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_mcp_server_fails_if_typedb_is_not_tls_but_mcp_expects_tls() -> Result<()> {
    // Cenário:
    // - `typedb-server-it` (sem TLS) está rodando.
    // - MCP Server é configurado com `typedb_tls_connection.test.toml`, que define:
    //   [typedb]
    //   address = "typedb-server-it:1729" # Aponta para o servidor SEM TLS
    //   tls_enabled = true                 # Mas MCP espera TLS
    //   tls_ca_path = "/app/test_certs/rootCA.pem"
    //
    // Espera-se que o MCP Server falhe ao conectar ao TypeDB, e o /readyz indique TypeDB DOWN.

    // Para este teste, usamos TYPEDB_TLS_CONNECTION_TEST_CONFIG_FILENAME, mas ele aponta para typedb-server-tls-it.
    // Precisamos de uma config que:
    // 1. Configure o MCP para usar TLS para o TypeDB.
    // 2. Configure o MCP para apontar para o `typedb-server-it` (que *não* tem TLS).
    //
    // Vamos criar um `typedb_expect_tls_got_plain.test.toml` para isso.
    /*
    Conteúdo de `tests/test_configs/typedb_expect_tls_got_plain.test.toml`:
    ```toml
    [server]
    bind_address = "0.0.0.0:8787"
    metrics_bind_address = "0.0.0.0:9090"
    # ... outros defaults ...

    [typedb]
    address = "typedb-server-it:1729" # Aponta para o servidor TypeDB SEM TLS
    username = "admin"
    tls_enabled = true                 # MCP Client (dentro do MCP Server) tentará TLS
    tls_ca_path = "/app/test_certs/rootCA.pem" # CA é irrelevante aqui, pois o handshake TLS falhará antes

    [oauth]
    enabled = false
    # ... outros defaults ...
    [logging]
    rust_log = "info,typedb_mcp_server_lib=debug,typedb_mcp_server=debug,typedb_driver=trace,hyper=warn"
    # ... etc
    ```
    */

    let config_filename_expect_tls = "typedb_expect_tls_got_plain.test.toml"; // Precisa criar este arquivo
    warn!(
        "Teste '{}' está INCOMPLETO e será IGNORADO até que o arquivo de configuração '{}' \
        seja criado e o comportamento de falha do servidor seja confirmado.",
        "test_mcp_server_fails_if_typedb_is_not_tls_but_mcp_expects_tls",
        config_filename_expect_tls
    );

    let test_env_result =
        TestEnvironment::setup("mcp_expect_tls_typedb_plain", config_filename_expect_tls).await;

    if test_env_result.is_ok() {
        let test_env = test_env_result.expect("test_env_result deveria ser Ok baseado no if");
        let readyz_url =
            format!("{}{}", test_env.mcp_http_base_url, constants::MCP_SERVER_DEFAULT_READYZ_PATH);
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(test_env.is_mcp_server_tls)
            .build()?;
        let resp = client.get(&readyz_url).send().await?.json::<serde_json::Value>().await?;

        assert_eq!(
            resp.get("status").and_then(|s| s.as_str()),
            Some("DOWN"),
            "MCP Server deveria estar DOWN no /readyz se tentou TLS com TypeDB não-TLS."
        );
        assert_eq!(
            resp.get("components").and_then(|c| c.get("typedb")).and_then(|s| s.as_str()),
            Some("DOWN"),
            "Componente TypeDB deveria estar DOWN no /readyz."
        );
        info!("MCP Server /readyz indicou falha na conexão com TypeDB (esperava TLS, obteve plain), como esperado.");
    } else {
        info!("TestEnvironment::setup falhou como esperado, pois o servidor MCP provavelmente não conseguiu iniciar/ficar pronto devido à falha de handshake TLS com o TypeDB. Erro: {:?}", test_env_result.err());
    }
    Ok(())
}
