
# Guia do Desenvolvedor: Adicionando Novas Ferramentas MCP

O Typedb-MCP-Server foi projetado para ser extensível, permitindo que novas ferramentas do Model Context Protocol (MCP) sejam adicionadas de forma modular. Este guia detalha o processo passo a passo para implementar e registrar uma nova ferramenta MCP.

## Pré-requisitos

Antes de começar, certifique-se de que você:

* Configurou seu [Ambiente de Desenvolvimento](./02_development_setup.md).
* Tem um bom entendimento da [Estrutura do Código](./04_code_structure.md), especialmente dos módulos em `src/tools/` e `src/mcp_service_handler.rs`.
* Está familiarizado com a especificação do Model Context Protocol, particularmente no que diz respeito à definição e chamada de ferramentas.
* Possui um caso de uso claro para a nova ferramenta e como ela interagiria com o TypeDB.

## Passo a Passo para Adicionar uma Nova Ferramenta

Vamos supor que queremos adicionar uma nova ferramenta chamada `example_tool` que pertence a uma nova categoria (ou a uma existente).

### 1. Definir os Parâmetros da Ferramenta

Toda ferramenta MCP pode aceitar argumentos. Estes são definidos como uma struct Rust no arquivo `src/tools/params.rs`.

* Abra `src/tools/params.rs`.
* Defina uma nova struct para os parâmetros da sua ferramenta. Ela deve derivar `serde::Deserialize` (para desserializar os argumentos JSON da requisição MCP) e `schemars::JsonSchema` (para que a documentação do schema da ferramenta possa ser gerada ou inferida).
* Use `#[serde(rename_all = "camelCase")]` para que os campos JSON sejam em camelCase, enquanto os campos Rust permanecem em snake_case.
* Adicione descrições aos campos usando `#[schemars(description = "...")]` para melhorar a documentação da API.

**Exemplo (`src/tools/params.rs`):**

```rust
// ... outras structs de params ...

/// Parâmetros para a ferramenta `example_tool`.
#[derive(Deserialize, JsonSchema, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExampleToolParams {
    /// O nome do banco de dados alvo.
    #[schemars(description = "O nome do banco de dados alvo para esta operação de exemplo.")]
    pub database_name: String,

    /// Uma mensagem de exemplo para a ferramenta processar.
    #[schemars(description = "Uma mensagem de exemplo que a ferramenta irá processar.")]
    pub message: String,

    /// Um parâmetro opcional com valor padrão.
    #[serde(default = "default_example_optional_param")]
    #[schemars(description = "Um parâmetro opcional. Default: 10.")]
    pub optional_param: Option<i32>,
}

fn default_example_optional_param() -> Option<i32> {
    Some(10)
}
```

Se sua ferramenta não necessitar de parâmetros, você pode pular esta etapa, e o handler da ferramenta não receberá uma struct de parâmetros agregados (ou receberá um tipo vazio se a macro `#[tool]` exigir).

### 2. Implementar o Handler da Ferramenta

Crie a lógica para sua ferramenta. Se for uma nova categoria de ferramenta, você pode criar um novo arquivo Rust em `src/tools/` (ex: `src/tools/example_category.rs`). Se pertencer a uma categoria existente (como `query` ou `db_admin`), adicione o handler ao arquivo correspondente.

* O handler deve ser uma função `async`.
* Ele receberá uma referência `Arc<TypeDBDriver>` para interagir com o banco e a struct de parâmetros que você definiu (se houver).
* Deve retornar `Result<CallToolResult, ErrorData>`.
  * `CallToolResult::success(vec![Content::text("...")])` para sucesso. O conteúdo pode ser texto ou JSON (usando `Content::json(...)`).
  * `Err(ErrorData { ... })` para erros. Use as funções em `src/error.rs` (como `typedb_error_to_mcp_error_data`) para converter erros do TypeDB.

**Exemplo (em um novo arquivo `src/tools/example_category.rs` ou existente):**

```rust
// src/tools/example_category.rs
use std::sync::Arc;
use rmcp::model::{CallToolResult, Content, ErrorData}; // Adicione ErrorCode se necessário
use typedb_driver::TypeDBDriver;

use crate::error::McpServerError; // Se precisar de erros customizados da app
use super::params; // Para acessar ExampleToolParams

#[tracing::instrument(skip(driver, params), name = "tool_example_tool")]
pub async fn handle_example_tool(
    driver: Arc<TypeDBDriver>,
    params: params::ExampleToolParams,
) -> Result<CallToolResult, ErrorData> {
    tracing::info!(
        db.name = %params.database_name,
        message = %params.message,
        optional.param = ?params.optional_param,
        "Executando 'example_tool'."
    );

    // Lógica da sua ferramenta aqui...
    // Exemplo: conectar ao banco, abrir transação, executar query, etc.
    // if let Err(e) = driver.databases().contains(&params.database_name).await {
    //     return Err(typedb_error_to_mcp_error_data(&e, "example_tool (verificar banco)"));
    // }

    let output_message = format!(
        "Ferramenta de exemplo processou: '{}' para o banco '{}' com opcional: {:?}",
        params.message,
        params.database_name,
        params.optional_param.unwrap_or(-1) // Exemplo de uso do opcional
    );

    // Simular sucesso
    Ok(CallToolResult::success(vec![Content::text(output_message)]))

    // Simular erro
    // Err(ErrorData {
    //     code: ErrorCode::INTERNAL_ERROR, // Ou um código de erro customizado
    //     message: Cow::Owned("Algo deu errado na example_tool".to_string()),
    //     data: Some(serde_json::json!({"detail": "informação do erro"})),
    // })
}
```

* **Não esqueça de declarar o novo módulo em `src/tools/mod.rs` se você criou um novo arquivo:**

    ```rust
    // src/tools/mod.rs
    // ... outros mods ...
    pub mod example_category;
    ```

### 3. Registrar a Ferramenta no `McpServiceHandler`

Agora, informe ao servidor sobre sua nova ferramenta. Abra `src/mcp_service_handler.rs`.

* **Importe o Handler:**

    ```rust
    // src/mcp_service_handler.rs
    use crate::tools::{self, db_admin, query, schema_ops, example_category}; // Adicione seu novo módulo
    ```

* **Defina a Função da Ferramenta com a Macro `#[tool]`:**
    Adicione um método ao `impl McpServiceHandler` que usa a macro `#[tool]` para definir os metadados da ferramenta e delegar para sua função handler.

    ```rust
    // Dentro de impl McpServiceHandler { ... }

    #[tool(
        name = "example_tool", // Nome que será usado na chamada MCP
        description = "Uma ferramenta de exemplo para demonstrar a adição de novas funcionalidades."
    )]
    async fn tool_example_tool(
        &self,
        #[tool(aggr)] params: tools::params::ExampleToolParams, // Use #[tool(aggr)] para a struct de params
    ) -> Result<CallToolResult, ErrorData> {
        // Delega para sua função handler, passando o driver e os parâmetros
        example_category::handle_example_tool(self.driver.clone(), params).await
    }
    ```

  * `name`: O nome da ferramenta como será exposto via MCP.
  * `description`: Uma descrição legível da ferramenta.
  * `#[tool(aggr)] params: ...`: Indica que a struct `ExampleToolParams` deve ser desserializada a partir dos `arguments` da chamada MCP. Se sua ferramenta não tiver parâmetros, você pode omitir esta parte ou usar um tipo vazio. Para parâmetros individuais, use `#[tool(param)] nome_param: Tipo`.

* **Adicione a Ferramenta ao `tool_box!`:**
    A macro `tool_box!` é responsável por registrar as funções de ferramenta e seus atributos. Adicione o nome da *função método* (não o nome da string da ferramenta) à lista dentro da macro:

    ```rust
    // ...
    tool_box! {
        McpServiceHandler {
            tool_query_read, tool_insert_data, tool_delete_data, tool_update_data,
            tool_define_schema, tool_undefine_schema, tool_get_schema,
            tool_create_database, tool_database_exists, tool_list_databases, tool_delete_database,
            tool_validate_query,
            tool_example_tool // <<< ADICIONE AQUI
        } mcp_service_handler_tool_box_accessor
    }
    // ...
    ```

* **Defina os Escopos OAuth2 Necessários (se aplicável):**
    No construtor `McpServiceHandler::new`, adicione uma entrada ao `HashMap` `tool_required_scopes` para sua nova ferramenta, especificando os escopos OAuth2 que um cliente deve possuir no token JWT para poder executar esta ferramenta. Se a ferramenta não exigir escopos específicos além dos globais (se houver), você pode fornecer um `vec![]` vazio ou omitir a entrada se o comportamento padrão for adequado.

    ```rust
    // Dentro de McpServiceHandler::new(...)
    // ...
    tool_scopes.insert(
        "example_tool".to_string(), // Deve corresponder ao `name` em #[tool(name = "...")]
        vec!["example:execute".to_string(), "typedb:read_data".to_string()] // Escopos de exemplo
    );
    // Ou, se nenhum escopo específico:
    // tool_scopes.insert("example_tool".to_string(), vec![]);
    // ...
    ```

    Se OAuth2 estiver desabilitado no servidor, esta verificação de escopo é ignorada.

### 4. Adicionar Testes de Integração

É crucial adicionar testes de integração para sua nova ferramenta.

* Crie ou modifique um arquivo de teste em `tests/integration/` (ex: `tests/integration/example_tool_tests.rs`).
* Use o `TestMcpClient` (de `tests/common/client.rs`) para se conectar ao servidor e chamar sua nova ferramenta.
* Teste cenários de sucesso e de falha.
* Se sua ferramenta requer escopos OAuth2, teste com tokens que possuem e não possuem os escopos necessários.

**Exemplo de Teste (conceitual):**

```rust
// tests/integration/example_tool_tests.rs
// ... imports e setup do ambiente de teste ...

#[tokio::test]
async fn test_example_tool_succeeds() {
    // ... setup do ambiente docker e cliente MCP ...
    let mut client = mcp_client_with_scope("example:execute typedb:read_data").await; // Fornece escopos necessários

    let params = json!({
        "databaseName": "test_db_example",
        "message": "Olá Mundo",
        "optionalParam": 123
    });

    let result = client.call_tool("example_tool", Some(params)).await;
    assert!(result.is_ok(), "A chamada da example_tool falhou: {:?}", result.err());

    let response_content = result.unwrap().content.as_text().unwrap().text.clone();
    assert!(response_content.contains("Olá Mundo"));
    assert!(response_content.contains("test_db_example"));
    assert!(response_content.contains("123"));

    // ... teardown do ambiente ...
}

#[tokio::test]
async fn test_example_tool_fails_without_scope() {
    // ... setup ...
    let mut client = mcp_client_with_scope("some:other_scope").await; // Não tem os escopos necessários

    let params = json!({ "databaseName": "test_db", "message": "Teste" });
    let result = client.call_tool("example_tool", Some(params)).await;
    assert!(result.is_err(), "A chamada da example_tool deveria falhar por falta de escopo");
    // Verificar o código de erro específico de autorização
    if let Err(McpClientError::McpErrorResponse { code, .. }) = result {
        // O código para "Authorization Failed" no RMCP pode ser -32001
        // ou outro código específico de erro de permissão. Verifique src/error.rs.
        // Para este exemplo, vamos supor que é um erro de permissão genérico.
        assert_eq!(code.0, -32001 /* MCP_ERROR_CODE_AUTHORIZATION_FAILED */);
    } else {
        panic!("Tipo de erro inesperado: {:?}", result);
    }
    // ... teardown ...
}
```

### 5. Documentar a Nova Ferramenta

Atualize a documentação para incluir sua nova ferramenta:

* Adicione uma entrada para sua ferramenta em `docs/reference/api.md`. Inclua:
  * Nome da ferramenta.
  * Descrição.
  * Escopos OAuth2 necessários.
  * O JSON Schema dos parâmetros de entrada (você pode gerar isso usando `cargo test -- --show-output` se tiver um teste que imprima o schema, ou inspecionando a saída do `McpServiceHandler::list_tools` via um cliente MCP).
  * Uma descrição do formato de saída esperado.
  * Um exemplo de chamada JSON-RPC e uma resposta de exemplo.
* Mencione a nova ferramenta no `docs/user_guide/07_mcp_tools_overview.md` se apropriado.

### 6. Formatar e Lintar

Antes de commitar, execute:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -W clippy::cargo -D warnings
```

## Considerações Adicionais

* **Tratamento de Erros:** Seja robusto no tratamento de erros dentro do seu handler. Converta erros do TypeDB ou erros de lógica de negócios em `ErrorData` significativos para o cliente MCP.
* **Segurança:** Considere as implicações de segurança da sua nova ferramenta. Valide todas as entradas.
* **Performance:** Se sua ferramenta realizar operações intensivas, pense em como otimizá-la.
* **Idempotência:** Se aplicável, tente tornar sua ferramenta idempotente.

Seguindo estes passos, você poderá estender o Typedb-MCP-Server com novas e poderosas ferramentas para interagir com o TypeDB.
