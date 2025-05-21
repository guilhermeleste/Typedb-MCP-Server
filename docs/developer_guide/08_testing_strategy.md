
# Guia do Desenvolvedor: Estratégia de Testes

Uma estratégia de testes robusta é fundamental para garantir a qualidade, confiabilidade e manutenibilidade do Typedb-MCP-Server. Este documento descreve os diferentes tipos de testes empregados no projeto, como executá-los e diretrizes para escrever novos testes.

## Filosofia de Testes

Nossa filosofia de testes se baseia nos seguintes princípios:

* **Confiança:** Os testes devem nos dar confiança de que o sistema funciona como esperado e que novas alterações não quebram funcionalidades existentes.
* **Cobertura Abrangente:** Esforçamo-nos para cobrir os principais fluxos de usuários, casos de borda e cenários de erro.
* **Isolamento:** Testes unitários devem ser isolados e não depender de sistemas externos. Testes de integração podem envolver dependências, mas devem ser gerenciáveis e reproduzíveis.
* **Velocidade:** Testes devem rodar rapidamente para fornecer feedback ágil aos desenvolvedores. Testes mais lentos (como os de integração completos) podem ser executados com menos frequência ou em pipelines de CI dedicados.
* **Manutenibilidade:** Os testes devem ser fáceis de entender, manter e depurar.

## Tipos de Testes

O projeto utiliza principalmente os seguintes tipos de testes:

### 1. Testes Unitários

* **Localização:** Geralmente no mesmo arquivo do código que está sendo testado (dentro de um módulo `#[cfg(test)] mod tests { ... }`) ou em arquivos de módulo de teste (ex: `src/auth/tests.rs` se `src/auth.rs` for um módulo).
* **Propósito:** Verificar a corretude de pequenas unidades de código (funções, métodos de struct) de forma isolada.
* **Características:**
  * Rápidos de executar.
  * Não devem ter dependências externas (ex: rede, sistema de arquivos, banco de dados real).
  * Utilizam mocks ou stubs para simular dependências, se necessário (ex: usando a crate `mockall` ou implementações de teste de traits).
* **Exemplo:**
  * Testar a lógica de parsing de configuração em `src/config.rs`.
  * Testar a lógica de validação de um token JWT em `src/auth.rs` com tokens de exemplo.
  * Testar a formatação de uma mensagem de erro em `src/error.rs`.
* **Execução:**

    ```bash
    cargo test --lib # Para testes unitários na biblioteca
    cargo test --bin typedb_mcp_server # Para testes unitários no binário (se houver)
    # Ou simplesmente:
    cargo test <nome_do_modulo_ou_funcao_de_teste> # Para testes específicos
    ```

### 2. Testes de Integração

* **Localização:** Na pasta `tests/integration/`. Cada arquivo (ex: `connection_tests.rs`, `db_admin_tool_tests.rs`) geralmente foca em um aspecto específico da integração do sistema.
* **Propósito:** Verificar a interação entre diferentes componentes do Typedb-MCP-Server e, crucialmente, sua integração com serviços externos como o TypeDB Server e, opcionalmente, um mock de servidor OAuth2.
* **Características:**
  * Mais lentos que testes unitários, pois envolvem a inicialização de serviços reais.
  * Utilizam o `TestMcpClient` (de `tests/common/client.rs`) para simular um cliente MCP real que se conecta ao servidor via WebSocket.
  * Utilizam `DockerComposeEnv` (de `tests/common/docker_helpers.rs`) para orquestrar o ambiente de teste, incluindo:
    * Typedb-MCP-Server (compilado a partir do código atual).
    * TypeDB Server (`typedb-server-it`).
    * Mock de servidor OAuth2 JWKS (`mock-auth-server-it`, veja `README.docker.md`).
  * Podem testar o fluxo completo de uma requisição MCP, desde a conexão WebSocket, autenticação (se aplicável), chamada de ferramenta, interação com TypeDB, até a resposta ao cliente.
* **Exemplos:**
  * Conectar um cliente, chamar a ferramenta `create_database`, verificar se o banco foi criado no TypeDB e se o cliente recebeu a resposta correta.
  * Testar cenários de autenticação OAuth2 com tokens válidos, inválidos e expirados.
  * Verificar se os endpoints `livez`, `/readyz` e `/metrics` respondem corretamente.
* **Execução:**

    ```bash
    cargo test --test <nome_do_arquivo_de_teste_de_integracao> # Ex: cargo test --test connection_tests
    # Ou para todos os testes de integração (e unitários):
    cargo test --all-features
    ```

    **Nota:** Os testes de integração geralmente requerem que o Docker e Docker Compose estejam instalados e funcionando no ambiente de execução. Eles podem ser marcados com `#[ignore]` se forem muito lentos para execuções locais frequentes e rodarem principalmente em CI. Usar `#[serial_test::serial]` pode ser necessário para testes que modificam estado global do Docker ou usam portas fixas.

### 3. Testes de Documentação (Doc-tests)

* **Localização:** Embutidos nos comentários de documentação do código Rust (blocos de código dentro de `///` ou `//!` que são marcados como testáveis).
* **Propósito:** Garantir que os exemplos de código na documentação sejam corretos e funcionem como esperado.
* **Características:** Geralmente pequenos e focados em ilustrar o uso de uma API específica.
* **Execução:** `cargo test --doc`

## Helpers de Teste Comuns (`tests/common/`)

A pasta `tests/common/` contém módulos Rust com utilitários compartilhados para facilitar a escrita de testes de integração:

* **`client.rs` (`TestMcpClient`):** Um cliente MCP de teste que pode se conectar ao servidor via WebSocket, enviar requisições MCP e receber respostas. Lida com a serialização/desserialização JSON-RPC.
* **`auth_helpers.rs`:** Funções para gerar tokens JWT de teste com diferentes claims (ex: válidos, expirados, com escopos específicos) para testar cenários de autenticação OAuth2.
* **`docker_helpers.rs` (`DockerComposeEnv`):** Facilita o gerenciamento do ciclo de vida de ambientes Docker Compose para os testes. Ele pode iniciar (`up`), parar (`down`), verificar a saúde de serviços e obter logs de contêineres. Isso garante que os testes de integração tenham um ambiente limpo e consistente.

## Estratégia de Cobertura de Teste

* **Testes Unitários:** Devem cobrir a lógica de negócios, funções de utilidade, parsing, validações e casos de borda de componentes individuais.
* **Testes de Integração:** Devem cobrir:
  * Fluxos de usuário de ponta a ponta para cada ferramenta MCP.
  * Cenários de autenticação e autorização (com e sem OAuth2, tokens válidos/inválidos, escopos).
  * Conectividade e interação com o TypeDB (incluindo TLS, se aplicável).
  * Funcionalidade dos endpoints HTTP (métricas, health checks).
  * Resiliência básica (ex: como o servidor lida com a indisponibilidade temporária do TypeDB).
  * Configurações chave do servidor.

## Executando Testes

* **Todos os testes (unitários e de integração):**

    ```bash
    cargo test --all-features
    ```

* **Apenas testes unitários:**

    ```bash
    cargo test --lib # Para a biblioteca src/lib.rs e seus módulos
    # ou
    cargo test -p typedb_mcp_server_lib # Se o crate for nomeado explicitamente
    ```

* **Apenas um teste de integração específico:**

    ```bash
    cargo test --test nome_do_arquivo_de_teste_de_integracao # ex: connection_tests
    ```

* **Testes de Documentação:**

    ```bash
    cargo test --doc
    ```

* **Testes de Cobertura:**
    O script [`scripts/coverage.sh`](../../scripts/coverage.sh) usa `grcov` para gerar um relatório de cobertura de código.

    ```bash
    ./scripts/coverage.sh
    ```

    O relatório HTML será gerado em `target/coverage/index.html`.

## Escrevendo Novos Testes

* **Para Lógica Interna:** Adicione testes unitários no mesmo arquivo ou em um submódulo `tests`. Mantenha-os pequenos, focados e rápidos. Use mocks quando necessário.
* **Para Interações de Componentes ou Funcionalidades de API:** Adicione testes de integração em `tests/integration/`.
  * Crie um novo arquivo `.rs` se estiver testando uma nova área funcional.
  * Utilize `DockerComposeEnv` para configurar um ambiente limpo.
  * Use `TestMcpClient` para interagir com o servidor.
  * Limpe o ambiente após a execução do teste (o `Drop` trait em `DockerComposeEnv` geralmente cuida disso, mas seja explícito se necessário).
  * Considere o uso de `#[serial_test::serial]` ou nomes de projeto Docker únicos se os testes não puderem rodar em paralelo.
* **Nomenclatura:** Use nomes de teste descritivos que indiquem o que está sendo testado e o resultado esperado (ex: `test_create_database_succeeds_when_db_does_not_exist`).
* **Asserts:** Use os macros `assert!`, `assert_eq!`, `assert_ne!` de forma clara. Para resultados de `Result`, use `.unwrap()` ou `.expect()` quando o sucesso é esperado, ou `assert!(result.is_err())` e verifique o tipo/conteúdo do erro quando uma falha é esperada.

Manter uma suíte de testes abrangente e bem escrita é vital para a saúde a longo prazo do projeto. Contribuições que incluem testes apropriados são altamente valorizadas.
