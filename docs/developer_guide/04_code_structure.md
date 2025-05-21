
# Detalhamento da Pasta `src/` (Código-Fonte Principal)

A pasta `src/` contém todo o código Rust que compõe a lógica do Typedb-MCP-Server.

* **`main.rs`**:
  * **Propósito:** Ponto de entrada da aplicação binária.
  * **Responsabilidades:**
    * Carregar e processar a configuração inicial (usando o módulo `config`).
    * Configurar o logging e o tracing (usando os módulos `telemetry` e `tracing_subscriber`).
    * Inicializar o runtime Tokio para programação assíncrona.
    * Estabelecer a conexão com o servidor TypeDB (usando o módulo `db`).
    * Configurar e iniciar o servidor HTTP/WebSocket Axum.
    * Montar os middlewares (OAuth2, CORS, tracing, etc.).
    * Definir as rotas HTTP (para `/metrics`, `/health`, `/readyz`) e a rota WebSocket MCP.
    * Instanciar e compartilhar o estado da aplicação (`AppState`), incluindo o `McpServiceHandler`.
    * Gerenciar o graceful shutdown da aplicação.

* **`lib.rs`**:
  * **Propósito:** Define o crate da biblioteca (`typedb_mcp_server_lib`).
  * **Responsabilidades:**
    * Declara e exporta publicamente os principais módulos da lógica do servidor.
    * Permite que a lógica do servidor seja potencialmente reutilizada ou testada como uma biblioteca separada do binário.

* **`auth.rs`**:
  * **Propósito:** Lida com toda a lógica de autenticação e autorização de clientes.
  * **Responsabilidades:**
    * Middleware Axum para validar tokens JWT Bearer.
    * Implementação do `JwksCache` para buscar e cachear chaves públicas do provedor OAuth2.
    * Validação de claims do JWT (issuer, audience, expiração, escopos).
    * Definição do `ClientAuthContext` para propagar informações do usuário autenticado.
    * Geração de erros de autenticação específicos (`AuthErrorDetail`).

* **`config.rs`**:
  * **Propósito:** Define as estruturas de dados para a configuração da aplicação e a lógica para carregá-las.
  * **Responsabilidades:**
    * Structs fortemente tipadas (`Settings`, `TypeDB`, `Server`, `OAuth`, etc.) que espelham o arquivo TOML.
    * Lógica para carregar configurações de um arquivo TOML e de variáveis de ambiente, com precedência definida.
    * Definição de valores padrão para as configurações.

* **`db.rs`**:
  * **Propósito:** Gerencia a conexão com o servidor TypeDB.
  * **Responsabilidades:**
    * Função `connect` para estabelecer uma conexão com TypeDB usando o `typedb-driver`.
    * Suporte para conexões TLS com TypeDB, incluindo o uso de um CA customizado.

* **`error.rs`**:
  * **Propósito:** Centraliza as definições de erro customizadas da aplicação.
  * **Responsabilidades:**
    * Enum `McpServerError` que representa os diferentes tipos de erros que podem ocorrer.
    * Enum `AuthErrorDetail` para erros específicos de autenticação/autorização.
    * Funções para converter erros internos e erros do `typedb-driver` para o formato `ErrorData` do protocolo MCP.

* **`mcp_service_handler.rs`**:
  * **Propósito:** É o coração da lógica do servidor MCP, implementando o trait `ServerHandler` da crate `rmcp`.
  * **Responsabilidades:**
    * Registro de todas as ferramentas MCP disponíveis usando a macro `#[tool]` e `tool_box!`.
    * Despacho de chamadas de `tools/call` para os handlers de ferramenta apropriados.
    * Verificação de escopos OAuth2 necessários para cada ferramenta antes da execução.
    * Implementação dos métodos MCP para listar ferramentas, recursos e templates de recursos.
    * Servir recursos estáticos e dinâmicos (como o esquema do banco).

* **`metrics.rs`**:
  * **Propósito:** Define e registra todas as métricas da aplicação no formato Prometheus.
  * **Responsabilidades:**
    * Constantes para nomes de métricas e labels.
    * Função `register_metrics_descriptions` para descrever contadores, gauges e histogramas.
    * As métricas são expostas através de um endpoint HTTP gerenciado em `main.rs`.

* **`resources.rs`**:
  * **Propósito:** Gerencia os recursos estáticos e dinâmicos que o servidor MCP expõe.
  * **Responsabilidades:**
    * Definição de recursos estáticos (ex: guias informativos sobre TypeQL).
    * Lógica para servir recursos dinâmicos, como o esquema atual de um banco de dados (`schema://current/...`).

* **`telemetry.rs`**:
  * **Propósito:** Configura o pipeline de tracing distribuído usando OpenTelemetry.
  * **Responsabilidades:**
    * Inicialização do exportador OTLP (geralmente gRPC).
    * Configuração do sampler de tracing.
    * Integração com a crate `tracing` para que os spans sejam exportados.
    * Função de shutdown para o provider de tracing.

* **`transport.rs`**:
  * **Propósito:** Adapta a comunicação WebSocket do Axum para o formato esperado pela crate `rmcp`.
  * **Responsabilidades:**
    * Struct `WebSocketTransport` que implementa as traits `Stream` e `Sink` para mensagens JSON-RPC MCP.
    * Serialização de `ServerJsonRpcMessage` para frames de texto WebSocket.
    * Desserialização de frames de texto WebSocket para `ClientJsonRpcMessage`.

* **`tools/` (Diretório)**:
  * **`mod.rs`**: Declara os submódulos de ferramentas.
  * **`params.rs`**:
    * **Propósito:** Define as structs de parâmetros de entrada para cada ferramenta MCP.
    * **Responsabilidades:** Estas structs usam `serde::Deserialize` para desserializar os `arguments` da chamada da ferramenta e `schemars::JsonSchema` para (potencialmente) gerar documentação de API.
  * **`query.rs`**: Contém os handlers para ferramentas relacionadas a consultas de dados (ex: `query_read`, `insert_data`, `validate_query`).
  * **`schema_ops.rs`**: Contém os handlers para ferramentas relacionadas a operações de esquema (ex: `define_schema`, `get_schema`).
  * **`db_admin.rs`**: Contém os handlers para ferramentas relacionadas à administração de bancos de dados (ex: `create_database`, `list_databases`).
  * *(Outros arquivos de ferramentas, se existirem)*

## Detalhamento da Pasta `tests/`

A pasta `tests/` contém os testes automatizados para garantir a corretude e robustez do servidor.

* **`common/`**:
  * **`mod.rs`**: Módulo agregador para helpers de teste.
  * **`auth_helpers.rs`**: Utilitários para gerar tokens JWT de teste para cenários de OAuth2.
  * **`client.rs`**: Implementação de um `TestMcpClient` para interagir com o servidor MCP durante os testes de integração.
  * **`docker_helpers.rs`**: Utilitários para orquestrar contêineres Docker (usando `docker-compose`) para os testes de integração, gerenciando o ciclo de vida de serviços dependentes como TypeDB e mocks.
* **`integration/`**:
  * **`mod.rs`**: Módulo agregador para os testes de integração.
  * **`<nome_do_teste>_tests.rs`**: Arquivos individuais para diferentes suítes de testes de integração (ex: `connection_tests.rs`, `db_admin_tool_tests.rs`, `observability_tests.rs`). Estes testes verificam a funcionalidade do servidor como um todo, interagindo com ele através de seus endpoints expostos.

## Outros Arquivos e Pastas Relevantes

* **`Cargo.toml`**: Define os metadados do projeto, dependências, features e configurações de workspace.
* **`Dockerfile`**: Instruções para construir a imagem Docker do servidor.
* **`docker-compose.yml` e `docker-compose.test.yml`**: Usados para orquestrar o servidor e suas dependências em ambientes Docker.
* **`scripts/`**: Contém scripts úteis para tarefas de desenvolvimento como geração de certificados, build multi-plataforma, execução de testes de cobertura.
* **Arquivos de Configuração (`.toml` na raiz e em `config/`):** Fornecem exemplos e configurações padrão para diferentes ambientes.

Entender como esses componentes e arquivos se relacionam é fundamental para trabalhar efetivamente no código do Typedb-MCP-Server. Para um mergulho mais profundo na interação entre os componentes, consulte a [Arquitetura Detalhada](./03_architecture_deep_dive.md).
