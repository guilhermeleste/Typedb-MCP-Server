# Guia do Desenvolvedor: Introdução ao Desenvolvimento do Typedb-MCP-Server

Bem-vindo ao Guia do Desenvolvedor do Typedb-MCP-Server! Se você está interessado em entender a arquitetura interna deste projeto, contribuir com código, adicionar novas funcionalidades ou simplesmente aprender como ele é construído, este guia é para você.

## Filosofia do Projeto

O Typedb-MCP-Server é desenvolvido com as seguintes prioridades em mente:

* **Segurança:** A proteção dos dados e o controle de acesso são fundamentais. Isso se reflete no suporte a TLS e OAuth2.
* **Performance:** Construído em Rust e utilizando Tokio e Axum, o servidor visa ser leve, rápido e capaz de lidar com um número significativo de conexões e requisições concorrentes.
* **Observabilidade:** A capacidade de monitorar e entender o comportamento do servidor em tempo real é crucial. Métricas Prometheus, tracing distribuído e logging estruturado são integrados para este fim.
* **Extensibilidade:** A arquitetura é projetada para ser modular, facilitando a adição de novas "ferramentas" MCP e a adaptação a diferentes necessidades.
* **Conformidade com o Protocolo MCP:** Aderência à especificação do Model Context Protocol para garantir interoperabilidade com clientes compatíveis.
* **Qualidade de Código:** Esforço para manter um código limpo, bem testado e documentado, seguindo as melhores práticas do Rust.

## Tecnologias Chave

O Typedb-MCP-Server utiliza um stack de tecnologias moderno e focado em desempenho e segurança no ecossistema Rust:

* **Linguagem:** [Rust](https://www.rust-lang.org/) - Para segurança de memória, concorrência e performance.
* **Runtime Assíncrono:** [Tokio](https://tokio.rs/) - Para I/O assíncrono e concorrência eficiente.
* **Framework Web:** [Axum](https://github.com/tokio-rs/axum) - Para a camada HTTP/WebSocket, construído sobre Tokio e Hyper.
* **Banco de Dados Alvo:** [TypeDB](https://typedb.com/) - O banco de dados de grafos para o qual este servidor atua como gateway.
* **Protocolo de Comunicação:** [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) - O protocolo padrão para interação entre clientes e o servidor.
* **Autenticação (Opcional):** OAuth 2.0 / JWT - Utilizando crates como `jsonwebtoken` e `oauth2`.
* **TLS:** [Rustls](https://github.com/rustls/rustls) - Implementação TLS em Rust, usada através do `axum-server`.
* **Métricas:** [metrics](https://docs.rs/metrics/latest/metrics/) e [metrics-exporter-prometheus](https://docs.rs/metrics-exporter-prometheus/latest/metrics_exporter_prometheus/) - Para expor métricas no formato Prometheus.
* **Tracing:** [OpenTelemetry](https://opentelemetry.io/) e `tracing` - Para tracing distribuído e logging estruturado.
* **Configuração:** [config-rs](https://docs.rs/config/latest/config/) - Para carregar configurações de arquivos TOML e variáveis de ambiente.
* **Driver TypeDB:** [typedb-driver-rust](https://github.com/vaticle/typedb-driver-rust) - O driver oficial Rust para interagir com o TypeDB.

## O que Você Encontrará Neste Guia?

Este guia do desenvolvedor cobrirá:

1. **[Configuração do Ambiente de Desenvolvimento](./02_development_setup.md):** Como preparar sua máquina para compilar, testar e executar o servidor.
2. **[Arquitetura Detalhada](./03_architecture_deep_dive.md):** Uma exploração dos principais componentes do servidor e como eles interagem.
3. **[Estrutura do Código](./04_code_structure.md):** Um tour pelos módulos e arquivos do projeto.
4. **[Adicionando Novas Ferramentas MCP](./05_adding_new_mcp_tools.md):** Um passo a passo para estender as funcionalidades do servidor.
5. **[Trabalhando com Autenticação (OAuth2)](./06_working_with_auth.md):** Detalhes sobre a implementação da validação de tokens.
6. **[Trabalhando com Métricas e Tracing](./07_metrics_and_tracing.md):** Como adicionar e utilizar as capacidades de observabilidade.
7. **[Estratégia de Testes](./08_testing_strategy.md):** Como os testes são organizados e como escrever novos testes.
8. **[Docker para Desenvolvimento](./09_docker_for_development.md):** Utilizando Docker e Docker Compose para facilitar o desenvolvimento e os testes.

## Como Contribuir

Estamos entusiasmados com o seu interesse em contribuir! Seja corrigindo bugs, implementando novas funcionalidades, melhorando a documentação ou propondo ideias, sua ajuda é bem-vinda.

Por favor, consulte nosso **[Guia de Contribuição](../../CONTRIBUTING.md)** para detalhes sobre como começar, nosso processo de desenvolvimento e diretrizes de estilo de código.

Lembre-se também de aderir ao nosso **[Código de Conduta](../../CODE_OF_CONDUCT.md)** em todas as suas interações com o projeto.

## Próximos Passos

Se você é novo no projeto e deseja começar a desenvolver ou entender o código, recomendamos seguir para a [Configuração do Ambiente de Desenvolvimento](./02_development_setup.md).
