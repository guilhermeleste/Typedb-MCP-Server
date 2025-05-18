# Bem-vindo à Documentação do Typedb-MCP-Server

O Typedb-MCP-Server é um servidor Rust de alta performance, seguro e extensível, projetado para atuar como um gateway MCP (Model Context Protocol) para o banco de dados TypeDB. Ele permite que clientes compatíveis com MCP interajam com o TypeDB para realizar consultas, modificar esquemas e administrar bancos de dados de forma eficiente e segura.

Esta documentação abrangente foi criada para ajudá-lo a entender, configurar, usar e contribuir para o Typedb-MCP-Server.

## Para Quem é Esta Documentação?

Esta documentação é dividida em seções para atender a diferentes necessidades:

* **Usuários e Administradores:** Se você deseja instalar, configurar e executar o servidor, ou entender como ele se integra com clientes MCP e o TypeDB, comece pelo **[Guia do Usuário](./user_guide/01_introduction.md)**.
* **Desenvolvedores:** Se você está interessado em entender a arquitetura interna do servidor, contribuir com o código, adicionar novas ferramentas MCP ou estender suas funcionalidades, o **[Guia do Desenvolvedor](./developer_guide/01_introduction.md)** é para você.
* **Todos:** A seção de **[Referência](./reference/configuration.md)** contém detalhes específicos sobre todas as opções de configuração, ferramentas MCP expostas e endpoints HTTP.

## Navegando pela Documentação

Aqui está uma visão geral das principais seções da documentação:

* **[Guia do Usuário](./user_guide/01_introduction.md)**
  * [Introdução ao Typedb-MCP-Server para Usuários](./user_guide/01_introduction.md)
  * [Pré-requisitos](./user_guide/02_prerequisites.md)
  * [Instalação (Código-Fonte e Docker)](./user_guide/03_installation.md)
  * [Configuração do Servidor](./user_guide/04_configuration.md) (Visão Geral)
  * [Executando o Servidor](./user_guide/05_running_the_server.md)
  * [Conectando Clientes MCP](./user_guide/06_connecting_clients.md)
  * [Visão Geral das Ferramentas MCP](./user_guide/07_mcp_tools_overview.md)
  * [Observabilidade (Métricas, Health Checks, Logging)](./user_guide/08_observability.md)
  * [Considerações Básicas de Segurança](./user_guide/09_security_basics.md)
  * [Troubleshooting Comum](./user_guide/10_troubleshooting.md)

* **[Guia do Desenvolvedor](./developer_guide/01_introduction.md)**
  * [Introdução ao Desenvolvimento](./developer_guide/01_introduction.md)
  * [Configuração do Ambiente de Desenvolvimento](./developer_guide/02_development_setup.md)
  * [Arquitetura Detalhada](./developer_guide/03_architecture_deep_dive.md) (Veja também o arquivo de [Arquitetura Principal](./architecture.md))
  * [Estrutura do Código](./developer_guide/04_code_structure.md)
  * [Adicionando Novas Ferramentas MCP](./developer_guide/05_adding_new_mcp_tools.md)
  * [Trabalhando com Autenticação (OAuth2)](./developer_guide/06_working_with_auth.md)
  * [Trabalhando com Métricas e Tracing](./developer_guide/07_metrics_and_tracing.md)
  * [Estratégia de Testes](./developer_guide/08_testing_strategy.md)
  * [Docker para Desenvolvimento](./developer_guide/09_docker_for_development.md)

* **[Documentação de Referência](./reference/)**
  * [Referência Completa de Configuração](./reference/configuration.md)
  * [Referência da API (Ferramentas MCP e Endpoints HTTP)](./reference/api.md)
  * [Lista Detalhada de Métricas](./reference/metrics_list.md)

* **[Tópicos Avançados](./advanced_topics/)** (A ser expandido)
  * [Segurança Aprofundada](./advanced_topics/security_deep_dive.md)
  * [Observabilidade Aprofundada](./advanced_topics/observability_deep_dive.md)
  * [Otimização de Performance](./advanced_topics/performance_tuning.md)
  * [Resiliência e Tolerância a Falhas](./advanced_topics/resilience_and_failover.md)

* **[Perguntas Frequentes (FAQ)](./FAQ.md)**

## Primeiros Passos Rápidos

Se você já tem familiaridade com TypeDB e Rust, e quer apenas colocar o servidor para rodar:

1. Clone o repositório: `git clone https://github.com/guilhermeleste/Typedb-MCP-Server.git`
2. Navegue até o diretório: `cd Typedb-MCP-Server`
3. Configure a senha do TypeDB: `export TYPEDB_PASSWORD="sua_senha"`
4. Compile e execute: `cargo run --release`

Para uma configuração mais robusta ou para produção, recomendamos fortemente a leitura do [Guia do Usuário](./user_guide/01_introduction.md) e da [Referência de Configuração](./reference/configuration.md).

## Contribuindo

Estamos abertos a contribuições! Por favor, veja nosso [Guia de Contribuição](../CONTRIBUTING.md) para mais detalhes.

## Reportando Problemas

Encontrou um bug ou tem alguma sugestão? Por favor, abra uma [issue no GitHub](https://github.com/guilhermeleste/Typedb-MCP-Server/issues).

---

Esperamos que esta documentação seja útil. Se você tiver alguma dúvida ou feedback, não hesite em nos contatar através das issues do projeto.
