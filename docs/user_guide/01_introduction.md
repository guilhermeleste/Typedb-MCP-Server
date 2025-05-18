# Guia do Usuário: Introdução ao Typedb-MCP-Server

Bem-vindo ao Guia do Usuário do Typedb-MCP-Server! Este guia foi elaborado para ajudá-lo a instalar, configurar e utilizar o Typedb-MCP-Server de forma eficaz.

## O que é o Typedb-MCP-Server?

O Typedb-MCP-Server é um servidor de alto desempenho, seguro e extensível, construído em Rust. Ele atua como um **gateway** que utiliza o **Model Context Protocol (MCP)** para facilitar a interação entre diversas aplicações clientes e um banco de dados **TypeDB**.

Em essência, ele permite que você:

* **Conecte** aplicações que "falam" MCP (como modelos de linguagem grandes, ferramentas de desenvolvimento especializadas ou outros microsserviços) a um servidor TypeDB.
* **Execute** operações no TypeDB, como consultas de dados (TypeQL), manipulação de esquemas e tarefas administrativas de banco de dados, através de um conjunto padronizado de "ferramentas" expostas pelo protocolo MCP.
* **Garanta** a comunicação de forma segura, com suporte a TLS e autenticação opcional via OAuth2/JWT.
* **Monitore** o desempenho e a saúde do servidor através de métricas Prometheus e logs estruturados.

## Para Quem é Este Guia?

Este guia é destinado principalmente a:

* **Usuários Finais e Administradores de Sistema:** Que precisam instalar, configurar, executar e monitorar o Typedb-MCP-Server.
* **Desenvolvedores de Aplicações Cliente:** Que desejam entender como seus clientes MCP podem se conectar e interagir com o servidor.

Se você está interessado em contribuir com o desenvolvimento do próprio Typedb-MCP-Server ou entender sua arquitetura interna em profundidade, consulte o **[Guia do Desenvolvedor](../developer_guide/01_introduction.md)**.

## O que Você Encontrará Neste Guia?

Este guia irá cobrir os seguintes tópicos:

1. **[Pré-requisitos](./02_prerequisites.md):** Software e conhecimentos necessários antes de começar.
2. **[Instalação](./03_installation.md):** Como instalar o servidor a partir do código-fonte ou usando Docker.
3. **[Configuração do Servidor](./04_configuration.md):** Uma visão geral de como configurar o servidor, com links para a [Referência Completa de Configuração](../reference/configuration.md).
4. **[Executando o Servidor](./05_running_the_server.md):** Comandos para iniciar e gerenciar o processo do servidor.
5. **[Conectando Clientes MCP](./06_connecting_clients.md):** Como os clientes se conectam e se autenticam.
6. **[Visão Geral das Ferramentas MCP](./07_mcp_tools_overview.md):** Uma introdução às capacidades que o servidor expõe.
7. **[Observabilidade](./08_observability.md):** Como monitorar o servidor usando métricas, health checks e logs.
8. **[Considerações Básicas de Segurança](./09_security_basics.md):** Recomendações para proteger sua instância.
9. **[Troubleshooting Comum](./10_troubleshooting.md):** Soluções para problemas frequentes.

## Por Que Usar o Typedb-MCP-Server?

* **Interface Padronizada:** Utiliza o Model Context Protocol, facilitando a integração com um ecossistema crescente de ferramentas e clientes compatíveis.
* **Desempenho e Eficiência:** Construído em Rust com foco em operações assíncronas para alto throughput e baixa latência.
* **Segurança:** Oferece TLS para comunicação segura e integração com OAuth2 para autenticação robusta de clientes.
* **Observabilidade Completa:** Métricas Prometheus, tracing distribuído (OpenTelemetry) e logging configurável permitem um monitoramento eficaz.
* **Flexibilidade:** Ampla gama de opções de configuração para adaptar o servidor às suas necessidades específicas.

## Próximos Passos

Recomendamos começar pelos [Pré-requisitos](./02_prerequisites.md) e seguir para a [Instalação](./03_installation.md).

Se você tiver alguma dúvida não coberta por esta documentação, sinta-se à vontade para consultar a seção de [Perguntas Frequentes (FAQ)](../FAQ.md) ou abrir uma [issue no GitHub](https://github.com/guilhermeleste/Typedb-MCP-Server/issues).
