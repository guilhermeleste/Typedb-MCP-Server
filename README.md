
# Typedb-MCP-Server

Servidor Rust de alta performance, seguro e extensível, atuando como gateway MCP (Model Context Protocol) para o banco de dados TypeDB. Expõe endpoints WebSocket (MCP), HTTP REST para métricas Prometheus, integra autenticação OAuth2 opcional, tracing distribuído (OpenTelemetry) e métricas detalhadas.

Este projeto visa fornecer uma ponte robusta e eficiente entre clientes que utilizam o Model Context Protocol e um backend TypeDB, com foco em segurança, observabilidade e extensibilidade.

---

## Índice

- [Typedb-MCP-Server](#typedb-mcp-server)
	- [Índice](#índice)
	- [Visão Geral](#visão-geral)
	- [Principais Funcionalidades](#principais-funcionalidades)
	- [Status do Projeto](#status-do-projeto)
	- [Começando](#começando)
		- [Pré-requisitos](#pré-requisitos)
		- [Instalação Rápida (Docker)](#instalação-rápida-docker)
		- [Instalação a partir do Código-Fonte](#instalação-a-partir-do-código-fonte)
	- [Configuração Essencial](#configuração-essencial)
	- [Execução](#execução)
	- [Endpoints Principais](#endpoints-principais)
	- [Documentação Completa](#documentação-completa)
	- [Contribuição](#contribuição)
	- [Licença](#licença)
	- [Agradecimentos](#agradecimentos)

---

## Visão Geral

O Typedb-MCP-Server é projetado para ser um componente central em arquiteturas que necessitam de interação programática e segura com o TypeDB. Ele implementa o Model Context Protocol, permitindo que clientes (como modelos de linguagem grandes ou outras aplicações) interajam com o banco de dados através de um conjunto padronizado de ferramentas para consulta, manipulação de esquema e administração de banco de dados.

Construído em Rust, o servidor prioriza performance e segurança, utilizando o runtime Tokio para operações assíncronas e o framework Axum para a camada web.

## Principais Funcionalidades

- **Gateway MCP para TypeDB:** Expõe as funcionalidades do TypeDB através do Model Context Protocol.
- **Transporte WebSocket:** Comunicação principal via WebSockets (com suporte a WSS para TLS).
- **Segurança:**
  - Suporte a TLS (HTTPS/WSS) para o servidor MCP.
  - Suporte a TLS para a conexão com o TypeDB.
  - Autenticação de cliente opcional via OAuth2/JWT.
  - Controle de escopos por ferramenta MCP (quando OAuth2 está habilitado).
- **Observabilidade:**
  - Métricas detalhadas no formato Prometheus expostas via endpoint HTTP (`/metrics`).
  - Tracing distribuído com OpenTelemetry (exportação OTLP).
  - Logging estruturado e configurável.
- **Configurabilidade:** Configuração flexível via arquivo TOML e/ou variáveis de ambiente.
- **Extensibilidade:** Arquitetura modular que facilita a adição de novas ferramentas MCP.
- **Dockerização:** Suporte completo para execução em contêineres Docker, incluindo exemplos com `docker-compose`.
- **Health Checks:** Endpoints `/livez` e `/readyz` para monitoramento de saúde e prontidão.

## Status do Projeto

- [Indicar o status atual do projeto: Em desenvolvimento ativo, Beta, Estável, etc.]
- [Mencionar quaisquer limitações conhecidas ou funcionalidades futuras importantes.]

## Começando

### Pré-requisitos

- **Rust:** Versão especificada em `rust-toolchain.toml` (atualmente >= 1.87.0).
- **Cargo:** Instalado com o Rust.
- **TypeDB Server:** Uma instância do TypeDB (versão 3.2.0 ou compatível) em execução e acessível.
- **Docker & Docker Compose (Opcional):** Para execução via contêineres.
- **Cliente MCP:** Uma aplicação ou ferramenta capaz de se comunicar via Model Context Protocol.

### Instalação Rápida (Docker)

A maneira mais rápida de executar o servidor é usando Docker Compose.
Consulte o [README.docker.md](./README.docker.md) e o arquivo [docker-compose.yml](./docker-compose.yml) para exemplos e instruções detalhadas.

```sh
# Exemplo básico (clone o repositório primeiro)
# cd Typedb-MCP-Server
# export TYPEDB_PASSWORD="sua_senha_do_typedb" # Se o TypeDB exigir senha
# docker-compose up -d
```

### Instalação a partir do Código-Fonte

1. **Clone o repositório:**

    ```sh
    git clone https://github.com/guilhermeleste/Typedb-MCP-Server.git
    cd Typedb-MCP-Server
    ```

2. **Compile o projeto:**

    ```sh
    cargo build --release
    ```

    O binário estará disponível em `target/release/typedb_mcp_server`.

Para mais detalhes sobre a instalação, consulte o [Guia do Usuário - Instalação](/docs/user_guide/03_installation.md).

## Configuração Essencial

A configuração do servidor é gerenciada através de um arquivo TOML (padrão: `typedb_mcp_server_config.toml`) e/ou variáveis de ambiente (prefixadas com `MCP_`).

**Exemplo mínimo de `typedb_mcp_server_config.toml`:**

```toml
[typedb]
address = "localhost:1729" # Endereço do seu TypeDB Server
username = "admin"         # Usuário do TypeDB (se aplicável)
# TYPEDB_PASSWORD deve ser fornecida via variável de ambiente

[server]
bind_address = "0.0.0.0:8787" # Endereço onde o MCP Server escutará
```

**Variável de Ambiente Obrigatória (se TypeDB usa autenticação):**

```sh
export TYPEDB_PASSWORD="sua_senha_typedb"
```

Para uma lista completa de todas as opções de configuração e seus detalhes, consulte a [Referência de Configuração](/docs/reference/configuration.md) e os arquivos de exemplo:

- [`typedb_mcp_server_config.toml`](./typedb_mcp_server_config.toml) (exemplo completo com defaults)
- [`config.example.toml`](./config.example.toml) (template para iniciar)
- [`config.dev.toml`](./config.dev.toml) (usado no `docker-compose.yml` padrão)

## Execução

Após a compilação e configuração:

```sh
# Com configuração padrão (e TYPEDB_PASSWORD no ambiente)
./target/release/typedb_mcp_server
```

Ou usando `cargo run`:

```sh
export TYPEDB_PASSWORD="sua_senha_typedb"
cargo run --release
```

Você pode especificar um arquivo de configuração customizado com a variável de ambiente `MCP_CONFIG_PATH`.

## Endpoints Principais

- **WebSocket MCP:**
  - Padrão: `ws://<host>:8787/mcp/ws` (ou `wss://` se TLS do servidor estiver ativado)
  - O path pode ser configurado via `server.mcp_websocket_path`.
- **Métricas Prometheus:**
  - Padrão: `http://<host>:9090/metrics`
  - O endereço de bind e o path podem ser configurados via `server.metrics_bind_address` e `server.metrics_path`.
- **Health Checks:**
  - Liveness: `/livez`
  - Readiness: `/readyz`

## Documentação Completa

Para uma documentação mais detalhada, incluindo guias para usuários e desenvolvedores, referência de API, tópicos avançados e mais, consulte a pasta [`/docs`](./docs/index.md).

- **[Guia do Usuário](/docs/user_guide/01_introduction.md):** Para instalar, configurar e usar o servidor.
- **[Guia do Desenvolvedor](/docs/developer_guide/01_introduction.md):** Para entender a arquitetura e contribuir com o projeto.
- **[Referência de Configuração](/docs/reference/configuration.md):** Detalhes de todas as opções de configuração.
- **[Referência da API](/docs/reference/api.md):** Detalhes das ferramentas MCP e endpoints HTTP.
- **[Arquitetura](/docs/architecture.md):** Visão geral da arquitetura do sistema.

## Contribuição

Contribuições são muito bem-vindas! Por favor, leia nosso [Guia de Contribuição](./CONTRIBUTING.md) para saber como você pode nos ajudar.
Também temos um [Código de Conduta](./CODE_OF_CONDUCT.md) que esperamos que todos os participantes da comunidade sigam.

## Licença

Este projeto é licenciado sob a [Licença MIT](./LICENSE).

## Agradecimentos

- À comunidade TypeDB e aos desenvolvedores do protocolo MCP.
- Aos criadores das excelentes bibliotecas Rust que tornam este projeto possível.

---

**Principais Alterações e Justificativas:**

- **Índice Atualizado:** Reflete melhor o conteúdo e a estrutura que um usuário/desenvolvedor esperaria.
- **Principais Funcionalidades:** Destaca os pontos fortes do servidor.
- **Status do Projeto:** Adicionado um placeholder para indicar o estado atual.
- **Começando:**
  - Pré-requisitos mais claros.
  - Instalação Rápida com Docker é mencionada primeiro por ser mais fácil para muitos usuários.
  - Link para o `README.docker.md`.
- **Configuração Essencial:**
  - Mostra um exemplo mínimo e direto.
  - Reforça a necessidade da variável `TYPEDB_PASSWORD`.
  - Links para os documentos de configuração mais detalhados.
- **Endpoints Principais:** Atualizado para refletir a configurabilidade dos paths.
- **Documentação Completa:** Seção dedicada com links diretos para os principais documentos que serão criados na pasta `/docs`. Isso é crucial para a navegação.
- **Contribuição e Licença:** Seções padrão.
- **Agradecimentos:** Uma seção opcional, mas simpática.
- **Clareza e Links:** Tentativa de usar uma linguagem mais direta e incluir links para onde o usuário pode encontrar mais informações (mesmo que os arquivos ainda não existam, os links já apontam para a estrutura planejada).

Lembre-se de substituir placeholders como `[Indicar o status atual do projeto: ...]` e a URL do rastreador de issues em `CONTRIBUTING.md` quando apropriado.
