# Typedb-MCP-Server

Servidor Rust de alta performance, seguro e extensível, atuando como gateway MCP (Model Context Protocol) para o banco de dados TypeDB. Expõe endpoints WebSocket (MCP), HTTP REST para métricas Prometheus, integra autenticação OAuth2 opcional, tracing distribuído (OpenTelemetry) e métricas detalhadas.

Este projeto visa fornecer uma ponte robusta e eficiente entre clientes que utilizam o Model Context Protocol e um backend TypeDB, com foco em segurança, observabilidade e extensibilidade, permitindo que aplicações, incluindo Modelos de Linguagem de Grande Escala (LLMs), interajam de forma padronizada com o TypeDB.

---

## Índice

- [Typedb-MCP-Server](#typedb-mcp-server)
  - [Índice](#índice)
  - [Visão Geral](#visão-geral)
  - [Principais Funcionalidades](#principais-funcionalidades)
  - [Status do Projeto](#status-do-projeto)
  - [Começando](#começando)
    - [Pré-requisitos](#pré-requisitos)
    - [Instalação](#instalação)
      - [Usando Docker (Recomendado para Início Rápido)](#usando-docker-recomendado-para-início-rápido)
      - [A partir do Código-Fonte](#a-partir-do-código-fonte)
    - [Configuração Essencial](#configuração-essencial)
    - [Execução](#execução)
  - [Endpoints Principais](#endpoints-principais)
  - [Segurança](#segurança)
  - [Observabilidade](#observabilidade)
  - [Extensibilidade](#extensibilidade)
  - [Documentação Completa](#documentação-completa)
  - [Contribuição](#contribuição)
  - [Licença](#licença)
  - [Agradecimentos](#agradecimentos)

---

## Visão Geral

O Typedb-MCP-Server é um componente crucial para arquiteturas que necessitam de interação programática e segura com o TypeDB. Ele implementa o Model Context Protocol, permitindo que diversos tipos de clientes (como LLMs, ferramentas de desenvolvimento ou microsserviços) utilizem um conjunto padronizado de ferramentas para consultar dados, manipular esquemas e administrar o banco de dados.

Construído em Rust, o servidor foi desenvolvido com foco em performance (utilizando Tokio e Axum) e segurança (suporte a TLS e OAuth2).

## Principais Funcionalidades

- **Gateway MCP para TypeDB:** Expõe as funcionalidades do TypeDB através do Model Context Protocol.
- **Transporte WebSocket:** Comunicação principal via WebSockets (WSS para TLS).
- **Segurança Robusta:**
  - TLS para o servidor MCP (HTTPS/WSS) e para a conexão com o TypeDB.
  - Autenticação de cliente opcional via OAuth2/JWT, com validação de `issuer`, `audience` e escopos.
  - Controle de acesso granular por ferramenta MCP através de escopos OAuth2.
- **Observabilidade Abrangente:**
  - Métricas detalhadas no formato Prometheus (`/metrics`).
  - Tracing distribuído com OpenTelemetry (exportação OTLP).
  - Logging JSON estruturado e configurável.
  - Endpoints de Health Check (`/health`, `/readyz`).
- **Configurabilidade Flexível:** Via arquivo TOML e variáveis de ambiente.
- **Extensibilidade:** Arquitetura modular que facilita a adição de novas ferramentas MCP.
- **Suporte a Docker:** `Dockerfile` e exemplos `docker-compose` para desenvolvimento e implantação.

## Status do Projeto

- **Versão Atual:** `0.1.0` (conforme `Cargo.toml`)
- **Estado:** Em desenvolvimento ativo. Funcionalidades principais implementadas, com foco contínuo em estabilidade, segurança e melhorias.
- Consulte as [Issues do GitHub](https://github.com/guilhermeleste/Typedb-MCP-Server/issues) para funcionalidades planejadas e problemas conhecidos.

## Começando

### Pré-requisitos

- **Rust:** Versão `>= 1.87.0` (conforme `rust-toolchain.toml`).
- **TypeDB Server:** Instância acessível (v3.2.0 ou compatível).
- **Docker & Docker Compose:** Recomendado para facilidade de uso.
- Consulte o [Guia do Usuário - Pré-requisitos](/docs/user_guide/02_prerequisites.md) para uma lista detalhada.

### Instalação

#### Usando Docker (Recomendado para Início Rápido)

A forma mais simples de executar o servidor, especialmente para desenvolvimento e testes, é com Docker Compose.

1. Clone o repositório: `git clone https://github.com/guilhermeleste/Typedb-MCP-Server.git && cd Typedb-MCP-Server`
2. Se o seu TypeDB (serviço `typedb-server-dev` no `docker-compose.yml`) exigir senha, crie um arquivo `.env` na raiz com `TYPEDB_PASSWORD=sua_senha_typedb` ou exporte a variável.
3. Execute: `docker-compose up -d --build`

Para mais detalhes, incluindo build multi-plataforma, veja o [`README.docker.md`](./README.docker.md) e a seção de [Instalação com Docker](/docs/user_guide/03_installation.md#2-usando-docker).

#### A partir do Código-Fonte

1. Clone o repositório (se ainda não o fez).
2. Compile: `cargo build --release`
    O binário estará em `target/release/typedb_mcp_server`.

Consulte o [Guia de Instalação a partir do Código-Fonte](/docs/user_guide/03_installation.md#1-compilando-a-partir-do-código-fonte) para mais detalhes.

### Configuração Essencial

A configuração é feita primariamente via arquivo TOML (padrão: `typedb_mcp_server_config.toml`) e pode ser sobrescrita ou complementada por variáveis de ambiente.

**1. Arquivo de Configuração TOML:**

Crie ou utilize o arquivo `typedb_mcp_server_config.toml` (ou `config.dev.toml`, `config.test.toml` dependendo do ambiente).

**Exemplo Mínimo (`typedb_mcp_server_config.toml`):**

```toml
[typedb]
address = "localhost:1729"  # Endereço do seu TypeDB Server

[server]
bind_address = "0.0.0.0:8787" # Onde o MCP Server escutará
```

**2. Variáveis de Ambiente e Arquivos `.env`:**

Variáveis de ambiente têm precedência sobre as configurações do arquivo TOML. Para facilitar o gerenciamento, especialmente em desenvolvimento local, você pode usar arquivos `.env`.

- **`.env.example`**: Este arquivo serve como um template e documentação para as variáveis de ambiente suportadas. Copie-o para `.env`.
- **`.env`**: Crie este arquivo na raiz do projeto (copiando de `.env.example`) e preencha com seus valores locais. **Este arquivo não deve ser versionado se contiver segredos.**

**Variáveis de Ambiente Chave:**

- `TYPEDB_PASSWORD`: **Obrigatória** se o TypeDB usa autenticação.

    ```bash
    export TYPEDB_PASSWORD="sua_senha_typedb"
    # Ou defina em seu arquivo .env:
    # TYPEDB_PASSWORD=sua_senha_typedb
    ```

    **Importante:** Nunca coloque `TYPEDB_PASSWORD` diretamente no arquivo TOML.

- `MCP_CONFIG_PATH`: Permite especificar um caminho alternativo para o arquivo de configuração TOML.

    ```bash
    export MCP_CONFIG_PATH="config/custom_config.toml"
    # Ou defina em seu arquivo .env:
    # MCP_CONFIG_PATH=config/custom_config.toml
    ```

- `RUST_LOG`: Controla o nível de log.

    ```bash
    export RUST_LOG="info,typedb_mcp_server=debug"
    # Ou defina em seu arquivo .env:
    # RUST_LOG=info,typedb_mcp_server=debug
    ```

**Sobrescrevendo Configurações TOML com Variáveis de Ambiente:**

Qualquer configuração do arquivo TOML pode ser sobrescrita usando variáveis de ambiente. O formato é `MCP_<NOME_DA_SECAO>__<NOME_DO_CAMPO>=<VALOR>`.

Exemplos:

- `MCP_SERVER__BIND_ADDRESS="127.0.0.1:9000"`
- `MCP_TYPEDB__ADDRESS="typedb.example.com:1729"`
- `MCP_AUTH__OAUTH_ENABLED=false`

Para todas as opções de configuração e variáveis de ambiente correspondentes, consulte a [Referência Completa de Configuração](/docs/reference/configuration.md) e o arquivo `.env.example`.

Veja também:

- [`typedb_mcp_server_config.toml`](./typedb_mcp_server_config.toml) (configuração padrão)
- [`config.example.toml`](./config.example.toml) (template para TOML)
- [`.env.example`](./.env.example) (template para variáveis de ambiente)

### Execução

Após a instalação e configuração:

- **Com Cargo:**

    ```bash
    # Exporte TYPEDB_PASSWORD se necessário
    cargo run --release
    ```

- **Binário Compilado:**

    ```bash
    # Exporte TYPEDB_PASSWORD se necessário
    ./target/release/typedb_mcp_server
    ```

- **Com Docker Compose:** (já mencionado na instalação) `docker-compose up`

Consulte o [Guia do Usuário - Executando o Servidor](/docs/user_guide/05_running_the_server.md) para mais detalhes.

## Endpoints Principais

- **WebSocket MCP:** `ws://<host>:<porta_servidor>/mcp/ws` (ou `wss://` com TLS). Path configurável via `server.mcp_websocket_path`.
- **Métricas Prometheus:** `http://<host>:<porta_metricas>/metrics`. Path e porta configuráveis.
- **Health Checks:** `/health` e `/readyz`.

Consulte a [Referência da API - Endpoints HTTP](/docs/reference/api.md#2-endpoints-http) para detalhes.

## Segurança

- **TLS:** Fortemente recomendado para todas as comunicações em produção (MCP e TypeDB).
- **OAuth2/JWT:** Autenticação de cliente opcional, com suporte a JWKS, validação de issuer/audience e escopos.
- **Gerenciamento de Credenciais:** `TYPEDB_PASSWORD` via variável de ambiente é crucial.
- **Limitação de Taxa e CORS:** Configuráveis para maior segurança.

Veja mais em [Guia do Usuário - Segurança Básica](/docs/user_guide/09_security_basics.md) e [Referência de Configuração](/docs/reference/configuration.md).

## Observabilidade

- **Métricas:** Formato Prometheus, acessível via HTTP. Veja a [Lista de Métricas](/docs/reference/metrics_list.md).
- **Logging:** Logs JSON estruturados e configuráveis via `RUST_LOG` ou arquivo de configuração.
- **Tracing Distribuído:** Suporte a OpenTelemetry (OTLP).
- **Health Checks:** `/health` para liveness e `/readyz` para readiness (incluindo dependências).

Detalhes em [Guia do Usuário - Observabilidade](/docs/user_guide/08_observability.md).

## Extensibilidade

Novas ferramentas MCP podem ser adicionadas de forma modular. Consulte o [Guia do Desenvolvedor - Adicionando Novas Ferramentas MCP](/docs/developer_guide/05_adding_new_mcp_tools.md).

## Documentação Completa

Para uma exploração aprofundada de todos os aspectos do Typedb-MCP-Server, visite nossa documentação completa:

➡️ **[Página Inicial da Documentação](/docs/index.md)**

Principais seções:

- **[Guia do Usuário](/docs/user_guide/01_introduction.md):** Para instalação, configuração e uso.
- **[Guia do Desenvolvedor](/docs/developer_guide/01_introduction.md):** Para entender a arquitetura, código e como contribuir.
- **[Referência de Configuração](/docs/reference/configuration.md):** Todas as opções de configuração.
- **[Referência da API](/docs/reference/api.md):** Detalhes das ferramentas MCP e endpoints HTTP.
- **[Perguntas Frequentes (FAQ)](/docs/FAQ.md)**

## Contribuição

Suas contribuições são muito bem-vindas! Por favor, leia nosso [Guia de Contribuição](./CONTRIBUTING.md) e nosso [Código de Conduta](./CODE_OF_CONDUCT.md).

## Licença

Este projeto é licenciado sob a [Licença MIT](./LICENSE).

## Agradecimentos

- A toda a equipe e comunidade por trás do TypeDB e do Model Context Protocol.
- Aos desenvolvedores das inúmeras bibliotecas Rust de alta qualidade que tornam este projeto possível.

---
> Gerado automaticamente a partir do código-fonte em 16/05/2025. Para detalhes de implementação, consulte os módulos e a documentação interna.
