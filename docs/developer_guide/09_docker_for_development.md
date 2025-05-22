
# Guia do Desenvolvedor: Usando Docker para Desenvolvimento e Testes

Docker e Docker Compose são ferramentas centrais no ciclo de vida de desenvolvimento e teste do Typedb-MCP-Server. Eles garantem ambientes consistentes, facilitam o gerenciamento de dependências de serviço (como TypeDB e mocks OAuth2) e são a base para a execução da nossa suíte de testes de integração.

Este guia foca no uso do Docker sob a perspectiva do desenvolvedor que deseja compilar, executar e testar o servidor. Para instruções de implantação ou uso básico pelo usuário final, consulte a seção [Instalação com Docker do Guia do Usuário](../user_guide/03_installation.md#2-usando-docker) e o arquivo [`README.docker.md`](../../README.docker.md).

## Pré-requisitos

* Docker instalado e o daemon Docker em execução.
* Docker Compose (CLI V2, `docker compose`) instalado. Geralmente incluído no Docker Desktop.

## Estrutura dos Arquivos Docker do Projeto

O projeto contém os seguintes arquivos chave relacionados ao Docker:

* **[`Dockerfile`](../../Dockerfile):**
  * Define como construir a imagem Docker para o Typedb-MCP-Server.
  * Utiliza um build multi-stage:
        1. **Estágio Builder (`builder`):** Compila a aplicação Rust em um ambiente Rust específico (definido pela versão em `rust-toolchain.toml`), resultando em um binário estático otimizado para release. Otimiza o cache de dependências do Cargo.
        2. **Estágio Final (`final`):** Copia o binário compilado para uma imagem base leve (atualmente `ubuntu:24.04`) e configura o ambiente de execução, incluindo um usuário não-root (`app_name`) e a exposição das portas padrão (8787 para MCP HTTP/WS, 8443 para MCP HTTPS/WSS, 9090 para métricas).
  * Inclui um `HEALTHCHECK` básico no `Dockerfile` que verifica o endpoint `/livez` do servidor MCP.
  * Fornece comentários e diretrizes para build multi-plataforma com `docker buildx`.

* **[`docker-compose.yml`](../../docker-compose.yml):**
  * **Propósito:** Orquestrar um ambiente de **desenvolvimento local interativo**.
  * **Serviços:**
    * `typedb-mcp-server`: Constrói e executa o Typedb-MCP-Server a partir do `Dockerfile` local.
      * Mapeia portas do host para o contêiner (controladas por variáveis de ambiente como `MCP_SERVER_PORT_HTTP`, `MCP_SERVER_PORT_HTTPS`, `MCP_METRICS_PORT` com defaults).
      * Monta o arquivo de configuração de desenvolvimento `config.dev.toml` para `/app/typedb_mcp_server_config.toml` no contêiner.
      * Monta o diretório `certs/generated` (se você usar `scripts/generate-dev-certs.sh` para certificados de desenvolvimento) para `/app/certs` no contêiner.
      * Permite a passagem de variáveis de ambiente (ex: `RUST_LOG`, `TYPEDB_PASSWORD`, configurações de OAuth2 e TLS).
    * `typedb-server-dev`: Executa uma instância do TypeDB (atualmente `typedb/typedb:3.2.0`) para o servidor MCP se conectar. A autenticação é geralmente desabilitada neste serviço para facilitar o desenvolvimento (`--server.authentication.enable=false`), mas pode ser habilitada via `TYPEDB_SERVER_OPTS`.
  * **Volumes:** Cria um volume nomeado (`typedb-dev-data`) para persistir os dados do `typedb-server-dev`.
  * **Rede:** Cria uma rede customizada (`typedb_mcp_network`) para comunicação entre os serviços.

* **[`docker-compose.test.yml`](../../docker-compose.test.yml):**
  * **Propósito:** Orquestrar um ambiente **dedicado e isolado para a execução de testes de integração automatizados**. Este arquivo é gerenciado pelos helpers de teste em `tests/common/docker_helpers.rs` (`DockerComposeEnv`).
  * **Serviços:**
    * `typedb-mcp-server-it`: Constrói e executa o servidor MCP. Sua configuração TOML é dinamicamente selecionada pelos testes (de `tests/test_configs/`) e passada via variável de ambiente `MCP_CONFIG_PATH`.
    * `typedb-server-it`: Instância TypeDB padrão para testes, sem TLS, mas com autenticação habilitada (senha controlada por `TYPEDB_PASSWORD_TEST`).
    * `typedb-server-tls-it`: Nova instância TypeDB configurada para usar TLS, para testar a conexão TLS entre o MCP Server e o TypeDB.
    * `mock-oauth2-server`: Um servidor Nginx que serve um arquivo `mock_jwks.json` para simular um provedor OAuth2.
  * **Portas Mapeadas:** Mapeia as portas internas dos contêineres para portas *fixas* no host (ex: `8788:8787` para MCP HTTP). Isso requer que os testes de integração sejam executados serialmente (`#[serial_test::serial]`).
  * **Volumes:**
    * Monta `tests/test_configs` e `tests/test_certs` no contêiner `typedb-mcp-server-it`.
    * Monta os certificados necessários para o `typedb-server-tls-it`.
    * Usa volumes nomeados prefixados com o nome do projeto Docker Compose (`${COMPOSE_PROJECT_NAME}_...`) para persistência de dados do TypeDB, garantindo isolamento entre execuções de teste.
  * **Rede:** Usa uma rede customizada e nomeada com base no projeto (`${COMPOSE_PROJECT_NAME}_test_net`) para isolamento.

* **[`.dockerignore`](../../.dockerignore):**
  * Especifica arquivos e diretórios que devem ser ignorados ao construir a imagem Docker (ex: `target/`, `.git/`), otimizando o contexto de build e o tamanho da imagem.

* **[`README.docker.md`](../../README.docker.md):**
  * Fornece instruções adicionais sobre build multi-plataforma e exemplos de como configurar OAuth2 (real e mock) em um ambiente Docker Compose (mais focado no `docker-compose.yml` de desenvolvimento).

## Construindo a Imagem Docker Localmente (Para Desenvolvimento)

Se você precisar construir a imagem Docker do servidor manualmente (fora do fluxo do `docker compose build`):

```bash
# No diretório raiz do projeto
docker build -t typedb-mcp-server:dev .
```

* `-t typedb-mcp-server:dev`: Define o nome e a tag da imagem (ex: `dev` para uma build de desenvolvimento).
* `.`: Especifica o diretório atual como o contexto de build.

Para builds **multi-plataforma** (ex: para `linux/amd64` e `linux/arm64`), você pode usar Docker Buildx. Consulte o `Dockerfile` e o `README.docker.md` para instruções. O script [`scripts/buildx-multiplatform.sh`](../../scripts/buildx-multiplatform.sh) também é um exemplo.

## Usando `docker-compose.yml` para Desenvolvimento Interativo

O `docker-compose.yml` é a forma recomendada de executar o servidor e suas dependências (TypeDB) durante o desenvolvimento interativo.

1. **Configuração Inicial:**
    * Copie [`.env.example`](../../.env.example) para `.env` e ajuste as variáveis, especialmente `TYPEDB_PASSWORD` se o `typedb-server-dev` for configurado com autenticação.
    * Ajuste [`config.dev.toml`](../../config.dev.toml) conforme necessário.

2. **Iniciar Ambiente:**

    ```bash
    docker compose up --build
    ```

    * `--build`: Reconstrói a imagem do `typedb-mcp-server` se houver alterações no código-fonte ou `Dockerfile`.
    * Adicione `-d` para executar em segundo plano.

3. **Acessar Serviços (Exemplos com portas default do `docker-compose.yml`):**
    * Typedb-MCP-Server (HTTP/WS): `ws://localhost:8787/mcp/ws`
    * Typedb-MCP-Server (HTTPS/WSS, se TLS habilitado em `config.dev.toml` e certs montados): `wss://localhost:8443/mcp/ws`
    * Métricas: `http://localhost:9090/metrics`
    * TypeDB (gRPC): `localhost:1729`

4. **Ver Logs:**

    ```bash
    docker compose logs -f typedb-mcp-server
    docker compose logs -f typedb-server-dev
    ```

5. **Parar Ambiente:**

    ```bash
    docker compose down
    ```

    Para remover o volume de dados do TypeDB:

    ```bash
    docker compose down -v
    ```

## Desenvolvimento Iterativo com Docker (Builds e Rebuilds)

Ao fazer alterações no código-fonte Rust (`src/`):

1. Reconstrua a imagem e reinicie os serviços:

    ```bash
    docker compose up --build
    ```

    O `Dockerfile` é estruturado para usar o cache de camadas do Docker, então apenas as camadas afetadas pelas suas mudanças serão reconstruídas, tornando o processo geralmente rápido após o primeiro build.

## Testes de Integração e Docker (`docker-compose.test.yml`)

Conforme detalhado na [Estratégia de Testes](./08_testing_strategy.md), os testes de integração são executados contra um ambiente Docker orquestrado pelo `docker-compose.test.yml`.

* **Gerenciamento Automatizado:** O `TestEnvironment` (de `tests/common/test_env.rs`) usa o `DockerComposeEnv` (de `tests/common/docker_helpers.rs`) para iniciar (`up`) e parar (`down -v --remove-orphans`) este ambiente para cada cenário de teste (ou para cada execução, dependendo da configuração de `#[serial_test::serial]`).
* **Isolamento:** Cada `TestEnvironment` usa um nome de projeto Docker Compose único (`-p <nome_do_projeto>`) para garantir que contêineres, redes e volumes nomeados sejam isolados e não haja conflitos entre execuções de teste.
* **Configuração Parametrizada:** O `TestEnvironment` passa o nome do arquivo de configuração TOML apropriado (de `tests/test_configs/`) para o serviço `typedb-mcp-server-it` através da variável de ambiente `MCP_CONFIG_PATH`.
* **Execução Serial:** Devido ao mapeamento de portas de host fixas no `docker-compose.test.yml` (ex: `8788:8787`), os testes de integração são marcados com `#[serial_test::serial]` para evitar conflitos de porta no host.

## Dicas para Desenvolvimento e Depuração com Docker

* **Acessar Shells em Contêineres:**
  * Para o ambiente de desenvolvimento:

   ```bash
        docker compose exec typedb-mcp-server /bin/bash
        ```

  * Para um ambiente de teste (você precisará saber o nome do projeto dinâmico, que é logado pelos testes):

  ```bash
        docker exec -it <nome_do_projeto_do_teste>-mcp-server-1 /bin/bash
        ```

* **Análise de Logs Detalhada:** Para problemas nos testes, os logs coletados pelo `DockerComposeEnv::logs_all_services()` ou diretamente via `docker compose -p <nome_do_projeto_do_teste> logs --tail=all` são cruciais. A variável `RUST_LOG` no `docker-compose.test.yml` já está configurada para ser verbosa.
  
* **Limpeza:** Após execuções de teste, especialmente se interrompidas, pode ser necessário limpar redes, volumes e contêineres Docker órfãos manualmente se o `Drop` do `TestEnvironment` não for executado. Comandos úteis:
  * `docker ps -a` (listar todos os contêineres)
  * `docker network ls`
  * `docker volume ls`
  * `docker system prune -a --volumes` (CUIDADO: Remove tudo não utilizado!)

O uso eficaz do Docker e Docker Compose, tanto para desenvolvimento interativo quanto para os testes de integração automatizados, é fundamental para a qualidade e a eficiência do desenvolvimento do Typedb-MCP-Server.
