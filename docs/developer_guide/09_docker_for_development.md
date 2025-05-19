
# Guia do Desenvolvedor: Usando Docker para Desenvolvimento e Testes

Docker e Docker Compose são ferramentas valiosas no ciclo de vida de desenvolvimento do Typedb-MCP-Server. Eles ajudam a criar ambientes consistentes, gerenciar dependências de serviço (como TypeDB) e simplificar a execução de testes de integração.

Este guia foca no uso do Docker sob a perspectiva do desenvolvedor. Para instruções de implantação ou uso básico pelo usuário final, consulte a seção [Instalação com Docker do Guia do Usuário](../user_guide/03_installation.md#2-usando-docker) e o arquivo [`README.docker.md`](../../README.docker.md).

## Pré-requisitos

* Docker instalado e em execução.
* Docker Compose instalado (geralmente incluído no Docker Desktop).

## Estrutura dos Arquivos Docker

O projeto contém os seguintes arquivos chave relacionados ao Docker:

* **[`Dockerfile`](../../Dockerfile):**
  * Define como construir a imagem Docker para o Typedb-MCP-Server.
  * Utiliza um build multi-stage:
        1. **Estágio Builder:** Compila o aplicativo Rust em um ambiente Rust específico, resultando em um binário estático otimizado.
        2. **Estágio Final (Runtime):** Copia o binário compilado para uma imagem base leve (atualmente `ubuntu:24.04`) e configura o ambiente de execução, incluindo um usuário não-root e a exposição das portas padrão.
  * Inclui um `HEALTHCHECK` para monitorar a saúde do contêiner.
  * Fornece instruções para build multi-plataforma (ex: para `linux/amd64` e `linux/arm64`).

* **[`docker-compose.yml`](../../docker-compose.yml):**
  * **Propósito:** Orquestrar um ambiente de desenvolvimento local.
  * **Serviços:**
    * `typedb-mcp-server`: Constrói e executa o Typedb-MCP-Server a partir do `Dockerfile` local.
    * `typedb-server-dev`: Executa uma instância do TypeDB (atualmente `typedb/typedb:3.2.0`) para o servidor MCP se conectar. A autenticação é desabilitada por padrão neste serviço (`--server.authentication.enable=false`).
  * **Volumes:**
    * Mapeia `config.dev.toml` para dentro do contêiner do servidor MCP.
    * Mapeia `certs/generated` (se você gerar certificados de desenvolvimento) para dentro do contêiner.
    * Cria um volume nomeado (`typedb-dev-data`) para persistir os dados do `typedb-server-dev` entre reinicializações.
  * **Rede:** Cria uma rede customizada (`typedb_mcp_network`) para comunicação entre os serviços.
  * **Variáveis de Ambiente:** Permite a passagem de variáveis de ambiente para configurar os serviços, com defaults que podem ser sobrescritos (ex: via arquivo `.env`).

* **[`docker-compose.test.yml`](../../docker-compose.test.yml):**
  * **Propósito:** Orquestrar um ambiente específico para a execução de testes de integração.
  * **Serviços:**
    * `typedb-mcp-server-it`: Similar ao do `docker-compose.yml`, mas usa `config.test.toml`.
    * `typedb-server-it`: Uma instância do TypeDB para os testes.
    * (Pode incluir um `mock-auth-server-it` se os testes de OAuth2 estiverem configurados para usá-lo via compose).
  * **Rede:** Usa uma rede separada (`typedb_mcp_test_network`).
  * Usado pelos helpers de teste em `tests/common/docker_helpers.rs`.

* **[`.dockerignore`](../../.dockerignore):**
  * Especifica arquivos e diretórios que devem ser ignorados ao construir a imagem Docker (ex: `target/`, `.git/`), otimizando o contexto de build.

* **[`README.docker.md`](../../README.docker.md):**
  * Fornece instruções adicionais sobre build multi-plataforma e exemplos de como configurar OAuth2 (real e mock) em um ambiente Docker Compose.

## Construindo a Imagem Docker Localmente

Para construir a imagem Docker do servidor a partir do código-fonte local:

```bash
# No diretório raiz do projeto
docker build -t typedb-mcp-server:dev .
```

* `-t typedb-mcp-server:dev`: Define o nome e a tag da imagem (ex: `dev` para uma build de desenvolvimento).
* `.`: Especifica o diretório atual como o contexto de build (onde o `Dockerfile` está).

### Build Multi-Plataforma (com Docker Buildx)

Se você precisa construir imagens para múltiplas arquiteturas (ex: `linux/amd64` e `linux/arm64`), você pode usar Docker Buildx. O `Dockerfile` e o `README.docker.md` contêm instruções sobre isso.

O script [`scripts/buildx-multiplatform.sh`](../../scripts/buildx-multiplatform.sh) automatiza este processo:

```bash
./scripts/buildx-multiplatform.sh
```

(Você precisará editar o script para usar seu nome de usuário/organização do Docker Hub se for fazer push).

## Usando Docker Compose para Desenvolvimento

O `docker-compose.yml` é a forma recomendada de executar o servidor e suas dependências (TypeDB) durante o desenvolvimento.

1. **Configuração:**
    * Modifique [`config.dev.toml`](../../config.dev.toml) conforme necessário para sua configuração de desenvolvimento.
    * Se o TypeDB (serviço `typedb-server-dev`) requer uma senha, crie um arquivo `.env` na raiz do projeto com:

        ```env
        TYPEDB_PASSWORD=sua_senha_para_typedb_dev
        ```

        Ou exporte a variável de ambiente.

2. **Iniciar Ambiente:**

    ```bash
    docker-compose up
    ```

    * Adicione `-d` para executar em segundo plano.
    * Adicione `--build` para forçar a reconstrução da imagem do `typedb-mcp-server` se você fez alterações no código-fonte.

3. **Acessar Serviços:**
    * Typedb-MCP-Server: `ws://localhost:8787/mcp/ws` (ou conforme portas mapeadas no `docker-compose.yml` e configuração).
    * Métricas: `http://localhost:9090/metrics`.
    * TypeDB (gRPC): `localhost:1729` (porta `TYPEDB_DEV_GRPC_PORT`).
    * TypeDB (HTTP Console, se aplicável pela imagem): `http://localhost:10080` (porta `TYPEDB_DEV_HTTP_PORT`).

4. **Ver Logs:**

    ```bash
    docker-compose logs -f typedb-mcp-server
    docker-compose logs -f typedb-server-dev
    ```

5. **Parar Ambiente:**

    ```bash
    docker-compose down
    ```

    Para remover o volume de dados do TypeDB (útil para um reset completo):

    ```bash
    docker-compose down -v
    ```

## Desenvolvimento Iterativo com Docker

Ao fazer alterações no código-fonte do Typedb-MCP-Server, você precisará reconstruir a imagem Docker para que essas alterações sejam refletidas no contêiner.

**Fluxo Típico:**

1. Faça alterações no código Rust em `src/`.
2. Reconstrua e reinicie os serviços com Docker Compose:

    ```bash
    docker-compose up --build -d
    ```

    O `--build` garante que a imagem `typedb-mcp-server` seja reconstruída.

**Otimização de Build com Cache de Camadas Docker:**
O `Dockerfile` é estruturado para aproveitar o cache de camadas do Docker. Por exemplo, as dependências do `Cargo.toml` são copiadas e construídas antes do código `src/`. Isso significa que, se apenas o código em `src/` mudar, o Docker pode reutilizar a camada de dependências já compiladas, acelerando o build.

## Testes de Integração com Docker

Os testes de integração (em `tests/integration/`) utilizam o `docker-compose.test.yml` e os helpers em `tests/common/docker_helpers.rs` para:

1. Iniciar um ambiente Docker Compose limpo para cada suíte de teste (ou grupo de testes, dependendo da granularidade).
2. Executar o Typedb-MCP-Server (a partir do código atual), um TypeDB de teste, e opcionalmente um mock de servidor OAuth2.
3. Conectar um `TestMcpClient` ao servidor dentro do Docker.
4. Realizar as asserções.
5. Derrubar o ambiente Docker Compose ao final do teste (gerenciado pelo `Drop` trait do `DockerComposeEnv`).

Isso garante que os testes de integração sejam executados em um ambiente isolado e reproduzível.

## Dicas para Desenvolvimento com Docker

* **Mapeamento de Volumes para Código (Hot Reloading - Avançado):** Para um ciclo de desenvolvimento Rust ainda mais rápido *dentro* do Docker (sem reconstruir a imagem a cada mudança), você poderia mapear seu diretório `src/` local para dentro do contêiner no `docker-compose.yml` e usar ferramentas como `cargo-watch` dentro do contêiner para recompilar e reiniciar o servidor automaticamente ao detectar alterações. Isso requer uma configuração mais complexa do Dockerfile e do ponto de entrada do contêiner.
* **Dev Containers:** Para um ambiente de desenvolvimento totalmente containerizado, incluindo seu editor e terminal, considere usar a funcionalidade de [Dev Containers do VS Code](https://code.visualstudio.com/docs/remote/containers) ou [GitHub Codespaces](https://github.com/features/codespaces). O projeto já inclui uma configuração básica em `.devcontainer/devcontainer.json`.
* **Análise de Logs:** Use `docker-compose logs -f <nome_do_servico>` extensivamente para depurar problemas.
* **Acessando Shells em Contêineres:**

    ```bash
    docker-compose exec typedb-mcp-server /bin/bash
    ```

    Isso permite inspecionar o ambiente dentro do contêiner.

O uso eficaz do Docker e Docker Compose pode acelerar significativamente o desenvolvimento, os testes e a implantação do Typedb-MCP-Server.
