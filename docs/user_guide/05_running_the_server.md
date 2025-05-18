
# Guia do Usuário: Executando o Typedb-MCP-Server

Após ter [instalado](./03_installation.md) e [configurado](./04_configuration.md) o Typedb-MCP-Server, você está pronto para iniciá-lo. Esta seção descreve as diferentes maneiras de executar o servidor.

## Pré-requisitos para Execução

Antes de iniciar o servidor, certifique-se de que:

1. **TypeDB Server está em execução:** O Typedb-MCP-Server precisa se conectar a uma instância do TypeDB. Garanta que seu TypeDB Server esteja ativo e acessível no endereço configurado (padrão: `localhost:1729`).
2. **Configuração Aplicada:** As configurações necessárias, especialmente o endereço do TypeDB e as credenciais (se aplicável), estão definidas, seja através do arquivo `typedb_mcp_server_config.toml` ou de variáveis de ambiente.
3. **Senha do TypeDB (Se Necessário):** Se o seu TypeDB requer autenticação, a variável de ambiente `TYPEDB_PASSWORD` **DEVE** estar definida no ambiente onde o Typedb-MCP-Server será executado.

    ```bash
    export TYPEDB_PASSWORD="sua_senha_typedb"
    ```

4. **Certificados TLS (Se Habilitado):** Se você habilitou TLS para o servidor MCP ou para a conexão com o TypeDB, os arquivos de certificado e chave devem estar nos caminhos especificados na configuração e serem legíveis pelo processo do servidor.

## Executando a partir do Código-Fonte (com Cargo)

Esta é a maneira comum de executar o servidor durante o desenvolvimento ou se você compilou a partir do código-fonte e não moveu o binário.

1. **Navegue até o diretório raiz do projeto:**

    ```bash
    cd caminho/para/Typedb-MCP-Server
    ```

2. **Defina a senha do TypeDB (se necessário):**

    ```bash
    export TYPEDB_PASSWORD="sua_senha_typedb"
    ```

3. **Execute com `cargo run`:**
    Para melhor performance, use o perfil de release:

    ```bash
    cargo run --release
    ```

    * O Cargo compilará o projeto (se ainda não estiver atualizado) e então executará o binário `target/release/typedb_mcp_server`.
    * Logs serão exibidos no terminal.

## Executando o Binário Compilado Diretamente

Se você já compilou o servidor (usando `cargo build --release`) e opcionalmente moveu o binário para um local no seu `PATH` (ou conhece o caminho para `target/release/typedb_mcp_server`):

1. **Defina a senha do TypeDB (se necessário):**

    ```bash
    export TYPEDB_PASSWORD="sua_senha_typedb"
    ```

2. **Execute o binário:**
    Se estiver no `PATH`:

    ```bash
    typedb_mcp_server
    ```

    Ou com o caminho completo:

    ```bash
    ./target/release/typedb_mcp_server
    ```

    (Ajuste o caminho conforme necessário se você moveu o binário).

## Executando com Docker

Consulte as seções relevantes em [Instalação com Docker](./03_installation.md#2-usando-docker) e o [`README.docker.md`](../../README.docker.md) para instruções detalhadas sobre como executar o servidor usando Docker e Docker Compose.

**Exemplo rápido com `docker-compose` (após clonar o repositório e definir `TYPEDB_PASSWORD` em um arquivo `.env` ou no ambiente):**

```bash
# No diretório raiz do projeto
docker-compose up --build
```

Isso utilizará o `docker-compose.yml` que, por padrão, usa `config.dev.toml` e inicia um contêiner TypeDB (`typedb-server-dev`) junto com o `typedb-mcp-server`.

## Observando a Saída do Servidor

Ao iniciar, o servidor exibirá logs no console (ou nos logs do Docker, se estiver usando contêineres). Procure por mensagens indicando:

* **Carregamento da Configuração:**

    ```log
    INFO typedb_mcp_server_lib::config: Carregando configurações. Arquivo: '...', Prefixo Env: 'MCP', ...
    INFO typedb_mcp_server_lib::config: Usando configurações: Settings { ... }
    ```

* **Conexão com TypeDB:**

    ```log
    INFO typedb_mcp_server_lib::db: Conectando ao TypeDB em localhost:1729 com o usuário 'admin' (TLS habilitado: false).
    INFO typedb_mcp_server_lib::db: Conexão com TypeDB em localhost:1729 estabelecida com sucesso.
    ```

* **Servidor Escutando:**

    ```log
    INFO typedb_mcp_server: Servidor MCP (HTTP/WS) escutando em 0.0.0.0:8787
    INFO typedb_mcp_server: Servidor de métricas Prometheus escutando em 0.0.0.0:9090 (path: /metrics)
    ```

    (As portas e protocolos podem variar dependendo da sua configuração de TLS).

Uma inicialização bem-sucedida exibirá mensagens semelhantes, indicando que o servidor está pronto para aceitar conexões.

## Parando o Servidor

* **Executado com `cargo run` ou binário direto:** Pressione `Ctrl+C` no terminal onde o servidor está sendo executado. O servidor tentará um desligamento gracioso (graceful shutdown).
* **Executado com `docker-compose up` (sem `-d`):** Pressione `Ctrl+C` no terminal.
* **Executado com `docker-compose up -d`:**

    ```bash
    docker-compose down
    ```

* **Executado com `docker run`:**
    1. Encontre o ID ou nome do contêiner: `docker ps`
    2. Pare o contêiner: `docker stop <ID_OU_NOME_DO_CONTAINER>`
    3. Remova o contêiner (opcional): `docker rm <ID_OU_NOME_DO_CONTAINER>`

O servidor é projetado para um desligamento gracioso, o que significa que ele tentará concluir as requisições em andamento e liberar recursos antes de parar completamente.

## Próximos Passos

Com o servidor em execução, você pode agora [Conectar Clientes MCP](./06_connecting_clients.md) a ele.
