
# Guia do Usuário: Instalação do Typedb-MCP-Server

Esta seção descreve como instalar o Typedb-MCP-Server. Você pode optar por compilar a partir do código-fonte ou usar imagens Docker pré-construídas (quando disponíveis) ou construir sua própria imagem Docker.

Certifique-se de ter atendido a todos os [Pré-requisitos](./02_prerequisites.md) antes de continuar.

## Opções de Instalação

Existem duas maneiras principais de instalar e executar o Typedb-MCP-Server:

1. **Compilando a partir do Código-Fonte:** Ideal para desenvolvimento, contribuições ou quando você precisa da versão mais recente diretamente do repositório.
2. **Usando Docker:** Recomendado para implantação simplificada, ambientes de teste consistentes e integração com `docker-compose`.

---

## 1. Compilando a partir do Código-Fonte

Siga estes passos para compilar o servidor a partir do código-fonte:

### Passo 1: Clone o Repositório

Se ainda não o fez, clone o repositório do Typedb-MCP-Server para sua máquina local:

```bash
git clone https://github.com/guilhermeleste/Typedb-MCP-Server.git
cd Typedb-MCP-Server
```

### Passo 2: Verifique sua Toolchain Rust

Certifique-se de que está usando a versão do Rust especificada no arquivo [`rust-toolchain.toml`](../../rust-toolchain.toml). Se você usa `rustup`, ele geralmente selecionará a toolchain correta automaticamente ao entrar no diretório do projeto. Você pode verificar com:

```bash
rustup show
```

Se necessário, instale a toolchain com `rustup toolchain install $(cat rust-toolchain.toml | grep channel | cut -d '"' -f 2)`.

### Passo 3: Compile o Projeto

Use o Cargo, o gerenciador de pacotes e sistema de build do Rust, para compilar o servidor. Para uma build otimizada para produção/uso, use o perfil `release`:

```bash
cargo build --release
```

* **O que acontece:** O Cargo fará o download de todas as dependências (crates) e compilará o código-fonte.
* **Saída:** O binário executável será gerado em `target/release/typedb_mcp_server`.
* **Tempo de Compilação:** A primeira compilação pode levar alguns minutos, pois todas as dependências precisam ser baixadas e compiladas. Compilações subsequentes serão mais rápidas.

### Passo 4: (Opcional) Adicione ao seu PATH

Para facilitar a execução, você pode copiar o binário para um diretório que esteja no seu `PATH` do sistema, ou adicionar `target/release/` ao seu `PATH`.

Exemplo (Linux/macOS):

```bash
sudo cp target/release/typedb_mcp_server /usr/local/bin/
```

Após a compilação, você estará pronto para [configurar](./04_configuration.md) e [executar](./05_running_the_server.md) o servidor.

---

## 2. Usando Docker

Executar o Typedb-MCP-Server com Docker simplifica o gerenciamento de dependências e a implantação.

### Opção A: Usando Docker Compose (Recomendado para Desenvolvimento e Testes)

O projeto inclui arquivos `docker-compose.yml` para facilitar a execução do servidor junto com uma instância do TypeDB.

1. **Clone o Repositório (se ainda não o fez):**

    ```bash
    git clone https://github.com/guilhermeleste/Typedb-MCP-Server.git
    cd Typedb-MCP-Server
    ```

2. **Configuração:**
    * O arquivo [`docker-compose.yml`](../../docker-compose.yml) é configurado para usar o [`config.dev.toml`](../../config.dev.toml) por padrão, que aponta para um serviço TypeDB chamado `typedb-server-dev` (também definido no compose).
    * **Senha do TypeDB:** Se o seu TypeDB (serviço `typedb-server-dev` no compose) estiver configurado para exigir uma senha (o que não é o padrão no `docker-compose.yml` fornecido, pois `TYPEDB_SERVER_OPTS=--server.authentication.enable=false`), você precisará fornecer a variável de ambiente `TYPEDB_PASSWORD` ao executar o `docker-compose up`. Isso pode ser feito através de um arquivo `.env` ou diretamente na linha de comando.
        Exemplo de arquivo `.env` na raiz do projeto:

        ```env
        TYPEDB_PASSWORD=sua_senha_typedb_para_o_compose
        ```

    * Para outras configurações, você pode modificar o arquivo `config.dev.toml` ou sobrescrever variáveis de ambiente no `docker-compose.yml`. Consulte a [Referência de Configuração](../reference/configuration.md).

3. **Inicie os Serviços:**

    ```bash
    docker-compose up -d --build
    ```

    * `--build`: Reconstrói a imagem do `typedb-mcp-server` se houver alterações no `Dockerfile` ou no código-fonte.
    * `-d`: Executa os contêineres em segundo plano (detached mode).

4. **Verifique os Logs (Opcional):**

    ```bash
    docker-compose logs -f typedb-mcp-server
    docker-compose logs -f typedb-server-dev
    ```

5. **Parando os Serviços:**

    ```bash
    docker-compose down
    ```

    Para remover volumes anônimos (onde os dados do TypeDB são armazenados por padrão no compose), use:

    ```bash
    docker-compose down -v
    ```

Consulte o arquivo [`README.docker.md`](../../README.docker.md) para mais detalhes sobre o uso do Docker, incluindo build multi-plataforma e configuração de OAuth2 com mocks.

### Opção B: Construindo e Executando a Imagem Docker Manualmente

Você também pode construir a imagem Docker diretamente e executá-la.

1. **Construa a Imagem:**
    No diretório raiz do projeto (onde o `Dockerfile` está localizado):

    ```bash
    docker build -t typedb-mcp-server:latest .
    ```

2. **Execute a Imagem:**
    Você precisará configurar as variáveis de ambiente necessárias e mapear as portas.

    ```bash
    # Exemplo mínimo, assumindo que o TypeDB está acessível em 'host.docker.internal:1729'
    # e não requer senha.
    docker run -d \
      -p 8787:8787 \
      -p 9090:9090 \
      -e MCP_TYPEDB__ADDRESS="host.docker.internal:1729" \
      --name mcp-server-manual \
      typedb-mcp-server:latest
    ```

    **Nota:**
    * `host.docker.internal` é um nome DNS especial que resolve para o IP interno do host a partir de dentro de um contêiner Docker Desktop (Windows, macOS). Em Linux, você pode precisar usar o IP da interface `docker0` ou configurar uma rede customizada.
    * Você precisará adaptar as variáveis de ambiente (`-e`) conforme sua configuração. Veja a [Referência de Configuração](../reference/configuration.md).
    * Para TLS, você precisará montar volumes para os certificados.

### Imagens Pré-Construídas

* [Se houver imagens Docker pré-construídas publicadas (ex: no Docker Hub ou GitHub Container Registry), forneça instruções sobre como usá-las aqui.]
* Atualmente, você precisará construir a imagem localmente a partir do `Dockerfile` fornecido.

---

## Próximos Passos

Após instalar o Typedb-MCP-Server, o próximo passo é [Configurar o Servidor](./04_configuration.md) de acordo com suas necessidades.
