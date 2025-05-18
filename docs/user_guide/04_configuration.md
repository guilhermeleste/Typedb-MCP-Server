
# Guia do Usuário: Configurando o Typedb-MCP-Server

A configuração adequada é essencial para que o Typedb-MCP-Server funcione conforme o esperado em seu ambiente. Este guia oferece uma visão geral dos mecanismos de configuração e das principais áreas que você precisará configurar.

Para uma lista exaustiva de todas as opções, seus valores padrão e explicações detalhadas, consulte a **[Referência Completa de Configuração](../reference/configuration.md)**.

## Visão Geral dos Mecanismos de Configuração

O Typedb-MCP-Server oferece flexibilidade na forma como é configurado, seguindo esta ordem de precedência (onde as configurações posteriores sobrescrevem as anteriores):

1. **Valores Padrão Internos:** O servidor possui valores padrão sensatos para a maioria das opções, permitindo que ele seja executado com o mínimo de configuração inicial.
2. **Arquivo de Configuração TOML:** Você pode fornecer um arquivo de configuração no formato TOML para especificar suas configurações.
3. **Variáveis de Ambiente:** Qualquer configuração pode ser sobrescrita por variáveis de ambiente, o que é útil para ambientes de contêiner ou para configurar dados sensíveis.

## 1. Arquivo de Configuração TOML

Este é o método principal para definir a maioria das configurações.

* **Nome Padrão:** Por padrão, o servidor procura um arquivo chamado `typedb_mcp_server_config.toml` no diretório onde é executado.
* **Caminho Customizado:** Você pode especificar um local diferente para seu arquivo de configuração usando a variável de ambiente `MCP_CONFIG_PATH`.

    ```bash
    export MCP_CONFIG_PATH="/etc/typedb-mcp-server/my_config.toml"
    # Então execute o servidor
    ./typedb_mcp_server
    ```

* **Estrutura:** O arquivo é organizado em seções (ex: `[typedb]`, `[server]`, `[oauth]`) que agrupam configurações relacionadas.

**Exemplo Básico (`typedb_mcp_server_config.toml`):**

```toml
# Configurações para a conexão com o TypeDB
[typedb]
address = "localhost:1729"  # Endereço do seu servidor TypeDB
username = "admin"            # Usuário para conectar ao TypeDB

# Configurações do próprio Typedb-MCP-Server
[server]
bind_address = "0.0.0.0:8787" # Em qual endereço e porta o MCP Server deve escutar

# Configurações de autenticação OAuth2 (opcional)
[oauth]
enabled = false # OAuth2 desabilitado por padrão
# Se habilitado, você precisará configurar 'jwks_uri', 'issuer', 'audience'.
# jwks_uri = "https://seu-auth-server.com/.well-known/jwks.json"
# issuer = ["https://seu-auth-server.com"]
# audience = ["api-do-meu-mcp-server"]
```

* Consulte o arquivo [`config.example.toml`](../../config.example.toml) para um template inicial.
* Consulte o arquivo [`typedb_mcp_server_config.toml`](../../typedb_mcp_server_config.toml) para um exemplo completo com todas as opções e valores padrão comentados.

## 2. Variáveis de Ambiente

As variáveis de ambiente são ideais para:

* Sobrescrever valores do arquivo TOML em ambientes específicos (desenvolvimento, teste, produção).
* Fornecer dados sensíveis, como senhas.

* **Prefixo:** Todas as variáveis de ambiente devem começar com `MCP_`.
* **Separador de Aninhamento:** Para seções aninhadas no TOML (como `typedb.address`), use um duplo underscore `__`.
  * Exemplo: `typedb.address` se torna `MCP_TYPEDB__ADDRESS`.
  * Exemplo: `oauth.jwks_uri` se torna `MCP_OAUTH__JWKS_URI`.
* **Booleanos:** Use `"true"` ou `"false"`.
* **Listas (Arrays de Strings):** Use uma string com valores separados por vírgula, sem espaços em torno das vírgulas.
  * Exemplo para `oauth.audience = ["api1", "api2"]`: `export MCP_OAUTH__AUDIENCE="api1,api2"`

### Variável de Ambiente Essencial: Senha do TypeDB

Se o seu servidor TypeDB estiver configurado com autenticação (o que é altamente recomendado para produção), a senha para o usuário do TypeDB **DEVE** ser fornecida através da variável de ambiente `TYPEDB_PASSWORD`:

```bash
export TYPEDB_PASSWORD="sua_senha_super_secreta_do_typedb"
```

**Nunca coloque a senha do TypeDB diretamente no arquivo de configuração TOML.**

## Principais Áreas de Configuração

Embora a [Referência Completa de Configuração](../reference/configuration.md) detalhe todas as opções, estas são as áreas mais comuns que você precisará ajustar:

### a. Conexão com TypeDB (`[typedb]`)

* **`address`**: O endereço do seu servidor TypeDB (obrigatório se não for `localhost:1729`).
* **`username`**: O nome de usuário para o TypeDB.
* **`TYPEDB_PASSWORD` (Variável de Ambiente)**: A senha para o usuário do TypeDB.
* **`tls_enabled`** e **`tls_ca_path`**: Se o seu TypeDB Server usa TLS, você precisará habilitar o TLS aqui e, possivelmente, fornecer o caminho para o certificado da CA raiz.

### b. Configurações do Servidor MCP (`[server]`)

* **`bind_address`**: O endereço IP e a porta onde o Typedb-MCP-Server escutará por conexões WebSocket MCP e requisições HTTP para health checks.
* **`tls_enabled`**, **`tls_cert_path`**, **`tls_key_path`**: Para habilitar HTTPS/WSS no próprio Typedb-MCP-Server. Essencial para produção.
* **`metrics_bind_address`**: O endereço IP e a porta para o endpoint de métricas Prometheus.

### c. Autenticação OAuth2 (`[oauth]`)

* **`enabled`**: Define se a autenticação OAuth2 para clientes MCP está ativa.
* Se `enabled = true`, você **precisará** configurar:
  * **`jwks_uri`**: O URI do endpoint JWKS (JSON Web Key Set) do seu provedor de identidade OAuth2.
  * **`issuer`** (recomendado): O(s) emissor(es) esperado(s) do token JWT.
  * **`audience`** (recomendado): O(s) público(s) esperado(s) do token JWT (geralmente um identificador para este servidor MCP).

### d. Logging (`[logging]`)

* **`rust_log`**: Controla o nível de detalhe dos logs. Útil para debugging. O formato padrão é `info`, com logs mais detalhados para os módulos do próprio servidor.

### e. Outras Configurações

* **`[cors]`**: Para permitir que clientes de diferentes origens (domínios) acessem o servidor.
* **`[rate_limit]`**: Para proteger o servidor contra um número excessivo de requisições.
* **`[tracing]`**: Para habilitar e configurar o tracing distribuído com OpenTelemetry.

## Verificando sua Configuração

Após configurar o servidor, ao iniciá-lo, observe os logs. O servidor registrará as configurações que está usando, incluindo de onde elas foram carregadas (defaults, arquivo TOML, variáveis de ambiente). Isso pode ajudar a diagnosticar problemas de configuração.

Por exemplo, você verá mensagens como:

```log
INFO typedb_mcp_server_lib::config: Carregando configurações. Arquivo: 'typedb_mcp_server_config.toml', Prefixo Env: 'MCP', Separador Env: '__'
DEBUG typedb_mcp_server: Configurações carregadas. config=Settings { typedb: TypeDB { ... }, server: Server { ... }, ... }
```

## Próximos Passos

Com o servidor configurado, você está pronto para [Executar o Servidor](./05_running_the_server.md).
