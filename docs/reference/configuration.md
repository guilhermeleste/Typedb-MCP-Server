# Referência Completa de Configuração do Typedb-MCP-Server

Este documento fornece uma referência detalhada de todas as opções de configuração disponíveis para o Typedb-MCP-Server. A configuração pode ser gerenciada através de um arquivo TOML e/ou variáveis de ambiente.

## Mecanismos de Configuração

Existem três maneiras principais de configurar o servidor, com a seguinte ordem de precedência (onde configurações posteriores sobrescrevem as anteriores):

1. **Valores Padrão Codificados:** O servidor possui valores padrão para a maioria das configurações, garantindo que ele possa ser executado com configuração mínima.
2. **Arquivo de Configuração TOML:** Um arquivo no formato TOML pode ser usado para especificar as configurações. Por padrão, o servidor procura por `typedb_mcp_server_config.toml` no diretório de trabalho.
3. **Variáveis de Ambiente:** Todas as configurações podem ser sobrescritas por variáveis de ambiente.

## Arquivo de Configuração Principal

* **Nome Padrão:** `typedb_mcp_server_config.toml`
* **Caminho Customizado:** Você pode especificar um caminho diferente para o arquivo de configuração usando a variável de ambiente `MCP_CONFIG_PATH`.

    ```bash
    export MCP_CONFIG_PATH="/caminho/para/meu/config.custom.toml"
    ```

* **Exemplos:**
  * [`typedb_mcp_server_config.toml`](../../typedb_mcp_server_config.toml): Um arquivo de exemplo abrangente mostrando todas as opções possíveis e seus valores padrão (conforme definido no código).
  * [`config.example.toml`](../../config.example.toml): Um template mais conciso para começar.

## Variáveis de Ambiente

Todas as opções de configuração definidas no arquivo TOML podem ser sobrescritas por variáveis de ambiente.

* **Prefixo:** Todas as variáveis de ambiente devem começar com `MCP_`.
* **Separador de Aninhamento:** Para seções aninhadas no TOML (como `[typedb]`), use um duplo underscore `__` para separar os níveis. Por exemplo, `typedb.address` se torna `MCP_TYPEDB__ADDRESS`.
* **Arrays/Listas:** Para campos que são listas de strings (ex: `oauth.audience`), as variáveis de ambiente podem usar uma string separada por vírgulas (sem espaços em torno das vírgulas): `MCP_OAUTH__AUDIENCE="api1,api2"`.

### Variável de Ambiente Obrigatória

* **`TYPEDB_PASSWORD`**: Se o seu servidor TypeDB requer autenticação, a senha **DEVE** ser fornecida através desta variável de ambiente. Não armazene senhas em texto plano no arquivo de configuração.

    ```bash
    export TYPEDB_PASSWORD="sua_senha_super_secreta"
    ```

---

## Seções de Configuração

A seguir, detalhamos cada seção e suas respectivas chaves de configuração.

### Seção `[typedb]`

Configurações para a conexão com o servidor TypeDB.

| Chave TOML        | Variável de Ambiente        | Tipo          | Descrição                                                                                                                                  | Padrão (Código)             | Obrigatório? | Exemplo TOML                       |
| :---------------- | :-------------------------- | :------------ | :----------------------------------------------------------------------------------------------------------------------------------------- | :-------------------------- | :----------- | :--------------------------------- |
| `address`         | `MCP_TYPEDB__ADDRESS`       | String        | Endereço (host:porta) do servidor TypeDB.                                                                                                | `"localhost:1729"`          | Sim          | `address = "typedb.meudominio:1729"` |
| `username`        | `MCP_TYPEDB__USERNAME`      | String        | Nome de usuário para autenticação com TypeDB. Se omitido ou string vazia, o padrão do código será usado.                                 | `"admin"`                   | Não          | `username = "meu_usuario_typedb"`    |
| `tls_enabled`     | `MCP_TYPEDB__TLS_ENABLED`   | Boolean       | Habilita (true) ou desabilita (false) TLS para a conexão com o servidor TypeDB.                                                            | `false`                     | Não          | `tls_enabled = true`               |
| `tls_ca_path`     | `MCP_TYPEDB__TLS_CA_PATH`   | String (Path) | Caminho para o arquivo PEM do certificado da Autoridade Certificadora (CA) raiz usado para verificar o certificado do servidor TypeDB. | `null` (Nenhum)             | Se `tls_enabled` for `true` e CA não padrão/autoassinada. | `tls_ca_path = "/certs/typedb_ca.pem"` |

---

### Seção `[server]`

Configurações para o próprio Typedb-MCP-Server (onde ele escuta e como se comporta).

| Chave TOML                 | Variável de Ambiente                 | Tipo          | Descrição                                                                                                                                                                 | Padrão (Código)                                                                     | Obrigatório? | Exemplo TOML                         |
| :------------------------- | :----------------------------------- | :------------ | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | :---------------------------------------------------------------------------------- | :----------- | :----------------------------------- |
| `bind_address`             | `MCP_SERVER__BIND_ADDRESS`           | String        | Endereço de bind (IP:PORTA) para o servidor MCP escutar. Se `server.tls_enabled = true` e não definido, pode tentar porta HTTPS padrão (ex: 8443, mas verifique `main.rs`). | `"0.0.0.0:8787"`                                                                    | Sim          | `bind_address = "0.0.0.0:8080"`      |
| `tls_enabled`              | `MCP_SERVER__TLS_ENABLED`            | Boolean       | Habilita (true) ou desabilita (false) TLS (HTTPS/WSS) para o servidor MCP.                                                                                                  | `false`                                                                             | Não          | `tls_enabled = true`                 |
| `tls_cert_path`            | `MCP_SERVER__TLS_CERT_PATH`          | String (Path) | Caminho para o arquivo PEM do certificado do servidor MCP (fullchain).                                                                                                      | `null` (Nenhum)                                                                     | Se `server.tls_enabled` for `true`. | `tls_cert_path = "/certs/mcp.crt"`   |
| `tls_key_path`             | `MCP_SERVER__TLS_KEY_PATH`           | String (Path) | Caminho para o arquivo PEM da chave privada do servidor MCP.                                                                                                            | `null` (Nenhum)                                                                     | Se `server.tls_enabled` for `true`. | `tls_key_path = "/certs/mcp.key"`    |
| `worker_threads`           | `MCP_SERVER__WORKER_THREADS`         | Integer (usize) | Número de threads worker para o runtime Tokio. Se omitido, usa o número de CPUs lógicas disponíveis.                                                                  | `null` (Usa `num_cpus::get()`)                                                        | Não          | `worker_threads = 8`                 |
| `metrics_bind_address`     | `MCP_SERVER__METRICS_BIND_ADDRESS`   | String        | Endereço (IP:PORTA) para o endpoint de métricas Prometheus. Se `null`, o padrão em `main.rs` é "0.0.0.0:9090".                                                              | `null` (usa "0.0.0.0:9090" em `main.rs`)                                                | Não          | `metrics_bind_address = "0.0.0.0:9100"` |
| `mcp_websocket_path`       | `MCP_SERVER__MCP_WEBSOCKET_PATH`     | String        | Path do endpoint WebSocket MCP. Se `null`, o padrão em `main.rs` é "/mcp/ws".                                                                                                | `null` (usa "/mcp/ws" em `main.rs`)                                                     | Não          | `mcp_websocket_path = "/mcp"`        |
| `metrics_path`             | `MCP_SERVER__METRICS_PATH`           | String        | Path do endpoint de métricas Prometheus. Se `null`, o padrão em `main.rs` é "/metrics".                                                                                     | `null` (usa "/metrics" em `main.rs`)                                                    | Não          | `metrics_path = "/prom-metrics"`     |

---

### Seção `[oauth]`

Configurações para autenticação OAuth 2.0 dos clientes MCP.

| Chave TOML                       | Variável de Ambiente                       | Tipo             | Descrição                                                                                                                                                              | Padrão (Código)                  | Obrigatório? | Exemplo TOML                                                              |
| :------------------------------- | :----------------------------------------- | :--------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------------------------------- | :----------- | :------------------------------------------------------------------------ |
| `enabled`                        | `MCP_OAUTH__ENABLED`                       | Boolean          | Habilita (true) ou desabilita (false) a autenticação OAuth2.                                                                                                         | `false`                          | Não          | `enabled = true`                                                          |
| `jwks_uri`                       | `MCP_OAUTH__JWKS_URI`                      | String (URI)     | URI do endpoint JWKS (JSON Web Key Set) do Authorization Server.                                                                                                       | `null` (Nenhum)                  | Se `oauth.enabled` for `true`. | `jwks_uri = "https://auth.example.com/.well-known/jwks.json"`           |
| `issuer`                         | `MCP_OAUTH__ISSUER`                        | String ou Lista de Strings | Issuer(s) esperado(s) no JWT (claim "iss"). Se definido, o token será validado. Formato env: `"iss1,iss2"`.                                                     | `null` (Nenhum)                  | Não          | `issuer = ["https://auth.example.com"]`                                   |
| `audience`                       | `MCP_OAUTH__AUDIENCE`                      | String ou Lista de Strings | Audience(s) esperado(s) no JWT (claim "aud"). O token deve conter um destes. Formato env: `"aud1,aud2"`.                                                         | `null` (Nenhum)                  | Não          | `audience = "typedb-mcp-api"`                                             |
| `jwks_refresh_interval`          | `MCP_OAUTH__JWKS_REFRESH_INTERVAL`         | String (Duration) | Intervalo para recarregar o JWKS. Formato legível (ex: "1h", "30m", "3600s").                                                                                         | `"1h"` (3600 segundos)           | Não          | `jwks_refresh_interval = "30m"`                                           |
| `jwks_request_timeout_seconds`   | `MCP_OAUTH__JWKS_REQUEST_TIMEOUT_SECONDS`  | Integer (u64)  | Timeout em segundos para a requisição HTTP ao buscar o JWKS.                                                                                                         | `30`                             | Não          | `jwks_request_timeout_seconds = 10`                                       |
| `required_scopes`                | `MCP_OAUTH__REQUIRED_SCOPES`               | Lista de Strings | Lista de escopos OAuth2 que um token DEVE conter para acesso geral ao servidor. Autorização granular por ferramenta pode impor mais. Formato env: `"scope1,scope2"`. | `null` (Nenhum)                  | Não          | `required_scopes = ["mcp:access", "typedb:read"]`                       |

---

### Seção `[logging]`

Configurações de logging da aplicação.

| Chave TOML | Variável de Ambiente  | Tipo   | Descrição                                                                                                                                    | Padrão (Código)                                            | Obrigatório? | Exemplo TOML                                       |
| :--------- | :------------------ | :----- | :------------------------------------------------------------------------------------------------------------------------------------------- | :--------------------------------------------------------- | :----------- | :------------------------------------------------- |
| `rust_log` | `MCP_LOGGING__RUST_LOG` | String | String de configuração para o `EnvFilter` do `tracing_subscriber`. Controla o nível de log para diferentes módulos. Formato: `warn,app=debug`. | `"info,typedb_mcp_server_lib=info,typedb_driver=info"` | Não          | `rust_log = "debug,typedb_mcp_server=trace"` |

---

### Seção `[cors]`

Configurações de CORS (Cross-Origin Resource Sharing).

| Chave TOML          | Variável de Ambiente            | Tipo             | Descrição                                                                                                                               | Padrão (Código) | Obrigatório? | Exemplo TOML                                                           |
| :------------------ | :------------------------------ | :--------------- | :-------------------------------------------------------------------------------------------------------------------------------------- | :-------------- | :----------- | :--------------------------------------------------------------------- |
| `allowed_origins`   | `MCP_CORS__ALLOWED_ORIGINS`     | Lista de Strings | Lista de origens permitidas. Usar `["*"]` para permitir todas (NÃO RECOMENDADO para produção). Formato env: `"http://host1,https://host2"`. | `["*"]`         | Não          | `allowed_origins = ["https://meufrontend.com", "http://localhost:3000"]` |

---

### Seção `[rate_limit]`

Configurações de Limitação de Taxa (Rate Limiting) por IP.

| Chave TOML              | Variável de Ambiente                | Tipo          | Descrição                                                                                                          | Padrão (Código) | Obrigatório? | Exemplo TOML                   |
| :---------------------- | :---------------------------------- | :------------ | :----------------------------------------------------------------------------------------------------------------- | :-------------- | :----------- | :----------------------------- |
| `enabled`               | `MCP_RATE_LIMIT__ENABLED`           | Boolean       | Habilita (true) ou desabilita (false) o rate limiting.                                                               | `true`          | Não          | `enabled = false`              |
| `requests_per_second`   | `MCP_RATE_LIMIT__REQUESTS_PER_SECOND` | Integer (u64) | Número de requisições (ou novas conexões, dependendo da implementação) permitidas por segundo, por IP.           | `100`           | Não          | `requests_per_second = 50`     |
| `burst_size`            | `MCP_RATE_LIMIT__BURST_SIZE`        | Integer (u32) | Número de requisições permitidas em um burst (rajada), por IP.                                                       | `200`           | Não          | `burst_size = 100`             |

---

### Seção `[tracing]`

Configurações para Tracing Distribuído (OpenTelemetry).

| Chave TOML                   | Variável de Ambiente                     | Tipo         | Descrição                                                                                                                                       | Padrão (Código)         | Obrigatório? | Exemplo TOML                                     |
| :--------------------------- | :--------------------------------------- | :----------- | :---------------------------------------------------------------------------------------------------------------------------------------------- | :---------------------- | :----------- | :----------------------------------------------- |
| `enabled`                    | `MCP_TRACING__ENABLED`                   | Boolean      | Habilita (true) ou desabilita (false) o tracing OpenTelemetry.                                                                                    | `false`                 | Não          | `enabled = true`                                 |
| `exporter_otlp_endpoint`     | `MCP_TRACING__EXPORTER_OTLP_ENDPOINT`    | String (URI) | Endpoint do coletor OTLP (gRPC). Ex: "<http://localhost:4317>".                                                                                     | `null` (Nenhum)         | Se `tracing.enabled` for `true`. | `exporter_otlp_endpoint = "http://otel-collector:4317"` |
| `service_name`               | `MCP_TRACING__SERVICE_NAME`              | String       | Nome do serviço que aparecerá no sistema de tracing.                                                                                              | `"typedb-mcp-server"` | Não          | `service_name = "meu-mcp-servico"`               |
| `sampler`                    | `MCP_TRACING__SAMPLER`                   | String       | Estratégia de amostragem para traces. Valores comuns: "always_on", "always_off", "traceidratio", "parentbased_always_on".                       | `"always_on"`           | Não          | `sampler = "traceidratio"`                       |
| `sampler_arg`                | `MCP_TRACING__SAMPLER_ARG`               | String       | Argumento para o sampler. Para "traceidratio", é a taxa (ex: "0.1" para 10%). Para "always_on" ou "always_off", geralmente "1.0" ou não usado. | `"1.0"`                 | Não          | `sampler_arg = "0.05"`                           |

---

Este documento deve ser mantido atualizado conforme novas opções de configuração são adicionadas ou modificadas no arquivo `src/config.rs`.
