# Referência Detalhada de Métricas do Typedb-MCP-Server

O Typedb-MCP-Server expõe uma variedade de métricas no formato Prometheus para monitoramento e observabilidade. Este documento detalha cada métrica, seu tipo, descrição e quaisquer labels associados.

**Endpoint de Métricas Padrão:** `http://<host_do_servidor_de_metricas>:<porta_de_metricas>/metrics`

* O host e a porta são definidos por `server.metrics_bind_address` (padrão: `0.0.0.0:9090`).
* O path é definido por `server.metrics_path` (padrão: `/metrics`).

**Prefixo Global:** Todas as métricas são prefixadas com `typedb_mcp_server_` para fácil identificação e namespacing em seu sistema de monitoramento.

## Convenções de Nomes e Labels

* **Nomes de Métricas:** Seguem o padrão `snake_case`.
* **Unidades:** Onde aplicável, as unidades são indicadas na descrição ou no nome (ex: `_seconds`, `_total`).
* **Labels Comuns:**
  * `tool_name`: O nome da ferramenta MCP invocada.
  * `status`: O resultado de uma operação (ex: "success", "failure", "error_type").
  * `operation_type`: O tipo de operação realizada (ex: "read", "write_data", "define_schema").
  * `app_version`: A versão do Typedb-MCP-Server.
  * `rust_version`: A versão do compilador Rust usado para construir o servidor.

---

## Contadores (Counters)

Contadores são valores cumulativos que só podem aumentar ou ser resetados para zero na reinicialização do servidor.

| Nome da Métrica (após prefixo)        | Descrição                                                                                                | Labels Comuns          | Unidade |
| :------------------------------------- | :------------------------------------------------------------------------------------------------------- | :--------------------- | :------ |
| `websocket_connections_total`          | Número total de conexões WebSocket estabelecidas desde o início do servidor.                               | N/A                    | Contagem |
| `tool_calls_total`                     | Número total de chamadas de ferramentas MCP.                                                               | `tool_name`, `status`    | Contagem |
| `oauth_tokens_validated_total`         | Número total de tokens OAuth2 processados para validação.                                                  | `status`               | Contagem |
| `typedb_requests_total`                | Número total de requisições diretas ao TypeDB (ex: abertura de transação, execução de query dentro de uma tx). | `operation_type`, `status` | Contagem |
| `jwks_fetch_total`                     | Número total de tentativas de buscar o JWKS (JSON Web Key Set) do provedor OAuth2.                         | `status`               | Contagem |
| `config_load_attempts_total`           | Número total de tentativas de carregar a configuração da aplicação.                                        | `status`               | Contagem |

---

## Gauges

Gauges são valores que podem aumentar ou diminuir arbitrariamente.

| Nome da Métrica (após prefixo)         | Descrição                                                                                                     | Labels Comuns                 | Unidade |
| :-------------------------------------- | :------------------------------------------------------------------------------------------------------------ | :---------------------------- | :------ |
| `websocket_active_connections`          | Número de conexões WebSocket atualmente ativas.                                                                 | N/A                           | Contagem |
| `jwks_keys_cached_count`                | Número de chaves públicas (JWKs) atualmente em cache do provedor OAuth2.                                        | N/A                           | Contagem |
| `info`                                  | Informações sobre o servidor, como versão da aplicação e versão do Rust. Exposto como um gauge com valor `1`. | `app_version`, `rust_version` | Contagem (valor `1`) |
| `ready_status`                          | Status de prontidão do servidor. `1` se pronto para receber tráfego, `0` caso contrário.                      | N/A                           | Booleano (0 ou 1) |

---

## Histogramas (Histograms)

Histogramas amostram observações (geralmente durações de requisições ou tamanhos de resposta) e as contam em buckets configuráveis. Eles também fornecem uma soma de todos os valores observados. As métricas de histograma expostas pelo Prometheus incluem:

* `_bucket{le="<upper_bound>"}`: Contagem de observações menores ou iguais ao limite superior do bucket.
* `_sum`: Soma total de todos os valores observados.
* `_count`: Contagem total de observações.

| Nome da Métrica (após prefixo)                  | Descrição                                                                           | Labels Comuns          | Unidade   |
| :---------------------------------------------- | :---------------------------------------------------------------------------------- | :--------------------- | :-------- |
| `tool_call_duration_seconds`                    | Distribuição da duração das chamadas de ferramentas MCP.                              | `tool_name`, `status`    | Segundos  |
| `oauth_token_validation_duration_seconds`       | Distribuição da duração da validação de tokens OAuth2.                                | `status`               | Segundos  |
| `typedb_request_duration_seconds`               | Distribuição da duração das requisições diretas ao TypeDB.                             | `operation_type`, `status` | Segundos  |
| `jwks_fetch_duration_seconds`                   | Distribuição da duração das buscas ao JWKS do provedor OAuth2.                         | `status`               | Segundos  |

---

## Detalhes dos Labels

### `status`

Indica o resultado de uma operação. Valores comuns podem incluir:

* `success`: A operação foi concluída com sucesso.
* `failure`: A operação falhou devido a um erro esperado ou tratado (ex: erro de validação de entrada, recurso não encontrado).
* `error_auth`: A operação falhou devido a um erro de autenticação ou autorização.
* `error_internal`: A operação falhou devido a um erro interno inesperado no servidor.
* `error_typedb`: A operação falhou devido a um erro retornado pelo TypeDB.
* Para `jwks_fetch_total`: `success`, `http_error`, `json_error`.
* Para `config_load_attempts_total`: `success`, `failure`.
* Para `oauth_tokens_validated_total`: `valid`, `invalid_signature`, `expired`, `kid_not_found`, `malformed`, `issuer_mismatch`, `audience_mismatch`, `fetch_jwks_failed`.

### `operation_type`

Descreve o tipo de interação com o TypeDB ou outra operação interna. Exemplos:

* Para `typedb_requests_total`:
  * `transaction_open_read`
  * `transaction_open_write`
  * `transaction_open_schema`
  * `transaction_commit`
  * `transaction_rollback`
  * `query_read` (execução de uma query de leitura dentro de uma tx)
  * `query_write` (execução de uma query de escrita dentro de uma tx)
  * `query_schema` (execução de uma query de esquema dentro de uma tx)
  * `db_create`
  * `db_delete`
  * `db_exists`
  * `db_list`
  * `db_get_schema`
  * `db_get_type_schema`

### `tool_name`

O nome exato da ferramenta MCP invocada, como definido na [Referência da API](./api.md). Exemplos: `query_read`, `define_schema`, `create_database`.

### `app_version`

A versão do Typedb-MCP-Server, conforme definida no `Cargo.toml` (ex: "0.1.0").

### `rust_version`

A versão do compilador Rust usado para construir o servidor (ex: "1.87.0").

## Utilizando as Métricas

Estas métricas podem ser coletadas por um servidor Prometheus e usadas para:

* Criar dashboards no Grafana ou outras ferramentas de visualização.
* Configurar alertas para condições anormais (ex: alta taxa de erro, latência elevada, servidor não pronto).
* Analisar tendências de performance e uso ao longo do tempo.
* Diagnosticar problemas e gargalos.

Para mais informações sobre como configurar o Prometheus para coletar estas métricas, consulte a [documentação oficial do Prometheus](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#scrape_config).

---

Este documento é gerado com base nas métricas definidas em [`src/metrics.rs`](../../src/metrics.rs). Consulte o código-fonte para as definições exatas e para quaisquer métricas adicionadas recentemente.
