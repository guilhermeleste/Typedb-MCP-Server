
# Guia do Usuário: Observabilidade do Typedb-MCP-Server

Entender o comportamento e a saúde do Typedb-MCP-Server é crucial para garantir sua operação confiável e eficiente. Este servidor foi projetado com a observabilidade em mente, expondo métricas detalhadas, health checks e logs configuráveis.

Esta seção do guia do usuário cobre como acessar e interpretar essas ferramentas de observabilidade. Para detalhes técnicos mais profundos, consulte a seção [Observabilidade Aprofundada](../advanced_topics/observability_deep_dive.md) no Guia de Tópicos Avançados (quando disponível) e a [Referência de Métricas](../reference/metrics_list.md).

## 1. Métricas com Prometheus

O Typedb-MCP-Server expõe métricas no formato de texto Prometheus, permitindo que você as colete e visualize com ferramentas como Prometheus e Grafana.

### Acessando o Endpoint de Métricas

* **URL Padrão:** `http://<host_do_servidor_de_metricas>:<porta_de_metricas>/metrics`
* **Configuração:**
  * O endereço de bind (host e porta) é definido pela opção `server.metrics_bind_address` no seu arquivo de configuração (padrão: `0.0.0.0:9090`).
  * O path do endpoint é definido por `server.metrics_path` (padrão: `/metrics`).

**Exemplo:** Se o servidor de métricas estiver rodando em `localhost` na porta `9090` com o path padrão, você pode acessar as métricas em `http://localhost:9090/metrics` através do seu navegador ou de uma ferramenta como `curl`.

### Principais Métricas a Observar

Embora uma [lista completa de métricas esteja disponível na referência](../reference/metrics_list.md), algumas das mais importantes para monitoramento geral incluem:

* **`typedb_mcp_server_websocket_active_connections` (Gauge):** Número de clientes MCP atualmente conectados. Útil para entender a carga de conexões.
* **`typedb_mcp_server_tool_calls_total` (Counter):** Total de chamadas de ferramentas MCP, com labels `tool_name` e `status`. Monitore a taxa de chamadas e a proporção de `status="failure"` ou `status="error_..."` para identificar problemas.
* **`typedb_mcp_server_tool_call_duration_seconds` (Histogram):** Distribuição da latência das chamadas de ferramentas. Picos ou aumentos nesta métrica podem indicar gargalos de performance.
* **`typedb_mcp_server_typedb_requests_total` (Counter):** Número total de interações diretas com o TypeDB, com labels `operation_type` e `status`. Importante para monitorar a saúde da comunicação com o banco.
* **`typedb_mcp_server_typedb_request_duration_seconds` (Histogram):** Latência das operações com o TypeDB.
* **`typedb_mcp_server_oauth_tokens_validated_total` (Counter):** Se OAuth2 estiver habilitado, monitora a taxa de validação de tokens e o status (ex: `valid`, `expired`, `invalid_signature`).
* **`up` (Gauge - fornecida pelo Prometheus ao coletar):** Indica se o servidor MCP está acessível para o Prometheus (`1` para acessível, `0` para inacessível).

### Integrando com Prometheus e Grafana

1. **Configure o Prometheus:** Adicione um job de scrape ao seu arquivo `prometheus.yml` para coletar as métricas do Typedb-MCP-Server.

    ```yaml
    scrape_configs:
      - job_name: 'typedb-mcp-server'
        static_configs:
          - targets: ['<host_do_servidor_de_metricas>:<porta_de_metricas>']
            # Se você alterou o server.metrics_path:
            # metrics_path: '/seu/path/de/metricas'
    ```

2. **Crie Dashboards no Grafana:** Use as métricas coletadas para criar dashboards que visualizem a saúde, performance e uso do servidor.

## 2. Health Checks

O servidor expõe dois endpoints HTTP para verificação de saúde, comumente usados por orquestradores de contêineres (como Kubernetes) ou balanceadores de carga.

### Liveness Probe (`livez`)

* **Endpoint:** `http://<host_do_servidor_mcp>:<porta_do_servidor_mcp>livez`
* **Método:** `GET`
* **Descrição:** Indica se a aplicação está rodando e o servidor HTTP base está respondendo. Uma falha aqui geralmente significa que o processo do servidor travou ou parou.
* **Resposta:**
  * `200 OK`: Se o servidor estiver funcional em um nível básico. O corpo pode conter `OK` ou um JSON simples.
  * Outros códigos: Se o servidor não estiver respondendo.

### Readiness Probe (`/readyz`)

* **Endpoint:** `http://<host_do_servidor_mcp>:<porta_do_servidor_mcp>/readyz`
* **Método:** `GET`
* **Descrição:** Indica se a aplicação está pronta para aceitar tráfego de clientes. Isso inclui a verificação da saúde de suas dependências críticas.
* **Resposta:**
  * `200 OK`: Se o servidor MCP e todas as suas dependências críticas (TypeDB e, se OAuth2 estiver habilitado, o JWKS URI) estiverem saudáveis e operacionais. O corpo da resposta é um JSON detalhando o status:

    ```json
    {
      "status": "UP", // Ou "DOWN"
      "components": {
        "typedb": "UP", // Ou "DOWN" se a conexão com o TypeDB falhar
        "jwks": "UP"    // Ou "DOWN" se OAuth2 estiver habilitado e o JWKS não estiver acessível,
                        // ou "NOT_CONFIGURED" se OAuth2 estiver desabilitado.
      }
    }
    ```

  * `503 Service Unavailable`: Se o servidor ou alguma de suas dependências críticas não estiverem prontas. O corpo JSON fornecerá detalhes sobre qual componente está causando o status "DOWN".

**Importância:**

* **Liveness:** Ajuda o sistema de orquestração a decidir se deve reiniciar um contêiner.
* **Readiness:** Ajuda o sistema de orquestração ou balanceador de carga a decidir se deve enviar tráfego para esta instância do servidor.

## 3. Logging

O Typedb-MCP-Server produz logs estruturados em formato JSON, o que facilita a análise e integração com sistemas centralizados de gerenciamento de logs (como ELK Stack, Splunk, Grafana Loki).

### Configuração de Log

* **Nível de Log:** O nível de detalhe dos logs é controlado pela variável de ambiente `RUST_LOG` ou pela chave `logging.rust_log` no arquivo de configuração.
* **Formato:** `RUST_LOG="[level],[target=level],[target2=level]"`
  * `level`: Nível padrão (ex: `info`, `warn`, `debug`, `trace`).
  * `target=level`: Define o nível para um módulo específico (target).
    * `typedb_mcp_server`: Logs do binário principal.
    * `typedb_mcp_server_lib`: Logs da biblioteca principal do servidor.
    * `typedb_driver`: Logs do driver TypeDB.
    * `axum`, `hyper`, `tower_http`: Logs das dependências da camada web.
* **Exemplo de Configuração:**

    ```toml
    # Em typedb_mcp_server_config.toml
    [logging]
    rust_log = "info,typedb_mcp_server_lib=debug,typedb_driver=warn"
    ```

    Ou via variável de ambiente:

    ```bash
    export RUST_LOG="info,typedb_mcp_server_lib=debug,typedb_driver=warn"
    ```

    O padrão é `"info,typedb_mcp_server_lib=info,typedb_driver=info"`.

### Campos de Log Importantes (JSON)

Cada linha de log é um objeto JSON que pode incluir (mas não se limita a):

* `timestamp`: Horário do evento de log.
* `level`: Nível do log (ex: `INFO`, `WARN`, `ERROR`, `DEBUG`, `TRACE`).
* `fields`:
  * `message`: A mensagem de log principal.
  * Outros campos contextuais dependendo do log (ex: `tool.name`, `client.user_id`, `error.message`, `db.name`).
* `target`: O módulo Rust que originou o log.
* `span`: Informações sobre o span de tracing atual (se o log ocorrer dentro de um span).
* `spans`: Lista de spans pai.
* `file`: O arquivo fonte onde o log foi emitido.
* `line`: O número da linha no arquivo fonte.

**Exemplo de Linha de Log (formatada para legibilidade):**

```json
{
  "timestamp": "2025-05-17T10:20:30.123Z",
  "level": "INFO",
  "fields": {
    "message": "Servidor MCP (HTTP/WS) escutando",
    "address": "0.0.0.0:8787"
  },
  "target": "typedb_mcp_server",
  "span": {
    "name": "server_main_async_logic",
    "address": "0.0.0.0:8787"
  },
  "spans": [
    { "name": "server_main_async_logic", "address": "0.0.0.0:8787" }
  ],
  "file": "src/main.rs",
  "line": 200
}
```

### Dicas para Análise de Logs

* **Aumente o Nível de Log:** Para depurar problemas, aumente o nível de log para `debug` ou `trace` para os módulos relevantes (ex: `typedb_mcp_server_lib=trace`).
* **Filtre por Target:** Se você suspeitar de um problema em um componente específico (ex: autenticação), filtre os logs pelo `target` correspondente (ex: `typedb_mcp_server_lib::auth`).
* **Procure por Erros e Avisos:** Filtre por `level: "ERROR"` ou `level: "WARN"` para encontrar rapidamente problemas potenciais.

## 4. Tracing Distribuído (OpenTelemetry)

Se habilitado na configuração (`tracing.enabled = true`), o Typedb-MCP-Server pode exportar dados de tracing distribuído para um coletor OpenTelemetry (OTLP) compatível. Isso permite rastrear requisições à medida que elas fluem pelo servidor e, potencialmente, por outros microsserviços em seu sistema.

* **Configuração:** Veja a seção `[tracing]` na [Referência de Configuração](../reference/configuration.md).
* **Uso:** Integre com ferramentas de visualização de tracing como Jaeger ou Zipkin para analisar os spans.

---

Ao utilizar essas ferramentas de observabilidade em conjunto, você terá uma visão abrangente do estado e do desempenho do seu Typedb-MCP-Server, facilitando a operação e o diagnóstico de problemas.
