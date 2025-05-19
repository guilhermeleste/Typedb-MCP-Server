
# Guia do Desenvolvedor: Trabalhando com Métricas e Tracing

O Typedb-MCP-Server integra-se com sistemas de métricas (Prometheus) e tracing distribuído (OpenTelemetry) para fornecer uma observabilidade robusta. Este guia destina-se a desenvolvedores que desejam entender como adicionar novas métricas, instrumentar código com tracing, ou como esses sistemas são configurados.

Para uma visão geral de como os usuários consomem essas funcionalidades, consulte a seção [Observabilidade do Guia do Usuário](../user_guide/08_observability.md).
Para uma lista completa de métricas expostas, veja a [Referência de Métricas](../reference/metrics_list.md).

## 1. Métricas com a Crate `metrics` e Prometheus

O servidor utiliza a crate [`metrics`](https://docs.rs/metrics) como uma fachada para instrumentação de código. As métricas são então expostas no formato Prometheus através da crate [`metrics-exporter-prometheus`](https://docs.rs/metrics-exporter-prometheus).

### a. Definição de Métricas (`src/metrics.rs`)

Todas as métricas customizadas da aplicação são definidas como constantes e registradas com descrições no módulo `src/metrics.rs`.

* **Prefixo Global:** Todas as métricas usam o prefixo `typedb_mcp_server_` (definido como `METRIC_PREFIX` em `src/metrics.rs`).
* **Tipos de Métricas:**
  * **Contadores (`Counter`):** Para valores que só aumentam (ex: total de requisições). Use `metrics::counter!(METRIC_NAME, value, LABELS_ARRAY).increment(amount);`.
  * **Gauges (`Gauge`):** Para valores que podem aumentar ou diminuir (ex: número de conexões ativas). Use `metrics::gauge!(METRIC_NAME, LABELS_ARRAY).set(value);` ou `.increment(amount);` / `.decrement(amount);`.
  * **Histogramas (`Histogram`):** Para medir distribuições de valores, como latências. Use `metrics::histogram!(METRIC_NAME, LABELS_ARRAY).record(value_seconds);`.
* **Labels:** As métricas podem ter labels para dimensionalidade (ex: `tool_name`, `status`). Os labels são passados como um array de tuplas `("key", "value")`.

### b. Registrando Novas Métricas

Para adicionar uma nova métrica:

1. **Defina uma Constante para o Nome:**
    Em `src/metrics.rs`, adicione uma constante para o nome da sua métrica (sem o prefixo global, que será adicionado automaticamente).

    ```rust
    // src/metrics.rs
    pub const NOVA_METRICA_TOTAL: &str = "nova_metrica_total";
    ```

2. **Descreva a Métrica:**
    Na função `register_metrics_descriptions()` em `src/metrics.rs`, adicione uma chamada para descrever sua nova métrica. Isso é importante para que o exportador Prometheus saiba o tipo e a ajuda da métrica.

    ```rust
    // src/metrics.rs
    // Dentro de register_metrics_descriptions()
    describe_counter!(
        format!("{}{}", METRIC_PREFIX, NOVA_METRICA_TOTAL),
        Unit::Count, // Ou Unit::Seconds, Unit::Bytes, etc.
        SharedString::from("Descrição da sua nova métrica.")
    );
    ```

3. **Use a Métrica no Código:**
    No local apropriado do seu código, use as macros da crate `metrics` para registrar observações.

    **Exemplo de Contador:**

    ```rust
    use crate::metrics; // Certifique-se de que o módulo metrics está no escopo

    // ... no seu código ...
    metrics::counter!(
        format!("{}{}", metrics::METRIC_PREFIX, metrics::NOVA_METRICA_TOTAL),
        "label_exemplo" => "valor_label" // Labels são opcionais
    ).increment(1);
    ```

    **Exemplo de Gauge:**

    ```rust
    // Para definir um valor absoluto
    metrics::gauge!(
        format!("{}{}", metrics::METRIC_PREFIX, metrics::ALGUM_GAUGE_ATIVO),
    ).set(42.0);

    // Para incrementar/decrementar
    metrics::gauge!(
        format!("{}{}", metrics::METRIC_PREFIX, metrics::ALGUM_GAUGE_ATIVO),
    ).increment(1.0);
    ```

    **Exemplo de Histograma (para medir duração):**

    ```rust
    use std::time::Instant;
    use crate::metrics;

    let start_time = Instant::now();
    // ... sua operação ...
    let duration_secs = start_time.elapsed().as_secs_f64();

    metrics::histogram!(
        format!("{}{}", metrics::METRIC_PREFIX, metrics::DURACAO_OPERACAO_SECONDS),
        "status" => "success"
    ).record(duration_secs);
    ```

### c. Configuração e Exposição

* O setup inicial do exportador Prometheus e a inicialização do servidor HTTP para o endpoint `/metrics` são feitos em `src/main.rs` na função `setup_metrics`.
* As configurações `server.metrics_bind_address` e `server.metrics_path` controlam onde este endpoint é exposto.

## 2. Tracing Distribuído com `tracing` e OpenTelemetry

O servidor utiliza a crate [`tracing`](https://docs.rs/tracing) para logging estruturado e spans de tracing, e [`opentelemetry`](https://opentelemetry.io/) (com `opentelemetry-otlp`) para exportar esses spans para um coletor OpenTelemetry.

### a. Adicionando Spans de Tracing

A macro `#[tracing::instrument]` é a maneira mais fácil de adicionar tracing a funções. Ela cria um span que cobre a execução da função e automaticamente inclui os argumentos da função como campos do span (a menos que sejam explicitamente ignorados).

```rust
// Exemplo de instrumentação de uma função
#[tracing::instrument(
    name = "minha_operacao_customizada", // Nome do span (opcional, usa nome da função por padrão)
    skip(sensivel_arg), // Não incluir este argumento nos atributos do span
    fields(db.name = %database_name) // Adicionar campos customizados ao span
)]
async fn fazer_algo_importante(database_name: &str, sensivel_arg: &str, outro_param: i32) -> Result<(), ()> {
    tracing::debug!(evento = "Iniciando sub-operação", param = outro_param);
    // ... lógica da função ...

    // Adicionar eventos dentro de um span
    tracing::info!(resultado = "Operação concluída com sucesso", "Descrição do evento");

    // Adicionar atributos a um span existente a partir de qualquer lugar
    tracing::Span::current().record("http.status_code", 200);

    Ok(())
}
```

* **`name`**: Define o nome do span. Se omitido, usa o nome da função.
* **`skip(...)`**: Lista de argumentos da função que não devem ser incluídos automaticamente como atributos do span. Útil para dados sensíveis ou muito grandes.
* **`fields(...)`**: Permite adicionar atributos customizados ao span. Use `%` para formatação `Display` e `?` para formatação `Debug`.
* **Macros de Evento:** `tracing::info!`, `tracing::debug!`, `tracing::warn!`, `tracing::error!` criam eventos dentro do span atual.
* **`tracing::Span::current().record(...)`**: Permite adicionar atributos ao span atual de forma dinâmica.

### b. Propagação de Contexto

Para que o tracing distribuído funcione corretamente através de limites de tasks assíncronas ou threads, o contexto de tracing (que inclui o ID do trace e o ID do span pai) precisa ser propagado.

* **Tokio Tasks:** A crate `tracing` integra-se bem com Tokio. Spans geralmente são propagados automaticamente para tasks filhas se a task filha for gerada dentro de um span.
* **Limites de Rede (Cliente/Servidor):** Para tracing entre serviços, é necessário usar propagadores de contexto OpenTelemetry (ex: W3C Trace Context) para injetar/extrair o contexto de headers HTTP ou metadados de mensagens. O Typedb-MCP-Server (como servidor) atualmente não *inicia* novos traces baseados em headers de entrada automaticamente para requisições MCP, mas o fará para requisições HTTP se o middleware `TraceLayer` do `tower-http` for usado apropriadamente.

### c. Configuração do Pipeline OpenTelemetry (`src/telemetry.rs`)

O módulo `src/telemetry.rs` é responsável por:

* Inicializar o exportador OTLP (gRPC) com base na configuração `tracing.exporter_otlp_endpoint`.
* Configurar o `SdkTracerProvider` com um sampler (`tracing.sampler` e `tracing.sampler_arg`) e um processador de batch de spans.
* Definir recursos OpenTelemetry (como `service.name`).
* Registrar o provider globalmente.

A função `setup_logging_and_tracing` em `src/main.rs` chama `telemetry::init_tracing_pipeline` se o tracing estiver habilitado.

### d. Logging Estruturado

Os eventos de log criados com as macros da crate `tracing` (ex: `tracing::info!`) são:

* **Estruturados:** Emitidos em formato JSON por padrão (configurado em `setup_logging_and_tracing` em `main.rs`).
* **Contextualizados:** Automaticamente incluem informações do span atual e de seus pais, se o log ocorrer dentro de um span.
* **Filtráveis:** Controlados pela diretiva `RUST_LOG` ou `logging.rust_log`.

## Considerações para Desenvolvedores

* **Cardinalidade de Labels de Métricas:** Tenha cuidado ao adicionar labels com alta cardinalidade (muitos valores únicos, como IDs de usuário ou de requisição) às métricas, pois isso pode sobrecarregar o sistema Prometheus.
* **Nomes de Spans e Atributos:** Use nomes consistentes e significativos para spans e atributos de tracing. Siga as [convenções semânticas do OpenTelemetry](https://opentelemetry.io/docs/specs/semconv/) sempre que possível.
* **Overhead:** Embora `tracing` e `metrics` sejam projetados para serem eficientes, instrumentação excessiva pode introduzir algum overhead. Use com critério, especialmente em caminhos de código críticos para performance.
* **Teste:** Verifique se suas novas métricas aparecem corretamente no endpoint `/metrics` e se os spans de tracing são gerados como esperado (usando um coletor OTLP local para desenvolvimento, se necessário).
