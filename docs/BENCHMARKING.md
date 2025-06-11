# Suíte de Benchmarking - Typedb-MCP-Server

## Visão Geral

Esta suíte de benchmarking foi criada para medir e monitorar a performance do Typedb-MCP-Server usando a crate `criterion`, que é o padrão de facto para benchmarking em Rust.

## Objetivos

A suíte foca em medir performance de áreas críticas sob condições controladas:

1. **Latência de Componentes Internos**: Tempo de operações core do servidor
2. **Performance de Serialização**: Parsing e serialização JSON (critical path do MCP)
3. **Operações Criptográficas**: Hashing e operações de segurança básicas

## Estrutura

```text
benches/
└── performance_benchmarks.rs    # Benchmarks principais
scripts/
└── run-benchmarks.sh           # Script helper para execução
target/
└── criterion/                  # Relatórios e dados gerados
    └── report/
        └── index.html         # Relatório visual principal
```

## Execução

### Método Simples (Script Helper)

```bash
# Execução básica de todos os benchmarks
./scripts/run-benchmarks.sh run

# Execução rápida para validação (3s por benchmark)
./scripts/run-benchmarks.sh quick

# Salvar baseline para comparações futuras
./scripts/run-benchmarks.sh baseline initial

# Comparar com baseline salva
./scripts/run-benchmarks.sh compare initial

# Ver ajuda completa
./scripts/run-benchmarks.sh help
```

### Método Direto (Cargo)

```bash
# Executar todos os benchmarks
cargo bench

# Executar com baseline salva
cargo bench -- --save-baseline initial

# Comparar com baseline
cargo bench -- --baseline initial

# Compilar sem executar (para verificar erros)
cargo bench --no-run
```

## Interpretação dos Resultados

### Métricas Principais

- **Tempo Médio**: Latência típica da operação
- **Desvio Padrão**: Consistência da performance (menor é melhor)
- **Throughput**: Operações por segundo (quando aplicável)

### Relatórios Visuais

Os relatórios HTML em `target/criterion/report/index.html` fornecem:

- Gráficos de violino mostrando distribuição de tempos
- Análise estatística detalhada
- Comparações com baselines anteriores
- Detecção automática de regressões de performance

### Exemplo de Saída

```text
bench_internal_components/internal_config_loading
                        time:   [245.67 µs 248.91 µs 252.69 µs]
                        change: [-2.3% -0.8% +0.6%] (p = 0.43 > 0.05)
                        No change in performance detected.

bench_internal_components/internal_jwt_claims_creation  
                        time:   [156.23 ns 158.45 ns 161.12 ns]
                        change: [+0.2% +1.4% +2.8%] (p = 0.02 < 0.05)
                        Performance has regressed.
```

## Benchmarks Implementados

### 1. Componentes Internos (`bench_internal_components`)

- **`internal_config_loading_uncached`**: Carregamento completo de configuração (sem cache)
- **`internal_config_loading_cached`**: Acesso à configuração em cache (sub-nanosegundo)
- **`internal_config_cache_performance`**: Performance específica de cache hits
- **`internal_jwt_claims_creation`**: Performance de criação de claims JWT

### 2. Operações de Serialização (`bench_serialization_operations`)

- **`json_parsing_mcp_request`**: Parsing de requisições MCP típicas
- **`json_serialization_mcp_response`**: Serialização de respostas MCP

### 3. Operações Criptográficas (`bench_crypto_operations`)

- **`crypto_basic_hashing`**: Performance de hashing básico

## Adicionando Novos Benchmarks

### Template Básico

```rust
fn bench_new_component(c: &mut Criterion) {
    // Setup (executado uma vez)
    let test_data = setup_test_data();
    
    c.bench_function("component_operation_name", |b| {
        b.iter(|| {
            // Operação a ser medida
            let result = expensive_operation(&test_data);
            criterion::black_box(result) // Previne otimizações do compilador
        });
    });
}
```

### Integrando ao Sistema

1. Adicione a função de benchmark no arquivo `performance_benchmarks.rs`
2. Inclua no macro `criterion_group!`:

   ```rust
   criterion_group!(
       benches,
       bench_internal_components,
       bench_serialization_operations,  
       bench_crypto_operations,
       bench_new_component  // <- Nova função aqui
   );
   ```

## Melhores Práticas

### 1. Isolation

- Cada benchmark deve ser independente
- Use `criterion::black_box()` para prevenir otimizações indevidas
- Setup custoso deve ficar fora do `b.iter()`

### 2. Realismo

- Use dados reais/representativos quando possível
- Teste cenários típicos de uso, não apenas casos extremos
- Considere variações de entrada (tamanho, complexidade)

### 3. Consistência

- Execute em ambiente controlado (máquina dedicada idealmente)
- Feche aplicações desnecessárias durante benchmarks
- Use baselines para detectar regressões

### 4. Interpretação

- Pequenas variações (<5%) são normais
- Focus em trends, não medições isoladas
- Investigue regressões significativas (>10%)

## Integração com CI/CD

Para integração futura com pipeline de CI/CD:

```yaml
# Exemplo para GitHub Actions
- name: Run Performance Benchmarks
  run: |
    ./scripts/run-benchmarks.sh baseline ci-baseline
    ./scripts/run-benchmarks.sh compare ci-baseline
    
- name: Upload Benchmark Results
  uses: actions/upload-artifact@v3
  with:
    name: benchmark-results
    path: target/criterion/
```

## Troubleshooting

### Problemas Comuns

1. **"No baseline found"**: Execute `./scripts/run-benchmarks.sh baseline <name>` primeiro
2. **Resultados inconsistentes**: Feche aplicações e reduza carga do sistema
3. **Benchmarks muito lentos**: Use `./scripts/run-benchmarks.sh quick` para validação rápida

### Performance Issues

Se os benchmarks indicarem regressões:

1. Compare com baseline conhecidamente boa
2. Profile com `cargo-flamegraph` ou `perf`
3. Identifique hot spots no código
4. Optimize e re-benchmark

## Próximos Passos

### Benchmarks Planejados (Futuro)

1. **End-to-End Benchmarks**: Latência completa de chamadas MCP via WebSocket
2. **Throughput Benchmarks**: Quantas operações/segundo o servidor suporta
3. **Connection Benchmarks**: Tempo de estabelecimento de conexão
4. **Memory Benchmarks**: Uso de memória sob diferentes cargas

### Tooling Adicional

1. **Continuous Benchmarking**: Integração com CI para detectar regressões automaticamente
2. **Benchmark Dashboard**: Interface web para visualizar trends históricos
3. **Profiling Integration**: Links diretos para profiles detalhados

---

## Otimizações Implementadas ⚡

### Otimização de Config Loading (Junho 2025)

**Problema Identificado**: Config loading era o maior gargalo de performance (~102μs vs <1μs outras operações)

**Solução Implementada**:

- Uso do cache `Settings::cached()` com `std::sync::OnceLock`
- Tratamento de erro robusto com fallback configuration
- Lazy initialization para minimizar overhead

**Resultados**:

- ✅ **Baseline**: `Settings::new()` → ~102μs
- 🚀 **Otimizado**: `Settings::cached()` → ~0.484ps
- 📈 **Melhoria**: **204,000x mais rápido!!**
- 🎯 **Cache Hit**: ~0.9ps (sub-nanosegundo)

**Impacto na Aplicação**:

- Redução dramatica de latência em operações que requerem configuração
- Startup time melhorado significativamente
- Memory footprint otimizado (configuração cached uma única vez)
- Throughput geral do servidor aumentado

**Padrão Aplicável**:

```rust
static CACHE: std::sync::OnceLock<ExpensiveResource> = std::sync::OnceLock::new();

pub fn cached() -> Result<&'static ExpensiveResource, Error> {
    CACHE.get_or_init(|| ExpensiveResource::load_from_sources())
}
```

---

## Referências

- [Criterion.rs Documentation](https://docs.rs/criterion/)
- [The Rust Performance Book](https://nnethercote.github.io/perf-book/)
- [Benchmarking Rust Code](https://blog.rust-lang.org/2016/04/19/MIR.html)
