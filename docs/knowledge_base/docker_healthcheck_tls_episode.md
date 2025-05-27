# Episode: Docker Healthcheck TLS Incompatibility Fix

**Date:** 2025-05-27  
**Type:** Debugging Session  
**Outcome:** ✅ Success  

## Problem Description

O teste `test_server_tls_connection_succeeds_with_wss` estava falhando com erro "container mcp-server is unhealthy" durante o `docker compose up --wait`. O container conseguia iniciar mas o Docker Compose o marcava como unhealthy, fazendo o comando falhar.

## Root Cause Analysis

**Causa raiz identificada:** Incompatibilidade entre healthcheck fixo no Dockerfile e configuração TLS dinâmica.

**Detalhes:**

- Dockerfile tem healthcheck fixo: `curl -f http://localhost:8787/livez`
- Arquivo `server_tls.test.toml` configura servidor para escutar em HTTPS porta 8443
- Healthcheck HTTP na porta 8787 falha quando servidor está em HTTPS 8443
- `docker compose up --wait` aguarda containers "healthy", mas healthcheck falha
- Container é marcado como "unhealthy" e comando `up --wait` falha

## Analysis Steps

1. **Container Status Investigation:** Container iniciava mas era marcado como unhealthy
2. **Healthcheck Analysis:** Dockerfile hardcoded HTTP healthcheck para porta 8787
3. **Configuration Impact:** TLS config mudava porta para 8443 e protocolo para HTTPS
4. **Docker Compose Behavior:** `--wait` flag depende de healthchecks passando

## Solution Implemented

**Modificação em `tests/common/docker_helpers.rs`:**

```rust
// Antes: Sempre usa --wait
let up_subcommand_args: Vec<&str> = 
    vec!["up", "-d", "--remove-orphans", "--force-recreate", "--build", "--wait"];

// Depois: Condicional baseado em wait_for_health
pub fn up(&self, config_filename: &str, active_profiles: Option<Vec<String>>, wait_for_health: bool) -> Result<()> {
    // ...
    let mut up_subcommand_args: Vec<&str> = 
        vec!["up", "-d", "--remove-orphans", "--force-recreate", "--build"];
    
    if wait_for_health {
        up_subcommand_args.push("--wait");
    }
    // ...
}
```

**Modificação em `tests/common/test_env.rs`:**

```rust
// Não usar --wait do Docker Compose quando MCP server usar TLS
let should_wait_docker_compose_health = !is_mcp_server_tls;

docker_env.up(&config.config_filename, Some(active_profiles.clone()), should_wait_docker_compose_health)
```

## Impact Assessment

- **Severidade:** Média-Alta (bloqueia todos os testes TLS)
- **Scope:** Testes de integração com servidor MCP TLS
- **Resultado:** Docker Compose não mais depende de healthcheck HTTP quando TLS ativo
- **Benefício:** Lógica customizada `wait_for_mcp_server_ready_from_test_env` com HTTPS funciona corretamente

## Knowledge Extracted

### Docker Compose Pattern

**Título:** Conditional Healthcheck Usage in Docker Compose  
**Insight:** Quando containers têm configurações dinâmicas que afetam healthchecks, use `--wait` condicionalmente baseado na configuração esperada.

**Pattern aplicável:**

```rust
// Para ambientes com configuração dinâmica
let should_wait_for_docker_healthcheck = !configuration_changes_healthcheck_behavior;
docker_env.up(config, profiles, should_wait_for_docker_healthcheck)
```

### Testing Strategy Pattern  

**Título:** Custom Health Checks for Dynamic Configurations  
**Approach:** Quando Dockerfile healthchecks são incompatíveis com configurações de teste:

1. Desabilitar `--wait` do Docker Compose para configurações problemáticas
2. Implementar lógica customizada de health check que entende a configuração
3. Manter método de compatibilidade para casos simples

### Architecture Pattern

**Título:** Test Environment Configuration Awareness  
**Insight:** Sistemas de teste devem ser "configuration-aware" para adaptar comportamentos de infraestrutura baseado em configuração de aplicação.

**Better Approach:**

- Test environment adapta comportamento baseado em `TestConfiguration`
- Infrastructure tools (Docker Compose) usam flags condicionalmente
- Custom readiness checks complementam healthchecks simples

## Files Modified

- ✅ `/tests/common/docker_helpers.rs` - Adicionado parâmetro `wait_for_health` à função `up`
- ✅ `/tests/common/test_env.rs` - Lógica condicional para não usar `--wait` com TLS
- ✅ Método de compatibilidade `up_compat` para manter API anterior

## Metrics

- **Problem Resolution Speed:** Alto
- **Solution Elegance:** Alta (mínima mudança, máxima compatibilidade)
- **Prevention Value:** Alto (resolve toda classe de problemas similares)
- **Code Quality Impact:** Positivo (API mais flexível)

## Lessons Learned

1. **Infrastructure Awareness:** Ferramentas de teste devem ser conscientes de configurações de aplicação que afetam infraestrutura
2. **Conditional Behavior:** Use flags condicionalmente baseado em contexto, não cegamente
3. **Layered Health Checks:** Combine healthchecks simples (Docker) com lógica customizada (application-aware)
4. **Backward Compatibility:** Mantenha métodos de compatibilidade para transições suaves

## Related Documentation

- [Docker TLS Permissions Episode](./docker_tls_permissions_episode.md) - Problema anterior relacionado a TLS
- [Docker TLS Patterns](./docker_tls_patterns.md) - Padrões gerais Docker/TLS

---

**Status:** Solução implementada e testada  
**Next Actions:** Validar que teste passa consistentemente, considerar documentar pattern para futuros casos similares
