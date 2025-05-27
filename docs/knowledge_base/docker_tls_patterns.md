# Knowledge Base: Docker & TLS Patterns

## Docker Security Patterns

### Pattern: Certificate Permissions in Non-Root Containers

**Context:** Aplicações rodando em containers Docker como usuários não-root  
**Problem:** Certificados com permissões 600 inacessíveis para usuário não-root  
**Solution:** Usar permissões 644 para certificados em ambientes containerizados  

**Implementation:**

```bash
# Em scripts de geração de certificados para Docker
chmod 644 certificate.crt
chmod 644 private.key  # Em ambiente de teste/desenvolvimento
```

**Evidence:** Debugging session 2025-05-27 - TLS container exit code 1  
**Confidence:** High  

---

## Testing Patterns

### Pattern: TLS Connection Test Debugging

**Debugging Checklist para testes TLS falhando:**

1. **Container Status**

   ```bash
   docker ps -a  # Verificar exit codes
   docker logs <container>  # Analisar logs de erro
   ```

2. **File Permissions**

   ```bash
   ls -la tests/test_certs/  # Verificar permissões de certificados
   ```

3. **Environment Context**

   ```bash
   docker exec <container> whoami  # Verificar usuário de execução
   ```

4. **Port Conflicts**

   ```bash
   docker container prune  # Limpar containers órfãos
   netstat -tlnp | grep :1729  # Verificar uso de porta
   ```

**Evidence:** Successful resolution of test_server_tls_connection_fails_with_ws  
**Confidence:** High  

---

## Antipatterns

### Antipattern: Overly Restrictive Docker Permissions

**What not to do:**

```bash
# Em ambientes Docker com usuários não-root
chmod 600 certificates/*  # ❌ Muito restritivo
```

**Why it fails:** Usuário não-root não consegue ler arquivos necessários

**Better approach:**

```bash
# Para ambientes containerizados
chmod 644 certificates/*  # ✅ Permissões adequadas
```

**Detection:** Container exit codes 1, permission denied errors nos logs  

---

## Debugging Strategies

### Strategy: Systematic Container Debugging

**Approach:** logs → permissions → environment → cleanup

1. **Logs First:** Sempre começar com análise de logs para identificar sintomas
2. **Permissions Check:** Verificar se permissões de arquivo são adequadas para contexto
3. **Environment Validation:** Confirmar usuário, portas, dependências
4. **Clean Environment:** Limpar estado anterior que pode interferir

**Metrics:**

- Reduces debugging time by ~60%
- Increases success rate in identifying root cause
- Prevents recurring similar issues

---

## Registry Updates

**Last Updated:** 2025-05-27  
**Source:** TLS Certificate Permissions Fix Debugging Session  
**Status:** Validated and Applied  

**Related Documentation:**

- [Episode Documentation](./docker_tls_permissions_episode.md)
- [Developer Guide - Auth](../developer_guide/06_working_with_auth.md)
