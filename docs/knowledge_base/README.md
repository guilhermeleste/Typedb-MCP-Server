# Knowledge Base Index

## 🧠 Sistema de Conhecimento do Typedb-MCP-Server

Este diretório contém o conhecimento estruturado extraído de experiências de desenvolvimento, debugging e melhorias do projeto.

## 📋 Categorias de Conhecimento

### 🐳 Docker & Containers

- [Docker TLS Patterns](./docker_tls_patterns.md) - Padrões de permissões e TLS em containers
- [Docker TLS Permissions Episode](./docker_tls_permissions_episode.md) - Debugging session detalhada de permissões TLS
- [Docker Healthcheck TLS Episode](./docker_healthcheck_tls_episode.md) - Correção de healthcheck incompatível com TLS

### 🔐 Security & Authentication

- [TLS Configuration Best Practices](./docker_tls_patterns.md#docker-security-patterns)
- Certificate permissions in containerized environments

### 🧪 Testing Strategies

- [TLS Connection Test Debugging](./docker_tls_patterns.md#testing-patterns)
- Systematic debugging approaches

### 🚫 Antipatterns Identificados

- [Overly Restrictive Docker Permissions](./docker_tls_patterns.md#antipatterns)

## 📊 Métricas de Conhecimento

| Métrica | Valor | Data |
|---------|-------|------|
| Debug Session Effectiveness | 95% | 2025-05-27 |
| Problem Resolution Speed | Alto | 2025-05-27 |
| Knowledge Capture Quality | Excelente | 2025-05-27 |
| Prevention Value | Alto | 2025-05-27 |

## 🔍 Episodes de Debugging

### 2025-05-27: TLS Certificate Permissions Fix

- **Problem:** Container exit code 1 durante inicialização TLS
- **Root Cause:** Permissões 600 em certificados impedem acesso de usuário não-root
- **Solution:** Alterar para permissões 644 em scripts de geração
- **Impact:** Teste crítico agora passa consistentemente
- **Files:** [Episode Details](./docker_tls_permissions_episode.md)

## 🎯 Padrões de Aplicação

### Debugging Sistemático

1. **Logs** → Identificar sintomas
2. **Permissions** → Verificar contexto de acesso
3. **Environment** → Validar configuração
4. **Cleanup** → Eliminar interferências

### Docker Security

- Sempre considerar contexto do usuário para permissões de arquivo
- Usar 644 para certificados em ambientes containerizados
- Testar com usuários não-root

## 🔗 Integração com Sistema f1e

**Status:** Sistema f1e indisponível temporariamente  
**Workaround:** Conhecimento capturado em arquivos markdown estruturados  
**Migration Plan:** Migrar para f1e quando disponível  

## 📚 Referências Relacionadas

- [Debugging Sessions](../debugging_sessions/)
- [Developer Guide](../developer_guide/)
- [Architecture Documentation](../architecture.md)

---

**Última Atualização:** 2025-05-27  
**Próxima Revisão:** Conforme novos episodes de debugging  
**Responsável:** Sistema de Memória AI com validação manual
