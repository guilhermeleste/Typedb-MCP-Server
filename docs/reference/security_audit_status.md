# Status de Segurança das Dependências (cargo audit)

Este documento registra o status de segurança das dependências Rust do Typedb-MCP-Server, conforme reportado por `cargo audit`.

## Última verificação: 2025-05-23

### Vulnerabilidades Encontradas

- **Crate:** `rsa` 0.9.8  
  **ID:** [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071)  
  **Gravidade:** Média (5.9)  
  **Descrição:** Vulnerável ao ataque Marvin (sidechannel de timing).  
  **Solução:** Não há atualização disponível no momento.  
  **Ação:** Monitoramento contínuo. Documentado para rastreabilidade.

### Avisos de Manutenção

- **Crate:** `paste` 1.0.15  
  **ID:** [RUSTSEC-2024-0436](https://rustsec.org/advisories/RUSTSEC-2024-0436)  
  **Descrição:** Crate não é mais mantida.  
  **Impacto:** Dependência transitiva via `rmcp`/`netlink-packet-utils`.  
  **Ação:** Monitorar futuras atualizações e dependências alternativas.

---

## Procedimento Recomendado

- Revisar este status a cada release ou atualização de dependências.
- Não expor detalhes técnicos a clientes externos.
- Registrar ações de mitigação ou atualização quando disponíveis.
- Automatizar auditoria em CI/CD quando possível.

---

> Este arquivo é gerado e mantido conforme o padrão de segurança Typedb-MCP-Server.
