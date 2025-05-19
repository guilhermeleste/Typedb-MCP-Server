# Plano Definitivo de Testes para o Módulo de Configuração (`config.rs`)

Este plano visa garantir robustez, rastreabilidade e manutenção dos testes de configuração do Typedb-MCP-Server, cobrindo todos os cenários críticos e armadilhas conhecidas da crate `config` e Serde.

---

## 1. Isolamento de Ambiente

- [ ] Cada teste deve limpar e restaurar todas as variáveis de ambiente relevantes (`MCP_*`, `MCP_CONFIG_PATH`).
- [ ] Uso de arquivos TOML temporários para evitar poluição entre execuções.

## 2. Blocos Temáticos de Testes

### 2.1 Defaults

- [ ] Todos os campos recebem o valor default correto quando TOML/ENV estão ausentes.

### 2.2 Carregamento TOML

- [ ] Todos os campos são corretamente populados a partir de um arquivo TOML.

### 2.3 Carregamento ENV

- [ ] Todos os campos são corretamente populados a partir de variáveis de ambiente.

### 2.4 Merge TOML + ENV

- [ ] ENV sobrescreve TOML corretamente, inclusive arrays e objetos.

### 2.5 Arrays e Objetos

- [ ] Arrays e objetos são substituídos (não mesclados) quando definidos por ENV.

### 2.6 Campos Opcionais

- [ ] Testar ausência e presença de campos opcionais, inclusive arrays vazios.

### 2.7 Erros de Parsing

- [ ] Testar mensagens e rastreabilidade para:
  - Campos obrigatórios ausentes
  - Tipos errados
  - Arrays malformados

### 2.8 Mensagens de Erro

- [ ] Mensagens de erro devem ser claras e rastreáveis ao campo/fonte.

### 2.9 Round-trip

- [ ] Serializar, deserializar e comparar structs para garantir consistência.

---

## 3. Helpers e Utilitários

- [ ] Helpers para criar/limpar arquivos TOML temporários.
- [ ] Helpers para setar, limpar e restaurar variáveis de ambiente.
- [ ] Helpers para capturar e validar mensagens de erro.

---

## 4. Manutenção e Robustez

- [ ] Cada teste deve ser autocontido, claro e fácil de manter.
- [ ] Evitar dependência entre testes.
- [ ] Cobrir todos os caminhos críticos, inclusive negativos.

---

> Siga rigorosamente este plano para garantir qualidade, rastreabilidade e manutenção dos testes de configuração.
