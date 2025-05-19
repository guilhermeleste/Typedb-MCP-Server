# Refatoração e Correção dos Testes de Integração

Data de Início: 19 de Maio de 2025

## 1. Contexto do Problema

Observou-se que os testes de integração do projeto `Typedb-MCP-Server` não estavam sendo executados corretamente ou estavam falhando de forma consistente. Uma investigação inicial apontou para deficiências na infraestrutura de suporte aos testes, especialmente em relação à geração e validação de tokens JWT, cruciais para simular cenários de autenticação e autorização.

O objetivo desta refatoração é restabelecer a confiabilidade e a cobertura dos testes de integração, garantindo que eles possam ser executados de forma robusta e fornecer feedback preciso sobre a saúde do sistema.

## 2. Investigação Inicial

A análise inicial focou nos seguintes pontos:

* **Execução dos Testes:** Confirmação de que os testes de integração não estavam sendo incluídos nas execuções de teste ou falhavam prematuramente.
* **Módulos Auxiliares de Teste:** Revisão dos módulos em `tests/common/`, como `auth_helpers.rs`, que são fundamentais para configurar o ambiente de teste.
* **Geração de Tokens:** Identificação de problemas na geração de tokens JWT para testes, incluindo o uso de algoritmos, chaves e claims.
* **Mock JWKS Server:** Necessidade de garantir que o servidor mock de JWKS (`mock_jwks.json` e o script `run-mock-oauth2.sh`) estivesse configurado corretamente e alinhado com os tokens gerados.

## 3. Trabalho Realizado no Módulo `tests/common/auth_helpers.rs`

O módulo `auth_helpers.rs` foi o primeiro a ser refatorado, dado seu papel central na geração de tokens de teste. As seguintes melhorias e correções foram implementadas:

* **Estrutura `TestClaims` Aprimorada:** A struct `TestClaims` foi revisada para ser mais flexível e completa, permitindo a inclusão de todos os claims necessários para os cenários de teste, como `sub`, `exp`, `iat`, `nbf`, `iss`, `aud`, `scope` e claims customizados. Campos opcionais agora usam `#[serde(skip_serializing_if = "Option::is_none")]`.
* **Key ID (`kid`) Explícito:** A constante `TEST_KID` foi definida e é explicitamente incluída no header dos tokens gerados. Este `kid` deve corresponder a uma chave conhecida pelo mock JWKS server.
* **Parametrização do Algoritmo de Assinatura:** A função `generate_test_jwt` agora aceita um parâmetro `alg: Algorithm`, permitindo a geração de tokens com diferentes algoritmos (inicialmente HS256 e RS256).
* **Chaves RSA de Placeholder:** Foram adicionadas constantes `TEST_RSA_PRIVATE_KEY_PEM` e `TEST_RSA_PUBLIC_KEY_PEM` com conteúdo de placeholder. Foi documentado explicitamente que estas chaves **DEVEM** ser substituídas por chaves PEM válidas e correspondentes para que os testes com RS256 funcionem. A ausência de chaves válidas causará pânico, conforme indicado pelos `expect()` no código.
* **Segredo HS256 Dedicado:** Um segredo específico (`test-secret-for-auth-helpers`) é usado para a assinatura e validação de tokens HS256 dentro deste módulo.
* **Testes Unitários em `auth_helpers.rs`:**
  * O teste `test_generate_and_decode_hs256_token` foi aprimorado para validar todos os claims e o `kid` do header.
  * A estrutura para o teste `test_generate_and_decode_rs256_token` foi criada, com um aviso claro de que ele falhará (ou causará pânico) até que as chaves RSA de placeholder sejam substituídas por chaves válidas.
* **Função `current_timestamp_secs`:** Mantida para obter o timestamp atual.
* **Documentação e Comentários:** O módulo foi extensivamente comentado para explicar a lógica, o propósito das chaves de teste e os próximos passos.

## 4. Plano de Aprimoramento para `auth_helpers.rs` (Conforme Documentado no Código)

O próprio arquivo `auth_helpers.rs` contém um "Plano de Aprimoramento Futuro" detalhado. Os pontos principais incluem:

1. **Fornecer Chaves RSA de Teste Válidas:** Substituir os placeholders por chaves RSA PEM reais e correspondentes, possivelmente carregadas de arquivos.
2. **Remover `#[should_panic]` do Teste RS256:** Após fornecer chaves válidas e o teste passar.
3. **Testes Adicionais para Casos de Erro na Validação:** Cobrir cenários como `kid` inválido, algoritmo incorreto, `iat`/`nbf` futuros, `aud`/`iss` inválidos.
4. **Carregamento de Chaves de Arquivos:** Considerar carregar chaves de arquivos `.pem` dedicados.
5. **Refinar Constantes de Teste:** Avaliar a configurabilidade de `TEST_KID`, issuers, etc.
6. **Helpers para Claims Comuns:** Criar funções para gerar `TestClaims` comuns (válido, expirado, com escopo específico).

## 5. Próximos Passos Gerais para os Testes de Integração

Com a base de `auth_helpers.rs` fortalecida, os próximos passos incluem:

1. **Revisão de Outros Helpers:** Analisar e refatorar outros módulos em `tests/common/` que possam estar desatualizados ou contribuindo para as falhas.
2. **Configuração do Mock JWKS Server:**
    * Verificar se o `mock_jwks.json` está correto e contém as chaves públicas (especialmente a pública RSA quando for adicionada) correspondentes aos `kid`s usados nos testes.
    * Garantir que o script `run-mock-oauth2.sh` inicie o servidor mock corretamente antes da suíte de testes de integração.
3. **Revisão e Correção dos Testes de Integração:**
    * Analisar os arquivos em `tests/behaviour/` e `tests/integration/`.
    * Atualizar os testes para usar os helpers refatorados (como `auth_helpers.rs`).
    * Corrigir a lógica de asserção e o setup de cada teste.
    * Garantir que os tokens gerados sejam válidos para os cenários que cada teste pretende cobrir.
4. **Execução no Pipeline de CI:**
    * Assegurar que todos os serviços necessários (como o mock JWKS server e o próprio Typedb) sejam iniciados corretamente no ambiente de CI.
    * Integrar a execução dos testes de integração ao pipeline de CI para que sejam executados automaticamente a cada mudança.
5. **Documentação:** Manter esta documentação atualizada conforme o progresso da refatoração.

Este esforço é crucial para aumentar a qualidade e a estabilidade do `Typedb-MCP-Server`, permitindo o desenvolvimento de novas funcionalidades com maior segurança e confiança.

## 6. Processo Detalhado de Refatoração por Arquivo de Teste

Esta seção descreve o processo iterativo a ser aplicado a cada arquivo de teste de integração, incluindo aqueles já parcialmente refatorados, para garantir conformidade, completude e robustez. O objetivo final é que cada arquivo de código de teste esteja completo, sem placeholders, pronto para uso e seguindo rigorosamente o padrão de código estabelecido para todo o projeto `Typedb-MCP-Server`.

### 6.1. Fases do Processo para Cada Arquivo

Para cada arquivo individualmente localizado em `tests/behaviour/`, `tests/integration/`, e também os módulos auxiliares em `tests/common/` (como `auth_helpers.rs`, `test_utils.rs`, etc.), o seguinte processo detalhado e iterativo deve ser obrigatoriamente seguido:

#### Fase 1: Análise e Planejamento Inicial

1. **Leitura Crítica e Compreensão Profunda do Código Existente:**
    * Analisar o propósito original e os cenários que o teste (ou helper) visa cobrir.
    * Identificar todas as funcionalidades do sistema que estão sendo exercitadas.
    * Mapear todas as dependências internas (outros helpers, módulos do `src/`) e externas (serviços mock, variáveis de ambiente, arquivos de configuração específicos para o teste).
2. **Identificação Exaustiva de Placeholders, TODOs e Dívidas Técnicas:**
    * Listar todos os placeholders (ex: chaves RSA de exemplo, segredos fixos que deveriam ser configuráveis ou carregados de forma segura, URLs mockadas, valores mágicos).
    * Catalogar todos os comentários como `// TODO:`, `// FIXME:`, `// HACK:`, `// XXX:`, ou qualquer outra indicação de trabalho incompleto ou subótimo.
    * Identificar qualquer código que utilize `unwrap()`, `expect()` de forma inadequada em contextos onde um erro deveria ser tratado ou propagado (mesmo em testes, o pânico deve ser intencional e documentado).
3. **Auditoria de Aderência ao "Padrão de Código Definitivo para Typedb-MCP-Server":**
    * Avaliar minuciosamente o código atual em relação a todos os aspectos do padrão de código do projeto.
    * Identificar e listar todos os desvios, incluindo, mas não se limitando a: formatação, convenções de nomeação (variáveis, funções, módulos, etc.), tratamento de erros, uso de `Result` e `Option`, clareza, concisão, e documentação (Rustdoc para todos os itens públicos).
4. **Elaboração de um Plano de Refatoração Detalhado e Acionável:**
    * Definir as estratégias e etapas específicas para remover cada placeholder identificado, substituindo-os por soluções robustas e configuráveis.
    * Planejar a implementação ou resolução de cada TODO e dívida técnica.
    * Esboçar as modificações necessárias para alinhar o código completamente com o padrão do projeto.
    * Identificar proativamente qualquer necessidade de pesquisa (ex: APIs de crates atualizadas, melhores práticas para mocks específicos, técnicas de asserção avançadas, configuração de serviços para testes).

#### Fase 2: Pesquisa Dirigida e Validação (Se Necessário)

1. **Execução de Pesquisas Focadas:**
    * Caso o plano de refatoração identifique lacunas de conhecimento ou a necessidade de validar abordagens, utilizar a ferramenta `vscode-websearchforcopilot_webSearch` para obter informações precisas de fontes oficiais (documentação de crates, `std` docs, RFCs, artigos de referência).
    * Formular queries específicas para a pesquisa (ex: "rust crate `jsonwebtoken` best practices for `kid` header", "generating temporary RSA keys for testing in rust", "axum test client custom headers").
    * Registrar os resultados da pesquisa internamente, seguindo o formato especificado nas instruções gerais (incluindo nome da crate, versão, links, features, APIs relevantes, tratamento de erros, notas de pânico/segurança e data).
2. **Análise Crítica e Integração dos Resultados da Pesquisa:**
    * Avaliar a aplicabilidade e confiabilidade das informações obtidas.
    * Integrar as descobertas e as melhores práticas identificadas diretamente no plano de refatoração, ajustando as estratégias conforme necessário.

#### Fase 3: Implementação Focada e Refatoração Disciplinada

1. **Implementação Sistemática das Mudanças Planejadas:**
    * Aplicar as refatorações de forma incremental e controlada, seguindo o plano.
    * Substituir todos os placeholders por implementações funcionais, seguras e, quando aplicável, configuráveis (ex: carregar chaves de arquivos dedicados, usar variáveis de ambiente para configuração de teste).
    * Implementar as soluções para os TODOs e corrigir as dívidas técnicas.
    * Corrigir todos os desvios do padrão de código, garantindo uniformidade.
2. **Desenvolvimento ou Atualização de Testes Unitários Robustos (especialmente para helpers em `tests/common/`):**
    * Para cada helper, garantir que existam testes unitários que cubram exaustivamente seus casos de uso normais, casos de borda e cenários de erro.
    * As asserções devem ser precisas e significativas.
3. **Documentação Exemplar (Rustdoc):**
    * Adicionar ou atualizar a documentação Rustdoc para todos os itens públicos (structs, enums, funções, módulos) dentro do arquivo de teste ou helper.
    * A documentação deve ser clara, concisa, explicar o propósito, os parâmetros (com seus tipos e significados), os valores de retorno, os possíveis erros (se `Result`), e incluir exemplos de uso práticos sempre que agregar valor.
    * Garantir que a documentação também siga o padrão de código.

#### Fase 4: Verificação Rigorosa, Correção e Validação Final

1. **Execução e Validação dos Testes:**
    * Executar todos os testes relevantes (unitários para helpers, e os próprios testes de integração que estão sendo refatorados).
    * Analisar falhas, depurar e corrigir até que todos os testes passem de forma consistente e pelas razões corretas.
    * Verificar se os testes cobrem os cenários pretendidos de forma eficaz.
2. **Análise Estática de Código e Correção de Lints:**
    * Executar o comando `cargo clippy --all-targets --all-features -- -D warnings` (ou o comando de linting configurado no projeto).
    * Analisar cada warning e erro reportado pelo `clippy`.
    * Corrigir todos os lints e warnings, a menos que haja uma justificativa explícita e documentada para uma exceção específica (o que deve ser raro).
3. **Revisão Manual Detalhada (Autocrítica):**
    * Realizar uma leitura crítica do código refatorado, como se fosse um revisor externo.
    * Verificar a clareza, legibilidade, manutenibilidade e segurança do código.
    * Confirmar que todos os requisitos da tarefa original de refatoração para aquele arquivo foram completamente atendidos.
    * Assegurar que não restam placeholders, TODOs não resolvidos (ou não formalmente adiados com um plano claro), ou desvios do padrão.
    * Validar que nenhuma funcionalidade foi inventada ou adicionada sem ser explicitamente solicitada ou derivada de uma pesquisa documentada.

#### Fase 5: Checklist de Conclusão por Arquivo

Antes de considerar a refatoração de um arquivo como "concluída" e pronta para integração, todos os itens a seguir devem ser verificados e marcados positivamente:

* [ ] **Fase 1: Análise e Planejamento Inicial:**
  * [ ] Código existente completamente compreendido e seu propósito original documentado internamente.
  * [ ] Todos os placeholders, TODOs, e dívidas técnicas foram identificados e catalogados.
  * [ ] Todos os desvios do padrão de código foram identificados.
  * [ ] Um plano de refatoração detalhado e acionável foi criado.
* [ ] **Fase 2: Pesquisa (se aplicável):**
  * [ ] Todas as pesquisas necessárias foram realizadas utilizando `vscode-websearchforcopilot_webSearch`.
  * [ ] Os resultados das pesquisas foram devidamente registrados e integrados ao plano.
* [ ] **Fase 3: Implementação e Refatoração:**
  * [ ] Todos os placeholders foram removidos e substituídos por código funcional, seguro e configurável.
  * [ ] Todos os TODOs e dívidas técnicas foram implementados/resolvidos ou formalmente adiados com justificativa e plano futuro.
  * [ ] O código está 100% aderente ao "Padrão de Código Definitivo para Typedb-MCP-Server" (formatação, nomeação, etc.).
  * [ ] O tratamento de `Result`s e `Option`s é explícito e correto; `unwrap()` ou `expect()` são usados apenas intencionalmente para pânicos em testes (e justificados) ou em situações irrecuperáveis validadas.
  * [ ] A documentação Rustdoc para todos os itens públicos está completa, clara, precisa e segue o padrão.
  * [ ] Testes unitários para helpers (se aplicável) são robustos e cobrem todos os cenários relevantes.
* [ ] **Fase 4: Verificação e Correção:**
  * [ ] Todos os testes relevantes passam consistentemente e validam os cenários corretos.
  * [ ] O comando `cargo clippy --all-targets --all-features -- -D warnings` não reporta warnings ou erros.
  * [ ] O código foi revisado manualmente (autocrítica) para clareza, segurança, manutenibilidade e aderência aos requisitos.
* [ ] **Estado Final do Arquivo:**
  * [ ] O arquivo é considerado completo, robusto e pronto para uso em produção (no contexto de testes).
  * [ ] Nenhuma funcionalidade, crate, feature de crate, ou importação foi introduzida sem ser explicitamente solicitada, definida nos arquivos do projeto, ou resultado direto e documentado das pesquisas obrigatórias.
  * [ ] O código é totalmente rastreável às instruções, ao plano de refatoração e às pesquisas realizadas.

### 6.2. Rastreamento do Progresso da Refatoração

Para acompanhar o progresso da refatoração em todos os arquivos de teste relevantes, a seguinte tabela será mantida e atualizada:

| Caminho do Arquivo                      | Status da Refatoração | Responsável | Data da Última Atualização | Observações / Próximos Passos Específicos                                 |
| :-------------------------------------- | :-------------------- | :---------- | :------------------------- | :------------------------------------------------------------------------- |
| `tests/common/auth_helpers.rs`          | Em Progresso          | AI/Dev      | 2025-05-19                 | Concluir Plano de Aprimoramento Futuro (chaves RSA, mais testes de erro) |
| `tests/common/test_utils.rs`            | A Iniciar             | AI/Dev      |                            | Aplicar processo completo da Seção 6.1                                     |
| `tests/common/mod.rs`                   | A Iniciar             | AI/Dev      |                            | Revisar e aplicar processo se necessário                                   |
| `tests/behaviour/main_endpoints.rs`     | A Iniciar             | AI/Dev      |                            | Aplicar processo completo da Seção 6.1                                     |
| `tests/behaviour/mod.rs`                | A Iniciar             | AI/Dev      |                            | Revisar e aplicar processo se necessário                                   |
| `tests/integration/main_flow_tests.rs`  | A Iniciar             | AI/Dev      |                            | Aplicar processo completo da Seção 6.1                                     |
| `tests/integration/auth_tests.rs`       | A Iniciar             | AI/Dev      |                            | Aplicar processo completo da Seção 6.1                                     |
| `tests/integration/config_tests.rs`     | A Iniciar             | AI/Dev      |                            | Aplicar processo completo da Seção 6.1                                     |
| `tests/integration/mod.rs`              | A Iniciar             | AI/Dev      |                            | Revisar e aplicar processo se necessário                                   |
| *(Adicionar outros arquivos conforme necessário)* |                       |             |                            |                                                                            |

Este processo estruturado e o checklist detalhado visam garantir que cada componente dos testes de integração seja elevado a um alto padrão de qualidade, contribuindo para a robustez geral do `Typedb-MCP-Server`.
