# Como Contribuir para o Typedb-MCP-Server

Primeiramente, obrigado pelo seu interesse em contribuir para o Typedb-MCP-Server! Nós apreciamos sua ajuda e entusiasmo. Seja reportando bugs, sugerindo melhorias, escrevendo documentação ou contribuindo com código, sua participação é valiosa.

Este documento fornece diretrizes para contribuir com o projeto. Por favor, reserve um momento para revisá-lo.

## Código de Conduta

Este projeto e todos que participam dele são regidos pelo nosso [Código de Conduta](./CODE_OF_CONDUCT.md). Ao participar, espera-se que você siga este código. Por favor, relate comportamentos inadequados conforme descrito no código de conduta.

## Como Você Pode Contribuir

Existem várias maneiras de contribuir:

* **Reportando Bugs:** Se você encontrar um bug, por favor, abra uma issue em nosso [rastreador de issues do GitHub](https://github.com/guilhermeleste/Typedb-MCP-Server/issues).
* **Sugerindo Melhorias:** Tem uma ideia para uma nova funcionalidade ou uma melhoria em uma existente? Abra uma issue para discussão.
* **Escrevendo Documentação:** Uma boa documentação é crucial. Melhorias na documentação existente ou novas seções são sempre bem-vindas.
* **Contribuindo com Código:** Se você deseja corrigir um bug ou implementar uma nova funcionalidade, sinta-se à vontade para submeter um Pull Request.

## Primeiros Passos (Para Contribuições de Código)

1. **Faça um Fork** do repositório no GitHub.
2. **Clone** seu fork localmente: `git clone https://github.com/SEU_USUARIO/Typedb-MCP-Server.git` (substitua `SEU_USUARIO` pelo seu nome de usuário).
3. **Crie um Branch** para suas alterações: `git checkout -b minha-nova-feature` (use nomes de branch descritivos, ex: `fix/erro-conexao-tls` ou `feat/adicionar-ferramenta-xyz`).
4. **Configure seu ambiente de desenvolvimento:**
    * Consulte o [Guia de Configuração do Ambiente de Desenvolvimento](./docs/developer_guide/02_development_setup.md) para instruções detalhadas. Os principais requisitos incluem:
        * A versão correta do Rust (conforme `rust-toolchain.toml`).
        * Docker e Docker Compose (essenciais para rodar os testes de integração).
        * `mkcert` para gerar certificados TLS de teste (e ter executado `mkcert -install` uma vez).
    * Compile o projeto para baixar dependências: `cargo build --all-features`.

## Reportando Bugs

Antes de reportar um bug, por favor, verifique o [rastreador de issues](https://github.com/guilhermeleste/Typedb-MCP-Server/issues) para garantir que o bug ainda não foi reportado.

Ao reportar um bug, por favor, inclua:

* Uma descrição clara e concisa do bug.
* Passos para reproduzir o comportamento.
* O comportamento esperado.
* O comportamento real.
* Versão do Typedb-MCP-Server (do `Cargo.toml` ou commit hash), versão do Rust, e seu sistema operacional.
* Logs relevantes do servidor (idealmente com `RUST_LOG` configurado para `trace` ou `debug` para os módulos relevantes) e do cliente, se aplicável.
* Configurações relevantes (arquivos TOML, variáveis de ambiente).

## Sugerindo Melhorias

Para sugerir uma melhoria:

* Abra uma issue detalhando sua sugestão.
* Explique por que a melhoria seria útil e para quais casos de uso.
* Se possível, forneça exemplos de como a funcionalidade poderia funcionar ou ser usada.

## Processo de Pull Request (PR)

1. **Escreva um bom código:**
    * Siga as diretrizes de estilo de código (veja abaixo).
    * Adicione testes unitários e/ou de integração para suas alterações. Testes são cruciais!
    * Certifique-se de que todos os testes existentes passam: `cargo test --all-features --all-targets`.
        * Lembre-se que os testes de integração (`--test integration`) requerem Docker e Docker Compose.
2. **Formate e Linte seu código:**
    * Execute `cargo fmt --all` para formatar o código.
    * Execute `cargo clippy --all-targets --all-features -- -D warnings` para verificar lints e corrija quaisquer avisos ou erros.
3. **Documente suas alterações:**
    * Se suas alterações afetam o comportamento do usuário, adicionam novas funcionalidades ou modificam APIs, atualize a documentação relevante (arquivos em `/docs`, READMEs).
    * Adicione comentários Rustdoc (`///`) para todos os itens públicos (funções, structs, enums, traits, módulos).
    * Comente seu código onde for necessário para clareza da lógica interna.
4. **Faça o Commit** de suas alterações com mensagens de commit claras e descritivas, seguindo o padrão [Conventional Commits](https://www.conventionalcommits.org/) (ex: `fix: corrige panic ao lidar com schema vazio`, `feat: adiciona suporte para a ferramenta 'nova_ferramenta'`).
5. **Faça o Rebase** do seu branch com o branch `main` (ou o branch de desenvolvimento ativo) do repositório principal antes de submeter o PR, para garantir que suas alterações estejam sincronizadas e para resolver quaisquer conflitos localmente.

    ```bash
    git fetch upstream # Assumindo que 'upstream' é o remote do repositório principal
    git rebase upstream/main
    ```

6. **Envie (Push)** seu branch para o seu fork no GitHub.
7. **Abra um Pull Request** para o branch `main` (ou o branch de desenvolvimento ativo) do repositório principal.
    * Forneça um título claro e uma descrição detalhada do seu PR.
    * Se o seu PR corrige uma issue existente, referencie a issue em sua descrição (ex: "Corrige #123").
    * Explique as mudanças feitas e por quê.
8. **Participe da Revisão:**
    * Esteja preparado para discutir suas alterações e fazer modificações com base no feedback dos revisores.
    * Seja responsivo aos comentários e mantenha uma comunicação clara.
    * O pipeline de CI deve passar para que seu PR seja considerado para merge.

## Diretrizes de Estilo de Código

* **Rust:** Siga as convenções padrão do Rust e o estilo imposto pelo `rustfmt`. Use o arquivo [`rustfmt.toml`](./rustfmt.toml) na raiz do projeto. Execute `cargo fmt --all` antes de commitar.
* **Clippy:** Adira aos lints configurados no [`clippy.toml`](./clippy.toml) e no [`Cargo.toml`](./Cargo.toml). Corrija todos os avisos do Clippy (`cargo clippy --all-targets --all-features -- -D warnings`).
* **Comentários:** Escreva comentários claros e úteis onde o código não for autoexplicativo. Use Rustdoc para documentar a API pública.
* **Testes:** Adicione testes para novas funcionalidades e correções de bugs. Consulte a [Estratégia de Testes](./docs/developer_guide/08_testing_strategy.md) para mais detalhes sobre como escrever e executar testes.

## Configuração do Ambiente de Desenvolvimento

Consulte o [Guia de Configuração do Ambiente de Desenvolvimento](./docs/developer_guide/02_development_setup.md) para informações detalhadas sobre como configurar seu ambiente, incluindo ferramentas, build e execução de testes.

## Licença

Ao contribuir, você concorda que suas contribuições serão licenciadas sob a [Licença MIT](./LICENSE) do projeto.

## Dúvidas?

Se você tiver alguma dúvida sobre como contribuir, sinta-se à vontade para abrir uma issue no GitHub para discussão.

Obrigado por contribuir para o Typedb-MCP-Server!
