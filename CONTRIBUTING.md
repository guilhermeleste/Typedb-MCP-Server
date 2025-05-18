# Como Contribuir para o Typedb-MCP-Server

Primeiramente, obrigado pelo seu interesse em contribuir para o Typedb-MCP-Server! Nós apreciamos sua ajuda e entusiasmo. Seja reportando bugs, sugerindo melhorias, escrevendo documentação ou contribuindo com código, sua participação é valiosa.

Este documento fornece diretrizes para contribuir com o projeto. Por favor, reserve um momento para revisá-lo.

## Código de Conduta

Este projeto e todos que participam dele são regidos pelo nosso [Código de Conduta](./CODE_OF_CONDUCT.md). Ao participar, espera-se que você siga este código. Por favor, relate comportamentos inaceitáveis conforme descrito no código de conduta.

## Como Você Pode Contribuir

Existem várias maneiras de contribuir:

* **Reportando Bugs:** Se você encontrar um bug, por favor, abra uma issue em nosso [rastreador de issues do GitHub](https://github.com/guilhermeleste/Typedb-MCP-Server/issues) (substitua pela URL correta se diferente).
* **Sugerindo Melhorias:** Tem uma ideia para uma nova funcionalidade ou uma melhoria em uma existente? Abra uma issue para discussão.
* **Escrevendo Documentação:** Uma boa documentação é crucial. Melhorias na documentação existente ou novas seções são sempre bem-vindas.
* **Contribuindo com Código:** Se você deseja corrigir um bug ou implementar uma nova funcionalidade, sinta-se à vontade para submeter um Pull Request.

## Primeiros Passos (Para Contribuições de Código)

1. **Faça um Fork** do repositório no GitHub.
2. **Clone** seu fork localmente: `git clone https://github.com/SEU_USUARIO/Typedb-MCP-Server.git`
3. **Crie um Branch** para suas alterações: `git checkout -b minha-nova-feature`
4. **Configure seu ambiente de desenvolvimento:**
    * Certifique-se de ter a versão correta do Rust instalada, conforme especificado no arquivo `rust-toolchain.toml`.
    * Instale as dependências de build com `cargo build`.
    * Para testes de integração que usam Docker, certifique-se de ter o Docker e Docker Compose instalados.

## Reportando Bugs

Antes de reportar um bug, por favor, verifique o [rastreador de issues](https://github.com/guilhermeleste/Typedb-MCP-Server/issues) para garantir que o bug ainda não foi reportado.

Ao reportar um bug, por favor, inclua:

* Uma descrição clara e concisa do bug.
* Passos para reproduzir o comportamento.
* O comportamento esperado.
* O comportamento real.
* Versão do Typedb-MCP-Server, versão do Rust, e seu sistema operacional.
* Logs relevantes ou mensagens de erro.

## Sugerindo Melhorias

Para sugerir uma melhoria:

* Abra uma issue detalhando sua sugestão.
* Explique por que a melhoria seria útil e para quais casos de uso.
* Se possível, forneça exemplos de como a funcionalidade poderia funcionar.

## Processo de Pull Request (PR)

1. **Escreva um bom código:**
    * Siga as diretrizes de estilo de código (veja abaixo).
    * Adicione testes unitários e/ou de integração para suas alterações.
    * Certifique-se de que todos os testes existentes passam (`cargo test --all-features`).
2. **Formate e Linte seu código:**
    * Execute `cargo fmt --all -- --check` para verificar a formatação.
    * Execute `cargo clippy --tests -- -W clippy::pedantic -W clippy::nursery -W clippy::cargo` para verificar lints e corrija quaisquer avisos ou erros.
3. **Documente suas alterações:**
    * Se suas alterações afetam o comportamento do usuário ou adicionam novas funcionalidades, atualize a documentação relevante (README.md, arquivos em `/docs`).
    * Comente seu código onde for necessário para clareza.
4. **Faça o Commit** de suas alterações com mensagens de commit claras e descritivas.
5. **Envie (Push)** seu branch para o seu fork no GitHub.
6. **Abra um Pull Request** para o branch `main` (ou o branch de desenvolvimento ativo) do repositório principal.
    * Forneça um título claro e uma descrição detalhada do seu PR.
    * Se o seu PR corrige uma issue existente, referencie a issue em sua descrição (ex: "Corrige #123").
7. **Participe da Revisão:**
    * Esteja preparado para discutir suas alterações e fazer modificações com base no feedback dos revisores.
    * Seja responsivo aos comentários.

## Diretrizes de Estilo de Código

* **Rust:** Siga as convenções padrão do Rust e o estilo imposto pelo `rustfmt`. Use o arquivo `rustfmt.toml` na raiz do projeto. Execute `cargo fmt` antes de commitar.
* **Clippy:** Adira aos lints configurados no `clippy.toml` e no `Cargo.toml`. Corrija todos os avisos do Clippy.
* **Comentários:** Escreva comentários claros e úteis onde o código não for autoexplicativo.
* **Testes:** Adicione testes para novas funcionalidades e correções de bugs.

## Configuração do Ambiente de Desenvolvimento

Consulte o [Guia do Desenvolvedor](/docs/developer_guide/02_development_setup.md) para informações detalhadas sobre como configurar seu ambiente de desenvolvimento, incluindo ferramentas, build e execução de testes.

## Licença

Ao contribuir, você concorda que suas contribuições serão licenciadas sob a [Licença MIT](./LICENSE) do projeto.

## Dúvidas?

Se você tiver alguma dúvida, sinta-se à vontade para abrir uma issue no GitHub.

Obrigado por contribuir!
