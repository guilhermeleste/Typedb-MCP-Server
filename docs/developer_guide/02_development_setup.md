# Guia do Desenvolvedor: Configuração do Ambiente de Desenvolvimento

Para contribuir com o desenvolvimento do Typedb-MCP-Server ou simplesmente para compilar e executar o projeto localmente a partir do código-fonte, incluindo a execução de sua suíte de testes completa, você precisará configurar seu ambiente de desenvolvimento. Siga os passos abaixo.

## 1. Instalar o Rust

O Typedb-MCP-Server é escrito em Rust. A maneira recomendada de instalar e gerenciar as versões do Rust é através do `rustup`.

* **Instale o `rustup`:** Se você ainda não tem o `rustup` instalado, siga as instruções em [rustup.rs](https://rustup.rs/).
* **Versão do Rust:** O projeto especifica a versão exata da toolchain Rust a ser usada no arquivo [`rust-toolchain.toml`](../../rust-toolchain.toml) na raiz do repositório. Ao entrar no diretório do projeto, o `rustup` geralmente detectará este arquivo e oferecerá para instalar ou usar a toolchain especificada.
  * Você pode verificar sua toolchain ativa com `rustup show`.
  * O arquivo `rust-toolchain.toml` também especifica os componentes `rustfmt` (para formatação) e `clippy` (para linting), que são essenciais. O `rustup` deve instalá-los automaticamente com a toolchain.

## 2. Clonar o Repositório

Obtenha o código-fonte clonando o repositório oficial:

```bash
git clone https://github.com/guilhermeleste/Typedb-MCP-Server.git
cd Typedb-MCP-Server
```

## 3. Ferramentas de Build e Dependências do Sistema

* **Cargo:** O gerenciador de pacotes e sistema de build do Rust, instalado automaticamente com o `rustup`.
* **Compilador C e `make`:** Algumas dependências do Rust podem ser crates que envolvem código C/C++ e podem precisar de um compilador C (como GCC ou Clang) e `make` para serem construídas.
  * **Linux (Debian/Ubuntu):** `sudo apt update && sudo apt install build-essential`
  * **Linux (Fedora):** `sudo dnf groupinstall "Development Tools"`
  * **macOS:** As Ferramentas de Linha de Comando do Xcode geralmente fornecem o necessário (`xcode-select --install`).
  * **Windows:** É recomendado usar o toolchain MSVC do Rust, que requer o "Build Tools for Visual Studio". Consulte a [documentação do Rust para Windows](https://forge.rust-lang.org/infra/other-installation-methods.html#windows).

## 4. Docker e Docker Compose (Essencial para Testes de Integração)

A suíte de testes de integração do Typedb-MCP-Server depende **criticamente** do Docker e Docker Compose para orquestrar os serviços necessários (o próprio servidor MCP, instâncias do TypeDB para teste e um mock de servidor OAuth2).

* **Instale o Docker:** Siga as instruções em [docker.com/get-started](https://www.docker.com/get-started). Certifique-se de que o daemon Docker esteja em execução.
* **Instale o Docker Compose:**
  * **Docker Desktop:** Se você instalou o Docker Desktop (Windows, macOS, Linux), ele geralmente já inclui o Docker Compose (CLI V2, acessível via `docker compose`).
  * **Linux (Standalone):** Se você instalou o Docker Engine separadamente no Linux, siga as instruções em [docs.docker.com/compose/install/](https://docs.docker.com/compose/install/) para instalar o plugin do Compose.
  * Verifique sua instalação com `docker compose version`.

## 5. `mkcert` (Para Geração de Certificados TLS de Teste)

Para testar cenários que envolvem TLS, como HTTPS para o servidor MCP ou conexões TLS com o TypeDB, usamos certificados autoassinados gerados com `mkcert`. Esta ferramenta cria uma autoridade de certificação (CA) local que é confiável pelo seu sistema e navegadores.

* **Instale `mkcert`:**
  * Siga as instruções de instalação para o seu sistema operacional em [mkcert.dev/#installation](https://mkcert.dev/#installation) ou no [README do mkcert no GitHub](https://github.com/FiloSottile/mkcert).
  * **Importante:** Após instalar o `mkcert`, execute o seguinte comando **uma vez** para instalar a CA local do `mkcert` nos seus repositórios de confiança do sistema (pode exigir privilégios de administrador/sudo):

    ```bash
    mkcert -install
    ```

* **Gere os Certificados de Teste:** O projeto inclui um script para automatizar a geração dos certificados necessários para os testes:

    ```bash
    ./scripts/generate-test-certs.sh --force
    ```

    Este script usará `mkcert` para criar os certificados no diretório `tests/test_certs/`. A flag `--force` garante que os certificados sejam recriados se já existirem.

## 6. Configuração de Variáveis de Ambiente para Testes

* **`TYPEDB_PASSWORD_TEST`**: Os testes de integração que interagem com o TypeDB esperam que as instâncias de teste do TypeDB (controladas pelo `docker-compose.test.yml`) usem uma senha.
  * O `docker-compose.test.yml` usa a variável de ambiente `TYPEDB_PASSWORD_TEST` para configurar a senha do TypeDB e para passar essa senha para o `typedb-mcp-server-it`.
  * Por padrão, se `TYPEDB_PASSWORD_TEST` não estiver definida, o valor `"password"` será usado.
  * Você pode definir esta variável no seu ambiente se desejar usar uma senha diferente para os testes:

    ```bash
        export TYPEDB_PASSWORD_TEST="sua_senha_de_teste_para_typedb"
        ```

        Consulte o arquivo [`.env.example`](../../.env.example) para mais detalhes sobre esta e outras variáveis.

## 7. Comandos Úteis de Desenvolvimento

Uma vez que seu ambiente esteja configurado, aqui estão alguns comandos `cargo` que você usará frequentemente:

* **Verificar o Código (sem compilar binários):**

    ```bash
    cargo check --all-targets --all-features
    ```

* **Compilar para Desenvolvimento (debug build):**

    ```bash
    cargo build
    ```

    O binário estará em `target/debug/typedb_mcp_server`.

* **Compilar para Release (otimizado):**

    ```bash
    cargo build --release
    ```

    O binário estará em `target/release/typedb_mcp_server`.

* **Executar o Servidor (debug build, para desenvolvimento interativo):**

    ```bash
    # Certifique-se de que TYPEDB_PASSWORD esteja definida se seu TypeDB de dev a requer.
    # Este comando usa a configuração de config.dev.toml e docker-compose.yml.
    cargo run
    ```

* **Executar todos os Testes (Unitários e de Integração):**
  * **Pré-requisitos:** Docker e Docker Compose devem estar em execução. O script `scripts/generate-test-certs.sh` deve ter sido executado.
  * Comando:

    ```bash
        cargo test --all-features --all-targets
        ```

  * Para ver a saída dos testes (útil para depuração):

    ```bash
        cargo test --all-features --all-targets -- --nocapture
        ```

  * **Nota:** Os testes de integração são marcados com `#[serial_test::serial]` e iniciarão seus próprios ambientes Docker Compose. Consulte a [Estratégia de Testes](./08_testing_strategy.md) para mais detalhes.

* **Formatar o Código:**
    O projeto usa `rustfmt` com configurações definidas em [`rustfmt.toml`](../../rustfmt.toml).

    ```bash
    cargo fmt --all
    ```

    Para verificar se o código está formatado (útil em CI):

    ```bash
    cargo fmt --all -- --check
    ```

* **Linting com Clippy:**
    O projeto usa `clippy` com configurações definidas em [`clippy.toml`](../../clippy.toml) e no [`Cargo.toml`](../../Cargo.toml).

    ```bash
    cargo clippy --all-targets --all-features -- -D warnings
    ```

    Isto tratará todos os avisos do Clippy como erros.

* **Limpar Artefatos de Build:**

    ```bash
    cargo clean
    ```

* **Gerar Documentação Localmente:**

    ```bash
    cargo doc --open --no-deps
    ```

## Editor e IDE

* **Rust Analyzer:** Recomenda-se o uso do [rust-analyzer](https://rust-analyzer.github.io/) para a maioria dos editores (VS Code, Neovim, etc.) para autocompletar, análise de código em tempo real e outras funcionalidades.
* **Formatação ao Salvar:** Configure seu editor para usar `rustfmt` para formatação automática ao salvar.
* **`.editorconfig`**: O arquivo [`.editorconfig`](../../.editorconfig) incluído no projeto ajuda a manter a consistência de formatação básica entre diferentes editores.

## Próximos Passos

Com seu ambiente de desenvolvimento configurado, você está pronto para:

* Explorar a [Arquitetura Detalhada](./03_architecture_deep_dive.md).
* Entender a [Estrutura do Código](./04_code_structure.md).
* Aprender sobre a [Estratégia de Testes](./08_testing_strategy.md) em mais detalhes.
