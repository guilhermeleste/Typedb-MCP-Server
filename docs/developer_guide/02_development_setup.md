
# Guia do Desenvolvedor: Configuração do Ambiente de Desenvolvimento

Para contribuir com o desenvolvimento do Typedb-MCP-Server ou simplesmente para compilar e executar o projeto localmente a partir do código-fonte, você precisará configurar seu ambiente de desenvolvimento. Siga os passos abaixo.

## 1. Instalar o Rust

O Typedb-MCP-Server é escrito em Rust. A maneira recomendada de instalar e gerenciar as versões do Rust é através do `rustup`.

* **Instale o `rustup`:** Se você ainda não tem o `rustup` instalado, siga as instruções em [rustup.rs](https://rustup.rs/).
* **Versão do Rust:** O projeto especifica a versão exata da toolchain Rust a ser usada no arquivo [`rust-toolchain.toml`](../../rust-toolchain.toml) na raiz do repositório. Ao entrar no diretório do projeto, o `rustup` geralmente detectará este arquivo e oferecerá para instalar ou usar a toolchain especificada.
  * Você pode verificar sua toolchain ativa com `rustup show`.
  * Se necessário, você pode instalar manualmente a toolchain listada no arquivo:

        # Exemplo, verifique o rust-toolchain.toml para a versão exata
        rustup toolchain install $(grep "channel" rust-toolchain.toml | cut -d '"' -f 2)
        rustup component add rustfmt clippy --toolchain $(grep "channel" rust-toolchain.toml | cut -d '"' -f 2)

        O `rust-toolchain.toml` também especifica os componentes `rustfmt` e `clippy` que são essenciais para formatação e linting.

## 2. Clonar o Repositório

Obtenha o código-fonte clonando o repositório oficial:

Obtenha o código-fonte clonando o repositório oficial:

    git clone https://github.com/guilhermeleste/Typedb-MCP-Server.git
    cd Typedb-MCP-Server
    
    ## 3. Ferramentas de Build e Dependências do Sistema
    
        git clone https://github.com/guilhermeleste/Typedb-MCP-Server.git
        cd Typedb-MCP-Server
    
    ## 3. Ferramentas de Build e Dependências do Sistema
    
        git clone <https://github.com/guilhermeleste/Typedb-MCP-Server.git>
        cd Typedb-MCP-Server
    
    ## 3. Ferramentas de Build e Dependências do Sistema

## 3. Ferramentas de Build e Dependências do Sistema

git clone <https://github.com/guilhermeleste/Typedb-MCP-Server.git>
cd Typedb-MCP-Server

```

## 3. Ferramentas de Build e Dependências do Sistema

* **Cargo:** O gerenciador de pacotes e sistema de build do Rust, instalado automaticamente com o `rustup`.
* **Compilador C e `make`:** Algumas dependências do Rust podem ser crates que envolvem código C/C++ e podem precisar de um compilador C (como GCC ou Clang) e `make` para serem construídas.
  * **Linux (Debian/Ubuntu):** `sudo apt update && sudo apt install build-essential`
  * **Linux (Fedora):** `sudo dnf groupinstall "Development Tools"`
  * **macOS:** As Ferramentas de Linha de Comando do Xcode geralmente fornecem o necessário (`xcode-select --install`).
  * **Windows:** É recomendado usar o toolchain MSVC do Rust, que requer o "Build Tools for Visual Studio". Consulte a [documentação do Rust para Windows](https://forge.rust-lang.org/infra/other-installation-methods.html#windows).

## 4. Docker e Docker Compose (Recomendado para Testes de Integração)

Muitos dos testes de integração dependem do Docker e Docker Compose para orquestrar o Typedb-MCP-Server, uma instância do TypeDB para testes e, opcionalmente, um mock de servidor OAuth2.

* **Instale o Docker:** Siga as instruções em [docker.com/get-started](https://www.docker.com/get-started).
* **Instale o Docker Compose:** Siga as instruções em [docs.docker.com/compose/install/](https://docs.docker.com/compose/install/).
    (Nota: Docker Desktop para Windows e macOS geralmente já inclui Docker Compose).

## 5. `mkcert` (Para Desenvolvimento com TLS)

* **Gere Certificados de Desenvolvimento:** O projeto inclui um script para facilitar isso:

        ./scripts/generate-dev-certs.sh

    Este script criará os certificados necessários na pasta `certs/generated-dev/`. Consulte o script para mais opções, como especificar hosts customizados.
    ```

    Este script criará os certificados necessários na pasta `certs/generated-dev/`. Consulte o script para mais opções, como especificar hosts customizados.
  * Após a primeira execução, o `mkcert` pode pedir sua senha para instalar a CA local no seu trust store do sistema.

## 6. Comandos Úteis de Desenvolvimento

Uma vez que seu ambiente esteja configurado, aqui estão alguns comandos `cargo` que você usará frequentemente:
* **Verificar o Código (sem compilar binários):**

        cargo check

* **Compilar para Desenvolvimento (debug build):**
* **Compilar para Desenvolvimento (debug build):**

    ```bash
    cargo build
    ```

    O binário estará em `target/debug/typedb_mcp_server`.

* **Compilar para Release (otimizado):**
* **Compilar para Release (otimizado):**

        cargo build --release

    O binário estará em `target/release/typedb_mcp_server`.
* **Executar o Servidor (debug build):**

    ```bash
* **Executar o Servidor (debug build):**

        # Não esqueça de exportar TYPEDB_PASSWORD se necessário
        cargo run

* **Executar o Servidor (release build):**
    cargo run --release
    ```

* **Executar todos os Testes:**

    ```bash
    cargo test --all-features
    ```
* **Executar todos os Testes:**

        cargo test --all-features

  * Alguns testes de integração podem exigir que o Docker esteja em execução para iniciar serviços dependentes (como TypeDB).
    cargo fmt --all
    ```

* **Formatar o Código:**
    O projeto usa `rustfmt` com configurações definidas em [`rustfmt.toml`](../../rustfmt.toml).

        cargo fmt --all

    Para verificar se o código está formatado (útil em CI):

    ```bash
    cargo clippy --tests -- -D warnings
    ```

    Para uma análise mais rigorosa, similar à usada em CI:

    ```bash
    O projeto usa `clippy` com configurações definidas em [`clippy.toml`](../../clippy.toml) e no [`Cargo.toml`](../../Cargo.toml).

        cargo clippy --tests -- -D warnings

    Para uma análise mais rigorosa, similar à usada em CI:
    ```

* **Limpar Artefatos de Build:**

    ```bash
    cargo clean
    ```
* **Gerar Documentação Localmente:**

        cargo doc --open --no-deps

* **Limpar Artefatos de Build:**

Certifique-se de que seu editor esteja configurado para usar `rustfmt` para formatação (idealmente ao salvar) e para exibir diagnósticos do `clippy`. O arquivo [`.editorconfig`](../../.editorconfig) incluído no projeto ajuda a manter a consistência de formatação básica entre diferentes editores.

## Próximos Passos

Com seu ambiente de desenvolvimento configurado, você está pronto para explorar a [Arquitetura Detalhada](./03_architecture_deep_dive.md) e a [Estrutura do Código](./04_code_structure.md).
