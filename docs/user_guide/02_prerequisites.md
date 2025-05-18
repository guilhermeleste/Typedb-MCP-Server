# Guia do Usuário: Pré-requisitos

Antes de prosseguir com a instalação e configuração do Typedb-MCP-Server, é importante garantir que você tenha o software e os conhecimentos necessários. Esta seção detalha os pré-requisitos para uma experiência tranquila.

## Requisitos de Software

### 1. Servidor TypeDB

* **Instância em Execução:** Você precisará de uma instância do TypeDB Server (versão 3.2.0 ou uma versão compatível) em execução e acessível pela máquina onde o Typedb-MCP-Server será executado.
* **Detalhes da Conexão:** Tenha em mãos o endereço (host e porta) do seu servidor TypeDB. Se a autenticação estiver habilitada no TypeDB (o que é recomendado para ambientes de produção), você também precisará das credenciais (username e password).
  * **Onde encontrar:** Consulte a documentação oficial do [TypeDB](https://typedb.com/docs/running-typedb/install-and-run) para instruções de instalação e execução.

### 2. Para Instalação a partir do Código-Fonte

Se você planeja compilar e executar o servidor a partir do código-fonte, precisará de:

* **Rust e Cargo:**
  * A versão mínima do Rust requerida está especificada no arquivo [`rust-toolchain.toml`](../../rust-toolchain.toml) na raiz do projeto (atualmente >= 1.87.0).
  * Recomendamos usar o `rustup` para gerenciar suas instalações do Rust. Se você não o tiver, instale-o a partir de [rustup.rs](https://rustup.rs/).
  * Com o `rustup` instalado, você pode facilmente instalar a toolchain correta navegando até o diretório do projeto e executando `rustup show`, ou permitindo que o `rustup` a instale automaticamente ao executar comandos do `cargo`.
* **Git:** Para clonar o repositório do projeto.
* **Dependências de Build:** Um compilador C e `make` (ou equivalentes) podem ser necessários para compilar algumas dependências do Rust. Na maioria dos sistemas Linux, eles podem ser instalados através do gerenciador de pacotes (ex: `build-essential` no Debian/Ubuntu).

### 3. Para Execução com Docker (Recomendado para muitos casos de uso)

Se você prefere executar o servidor usando contêineres:

* **Docker:** Uma instalação funcional do Docker. Visite [docker.com](https://www.docker.com/get-started) para instruções de instalação.
* **Docker Compose (Opcional, mas Recomendado):** Para orquestrar o Typedb-MCP-Server junto com uma instância do TypeDB e, opcionalmente, outros serviços (como um mock OAuth2 server para testes). Consulte a documentação do Docker para instalar o [Docker Compose](https://docs.docker.com/compose/install/).

### 4. Cliente MCP

Para interagir com o Typedb-MCP-Server, você precisará de uma aplicação cliente que implemente o Model Context Protocol. Isso pode ser:

* Um modelo de linguagem grande (LLM) configurado para usar um servidor MCP.
* Ferramentas de desenvolvimento como o [MCP Inspector](https://github.com/modelcontextprotocol/inspector) (via `npx @modelcontextprotocol/inspector`).
* Um cliente WebSocket genérico (como `wscat`) para testes básicos de conexão e envio de mensagens JSON-RPC.
* Sua própria aplicação customizada.

### 5. (Opcional) Para Configuração de TLS e OAuth2

* **mkcert (Para Desenvolvimento com TLS):** Se você planeja testar conexões TLS localmente e precisa gerar certificados de desenvolvimento autoassinados e uma CA local confiável, `mkcert` é uma ferramenta útil. Consulte `scripts/generate-dev-certs.sh` para um exemplo de uso.
* **Provedor OAuth2 (Para Produção):** Se for usar autenticação OAuth2 em produção, você precisará de um Authorization Server compatível com OpenID Connect que exponha um endpoint JWKS.
* **nginx ou similar (Para Mock OAuth2 em Desenvolvimento):** O script `scripts/run-mock-oauth2.sh` utiliza `nginx` dentro do Docker para servir um arquivo `mock_jwks.json`.

## Conhecimentos Recomendados

Embora não estritamente obrigatórios para uma configuração básica, os seguintes conhecimentos podem ser úteis:

* **TypeDB e TypeQL:** Familiaridade com os conceitos do TypeDB e a linguagem de consulta TypeQL ajudará a entender as operações que o servidor facilita.
* **Linha de Comando:** Conforto com operações básicas de linha de comando para compilação, execução e gerenciamento de contêineres.
* **WebSocket:** Entendimento básico de como funcionam as conexões WebSocket.
* **JSON e TOML:** O servidor usa TOML para configuração e JSON para comunicação MCP.
* **OAuth2 e JWT (Opcional):** Se você planeja usar o recurso de autenticação, um entendimento dos fluxos OAuth2 e da estrutura JWT será benéfico.
* **Docker (Opcional):** Se for usar contêineres, familiaridade com os conceitos básicos do Docker e Docker Compose.

## Próximos Passos

Com os pré-requisitos atendidos, você está pronto para prosseguir para a seção de [Instalação](./03_installation.md).
