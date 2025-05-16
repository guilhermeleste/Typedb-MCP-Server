# Typedb-MCP-Server

Servidor Rust de alta performance, seguro e extensível, atuando como gateway MCP (Model Context Protocol) para o banco de dados TypeDB. Expõe endpoints WebSocket (MCP), HTTP REST para métricas Prometheus, integra autenticação OAuth2, tracing distribuído (OpenTelemetry) e métricas detalhadas.

---

## Índice

- [Typedb-MCP-Server](#typedb-mcp-server)
	- [Índice](#índice)
	- [Visão Geral](#visão-geral)
	- [Requisitos](#requisitos)
	- [Instalação](#instalação)
	- [Configuração](#configuração)
	- [Execução](#execução)
	- [Endpoints](#endpoints)
	- [Segurança](#segurança)
	- [Métricas e Observabilidade](#métricas-e-observabilidade)
	- [Extensibilidade](#extensibilidade)
	- [Estrutura de Pastas](#estrutura-de-pastas)
	- [Arquitetura Detalhada](#arquitetura-detalhada)

---

## Visão Geral

O Typedb-MCP-Server é um gateway MCP para TypeDB, implementado em Rust, com foco em:

- Segurança (TLS, OAuth2/JWT, controle de escopos)
- Performance (Tokio, Axum, WebSocket)
- Observabilidade (Prometheus, OpenTelemetry)
- Extensibilidade modular (ferramentas MCP)

## Requisitos

- **Rust** >= 1.86.0
- **TypeDB** (servidor externo)
- **Tokio** (runtime assíncrono)
- **Axum** (framework web)
- **Ferramentas auxiliares:**
  - [cargo](https://doc.rust-lang.org/cargo/)
  - [TypeDB Client/Server](https://typedb.com/)

## Instalação

Clone o repositório e instale as dependências:

```sh
# Clone o projeto
$ git clone https://github.com/guilhermeleste/Typedb-MCP-Server.git
$ cd Typedb-MCP-Server

# Compile em release
$ cargo build --release
```

## Configuração

A configuração é feita via arquivo TOML (`typedb_mcp_server_config.toml`) e/ou variáveis de ambiente prefixadas com `MCP_`.

Exemplo de configuração:

```toml
[typedb]
address = "localhost:1729"
username = "admin"
tls_enabled = false
# tls_ca_path = "/path/to/ca.pem"

[server]
bind_address = "0.0.0.0:8787"
tls_enabled = false
# tls_cert_path = ""
# tls_key_path = ""
metrics_bind_address = "0.0.0.0:9090"

[oauth]
enabled = false
# jwks_uri = "https://auth-server/.well-known/jwks.json"
# issuer = ["https://auth-server"]
# audience = ["typedb-mcp-server"]
```

> **Nota:** A senha do TypeDB deve ser fornecida via variável de ambiente `TYPEDB_PASSWORD`.

Veja exemplos completos em [`typedb_mcp_server_config.toml`](typedb_mcp_server_config.toml) e [`config.example.toml`](config.example.toml).

## Execução

```sh
# Exemplo: executando com configuração padrão
$ export TYPEDB_PASSWORD="<senha>"
$ cargo run --release
```

- Use `MCP_CONFIG_PATH` para customizar o caminho do arquivo de configuração.
- Variáveis de ambiente sobrescrevem o arquivo TOML.

## Endpoints

- **WebSocket MCP:**
  - Default: `ws://<host>:8787/mcp` (ou `wss://` se TLS ativado)
- **Métricas Prometheus:**
  - Default: `http://<host>:9090/metrics`
- **Healthchecks:**
  - `/livez`, `/readyz`

## Segurança

- TLS obrigatório em produção (via Rustls)
- Autenticação OAuth2/JWT opcional, recomendada
- Controle de escopos por ferramenta MCP
- Configuração sensível nunca persistida em arquivos versionados

## Métricas e Observabilidade

- **Prometheus:** métricas detalhadas expostas em `/metrics`
- **OpenTelemetry:** tracing distribuído (OTLP)
- **Logging:** configurável via `RUST_LOG` ou arquivo de configuração

## Extensibilidade

- Novas ferramentas MCP podem ser adicionadas em `src/tools/` e registradas no `McpServiceHandler`
- Configuração modular e validada

## Estrutura de Pastas

```sh
├── src/
│   ├── main.rs              # Binário principal
│   ├── lib.rs               # Biblioteca central
│   ├── config.rs            # Configuração
│   ├── db.rs                # Integração TypeDB
│   ├── error.rs             # Tipos de erro
│   ├── mcp_service_handler.rs # Handler MCP
│   ├── auth.rs              # OAuth2/JWT
│   ├── metrics.rs           # Métricas Prometheus
│   ├── telemetry.rs         # Tracing OpenTelemetry
│   ├── resources.rs         # Recursos MCP
│   ├── transport.rs         # Transporte WebSocket
│   └── tools/               # Ferramentas MCP (query, schema_ops, db_admin, ...)
├── tests/                   # Testes de integração
├── certs/                   # Certificados TLS (não versionados)
├── scripts/                 # Scripts auxiliares
├── docs/                    # Documentação (inclui architecture.md)
├── typedb_mcp_server_config.toml # Exemplo de configuração
├── config.example.toml      # Exemplo alternativo
├── .gitignore
├── Cargo.toml
└── README.md
```

## Arquitetura Detalhada

Veja [docs/architecture.md](docs/architecture.md) para um diagrama de alto nível, fluxo de inicialização e explicação dos módulos.

---

> Gerado automaticamente a partir do código-fonte em 16/05/2025. Para detalhes de implementação, consulte os módulos e a documentação interna.
