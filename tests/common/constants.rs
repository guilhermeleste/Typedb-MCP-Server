// MIT License
//
// Copyright (c) 2025 Guilherme Leste
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//! Constantes Globais para Testes de Integração do Typedb-MCP-Server.
//!
//! Este módulo centraliza valores fixos usados em múltiplos arquivos de teste,
//! como nomes de serviços Docker, portas de host e internas, nomes de
//! arquivos de configuração e caminhos de endpoint, para garantir consistência
//! e facilitar a manutenção.

use std::time::Duration;

// === Nomes de Serviços Docker ===

/// Nome do serviço Docker para o Typedb-MCP-Server nos testes de integração.
pub const MCP_SERVER_SERVICE_NAME: &str = "typedb-mcp-server-it";
/// Nome do serviço Docker para a instância padrão do TypeDB Server (sem TLS).
pub const TYPEDB_SERVICE_NAME: &str = "typedb-server-it";
/// Nome do serviço Docker para a instância do TypeDB Server com TLS habilitado.
pub const TYPEDB_TLS_SERVICE_NAME: &str = "typedb-server-tls-it";
/// Nome do serviço Docker para o Mock OAuth2/JWKS Server.
pub const MOCK_OAUTH_SERVICE_NAME: &str = "mock-oauth2-server";
/// Nome do serviço Docker para o Vault usado nos testes.
pub const VAULT_SERVICE_NAME: &str = "vault";

// === Portas Internas dos Contêineres ===
// Estas são as portas que os serviços escutam DENTRO de seus respectivos contêineres Docker.

/// Porta HTTP/WS INTERNA do contêiner para o Typedb-MCP-Server.
pub const MCP_SERVER_INTERNAL_HTTP_PORT: u16 = 8787;
/// Porta HTTPS/WSS INTERNA do contêiner para o Typedb-MCP-Server.
pub const MCP_SERVER_INTERNAL_HTTPS_PORT: u16 = 8443;
/// Porta INTERNA do contêiner para o endpoint de métricas do Typedb-MCP-Server.
pub const MCP_SERVER_INTERNAL_METRICS_PORT: u16 = 9090;

/// Porta INTERNA do contêiner para o Mock OAuth2/JWKS Server (Nginx).
pub const MOCK_OAUTH_INTERNAL_PORT: u16 = 80;
/// Porta INTERNA do contêiner para o Vault.
pub const VAULT_INTERNAL_PORT: u16 = 8200;

/// Porta gRPC INTERNA do contêiner para os serviços TypeDB Server.
pub const TYPEDB_INTERNAL_PORT: u16 = 1729;

// === Portas do HOST Mapeadas ===
// Estas são as portas no HOST que são mapeadas para as portas internas dos contêineres
// no arquivo `docker-compose.test.yml`. Os testes de cliente que rodam no host
// usarão estas portas para se conectar aos serviços dentro do Docker.

/// Porta HTTP/WS no HOST mapeada para o Typedb-MCP-Server.
pub const MCP_SERVER_HOST_HTTP_PORT: u16 = 8788;
/// Porta HTTPS/WSS no HOST mapeada para o Typedb-MCP-Server.
pub const MCP_SERVER_HOST_HTTPS_PORT: u16 = 8444;
/// Porta de Métricas no HOST mapeada para o Typedb-MCP-Server.
pub const MCP_SERVER_HOST_METRICS_PORT: u16 = 9091;

/// Porta no HOST mapeada para o Mock OAuth2/JWKS Server.
pub const MOCK_OAUTH_HOST_PORT: u16 = 8089;

/// Porta no HOST mapeada para o TypeDB Server padrão (sem TLS).
pub const TYPEDB_HOST_PORT: u16 = 1729;
/// Porta no HOST mapeada para o TypeDB Server com TLS.
pub const TYPEDB_TLS_HOST_PORT: u16 = 11730;

// === Caminhos de Endpoint Padrão ===

/// Caminho padrão do endpoint WebSocket MCP no servidor.
pub const MCP_SERVER_DEFAULT_WEBSOCKET_PATH: &str = "/mcp/ws";
/// Caminho padrão do endpoint de métricas Prometheus no servidor.
pub const MCP_SERVER_DEFAULT_METRICS_PATH: &str = "/metrics";
/// Caminho padrão do endpoint de liveness.
pub const MCP_SERVER_DEFAULT_LIVEZ_PATH: &str = "/livez";
/// Caminho padrão do endpoint de readiness.
pub const MCP_SERVER_DEFAULT_READYZ_PATH: &str = "/readyz";

// === Arquivos de Configuração e Docker Compose ===

/// Caminho padrão para o arquivo Docker Compose usado nos testes de integração,
/// relativo à raiz do projeto Typedb-MCP-Server (onde o Cargo.toml principal está).
pub const DEFAULT_DOCKER_COMPOSE_TEST_FILE: &str = "docker-compose.test.yml";

/// Nome do arquivo de configuração TOML base/default para os testes.
/// Esperado em `tests/test_configs/`.
pub const DEFAULT_TEST_CONFIG_FILENAME: &str = "default.test.toml";
/// Nome do arquivo de configuração TOML para testes com OAuth2 habilitado.
/// Esperado em `tests/test_configs/`.
pub const OAUTH_ENABLED_TEST_CONFIG_FILENAME: &str = "oauth_enabled.test.toml";
/// Nome do arquivo de configuração TOML para testes com TLS habilitado no servidor MCP.
/// Esperado em `tests/test_configs/`.
pub const SERVER_TLS_TEST_CONFIG_FILENAME: &str = "server_tls.test.toml";
/// Nome do arquivo de configuração TOML para testes onde o servidor MCP
/// conecta-se ao TypeDB usando TLS.
/// Esperado em `tests/test_configs/`.
pub const TYPEDB_TLS_CONNECTION_TEST_CONFIG_FILENAME: &str = "typedb_tls_connection.test.toml";

// === Constantes de Autenticação para Teste ===

/// Key ID (kid) usado para tokens JWT de teste e no `mock_jwks.json`.
pub const TEST_JWT_KID: &str = "test-key-1";
/// Issuer (iss) esperado e usado para tokens JWT de teste.
/// Deve corresponder ao configurado em `oauth_enabled.test.toml`.
pub const TEST_JWT_ISSUER: &str = "test-issuer";
/// Audience (aud) esperado e usado para tokens JWT de teste.
/// Deve corresponder ao configurado em `oauth_enabled.test.toml`.
pub const TEST_JWT_AUDIENCE: &str = "test-audience";

// === Timeouts Padrão para Testes ===

/// Timeout padrão para conexões WebSocket nos testes.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
/// Timeout padrão para requisições MCP nos testes.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// Timeout padrão para healthchecks de prontidão do servidor MCP (`/readyz`).
pub const DEFAULT_MCP_SERVER_READY_TIMEOUT: Duration = Duration::from_secs(60);
/// Timeout padrão para healthchecks de serviços TypeDB.
pub const DEFAULT_TYPEDB_READY_TIMEOUT: Duration = Duration::from_secs(90);
/// Timeout padrão para healthchecks do Mock OAuth Server.
pub const DEFAULT_MOCK_AUTH_READY_TIMEOUT: Duration = Duration::from_secs(30);

// === Constantes de Rate Limit (para referência no log de resilience_tests) ===
// Estes valores devem espelhar os definidos em `default.test.toml` se forem usados
// para justificar o comportamento do teste de rate limiting.
/// Valor padrão de `requests_per_second` usado em `default.test.toml`.
pub const DEFAULT_RATE_LIMIT_REQUESTS_PER_SECOND: u64 = 1000;
/// Valor padrão de `burst_size` usado em `default.test.toml`.
pub const DEFAULT_RATE_LIMIT_BURST_SIZE: u32 = 2000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants_are_defined_and_accessible() {
        assert_eq!(MCP_SERVER_SERVICE_NAME, "typedb-mcp-server-it");
        assert_eq!(MCP_SERVER_HOST_HTTP_PORT, 8788);
        assert_eq!(MCP_SERVER_DEFAULT_WEBSOCKET_PATH, "/mcp/ws");
        assert_eq!(MCP_SERVER_DEFAULT_METRICS_PATH, "/metrics");
        assert_eq!(MCP_SERVER_DEFAULT_LIVEZ_PATH, "/livez");
        assert_eq!(MCP_SERVER_DEFAULT_READYZ_PATH, "/readyz");
        assert_eq!(DEFAULT_TEST_CONFIG_FILENAME, "default.test.toml");
        assert_eq!(TEST_JWT_KID, "test-key-1");
        assert_eq!(DEFAULT_TYPEDB_READY_TIMEOUT, Duration::from_secs(90));
        assert_eq!(DEFAULT_RATE_LIMIT_REQUESTS_PER_SECOND, 1000);
        assert_eq!(DEFAULT_RATE_LIMIT_BURST_SIZE, 2000);
    }
}
