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

//! Raiz do crate de testes de integração para o Typedb-MCP-Server.
//!
//! Este arquivo atua como o ponto de entrada que o Cargo utiliza para descobrir
//! e compilar todos os testes de integração. Ele declara:
//!
//! 1.  O módulo `common` (localizado em `tests/common/mod.rs`), que contém
//!     utilitários e helpers compartilhados por todas as suítes de teste.
//! 2.  Cada suíte de teste de integração individual (arquivos `*_tests.rs`) como
//!     um submódulo público. Estes arquivos residem no diretório `tests/integration/`.
//!
//! A organização geral da pasta `tests/` é:
//! └── tests/
//!     ├── common/                 # Utilitários de teste (client, auth, docker, mcp_utils)
//!     │   └── mod.rs
//!     │   └── ... (outros arquivos .rs)
//!     ├── integration.rs          # Este arquivo, o ponto de entrada do crate de teste.
//!     └── integration/            # Módulos contendo os testes de integração.
//!         ├── connection_tests.rs
//!         ├── db_admin_tool_tests.rs
//!         └── ... (outros arquivos *_tests.rs)
//!
//! Dentro dos módulos de teste (ex: `db_admin_tool_tests`), os utilitários
//! do módulo `common` podem ser acessados usando `crate::common::NomeDoItem;`,
//! pois `integration.rs` define a raiz (`crate`) para esta compilação de teste.

// Permite que módulos/funções não sejam usados em todas as configurações de build/teste
// sem gerar warnings, comum em arquivos raiz de bibliotecas de teste.
#![allow(dead_code)]

/// Módulo contendo utilitários compartilhados para os testes de integração.
/// Localizado em `tests/common/mod.rs`.
pub mod common;

// --- Suítes de Teste de Integração ---
// Cada arquivo em `tests/integration/` é declarado como um submódulo.
// O atributo `#[path]` especifica o caminho para o arquivo fonte do módulo,
// relativo à raiz do crate de teste (a pasta `tests/` neste caso, pois
// `integration.rs` está nela e o Cargo o trata como um ponto de entrada).

/// Testes de robustez do cleanup automático do TestEnvironment.
/// Verifica se o Drop trait funciona corretamente em cenários adversos.
#[path = "integration/cleanup_tests.rs"]
pub mod cleanup_tests;

/// Testes focados na conexão WebSocket, handshake, TLS e cenários básicos de autenticação.
#[path = "integration/connection_tests.rs"]
pub mod connection_tests;

/// Testes para as ferramentas MCP relacionadas à administração de bancos de dados
/// (criar, deletar, listar, verificar existência).
#[path = "integration/db_admin_tool_tests.rs"]
pub mod db_admin_tool_tests;

/// Testes para as ferramentas MCP relacionadas a operações de observabilidade
/// (endpoints /metrics, livez, /readyz).
#[path = "integration/observability_tests.rs"]
pub mod observability_tests;

/// Testes para as ferramentas MCP de consulta e manipulação de dados
/// (query_read, insert_data, etc.).
#[path = "integration/query_tool_tests.rs"]
pub mod query_tool_tests;

/// Testes focados na resiliência do servidor, como tratamento de timeouts,
/// falhas de dependência e graceful shutdown.
#[path = "integration/resilience_tests.rs"]
pub mod resilience_tests;

/// Testes para as ferramentas MCP de gerenciamento de recursos (estáticos e dinâmicos).
#[path = "integration/resource_tests.rs"]
pub mod resource_tests;

/// Testes para as ferramentas MCP relacionadas a operações de esquema no TypeDB
/// (define, undefine, get schema).
#[path = "integration/schema_ops_tool_tests.rs"]
pub mod schema_ops_tool_tests;

/// Testes específicos para cenários onde a conexão TLS com o TypeDB está habilitada.
#[path = "integration/typedb_tls_tests.rs"]
pub mod typedb_tls_tests;

/// Testes para integração básica com o Vault em modo dev.
#[path = "integration/vault_integration_tests.rs"]
pub mod vault_integration_tests;

// Se você adicionar novos arquivos de teste em `tests/integration/`,
// adicione uma declaração de módulo similar para eles aqui.
// Exemplo:
// #[path = "integration/nova_suite_de_testes.rs"]
// pub mod nova_suite_de_testes;

// É uma boa prática ter um teste simples no arquivo raiz do crate de teste
// para garantir que ele próprio compila e a estrutura básica está correta.
#[cfg(test)]
mod integration_crate_tests {
    #[test]
    fn test_integration_crate_compiles() {
        // Este teste apenas confirma que o crate de integração (este arquivo e seus módulos)
        // compila sem erros. A funcionalidade real é testada nos submódulos.
        assert!(true, "O crate de testes de integração compilou com sucesso.");
    }
}
