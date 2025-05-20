// tests/integration.rs
// Ponto de entrada para o crate de testes de integração do Typedb-MCP-Server.

// Licença Apache 2.0
// Copyright 2025 Guilherme Leste
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

/// Testes focados na conexão WebSocket, handshake, TLS e cenários básicos de autenticação.
#[path = "integration/connection_tests.rs"]
pub mod connection_tests;

/// Testes para as ferramentas MCP relacionadas à administração de bancos de dados
/// (criar, deletar, listar, verificar existência).
#[path = "integration/db_admin_tool_tests.rs"]
pub mod db_admin_tool_tests;

/// Testes para as ferramentas MCP relacionadas a operações de observabilidade
/// (endpoints /metrics, /livez, /readyz).
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