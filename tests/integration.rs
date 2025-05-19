// tests/integration.rs
// Ponto de entrada para o crate de testes de integração.

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

//! Raiz do crate de testes de integração para Typedb-MCP-Server.
//!
//! Este arquivo (`tests/integration.rs`) é o ponto de entrada que o Cargo usa
//! para compilar todos os testes de integração. Ele declara o módulo `common`
//! (que reside em `tests/common/mod.rs`) e todos os arquivos de suíte de teste
//! individuais que estão localizados no diretório `tests/integration/`.
//!
//! A organização é a seguinte:
//! - `tests/common/mod.rs`: Contém utilitários compartilhados por todos os testes.
//!   - `tests/common/client.rs`: Helpers para o cliente MCP.
//!   - `tests/common/auth_helpers.rs`: Helpers para autenticação e JWT.
//!   - `tests/common/docker_helpers.rs` (a ser adicionado): Helpers para Docker.
//! - `tests/integration.rs` (este arquivo): Raiz do crate de teste de integração.
//! - `tests/integration/`: Diretório contendo os módulos de teste específicos.
//!   - `tests/integration/connection_tests.rs`: Testes de conexão e autenticação.
//!   - `tests/integration/db_admin_tool_tests.rs`: Testes para db_admin_tool.
//!   - ... e outros arquivos de teste.
//!
//! Cada arquivo `*_tests.rs` em `tests/integration/` é declarado como um submódulo
//! público neste arquivo usando o atributo `#[path]` para especificar sua localização.
//! Dentro desses submódulos, os utilitários de `tests/common/` podem ser acessados
//! via `use crate::common::NomeDoItem;`.

// Declara o módulo `common` que está em `tests/common/mod.rs`.
// Este `common` será acessível como `crate::common` de dentro dos submódulos abaixo.
pub mod common;

// Declara cada suíte de teste de integração como um submódulo público.
// O atributo `#[path]` é usado para informar ao compilador Rust onde encontrar
// o arquivo fonte para cada módulo, já que eles estão em um subdiretório (`integration/`).

/// Testes de conexão, autenticação e TLS.
#[path = "integration/connection_tests.rs"]
pub mod connection_tests;

/// Testes para as ferramentas de administração de banco de dados (db_admin_tool).
#[path = "integration/db_admin_tool_tests.rs"]
pub mod db_admin_tool_tests;

/// Testes para as ferramentas de consulta e manipulação de dados (query_tool).
#[path = "integration/query_tool_tests.rs"]
pub mod query_tool_tests;

/// Testes de resiliência e tratamento de erros do servidor.
#[path = "integration/resilience_tests.rs"]
pub mod resilience_tests;

/// Testes para as ferramentas de gerenciamento de recursos (resource_tool).
#[path = "integration/resource_tests.rs"]
pub mod resource_tests;

/// Testes para as ferramentas de operações de esquema (schema_ops_tool).
#[path = "integration/schema_ops_tool_tests.rs"]
pub mod schema_ops_tool_tests;

/// Testes para cenários com TLS habilitado.
#[path = "integration/typedb_tls_tests.rs"]
pub mod typedb_tls_tests;

// Adicione aqui outros módulos de teste do diretório `tests/integration/`
// conforme eles forem sendo refatorados ou criados.
// Exemplo:
// #[path = "integration/outro_teste_specífico.rs"]
// pub mod outro_teste_especifico;
