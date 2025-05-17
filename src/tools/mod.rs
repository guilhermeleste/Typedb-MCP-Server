// src/tools/mod.rs

// Copyright (C) 2024 -今日の未来-
// SPDX-License-Identifier: Apache-2.0

//! Módulo agregador para todas as ferramentas MCP disponíveis.
//!
//! Este módulo declara os submódulos que contêm a lógica específica para
//! cada categoria de ferramenta do `Typedb-MCP-Server`. Cada submódulo
//! é responsável por uma área funcional das ferramentas.
///
/// Ferramentas relacionadas à administração de bancos de dados TypeDB
/// (criar, deletar, listar, verificar existência).
pub mod db_admin;

/// Ferramentas relacionadas à execução de consultas TypeQL.
pub mod query;

/// Ferramentas relacionadas a operações no esquema TypeDB.
pub mod schema_ops;

/// Módulo para lidar com parâmetros de ferramentas.
pub mod params;

#[cfg(test)]
mod tests {
    // Este teste é trivial e serve principalmente para cumprir o requisito
    // de ter um bloco de teste em cada arquivo. A correção das declarações
    // `pub mod` é verificada pelo compilador Rust ao tentar encontrar
    // os arquivos/diretórios correspondentes (db_admin.rs, params.rs, etc.).
    #[test]
    fn test_module_declaration_compiles() {
        // Se este arquivo compila, significa que as declarações `pub mod`
        // estão sintaticamente corretas. O compilador procurará por:
        // - src/tools/db_admin.rs (ou src/tools/db_admin/mod.rs)
        // - src/tools/params.rs (ou src/tools/params/mod.rs)
        // - src/tools/query.rs (ou src/tools/query/mod.rs)
        // - src/tools/schema_ops.rs (ou src/tools/schema_ops/mod.rs)
        // A falha em encontrar esses arquivos resultaria em um erro de compilação,
        // que é o "teste" para essas declarações.
        assert!(
            true,
            "Este teste apenas confirma que o arquivo mod.rs compila."
        );
    }
}