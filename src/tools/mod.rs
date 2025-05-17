#![allow(clippy::too_long_first_doc_paragraph)]
// src/tools/mod.rs

// Copyright (C) 2024 -今日の未来-
// SPDX-License-Identifier: Apache-2.0

//! Módulo agregador para todas as ferramentas MCP disponíveis.
//!
//! Este módulo declara os submódulos que contêm a lógica específica para cada categoria de ferramenta do `Typedb-MCP-Server`.
//!
//! Cada submódulo é responsável por uma área funcional das ferramentas.
///
/// Ferramentas relacionadas à administração de bancos de dados TypeDB.
///
/// Inclui criar, deletar, listar e verificar existência de bancos.
pub mod db_admin;

/// Ferramentas relacionadas à execução de consultas TypeQL.
pub mod query;

/// Ferramentas relacionadas a operações no esquema TypeDB.
pub mod schema_ops;

/// Módulo para lidar com parâmetros de ferramentas.
pub mod params;

#[cfg(test)]
mod tests {
    // Teste simples para garantir que o módulo compila e é reconhecido.
    // Não testa nenhuma funcionalidade específica, apenas a presença do módulo.
    #[test]
    fn test_module_declaration_compiles() {
        // Garante que o módulo compila. Um teste vazio que compila e executa
        // com sucesso é suficiente para este propósito.
    }
}