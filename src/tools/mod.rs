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

#![allow(clippy::too_long_first_doc_paragraph)]

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
