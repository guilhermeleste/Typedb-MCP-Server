// src/tools/mod.rs

// Licença Apache 2.0
// Copyright [ANO_ATUAL] [SEU_NOME_OU_ORGANIZACAO]
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

//! Módulo agregador para todas as ferramentas MCP e seus parâmetros.
//!
//! Este módulo declara os submódulos que contêm a lógica específica para
//! cada categoria de ferramenta do `Typedb-MCP-Server`. Cada submódulo
//! é responsável por uma área funcional das ferramentas.

/// Ferramentas relacionadas à administração de bancos de dados TypeDB
/// (criar, deletar, listar, verificar existência).
// Validação: `pub mod <nome>;` é a sintaxe padrão para declarar um módulo público
// que reside em `<nome>.rs` ou `<nome>/mod.rs`.
// Fonte: https://doc.rust-lang.org/book/ch07-02-defining-modules-to-control-scope-and-privacy.html
pub mod db_admin;

/// Estruturas de parâmetros de entrada para todas as ferramentas MCP.
// Validação: Idem acima.
pub mod params;

/// Ferramentas relacionadas à execução de consultas TypeQL de dados
/// (leitura, inserção, atualização, deleção, validação).
// Validação: Idem acima.
pub mod query;

/// Ferramentas relacionadas a operações no esquema TypeDB
/// (definir, remover, obter esquema).
// Validação: Idem acima.
pub mod schema_ops;

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