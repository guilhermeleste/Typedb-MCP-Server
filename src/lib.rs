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

//! # Typedb-MCP-Server Library
//!
//! Este crate (`typedb_mcp_server_lib`) define a lógica central para o `Typedb-MCP-Server`.
//! Ele encapsula a funcionalidade necessária para atuar como um gateway MCP (Model Context Protocol)
//! para o banco de dados `TypeDB`.
//!
//! A biblioteca lida com:
//! - Carregamento e gerenciamento de configurações.
//! - Conectividade e interação com o `TypeDB`.
//! - Definição e tratamento de erros específicos da aplicação.
//! - Implementação do `ServerHandler` do RMCP, incluindo a lógica de despacho para as diversas ferramentas MCP.
//! - Mecanismos de autenticação, como OAuth2/JWT.
//! - Coleta e exposição de métricas (compatível com Prometheus).
//! - Configuração e exportação de tracing distribuído (OpenTelemetry).
//! - Gerenciamento de recursos estáticos e dinâmicos expostos via MCP.
//! - A lógica específica para cada categoria de ferramenta MCP e seus parâmetros.
//! - Adaptação do transporte WebSocket para o protocolo MCP.
//!
//! O binário principal do servidor, localizado em `src/main.rs`, utiliza esta biblioteca
//! para construir, configurar e executar o servidor Typedb-MCP-Server.

/// Módulo para carregamento e gerenciamento de configurações da aplicação.
/// Define as estruturas de configuração e a lógica para lê-las de arquivos TOML
/// e variáveis de ambiente.
pub mod config;

/// Módulo para interação e conectividade com o banco de dados TypeDB.
/// Fornece funcionalidades para estabelecer e gerenciar conexões com uma instância
/// do TypeDB, incluindo suporte a TLS.
pub mod db;

/// Módulo para definições de erro customizadas e utilitários de tratamento de erro.
/// Centraliza os tipos de erro da aplicação, facilitando a conversão de erros
/// de dependências e a formatação para o protocolo MCP.
pub mod error;

/// Módulo para registro, rastreamento e prevenção de erros.
/// Fornece funcionalidades para capturar erros sistematicamente, identificar padrões,
/// implementar soluções robustas e criar medidas preventivas automáticas.
pub mod error_registry;

/// Módulo contendo o handler principal do serviço MCP (`McpServiceHandler`).
/// Implementa o trait `ServerHandler` da crate `rmcp` e orquestra a
/// execução das ferramentas MCP disponíveis.
pub mod mcp_service_handler;

/// Módulo para lógica de autenticação OAuth 2.0 e autorização.
/// Inclui middleware para validação de tokens JWT e gerenciamento de JWKS.
pub mod auth;

/// Módulo para definição e registro de métricas da aplicação, compatível com Prometheus.
/// Define as métricas que o servidor expõe para monitoramento.
pub mod metrics;

/// Módulo para configuração e inicialização do tracing distribuído utilizando OpenTelemetry.
/// Permite a observabilidade do fluxo de requisições através do servidor.
pub mod telemetry;

/// Módulo para gerenciamento de recursos estáticos e dinâmicos expostos via MCP.
/// Define os recursos informativos que os clientes MCP podem acessar.
pub mod resources;

/// Módulo agregador para todas as ferramentas MCP e seus respectivos parâmetros.
/// Organiza a lógica específica de cada ferramenta em submódulos.
pub mod tools;

/// Módulo responsável pela adaptação do transporte WebSocket para o protocolo MCP.
/// Define como as mensagens MCP são trocadas sobre uma conexão WebSocket.
pub mod transport;

// Itens que podem ser reexportados para facilitar o uso da biblioteca, se necessário.
// Por enquanto, manteremos a necessidade de importar diretamente dos submódulos
// para maior clareza da origem de cada item.
// Exemplo:
pub use ::config::ConfigError;
pub use config::Settings;
pub use error::AuthErrorDetail; // Adicionado para exportar AuthErrorDetail
pub use error::McpServerError; // Corrigido para exportar ConfigError da crate config

#[cfg(test)]
mod tests {
    /// Testa se a biblioteca e suas declarações de módulo compilam corretamente.
    ///
    /// A compilação bem-sucedida deste teste indica que a estrutura de `lib.rs`
    /// está sintaticamente correta e que o compilador conseguiu processar
    /// as declarações de módulo. A funcionalidade interna de cada módulo
    /// é verificada em seus próprios testes unitários e nos testes de integração.
    #[test]
    fn test_library_compiles_and_modules_are_declared() {
        // Este teste serve primariamente para garantir que `lib.rs` é compilável
        // e que os `pub mod` estão corretos. Não há lógica para assertar aqui,
        // a própria compilação é o teste.
    }
}
