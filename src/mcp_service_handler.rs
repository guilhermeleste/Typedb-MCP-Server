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

//! Implementação principal do `ServerHandler` do RMCP para o Typedb-MCP-Server.
//!
//! Esta struct, `McpServiceHandler`, é o coração da lógica do servidor MCP.
//! Ela é instanciada para cada conexão WebSocket e mantém o contexto dessa conexão,
//! incluindo informações de autenticação. Define todas as ferramentas MCP disponíveis,
//! lida com suas chamadas (incluindo verificação de escopos OAuth2 baseada no contexto
//! da conexão), e serve os recursos MCP estáticos e dinâmicos.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

// rmcp v0.1.5 imports
use rmcp::{
    handler::server::tool::ToolBox,
    model::{
        CallToolRequestParam, CallToolResult, ErrorCode, ErrorData, GetPromptRequestParam,
        GetPromptResult, Implementation, ListPromptsResult, ListResourceTemplatesResult,
        ListResourcesResult, ListToolsResult, PaginatedRequestParam, ProtocolVersion,
        ReadResourceRequestParam, ReadResourceResult, ResourceContents, ServerCapabilities,
        ServerInfo,
    },
    service::{RequestContext, RoleServer},
    tool,     // Para a macro #[tool]
    tool_box, // Importa a macro tool_box corretamente
    ServerHandler,
};

// Crates do projeto
use crate::{
    auth::ClientAuthContext,
    config::Settings,
    error, // Para acessar os códigos de erro MCP definidos
    resources,
    tools::{self, db_admin, query, schema_ops},
};
use typedb_driver::TypeDBDriver;

/// Instruções iniciais fornecidas aos clientes MCP ao conectar.
///
/// Estas instruções descrevem as capacidades do servidor, as ferramentas disponíveis
/// e seus requisitos de escopo, além de orientações gerais de uso.
const SERVER_INSTRUCTIONS: &str = r"
Você é um assistente especializado em interagir com um banco de dados TypeDB.
Você tem acesso às seguintes categorias de ferramentas para gerenciar e consultar este banco de dados:

1.  **CONSULTAS DE DADOS:**
    *   `query_read`: Busca dados. Requer escopo: `typedb:read_data`.
    *   `insert_data`: Adiciona dados. Requer escopo: `typedb:write_data`.
    *   `delete_data`: Remove dados. Requer escopo: `typedb:write_data`.
    *   `update_data`: Modifica dados. Requer escopo: `typedb:write_data`.

2.  **OPERAÇÕES DE ESQUEMA:**
    *   `define_schema`: Define/estende esquema. Requer escopo: `typedb:manage_schema`.
    *   `undefine_schema`: Remove definições de esquema. Requer escopo: `typedb:manage_schema`.
    *   `get_schema`: Visualiza esquema. Requer escopo: `typedb:manage_schema`.

3.  **GERENCIAMENTO DE BANCO DE DADOS:**
    *   `create_database`: Cria banco. Requer escopo: `typedb:manage_databases`.
    *   `database_exists`: Verifica se banco existe. Requer escopo: `typedb:manage_databases`.
    *   `list_databases`: Lista bancos. Requer escopo: `typedb:manage_databases`.
    *   `delete_database`: DELETA banco. Requer escopo: `typedb:admin_databases`. (EXTREMA CAUTELA)

4.  **UTILITÁRIOS:**
    *   `validate_query`: Valida sintaxe de query. Requer escopo: `typedb:validate_queries`.

RECURSOS: `info://typeql/query_types`, `info://typedb/transactions_and_tools`, `schema://current/{database_name}?type={schema_type}`.
DIRETRIZES: Especifique `database_name`. Cuidado com `delete_database`. Autenticação OAuth2 Bearer Token é necessária se habilitada.
";

/// Estrutura principal que implementa `ServerHandler` e mantém o estado do servidor MCP
/// para uma conexão WebSocket específica.
///
/// Contém referências compartilhadas ao driver `TypeDB` e às configurações da aplicação,
/// além de um contexto de autenticação opcional para a conexão atual.
#[derive(Clone, Debug)]
pub struct McpServiceHandler {
    /// Driver `TypeDB` para interação com o banco de dados. Compartilhado entre conexões.
    pub driver: Arc<TypeDBDriver>,
    /// Configurações globais da aplicação. Compartilhadas entre conexões.
    pub settings: Arc<Settings>,
    /// Mapeia nome da ferramenta para a lista de escopos `OAuth2` necessários.
    /// Esta estrutura é compartilhada e imutável após a criação do handler.
    tool_required_scopes: Arc<HashMap<String, Vec<String>>>,
    /// Contexto de autenticação do cliente para esta conexão específica.
    /// `None` se `OAuth2` estiver desabilitado ou se a autenticação falhou ou não foi fornecida.
    auth_context: Option<Arc<ClientAuthContext>>,
}

// Define o ToolBox para McpServiceHandler.
// A macro `tool_box!` gera o acessor e o `ToolBoxHolder` estático,
// além das funções `_tool_attr()` e `_tool_call()` para cada ferramenta.
tool_box! {
    McpServiceHandler {
        // Ferramentas de Consulta de Dados
        tool_query_read, tool_insert_data, tool_delete_data, tool_update_data,
        // Ferramentas de Operações de Esquema
        tool_define_schema, tool_undefine_schema, tool_get_schema,
        // Ferramentas de Gerenciamento de Banco de Dados
        tool_create_database, tool_database_exists, tool_list_databases, tool_delete_database,
        // Ferramentas Utilitárias
        tool_validate_query
    } mcp_service_handler_tool_box_accessor // Nome da função acessora gerada
}

impl McpServiceHandler {
    /// Cria uma nova instância do `McpServiceHandler` para uma conexão WebSocket específica.
    ///
    /// Este construtor é chamado pelo `websocket_handler` em `main.rs` para cada nova conexão.
    ///
    /// # Parâmetros
    /// * `driver`: Um `Arc<TypeDBDriver>` compartilhado para interagir com o `TypeDB`.
    /// * `settings`: Um `Arc<Settings>` compartilhado contendo as configurações da aplicação.
    /// * `auth_context`: Opcional `Arc<ClientAuthContext>` para esta conexão.
    ///   Será `Some` se `OAuth2` estiver habilitado e o cliente tiver se autenticado com sucesso.
    #[must_use]
    pub fn new_for_connection(
        driver: Arc<TypeDBDriver>,
        settings: Arc<Settings>,
        auth_context: Option<Arc<ClientAuthContext>>,
    ) -> Self {
        // O `tool_required_scopes` é imutável e pode ser construído uma vez e compartilhado.
        // Poderia ser um static Lazy ou parte do AppState, mas para simplificar,
        // o reconstruímos aqui. Para performance, idealmente seria compartilhado.
        // No entanto, como `McpServiceHandler` é `Clone`, este Arc será clonado barato.
        let mut tool_scopes_map = HashMap::new();
        tool_scopes_map.insert("query_read".to_string(), vec!["typedb:read_data".to_string()]);
        tool_scopes_map.insert("insert_data".to_string(), vec!["typedb:write_data".to_string()]);
        tool_scopes_map.insert("delete_data".to_string(), vec!["typedb:write_data".to_string()]);
        tool_scopes_map.insert("update_data".to_string(), vec!["typedb:write_data".to_string()]);
        tool_scopes_map
            .insert("define_schema".to_string(), vec!["typedb:manage_schema".to_string()]);
        tool_scopes_map
            .insert("undefine_schema".to_string(), vec!["typedb:manage_schema".to_string()]);
        tool_scopes_map.insert("get_schema".to_string(), vec!["typedb:manage_schema".to_string()]);
        tool_scopes_map
            .insert("create_database".to_string(), vec!["typedb:manage_databases".to_string()]);
        tool_scopes_map
            .insert("database_exists".to_string(), vec!["typedb:manage_databases".to_string()]);
        tool_scopes_map
            .insert("list_databases".to_string(), vec!["typedb:manage_databases".to_string()]);
        tool_scopes_map
            .insert("delete_database".to_string(), vec!["typedb:admin_databases".to_string()]);
        tool_scopes_map
            .insert("validate_query".to_string(), vec!["typedb:validate_queries".to_string()]);

        Self { driver, settings, tool_required_scopes: Arc::new(tool_scopes_map), auth_context }
    }

    /// Construtor usado para criar uma instância "template" do `McpServiceHandler`,
    /// tipicamente para fins onde um `auth_context` específico da conexão ainda não está disponível
    /// (ex: obtenção de `ServerInfo` antes da conexão estar totalmente estabelecida).
    ///
    /// Para lidar com requisições MCP de uma conexão ativa, use `new_for_connection`.
    #[must_use]
    pub fn new(driver: Arc<TypeDBDriver>, settings: Arc<Settings>) -> Self {
        Self::new_for_connection(driver, settings, None)
    }

    /// Constrói e retorna as capacidades do servidor MCP.
    ///
    /// Indica quais funcionalidades do protocolo MCP o servidor suporta.
    fn build_server_capabilities() -> ServerCapabilities {
        ServerCapabilities::builder()
            .enable_tools() // Servidor suporta a funcionalidade de ferramentas
            .enable_tool_list_changed() // Servidor pode notificar sobre mudanças na lista de ferramentas
            .enable_resources() // Servidor suporta recursos
            .enable_resources_list_changed() // Servidor pode notificar sobre mudanças nos recursos
            .build()
    }

    /// Retorna uma referência estática ao `ToolBox<Self>` que contém
    /// os metadados e a lógica de despacho para todas as ferramentas MCP registradas.
    fn tool_box() -> &'static ToolBox<Self> {
        // Chama a função acessora gerada pela macro `tool_box!`
        mcp_service_handler_tool_box_accessor()
    }

    // --- Definições das Ferramentas MCP ---
    // Cada método `tool_*` corresponde a uma ferramenta MCP.
    // A macro `#[tool(...)]` registra a ferramenta com seus metadados.
    // O parâmetro `#[tool(aggr)] params: ...` indica que os argumentos da chamada MCP
    // devem ser desserializados na struct de parâmetros especificada.

    #[tool(
        name = "query_read",
        description = "Executa uma consulta TypeQL de leitura (match...get, fetch, aggregate)."
    )]
    async fn tool_query_read(
        &self,
        #[tool(aggr)] params: tools::params::QueryReadParams,
    ) -> Result<CallToolResult, ErrorData> {
        query::handle_query_read(self.driver.clone(), params).await
    }

    #[tool(name = "insert_data", description = "Insere dados usando uma consulta TypeQL 'insert'.")]
    async fn tool_insert_data(
        &self,
        #[tool(aggr)] params: tools::params::InsertDataParams,
    ) -> Result<CallToolResult, ErrorData> {
        query::handle_insert_data(self.driver.clone(), params).await
    }

    #[tool(
        name = "delete_data",
        description = "Remove dados usando uma consulta TypeQL 'match...delete'."
    )]
    async fn tool_delete_data(
        &self,
        #[tool(aggr)] params: tools::params::DeleteDataParams,
    ) -> Result<CallToolResult, ErrorData> {
        query::handle_delete_data(self.driver.clone(), params).await
    }

    #[tool(
        name = "update_data",
        description = "Atualiza dados atomicamente usando 'match...delete...insert'."
    )]
    async fn tool_update_data(
        &self,
        #[tool(aggr)] params: tools::params::UpdateDataParams,
    ) -> Result<CallToolResult, ErrorData> {
        query::handle_update_data(self.driver.clone(), params).await
    }

    #[tool(
        name = "define_schema",
        description = "Define ou estende o esquema usando TypeQL 'define'."
    )]
    async fn tool_define_schema(
        &self,
        #[tool(aggr)] params: tools::params::DefineSchemaParams,
    ) -> Result<CallToolResult, ErrorData> {
        schema_ops::handle_define_schema(self.driver.clone(), params).await
    }

    #[tool(
        name = "undefine_schema",
        description = "Remove elementos do esquema usando TypeQL 'undefine'."
    )]
    async fn tool_undefine_schema(
        &self,
        #[tool(aggr)] params: tools::params::UndefineSchemaParams,
    ) -> Result<CallToolResult, ErrorData> {
        schema_ops::handle_undefine_schema(self.driver.clone(), params).await
    }

    #[tool(
        name = "get_schema",
        description = "Recupera a definição do esquema TypeQL (completo ou apenas tipos)."
    )]
    async fn tool_get_schema(
        &self,
        #[tool(aggr)] params: tools::params::GetSchemaParams,
    ) -> Result<CallToolResult, ErrorData> {
        schema_ops::handle_get_schema(self.driver.clone(), params).await
    }

    #[tool(name = "create_database", description = "Cria um novo banco de dados TypeDB.")]
    async fn tool_create_database(
        &self,
        #[tool(aggr)] params: tools::params::CreateDatabaseParams,
    ) -> Result<CallToolResult, ErrorData> {
        db_admin::handle_create_database(self.driver.clone(), params).await
    }

    #[tool(name = "database_exists", description = "Verifica se um banco de dados TypeDB existe.")]
    async fn tool_database_exists(
        &self,
        #[tool(aggr)] params: tools::params::DatabaseExistsParams,
    ) -> Result<CallToolResult, ErrorData> {
        db_admin::handle_database_exists(self.driver.clone(), params).await
    }

    #[tool(
        name = "list_databases",
        description = "Lista todos os bancos de dados TypeDB existentes."
    )]
    async fn tool_list_databases(&self) -> Result<CallToolResult, ErrorData> {
        db_admin::handle_list_databases(self.driver.clone()).await
    }

    #[tool(
        name = "delete_database",
        description = "PERMANENTEMENTE remove um banco de dados TypeDB."
    )]
    async fn tool_delete_database(
        &self,
        #[tool(aggr)] params: tools::params::DeleteDatabaseParams,
    ) -> Result<CallToolResult, ErrorData> {
        db_admin::handle_delete_database(self.driver.clone(), params).await
    }

    #[tool(
        name = "validate_query",
        description = "Valida uma consulta TypeQL em um banco de dados existente."
    )]
    async fn tool_validate_query(
        &self,
        #[tool(aggr)] params: tools::params::ValidateQueryParams,
    ) -> Result<CallToolResult, ErrorData> {
        query::handle_validate_query(self.driver.clone(), params).await
    }
}

impl ServerHandler for McpServiceHandler {
    /// Retorna informações sobre o servidor, incluindo a versão do protocolo,
    /// informações de implementação, capacidades e instruções iniciais.
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2025_03_26, // Última versão conhecida do RMCP
            server_info: Implementation::from_build_env(),   // Obtém info do Cargo.toml
            capabilities: Self::build_server_capabilities(),
            instructions: Some(SERVER_INSTRUCTIONS.to_string()),
        }
    }

    /// Processa uma chamada de ferramenta MCP (`tools/call`) de um cliente.
    ///
    /// Realiza a verificação de escopos `OAuth2` se aplicável e, em seguida,
    /// despacha a chamada para o handler da ferramenta apropriada usando o `ToolBox`.
    ///
    /// # Parâmetros
    /// * `request_param`: Os parâmetros da requisição `tools/call`.
    /// * `_context`: O contexto da requisição `rmcp`. Embora presente na assinatura do trait,
    ///   o `ClientAuthContext` é agora acessado via `self.auth_context` nesta implementação.
    async fn call_tool(
        &self,
        request_param: CallToolRequestParam,
        _context: RequestContext<RoleServer>, // _context não é usado para buscar ClientAuthContext aqui
    ) -> Result<CallToolResult, ErrorData> {
        let tool_name_str = request_param.name.as_ref();
        tracing::debug!(tool.name = %tool_name_str, "Recebida chamada de ferramenta MCP.");

        // Verificação de autorização baseada em escopos OAuth2
        if self.settings.oauth.enabled {
            if let Some(ref auth_ctx) = self.auth_context {
                // Usa o auth_context da instância
                if let Some(required_scopes) = self.tool_required_scopes.get(tool_name_str) {
                    if required_scopes.is_empty() {
                        tracing::debug!(tool.name = %tool_name_str, "Nenhum escopo específico requerido para esta ferramenta, acesso permitido.");
                    } else {
                        let client_has_all_required_scopes = required_scopes
                            .iter()
                            .all(|req_scope| auth_ctx.scopes.contains(req_scope));

                        if !client_has_all_required_scopes {
                            tracing::warn!(
                                tool.name = %tool_name_str,
                                client.user_id = %auth_ctx.user_id,
                                scopes.required = ?required_scopes,
                                scopes.possessed = ?auth_ctx.scopes,
                                "Autorização falhou: escopos insuficientes."
                            );
                            return Err(ErrorData {
                                code: ErrorCode(error::MCP_ERROR_CODE_AUTHORIZATION_FAILED),
                                message: Cow::Owned(format!(
                                    "Escopos OAuth2 insuficientes para executar a ferramenta '{tool_name_str}'. Requer: {required_scopes:?}."
                                )),
                                data: Some(serde_json::json!({
                                    "type": "InsufficientScope",
                                    "requiredScopes": required_scopes,
                                    "possessedScopes": auth_ctx.scopes.iter().collect::<Vec<_>>(),
                                })),
                            });
                        }
                        tracing::debug!(tool.name = %tool_name_str, client.user_id = %auth_ctx.user_id, scopes = ?auth_ctx.scopes, "Autorização de escopo bem-sucedida.");
                    }
                } else {
                    // Ferramenta não encontrada no mapa de escopos.
                    // Pode ser um erro de configuração ou uma ferramenta que não requer escopos.
                    // Por segurança, poderíamos negar, mas a política atual do código é logar e permitir.
                    tracing::warn!(tool.name = %tool_name_str, "Configuração de escopos não encontrada para a ferramenta. Permitindo acesso por padrão, mas isso deve ser revisado.");
                }
            } else {
                // OAuth está habilitado globalmente, mas esta instância de handler (para esta conexão)
                // não tem um ClientAuthContext. Isso significa que a conexão não foi autenticada.
                tracing::error!(tool.name = %tool_name_str, "OAuth habilitado, mas ClientAuthContext ausente para esta conexão. Acesso negado.");
                return Err(ErrorData {
                    code: ErrorCode(error::MCP_ERROR_CODE_AUTHENTICATION_FAILED), // Authentication Failed
                    message: Cow::Owned("Autenticação necessária. Nenhum contexto de autenticação válido para esta sessão.".to_string()),
                    data: Some(serde_json::json!({"type": "AuthenticationRequired"})),
                });
            }
        } else {
            tracing::debug!("Autenticação OAuth2 desabilitada, verificação de escopo pulada.");
        }

        // O ToolCallContext espera `&McpServiceHandler` como primeiro argumento.
        // O `_context` original da `rmcp` ainda é passado, embora não seja usado para Auth aqui.
        let tool_call_context =
            rmcp::handler::server::tool::ToolCallContext::new(self, request_param, _context);
        Self::tool_box().call(tool_call_context).await
    }

    /// Retorna a lista de ferramentas MCP disponíveis neste servidor.
    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParam>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult { next_cursor: None, tools: Self::tool_box().list() })
    }

    /// Retorna a lista de recursos estáticos informativos disponíveis.
    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParam>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        tracing::debug!("Listando recursos estáticos MCP.");
        Ok(ListResourcesResult { resources: resources::list_static_resources(), next_cursor: None })
    }

    /// Retorna a lista de templates de URI para recursos dinâmicos.
    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParam>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, ErrorData> {
        tracing::debug!("Listando templates de recursos MCP.");
        Ok(ListResourceTemplatesResult {
            resource_templates: resources::list_resource_templates(),
            next_cursor: None,
        })
    }

    /// Lê e retorna o conteúdo de um recurso MCP (estático ou dinâmico).
    async fn read_resource(
        &self,
        request: ReadResourceRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, ErrorData> {
        tracing::debug!(uri = %request.uri, "Lendo recurso MCP.");
        let uri_str = request.uri.as_str();

        // Tenta ler como recurso estático primeiro
        if let Some(static_content) = resources::read_static_resource(uri_str) {
            tracing::info!("Recurso estático '{}' encontrado e retornado.", uri_str);
            Ok(ReadResourceResult {
                contents: vec![ResourceContents::TextResourceContents {
                    uri: request.uri, // Retorna a URI original da requisição
                    mime_type: Some("text/plain".to_string()),
                    text: static_content,
                }],
            })
        // Se não for estático, tenta ler como recurso de schema dinâmico
        } else if uri_str.starts_with("schema://current/") {
            match resources::read_dynamic_schema_resource(self.driver.clone(), uri_str).await {
                Ok(schema_content) => {
                    tracing::info!("Recurso de schema dinâmico '{}' lido com sucesso.", uri_str);
                    Ok(ReadResourceResult {
                        contents: vec![ResourceContents::TextResourceContents {
                            uri: request.uri,
                            mime_type: Some("text/plain+typeql".to_string()),
                            text: schema_content,
                        }],
                    })
                }
                Err(e) => {
                    // `read_dynamic_schema_resource` já retorna ErrorData
                    tracing::warn!(uri = %uri_str, error.message = %e.message, "Falha ao ler recurso de schema dinâmico.");
                    Err(e)
                }
            }
        // Se não for nenhum dos conhecidos, retorna RESOURCE_NOT_FOUND
        } else {
            tracing::warn!("Recurso com URI '{}' não encontrado.", uri_str);
            Err(ErrorData {
                code: ErrorCode::RESOURCE_NOT_FOUND,
                message: Cow::Owned(format!("Recurso com URI '{uri_str}' não encontrado.")),
                data: None,
            })
        }
    }

    /// Retorna a lista de prompts (não implementado atualmente).
    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParam>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, ErrorData> {
        tracing::debug!("Listando prompts MCP (nenhum implementado).");
        Ok(ListPromptsResult { prompts: vec![], next_cursor: None })
    }

    /// Obtém um prompt específico (não implementado atualmente).
    async fn get_prompt(
        &self,
        request: GetPromptRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResult, ErrorData> {
        tracing::warn!(prompt.name = %request.name, "Tentativa de obter prompt não implementado.");
        Err(ErrorData {
            code: ErrorCode::METHOD_NOT_FOUND, // Ou um erro mais específico se o MCP definir
            message: Cow::Owned(format!(
                "A funcionalidade GetPrompt (para o prompt '{}') não está implementada.",
                request.name
            )),
            data: None,
        })
    }
}
