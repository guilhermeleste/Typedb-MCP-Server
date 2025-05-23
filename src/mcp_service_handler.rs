// src/mcp_service_handler.rs

// Licença Apache 2.0
// Copyright 2024 Guilherme Leste
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

//! Implementação principal do `ServerHandler` do RMCP para o Typedb-MCP-Server.
//!
//! Esta struct, `McpServiceHandler`, é o coração da lógica do servidor MCP.
//! Ela define todas as ferramentas MCP disponíveis, lida com suas chamadas (incluindo
//! verificação de escopos OAuth2), e serve os recursos MCP estáticos e dinâmicos.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

// rmcp v0.1.5
use rmcp::{
    handler::server::tool::ToolBox,
    model::{
        CallToolRequestParam,
        CallToolResult,
        ErrorCode,
        ErrorData,
        GetPromptRequestParam,
        GetPromptResult,
        Implementation,
        ListPromptsResult,
        ListResourceTemplatesResult,
        ListResourcesResult,
        ListToolsResult,
        PaginatedRequestParam, // Adicionado ListToolsResult
        ProtocolVersion,
        ReadResourceRequestParam,
        ReadResourceResult,
        ResourceContents,
        ServerCapabilities,
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
    resources,
    tools::{self, db_admin, query, schema_ops},
};
use typedb_driver::TypeDBDriver;

/// Instruções iniciais fornecidas aos clientes MCP ao conectar.
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

/// Estrutura principal que implementa `ServerHandler` e mantém o estado do servidor MCP.
#[derive(Clone, Debug)]
pub struct McpServiceHandler {
    /// Driver `TypeDB` para interação com o banco de dados.
    pub driver: Arc<TypeDBDriver>,
    /// Configurações globais da aplicação.
    pub settings: Arc<Settings>,
    /// Mapeia nome da ferramenta para a lista de escopos `OAuth2` necessários.
    tool_required_scopes: Arc<HashMap<String, Vec<String>>>,
}

// Define o ToolBox para McpServiceHandler.
// A macro `tool_box!` gera:
// 1. A função acessora `mcp_service_handler_tool_box_accessor()`.
// 2. O `static ToolBoxHolder` que armazena o `ToolBox`.
// 3. Funções `#[doc(hidden)] pub fn <tool_name>_tool_attr() -> rmcp::model::Tool`
// 4. Funções `#[doc(hidden)] pub async fn <tool_name>_tool_call(...) -> Result<CallToolResult, ErrorData>`
tool_box! {
    McpServiceHandler {
        tool_query_read, tool_insert_data, tool_delete_data, tool_update_data,
        tool_define_schema, tool_undefine_schema, tool_get_schema,
        tool_create_database, tool_database_exists, tool_list_databases, tool_delete_database,
        tool_validate_query
    } mcp_service_handler_tool_box_accessor
}

impl McpServiceHandler {
    /// Cria uma nova instância do `McpServiceHandler`.
    ///
    /// # Parâmetros
    /// * `driver`: Um `Arc<TypeDBDriver>` para interagir com o `TypeDB`.
    /// * `settings`: Um `Arc<Settings>` contendo as configurações da aplicação.
    #[must_use]
    pub fn new(driver: Arc<TypeDBDriver>, settings: Arc<Settings>) -> Self {
        let mut tool_scopes = HashMap::new();
        tool_scopes.insert("query_read".to_string(), vec!["typedb:read_data".to_string()]);
        tool_scopes.insert("insert_data".to_string(), vec!["typedb:write_data".to_string()]);
        tool_scopes.insert("delete_data".to_string(), vec!["typedb:write_data".to_string()]);
        tool_scopes.insert("update_data".to_string(), vec!["typedb:write_data".to_string()]);
        tool_scopes.insert("define_schema".to_string(), vec!["typedb:manage_schema".to_string()]);
        tool_scopes.insert("undefine_schema".to_string(), vec!["typedb:manage_schema".to_string()]);
        tool_scopes.insert("get_schema".to_string(), vec!["typedb:manage_schema".to_string()]);
        tool_scopes
            .insert("create_database".to_string(), vec!["typedb:manage_databases".to_string()]);
        tool_scopes
            .insert("database_exists".to_string(), vec!["typedb:manage_databases".to_string()]);
        tool_scopes
            .insert("list_databases".to_string(), vec!["typedb:manage_databases".to_string()]);
        tool_scopes
            .insert("delete_database".to_string(), vec!["typedb:admin_databases".to_string()]);
        tool_scopes
            .insert("validate_query".to_string(), vec!["typedb:validate_queries".to_string()]);

        Self { driver, settings, tool_required_scopes: Arc::new(tool_scopes) }
    }

    /// Constrói as capacidades do servidor MCP.
    fn build_server_capabilities() -> ServerCapabilities {
        // Removido &self
        ServerCapabilities::builder()
            .enable_tools()
            .enable_tool_list_changed()
            .enable_resources()
            .enable_resources_list_changed()
            .build()
    }

    /// Função acessora para o `ToolBox` estático.
    fn tool_box() -> &'static ToolBox<Self> {
        // CORREÇÃO: Chamar a função livre gerada pela macro, não um método associado.
        mcp_service_handler_tool_box_accessor()
    }

    // --- Definições das Ferramentas MCP ---
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
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2025_03_26,
            server_info: Implementation::from_build_env(),
            capabilities: Self::build_server_capabilities(), // Alterado para Self::
            instructions: Some(SERVER_INSTRUCTIONS.to_string()),
        }
    }

    async fn call_tool(
        &self,
        request_param: CallToolRequestParam,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let tool_name_str = request_param.name.as_ref();
        tracing::debug!(tool.name = %tool_name_str, client.context_extensions = ?context.extensions, "Recebida chamada de ferramenta MCP.");

        if self.settings.oauth.enabled {
            if let Some(auth_ctx) = context.extensions.get::<Arc<ClientAuthContext>>() {
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
                                code: ErrorCode(crate::error::MCP_ERROR_CODE_AUTHORIZATION_FAILED),
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
                    tracing::warn!(tool.name = %tool_name_str, "Configuração de escopos não encontrada para a ferramenta. Permitindo acesso por padrão, mas isso deve ser revisado.");
                }
            } else {
                tracing::error!(tool.name = %tool_name_str, "OAuth habilitado, mas ClientAuthContext não encontrado nas extensões da requisição do RMCP. Isso indica uma falha na propagação do contexto de autenticação.");
                return Err(ErrorData {
                    code: ErrorCode(crate::error::MCP_ERROR_CODE_AUTHENTICATION_FAILED),
                    message: Cow::Owned("Falha interna na autenticação: contexto de autenticação ausente no servidor.".to_string()),
                    data: Some(serde_json::json!({"type": "AuthContextMissing"})),
                });
            }
        } else {
            tracing::debug!("Autenticação OAuth2 desabilitada, verificação de escopo pulada.");
        }

        let tool_call_context =
            rmcp::handler::server::tool::ToolCallContext::new(self, request_param, context);
        Self::tool_box().call(tool_call_context).await
    }

    // CORREÇÃO: Adicionada implementação manual de list_tools.
    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParam>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult { next_cursor: None, tools: Self::tool_box().list() })
    }

    // CORREÇÃO: Removido tool_box!(@derive ...);

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParam>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        tracing::debug!("Listando recursos estáticos MCP.");
        Ok(ListResourcesResult { resources: resources::list_static_resources(), next_cursor: None })
    }

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

    async fn read_resource(
        &self,
        request: ReadResourceRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, ErrorData> {
        tracing::debug!(uri = %request.uri, "Lendo recurso MCP.");
        let uri_str = request.uri.as_str();

        if let Some(static_content) = resources::read_static_resource(uri_str) {
            tracing::info!("Recurso estático '{}' encontrado e retornado.", uri_str);
            Ok(ReadResourceResult {
                contents: vec![ResourceContents::TextResourceContents {
                    uri: request.uri,
                    mime_type: Some("text/plain".to_string()),
                    text: static_content,
                }],
            })
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
                    tracing::warn!(uri = %uri_str, error.message = %e.message, "Falha ao ler recurso de schema dinâmico.");
                    Err(e)
                }
            }
        } else {
            tracing::warn!("Recurso com URI '{}' não encontrado.", uri_str);
            Err(ErrorData {
                code: ErrorCode::RESOURCE_NOT_FOUND,
                message: Cow::Owned(format!("Recurso com URI '{uri_str}' não encontrado.")),
                data: None,
            })
        }
    }

    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParam>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, ErrorData> {
        tracing::debug!("Listando prompts MCP (nenhum implementado).");
        Ok(ListPromptsResult { prompts: vec![], next_cursor: None })
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResult, ErrorData> {
        tracing::warn!(prompt.name = %request.name, "Tentativa de obter prompt não implementado.");
        Err(ErrorData {
            code: ErrorCode::METHOD_NOT_FOUND,
            message: Cow::Owned(format!(
                "A funcionalidade GetPrompt (para o prompt '{}') não está implementada.",
                request.name
            )),
            data: None,
        })
    }
}
