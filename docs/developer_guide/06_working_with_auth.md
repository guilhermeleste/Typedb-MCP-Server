
# Guia do Desenvolvedor: Trabalhando com Autenticação (OAuth2/JWT)

O Typedb-MCP-Server implementa um mecanismo de autenticação opcional baseado em OAuth 2.0 e JSON Web Tokens (JWTs) para proteger seus endpoints e controlar o acesso às ferramentas MCP. Este guia detalha como a autenticação funciona internamente e como os desenvolvedores podem interagir com ela.

Consulte também a [Referência de Configuração (seção [oauth])](../reference/configuration.md#seção-oauth) para todas as opções de configuração relacionadas à autenticação.

## Visão Geral do Fluxo de Autenticação

Quando a autenticação OAuth2 está habilitada (`oauth.enabled = true`):

1. **Requisição do Cliente:** Um cliente MCP tenta estabelecer uma conexão WebSocket com o servidor. Esta requisição HTTP de upgrade DEVE incluir um header `Authorization: Bearer <SEU_TOKEN_JWT>`.
2. **Middleware de Autenticação (`oauth_middleware` em `src/auth.rs`):**
    * Este middleware Axum intercepta a requisição de upgrade WebSocket *antes* que o WebSocket seja estabelecido.
    * Ele extrai o token JWT do header.
    * Se nenhum token for fornecido, a requisição é rejeitada (geralmente com um HTTP 401 ou 400).
3. **Validação do Token (`validate_and_decode_token` em `src/auth.rs`):**
    * **Busca de Chave Pública (JWKS):** O `kid` (Key ID) do header do JWT é usado para encontrar a chave pública correspondente. As chaves são obtidas do `jwks_uri` configurado e cacheadas pelo `JwksCache` para evitar buscas repetidas.
    * **Verificação da Assinatura:** A assinatura do token é verificada usando a chave pública.
    * **Validação de Claims:**
        * `exp` (Expiration Time): Verifica se o token não expirou.
        * `nbf` (Not Before Time): Verifica se o token já é válido (se presente).
        * `iss` (Issuer): Compara com a lista de `oauth.issuer` configurados (se houver).
        * `aud` (Audience): Compara com a lista de `oauth.audience` configurados (se houver).
        * `oauth.required_scopes` (Escopos Gerais do Servidor): Verifica se o token possui todos os escopos listados na configuração `oauth.required_scopes`.
4. **Criação do Contexto de Autenticação:**
    * Se todas as validações passarem, um `ClientAuthContext` é criado. Esta struct contém informações extraídas do token, como:
        * `user_id`: Geralmente o claim `sub` do token.
        * `scopes`: Um `HashSet<String>` dos escopos concedidos ao cliente (parseados do claim `scope`).
        * `raw_token`: O token JWT original.
    * Este `ClientAuthContext` (envolvido em um `Arc`) é injetado nas extensões da requisição Axum usando `request.extensions_mut().insert(...)`.
5. **Prosseguimento da Requisição:**
    * A requisição de upgrade WebSocket prossegue para o `websocket_handler` em `src/main.rs`.
    * O `websocket_handler` pode então extrair o `ClientAuthContext` das extensões da requisição. Este contexto é passado para o `McpServiceHandler` através do `RequestContext` da crate `rmcp`.
6. **Autorização no Nível da Ferramenta (`McpServiceHandler`):**
    * Quando o `McpServiceHandler` recebe uma chamada `tools/call`, ele verifica se a ferramenta específica requer escopos OAuth2 (definidos no `HashMap` `tool_required_scopes`).
    * Se escopos são necessários, ele compara os escopos no `ClientAuthContext` do cliente com os escopos requeridos pela ferramenta.
    * Se o cliente não possuir os escopos necessários, a chamada da ferramenta é rejeitada com um erro MCP de autorização.

Se `oauth.enabled = false`, o `oauth_middleware` permite que todas as requisições passem sem verificação de token, e nenhum `ClientAuthContext` é injetado.

## Componentes Chave da Autenticação (`src/auth.rs`)

* **`ClientAuthContext` (struct):**
  * Armazena `user_id`, `scopes` e `raw_token`.
  * É clonável e envolvida em `Arc` para compartilhamento seguro.

* **`Claims` (struct):**
  * Representa os claims esperados em um token JWT (sub, exp, iss, aud, scope, etc.).
  * Deriva `serde::Deserialize`.

* **`JwksCache` (struct):**
  * Responsável por buscar as chaves públicas (JWKS) do `jwks_uri`.
  * Implementa caching e refresh automático das chaves em intervalos configuráveis (`oauth.jwks_refresh_interval`).
  * Usa `reqwest` para as chamadas HTTP.
  * Armazena as chaves em um `Arc<RwLock<Option<JwkSet>>>`.
  * Método `get_decoding_key_for_kid(&self, kid: &str)`: Retorna a `DecodingKey` para um `kid` específico, atualizando o cache se necessário.
  * Método `is_cache_ever_populated(&self)`: Usado pelo health check `/readyz` para verificar se o JWKS foi carregado com sucesso pelo menos uma vez.

* **`validate_and_decode_token` (função async):**
  * Orquestra a validação completa do token: decodifica o header, obtém a chave de decodificação do `JwksCache`, e usa a crate `jsonwebtoken` para decodificar e validar o token contra os claims e configurações.

* **`oauth_middleware` (função async - middleware Axum):**
  * Extrai o token, chama `validate_and_decode_token`, e injeta o `ClientAuthContext` ou retorna um erro HTTP.
  * Recebe o `JwksCache` e a configuração `oauth` como estado (`State`).

## Interagindo com o Contexto de Autenticação

### No `McpServiceHandler`

O `McpServiceHandler` recebe o `ClientAuthContext` através do `RequestContext<RoleServer>` que é passado para o método `call_tool`.

```rust
// Em src/mcp_service_handler.rs

async fn call_tool(
    &self,
    request_param: CallToolRequestParam,
    context: RequestContext<RoleServer>, // <--- O contexto da requisição RMCP
) -> Result<CallToolResult, ErrorData> {
    let tool_name_str = request_param.name.as_ref();

    if self.settings.oauth.enabled {
        // Tenta extrair o ClientAuthContext das extensões do RequestContext
        if let Some(auth_ctx) = context.extensions.get::<Arc<ClientAuthContext>>() {
            // `auth_ctx` é um Arc<ClientAuthContext>
            // Agora você pode acessar auth_ctx.user_id, auth_ctx.scopes, etc.

            if let Some(required_scopes) = self.tool_required_scopes.get(tool_name_str) {
                if !required_scopes.is_empty() {
                    let client_has_all_required_scopes = required_scopes
                        .iter()
                        .all(|req_scope| auth_ctx.scopes.contains(req_scope));

                    if !client_has_all_required_scopes {
                        // ... retornar erro de autorização ...
                    }
                }
            }
            // ...
        } else {
            // Este caso indica um problema: OAuth está habilitado, mas o contexto não foi injetado.
            // O middleware deveria ter rejeitado a conexão antes, ou há um erro na propagação.
            tracing::error!(
                tool.name = %tool_name_str,
                "OAuth habilitado, mas ClientAuthContext não encontrado nas extensões da requisição RMCP."
            );
            return Err(ErrorData { /* ... erro de autenticação interna ... */ });
        }
    }
    // ... restante da lógica de call_tool ...
}
```

### Em Novos Middlewares ou Handlers HTTP (Raro para MCP)

Se você estivesse adicionando novos endpoints HTTP (não MCP) que precisassem de autenticação, você poderia aplicar o `oauth_middleware` a eles e extrair o `Extension<Arc<ClientAuthContext>>` de forma similar no seu handler Axum.

## Testando a Autenticação

* **Testes de Integração:** A pasta `tests/integration/` contém testes que cobrem cenários de autenticação, como `connection_tests.rs`.
* **`tests/common/auth_helpers.rs`:** Fornece utilitários para gerar tokens JWT de teste com diferentes claims (expirados, com escopos específicos, issuers/audiences errados, etc.).
* **`mock_jwks.json` e `scripts/run-mock-oauth2.sh`:** Permitem simular um servidor JWKS para testes locais sem depender de um provedor de identidade externo. O `docker-compose.test.yml` pode ser configurado para usar este mock.

## Considerações para Desenvolvedores

* **Segurança de JWKS URI:** O `jwks_uri` deve ser HTTPS em produção.
* **Tratamento de Erros:** O `AuthErrorDetail` em `src/error.rs` define erros específicos de autenticação que são convertidos para `ErrorData` MCP ou códigos de status HTTP apropriados.
* **Performance do Cache JWKS:** O refresh automático e o caching ajudam a evitar chamadas excessivas ao `jwks_uri`. O timeout para estas requisições (`jwks_request_timeout_seconds`) é configurável.
* **Extensibilidade de Claims:** A struct `Claims` pode ser estendida para incluir claims customizados se o seu provedor de identidade os fornecer e o servidor precisar deles. Lembre-se de que apenas claims padrão (sub, exp, iss, aud, scope) são ativamente usados pela lógica de validação principal.

Ao adicionar novas ferramentas ou modificar a lógica de acesso, sempre considere as implicações de autenticação e autorização, especialmente se a ferramenta realizar operações sensíveis.
