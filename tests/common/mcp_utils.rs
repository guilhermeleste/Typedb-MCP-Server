// tests/common/mcp_utils.rs
use rmcp::model::{CallToolResult, RawContent};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};

/// Extrai o conteúdo de texto de um `CallToolResult`.
///
/// Assume que o resultado contém pelo menos um item e que o primeiro item
/// é do tipo `RawContent::Text`. Caso contrário, entra em pânico.
///
/// # Panics
/// - Se `call_result.content` estiver vazio.
/// - Se o primeiro item em `call_result.content` não for `RawContent::Text`.
pub fn get_text_from_call_result(call_result: CallToolResult) -> String {
    assert!(!call_result.content.is_empty(), "A resposta da ferramenta MCP não pode estar vazia.");
    let content_item = &call_result.content[0];
    match &content_item.raw {
        RawContent::Text(text_content) => {
            text_content.text.clone()
        },
        RawContent::Resource(resource_content) => {
            match &resource_content.resource {
                rmcp::model::ResourceContents::TextResourceContents { text, .. } => text.clone(),
                rmcp::model::ResourceContents::BlobResourceContents { blob, .. } => {
                    let decoded_bytes = BASE64_STANDARD.decode(blob).expect("Falha ao decodificar blob base64 no helper");
                    String::from_utf8(decoded_bytes).expect("Blob decodificado não é UTF-8 válido no helper")
                }
            }
        }
        _ => panic!("Conteúdo da resposta não é Texto ou Recurso textual como esperado. Conteúdo: {:?}", content_item.raw),
    }
}