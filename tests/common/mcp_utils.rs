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

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use rmcp::model::{CallToolResult, RawContent};

/// Extrai o conteúdo de texto de um `CallToolResult`.
///
/// Assume que o resultado contém pelo menos um item e que o primeiro item
/// é do tipo `RawContent::Text`. Caso contrário, entra em pânico.
///
/// # Panics
/// - Se `call_result.content` estiver vazio.
/// - Se o primeiro item em `call_result.content` não for `RawContent::Text`.
#[must_use] pub fn get_text_from_call_result(call_result: CallToolResult) -> String {
    assert!(!call_result.content.is_empty(), "A resposta da ferramenta MCP não pode estar vazia.");
    let content_item = &call_result.content[0];
    match &content_item.raw {
        RawContent::Text(text_content) => text_content.text.clone(),
        RawContent::Resource(resource_content) => match &resource_content.resource {
            rmcp::model::ResourceContents::TextResourceContents { text, .. } => text.clone(),
            rmcp::model::ResourceContents::BlobResourceContents { blob, .. } => {
                let decoded_bytes = BASE64_STANDARD
                    .decode(blob)
                    .expect("Falha ao decodificar blob base64 no helper");
                String::from_utf8(decoded_bytes)
                    .expect("Blob decodificado não é UTF-8 válido no helper")
            }
        },
        _ => panic!(
            "Conteúdo da resposta não é Texto ou Recurso textual como esperado. Conteúdo: {:?}",
            content_item.raw
        ),
    }
}
