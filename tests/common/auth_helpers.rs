// tests/common/auth_helpers.rs

// Licença Apache 2.0
// Copyright 2025 Guilherme Leste
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

//! Fornece funções utilitárias e dados de teste relacionados à autenticação OAuth 2.0,
//! especificamente para a geração de JSON Web Tokens (JWTs) de teste.

use jsonwebtoken::{encode, EncodingKey, Header};
// Tornando Algorithm público para ser acessível por outros módulos
pub use jsonwebtoken::Algorithm;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Claims que podem ser usados para gerar tokens de teste.
/// Esta struct é similar à `Claims` definida em `src/auth.rs`,
/// mas pode ser específica para as necessidades de geração de tokens de teste.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TestClaims {
    /// Subject (user ID)
    pub sub: String,
    /// Expiration time (Unix timestamp)
    pub exp: usize,
    /// Issued at (Unix timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<usize>,
    /// Not before (Unix timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<usize>,
    /// Issuer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Audience (String ou Vec<String>)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<serde_json::Value>,
    /// Escopos (string separada por espaço)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Outros claims customizados para teste
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_claim: Option<String>,
}

// ATENÇÃO: As chaves RSA abaixo são placeholders.
// Substitua "..." por conteúdo de chaves PEM válidas para testar a assinatura RS256.
// A chave privada é usada para assinar. A pública correspondente seria configurada no mock JWKS.
// ESTAS CHAVES SÃO APENAS PARA TESTE E NÃO DEVEM SER USADAS EM PRODUÇÃO.
const TEST_RSA_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDEx2KKIGHhMQam\nkUUJXHFTv48ZWgd1gf/JxpXVaBlS/SjeKza6tlACKXDlUofPBP7lsoJ8zrkjjMQM\nz+L6nXhvoBmWmJl6b+MXoktJAc/Z1Rxxtwhc1T6uBk2qvWyb8EquGM1gKMcc+3Wy\nKz4nTWUB1o9F/IwlXzZpaYqsZpAXzd7l5O+M1SMaewFRIgLR9LjWLPDnkx+7wXK3\n63pKHTxeEBtoZtYX5WvLdAmNata0juX5Tw9ZXO5Mpub8VwF/KxVGRy/nGLRxGeuP\n+/so6KMc4Umis3iVbMgJlJD8FSCUi0/DNRoZDOBOD7/logCuPo8n8NmZFYfScnu0\n+Snu1Mb3AgMBAAECggEAD3b1/RH/b0G5mpSXHt23gFPxLJZhOLBvSE3Fj8B/IQEJ\nWbB+vBzA2/Kizzr1tmTXnXiyfZmHfk49SB58YaLHiMpFyIqUoUUyzTQxg3rTeXSg\nqCUw0I7nvqh7KRx68SRo0hbb6R87SsFOZiK030TbV9Ijb2YiI3vAnHcxcUwcLeqa\nINDImk1sFiZv9kk8btJ5Nc+w7TyNnK+r1ZMiawcNIC4w3mdc6ohl+TGuNNNTOL3D\nqJ9uFXzFX1CiBg/VIXy70AwXQ8pSIScjWpgiOigp0azvb+g/rAaakClofaiQnL5y\nFWZdMbPn1FYBBBuTLGMR1uKhFlxJ9A+DaKoI1hcaZQKBgQDznAG0CzajELti+EJx\nmtWQn0yFUPOQzcCS2USIW6Dmo4RPpaPwXuOLZTTw8v3BhKyjZC+igCJpZFeSsAkb\ngCA+kmd3OQ3e57LHUSoKpSCX5djpyWZtFza6HMQn2u/vz6a4QAYaoqlfdli9ORQB\nfAo+aiWL9/6J2y4Af3nkHvZsKwKBgQDOyZsw0NIynuJIDNEEmZ1ajN6LZwhkMoGU\n7cncxkbYibI9Tf7MrVYMwWuveqnrAo33nBoMASxC2MCWcb0NOLr/0ZOorlxzsiWU\n7/2DjKJYNt73J8Yxuf3CoqHnsnoL5ffPnGkyTmWdNikc9jx37cZb7VAJ9ThHL+5+\nuqghGXVOZQKBgQDIIkWf9Ypogul/kHd9v3duvgBukifXscFgo1BTOfvBH1sm1+0M\nH9iOf5Hz1Z01a9sszLT5qo0ayo3LfAWvax6SaVLJNr03gGB2sS552lkhkXoX7xbP\nzr9uPQ3FtG9kM9NDEY4yOaouPBsBMbBG2/HKfwfjqtSZytBLJm8sQ2etSwKBgAP8\n/3FBlcxEJDkfhiiAjfhhHymxIwhLsRQeQfZwHI2wmi90gaWQ8kfssxb/VqehtPtB\nl38DxsbDR3OfXfYTUgf9Esv+EOpqVS86MbmHzNnGtSYvLjNnUu2eFWFSn+f613y5\nl43Q1UTi9ogId8IYY+sB+Lk4cY1t7zuiffulcg3BAoGAdSBxd8yXGOUyTKwOh5Od\n/jik25d31mX1WDvspEPHnONdlZIA4mr9ku8otMdTuEhI+YW2s/IfIo4k88K+LxOg\ndq7EDeNEZT+/KnMPppNBcTALx/I21+iTR3elZAakO70HEXMniC7hF30bOVizmlvY\n4zRGK7m3K4paxD1F69HHmJU=\n-----END PRIVATE KEY-----";
// Adicione a chave pública PEM correspondente à chave privada acima.
// Esta chave é usada para verificar a assinatura do token.
const TEST_RSA_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxMdiiiBh4TEGppFFCVxx\nU7+PGVoHdYH/ycaV1WgZUv0o3is2urZQAilw5VKHzwT+5bKCfM65I4zEDM/i+p14\nb6AZlpiZem/jF6JLSQHP2dUccbcIXNU+rgZNqr1sm/BKrhjNYCjHHPt1sis+J01l\nAdaPRfyMJV82aWmKrGaQF83e5eTvjNUjGnsBUSIC0fS41izw55Mfu8Fyt+t6Sh08\nXhAbaGbWF+Vry3QJjWrWtI7l+U8PWVzuTKbm/FcBfysVRkcv5xi0cRnrj/v7KOij\nHOFJorN4lWzICZSQ/BUglItPwzUaGQzgTg+/5aIArj6PJ/DZmRWH0nJ7tPkp7tTG\n9wIDAQAB\n-----END PUBLIC KEY-----";

/// Key ID de teste para JWTs.
pub const TEST_KID: &str = "test-key-1"; // Atualizado para corresponder ao mock_jwks.json

/// Gera um token JWT de teste.
///
/// # Parâmetros
/// * `claims`: Os claims a serem incluídos no token.
/// * `alg`: O algoritmo de assinatura (ex: `Algorithm::RS256` ou `Algorithm::HS256`).
///          Se o algoritmo for `RS256`, `TEST_RSA_PRIVATE_KEY_PEM` deve ser uma chave válida.
///
/// # Retorna
/// Uma string contendo o token JWT assinado.
///
/// # Panics
/// * Se `alg` for `Algorithm::RS256` e `TEST_RSA_PRIVATE_KEY_PEM` não for uma chave PEM RSA válida.
/// * Se `alg` for um algoritmo não suportado por este helper.
/// * Se a codificação do token falhar por outros motivos.
pub fn generate_test_jwt(
    claims: TestClaims,
    alg: Algorithm,
) -> String {
    let mut header = Header::new(alg);
    header.kid = Some(TEST_KID.to_string()); // KID que o mock JWKS server conhecerá

    // Para RS256, é crucial que TEST_RSA_PRIVATE_KEY_PEM seja uma chave válida.
    // O expect() causará pânico se a chave for inválida (como o placeholder "...").
    // Para HS256, um segredo simples é usado.
    let encoding_key = match alg {
        Algorithm::RS256 => EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY_PEM.as_bytes())
            .expect("Falha ao carregar chave RSA privada de teste. Verifique TEST_RSA_PRIVATE_KEY_PEM."),
        Algorithm::HS256 => EncodingKey::from_secret("test-secret-for-auth-helpers".as_bytes()),
        _ => panic!("Algoritmo de teste não suportado neste helper: {:?}", alg),
    };

    encode(&header, &claims, &encoding_key).expect("Falha ao codificar token de teste")
}

/// Retorna o timestamp atual em segundos desde a época Unix.
pub fn current_timestamp_secs() -> usize {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Tempo voltou para trás")
        .as_secs() as usize
}

// Outras funções helper podem incluir:
// - Gerar claims com expiração específica (válido, expirado).
// - Gerar claims com issuer/audience específicos.
// - Gerar claims com escopos específicos.

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{decode, DecodingKey, Validation}; // Algorithm já está no escopo de super

    // Para testar com RS256, precisaríamos da chave pública correspondente ao
    // TEST_RSA_PRIVATE_KEY_PEM para usar com DecodingKey::from_rsa_pem.
    // Exemplo: const TEST_RSA_PUBLIC_KEY_PEM_FOR_DECODE: &str = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----";

    #[test]
    fn test_generate_and_decode_hs256_token() {
        let now = current_timestamp_secs();
        let claims_to_encode = TestClaims {
            sub: "user-test-hs256".to_string(),
            exp: now + 3600, // Expira em 1 hora
            iat: Some(now),
            nbf: Some(now),
            iss: Some("auth-helper-issuer".to_string()),
            aud: Some(serde_json::json!("auth-helper-audience")),
            scope: Some("profile email".to_string()),
            custom_claim: Some("custom_value".to_string()),
        };

        let token = generate_test_jwt(claims_to_encode.clone(), Algorithm::HS256);
        assert!(!token.is_empty(), "O token gerado não deve estar vazio");

        let decoding_key = DecodingKey::from_secret("test-secret-for-auth-helpers".as_bytes());
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&["auth-helper-issuer"]);
        validation.set_audience(&["auth-helper-audience"]);
        validation.validate_nbf = true;
        // A validação de `exp` e `iat` é feita por padrão se presentes.

        let decoded_token_data = decode::<TestClaims>(&token, &decoding_key, &validation)
            .expect("Decodificação do token de teste HS256 falhou");

        assert_eq!(decoded_token_data.claims.sub, claims_to_encode.sub);
        assert_eq!(decoded_token_data.claims.exp, claims_to_encode.exp);
        assert_eq!(decoded_token_data.claims.iat, claims_to_encode.iat);
        assert_eq!(decoded_token_data.claims.nbf, claims_to_encode.nbf);
        assert_eq!(decoded_token_data.claims.iss, claims_to_encode.iss);
        assert_eq!(decoded_token_data.claims.aud, claims_to_encode.aud);
        assert_eq!(decoded_token_data.claims.scope, claims_to_encode.scope);
        assert_eq!(decoded_token_data.claims.custom_claim, claims_to_encode.custom_claim);
        assert_eq!(decoded_token_data.header.kid.unwrap(), TEST_KID);
    }

    // Para adicionar um teste para RS256 (`test_generate_and_decode_rs256_token`):
    // 1. Substitua o placeholder em `TEST_RSA_PRIVATE_KEY_PEM` por uma chave RSA privada real.
    // 2. Obtenha a chave pública PEM correspondente.
    // 3. Use `DecodingKey::from_rsa_pem(&TEST_RSA_PUBLIC_KEY_PEM_FOR_DECODE.as_bytes())`.
    // 4. Chame `generate_test_jwt` com `Algorithm::RS256`.
    // Este teste é omitido aqui porque requer chaves RSA válidas que não foram fornecidas.

    /// Testa a geração e decodificação de um token JWT usando RS256.
    ///
    /// ATENÇÃO: Este teste FALHARÁ até que os placeholders em
    /// `TEST_RSA_PRIVATE_KEY_PEM` e `TEST_RSA_PUBLIC_KEY_PEM`
    /// sejam substituídos por chaves RSA PEM válidas e correspondentes.
    #[test]
    // #[should_panic(expected = \"Falha ao carregar chave RSA privada de teste. Verifique TEST_RSA_PRIVATE_KEY_PEM.\")] // Removido
    // OU, se a chave privada for válida mas a pública não, o pânico será em `DecodingKey::from_rsa_pem`
    // ou na decodificação. Para cobrir o caso mais provável com placeholders, o pânico na chave privada é esperado.
    // Se você fornecer uma chave privada válida, mas uma pública inválida (ou o placeholder),
    // o `expect` em `DecodingKey::from_rsa_pem` será ativado.
    // Para um teste que *passaria* com chaves válidas, remova `#[should_panic]`.
    fn test_generate_and_decode_rs256_token() {
        let now = current_timestamp_secs();
        let claims_to_encode = TestClaims {
            sub: "user-test-rs256".to_string(),
            exp: now + 3600, // Expira em 1 hora
            iat: Some(now),
            nbf: Some(now),
            iss: Some("auth-helper-issuer-rs256".to_string()),
            aud: Some(serde_json::json!("auth-helper-audience-rs256")),
            scope: Some("read write".to_string()),
            custom_claim: Some("custom_rs256_value".to_string()),
        };

        // Esta linha causará pânico se TEST_RSA_PRIVATE_KEY_PEM for o placeholder "..."
        let token = generate_test_jwt(claims_to_encode.clone(), Algorithm::RS256);
        assert!(!token.is_empty(), "O token gerado não deve estar vazio");

        // Esta linha causará pânico se TEST_RSA_PUBLIC_KEY_PEM for o placeholder "..."
        // ou não corresponder à chave privada.
        let decoding_key = DecodingKey::from_rsa_pem(TEST_RSA_PUBLIC_KEY_PEM.as_bytes())
            .expect("Falha ao carregar chave RSA pública de teste. Verifique TEST_RSA_PUBLIC_KEY_PEM.");

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&["auth-helper-issuer-rs256"]);
        validation.set_audience(&["auth-helper-audience-rs256"]);
        validation.validate_nbf = true;

        let decoded_token_data = decode::<TestClaims>(&token, &decoding_key, &validation)
            .expect("Decodificação do token de teste RS256 falhou");

        assert_eq!(decoded_token_data.claims.sub, claims_to_encode.sub);
        assert_eq!(decoded_token_data.claims.exp, claims_to_encode.exp);
        assert_eq!(decoded_token_data.claims.iat, claims_to_encode.iat);
        assert_eq!(decoded_token_data.claims.nbf, claims_to_encode.nbf);
        assert_eq!(decoded_token_data.claims.iss, claims_to_encode.iss);
        assert_eq!(decoded_token_data.claims.aud, claims_to_encode.aud);
        assert_eq!(decoded_token_data.claims.scope, claims_to_encode.scope);
        assert_eq!(decoded_token_data.claims.custom_claim, claims_to_encode.custom_claim);
        assert_eq!(decoded_token_data.header.kid.as_deref(), Some(TEST_KID));
    }
}

// --- Plano de Aprimoramento Futuro ---
//
// 1. **Fornecer Chaves RSA de Teste Válidas:**
//    A principal pendência é substituir os placeholders em `TEST_RSA_PRIVATE_KEY_PEM`
//    e `TEST_RSA_PUBLIC_KEY_PEM` por chaves RSA PEM reais e correspondentes.
//    Isso pode ser feito gerando um par de chaves RSA de teste (ex: com OpenSSL)
//    e incorporando o conteúdo PEM como strings no código ou, preferencialmente,
//    carregando-as de arquivos `.pem` dedicados em `tests/common/test_keys/`.
//    Exemplo de geração com OpenSSL (2048 bits):
//    ```bash
//    openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
//    openssl rsa -pubout -in private_key.pem -out public_key.pem
//    ```
//
// 2. **Remover `#[should_panic]` do Teste RS256:**
//    Uma vez que as chaves RSA válidas estejam no lugar e o teste
//    `test_generate_and_decode_rs256_token` passe consistentemente, o atributo
//    `#[should_panic(...)]` deve ser removido para que o teste valide a funcionalidade
//    correta de geração e decodificação de tokens RS256.
//
// 3. **Testes Adicionais para Casos de Erro na Validação:**
//    Considerar adicionar testes mais granulares para a validação de tokens, cobrindo cenários como:
//    * Token com `kid` (Key ID) que não existe no JWKS mockado.
//    * Token assinado com um algoritmo diferente do esperado pela chave de validação (ex: token HS256, chave RS256).
//    * Token com `iat` (Issued At) no futuro (se a validação `validate_exp` não cobrir isso implicitamente).
//    * Token com `nbf` (Not Before) no futuro, mas `validate_nbf = false` na validação.
//    * Token com `aud` (Audience) ou `iss` (Issuer) inválidos, mas onde a validação para estes não está configurada.
//
// 4. **Carregamento de Chaves de Arquivos (Opcional, mas Recomendado):**
//    Para evitar ter strings PEM longas diretamente no código Rust, as chaves de teste
//    poderiam ser carregadas de arquivos. Isso exigiria adicionar lógica para ler
//    arquivos em tempo de teste (ex: usando `std::fs::read_to_string`) e possivelmente
//    adicionar os arquivos de chave ao controle de versão (em um diretório como `tests/resources/keys/`).
//    Isso tornaria as chaves mais fáceis de gerenciar e substituir.
//
// 5. **Refinar Constantes de Teste:**
//    Avaliar se constantes como `TEST_KID`, issuers e audiences de teste devem ser
//    mais configuráveis ou variadas para diferentes cenários de teste, em vez de
//    serem valores fixos globais para todos os testes neste helper.
//
// 6. **Helper para Claims Comuns:**
//    Criar funções auxiliares para gerar `TestClaims` com configurações comuns:
//    * `valid_claims(sub: &str, lifetime_secs: usize) -> TestClaims`
//    * `expired_claims(sub: &str) -> TestClaims`
//    * `claims_with_specific_scope(sub: &str, scope: &str) -> TestClaims`
//    Isso reduziria a duplicação na criação de claims dentro dos testes.
