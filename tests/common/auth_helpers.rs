// tests/common/auth_helpers.rs

//! Fornece funções utilitárias e dados de teste relacionados à autenticação OAuth 2.0,
//! especificamente para a geração de JSON Web Tokens (JWTs) de teste para uso
//! nos testes de integração do Typedb-MCP-Server.
//!
//! As chaves RSA usadas aqui são carregadas de arquivos e devem corresponder
//! à chave pública configurada no `mock_jwks.json`.

use jsonwebtoken::{encode, EncodingKey, Header}; // Importa Algorithm diretamente
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

// Importa constantes do mesmo crate `common`
use super::constants;

/// Claims que podem ser usados para gerar tokens de teste.
/// Esta struct é similar à `Claims` definida em `src/auth.rs`,
/// mas é específica para as necessidades de geração de tokens de teste,
/// permitindo a inclusão de todos os claims relevantes.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TestClaims {
    /// Subject (user ID). Requerido pelo JWT.
    pub sub: String,
    /// Expiration time (Unix timestamp). Requerido pelo JWT.
    pub exp: usize,
    /// Issued at (Unix timestamp). Opcional.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<usize>,
    /// Not before (Unix timestamp). Opcional.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<usize>,
    /// Issuer. Opcional, mas importante para validação.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Audience (String ou Vec<String>). Opcional, mas importante para validação.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<serde_json::Value>, // Permite string ou array de strings
    /// Escopos (string separada por espaço). Opcional.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Claim customizado para fins de teste (exemplo).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_claim: Option<String>,
}

/// Chave privada RSA de teste em formato PEM, carregada do arquivo.
/// **USADA APENAS PARA TESTES.**
/// Este arquivo deve existir em `tests/common/test_keys/private_key.pem`.
pub const TEST_RSA_PRIVATE_KEY_PEM: &str = include_str!("test_keys/private_key.pem");

/// Chave pública RSA de teste em formato PEM, carregada do arquivo.
/// **USADA APENAS PARA TESTES.**
/// Este arquivo deve existir em `tests/common/test_keys/public_key.pem`
/// e corresponder à chave privada acima. O módulo `n` e expoente `e` desta chave
/// devem ser usados para construir o `mock_jwks.json`.
pub const TEST_RSA_PUBLIC_KEY_PEM: &str = include_str!("test_keys/public_key.pem");

/// Segredo para assinar tokens HS256, caso necessário em algum teste específico.
/// **USADO APENAS PARA TESTES.**
pub const TEST_HS256_SECRET: &str =
    "mcp-integration-test-hs256-super-secret-key-do-not-use-in-prod";

// Reexportar Algorithm para que outros módulos de teste possam usá-lo via `auth_helpers::Algorithm`
// Isso resolve o erro de "enum import `Algorithm` is private" em `test_env.rs`.
pub use jsonwebtoken::Algorithm as JwtAuthAlgorithm;

/// Gera um token JWT de teste assinado com o algoritmo especificado.
///
/// # Arguments
///
/// * `claims`: Os claims a serem incluídos no payload do token.
/// * `alg`: O algoritmo de assinatura a ser usado (`JwtAuthAlgorithm::RS256` ou `JwtAuthAlgorithm::HS256`).
///
/// # Returns
///
/// Uma `String` contendo o token JWT assinado.
///
/// # Panics
///
/// * Se `alg` for `JwtAuthAlgorithm::RS256` e `TEST_RSA_PRIVATE_KEY_PEM` não for uma chave PEM RSA válida.
/// * Se `alg` for um algoritmo não suportado por este helper (atualmente suporta RS256 e HS256).
/// * Se a codificação do token falhar por outros motivos.
pub fn generate_test_jwt(claims: TestClaims, alg: JwtAuthAlgorithm) -> String {
    let mut header = Header::new(alg);
    // O Key ID (kid) é crucial para que o servidor consiga encontrar a chave pública correta no JWKS.
    // Este valor deve corresponder ao 'kid' no `tests/resources/mock_jwks.json`.
    header.kid = Some(constants::TEST_JWT_KID.to_string());

    let encoding_key = match alg {
        JwtAuthAlgorithm::RS256 => EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY_PEM.as_bytes())
            .expect("Falha ao carregar chave RSA privada de teste de 'tests/common/test_keys/private_key.pem'. Verifique o arquivo e seu conteúdo."),
        JwtAuthAlgorithm::HS256 => EncodingKey::from_secret(TEST_HS256_SECRET.as_bytes()),
        _ => panic!("Algoritmo de assinatura de teste não suportado por este helper: {:?}. Suportados: RS256, HS256.", alg),
    };

    encode(&header, &claims, &encoding_key).expect("Falha ao codificar token JWT de teste.")
}

/// Retorna o timestamp atual em segundos desde a época Unix (Unix epoch).
/// Usado para definir os campos `exp`, `iat`, `nbf` nos claims do JWT.
pub fn current_timestamp_secs() -> usize {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Falha ao obter timestamp: tempo do sistema retrocedeu.")
        .as_secs() as usize
}

#[cfg(test)]
mod tests {
    use super::*; // Importa tudo do módulo pai (auth_helpers)
    use jsonwebtoken::{decode, DecodingKey, Validation};
    // Não precisa importar `constants` aqui novamente se já estiver no escopo de `super`
    // use crate::common::constants;

    #[test]
    fn test_generate_and_decode_rs256_token_with_valid_keys() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init(); // Para logs de teste
        let now = current_timestamp_secs();
        let claims_to_encode = TestClaims {
            sub: "test-user-rs256".to_string(),
            exp: now + 3600, // Expira em 1 hora
            iat: Some(now),
            nbf: Some(now),
            iss: Some(constants::TEST_JWT_ISSUER.to_string()),
            aud: Some(serde_json::json!(constants::TEST_JWT_AUDIENCE)), // Pode ser string ou array
            scope: Some("read write admin".to_string()),
            custom_claim: Some("valor_custom_rs256".to_string()),
        };

        // Gera o token usando RS256
        let token = generate_test_jwt(claims_to_encode.clone(), JwtAuthAlgorithm::RS256);
        assert!(!token.is_empty(), "Token RS256 gerado não deve estar vazio.");
        tracing::debug!("Token RS256 Gerado: {}", token);

        // Prepara para decodificar/validar usando a chave pública
        let decoding_key = DecodingKey::from_rsa_pem(TEST_RSA_PUBLIC_KEY_PEM.as_bytes())
            .expect("Falha ao carregar chave RSA pública de teste de 'tests/common/test_keys/public_key.pem'.");

        let mut validation = Validation::new(JwtAuthAlgorithm::RS256);
        validation.set_issuer(&[constants::TEST_JWT_ISSUER]);
        validation.set_audience(&[constants::TEST_JWT_AUDIENCE]);
        validation.validate_nbf = true;
        // A validação de `exp` (e `iat` se presente) é feita por padrão pela crate jsonwebtoken.

        let decoded_token_data = decode::<TestClaims>(&token, &decoding_key, &validation)
            .expect("Decodificação/validação do token de teste RS256 falhou.");

        // Verifica os claims
        assert_eq!(decoded_token_data.claims.sub, claims_to_encode.sub);
        assert_eq!(decoded_token_data.claims.exp, claims_to_encode.exp);
        assert_eq!(decoded_token_data.claims.iat, claims_to_encode.iat);
        assert_eq!(decoded_token_data.claims.nbf, claims_to_encode.nbf);
        assert_eq!(decoded_token_data.claims.iss, claims_to_encode.iss);
        assert_eq!(decoded_token_data.claims.aud, claims_to_encode.aud);
        assert_eq!(decoded_token_data.claims.scope, claims_to_encode.scope);
        assert_eq!(decoded_token_data.claims.custom_claim, claims_to_encode.custom_claim);

        // Verifica o header (kid)
        assert_eq!(decoded_token_data.header.kid.as_deref(), Some(constants::TEST_JWT_KID));
    }

    #[test]
    fn test_generate_and_decode_hs256_token() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let now = current_timestamp_secs();
        let claims_to_encode = TestClaims {
            sub: "test-user-hs256".to_string(),
            exp: now + 3600,
            iat: Some(now),
            nbf: Some(now),
            iss: Some(constants::TEST_JWT_ISSUER.to_string()),
            aud: Some(serde_json::json!([constants::TEST_JWT_AUDIENCE, "another-aud"])), // Testando com array de audience
            scope: Some("guest basic_user".to_string()),
            custom_claim: None,
        };

        let token = generate_test_jwt(claims_to_encode.clone(), JwtAuthAlgorithm::HS256);
        assert!(!token.is_empty(), "Token HS256 gerado não deve estar vazio.");
        tracing::debug!("Token HS256 Gerado: {}", token);

        let decoding_key = DecodingKey::from_secret(TEST_HS256_SECRET.as_bytes());
        let mut validation = Validation::new(JwtAuthAlgorithm::HS256);
        validation.set_issuer(&[constants::TEST_JWT_ISSUER]);
        // Validar contra qualquer um dos audiences no token
        validation.set_audience(&[constants::TEST_JWT_AUDIENCE, "another-aud"]);
        validation.validate_nbf = true;

        let decoded_token_data = decode::<TestClaims>(&token, &decoding_key, &validation)
            .expect("Decodificação/validação do token de teste HS256 falhou.");

        assert_eq!(decoded_token_data.claims.sub, claims_to_encode.sub);
        assert_eq!(decoded_token_data.claims.exp, claims_to_encode.exp);
        assert_eq!(decoded_token_data.claims.iss, claims_to_encode.iss);
        assert_eq!(decoded_token_data.claims.aud, claims_to_encode.aud);
        assert_eq!(decoded_token_data.claims.scope, claims_to_encode.scope);
        assert_eq!(decoded_token_data.header.kid.as_deref(), Some(constants::TEST_JWT_KID));
    }

    #[test]
    fn test_token_expiration_rs256() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let now = current_timestamp_secs();
        let expired_claims = TestClaims {
            sub: "expired-user-rs256".to_string(),
            exp: now - 3600, // Expirou 1 hora atrás
            iat: Some(now - 7200),
            iss: Some(constants::TEST_JWT_ISSUER.to_string()),
            aud: Some(serde_json::json!(constants::TEST_JWT_AUDIENCE)),
            scope: None,
            custom_claim: None,
            nbf: None,
        };

        let token = generate_test_jwt(expired_claims, JwtAuthAlgorithm::RS256);
        let decoding_key = DecodingKey::from_rsa_pem(TEST_RSA_PUBLIC_KEY_PEM.as_bytes()).unwrap();
        let validation = Validation::new(JwtAuthAlgorithm::RS256);
        // Não definir issuer/audience aqui para focar apenas na expiração,
        // mas em um cenário real, eles seriam validados.
        // validation.set_issuer(&[constants::TEST_JWT_ISSUER]);
        // validation.set_audience(&[constants::TEST_JWT_AUDIENCE]);

        let result = decode::<TestClaims>(&token, &decoding_key, &validation);
        assert!(result.is_err(), "Token expirado deveria falhar na validação.");
        assert_eq!(result.unwrap_err().kind(), &jsonwebtoken::errors::ErrorKind::ExpiredSignature);
    }

    #[test]
    fn test_token_nbf_not_yet_valid_rs256() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let now = current_timestamp_secs();
        let nbf_claims = TestClaims {
            sub: "future-user-rs256".to_string(),
            exp: now + 3600,
            iat: Some(now),
            nbf: Some(now + 3600), // Válido apenas daqui a 1 hora
            iss: Some(constants::TEST_JWT_ISSUER.to_string()),
            aud: Some(serde_json::json!(constants::TEST_JWT_AUDIENCE)),
            scope: None,
            custom_claim: None,
        };

        let token = generate_test_jwt(nbf_claims, JwtAuthAlgorithm::RS256);
        let decoding_key = DecodingKey::from_rsa_pem(TEST_RSA_PUBLIC_KEY_PEM.as_bytes()).unwrap();
        let mut validation = Validation::new(JwtAuthAlgorithm::RS256);
        validation.validate_nbf = true; // Importante para testar NBF

        let result = decode::<TestClaims>(&token, &decoding_key, &validation);
        assert!(result.is_err(), "Token com NBF no futuro deveria falhar na validação.");
        assert_eq!(result.unwrap_err().kind(), &jsonwebtoken::errors::ErrorKind::ImmatureSignature);
    }

    #[test]
    fn test_token_invalid_issuer_rs256() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let now = current_timestamp_secs();
        let claims = TestClaims {
            sub: "user-wrong-issuer-rs256".to_string(),
            exp: now + 3600,
            iat: Some(now),
            iss: Some("urn:wrong-issuer".to_string()), // Issuer incorreto
            aud: Some(serde_json::json!(constants::TEST_JWT_AUDIENCE)),
            scope: None,
            custom_claim: None,
            nbf: None,
        };

        let token = generate_test_jwt(claims, JwtAuthAlgorithm::RS256);
        let decoding_key = DecodingKey::from_rsa_pem(TEST_RSA_PUBLIC_KEY_PEM.as_bytes()).unwrap();
        let mut validation = Validation::new(JwtAuthAlgorithm::RS256);
        validation.set_issuer(&[constants::TEST_JWT_ISSUER]); // Servidor espera este issuer

        let result = decode::<TestClaims>(&token, &decoding_key, &validation);
        assert!(result.is_err(), "Token com issuer inválido deveria falhar na validação.");
        assert_eq!(result.unwrap_err().kind(), &jsonwebtoken::errors::ErrorKind::InvalidIssuer);
    }

    #[test]
    fn test_token_invalid_audience_rs256() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let now = current_timestamp_secs();
        let claims = TestClaims {
            sub: "user-wrong-audience-rs256".to_string(),
            exp: now + 3600,
            iat: Some(now),
            iss: Some(constants::TEST_JWT_ISSUER.to_string()),
            aud: Some(serde_json::json!("api://wrong-audience")), // Audience incorreto
            scope: None,
            custom_claim: None,
            nbf: None,
        };

        let token = generate_test_jwt(claims, JwtAuthAlgorithm::RS256);
        let decoding_key = DecodingKey::from_rsa_pem(TEST_RSA_PUBLIC_KEY_PEM.as_bytes()).unwrap();
        let mut validation = Validation::new(JwtAuthAlgorithm::RS256);
        validation.set_audience(&[constants::TEST_JWT_AUDIENCE]); // Servidor espera este audience

        let result = decode::<TestClaims>(&token, &decoding_key, &validation);
        assert!(result.is_err(), "Token com audience inválido deveria falhar na validação.");
        assert_eq!(result.unwrap_err().kind(), &jsonwebtoken::errors::ErrorKind::InvalidAudience);
    }

    #[test]
    fn test_current_timestamp_secs_is_reasonable() {
        let ts1 = current_timestamp_secs();
        std::thread::sleep(std::time::Duration::from_secs(1));
        let ts2 = current_timestamp_secs();
        assert!(ts2 > ts1, "Timestamp deveria aumentar com o tempo.");
        assert!(
            ts2.saturating_sub(ts1) >= 1,
            "Diferença de timestamp deveria ser de pelo menos 1 segundo."
        );
    }
}
