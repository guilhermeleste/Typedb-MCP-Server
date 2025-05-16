// src/auth.rs

// Licença Apache 2.0
// Copyright [ANO_ATUAL] [SEU_NOME_OU_ORGANIZACAO]
// ... (cabeçalho de licença completo)

//! Módulo responsável pela autenticação OAuth 2.0 e autorização baseada em escopos.

use crate::config;
use crate::error::AuthErrorDetail;
use axum::{
    body::Body,
    extract::{Request, State},
    http::StatusCode,

    middleware::Next,
    response::{IntoResponse, Response},
};
use axum_extra::headers::{authorization::Bearer, Authorization};
use axum_extra::typed_header::{TypedHeader, TypedHeaderRejection};

use jsonwebtoken::{
    decode, decode_header,
    errors::ErrorKind as JwtErrorKind,
    jwk::JwkSet,
    Algorithm, DecodingKey, Header, TokenData, Validation,
};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::{
    collections::HashSet,
    fmt::Debug,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

/// Contexto de autenticação do cliente.
#[derive(Clone, Debug)]
pub struct ClientAuthContext {
    pub user_id: String,
    pub scopes: HashSet<String>,
    pub raw_token: String,
}

/// Claims esperados no token JWT.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub iat: Option<usize>,
    pub nbf: Option<usize>,
    pub iss: Option<String>,
    pub aud: Option<JsonValue>,
    pub scope: Option<String>,
}

/// Cache para chaves JWKS.
#[derive(Debug)]
pub struct JwksCache {
    jwks_uri: String,
    keys: Arc<RwLock<JwkSet>>,
    last_updated: Arc<RwLock<Option<Instant>>>,
    refresh_interval: Duration,
    http_client: reqwest::Client,
}

impl JwksCache {
    pub fn new(
        jwks_uri: String,
        refresh_interval: Duration,
        http_client: reqwest::Client,
    ) -> Self {
        JwksCache {
            jwks_uri,
            keys: Arc::new(RwLock::new(JwkSet { keys: Vec::new() })),
            last_updated: Arc::new(RwLock::new(None)),
            refresh_interval,
            http_client,
        }
    }

    #[tracing::instrument(skip(self), name = "jwks_cache_refresh_keys")]
    pub async fn refresh_keys(&self) -> Result<(), AuthErrorDetail> {
        tracing::info!("Atualizando chaves JWKS de: {}", self.jwks_uri);
        let response = self.http_client.get(&self.jwks_uri).send().await
            .map_err(|e| AuthErrorDetail::JwksFetchFailed(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let err_body = response.text().await.unwrap_or_else(|_| String::from("<corpo do erro ilegível>"));
            return Err(AuthErrorDetail::JwksFetchFailed(format!("Status {} ao buscar JWKS: {}", status, err_body)));
        }

        let jwks: JwkSet = response.json().await.map_err(|e| AuthErrorDetail::JwksFetchFailed(format!("JWKS JSON inválido: {}", e)))?;
        let mut keys_guard = self.keys.write().await;
        *keys_guard = jwks;
        *self.last_updated.write().await = Some(Instant::now());
        Ok(())
    }

    #[tracing::instrument(skip(self), name = "jwks_cache_get_key", fields(token.kid = %kid))]
    pub async fn get_decoding_key_for_kid(&self, kid: &str) -> Result<Option<DecodingKey>, AuthErrorDetail> {
        let needs_refresh = {
            let last_updated_guard = self.last_updated.read().await;
            match *last_updated_guard {
                Some(last_update_time) => last_update_time.elapsed() > self.refresh_interval,
                None => true,
            }
        };
        if needs_refresh {
            if let Err(e) = self.refresh_keys().await {
                if self.last_updated.read().await.is_none() { return Err(e); }
                tracing::warn!("Falha ao atualizar JWKS, usando cache antigo: {}", e);
            }
        }
        let keys_guard = self.keys.read().await;
        keys_guard.find(kid)
            .map(DecodingKey::from_jwk)
            .transpose()
            .map_err(|e| AuthErrorDetail::TokenInvalid(format!("JWK para kid '{}' inválido: {}", kid, e)))
    }

    pub async fn is_cache_ever_populated(&self) -> bool {
        self.last_updated.read().await.is_some()
    }
}

#[tracing::instrument(skip(token_str, jwks_cache, oauth_config), name = "validate_jwt_token")]
async fn validate_and_decode_token(
    token_str: &str,
    jwks_cache: &JwksCache,
    oauth_config: &config::OAuth,
) -> Result<TokenData<Claims>, AuthErrorDetail> {
    let header: Header = decode_header(token_str).map_err(|e| AuthErrorDetail::TokenInvalid(format!("Header do token inválido: {}", e)))?;
    let kid = header.kid.as_deref().ok_or(AuthErrorDetail::KidNotFoundInJwks)?;
    let alg: Algorithm = header.alg;
    let decoding_key = jwks_cache.get_decoding_key_for_kid(kid).await?.ok_or(AuthErrorDetail::KidNotFoundInJwks)?;

    let mut validation = Validation::new(alg);
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.leeway = 60;
    if let Some(ref issuers) = oauth_config.issuer { if !issuers.is_empty() { validation.iss = Some(issuers.iter().cloned().collect()); }}
    if let Some(ref audiences) = oauth_config.audience { if !audiences.is_empty() { validation.aud = Some(audiences.iter().cloned().collect()); }}

    let token_data: TokenData<Claims> = decode::<Claims>(token_str, &decoding_key, &validation).map_err(|e| match e.kind() {
        JwtErrorKind::InvalidToken => AuthErrorDetail::TokenInvalid("Formato de token inválido".to_string()),
        JwtErrorKind::InvalidSignature => AuthErrorDetail::SignatureInvalid,
        JwtErrorKind::ExpiredSignature => AuthErrorDetail::TokenExpired,
        JwtErrorKind::InvalidIssuer => AuthErrorDetail::IssuerMismatch { expected: oauth_config.issuer.clone().unwrap_or_default(), found: None },
        JwtErrorKind::InvalidAudience => AuthErrorDetail::AudienceMismatch { expected: oauth_config.audience.clone().unwrap_or_default(), found: None },
        JwtErrorKind::ImmatureSignature => AuthErrorDetail::TokenInvalid("Token ainda não é válido (nbf)".to_string()),
        _ => AuthErrorDetail::TokenInvalid(format!("Erro de validação não especificado: {}", e)),
    })?;

    if let Some(ref expected_audiences) = oauth_config.audience {
        if !expected_audiences.is_empty() {
            let token_audiences_set: HashSet<String> = match &token_data.claims.aud {
                Some(JsonValue::String(s)) => [s.clone()].into_iter().collect(),
                Some(JsonValue::Array(arr)) => arr.iter().filter_map(|v| v.as_str().map(String::from)).collect(),
                _ => HashSet::new(),
            };
            if !expected_audiences.iter().any(|aud| token_audiences_set.contains(aud)) {
                return Err(AuthErrorDetail::AudienceMismatch {
                    expected: expected_audiences.clone(),
                    found: Some(token_audiences_set.into_iter().collect()),
                });
            }
        }
    }
    if let Some(ref required_scopes_for_server) = oauth_config.required_scopes {
        if !required_scopes_for_server.is_empty() {
            let client_scopes_set: HashSet<String> = token_data.claims.scope.as_deref().unwrap_or_default().split(' ').filter(|s| !s.is_empty()).map(String::from).collect();
            if !required_scopes_for_server.iter().all(|req_scope| client_scopes_set.contains(req_scope)) {
                return Err(AuthErrorDetail::InsufficientScope {
                    required: required_scopes_for_server.clone(),
                    possessed: client_scopes_set.into_iter().collect(),
                });
            }
        }
    }
    Ok(token_data)
}

#[tracing::instrument(skip_all, name = "oauth_middleware")]
pub async fn oauth_middleware(
    State(state_tuple): State<(Arc<JwksCache>, Arc<config::OAuth>)>,
    auth_header_result: Result<TypedHeader<Authorization<Bearer>>, TypedHeaderRejection>, // Corrigido aqui
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let (jwks_cache, oauth_config) = state_tuple;
    if !oauth_config.enabled { return Ok(next.run(request).await); }

    let token_str = match auth_header_result {
        Ok(TypedHeader(Authorization(bearer))) => bearer.token().to_string(),
        Err(rejection) => {
            tracing::warn!("Header Authorization ausente/malformado: {}", rejection);
            return Err(rejection.into_response().status());
        }
    };

    match validate_and_decode_token(&token_str, &jwks_cache, &oauth_config).await {
        Ok(token_data) => {
            let client_scopes: HashSet<String> = token_data.claims.scope.as_deref().unwrap_or_default().split(' ').filter(|s| !s.is_empty()).map(String::from).collect();
            request.extensions_mut().insert(Arc::new(ClientAuthContext {
                user_id: token_data.claims.sub.clone(),
                scopes: client_scopes,
                raw_token: token_str,
            }));
            Ok(next.run(request).await)
        }
        Err(auth_err) => {
            tracing::warn!("Falha na autenticação OAuth2: {}", auth_err);
            Err(match auth_err {
                AuthErrorDetail::TokenMissingOrMalformed => StatusCode::BAD_REQUEST,
                AuthErrorDetail::TokenInvalid(_) | AuthErrorDetail::KidNotFoundInJwks | AuthErrorDetail::SignatureInvalid | AuthErrorDetail::TokenExpired => StatusCode::UNAUTHORIZED,
                AuthErrorDetail::JwksFetchFailed(_) | AuthErrorDetail::InvalidAuthConfig(_) => StatusCode::INTERNAL_SERVER_ERROR,
                AuthErrorDetail::IssuerMismatch { .. } | AuthErrorDetail::AudienceMismatch { .. } | AuthErrorDetail::InsufficientScope { .. } => StatusCode::FORBIDDEN,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use axum::{
        body::Body,
        extract::Extension, 
        middleware, 
        routing::get,
        Router
    };
    use tower::ServiceExt;
    use jsonwebtoken::{encode, EncodingKey, Header as JwtHeader, Algorithm};
    use jsonwebtoken::jwk::{JwkSet, AlgorithmParameters as JwkAlgorithmParameters, CommonParameters as JwkCommonParameters, RSAKeyParameters as JwkRSAKeyParameters, PublicKeyUse as JwkPublicKeyUse, Jwk, KeyAlgorithm};
    use jsonwebtoken::jwk::RSAKeyType; // Corrigido o caminho para RSAKeyType
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use std::time::Duration; 

    const TEST_KID_RS256: &str = "test-key-id-rs256";

    fn rsa_private_key_pem_for_test() -> String {
        // Chave RSA PEM de 2048 bits para testes (gerada e mantida localmente)
        // IMPORTANTE: Esta é uma chave de TESTE. NÃO use em produção.
        "-----BEGIN RSA PRIVATE KEY-----\\n\\
        MIIEowIBAAKCAQEA4gV5pG1kZ0h6msxPZPkPz5/g4zY2jP0yZ8Q8y7jQ8n7xZ0hN\\n\\
        ... (conteúdo da chave omitido para brevidade) ...\\n\\
        -----END RSA PRIVATE KEY-----".to_string()
    }

    fn rsa_public_jwk_for_test(_token_algorithm: Algorithm) -> Jwk {
        // JWK público correspondente à chave privada de teste
        // IMPORTANTE: Este é um JWK de TESTE. NÃO use em produção.

        let key_alg = match _token_algorithm {
            Algorithm::RS256 => Some(KeyAlgorithm::RS256), // Usar KeyAlgorithm diretamente
            Algorithm::RS384 => Some(KeyAlgorithm::RS384),
            Algorithm::RS512 => Some(KeyAlgorithm::RS512),
            _ => None,
        };

        Jwk {
            common: JwkCommonParameters {
                public_key_use: Some(JwkPublicKeyUse::Signature),
                key_operations: None,
                key_algorithm: key_alg,
                key_id: Some(TEST_KID_RS256.to_string()),
                x509_url: None,
                x509_chain: None,
                x509_sha1_fingerprint: None,
                x509_sha256_fingerprint: None,
            },
            algorithm: JwkAlgorithmParameters::RSA(JwkRSAKeyParameters {
                key_type: RSAKeyType::RSA, // Corrigido para RSAKeyType
                n: "4gV5pG1kZ0h6msxPZPkPz5_g4zY2jP0yZ8Q8y7jQ8n7xZ0hN...".to_string(),
                e: "AQAB".to_string(),
            }),
        }
    }

    // Função auxiliar para criar uma configuração OAuth de teste
    fn test_oauth_config(jwks_uri: String, enabled: bool) -> config::OAuth {
        config::OAuth {
            enabled,
            jwks_uri: Some(jwks_uri),
            issuer: Some(vec!["test-issuer".to_string()]),
            audience: Some(vec!["test-audience".to_string()]),
            required_scopes: None,
            jwks_request_timeout_seconds: Some(5),
            jwks_refresh_interval: Some(Duration::from_secs(300)), // Corrigido para Duration
        }
    }

    // Função auxiliar para criar um JwksCache de teste
    fn test_jwks_cache(jwks_uri: String, http_client: reqwest::Client) -> JwksCache {
        JwksCache::new(
            jwks_uri,
            Duration::from_secs(300), // refresh_interval
            http_client,
        )
    }

    // Função auxiliar para gerar um token JWT de teste
    fn generate_test_jwt(claims: &Claims, kid: &str, alg: Algorithm) -> String {
        let private_key_pem = rsa_private_key_pem_for_test();
        let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).unwrap();
        let mut header = JwtHeader::new(alg);
        header.kid = Some(kid.to_string());
        encode(&header, claims, &encoding_key).unwrap()
    }

    #[tokio::test]
    async fn test_oauth_middleware_valid_token() {
        let mock_server = MockServer::start().await;
        let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());

        let public_jwk = rsa_public_jwk_for_test(Algorithm::RS256);
        let jwks = JwkSet { keys: vec![public_jwk] };

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let oauth_config = Arc::new(test_oauth_config(jwks_uri.clone(), true));
        let http_client = reqwest::Client::new();
        let jwks_cache = Arc::new(test_jwks_cache(jwks_uri, http_client));

        // Forçar refresh inicial para popular o cache
        jwks_cache.refresh_keys().await.expect("Falha ao popular o cache JWKS antes do teste");
        assert!(jwks_cache.is_cache_ever_populated().await, "Cache JWKS não foi populado após refresh");


        let now = jsonwebtoken::get_current_timestamp();
        let claims = Claims {
            sub: "user123".to_string(),
            exp: (now + 3600) as usize, // Expira em 1 hora
            iat: Some(now as usize),
            nbf: Some(now as usize),
            iss: Some("test-issuer".to_string()),
            aud: Some(serde_json::json!(["test-audience"])),
            scope: Some("read write".to_string()),
        };
        let token = generate_test_jwt(&claims, TEST_KID_RS256, Algorithm::RS256);

        let app = Router::new()
            .route("/", get(|Extension(auth_ctx): Extension<Arc<ClientAuthContext>>| async move {
                assert_eq!(auth_ctx.user_id, "user123");
                assert!(auth_ctx.scopes.contains("read"));
                assert!(auth_ctx.scopes.contains("write"));
                StatusCode::OK
            }))
            .layer(middleware::from_fn_with_state((jwks_cache.clone(), oauth_config.clone()), oauth_middleware));

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/")
                    .header("Authorization", format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_oauth_middleware_disabled() {
        let oauth_config = Arc::new(test_oauth_config("".to_string(), false)); // OAuth desabilitado
        let http_client = reqwest::Client::new();
        // JwksCache não será usado, mas precisa ser fornecido
        let jwks_cache = Arc::new(test_jwks_cache("http://localhost/jwks".to_string(), http_client));


        let app = Router::new()
            .route("/", get(|| async { StatusCode::OK }))
            .layer(middleware::from_fn_with_state((jwks_cache, oauth_config), oauth_middleware));

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/")
                    // Sem header de autorização
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_oauth_middleware_no_auth_header_when_required() {
        let mock_server = MockServer::start().await;
        let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());
        let oauth_config = Arc::new(test_oauth_config(jwks_uri.clone(), true)); // OAuth habilitado
        let http_client = reqwest::Client::new();
        let jwks_cache = Arc::new(test_jwks_cache(jwks_uri, http_client));

        let app = Router::new()
            .route("/", get(|| async { StatusCode::OK })) // Handler não deve ser chamado
            .layer(middleware::from_fn_with_state((jwks_cache, oauth_config), oauth_middleware));

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/")
                    // Sem header de autorização
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Espera-se Unauthorized ou Forbidden, dependendo da implementação exata do erro
        // AuthErrorDetail::AuthHeaderMissing -> StatusCode::UNAUTHORIZED
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_oauth_middleware_invalid_token_bad_signature() {
        let mock_server = MockServer::start().await;
        let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());

        // JWKS com uma chave pública diferente da usada para assinar o token
        let mut wrong_public_jwk = rsa_public_jwk_for_test(Algorithm::RS256);
        // Modificar 'n' para simular uma chave diferente
        if let JwkAlgorithmParameters::RSA(ref mut rsa_params) = wrong_public_jwk.algorithm {
            rsa_params.n = "diferente-n-value".to_string();
        }
        let jwks_with_wrong_key = JwkSet { keys: vec![wrong_public_jwk] };


        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&jwks_with_wrong_key))
            .mount(&mock_server)
            .await;

        let oauth_config = Arc::new(test_oauth_config(jwks_uri.clone(), true));
        let http_client = reqwest::Client::new();
        let jwks_cache = Arc::new(test_jwks_cache(jwks_uri, http_client));
        jwks_cache.refresh_keys().await.unwrap(); // Popular o cache

        let now = jsonwebtoken::get_current_timestamp();
        let claims = Claims {
            sub: "user123".to_string(), exp: (now + 3600) as usize, iat: Some(now as usize),
            nbf: Some(now as usize), iss: Some("test-issuer".to_string()),
            aud: Some(serde_json::json!(["test-audience"])), scope: Some("read".to_string()),
        };
        // Token assinado com a chave de teste correta
        let token = generate_test_jwt(&claims, TEST_KID_RS256, Algorithm::RS256);


        let app = Router::new()
            .route("/", get(|| async { StatusCode::OK }))
            .layer(middleware::from_fn_with_state((jwks_cache, oauth_config), oauth_middleware));

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/")
                    .header("Authorization", format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // AuthErrorDetail::TokenInvalid com SignatureInvalid -> StatusCode::UNAUTHORIZED
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_oauth_middleware_expired_token() {
        let mock_server = MockServer::start().await;
        let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());
        let public_jwk = rsa_public_jwk_for_test(Algorithm::RS256);
        let jwks = JwkSet { keys: vec![public_jwk] };
        Mock::given(method("GET")).and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server).await;

        let oauth_config = Arc::new(test_oauth_config(jwks_uri.clone(), true));
        let http_client = reqwest::Client::new();
        let jwks_cache = Arc::new(test_jwks_cache(jwks_uri, http_client));
        jwks_cache.refresh_keys().await.unwrap();

        let now = jsonwebtoken::get_current_timestamp();
        let claims = Claims {
            sub: "user123".to_string(),
            exp: (now - 3600) as usize, // Expired 1 hora atrás
            iat: Some((now - 7200) as usize), nbf: Some((now - 7200) as usize),
            iss: Some("test-issuer".to_string()), aud: Some(serde_json::json!(["test-audience"])),
            scope: Some("read".to_string()),
        };
        let token = generate_test_jwt(&claims, TEST_KID_RS256, Algorithm::RS256);

        let app = Router::new().route("/", get(|| async { StatusCode::OK }))
            .layer(middleware::from_fn_with_state((jwks_cache, oauth_config), oauth_middleware));

        let response = app.oneshot(axum::http::Request::builder().uri("/")
            .header("Authorization", format!("Bearer {}", token)).body(Body::empty()).unwrap()
        ).await.unwrap();
        // AuthErrorDetail::TokenInvalid com ExpiredSignature -> StatusCode::UNAUTHORIZED
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }


    #[tokio::test]
    async fn test_jwks_cache_refresh_and_get_key() {
        let mock_server = MockServer::start().await;
        let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());

        let public_jwk_rs256 = rsa_public_jwk_for_test(Algorithm::RS256);
        let jwks = JwkSet { keys: vec![public_jwk_rs256.clone()] };

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let http_client = reqwest::Client::new();
        let cache = test_jwks_cache(jwks_uri, http_client);

        assert!(!cache.is_cache_ever_populated().await, "Cache não deveria estar populado inicialmente");

        // Test refresh_keys
        let refresh_result = cache.refresh_keys().await;
        assert!(refresh_result.is_ok(), "Falha ao atualizar chaves JWKS: {:?}", refresh_result.err());
        assert!(cache.is_cache_ever_populated().await, "Cache deveria estar populado após refresh");


        // Test get_decoding_key_for_kid com KID existente
        let decoding_key_result = cache.get_decoding_key_for_kid(TEST_KID_RS256).await;
        assert!(decoding_key_result.is_ok(), "Erro ao obter chave de decodificação: {:?}", decoding_key_result.err());
        assert!(decoding_key_result.unwrap().is_some(), "Chave de decodificação não encontrada para KID existente");

        // Test get_decoding_key_for_kid com KID inexistente
        let decoding_key_result_unknown = cache.get_decoding_key_for_kid("unknown-kid").await;
        assert!(decoding_key_result_unknown.is_ok(), "Erro ao obter chave para KID desconhecido: {:?}", decoding_key_result_unknown.err());
        assert!(decoding_key_result_unknown.unwrap().is_none(), "Chave encontrada para KID desconhecido inesperadamente");
    }

    #[tokio::test]
    async fn test_jwks_cache_handles_http_error_on_refresh() {
        let mock_server = MockServer::start().await;
        let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(500)) // Simula erro de servidor
            .mount(&mock_server)
            .await;

        let http_client = reqwest::Client::new();
        let cache = test_jwks_cache(jwks_uri, http_client);

        let refresh_result = cache.refresh_keys().await;
        assert!(refresh_result.is_err(), "Atualização de JWKS deveria falhar com erro HTTP");
        // Corrigido para JwksFetchFailed
        if let Err(AuthErrorDetail::JwksFetchFailed(_)) = refresh_result {
            // Correto
        } else {
            panic!("Erro inesperado: {:?}", refresh_result);
        }
        assert!(!cache.is_cache_ever_populated().await, "Cache não deveria ser populado após falha no refresh");
    }
}