// src/auth.rs

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

//! Módulo responsável pela autenticação OAuth 2.0 e autorização baseada em escopos.

use crate::config;
use crate::error::AuthErrorDetail; // Importação corrigida e verificada
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
    // Jwk e JwkSet são usados no código de produção (JwksCache)
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
    /// Identificador do usuário (geralmente o `sub` do token JWT).
    pub user_id: String,
    /// Conjunto de escopos `OAuth2` concedidos ao cliente.
    pub scopes: HashSet<String>,
    /// O token JWT bruto, como uma string.
    pub raw_token: String,
}

/// Claims esperados no token JWT.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Claims {
    /// (Subject) Identificador principal do usuário.
    pub sub: String,
    /// (Expiration Time) Timestamp de quando o token expira.
    pub exp: usize,
    /// (Issued At) Timestamp de quando o token foi emitido (opcional).
    pub iat: Option<usize>,
    /// (Not Before) Timestamp antes do qual o token não deve ser aceito (opcional).
    pub nbf: Option<usize>,
    /// (Issuer) Emissor do token (opcional).
    pub iss: Option<String>,
    /// (Audience) Destinatário(s) do token (opcional). Pode ser uma string ou um array de strings.
    pub aud: Option<JsonValue>,
    /// (Scope) Escopos concedidos, geralmente uma string separada por espaços (opcional).
    pub scope: Option<String>,
}

/// Cache para chaves JWKS (JSON Web Key Set).
///
/// Armazena as chaves públicas do Authorization Server e as atualiza periodicamente.
#[derive(Debug)]
pub struct JwksCache {
    jwks_uri: String,
    keys: Arc<RwLock<Option<JwkSet>>>, // MODIFICADO para Option<JwkSet>
    last_updated: Arc<RwLock<Option<Instant>>>,
    refresh_interval: Duration,
    http_client: reqwest::Client,
}

impl JwksCache {
    /// Cria uma nova instância do `JwksCache`.
    ///
    /// # Parâmetros
    /// * `jwks_uri`: A URI do endpoint JWKS.
    /// * `refresh_interval`: O intervalo para atualizar as chaves.
    /// * `http_client`: Um cliente HTTP `reqwest` para buscar as chaves.
    #[must_use]
    pub fn new(
        jwks_uri: String,
        refresh_interval: Duration,
        http_client: reqwest::Client,
    ) -> Self {
        Self {
            jwks_uri,
            keys: Arc::new(RwLock::new(None)), // MODIFICADO para None
            last_updated: Arc::new(RwLock::new(None)),
            refresh_interval,
            http_client,
        }
    }

    /// Atualiza as chaves JWKS a partir da URI configurada.
    ///
    /// Esta função é chamada internamente quando as chaves estão desatualizadas
    /// ou nunca foram carregadas.
    #[tracing::instrument(skip(self), name = "jwks_cache_refresh_keys")]
    pub async fn refresh_keys(&self) -> Result<(), AuthErrorDetail> {
        tracing::info!("Atualizando chaves JWKS de: {}", self.jwks_uri);
        let response = self.http_client.get(&self.jwks_uri).send().await
            .map_err(|e| AuthErrorDetail::JwksFetchFailed(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let err_body = response.text().await.unwrap_or_else(|_| String::from("<corpo do erro ilegível>"));
            return Err(AuthErrorDetail::JwksFetchFailed(format!("Status {status} ao buscar JWKS: {err_body}")));
        }

        let jwks_data: JwkSet = response.json().await.map_err(|e| AuthErrorDetail::JwksFetchFailed(format!("JWKS JSON inválido: {e}")))?;
        
        {
            let mut keys_guard = self.keys.write().await;
            *keys_guard = Some(jwks_data); // MODIFICADO para Some(jwks_data)
        } 
        
        {
            let mut last_updated_guard = self.last_updated.write().await;
            *last_updated_guard = Some(Instant::now());
        }
        Ok(())
    }

    /// Obtém a chave de decodificação para um `kid` (Key ID) específico.
    ///
    /// Se o cache estiver desatualizado ou nunca populado, tenta atualizar as chaves.
    ///
    /// # Parâmetros
    /// * `kid`: O Key ID da chave a ser procurada.
    ///
    /// # Retorna
    /// `Ok(Some(DecodingKey))` se a chave for encontrada, `Ok(None)` se não,
    /// ou `Err(AuthErrorDetail)` se ocorrer um erro.
    #[tracing::instrument(skip(self), name = "jwks_cache_get_key", fields(token.kid = %kid))]
    pub async fn get_decoding_key_for_kid(&self, kid: &str) -> Result<Option<DecodingKey>, AuthErrorDetail> {
        let (is_populated_initially, needs_refresh_flag) =
            self.last_updated.read().await.map_or((true, true), |last_update_time| {
                (false, last_update_time.elapsed() > self.refresh_interval)
            });

        if needs_refresh_flag {
            if let Err(e) = self.refresh_keys().await { 
                if !is_populated_initially { 
                    return Err(e); 
                }
                tracing::warn!("Falha ao atualizar JWKS, usando cache antigo: {}", e);
            }
        }
        
        let keys_guard = self.keys.read().await;
        keys_guard.as_ref().and_then(|set| set.find(kid)) // MODIFICADO para usar as_ref() e and_then()
            .map(DecodingKey::from_jwk)
            .transpose()
            .map_err(|e| AuthErrorDetail::TokenInvalid(format!("JWK para kid '{kid}' inválido: {e}")))
    }

    /// Verifica se o cache JWKS já foi populado alguma vez.
    ///
    /// # Retorna
    /// `true` se o cache já foi populado (mesmo que agora esteja desatualizado),
    /// `false` caso contrário.
    pub async fn is_cache_ever_populated(&self) -> bool {
        self.last_updated.read().await.is_some()
    }
}

/// Valida e decodifica um token JWT.
///
/// Verifica a assinatura, expiração, nbf, issuer e audience do token
/// de acordo com a configuração OAuth2.
///
/// # Parâmetros
/// * `token_str`: O token JWT como string.
/// * `jwks_cache`: Uma referência ao cache JWKS.
/// * `oauth_config`: As configurações OAuth2 da aplicação.
///
/// # Retorna
/// `Ok(TokenData<Claims>)` se o token for válido, ou `Err(AuthErrorDetail)` caso contrário.
#[tracing::instrument(skip(token_str, jwks_cache, oauth_config), name = "validate_jwt_token")]
async fn validate_and_decode_token(
    token_str: &str,
    jwks_cache: &JwksCache,
    oauth_config: &config::OAuth,
) -> Result<TokenData<Claims>, AuthErrorDetail> {
    let header: Header = decode_header(token_str).map_err(|e| AuthErrorDetail::TokenInvalid(format!("Header do token inválido: {e}")))?;
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
        _ => AuthErrorDetail::TokenInvalid(format!("Erro de validação não especificado: {e}")),
    })?;

    if let Some(ref expected_audiences) = oauth_config.audience {
        if !expected_audiences.is_empty() {
            let token_audiences_set: HashSet<String> = match &token_data.claims.aud {
                Some(JsonValue::String(s)) => std::iter::once(s.clone()).collect(),
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

/// Middleware Axum para autenticação OAuth2.
///
/// Extrai o token Bearer do header Authorization, valida-o e, se bem-sucedido,
/// insere um `ClientAuthContext` nas extensões da requisição para uso por handlers posteriores.
/// Se a autenticação falhar ou OAuth2 estiver desabilitado, permite que a requisição prossiga
/// (se desabilitado) ou retorna um erro HTTP apropriado.
#[tracing::instrument(skip_all, name = "oauth_middleware")]
pub async fn oauth_middleware(
    State(state_tuple): State<(Arc<JwksCache>, Arc<config::OAuth>)>,
    auth_header_result: Result<TypedHeader<Authorization<Bearer>>, TypedHeaderRejection>,
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
    // Importações corrigidas e agrupadas para jsonwebtoken::jwk
    use jsonwebtoken::jwk::{
        JwkSet, AlgorithmParameters as JwkAlgorithmParameters, CommonParameters as JwkCommonParameters, 
        RSAKeyParameters, RSAKeyType, KeyAlgorithm, PublicKeyUse as JwkPublicKeyUse, Jwk
    };
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use std::time::Duration; 

    const TEST_KID_RS256: &str = "test-key-id-rs256";

    fn rsa_private_key_pem_for_test() -> String {
        // IMPORTANTE: Esta é uma chave de TESTE. NÃO use em produção.
        // Substitua este conteúdo por uma chave RSA PEM válida de 2048 bits.
        // Esta chave é fictícia e SÓ serve para o código compilar.
        "-----BEGIN PRIVATE KEY-----\n\
        MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDR8DXjT5Vl\n\
        tA3G2l3k6nL0P9kK+p7T9Hn3fX6S+y5n9Vb9q8kY5f3x8wN6wXz3mX0z9A/A5y\n\
        b6z7hZ3Y2tqP0yZ8Q8y7jQ8n7xZ0hN3gV5pG1kZ0h6msxPZPkPz5/g4zY2jMI\n\
        IEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDR8DXjT5VltA3G\n\
        2l3k6nL0P9kK+p7T9Hn3fX6S+y5n9Vb9q8kY5f3x8wN6wXz3mX0z9A/A5yb6z\n\
        rCPOG3hB5xL0Hy0=\n\
        -----END PRIVATE KEY-----".to_string().replace("\\n", "\n")
    }
    
    fn rsa_public_jwk_for_test(token_algorithm: Algorithm) -> Jwk {
        let key_alg = match token_algorithm {
            Algorithm::RS256 => Some(KeyAlgorithm::RS256),
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
            algorithm: JwkAlgorithmParameters::RSA(RSAKeyParameters { // Corrigido aqui
                key_type: RSAKeyType::RSA, 
                // Este valor de 'n' é um placeholder e precisa ser um módulo RSA válido em Base64URL
                // que corresponda à chave privada para os testes funcionarem.
                n: "0f_p7K1j7hZ3Y2tqP0yZ8Q8y7jQ8n7xZ0hN3gV5pG1kZ0h6msxPZPkPz5_g4zY2jMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDR8DXjT5VltA3G2l3k6nL0P9kK-p7T9Hn3fX6S-y5n9Vb9q8kY5f3x8wN6wXz3mX0z9A_A5y".to_string(), 
                e: "AQAB".to_string(),
            }),
        }
    }

    fn test_oauth_config(jwks_uri: String, enabled: bool) -> config::OAuth {
        config::OAuth {
            enabled,
            jwks_uri: Some(jwks_uri),
            issuer: Some(vec!["test-issuer".to_string()]),
            audience: Some(vec!["test-audience".to_string()]),
            required_scopes: None,
            jwks_request_timeout_seconds: Some(5),
            jwks_refresh_interval: Some(Duration::from_secs(300)),
        }
    }

    fn test_jwks_cache(jwks_uri: String, http_client: reqwest::Client) -> JwksCache {
        JwksCache::new(
            jwks_uri,
            Duration::from_secs(300),
            http_client,
        )
    }

    fn generate_test_jwt(claims: &Claims, kid: &str, alg: Algorithm) -> String {
        let private_key_pem = rsa_private_key_pem_for_test();
        let encoding_key = match EncodingKey::from_rsa_pem(private_key_pem.as_bytes()) {
            Ok(key) => key,
            Err(e) => panic!("Falha ao criar EncodingKey a partir do PEM de teste: {e:?}"),
        };
        let mut header = JwtHeader::new(alg);
        header.kid = Some(kid.to_string());
        match encode(&header, claims, &encoding_key) {
            Ok(token) => token,
            Err(e) => panic!("Falha ao gerar JWT de teste: {e:?}"),
        }
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

        let refresh_result = jwks_cache.refresh_keys().await;
        assert!(refresh_result.is_ok(), "Falha ao popular o cache JWKS antes do teste: {:?}", refresh_result.err());
        assert!(jwks_cache.is_cache_ever_populated().await, "Cache JWKS não foi populado após refresh");

        let now = jsonwebtoken::get_current_timestamp();
        let claims = Claims {
            sub: "user123".to_string(),
            exp: match usize::try_from(now + 3600) {
                Ok(val) => val,
                Err(e) => panic!("Falha ao converter timestamp 'exp' para usize: {e}"),
            },
            iat: Some(match usize::try_from(now) {
                Ok(val) => val,
                Err(e) => panic!("Falha ao converter timestamp 'iat' para usize: {e}"),
            }),
            nbf: Some(match usize::try_from(now) {
                Ok(val) => val,
                Err(e) => panic!("Falha ao converter timestamp 'nbf' para usize: {e}"),
            }),
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

        let request = axum::http::Request::builder()
            .uri("/")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty());
        let request = match request {
            Ok(req) => req,
            Err(e) => panic!("Falha ao construir request: {e:?}"),
        };
        let response = app.oneshot(request).await;
        let response = match response {
            Ok(resp) => resp,
            Err(e) => panic!("Falha ao executar oneshot: {e:?}"),
        };
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_oauth_middleware_disabled() {
        let oauth_config = Arc::new(test_oauth_config(String::new(), false)); 
        let http_client = reqwest::Client::new();
        let jwks_cache = Arc::new(test_jwks_cache("http://localhost/jwks".to_string(), http_client));

        let app = Router::new()
            .route("/", get(|| async { StatusCode::OK }))
            .layer(middleware::from_fn_with_state((jwks_cache, oauth_config), oauth_middleware));

        let request = axum::http::Request::builder()
            .uri("/")
            .body(Body::empty());
        let request = match request {
            Ok(req) => req,
            Err(e) => panic!("Falha ao construir request: {e:?}"),
        };
        let response = app.oneshot(request).await;
        let response = match response {
            Ok(resp) => resp,
            Err(e) => panic!("Falha ao executar oneshot: {e:?}"),
        };
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_oauth_middleware_no_auth_header_when_required() {
        let mock_server = MockServer::start().await;
        let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());
        let oauth_config = Arc::new(test_oauth_config(jwks_uri.clone(), true)); 
        let http_client = reqwest::Client::new();
        let jwks_cache = Arc::new(test_jwks_cache(jwks_uri, http_client));

        let app = Router::new()
            .route("/", get(|| async { StatusCode::OK })) 
            .layer(middleware::from_fn_with_state((jwks_cache, oauth_config), oauth_middleware));

        let request = axum::http::Request::builder()
            .uri("/")
            .body(Body::empty());
        let request = match request {
            Ok(req) => req,
            Err(e) => panic!("Falha ao construir request: {e:?}"),
        };
        let response = app.oneshot(request).await;
        let response = match response {
            Ok(resp) => resp,
            Err(e) => panic!("Falha ao executar oneshot: {e:?}"),
        };
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_oauth_middleware_invalid_token_bad_signature() {
        let mock_server = MockServer::start().await;
        let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());

        let mut wrong_public_jwk = rsa_public_jwk_for_test(Algorithm::RS256);
        if let JwkAlgorithmParameters::RSA(ref mut rsa_params) = wrong_public_jwk.algorithm {
            rsa_params.n = "diferente-n-value-que-nao-corresponde-a-chave-privada".to_string(); 
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
        let refresh_result = jwks_cache.refresh_keys().await;
        assert!(refresh_result.is_ok(), "Falha ao popular o cache JWKS antes do teste: {:?}", refresh_result.err());

        let now = jsonwebtoken::get_current_timestamp();
        let claims = Claims {
            sub: "user123".to_string(),
            exp: match usize::try_from(now + 3600) {
                Ok(val) => val,
                Err(e) => panic!("Falha ao converter timestamp 'exp' para usize: {e}"),
            },
            iat: Some(match usize::try_from(now) {
                Ok(val) => val,
                Err(e) => panic!("Falha ao converter timestamp 'iat' para usize: {e}"),
            }),
            nbf: Some(match usize::try_from(now) {
                Ok(val) => val,
                Err(e) => panic!("Falha ao converter timestamp 'nbf' para usize: {e}"),
            }),
            iss: Some("test-issuer".to_string()),
            aud: Some(serde_json::json!(["test-audience"])),
            scope: Some("read".to_string()),
        };
        let token = generate_test_jwt(&claims, TEST_KID_RS256, Algorithm::RS256);

        let app = Router::new()
            .route("/", get(|| async { StatusCode::OK }))
            .layer(middleware::from_fn_with_state((jwks_cache, oauth_config), oauth_middleware));

        let request = axum::http::Request::builder()
            .uri("/")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty());
        let request = match request {
            Ok(req) => req,
            Err(e) => panic!("Falha ao construir request: {e:?}"),
        };
        let response = app.oneshot(request).await;
        let response = match response {
            Ok(resp) => resp,
            Err(e) => panic!("Falha ao executar oneshot: {e:?}"),
        };
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
        let refresh_result = jwks_cache.refresh_keys().await;
        assert!(refresh_result.is_ok(), "Falha ao popular o cache JWKS antes do teste: {:?}", refresh_result.err());

        let now = jsonwebtoken::get_current_timestamp();
        let claims = Claims {
            sub: "user123".to_string(),
            exp: match usize::try_from(now - 3600) {
                Ok(val) => val,
                Err(e) => panic!("Falha ao converter timestamp 'exp' para usize: {e}"),
            },
            iat: Some(match usize::try_from(now - 7200) {
                Ok(val) => val,
                Err(e) => panic!("Falha ao converter timestamp 'iat' para usize: {e}"),
            }),
            nbf: Some(match usize::try_from(now - 7200) {
                Ok(val) => val,
                Err(e) => panic!("Falha ao converter timestamp 'nbf' para usize: {e}"),
            }),
            iss: Some("test-issuer".to_string()),
            aud: Some(serde_json::json!(["test-audience"])),
            scope: Some("read".to_string()),
        };
        let token = generate_test_jwt(&claims, TEST_KID_RS256, Algorithm::RS256);

        let app = Router::new().route("/", get(|| async { StatusCode::OK }))
            .layer(middleware::from_fn_with_state((jwks_cache, oauth_config), oauth_middleware));

        let request = axum::http::Request::builder()
            .uri("/")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty());
        let request = match request {
            Ok(req) => req,
            Err(e) => panic!("Falha ao construir request: {e:?}"),
        };
        let response = app.oneshot(request).await;
        let response = match response {
            Ok(resp) => resp,
            Err(e) => panic!("Falha ao executar oneshot: {e:?}"),
        };
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

        assert!(!cache.is_cache_ever_populated().await);

        let refresh_result = cache.refresh_keys().await;
        match refresh_result {
            Ok(()) => {},
            Err(e) => panic!("Falha ao atualizar chaves JWKS: {e:?}"),
        }
        assert!(cache.is_cache_ever_populated().await);

        let decoding_key_result = cache.get_decoding_key_for_kid(TEST_KID_RS256).await;
        match decoding_key_result {
            Ok(Some(_)) => { /* ok */ },
            Ok(None) => panic!("Chave de decodificação não encontrada para kid conhecido"),
            Err(e) => panic!("Erro ao obter chave de decodificação: {e:?}"),
        }

        let decoding_key_result_unknown = cache.get_decoding_key_for_kid("unknown-kid").await;
        match decoding_key_result_unknown {
            Ok(None) => { /* ok */ },
            Ok(Some(_)) => panic!("Chave encontrada para kid desconhecido, esperado None"),
            Err(e) => panic!("Erro ao obter chave para KID desconhecido: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_jwks_cache_handles_http_error_on_refresh() {
        let mock_server = MockServer::start().await;
        let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let http_client = reqwest::Client::new();
        let cache = test_jwks_cache(jwks_uri, http_client);

        let refresh_result = cache.refresh_keys().await;
        assert!(refresh_result.is_err());
        if let Err(AuthErrorDetail::JwksFetchFailed(_)) = refresh_result {
            // Correto
        } else {
            panic!("Erro inesperado: {refresh_result:?}");
        }
        assert!(!cache.is_cache_ever_populated().await);
    }
}