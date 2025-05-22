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
/// Armazena informações extraídas de um token JWT válido.
#[derive(Clone, Debug)]
pub struct ClientAuthContext {
    /// Identificador do usuário (geralmente o claim `sub` do token JWT).
    pub user_id: String,
    /// Conjunto de escopos OAuth2 concedidos ao cliente, parseados do claim `scope`.
    pub scopes: HashSet<String>,
    /// O token JWT bruto original, como uma string, para possível referência futura.
    pub raw_token: String,
}

/// Claims esperados e desserializáveis de um token JWT.
/// Esta struct define os campos padrão que o servidor tentará extrair do payload do token.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Claims {
    /// (Subject) Identificador principal do usuário.
    pub sub: String,
    /// (Expiration Time) Timestamp Unix de quando o token expira. Validação obrigatória.
    pub exp: usize,
    /// (Issued At) Timestamp Unix de quando o token foi emitido. Opcional.
    pub iat: Option<usize>,
    /// (Not Before) Timestamp Unix antes do qual o token não deve ser aceito. Opcional.
    pub nbf: Option<usize>,
    /// (Issuer) Emissor do token. Opcional, mas validado se configurado no servidor.
    pub iss: Option<String>,
    /// (Audience) Destinatário(s) do token. Opcional, mas validado se configurado no servidor.
    /// Pode ser uma string única ou um array de strings no JSON do token.
    pub aud: Option<JsonValue>,
    /// (Scope) Escopos concedidos, geralmente uma string separada por espaços. Opcional.
    pub scope: Option<String>,
}

/// Cache para chaves JWKS (JSON Web Key Set).
///
/// Armazena as chaves públicas do Authorization Server obtidas do `jwks_uri`
/// e as atualiza periodicamente conforme `refresh_interval`.
#[derive(Debug)]
pub struct JwksCache {
    jwks_uri: String,
    keys: Arc<RwLock<Option<JwkSet>>>,
    last_updated: Arc<RwLock<Option<Instant>>>,
    refresh_interval: Duration,
    http_client: reqwest::Client,
}

impl JwksCache {
    /// Cria uma nova instância do `JwksCache`.
    ///
    /// # Arguments
    /// * `jwks_uri`: A URI do endpoint JWKS do provedor de identidade.
    /// * `refresh_interval`: O intervalo no qual o cache tentará atualizar as chaves.
    /// * `http_client`: Um cliente `reqwest::Client` para realizar as buscas HTTP.
    #[must_use]
    pub fn new(
        jwks_uri: String,
        refresh_interval: Duration,
        http_client: reqwest::Client,
    ) -> Self {
        Self {
            jwks_uri,
            keys: Arc::new(RwLock::new(None)),
            last_updated: Arc::new(RwLock::new(None)),
            refresh_interval,
            http_client,
        }
    }

    /// Atualiza as chaves JWKS a partir da URI configurada.
    /// Esta função é chamada internamente quando as chaves estão desatualizadas,
    /// nunca foram carregadas, ou uma chave específica não é encontrada.
    #[tracing::instrument(skip(self), name = "jwks_cache_refresh_keys")]
    pub async fn refresh_keys(&self) -> Result<(), AuthErrorDetail> {
        tracing::info!("Atualizando chaves JWKS de: {}", self.jwks_uri);
        let response = self.http_client.get(&self.jwks_uri).send().await
            .map_err(|e| {
                tracing::error!("Erro na requisição HTTP ao buscar JWKS de {}: {}", self.jwks_uri, e);
                AuthErrorDetail::JwksFetchFailed(format!("Erro HTTP ao buscar JWKS: {}", e))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let err_body = response.text().await.unwrap_or_else(|_| String::from("<corpo do erro ilegível>"));
            tracing::warn!("Falha ao buscar JWKS: Status {}, Corpo: {}", status, err_body);
            return Err(AuthErrorDetail::JwksFetchFailed(format!("Status {} ao buscar JWKS: {}", status, err_body)));
        }

        let jwks_data: JwkSet = response.json().await.map_err(|e| {
            tracing::error!("JWKS JSON inválido recebido de {}: {}", self.jwks_uri, e);
            AuthErrorDetail::JwksFetchFailed(format!("JWKS JSON inválido: {}", e))
        })?;
        
        tracing::debug!("JWKS recebido com {} chaves de {}.", jwks_data.keys.len(), self.jwks_uri);
        {
            let mut keys_guard = self.keys.write().await;
            *keys_guard = Some(jwks_data);
        } 
        {
            let mut last_updated_guard = self.last_updated.write().await;
            *last_updated_guard = Some(Instant::now());
        }
        tracing::info!("Chaves JWKS atualizadas com sucesso de {}", self.jwks_uri);
        Ok(())
    }

    /// Obtém a chave de decodificação (`DecodingKey`) para um `kid` (Key ID) específico.
    /// Se o cache estiver desatualizado, ou a chave com o `kid` não for encontrada no cache atual,
    /// tenta atualizar as chaves do `jwks_uri`.
    #[tracing::instrument(skip(self), name = "jwks_cache_get_key", fields(token.kid = %kid))]
    pub async fn get_decoding_key_for_kid(&self, kid: &str) -> Result<Option<DecodingKey>, AuthErrorDetail> {
        let needs_initial_fetch = self.last_updated.read().await.is_none();
        let mut needs_refresh = self
            .last_updated
            .read()
            .await
            .map_or(true, |last_update_time| last_update_time.elapsed() > self.refresh_interval);

        // Tenta encontrar a chave no cache atual primeiro
        if !needs_initial_fetch && !needs_refresh {
            if let Some(jwk_set) = self.keys.read().await.as_ref() {
                if let Some(jwk) = jwk_set.find(kid) {
                    return DecodingKey::from_jwk(jwk).map_err(|e| {
                        AuthErrorDetail::TokenInvalid(format!("JWK para kid '{}' (do cache) inválido: {}", kid, e))
                    }).map(Some);
                }
                // Kid não encontrado no cache, forçar refresh
                needs_refresh = true; 
            } else {
                // Cache está None, mas não era para ser um fetch inicial. Estranho, mas forçar refresh.
                needs_refresh = true;
            }
        }

        // Se for fetch inicial, ou refresh forçado, ou kid não encontrado no cache válido
        if needs_initial_fetch || needs_refresh {
            if let Err(e) = self.refresh_keys().await { 
                if self.keys.read().await.is_none() {
                    tracing::error!("Falha crítica ao buscar JWKS pela primeira vez ou cache vazio: {}", e);
                    return Err(e); 
                }
                tracing::warn!("Falha ao atualizar JWKS (tentando usar cache antigo se disponível): {}", e);
            }
        }
        
        // Tentar novamente com o cache (potencialmente atualizado)
        let keys_guard = self.keys.read().await;
        match keys_guard.as_ref() {
            Some(jwk_set) => {
                match jwk_set.find(kid) {
                    Some(jwk) => {
                        DecodingKey::from_jwk(jwk).map_err(|e| {
                            AuthErrorDetail::TokenInvalid(format!("JWK para kid '{}' (pós-refresh) inválido: {}", kid, e))
                        }).map(Some)
                    }
                    None => {
                        tracing::warn!("Kid '{}' não encontrado no cache JWKS mesmo após tentativa de refresh.", kid);
                        Ok(None)
                    }
                }
            }
            None => {
                tracing::warn!("Cache JWKS continua vazio após tentativa de refresh, não foi possível encontrar kid '{}'.", kid);
                Ok(None)
            }
        }
    }

    /// Verifica se o cache JWKS já foi populado com sucesso pelo menos uma vez.
    /// Usado pelo health check `/readyz`.
    pub async fn is_cache_ever_populated(&self) -> bool {
        self.last_updated.read().await.is_some() && self.keys.read().await.is_some()
    }
}

/// Valida e decodifica um token JWT.
///
/// Verifica a assinatura, expiração, `nbf` (Not Before), `iss` (Issuer) e `aud` (Audience)
/// do token de acordo com as chaves públicas do `JwksCache` e as configurações `config::OAuth`.
#[tracing::instrument(skip(token_str, jwks_cache, oauth_config), name = "validate_jwt_token")]
async fn validate_and_decode_token(
    token_str: &str,
    jwks_cache: &JwksCache,
    oauth_config: &config::OAuth,
) -> Result<TokenData<Claims>, AuthErrorDetail> {
    let header: Header = decode_header(token_str)
        .map_err(|e| AuthErrorDetail::TokenInvalid(format!("Header do token inválido: {}", e)))?;
    
    let kid = header.kid.as_deref()
        .ok_or_else(|| {
            tracing::warn!("Token JWT não possui o campo 'kid' no header.");
            AuthErrorDetail::KidNotFoundInJwks // Consideramos Kid ausente como se não fosse encontrado
        })?;
    
    let alg: Algorithm = header.alg;
    // Opcional: Filtrar algoritmos suportados, se necessário.
    // Ex: if alg != Algorithm::RS256 { return Err(...) }

    let decoding_key = jwks_cache.get_decoding_key_for_kid(kid).await?
        .ok_or_else(|| {
            tracing::warn!("Kid '{}' do token não encontrado no JWKS fornecido por '{}'.", kid, jwks_cache.jwks_uri);
            AuthErrorDetail::KidNotFoundInJwks
        })?;

    let mut validation = Validation::new(alg);
    validation.validate_exp = true;
    validation.validate_nbf = true; 
    // `leeway` é definido diretamente na struct `Validation`, o default é 0.
    // Se `config::OAuth` tivesse `validation_leeway_seconds`, seria usado aqui.
    // Por agora, vamos usar um leeway fixo ou o default da lib (0).
    validation.leeway = 60; // Leeway de 60 segundos para clock skew.

    if let Some(ref issuers) = oauth_config.issuer {
        if !issuers.is_empty() {
            // `Validation::set_issuer` expects `&[T]` where T: ToString.
            // `issuers` is `&Vec<String>`, which can be passed directly as it coerces to `&[String]`.
            validation.set_issuer(issuers);
        }
    }
    if let Some(ref audiences) = oauth_config.audience {
        if !audiences.is_empty() {
            // `Validation::set_audience` expects `&[T]` where T: ToString.
            // `audiences` is `&Vec<String>`, which can be passed directly as it coerces to `&[String]`.
            validation.set_audience(audiences);
        }
    }

    let token_data: TokenData<Claims> = decode::<Claims>(token_str, &decoding_key, &validation)
        .map_err(|e| match e.kind() {
            JwtErrorKind::InvalidToken => AuthErrorDetail::TokenInvalid("Formato de token inválido".to_string()),
            JwtErrorKind::InvalidSignature => AuthErrorDetail::SignatureInvalid,
            JwtErrorKind::ExpiredSignature => AuthErrorDetail::TokenExpired,
            JwtErrorKind::InvalidIssuer => AuthErrorDetail::IssuerMismatch {
                expected: oauth_config.issuer.clone().unwrap_or_default(),
                found: None, // Pode ser melhorado para extrair o 'iss' do token se a lib permitir
            },
            JwtErrorKind::InvalidAudience => AuthErrorDetail::AudienceMismatch {
                expected: oauth_config.audience.clone().unwrap_or_default(),
                found: None, // Pode ser melhorado para extrair o 'aud' do token
            },
            JwtErrorKind::ImmatureSignature => AuthErrorDetail::TokenInvalid("Token ainda não é válido (nbf)".to_string()),
            _ => AuthErrorDetail::TokenInvalid(format!("Erro de validação JWT não especificado: {}", e)),
        })?;

    // Validação de audience mais robusta (se 'aud' for um array no token)
    if let Some(ref expected_audiences) = oauth_config.audience {
        if !expected_audiences.is_empty() {
            let token_audiences_set: HashSet<String> = match &token_data.claims.aud {
                Some(JsonValue::String(s)) => std::iter::once(s.clone()).collect(),
                Some(JsonValue::Array(arr)) => arr.iter().filter_map(|v| v.as_str().map(String::from)).collect(),
                _ => HashSet::new(),
            };
            if token_audiences_set.is_empty() && !expected_audiences.is_empty() {
                 tracing::warn!("Token não possui claim 'aud' mas audiences esperados são: {:?}", expected_audiences);
                 return Err(AuthErrorDetail::AudienceMismatch { expected: expected_audiences.clone(), found: None });
            }
            if !expected_audiences.iter().any(|expected_aud| token_audiences_set.contains(expected_aud)) {
                tracing::warn!("Claim 'aud' do token ({:?}) não corresponde a nenhum dos esperados ({:?})", token_audiences_set, expected_audiences);
                return Err(AuthErrorDetail::AudienceMismatch {
                    expected: expected_audiences.clone(),
                    found: Some(token_audiences_set.into_iter().collect()),
                });
            }
        }
    }
    // Validação de escopos gerais do servidor
    if let Some(ref required_scopes_for_server) = oauth_config.required_scopes {
        if !required_scopes_for_server.is_empty() {
            let client_scopes_str = token_data.claims.scope.as_deref().unwrap_or_default();
            let client_scopes_set: HashSet<String> = client_scopes_str.split(' ').filter(|s| !s.is_empty()).map(String::from).collect();
            
            if !required_scopes_for_server.iter().all(|req_scope| client_scopes_set.contains(req_scope)) {
                 tracing::warn!("Token não possui todos os escopos gerais requeridos pelo servidor. Requeridos: {:?}, Possuídos: {:?}", required_scopes_for_server, client_scopes_set);
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
/// Extrai o token Bearer do header `Authorization`. Se OAuth2 estiver habilitado na configuração,
/// valida o token usando `validate_and_decode_token`. Se a validação for bem-sucedida,
/// insere um `ClientAuthContext` nas extensões da requisição Axum para uso por handlers posteriores.
/// Se a autenticação falhar, retorna um erro HTTP apropriado (400, 401, 403, ou 500).
/// Se OAuth2 estiver desabilitado, permite que a requisição prossiga sem modificação.
#[tracing::instrument(skip_all, name = "oauth_middleware")]
pub async fn oauth_middleware(
    State(state_tuple): State<(Arc<JwksCache>, Arc<config::OAuth>)>,
    auth_header_result: Result<TypedHeader<Authorization<Bearer>>, TypedHeaderRejection>,
    mut request: Request<Body>, 
    next: Next,
) -> Result<Response, StatusCode> {
    let (jwks_cache, oauth_config) = state_tuple;
    if !oauth_config.enabled {
        tracing::trace!("OAuth2 desabilitado, permitindo requisição.");
        return Ok(next.run(request).await);
    }

    let token_str = match auth_header_result {
        Ok(TypedHeader(Authorization(bearer))) => bearer.token().to_string(),
        Err(rejection) => {
            tracing::warn!("Header Authorization ausente ou malformado: {}", rejection);
            return Err(rejection.into_response().status()); // Status da rejection (ex: 400)
        }
    };

    match validate_and_decode_token(&token_str, &jwks_cache, &oauth_config).await {
        Ok(token_data) => {
            let client_scopes_str = token_data.claims.scope.as_deref().unwrap_or_default();
            let client_scopes: HashSet<String> = client_scopes_str.split(' ').filter(|s| !s.is_empty()).map(String::from).collect();
            
            tracing::debug!("Token JWT validado com sucesso para sub: {}, escopos: {:?}", token_data.claims.sub, client_scopes);
            request.extensions_mut().insert(Arc::new(ClientAuthContext {
                user_id: token_data.claims.sub.clone(),
                scopes: client_scopes,
                raw_token: token_str,
            }));
            Ok(next.run(request).await)
        }
        Err(auth_err) => {
            tracing::warn!("Falha na autenticação OAuth2 no middleware: {}", auth_err);
            Err(match auth_err {
                AuthErrorDetail::TokenMissingOrMalformed => StatusCode::BAD_REQUEST, // 400
                AuthErrorDetail::TokenInvalid(_) | 
                AuthErrorDetail::KidNotFoundInJwks | 
                AuthErrorDetail::SignatureInvalid | 
                AuthErrorDetail::TokenExpired => StatusCode::UNAUTHORIZED, // 401
                AuthErrorDetail::JwksFetchFailed(_) | 
                AuthErrorDetail::InvalidAuthConfig(_) => StatusCode::INTERNAL_SERVER_ERROR, // 500
                AuthErrorDetail::IssuerMismatch { .. } | 
                AuthErrorDetail::AudienceMismatch { .. } | 
                AuthErrorDetail::InsufficientScope { .. } => StatusCode::FORBIDDEN, // 403
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config; // Para config::OAuth nos testes
    use axum::{extract::Extension, middleware, routing::get, Router};
    use jsonwebtoken::{encode, EncodingKey, Header as JwtHeader, Algorithm};
    use jsonwebtoken::jwk::{Jwk, JwkSet, AlgorithmParameters as JwkAlgorithmParameters, CommonParameters as JwkCommonParameters, RSAKeyParameters, KeyAlgorithm, PublicKeyUse as JwkPublicKeyUse, RSAKeyType};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tower::ServiceExt; // Para app.oneshot()

    // Chaves RSA 2048 bits e JWK para testes unitários de src/auth.rs
    // **IMPORTANTE**: Substitua estes PEMs por chaves RSA 2048 bits VÁLIDAS e COMPLETAS.
    // Estas são apenas para estrutura e causarão pânico se não forem válidas.
    const TEST_UNIT_RSA_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCyE54qG20VWunF
oGyXHNFUFp12eiqbNY1khT+g5CXHCxafIxCtG2ovb6RhO7SAGfMDdrM01/5vZxf2
ynx78pXDNbnPcIMab294djDSEJ3NZncxOnOJ7Clk6MF97sOXMbPzuB9+73rBS7gm
jydn88tiLT0oiV9m21K2ucLjCRbDrPkkBg2XqlMny+Dq1oHtw1th4Q+FRs/hlC3W
L1V14Tse5GZK1rrEh13XTKOCKMx47NugVWW3qJ2y7nPn6f/G5vgToB7334O2guS7
CIQ9e/rtj3+hDeSSHwQfDjgGqCZlIdG5MDOm95F276oKISstxVexJ47kwoGRD4Xj
xpnaT7oVAgMBAAECggEAC+AgC5nRn/t0nI/Svg8XbJ6neJe0EK61E6+JKz8bv9be
9tTdT1YFMk2lLjDPnD1exevcDpma56393KDrRU7Lqv2BuzI7I/+rdOKY5eFizKhZ
KYjG3LtJlWeqQ64xD/uqDwZH32y0CID2smeYjqek+BKhQftLR+43aWUg+IgKIxlg
mej8A+/O6VWp7LKP5x5kjIZwXNrCpwWyar6iJtegLQmkr8EBBQuWt/W6CljGl5GP
nTEKEzC93VV5dBMII3Vf7KHc7bnokSYyjmut/sp0HG1Xwkr1qD18HwnxK/OJDZf1
303pST+0m6u77wJU3xxhLV7rLFSRY7NRIDIVqnKCLwKBgQD6oANN2X7Q/DVVYhb6
fszD2rrOFL1HtCsYzLvhl3I6nMl/yQnQXnnrdEjfjXyUVWukm9KTJTuZAZw7Wgae
NF0OrAWpzF/izOLK46ai2AJ6a/TuLcEWKX8yClEI6zBUBUDmm+Tr9/NJhS44A66H
NzJgZa6rUvsk1VehrewoEdB/awKBgQC15UxLLyQqkE11SLKbg5Btl+cH7nccHr8S
ugVeKx7mdleZi843r1KqnZArKOcXHJz/cePV7TKlRTO3ToLs+vnxQNbnLhXa5ePy
j2jikdGLlXaXrj4T5Uq4ToxhDF972jXw/FRLkcncfyJwT/F9makAn27mP9GhEvP4
RXr54RaMfwKBgQCQ7rXacDs5CZCiFr5pD6jEXhoHENFAxPzjM4o29AiXwpF39z9Y
oznoIm/972kqspc0MvQ8KZzkZ5z8aZxIIsnpsSr5PXn5wzgn0ixMIZSVTRbwIb92
XHr06ihgevmQrRUSBvcESngDfSP0OpTUFuRoAIVZB/y6GTG7CsP1jA/BjwKBgAN4
3Ar3XGZfmMrrV1V2nnQpGSTinW1w/M67tEyG4DEgAy4QKCCR/S76kPzx6+9aAXky
0FmODJBxELqoCgHCDLFZPoDtNUeXadGAgU0J4Ykbkkb08YRptRJtlWpo1Q3FLZBr
EKTcpJDL8HlaXU67dylm4bQNdc/wT63mjaFldYu7AoGBAOPGWvzO04eiOqt7Mv7l
0XYmIVBd9wIynBjeQ+e/uUZ/3MK7LfbRZ+nBdVT2vFRpICaZkCzUY/Y7LPNzdXPH
qLLmcZuVCc5d+3NbgKFi6zUBcvoL/TxTDkA4XoyesQWK5sxvHMqPk9wdU6qMXjh7
ezJCKjG5c2dOsKn0rAhlBzZg
-----END PRIVATE KEY-----";
    const TEST_UNIT_RSA_PUBLIC_N_B64URL: &str = "shOeKhttFVrpxaBslxzRVBaddnoqmzWNZIU_oOQlxwsWnyMQrRtqL2-kYTu0gBnzA3azNNf-b2cX9sp8e_KVwzW5z3CDGm9veHYw0hCdzWZ3MTpziewpZOjBfe7DlzGz87gffu96wUu4Jo8nZ_PLYi09KIlfZttStrnC4wkWw6z5JAYNl6pTJ8vg6taB7cNbYeEPhUbP4ZQt1i9VdeE7HuRmSta6xIdd10yjgijMeOzboFVlt6idsu5z5-n_xub4E6Ae99-DtoLkuwiEPXv67Y9_oQ3kkh8EHw44BqgmZSHRuTAzpveRdu-qCiErLcVXsSeO5MKBkQ-F48aZ2k-6FQ";
    const TEST_UNIT_RSA_PUBLIC_E_B64URL: &str = "AQAB";
    const TEST_UNIT_KID_RS256: &str = "test-key-for-src-auth-unit-tests"; // Kid para os testes unitários
    const TEST_UNIT_ISSUER: &str = "test-issuer-for-src-auth";
    const TEST_UNIT_AUDIENCE: &str = "test-audience-for-src-auth";

    // Chave privada *diferente* para testar falha de assinatura
    const DIFFERENT_TEST_UNIT_RSA_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDbDmxWbDDR+DHn
MplybMFm8T47lplIToPaNKgHgzVAwMe3EP14H9XJpn3hFqm1cYkXip904hmll94B
lg9vJT6UTXNEH/NOP81O1qf/7rYiNB68LqViVzfAxu2gfJ82ErEqn3mVpCdjujUm
c4eOamd6IY1diBjzDQBaZvwmn+VIaBqyCNOs4FyrINF+6KpKvm37iBdtaWQRMUul
8RX79khag8eDinGsm31ZDMayUjErx4Sr2dpTlbvoWu3qMBuWEWSkRo3uD2GyJIWX
UFyq0dCc9L4+koJiyV/nUAzM8K7zwWrgB//T/zOP8Hpqz5D1IAo2/vo7N5SRg7qQ
48hNbBe3AgMBAAECggEAYZ5wViUZroB6EKtiaXUgzPTGBH0M6wWeSZ/8n3hvw18F
wUWvhxg8yAPLhgL49xRVASoz/D0EK+DdPPy3/RJubF2Fd/77CMxy/Ga5cFrbTKvI
ZJku93+hp2WfIM1YkBrNXA68epywNweUxwFmD+fIHEuWeW98mteY6DCLvtSzs0tq
N0HwQAvFcCrBuPw25m+SB1qjDcxI10dgsYXWAxics3TBGqHRHnPvrqO/zAivJNUa
PdpzRbHZK/Ggaj0b1J298ae7lVXwP4mP032u/W+DjKFYkA6w6DJap9UPDeiOOFyM
TVapPP07l/QNF+Tu9pV0uiE6smgKkw3OQwWwxZVyfQKBgQDyY85H3Zo4FXFc6ACX
MgXCffnickMtPQo+S42T0eKVe5Zy6dTOLnd1P+6Twed2c6pT2bfUd+H0IqEaLSYp
VIlJ4nFRGRwYNlQ3a8/Lt4m1I99a4ZLRjyE+aa3AuUvca3IRWv9gr0R6p5Gjmukd
2/p1Neo4iALO/ZuEng43fy1EKwKBgQDnWzagveMyyimcrR5pqt0si4+vS4aTgEl3
NK8La0p9NB+b00TJDgel2YMM+S/awcD+rIgfO6TIp7XV7lTOpg7OsPiVEaEOsr6D
PFK0lvWUnWv2iDJ7ib+WqVzv3l7nSjIKeCB4yfD2Wh5lG1ymG9aozf8M63O7/ewQ
lTcMW2F4pQKBgQCPhHDbNGbf1jJtJCFVZJTsd9LBNY549q9d+zY01A0pHSgTmkga
XID2t4f3jNQT2qB7TWn/L4xmFSr2aM0zo442ZRFbR1bPLzvmJLvAj0fGLRtOoEli
MzEn10K93fkA5c2AYTTcdmpBhX5CNLLaryk4xVeNaVrgXGD8wOkCCxcuSQKBgBoM
kBsLJlCqqILGjz0QivSgBh6Tn2RuNldgrDDZ9LoiK0jtQbpthPjsg6/rQrMby7Ih
FPaHTad2EqgyvIPD+LjW/jYylPLFt2OpYBqLQL1p+CT68swsF1FMYnVzkTXziaza
F7Xh7uqd/PwfV5AwZDv/ba8zt4U8Mt8vHdKbW18tAoGBALsaqxLdpoE4Dnt7n8IS
w60SBiJe2sqMoEKfiAL+zCzAoLuGSrDbVDQAhN/loWEMMjnXGEiJ+4k/hXNjLjaO
MxQSddKKIg210Mf6D+ua4Pbm2A3DXOks1Lq21iXwdNRSApF1MsMwxKFoa2GHNiGv
TFUAe5xee5mzcLwKeME2vyWU
-----END PRIVATE KEY-----"; // << SUBSTITUA POR UMA SEGUNDA CHAVE PRIVADA PEM REAL E COMPLETA DIFERENTE


    fn rsa_public_jwk_for_src_auth_test() -> Jwk {
        Jwk {
            common: JwkCommonParameters {
                public_key_use: Some(JwkPublicKeyUse::Signature),
                key_algorithm: Some(KeyAlgorithm::RS256),
                key_id: Some(TEST_UNIT_KID_RS256.to_string()),
                key_operations: None,
                x509_url: None, x509_chain: None, x509_sha1_fingerprint: None, x509_sha256_fingerprint: None,
            },
            algorithm: JwkAlgorithmParameters::RSA(RSAKeyParameters {
                key_type: RSAKeyType::RSA,
                n: TEST_UNIT_RSA_PUBLIC_N_B64URL.to_string(),
                e: TEST_UNIT_RSA_PUBLIC_E_B64URL.to_string(),
            }),
        }
    }
    
    fn generate_test_jwt_for_src_auth(claims: &Claims, alg: Algorithm, kid: &str, private_key_pem: &str) -> String {
        let encoding_key = match alg {
            Algorithm::RS256 => EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
                .expect("Falha ao carregar chave RSA privada de teste para src/auth.rs."),
            _ => panic!("Algoritmo não suportado para este helper de teste em src/auth.rs"),
        };
        let mut header = JwtHeader::new(alg);
        header.kid = Some(kid.to_string());
        encode(&header, claims, &encoding_key).expect("Falha ao gerar JWT de teste para src/auth.rs")
    }

    fn test_oauth_config_for_src_auth(jwks_uri: String, enabled: bool) -> config::OAuth {
        config::OAuth {
            enabled,
            jwks_uri: Some(jwks_uri),
            issuer: Some(vec![TEST_UNIT_ISSUER.to_string()]),
            audience: Some(vec![TEST_UNIT_AUDIENCE.to_string()]),
            required_scopes: None,
            jwks_request_timeout_seconds: Some(5),
            jwks_refresh_interval_raw: Some("300s".to_string()),
            jwks_refresh_interval: Some(Duration::from_secs(300)),
            // validation_leeway_seconds removido daqui
        }
    }

    fn test_jwks_cache_for_src_auth(jwks_uri: String, http_client: reqwest::Client) -> JwksCache {
        JwksCache::new(
            jwks_uri,
            Duration::from_secs(300),
            http_client,
        )
    }
    
    fn current_timestamp_for_test() -> usize {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as usize
    }

    #[tokio::test]
    async fn test_oauth_middleware_valid_token() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let mock_server = MockServer::start().await;
        let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());

        let public_jwk = rsa_public_jwk_for_src_auth_test();
        let jwks = JwkSet { keys: vec![public_jwk] };

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let oauth_config = Arc::new(test_oauth_config_for_src_auth(jwks_uri.clone(), true));
        let http_client = reqwest::Client::new();
        let jwks_cache = Arc::new(test_jwks_cache_for_src_auth(jwks_uri, http_client));

        jwks_cache.refresh_keys().await.expect("Refresh inicial do JWKS falhou");
        assert!(jwks_cache.is_cache_ever_populated().await, "Cache JWKS não populado após refresh forçado.");

        let now = current_timestamp_for_test();
        let claims = Claims {
            sub: "user123".to_string(),
            exp: now + 3600,
            iat: Some(now),
            nbf: Some(now),
            iss: Some(TEST_UNIT_ISSUER.to_string()),
            aud: Some(JsonValue::String(TEST_UNIT_AUDIENCE.to_string())),
            scope: Some("read write".to_string()),
        };
        let token = generate_test_jwt_for_src_auth(&claims, Algorithm::RS256, TEST_UNIT_KID_RS256, TEST_UNIT_RSA_PRIVATE_KEY_PEM);

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
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "Resposta inesperada para token válido. Corpo: {:?}", response.into_body());
    }

    #[tokio::test]
    async fn test_oauth_middleware_disabled() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let oauth_config = Arc::new(test_oauth_config_for_src_auth("http://dummy/jwks".to_string(), false));
        let http_client = reqwest::Client::new();
        let jwks_cache = Arc::new(test_jwks_cache_for_src_auth("http://dummy/jwks".to_string(), http_client));

        let app = Router::new()
            .route("/", get(|| async { StatusCode::OK }))
            .layer(middleware::from_fn_with_state((jwks_cache, oauth_config), oauth_middleware));

        let request = axum::http::Request::builder().uri("/").body(Body::empty()).unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_oauth_middleware_no_auth_header_when_required() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let mock_server = MockServer::start().await;
        let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());
        let oauth_config = Arc::new(test_oauth_config_for_src_auth(jwks_uri.clone(), true)); 
        let http_client = reqwest::Client::new();
        let jwks_cache = Arc::new(test_jwks_cache_for_src_auth(jwks_uri, http_client));

        let app = Router::new()
            .route("/", get(|| async { StatusCode::OK })) 
            .layer(middleware::from_fn_with_state((jwks_cache, oauth_config), oauth_middleware));

        let request = axum::http::Request::builder().uri("/").body(Body::empty()).unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_oauth_middleware_invalid_token_bad_signature() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let mock_server = MockServer::start().await;
        let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());
        
        let correct_public_jwk = rsa_public_jwk_for_src_auth_test(); // JWK da chave pública correta
        let jwks_correct_key = JwkSet { keys: vec![correct_public_jwk] };
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&jwks_correct_key))
            .mount(&mock_server)
            .await;

        let oauth_config = Arc::new(test_oauth_config_for_src_auth(jwks_uri.clone(), true));
        let http_client = reqwest::Client::new();
        let jwks_cache = Arc::new(test_jwks_cache_for_src_auth(jwks_uri, http_client));
        jwks_cache.refresh_keys().await.expect("Refresh inicial do JWKS falhou");

        let now = current_timestamp_for_test();
        let claims = Claims {
            sub: "user-bad-sig".to_string(),
            exp: now + 3600,
            iat: Some(now), nbf: Some(now),
            iss: Some(TEST_UNIT_ISSUER.to_string()),
            aud: Some(JsonValue::String(TEST_UNIT_AUDIENCE.to_string())),
            scope: Some("read".to_string()),
        };
        
        // Gerar token com uma chave privada DIFERENTE
        let token_bad_sig = generate_test_jwt_for_src_auth(&claims, Algorithm::RS256, TEST_UNIT_KID_RS256, DIFFERENT_TEST_UNIT_RSA_PRIVATE_KEY_PEM);


        let app = Router::new()
            .route("/", get(|| async { StatusCode::OK }))
            .layer(middleware::from_fn_with_state((jwks_cache, oauth_config), oauth_middleware));

        let request = axum::http::Request::builder()
            .uri("/")
            .header("Authorization", format!("Bearer {}", token_bad_sig))
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_oauth_middleware_expired_token() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let mock_server = MockServer::start().await;
        let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());
        let public_jwk = rsa_public_jwk_for_src_auth_test();
        let jwks = JwkSet { keys: vec![public_jwk] };
        Mock::given(method("GET")).and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server).await;

        let oauth_config = Arc::new(test_oauth_config_for_src_auth(jwks_uri.clone(), true));
        let http_client = reqwest::Client::new();
        let jwks_cache = Arc::new(test_jwks_cache_for_src_auth(jwks_uri, http_client));
        jwks_cache.refresh_keys().await.expect("Refresh inicial falhou.");

        let now = current_timestamp_for_test();
        let claims = Claims {
            sub: "user-expired".to_string(),
            exp: now - 3600, 
            iat: Some(now - 7200), nbf: Some(now - 7200),
            iss: Some(TEST_UNIT_ISSUER.to_string()),
            aud: Some(JsonValue::String(TEST_UNIT_AUDIENCE.to_string())),
            scope: Some("read".to_string()),
        };
        let token = generate_test_jwt_for_src_auth(&claims, Algorithm::RS256, TEST_UNIT_KID_RS256, TEST_UNIT_RSA_PRIVATE_KEY_PEM);

        let app = Router::new().route("/", get(|| async { StatusCode::OK }))
            .layer(middleware::from_fn_with_state((jwks_cache, oauth_config), oauth_middleware));

        let request = axum::http::Request::builder()
            .uri("/")
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_jwks_cache_refresh_and_get_key() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let mock_server = MockServer::start().await;
        let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());

        let public_jwk_rs256 = rsa_public_jwk_for_src_auth_test();
        let jwks = JwkSet { keys: vec![public_jwk_rs256.clone()] };

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let http_client = reqwest::Client::new();
        let cache = test_jwks_cache_for_src_auth(jwks_uri, http_client);

        assert!(!cache.is_cache_ever_populated().await);

        let refresh_result = cache.refresh_keys().await;
        assert!(refresh_result.is_ok(), "Falha ao atualizar chaves JWKS: {:?}", refresh_result.err());
        assert!(cache.is_cache_ever_populated().await);

        let decoding_key_result = cache.get_decoding_key_for_kid(TEST_UNIT_KID_RS256).await;
        match decoding_key_result {
            Ok(Some(_key)) => {},
            Ok(None) => panic!("Chave de decodificação não encontrada para kid conhecido '{}'", TEST_UNIT_KID_RS256),
            Err(e) => panic!("Erro ao obter chave de decodificação para kid '{}': {:?}", TEST_UNIT_KID_RS256, e),
        }

        let decoding_key_result_unknown = cache.get_decoding_key_for_kid("unknown-kid").await;
        match decoding_key_result_unknown {
            Ok(None) => {},
            Ok(Some(_)) => panic!("Chave encontrada para kid desconhecido, esperado None"),
            Err(e) => panic!("Erro ao obter chave para KID desconhecido: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_jwks_cache_handles_http_error_on_refresh() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let mock_server = MockServer::start().await;
        let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let http_client = reqwest::Client::new();
        let cache = test_jwks_cache_for_src_auth(jwks_uri, http_client);

        let refresh_result = cache.refresh_keys().await;
        assert!(refresh_result.is_err());
        if let Err(AuthErrorDetail::JwksFetchFailed(msg)) = refresh_result {
            assert!(msg.contains("Status 500"));
        } else {
            panic!("Erro inesperado: {:?}", refresh_result);
        }
        assert!(!cache.is_cache_ever_populated().await);
    }
}