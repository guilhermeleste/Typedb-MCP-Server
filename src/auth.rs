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

//! Módulo responsável pela autenticação OAuth 2.0 e autorização baseada em escopos.
//!
//! Fornece o middleware Axum para validar tokens JWT Bearer, um cache para chaves JWKS,
//! e a lógica para validar claims do token (issuer, audience, expiração, escopos).
//! O `ClientAuthContext` é usado para propagar informações do usuário autenticado
//! para os handlers de ferramentas MCP.

use crate::config; // Para config::OAuth
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

// jsonwebtoken v9.3.1 imports
use jsonwebtoken::{
    decode,
    decode_header,
    errors::ErrorKind as JwtErrorKind,
    jwk::JwkSet,
    Algorithm,
    DecodingKey,
    Header as JwtValidationHeader, // Alias para o Header do jsonwebtoken
    TokenData,
    Validation,
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
use tracing::{debug, error, info, trace, warn};

/// Contexto de autenticação do cliente.
/// Armazena informações extraídas de um token JWT válido.
#[derive(Clone, Debug)]
pub struct ClientAuthContext {
    /// Identificador do usuário (geralmente o claim `sub` do token JWT).
    pub user_id: String,
    /// Conjunto de escopos `OAuth2` concedidos ao cliente, parseados do claim `scope`.
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
    last_successful_refresh: Arc<RwLock<Option<Instant>>>,
    last_refresh_attempt_failed: Arc<RwLock<bool>>,
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
    pub fn new(jwks_uri: String, refresh_interval: Duration, http_client: reqwest::Client) -> Self {
        Self {
            jwks_uri,
            keys: Arc::new(RwLock::new(None)),
            last_successful_refresh: Arc::new(RwLock::new(None)),
            last_refresh_attempt_failed: Arc::new(RwLock::new(false)),
            refresh_interval,
            http_client,
        }
    }

    /// Atualiza as chaves JWKS a partir da URI configurada.
    ///
    /// Esta função é chamada internamente quando as chaves estão desatualizadas,
    /// nunca foram carregadas, ou uma chave específica não é encontrada.
    /// Atualiza `last_successful_refresh` e `last_refresh_attempt_failed` de acordo.
    ///
    /// # Errors
    ///
    /// Retorna `AuthErrorDetail` se:
    /// - Falha na requisição HTTP para o endpoint JWKS
    /// - Resposta HTTP com status de erro
    /// - Corpo da resposta não for um JSON válido ou JWKS inválido
    #[tracing::instrument(skip(self), name = "jwks_cache_refresh_keys")]
    pub async fn refresh_keys(&self) -> Result<(), AuthErrorDetail> {
        info!("Tentando atualizar chaves JWKS de: {}", self.jwks_uri);
        match self.http_client.get(&self.jwks_uri).send().await {
            Ok(response) => {
                if !response.status().is_success() {
                    let status = response.status();
                    let err_body = response
                        .text()
                        .await
                        .unwrap_or_else(|_| String::from("<corpo do erro ilegível>"));
                    warn!("Falha ao buscar JWKS: Status {}, Corpo: {}", status, err_body);
                    *self.last_refresh_attempt_failed.write().await = true;
                    return Err(AuthErrorDetail::JwksFetchFailed(format!(
                        "Status {status} ao buscar JWKS: {err_body}"
                    )));
                }

                match response.json::<JwkSet>().await {
                    Ok(jwks_data) => {
                        debug!(
                            "JWKS recebido com {} chaves de {}.",
                            jwks_data.keys.len(),
                            self.jwks_uri
                        );
                        *self.keys.write().await = Some(jwks_data);
                        *self.last_successful_refresh.write().await = Some(Instant::now());
                        *self.last_refresh_attempt_failed.write().await = false;
                        info!("Chaves JWKS atualizadas com sucesso de {}", self.jwks_uri);
                        Ok(())
                    }
                    Err(e) => {
                        error!("JWKS JSON inválido recebido de {}: {}", self.jwks_uri, e);
                        *self.last_refresh_attempt_failed.write().await = true;
                        Err(AuthErrorDetail::JwksFetchFailed(format!("JWKS JSON inválido: {e}")))
                    }
                }
            }
            Err(e) => {
                error!("Erro na requisição HTTP ao buscar JWKS de {}: {}", self.jwks_uri, e);
                *self.last_refresh_attempt_failed.write().await = true;
                Err(AuthErrorDetail::JwksFetchFailed(format!("Erro HTTP ao buscar JWKS: {e}")))
            }
        }
    }

    /// Obtém a chave de decodificação (`DecodingKey`) para um `kid` (Key ID) específico.
    ///
    /// Se o cache estiver potencialmente desatualizado (com base no `refresh_interval`) ou
    /// a chave com o `kid` não for encontrada no cache atual, esta função tentará
    /// atualizar as chaves do `jwks_uri` antes de tentar encontrar a chave novamente.
    ///
    /// # Errors
    ///
    /// Retorna `AuthErrorDetail` se:
    /// - Falha ao atualizar chaves do endpoint JWKS
    /// - JWK encontrada é inválida ou não pode ser convertida para DecodingKey
    /// - Erro interno no processamento das chaves
    ///
    /// # Retorna
    /// `Ok(Some(DecodingKey))` se a chave for encontrada e válida.
    /// `Ok(None)` se a chave com o `kid` não for encontrada mesmo após um refresh.
    /// `Err(AuthErrorDetail)` se ocorrer um erro durante o refresh ou ao processar a JWK.
    #[tracing::instrument(skip(self), name = "jwks_cache_get_key", fields(token.kid = %kid))]
    pub async fn get_decoding_key_for_kid(
        &self,
        kid: &str,
    ) -> Result<Option<DecodingKey>, AuthErrorDetail> {
        let needs_initial_fetch;
        let needs_refresh_due_to_interval;
        {
            let last_successful_refresh_guard = self.last_successful_refresh.read().await;
            needs_initial_fetch = last_successful_refresh_guard.is_none();
            needs_refresh_due_to_interval = last_successful_refresh_guard
                .is_none_or(|last_update_time| {
                    last_update_time.elapsed() > self.refresh_interval
                });
        }

        let mut attempt_refresh = needs_initial_fetch || needs_refresh_due_to_interval;

        if !attempt_refresh {
            if let Some(jwk_set) = self.keys.read().await.as_ref() {
                if jwk_set.find(kid).is_none() {
                    trace!("Kid '{}' não encontrado no cache JWKS atual. Forçando refresh.", kid);
                    attempt_refresh = true;
                }
            } else {
                trace!("Cache JWKS está None, mas não é fetch inicial. Forçando refresh.");
                attempt_refresh = true;
            }
        }

        if attempt_refresh {
            if let Err(e) = self.refresh_keys().await {
                if self.keys.read().await.is_none() {
                    error!("Falha crítica ao buscar JWKS pela primeira vez (ou cache vazio) e refresh falhou: {}", e);
                } else {
                    warn!("Falha ao atualizar JWKS: {}. Tentando usar cache antigo se a chave existir.", e);
                }
            }
        }

        Self::get_decoding_key_from_cache(&self.keys.read().await, kid)
    }

    /// Helper interno para extrair a `DecodingKey` do `JwkSet` em cache.
    fn get_decoding_key_from_cache(
        keys_guard: &tokio::sync::RwLockReadGuard<'_, Option<JwkSet>>,
        kid: &str,
    ) -> Result<Option<DecodingKey>, AuthErrorDetail> {
        if let Some(jwk_set) = keys_guard.as_ref() { if let Some(jwk) = jwk_set.find(kid) { DecodingKey::from_jwk(jwk)
        .map_err(|e| {
            AuthErrorDetail::TokenInvalid(format!(
                "JWK para kid '{kid}' (do cache) inválido: {e}"
            ))
        })
        .map(Some) } else {
            trace!("Kid '{}' não encontrado no JwkSet atual do cache.", kid);
            Ok(None)
        } } else {
            trace!("Cache JWKS está vazio. Não foi possível encontrar kid '{}'.", kid);
            Ok(None)
        }
    }

    /// Verifica a saúde do cache JWKS para o endpoint /readyz.
    ///
    /// Tenta um refresh se o cache estiver potencialmente obsoleto ou se o último refresh falhou.
    /// Retorna `false` se o refresh ativo falhar ou se nunca houve sucesso.
    ///
    /// # Panics
    ///
    /// Pode dar panic se `last_successful_opt` for `None` em contextos onde é esperado que seja `Some`.
    #[tracing::instrument(skip(self), name = "jwks_cache_check_health_for_readyz")]
    pub async fn check_health_for_readyz(&self) -> bool {
        let now = Instant::now();
        let last_successful_opt = *self.last_successful_refresh.read().await;
        let last_attempt_failed_before_check = *self.last_refresh_attempt_failed.read().await;

        let health_check_active_refresh_threshold =
            self.refresh_interval.checked_div(10).unwrap_or_else(|| Duration::from_secs(30));
        let min_health_check_active_refresh_interval = Duration::from_secs(15);
        let effective_health_check_threshold =
            health_check_active_refresh_threshold.max(min_health_check_active_refresh_interval);

        let needs_active_check = match last_successful_opt {
            Some(last_success_time) => {
                last_attempt_failed_before_check
                    || now.duration_since(last_success_time) > effective_health_check_threshold
            }
            None => true,
        };

        if needs_active_check {
            trace!(
                "JwksCache.check_health_for_readyz: Executando verificação ATIVA do JWKS URI (last_attempt_failed: {}, cache_age_exceeded_health_threshold: {}).",
                last_attempt_failed_before_check,
                last_successful_opt.is_none_or(|ls| now.duration_since(ls) > effective_health_check_threshold)
            );
            if self.refresh_keys().await.is_err() {
                warn!("JwksCache.check_health_for_readyz: Verificação ATIVA do JWKS URI falhou.");
            }
        } else {
            trace!("JwksCache.check_health_for_readyz: Verificação ativa do JWKS URI não necessária neste momento.");
        }

        let current_last_successful_opt = *self.last_successful_refresh.read().await;
        let current_last_attempt_failed = *self.last_refresh_attempt_failed.read().await;

        if let Some(last_successful) = current_last_successful_opt {
            if current_last_attempt_failed {
                warn!("JwksCache: Saúde DOWN para /readyz. A última tentativa de refresh do JWKS falhou.");
                false
            } else {
                info!("JwksCache: Saúde UP para /readyz. Último refresh bem-sucedido em {:?} atrás e nenhuma falha de refresh ativa registrada.", last_successful.elapsed());
                true
            }
        } else {
            warn!(
                "JwksCache: Saúde DOWN para /readyz. Nunca houve um refresh bem-sucedido do JWKS."
            );
            false
        }
    }
}

/// Valida e decodifica um token JWT.
///
/// Verifica a assinatura, expiração, `nbf` (Not Before), `iss` (Issuer) e `aud` (Audience)
/// do token de acordo com as chaves públicas do `JwksCache` e as configurações `config::OAuth`.
#[allow(clippy::too_many_lines)] // Função de validação JWT complexa, justifica o tamanho devido à lógica de segurança
#[tracing::instrument(skip(token_str, jwks_cache, oauth_config), name = "validate_jwt_token")]
async fn validate_and_decode_token(
    token_str: &str,
    jwks_cache: &JwksCache,
    oauth_config: &config::OAuth,
) -> Result<TokenData<Claims>, AuthErrorDetail> {
    let header: JwtValidationHeader = decode_header(token_str)
        .map_err(|e| AuthErrorDetail::TokenInvalid(format!("Header do token inválido: {e}")))?;

    let kid = header.kid.as_deref().ok_or_else(|| {
        warn!("Token JWT não possui o campo 'kid' no header.");
        AuthErrorDetail::KidNotFoundInJwks
    })?;

    let alg: Algorithm = header.alg;

    let decoding_key = jwks_cache.get_decoding_key_for_kid(kid).await?.ok_or_else(|| {
        warn!(
            "Kid '{}' do token não encontrado no JWKS fornecido por '{}'.",
            kid, jwks_cache.jwks_uri
        );
        AuthErrorDetail::KidNotFoundInJwks
    })?;

    let mut validation = Validation::new(alg);
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.leeway = 60;

    if let Some(ref issuers) = oauth_config.issuer {
        if !issuers.is_empty() {
            validation.set_issuer(issuers);
        }
    }
    if let Some(ref audiences) = oauth_config.audience {
        if !audiences.is_empty() {
            validation.set_audience(audiences);
        }
    }

    let token_data: TokenData<Claims> = decode::<Claims>(token_str, &decoding_key, &validation)
        .map_err(|e| match e.kind() {
            JwtErrorKind::InvalidToken => {
                AuthErrorDetail::TokenInvalid("Formato de token inválido".to_string())
            }
            JwtErrorKind::InvalidSignature => AuthErrorDetail::SignatureInvalid,
            JwtErrorKind::ExpiredSignature => AuthErrorDetail::TokenExpired,
            JwtErrorKind::InvalidIssuer => AuthErrorDetail::IssuerMismatch {
                expected: oauth_config.issuer.clone().unwrap_or_default(),
                found: None,
            },
            JwtErrorKind::InvalidAudience => AuthErrorDetail::AudienceMismatch {
                expected: oauth_config.audience.clone().unwrap_or_default(),
                found: None,
            },
            JwtErrorKind::ImmatureSignature => {
                AuthErrorDetail::TokenInvalid("Token ainda não é válido (nbf)".to_string())
            }
            _ => AuthErrorDetail::TokenInvalid(format!(
                "Erro de validação JWT não especificado: {e}"
            )),
        })?;

    if let Some(ref expected_audiences) = oauth_config.audience {
        if !expected_audiences.is_empty() {
            let token_audiences_set: HashSet<String> = match &token_data.claims.aud {
                Some(JsonValue::String(s)) => std::iter::once(s.clone()).collect(),
                Some(JsonValue::Array(arr)) => {
                    arr.iter().filter_map(|v| v.as_str().map(String::from)).collect()
                }
                _ => HashSet::new(),
            };
            if token_audiences_set.is_empty() && !expected_audiences.is_empty() {
                warn!(
                    "Token não possui claim 'aud' mas audiences esperados são: {:?}",
                    expected_audiences
                );
                return Err(AuthErrorDetail::AudienceMismatch {
                    expected: expected_audiences.clone(),
                    found: None,
                });
            }
            if !expected_audiences
                .iter()
                .any(|expected_aud| token_audiences_set.contains(expected_aud))
            {
                warn!(
                    "Claim 'aud' do token ({:?}) não corresponde a nenhum dos esperados ({:?})",
                    token_audiences_set, expected_audiences
                );
                return Err(AuthErrorDetail::AudienceMismatch {
                    expected: expected_audiences.clone(),
                    found: Some(token_audiences_set.into_iter().collect()),
                });
            }
        }
    }
    if let Some(ref required_scopes_for_server) = oauth_config.required_scopes {
        if !required_scopes_for_server.is_empty() {
            let client_scopes_str = token_data.claims.scope.as_deref().unwrap_or_default();
            let client_scopes_set: HashSet<String> =
                client_scopes_str.split(' ').filter(|s| !s.is_empty()).map(String::from).collect();

            if !required_scopes_for_server
                .iter()
                .all(|req_scope| client_scopes_set.contains(req_scope))
            {
                warn!("Token não possui todos os escopos gerais requeridos pelo servidor. Requeridos: {:?}, Possuídos: {:?}", required_scopes_for_server, client_scopes_set);
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
///
/// # Errors
///
/// Retorna `StatusCode` em caso de falha na autenticação ou validação do token.
#[tracing::instrument(skip_all, name = "oauth_middleware")]
pub async fn oauth_middleware(
    State(state_tuple): State<(Arc<JwksCache>, Arc<config::OAuth>)>,
    auth_header_result: Result<TypedHeader<Authorization<Bearer>>, TypedHeaderRejection>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let (jwks_cache, oauth_config) = state_tuple;
    if !oauth_config.enabled {
        trace!("OAuth2 desabilitado, permitindo requisição.");
        return Ok(next.run(request).await);
    }

    let token_str = match auth_header_result {
        Ok(TypedHeader(Authorization(bearer))) => bearer.token().to_string(),
        Err(rejection) => {
            warn!("Header Authorization ausente ou malformado: {}", rejection);
            return Err(rejection.into_response().status());
        }
    };

    match validate_and_decode_token(&token_str, &jwks_cache, &oauth_config).await {
        Ok(token_data) => {
            let client_scopes_str = token_data.claims.scope.as_deref().unwrap_or_default();
            let client_scopes: HashSet<String> =
                client_scopes_str.split(' ').filter(|s| !s.is_empty()).map(String::from).collect();

            debug!(
                "Token JWT validado com sucesso para sub: {}, escopos: {:?}",
                token_data.claims.sub, client_scopes
            );
            request.extensions_mut().insert(Arc::new(ClientAuthContext {
                user_id: token_data.claims.sub.clone(),
                scopes: client_scopes,
                raw_token: token_str,
            }));
            Ok(next.run(request).await)
        }
        Err(auth_err) => {
            warn!("Falha na autenticação OAuth2 no middleware: {}", auth_err);
            Err(match auth_err {
                AuthErrorDetail::TokenMissingOrMalformed => StatusCode::BAD_REQUEST,
                AuthErrorDetail::TokenInvalid(_)
                | AuthErrorDetail::KidNotFoundInJwks
                | AuthErrorDetail::SignatureInvalid
                | AuthErrorDetail::TokenExpired => StatusCode::UNAUTHORIZED,
                AuthErrorDetail::JwksFetchFailed(_) | AuthErrorDetail::InvalidAuthConfig(_) => {
                    StatusCode::INTERNAL_SERVER_ERROR
                }
                AuthErrorDetail::IssuerMismatch { .. }
                | AuthErrorDetail::AudienceMismatch { .. }
                | AuthErrorDetail::InsufficientScope { .. } => StatusCode::FORBIDDEN,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use axum::{extract::Extension, middleware, routing::get, Router};
    use jsonwebtoken::{
        encode,
        jwk::{
            AlgorithmParameters as JwkAlgorithmParameters, CommonParameters as JwkCommonParameters,
            Jwk, KeyAlgorithm, PublicKeyUse as JwkPublicKeyUse, RSAKeyParameters, RSAKeyType,
        },
        Algorithm as JwtAlgorithm, EncodingKey, Header as JwtTestHeader,
    };
    use std::time::{SystemTime, UNIX_EPOCH};
    use tower::ServiceExt; // Para app.oneshot(request).await
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Constantes de teste (chaves e identificadores)
    const TEST_UNIT_RSA_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCyE54qG20VWunF\n\
oGyXHNFUFp12eiqbNY1khT+g5CXHCxafIxCtG2ovb6RhO7SAGfMDdrM01/5vZxf2\n\
ynx78pXDNbnPcIMab294djDSEJ3NZncxOnOJ7Clk6MF97sOXMbPzuB9+73rBS7gm\n\
jydn88tiLT0oiV9m21K2ucLjCRbDrPkkBg2XqlMny+Dq1oHtw1th4Q+FRs/hlC3W\n\
L1V14Tse5GZK1rrEh13XTKOCKMx47NugVWW3qJ2y7nPn6f/G5vgToB7334O2guS7\n\
CIQ9e/rtj3+hDeSSHwQfDjgGqCZlIdG5MDOm95F276oKISstxVexJ47kwoGRD4Xj\n\
xpnaT7oVAgMBAAECggEAC+AgC5nRn/t0nI/Svg8XbJ6neJe0EK61E6+JKz8bv9be\n\
9tTdT1YFMk2lLjDPnD1exevcDpma56393KDrRU7Lqv2BuzI7I/+rdOKY5eFizKhZ\n\
KYjG3LtJlWeqQ64xD/uqDwZH32y0CID2smeYjqek+BKhQftLR+43aWUg+IgKIxlg\n\
mej8A+/O6VWp7LKP5x5kjIZwXNrCpwWyar6iJtegLQmkr8EBBQuWt/W6CljGl5GP\n\
nTEKEzC93VV5dBMII3Vf7KHc7bnokSYyjmut/sp0HG1Xwkr1qD18HwnxK/OJDZf1\n\
303pST+0m6u77wJU3xxhLV7rLFSRY7NRIDIVqnKCLwKBgQD6oANN2X7Q/DVVYhb6\n\
fszD2rrOFL1HtCsYzLvhl3I6nMl/yQnQXnnrdEjfjXyUVWukm9KTJTuZAZw7Wgae\n\
NF0OrAWpzF/izOLK46ai2AJ6a/TuLcEWKX8yClEI6zBUBUDmm+Tr9/NJhS44A66H\n\
NzJgZa6rUvsk1VehrewoEdB/awKBgQC15UxLLyQqkE11SLKbg5Btl+cH7nccHr8S\n\
ugVeKx7mdleZi843r1KqnZArKOcXHJz/cePV7TKlRTO3ToLs+vnxQNbnLhXa5ePy\n\
j2jikdGLlXaXrj4T5Uq4ToxhDF972jXw/FRLkcncfyJwT/F9makAn27mP9GhEvP4\n\
RXr54RaMfwKBgQCQ7rXacDs5CZCiFr5pD6jEXhoHENFAxPzjM4o29AiXwpF39z9Y\n\
oznoIm/972kqspc0MvQ8KZzkZ5z8aZxIIsnpsSr5PXn5wzgn0ixMIZSVTRbwIb92\n\
XHr06ihgevmQrRUSBvcESngDfSP0OpTUFuRoAIVZB/y6GTG7CsP1jA/BjwKBgAN4\n\
3Ar3XGZfmMrrV1V2nnQpGSTinW1w/M67tEyG4DEgAy4QKCCR/S76kPzx6+9aAXky\n\
0FmODJBxELqoCgHCDLFZPoDtNUeXadGAgU0J4Ykbkkb08YRptRJtlWpo1Q3FLZBr\n\
EKTcpJDL8HlaXU67dylm4bQNdc/wT63mjaFldYu7AoGBAOPGWvzO04eiOqt7Mv7l\n\
0XYmIVBd9wIynBjeQ+e/uUZ/3MK7LfbRZ+nBdVT2vFRpICaZkCzUY/Y7LPNzdXPH\n\
qLLmcZuVCc5d+3NbgKFi6zUBcvoL/TxTDkA4XoyesQWK5sxvHMqPk9wdU6qMXjh7\n\
ezJCKjG5c2dOsKn0rAhlBzZg\n\
-----END PRIVATE KEY-----";
    const TEST_UNIT_RSA_PUBLIC_N_B64URL: &str = "shOeKhttFVrpxaBslxzRVBaddnoqmzWNZIU_oOQlxwsWnyMQrRtqL2-kYTu0gBnzA3azNNf-b2cX9sp8e_KVwzW5z3CDGm9veHYw0hCdzWZ3MTpziewpZOjBfe7DlzGz87gffu96wUu4Jo8nZ_PLYi09KIlfZttStrnC4wkWw6z5JAYNl6pTJ8vg6taB7cNbYeEPhUbP4ZQt1i9VdeE7HuRmSta6xIdd10yjgijMeOzboFVlt6idsu5z5-n_xub4E6Ae99-DtoLkuwiEPXv67Y9_oQ3kkh8EHw44BqgmZSHRuTAzpveRdu-qCiErLcVXsSeO5MKBkQ-F48aZ2k-6FQ";
    const TEST_UNIT_RSA_PUBLIC_E_B64URL: &str = "AQAB";
    const TEST_UNIT_KID_RS256: &str = "test-key-for-src-auth-unit-tests";
    const TEST_UNIT_ISSUER: &str = "test-issuer-for-src-auth";
    const TEST_UNIT_AUDIENCE: &str = "test-audience-for-src-auth";

    // Função helper para criar uma JWK pública para os testes
    fn rsa_public_jwk_for_src_auth_test() -> Jwk {
        Jwk {
            common: JwkCommonParameters {
                public_key_use: Some(JwkPublicKeyUse::Signature),
                key_algorithm: Some(KeyAlgorithm::RS256),
                key_id: Some(TEST_UNIT_KID_RS256.to_string()),
                ..Default::default() // Outros campos são None por padrão
            },
            algorithm: JwkAlgorithmParameters::RSA(RSAKeyParameters {
                key_type: RSAKeyType::RSA, // Define o tipo explicitamente
                n: TEST_UNIT_RSA_PUBLIC_N_B64URL.to_string(),
                e: TEST_UNIT_RSA_PUBLIC_E_B64URL.to_string(),
                // Campos privados (d, p, q, etc.) não são incluídos na chave pública JWK
            }),
        }
    }

    // Função helper para gerar um JWT de teste
    fn generate_test_jwt_for_src_auth(
        claims: &Claims,
        alg: JwtAlgorithm,
        kid: &str,
        private_key_pem: &str,
    ) -> String {
        let encoding_key = match alg {
            JwtAlgorithm::RS256 => EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
                .expect("Falha ao carregar chave RSA privada de teste."),
            _ => panic!("Algoritmo não suportado para este helper de teste."),
        };
        let mut header = JwtTestHeader::new(alg);
        header.kid = Some(kid.to_string());
        encode(&header, claims, &encoding_key).expect("Falha ao gerar JWT de teste.")
    }

    // Função helper para criar config::OAuth de teste
    fn test_oauth_config_for_src_auth(jwks_uri: String, enabled: bool) -> config::OAuth {
        config::OAuth {
            enabled,
            jwks_uri: Some(jwks_uri),
            issuer: Some(vec![TEST_UNIT_ISSUER.to_string()]),
            audience: Some(vec![TEST_UNIT_AUDIENCE.to_string()]),
            required_scopes: None,
            jwks_request_timeout_seconds: Some(5),
            jwks_refresh_interval_raw: Some("300s".to_string()), // Usado para parsear
            jwks_refresh_interval: Some(Duration::from_secs(300)), // Resultado do parse
        }
    }

    // Função helper para criar JwksCache de teste
    fn test_jwks_cache_for_src_auth(jwks_uri: String, http_client: reqwest::Client) -> JwksCache {
        JwksCache::new(jwks_uri, Duration::from_secs(300), http_client)
    }

    // Função helper para obter timestamp atual
    fn current_timestamp_for_test() -> usize {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("SystemTime antes de UNIX_EPOCH é impossível")
            .as_secs() as usize
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

        // Força o refresh inicial para garantir que o cache está populado
        jwks_cache.refresh_keys().await.expect("Refresh inicial do JWKS falhou");
        assert!(
            jwks_cache.check_health_for_readyz().await,
            "Cache JWKS não saudável após refresh forçado."
        );

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
        let token = generate_test_jwt_for_src_auth(
            &claims,
            JwtAlgorithm::RS256,
            TEST_UNIT_KID_RS256,
            TEST_UNIT_RSA_PRIVATE_KEY_PEM,
        );

        let app = Router::new()
            .route(
                "/",
                get(|Extension(auth_ctx): Extension<Arc<ClientAuthContext>>| async move {
                    assert_eq!(auth_ctx.user_id, "user123");
                    assert!(auth_ctx.scopes.contains("read"));
                    assert!(auth_ctx.scopes.contains("write"));
                    StatusCode::OK
                }),
            )
            .layer(middleware::from_fn_with_state(
                (jwks_cache.clone(), oauth_config.clone()),
                oauth_middleware,
            ));

        let request = axum::http::Request::builder()
            .uri("/")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("Falha ao construir request de teste - dados válidos");
        let response = app.oneshot(request).await.expect("Falha na execução do request de teste");
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Resposta inesperada para token válido. Corpo: {:?}",
            response.into_body()
        );
    }

    #[tokio::test]
    async fn test_jwks_cache_refresh_and_get_key() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let mock_server = MockServer::start().await;
        let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());

        let http_client = reqwest::Client::new();
        let cache = test_jwks_cache_for_src_auth(jwks_uri.clone(), http_client.clone());

        // Etapa 1: Simular falha no primeiro refresh (que ocorre dentro de check_health_for_readyz)
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(500).set_delay(Duration::from_millis(50))) // Simula erro do servidor JWKS
            .mount(&mock_server)
            .await;

        // check_health_for_readyz tentará um refresh, que falhará devido ao mock acima.
        assert!(
            !cache.check_health_for_readyz().await,
            "Cache não deveria estar saudável se o primeiro refresh (interno e mockado para falhar) falhar."
        );
        mock_server.reset().await; // Limpar o mock de falha

        // Etapa 2: Configurar mock para sucesso e fazer refresh explícito
        let public_jwk_rs256 = rsa_public_jwk_for_src_auth_test();
        let jwks_data = JwkSet { keys: vec![public_jwk_rs256.clone()] };
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(&jwks_data)
                    .set_delay(Duration::from_millis(50)),
            )
            .mount(&mock_server)
            .await;

        let refresh_result = cache.refresh_keys().await;
        assert!(
            refresh_result.is_ok(),
            "Falha ao atualizar chaves JWKS explicitamente após mock de sucesso: {:?}",
            refresh_result.err()
        );

        // Etapa 3: Agora check_health_for_readyz deve ser true
        assert!(
            cache.check_health_for_readyz().await,
            "Cache JWKS não saudável após refresh explícito bem-sucedido."
        );

        // Etapa 4: Testar get_decoding_key_for_kid
        let decoding_key_result = cache.get_decoding_key_for_kid(TEST_UNIT_KID_RS256).await;
        match decoding_key_result {
            Ok(Some(_key)) => {} // Sucesso, chave encontrada
            Ok(None) => panic!(
                "Chave não encontrada para kid '{TEST_UNIT_KID_RS256}' após refresh bem-sucedido"
            ),
            Err(e) => panic!("Erro ao obter chave para kid '{TEST_UNIT_KID_RS256}': {e:?}"),
        }

        let decoding_key_result_unknown = cache.get_decoding_key_for_kid("unknown-kid").await;
        match decoding_key_result_unknown {
            Ok(None) => {} // Sucesso, kid desconhecido não encontrado como esperado
            Ok(Some(_)) => {
                panic!("Chave encontrada para kid desconhecido ('unknown-kid'), esperado None")
            }
            Err(e) => panic!("Erro ao obter chave para KID desconhecido ('unknown-kid'): {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_jwks_cache_handles_http_error_on_refresh() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let mock_server = MockServer::start().await;
        let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(500)) // Simula erro do servidor JWKS
            .mount(&mock_server)
            .await;

        let http_client = reqwest::Client::new();
        let cache = test_jwks_cache_for_src_auth(jwks_uri, http_client);

        let refresh_result = cache.refresh_keys().await;
        assert!(refresh_result.is_err(), "Refresh deveria falhar com erro HTTP 500.");
        if let Err(AuthErrorDetail::JwksFetchFailed(msg)) = refresh_result {
            assert!(msg.contains("Status 500"), "Mensagem de erro não continha 'Status 500'");
        } else {
            panic!("Tipo de erro inesperado para falha no refresh: {refresh_result:?}");
        }
        assert!(
            !cache.check_health_for_readyz().await,
            "Cache JWKS não deveria estar saudável após falha no refresh."
        );
    }
}
