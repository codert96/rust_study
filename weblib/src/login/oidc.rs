use super::{
    AuthorizationCodeRequest, Client as OAuthClient, IdentityVerifier, RefreshTokenRequest,
    RevokeToken, RevokeTokenRequest, RevokeType, TokenVerifier, UserInfo,
};
use crate::result::ToResponse;
use axum::extract::{Query, Request};
use axum::http::StatusCode;
use axum::response::{Redirect, Response};
use axum::{Form, RequestExt};
use oauth2::{
    AccessToken, AuthorizationCode, CsrfToken, EndpointMaybeSet, EndpointSet, EndpointState,
    ErrorResponse, PkceCodeChallenge, PkceCodeVerifier, RefreshToken, RevocableToken,
    StandardRevocableToken, TokenIntrospectionResponse,
};
use openidconnect::core::CoreAuthenticationFlow;
use openidconnect::{
    AccessTokenHash, AdditionalClaims, AuthDisplay, AuthPrompt, Client, GenderClaim, JsonWebKey,
    JweContentEncryptionAlgorithm, JwsSigningAlgorithm, Nonce, TokenResponse,
};
use redis::RedisResult;
use std::error::Error;

impl<
    AC,
    AD,
    GC,
    JE,
    K,
    P,
    TE,
    TR,
    TIR,
    RT,
    TRE,
    HasDeviceAuthUrl,
    HasIntrospectionUrl,
    HasRevocationUrl,
    HasTokenUrl,
    HasUserInfoUrl,
> IdentityVerifier
    for OAuthClient<
        Client<
            AC,
            AD,
            GC,
            JE,
            K,
            P,
            TE,
            TR,
            TIR,
            RT,
            TRE,
            EndpointSet,
            HasDeviceAuthUrl,
            HasIntrospectionUrl,
            HasRevocationUrl,
            HasTokenUrl,
            HasUserInfoUrl,
        >,
        openidconnect::reqwest::Client,
        redis::aio::ConnectionManager,
        openidconnect::Scope,
    >
where
    AC: AdditionalClaims,
    AD: AuthDisplay,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm<
        KeyType = <K::SigningAlgorithm as JwsSigningAlgorithm>::KeyType,
    >,
    K: JsonWebKey,
    P: AuthPrompt,
    TE: ErrorResponse + 'static,
    TR: TokenResponse<AC, GC, JE, K::SigningAlgorithm>,
    TIR: TokenIntrospectionResponse,
    RT: RevocableToken,
    TRE: ErrorResponse + 'static,
    HasDeviceAuthUrl: EndpointState,
    HasIntrospectionUrl: EndpointState,
    HasRevocationUrl: EndpointState,
    HasTokenUrl: EndpointState,
    HasUserInfoUrl: EndpointState,
{
    async fn to_authorize(&self, _: Request) -> Response {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let (auth_url, csrf_token, nonce) = self
            .inner
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scopes(self.scopes.clone())
            .set_pkce_challenge(pkce_challenge)
            .url();

        let redis_key: &str = &format!("oauth:csrf:{}", csrf_token.secret());
        let redis_result: RedisResult<(i64, i64, bool)> = redis::pipe()
            .hset(redis_key, "pkce_verifier", pkce_verifier.secret())
            .hset(redis_key, "nonce", nonce.secret())
            .expire(redis_key, 30)
            .query_async(&mut self.cache_store.clone())
            .await;
        match redis_result {
            Ok(_) => Redirect::to(auth_url.as_ref()).to_response(),
            Err(err) => (StatusCode::UNAUTHORIZED, err.to_string()).to_response(),
        }
    }
}

impl<
    AC,
    AD,
    GC,
    JE,
    K,
    P,
    TE,
    TR,
    TIR,
    RT,
    TRE,
    HasAuthUrl,
    HasDeviceAuthUrl,
    HasIntrospectionUrl,
    HasRevocationUrl,
    HasUserInfoUrl,
> TokenVerifier
    for OAuthClient<
        Client<
            AC,
            AD,
            GC,
            JE,
            K,
            P,
            TE,
            TR,
            TIR,
            RT,
            TRE,
            HasAuthUrl,
            HasDeviceAuthUrl,
            HasIntrospectionUrl,
            HasRevocationUrl,
            EndpointSet,
            HasUserInfoUrl,
        >,
        openidconnect::reqwest::Client,
        redis::aio::ConnectionManager,
        openidconnect::Scope,
    >
where
    AC: AdditionalClaims,
    AD: AuthDisplay,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm<
        KeyType = <K::SigningAlgorithm as JwsSigningAlgorithm>::KeyType,
    >,
    K: JsonWebKey,
    P: AuthPrompt,
    TE: ErrorResponse + 'static,
    TR: TokenResponse<AC, GC, JE, K::SigningAlgorithm>,
    TIR: TokenIntrospectionResponse,
    RT: RevocableToken,
    TRE: ErrorResponse + 'static,
    HasAuthUrl: EndpointState,
    HasDeviceAuthUrl: EndpointState,
    HasIntrospectionUrl: EndpointState,
    HasRevocationUrl: EndpointState,
    HasUserInfoUrl: EndpointState,
{
    //noinspection ALL
    async fn exchange_code(&self, request: Request) -> Response {
        let result: Result<_, Box<dyn Error>> = async move {
            let Query(request_args): Query<AuthorizationCodeRequest> = request.extract().await?;
            let redis_key: &str = &format!("oauth:csrf:{}", &request_args.state);
            let redis_result: (String, String) = redis::pipe()
                .hget(redis_key, "pkce_verifier")
                .hget(redis_key, "nonce")
                .del(redis_key)
                .query_async(&mut self.cache_store.clone())
                .await?;

            let token_response = self
                .inner
                .exchange_code(AuthorizationCode::new(request_args.code))
                // Set the PKCE code verifier.
                .set_pkce_verifier(PkceCodeVerifier::new(redis_result.0))
                .request_async(&self.http_client)
                .await?;
            if token_response.id_token().is_some() {
                let id_token = token_response.id_token().unwrap();
                let id_token_verifier = self.inner.id_token_verifier();
                let claims = id_token.claims(&id_token_verifier, &Nonce::new(redis_result.1))?;
                if let Some(expected_access_token_hash) = claims.access_token_hash() {
                    let actual_access_token_hash = AccessTokenHash::from_token(
                        token_response.access_token(),
                        id_token.signing_alg()?,
                        id_token.signing_key(&id_token_verifier)?,
                    )?;
                    if actual_access_token_hash != *expected_access_token_hash {
                        return Err("Invalid access token".into());
                    }
                }
            }
            Ok(token_response)
        }
        .await;
        result.to_response()
    }

    //noinspection ALL
    async fn refresh_token(&self, request: Request) -> Response {
        let result: Result<_, Box<dyn Error>> = async move {
            let Form(request_args): Form<RefreshTokenRequest> = request.extract().await?;
            let scope: Vec<openidconnect::Scope> = request_args
                .scope
                .into_iter()
                .map(openidconnect::Scope::new)
                .collect();

            self.inner
                .exchange_refresh_token(&RefreshToken::new(request_args.token))
                .add_scopes(scope)
                .request_async(&self.http_client)
                .await
                .map_err(Into::into)
        }
        .await;
        result.to_response()
    }
}

impl<
    AC,
    AD,
    GC,
    JE,
    K,
    P,
    TE,
    TR,
    TIR,
    RT,
    TRE,
    HasAuthUrl,
    HasDeviceAuthUrl,
    HasIntrospectionUrl,
    HasRevocationUrl,
    HasUserInfoUrl,
> TokenVerifier
    for OAuthClient<
        Client<
            AC,
            AD,
            GC,
            JE,
            K,
            P,
            TE,
            TR,
            TIR,
            RT,
            TRE,
            HasAuthUrl,
            HasDeviceAuthUrl,
            HasIntrospectionUrl,
            HasRevocationUrl,
            EndpointMaybeSet,
            HasUserInfoUrl,
        >,
        openidconnect::reqwest::Client,
        redis::aio::ConnectionManager,
        openidconnect::Scope,
    >
where
    AC: AdditionalClaims,
    AD: AuthDisplay,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm<
        KeyType = <K::SigningAlgorithm as JwsSigningAlgorithm>::KeyType,
    >,
    K: JsonWebKey,
    P: AuthPrompt,
    TE: ErrorResponse + 'static,
    TR: TokenResponse<AC, GC, JE, K::SigningAlgorithm>,
    TIR: TokenIntrospectionResponse,
    RT: RevocableToken,
    TRE: ErrorResponse + 'static,
    HasAuthUrl: EndpointState,
    HasDeviceAuthUrl: EndpointState,
    HasIntrospectionUrl: EndpointState,
    HasRevocationUrl: EndpointState,
    HasUserInfoUrl: EndpointState,
{
    //noinspection ALL
    async fn exchange_code(&self, request: Request) -> Response {
        let result: Result<_, Box<dyn Error>> = async move {
            let Query(request_args): Query<AuthorizationCodeRequest> = request.extract().await?;
            let redis_key: &str = &format!("oauth:csrf:{}", &request_args.state);
            let redis_result: (String, String, i64) = redis::pipe()
                .hget(redis_key, "pkce_verifier")
                .hget(redis_key, "nonce")
                .del(redis_key)
                .query_async(&mut self.cache_store.clone())
                .await?;

            let token_response = self
                .inner
                .exchange_code(AuthorizationCode::new(request_args.code))?
                .set_pkce_verifier(PkceCodeVerifier::new(redis_result.0))
                .request_async(&self.http_client)
                .await?;
            if token_response.id_token().is_some() {
                let id_token = token_response.id_token().unwrap();
                let id_token_verifier = self.inner.id_token_verifier();
                let claims = id_token.claims(&id_token_verifier, &Nonce::new(redis_result.1))?;
                if let Some(expected_access_token_hash) = claims.access_token_hash() {
                    let actual_access_token_hash = AccessTokenHash::from_token(
                        token_response.access_token(),
                        id_token.signing_alg()?,
                        id_token.signing_key(&id_token_verifier)?,
                    )?;
                    if actual_access_token_hash != *expected_access_token_hash {
                        return Err("Invalid access token".into());
                    }
                }
            }
            Ok(token_response)
        }
        .await;
        result.to_response()
    }

    //noinspection ALL
    async fn refresh_token(&self, request: Request) -> Response {
        let result: Result<_, Box<dyn Error>> = async move {
            let Form(request_args): Form<RefreshTokenRequest> = request.extract().await?;
            let scope: Vec<openidconnect::Scope> = request_args
                .scope
                .into_iter()
                .map(openidconnect::Scope::new)
                .collect();

            self.inner
                .exchange_refresh_token(&RefreshToken::new(request_args.token))?
                .add_scopes(scope)
                .request_async(&self.http_client)
                .await
                .map_err(Into::into)
        }
        .await;
        result.to_response()
    }
}

impl<
    AC,
    AD,
    GC,
    JE,
    K,
    P,
    TE,
    TR,
    TIR,
    TRE,
    HasAuthUrl,
    HasDeviceAuthUrl,
    HasIntrospectionUrl,
    HasTokenUrl,
    HasUserInfoUrl,
> RevokeToken
    for OAuthClient<
        Client<
            AC,
            AD,
            GC,
            JE,
            K,
            P,
            TE,
            TR,
            TIR,
            StandardRevocableToken,
            TRE,
            HasAuthUrl,
            HasDeviceAuthUrl,
            HasIntrospectionUrl,
            EndpointSet,
            HasTokenUrl,
            HasUserInfoUrl,
        >,
        openidconnect::reqwest::Client,
        redis::aio::ConnectionManager,
        openidconnect::Scope,
    >
where
    AC: AdditionalClaims,
    AD: AuthDisplay,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm<
        KeyType = <K::SigningAlgorithm as JwsSigningAlgorithm>::KeyType,
    >,
    K: JsonWebKey,
    P: AuthPrompt,
    TE: ErrorResponse + 'static,
    TR: TokenResponse<AC, GC, JE, K::SigningAlgorithm>,
    TIR: TokenIntrospectionResponse,
    TRE: ErrorResponse + 'static,
    HasAuthUrl: EndpointState,
    HasDeviceAuthUrl: EndpointState,
    HasIntrospectionUrl: EndpointState,
    HasTokenUrl: EndpointState,
    HasUserInfoUrl: EndpointState,
{
    //noinspection ALL
    async fn revoke_token(&self, request: Request) -> Response {
        let result: Result<_, Box<dyn Error>> = async move {
            let Query(request_args): Query<RevokeTokenRequest> = request.extract().await?;
            let revoke_token = match request_args.revoke_type {
                RevokeType::AccessToken => {
                    StandardRevocableToken::AccessToken(AccessToken::new(request_args.token))
                }
                RevokeType::RefreshToken => {
                    StandardRevocableToken::RefreshToken(RefreshToken::new(request_args.token))
                }
            };
            self.inner
                .revoke_token(revoke_token)?
                .request_async(&self.http_client)
                .await
                .map_err(Into::into)
        }
        .await;
        result.to_response()
    }
}

impl<
    AC,
    AD,
    GC,
    JE,
    K,
    P,
    TE,
    TR,
    TIR,
    RT,
    TRE,
    HasAuthUrl,
    HasDeviceAuthUrl,
    HasIntrospectionUrl,
    HasRevocationUrl,
    HasTokenUrl,
> UserInfo
    for OAuthClient<
        Client<
            AC,
            AD,
            GC,
            JE,
            K,
            P,
            TE,
            TR,
            TIR,
            RT,
            TRE,
            HasAuthUrl,
            HasDeviceAuthUrl,
            HasIntrospectionUrl,
            HasRevocationUrl,
            HasTokenUrl,
            EndpointSet,
        >,
        openidconnect::reqwest::Client,
        redis::aio::ConnectionManager,
        openidconnect::Scope,
    >
where
    AC: AdditionalClaims,
    AD: AuthDisplay,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm<
        KeyType = <K::SigningAlgorithm as JwsSigningAlgorithm>::KeyType,
    >,
    K: JsonWebKey,
    P: AuthPrompt,
    TE: ErrorResponse + 'static,
    TR: TokenResponse<AC, GC, JE, K::SigningAlgorithm>,
    TIR: TokenIntrospectionResponse,
    RT: RevocableToken,
    TRE: ErrorResponse + 'static,
    HasAuthUrl: EndpointState,
    HasDeviceAuthUrl: EndpointState,
    HasIntrospectionUrl: EndpointState,
    HasRevocationUrl: EndpointState,
    HasTokenUrl: EndpointState,
{
    async fn user_info(&self, request: Request) -> Response {
        let result: Result<_, Box<dyn Error>> = async move {
            let authorization = request
                .headers()
                .get(axum::http::header::AUTHORIZATION)
                .ok_or("Authorization header missing")?;
            let authorization = String::from_utf8_lossy(authorization.as_ref());
            let authorization = authorization
                .split_once(" ")
                .ok_or("Authorization header is error")?;

            let access_token = AccessToken::new(authorization.1.to_string());
            self.inner
                .user_info(access_token, None)
                .request_async::<AC, openidconnect::reqwest::Client, GC>(&self.http_client)
                .await
                .map_err(Into::into)
        }
        .await;
        result.to_response()
    }
}

impl<
    AC,
    AD,
    GC,
    JE,
    K,
    P,
    TE,
    TR,
    TIR,
    RT,
    TRE,
    HasAuthUrl,
    HasDeviceAuthUrl,
    HasIntrospectionUrl,
    HasRevocationUrl,
    HasTokenUrl,
> UserInfo
    for OAuthClient<
        Client<
            AC,
            AD,
            GC,
            JE,
            K,
            P,
            TE,
            TR,
            TIR,
            RT,
            TRE,
            HasAuthUrl,
            HasDeviceAuthUrl,
            HasIntrospectionUrl,
            HasRevocationUrl,
            HasTokenUrl,
            EndpointMaybeSet,
        >,
        openidconnect::reqwest::Client,
        redis::aio::ConnectionManager,
        openidconnect::Scope,
    >
where
    AC: AdditionalClaims,
    AD: AuthDisplay,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm<
        KeyType = <K::SigningAlgorithm as JwsSigningAlgorithm>::KeyType,
    >,
    K: JsonWebKey,
    P: AuthPrompt,
    TE: ErrorResponse + 'static,
    TR: TokenResponse<AC, GC, JE, K::SigningAlgorithm>,
    TIR: TokenIntrospectionResponse,
    RT: RevocableToken,
    TRE: ErrorResponse + 'static,
    HasAuthUrl: EndpointState,
    HasDeviceAuthUrl: EndpointState,
    HasIntrospectionUrl: EndpointState,
    HasRevocationUrl: EndpointState,
    HasTokenUrl: EndpointState,
{
    async fn user_info(&self, request: Request) -> Response {
        let result: Result<_, Box<dyn Error>> = async move {
            let authorization = request
                .headers()
                .get(axum::http::header::AUTHORIZATION)
                .ok_or("Authorization header missing")?;
            let authorization = String::from_utf8_lossy(authorization.as_ref());
            let authorization = authorization
                .split_once(" ")
                .ok_or("Authorization header is error")?;

            let access_token = AccessToken::new(authorization.1.to_string());
            self.inner
                .user_info(access_token, None)?
                .request_async::<AC, openidconnect::reqwest::Client, GC>(&self.http_client)
                .await
                .map_err(Into::into)
        }
        .await;
        result.to_response()
    }
}
