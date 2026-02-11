use super::{
    AuthorizationCodeRequest, Client as OAuthClient, IdentityVerifier, RefreshTokenRequest,
    RevokeToken, RevokeTokenRequest, RevokeType, TokenVerifier,
};
use crate::result::ToResponse;
use axum::extract::{Query, Request};
use axum::http::StatusCode;
use axum::response::{Redirect, Response};
use axum::{Form, RequestExt};
use oauth2::{
    AccessToken, AuthorizationCode, Client, CsrfToken, EndpointMaybeSet, EndpointSet,
    EndpointState, ErrorResponse, PkceCodeChallenge, PkceCodeVerifier, RefreshToken,
    RevocableToken, StandardRevocableToken, TokenIntrospectionResponse, TokenResponse,
};
use redis::RedisResult;
use std::error::Error;

impl<TE, TR, TIR, RT, TRE, HasDeviceAuthUrl, HasIntrospectionUrl, HasRevocationUrl, HasTokenUrl>
    IdentityVerifier
    for OAuthClient<
        Client<
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
        >,
        oauth2::reqwest::Client,
        redis::aio::ConnectionManager,
        oauth2::Scope,
    >
where
    TE: ErrorResponse + 'static,
    TR: TokenResponse,
    TIR: TokenIntrospectionResponse,
    RT: RevocableToken,
    TRE: ErrorResponse + 'static,
    HasDeviceAuthUrl: EndpointState,
    HasIntrospectionUrl: EndpointState,
    HasRevocationUrl: EndpointState,
    HasTokenUrl: EndpointState,
{
    async fn to_authorize(&self, _: Request) -> Response {
        async move {
            let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

            let (auth_url, csrf_token) = self
                .inner
                .authorize_url(CsrfToken::new_random)
                .add_scopes(self.scopes.clone())
                .set_pkce_challenge(pkce_challenge)
                .url();
            let redis_key: &str = &format!("oauth:csrf:{}", csrf_token.secret());
            let redis_result: RedisResult<(i64, bool)> = redis::pipe()
                .hset(redis_key, "pkce_verifier", pkce_verifier.secret())
                .expire(redis_key, 30)
                .query_async(&mut self.cache_store.clone())
                .await;
            match redis_result {
                Ok(_) => Redirect::to(auth_url.as_ref()).to_response(),
                Err(err) => (StatusCode::UNAUTHORIZED, err.to_string()).to_response(),
            }
        }
        .await
        .to_response()
    }
}

impl<TE, TR, TIR, RT, TRE, HasAuthUrl, HasDeviceAuthUrl, HasIntrospectionUrl, HasRevocationUrl>
    TokenVerifier
    for OAuthClient<
        Client<
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
        >,
        oauth2::reqwest::Client,
        redis::aio::ConnectionManager,
        oauth2::Scope,
    >
where
    TE: ErrorResponse + 'static,
    TR: TokenResponse,
    TIR: TokenIntrospectionResponse,
    RT: RevocableToken,
    TRE: ErrorResponse + 'static,
    HasAuthUrl: EndpointState,
    HasDeviceAuthUrl: EndpointState,
    HasIntrospectionUrl: EndpointState,
    HasRevocationUrl: EndpointState,
{
    async fn exchange_code(&self, request: Request) -> Response {
        let result: Result<_, Box<dyn Error>> = async move {
            let Query(request_args): Query<AuthorizationCodeRequest> = request.extract().await?;
            let redis_key: &str = &format!("oauth:csrf:{}", &request_args.state);
            let redis_result: (String, i64) = redis::pipe()
                .hget(redis_key, "pkce_verifier")
                .del(redis_key)
                .query_async(&mut self.cache_store.clone())
                .await?;
            let token_response = self
                .inner
                .exchange_code(AuthorizationCode::new(request_args.code))
                .set_pkce_verifier(PkceCodeVerifier::new(redis_result.0))
                .request_async(&self.http_client)
                .await?;
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

impl<TE, TR, TIR, RT, TRE, HasAuthUrl, HasDeviceAuthUrl, HasIntrospectionUrl, HasRevocationUrl>
    TokenVerifier
    for OAuthClient<
        Client<
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
        >,
        oauth2::reqwest::Client,
        redis::aio::ConnectionManager,
        oauth2::Scope,
    >
where
    TE: ErrorResponse + 'static,
    TR: TokenResponse,
    TIR: TokenIntrospectionResponse,
    RT: RevocableToken,
    TRE: ErrorResponse + 'static,
    HasAuthUrl: EndpointState,
    HasDeviceAuthUrl: EndpointState,
    HasIntrospectionUrl: EndpointState,
    HasRevocationUrl: EndpointState,
{
    async fn exchange_code(&self, request: Request) -> Response {
        let result: Result<_, Box<dyn Error>> = async move {
            let Query(request_args): Query<AuthorizationCodeRequest> = request.extract().await?;
            let redis_key: &str = &format!("oauth:csrf:{}", &request_args.state);
            let redis_result: (String, i64) = redis::pipe()
                .hget(redis_key, "pkce_verifier")
                .del(redis_key)
                .query_async(&mut self.cache_store.clone())
                .await?;
            let token_response = self
                .inner
                .exchange_code(AuthorizationCode::new(request_args.code))?
                .set_pkce_verifier(PkceCodeVerifier::new(redis_result.0))
                .request_async(&self.http_client)
                .await?;
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

impl<TE, TR, TIR, TRE, HasAuthUrl, HasDeviceAuthUrl, HasIntrospectionUrl, HasTokenUrl> RevokeToken
    for OAuthClient<
        Client<
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
        >,
        oauth2::reqwest::Client,
        redis::aio::ConnectionManager,
        oauth2::Scope,
    >
where
    TE: ErrorResponse + 'static,
    TR: TokenResponse,
    TIR: TokenIntrospectionResponse,
    TRE: ErrorResponse + 'static,
    HasAuthUrl: EndpointState,
    HasDeviceAuthUrl: EndpointState,
    HasIntrospectionUrl: EndpointState,
    HasTokenUrl: EndpointState,
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
