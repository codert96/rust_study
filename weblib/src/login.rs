#[cfg(all(feature = "redis", feature = "oauth2"))]
mod oauth2;
#[cfg(all(feature = "redis", feature = "openidconnect"))]
mod oidc;

use axum::response::Response;
use serde::Deserialize;

pub struct Client<Type, HttpClient, CacheStore, Scope> {
    inner: Type,
    http_client: HttpClient,
    cache_store: CacheStore,
    scopes: Vec<Scope>,
}

impl<Type, HttpClient, CacheStore, Scope> Client<Type, HttpClient, CacheStore, Scope> {
    pub fn new(
        inner: Type,
        http_client: HttpClient,
        cache_store: CacheStore,
        scopes: Vec<Scope>,
    ) -> Self {
        Self {
            inner,
            http_client,
            cache_store,
            scopes,
        }
    }

    pub fn inner(&self) -> &Type {
        &self.inner
    }

    pub fn http_client(&self) -> &HttpClient {
        &self.http_client
    }

}
pub trait IdentityVerifier {
    fn to_authorize(&self, request: axum::extract::Request) -> impl Future<Output = Response>;
}

pub trait TokenVerifier {
    fn exchange_code(&self, request: axum::extract::Request) -> impl Future<Output = Response>;
    fn refresh_token(&self, request: axum::extract::Request) -> impl Future<Output = Response>;
}

pub trait UserInfo {
    fn user_info(&self, request: axum::extract::Request) -> impl Future<Output = Response>;
}

pub trait RevokeToken {
    fn revoke_token(&self, request: axum::extract::Request) -> impl Future<Output = Response>;
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum RevokeType {
    AccessToken,
    RefreshToken,
}
#[derive(Deserialize)]
struct RevokeTokenRequest {
    revoke_type: RevokeType,
    token: String,
}
#[derive(Deserialize)]
struct AuthorizationCodeRequest {
    state: String,
    code: String,
}

#[derive(Deserialize)]
struct RefreshTokenRequest {
    token: String,
    scope: Vec<String>,
}
