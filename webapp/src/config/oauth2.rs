use axum::RequestPartsExt;
use axum::extract::{FromRequestParts, Query, Request};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::Response;
use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, ClientId, ClientSecret, DeviceAuthorizationUrl, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, RedirectUrl, RevocationUrl, TokenUrl,
};
use openidconnect::IssuerUrl;
use openidconnect::core::{CoreClient, CoreProviderMetadata};
use serde::Deserialize;
use serde_json::Value;
use std::error::Error;
use std::ops::Deref;
use weblib::bean;
use weblib::login::{
    Client as OAuthClient, IdentityVerifier, RevokeToken, TokenVerifier, UserInfo,
};
use weblib::result::ToResponse;
use weblib::state::{Bean, BeanContext};

pub type GithubClient = OAuthClient<
    BasicClient<EndpointSet, EndpointSet, EndpointNotSet, EndpointSet, EndpointSet>,
    oauth2::reqwest::Client,
    redis::aio::ConnectionManager,
    oauth2::Scope,
>;

#[bean(wait_for = redis::aio::ConnectionManager)]
async fn github_client(
    redis: Bean<redis::aio::ConnectionManager>,
) -> Result<GithubClient, Box<dyn Error>> {
    let http_client = oauth2::reqwest::Client::builder()
        .redirect(oauth2::reqwest::redirect::Policy::none())
        .proxy(oauth2::reqwest::Proxy::all("http://127.0.0.1:7897")?)
        .build()?;
    let client_id = std::env::var("GITHUB_CLIENT_ID")?;
    let client = BasicClient::new(ClientId::new(client_id.to_string()))
        .set_client_secret(ClientSecret::new(std::env::var("GITHUB_CLIENT_SECRET")?))
        .set_auth_uri(AuthUrl::new(
            "https://github.com/login/oauth/authorize".to_string(),
        )?)
        .set_token_uri(TokenUrl::new(
            "https://github.com/login/oauth/access_token".to_string(),
        )?)
        .set_revocation_url(RevocationUrl::new(format!(
            "https://api.github.com/applications/{client_id}/token"
        ))?)
        .set_redirect_uri(RedirectUrl::new(
            "http://127.0.0.1:8080/login/oauth2/code?login_type=github".to_string(),
        )?)
        .set_device_authorization_url(DeviceAuthorizationUrl::new(
            "https://github.com/login/device/code".to_string(),
        )?);
    let redis = redis.deref().clone();
    let client = OAuthClient::new(
        client,
        http_client,
        redis,
        vec![
            oauth2::Scope::new("read:user".to_string()),
            oauth2::Scope::new("user:email".to_string()),
        ],
    );
    Ok(client)
}
pub type GoogleClient = OAuthClient<
    CoreClient<
        EndpointSet,
        EndpointNotSet,
        EndpointNotSet,
        EndpointSet,
        EndpointMaybeSet,
        EndpointMaybeSet,
    >,
    openidconnect::reqwest::Client,
    redis::aio::ConnectionManager,
    openidconnect::Scope,
>;
#[bean(wait_for = redis::aio::ConnectionManager)]
async fn google_client(
    redis: Bean<redis::aio::ConnectionManager>,
) -> Result<GoogleClient, Box<dyn Error>> {
    let http_client = openidconnect::reqwest::Client::builder()
        .proxy(openidconnect::reqwest::Proxy::all("http://127.0.0.1:7897")?)
        .build()?;
    let provider_metadata = CoreProviderMetadata::discover_async(
        IssuerUrl::new("https://accounts.google.com".to_string())?,
        &http_client,
    )
    .await?;
    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(std::env::var("GOOGLE_CLIENT_ID")?),
        Some(ClientSecret::new(std::env::var("GOOGLE_CLIENT_SECRET")?)),
    )
    .set_revocation_url(RevocationUrl::new(
        "https://oauth2.googleapis.com/revoke".to_string(),
    )?)
    .set_redirect_uri(RedirectUrl::new(
        "http://127.0.0.1:8080/login/oauth2/code?login_type=google".to_string(),
    )?);
    let redis = redis.deref().clone();

    let client = OAuthClient::new(
        client,
        http_client,
        redis,
        vec![
            openidconnect::Scope::new("openid".to_string()),
            openidconnect::Scope::new("email".to_string()),
            openidconnect::Scope::new("profile".to_string()),
        ],
    );
    Ok(client)
}

pub enum Oauth2Client {
    Github(Bean<GithubClient>),
    Google(Bean<GoogleClient>),
}

#[derive(Deserialize)]
struct Oauth2Request {
    login_type: LoginType,
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum LoginType {
    Github,
    Google,
}
impl FromRequestParts<BeanContext> for Oauth2Client {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &BeanContext,
    ) -> Result<Self, Self::Rejection> {
        let args: Query<Oauth2Request> = parts
            .extract()
            .await
            .map_err(|_| (StatusCode::BAD_REQUEST, "缺少login_type参数").to_response())?;
        let client = match args.login_type {
            LoginType::Github => {
                let client: Bean<GithubClient> = state
                    .get()
                    .ok_or_else(|| (StatusCode::BAD_REQUEST, "缺少GithubClient").to_response())?;
                Oauth2Client::Github(client)
            }
            LoginType::Google => {
                let client: Bean<GoogleClient> = state
                    .get()
                    .ok_or_else(|| (StatusCode::BAD_REQUEST, "缺少GoogleClient").to_response())?;
                Oauth2Client::Google(client)
            }
        };
        Ok(client)
    }
}
impl IdentityVerifier for Oauth2Client {
    async fn to_authorize(&self, request: Request) -> Response {
        match self {
            Oauth2Client::Github(client) => client.to_authorize(request).await,
            Oauth2Client::Google(client) => client.to_authorize(request).await,
        }
    }
}

impl TokenVerifier for Oauth2Client {
    async fn exchange_code(&self, request: Request) -> Response {
        match self {
            Oauth2Client::Github(client) => client.exchange_code(request).await,
            Oauth2Client::Google(client) => client.exchange_code(request).await,
        }
    }

    async fn refresh_token(&self, request: Request) -> Response {
        match self {
            Oauth2Client::Github(client) => client.refresh_token(request).await,
            Oauth2Client::Google(client) => client.refresh_token(request).await,
        }
    }
}

impl UserInfo for Oauth2Client {
    async fn user_info(&self, request: Request) -> Response {
        match self {
            Oauth2Client::Github(client) => {
                let result: Result<_, Box<dyn Error>> = async move {
                    let response = client
                        .http_client()
                        .get("https://api.github.com/user")
                        .header(reqwest::header::ACCEPT, "application/vnd.github.v3+json")
                        .header(
                            reqwest::header::AUTHORIZATION,
                            request
                                .headers()
                                .get(axum::http::header::AUTHORIZATION)
                                .ok_or("missing authorization header")?,
                        )
                        .header(
                            reqwest::header::USER_AGENT,
                            request
                                .headers()
                                .get(axum::http::header::USER_AGENT)
                                .ok_or("missing authorization header")?,
                        )
                        .send()
                        .await?;
                    let status = response.status().as_u16();
                    let json = response.text().await?;
                    let json: Value = serde_json::from_str(&json)?;
                    Ok((StatusCode::from_u16(status)?, json))
                }
                .await;
                match result {
                    Ok(result) => {
                        let mut response = Some(result.1).to_response();
                        *response.status_mut() = result.0;
                        response
                    }
                    Err(err) => (StatusCode::UNAUTHORIZED, err.to_string()).to_response(),
                }
            }
            Oauth2Client::Google(client) => client.user_info(request).await,
        }
    }
}

impl RevokeToken for Oauth2Client {
    async fn revoke_token(&self, request: Request) -> Response {
        match self {
            Oauth2Client::Github(client) => client.revoke_token(request).await,
            Oauth2Client::Google(client) => client.revoke_token(request).await,
        }
    }
}
