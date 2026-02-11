use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, ClientId, ClientSecret, DeviceAuthorizationUrl, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, RedirectUrl, RevocationUrl, TokenUrl,
};
use openidconnect::IssuerUrl;
use openidconnect::core::{CoreClient, CoreProviderMetadata};
use std::error::Error;
use std::ops::Deref;
use weblib::bean;
use weblib::login::Client as OAuthClient;
use weblib::state::Bean;

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
