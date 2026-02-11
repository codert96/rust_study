use crate::config::*;
use axum::http::StatusCode;
use axum::response::Response;
use serde_json::Value;
use std::error::Error;
use weblib::login::{IdentityVerifier, RevokeToken, TokenVerifier, UserInfo};
use weblib::result::ToResponse;
use weblib::route;
use weblib::state::Bean;

#[route(GET, "/github/oauth2/authorize")]
async fn github(client: Bean<GithubClient>, request: axum::extract::Request) -> Response {
    client.to_authorize(request).await
}
#[route(GET, "/google/oauth2/authorize")]
async fn google(client: Bean<GoogleClient>, request: axum::extract::Request) -> Response {
    client.to_authorize(request).await
}

#[route(GET, "/google/oauth2/token")]
async fn google_token(client: Bean<GoogleClient>, request: axum::extract::Request) -> Response {
    client.exchange_code(request).await
}

#[route(GET, "/github/oauth2/token")]
async fn github_token(client: Bean<GithubClient>, request: axum::extract::Request) -> Response {
    client.exchange_code(request).await
}

#[route(GET, "/google/oauth2/revoke")]
async fn google_revoke_token(
    client: Bean<GoogleClient>,
    request: axum::extract::Request,
) -> Response {
    client.revoke_token(request).await
}

#[route(GET, "/github/oauth2/revoke")]
async fn github_revoke_token(
    client: Bean<GithubClient>,
    request: axum::extract::Request,
) -> Response {
    client.revoke_token(request).await
}

#[route(GET, "/google/oauth2/userinfo")]
async fn google_userinfo(client: Bean<GoogleClient>, request: axum::extract::Request) -> Response {
    client.user_info(request).await
}

#[route(GET, "/github/oauth2/userinfo")]
async fn github_userinfo(client: Bean<GithubClient>, request: axum::extract::Request) -> Response {
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
