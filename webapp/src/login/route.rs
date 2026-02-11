use crate::config::*;
use axum::response::Response;
use weblib::login::{IdentityVerifier, RevokeToken, TokenVerifier, UserInfo};
use weblib::route;

#[route(GET, "/oauth2/authorize")]
async fn github(client: Oauth2Client, request: axum::extract::Request) -> Response {
    client.to_authorize(request).await
}

#[route(GET, "/oauth2/token")]
async fn google_token(client: Oauth2Client, request: axum::extract::Request) -> Response {
    client.exchange_code(request).await
}

#[route(GET, "/oauth2/revoke")]
async fn google_revoke_token(client: Oauth2Client, request: axum::extract::Request) -> Response {
    client.revoke_token(request).await
}

#[route(GET, "/oauth2/userinfo")]
async fn google_userinfo(client: Oauth2Client, request: axum::extract::Request) -> Response {
    client.user_info(request).await
}
