use crate::config::{LoginClientManager, LoginClientSource, OAuth2Login, RedisPool};
use axum::body::Body;
use axum::extract::{Path, Query};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;
use std::ops::Deref;
use weblib::result::ToResponse;
use weblib::route;
use weblib::state::Bean;

#[derive(Deserialize, Debug)]
pub struct OAuth2CodeParams {
    pub login_type: String,
    pub code: String,
    pub state: String,
}

#[route(GET, "/oauth2/authorize/{login_type}")]
pub async fn oauth2_authorize(
    Path(login_type): Path<String>,
    client: Bean<LoginClientManager>,
    redis: Bean<RedisPool>,
) -> Response<Body> {
    let login = client.get(&login_type);
    if let Some(login) = login {
        let result = match login {
            LoginClientSource::Google(client) => client.authorize_url(vec!["".to_string()]),
            LoginClientSource::Github(client) => client.authorize_url(vec!["".to_string()]),
        }
        .await;
        match result {
            Ok((csrf_token, pkce_verifier, nonce, redirect)) => {
                let mut redis = redis.deref().clone();
                let redis_key = csrf_redis_key(&csrf_token);
                let redis_result = redis::pipe()
                    .atomic()
                    .hset(&redis_key, "pkce_verifier", pkce_verifier)
                    .hset(&redis_key, "nonce", nonce)
                    .expire(&redis_key, 30)
                    .query_async(&mut redis)
                    .await
                    .map(|_: (i64, i64, bool)| ())
                    .map_err(|e| e.to_string());
                match redis_result {
                    Ok(_) => redirect.into_response(),
                    Err(e) => (StatusCode::UNAUTHORIZED, e).to_response(),
                }
            }
            Err(err) => (StatusCode::UNAUTHORIZED, err.to_string()).to_response(),
        }
    } else {
        (StatusCode::UNAUTHORIZED, "不支持的登录类型").to_response()
    }
}

#[route(GET, "/oauth2/token")]
pub async fn oauth2_token(
    params: Query<OAuth2CodeParams>,
    client: Bean<LoginClientManager>,
    redis: Bean<RedisPool>,
) -> Response {
    if let Some(client) = client.get(&params.login_type) {
        let mut redis = redis.deref().clone();
        let redis_key = csrf_redis_key(&params.state);

        let redis_result: Result<(String, String), String> = redis::pipe()
            .atomic()
            .hget(&redis_key, "pkce_verifier")
            .hget(&redis_key, "nonce")
            .query_async(&mut redis)
            .await
            .map_err(|e| e.to_string());
        let code = &params.code;
        if redis_result.is_err() {
            return (StatusCode::UNAUTHORIZED, redis_result.err().unwrap()).to_response();
        }
        let (pkce_verifier, nonce) = redis_result.unwrap();

        match client {
            LoginClientSource::Google(client) => client
                .exchange_code(code.clone(), pkce_verifier, nonce)
                .await
                .map(|token| json!(token)),
            LoginClientSource::Github(client) => client
                .exchange_code(code.clone(), pkce_verifier, nonce)
                .await
                .map(|token| json!(token)),
        }
        .to_response()
    } else {
        (StatusCode::UNAUTHORIZED, "不支持的登录类型").to_response()
    }
}

fn csrf_redis_key(csrf: &str) -> String {
    format!("oauth2:csrf:{}", csrf)
}

#[route(GET, "/oauth2/user/{login_type}")]
pub async fn oauth2_user(
    Path(login_type): Path<String>,
    client: Bean<LoginClientManager>,
    headers: HeaderMap,
) -> Response {
    let authorization = headers.get(header::AUTHORIZATION);
    if authorization.is_none() {
        return (StatusCode::UNAUTHORIZED, "未登录").to_response();
    }
    let bytes = authorization.unwrap().as_bytes();
    let token_header = String::from_utf8_lossy(bytes);
    let token_header = token_header.split_once(" ");
    if token_header.is_none() {
        return (StatusCode::UNAUTHORIZED, "错误的请求头").to_response();
    }
    let (_token_type, token) = token_header.unwrap();

    if let Some(client) = client.get(&login_type) {
        let userinfo = match client {
            LoginClientSource::Google(client) => {
                client.userinfo(token).await.map(|userinfo| json!(userinfo))
            }
            LoginClientSource::Github(client) => {
                client.userinfo(token).await.map(|userinfo| json!(userinfo))
            }
        };
        userinfo.to_response()
    } else {
        (StatusCode::UNAUTHORIZED, "错误的请求头").to_response()
    }
}
