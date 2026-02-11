use axum::Json;
use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;
use std::error::Error;

pub trait ToResponse<T = Body> {
    /// Create a response.
    #[must_use]
    fn to_response(self) -> Response<T>;
}

impl ToResponse for (StatusCode, &str) {
    fn to_response(self) -> Response {
        let json = if self.0.is_success() {
            json!({
                "status": self.0.as_u16(),
                "data": self.1
            })
        } else {
            json!({
                "status": self.0.as_u16(),
                "error": self.1
            })
        };
        (
            self.0,
            [(CONTENT_TYPE, "application/json;charset=utf-8")],
            Json(json),
        )
            .into_response()
    }
}

impl ToResponse for (StatusCode, String) {
    fn to_response(self) -> Response {
        (self.0, self.1.as_ref()).to_response()
    }
}

impl<T: Serialize, E: ToString> ToResponse for Result<T, E> {
    fn to_response(self) -> Response {
        let json = match self {
            Ok(data) => {
                json!({
                    "status": 200,
                    "data": data
                })
            }
            Err(err) => {
                json!({
                    "status": 400,
                    "error": err.to_string()
                })
            }
        };
        (
            StatusCode::OK,
            [(CONTENT_TYPE, "application/json;charset=utf-8")],
            Json(json),
        )
            .into_response()
    }
}

impl<T: Serialize> ToResponse for Option<T> {
    fn to_response(self) -> Response {
        Ok::<Option<T>, Box<dyn Error>>(self).to_response()
    }
}

impl ToResponse for String {
    fn to_response(self) -> Response {
        Ok::<String, Box<dyn Error>>(self).to_response()
    }
}
impl ToResponse for &str {
    fn to_response(self) -> Response {
        Ok::<&str, Box<dyn Error>>(self).to_response()
    }
}

impl<T> ToResponse<T> for Response<T> {
    fn to_response(self) -> Response<T> {
        self
    }
}

impl<T: Serialize> ToResponse for Vec<T> {
    fn to_response(self) -> Response {
        Ok::<Vec<T>, Box<dyn Error>>(self).to_response()
    }
}

impl<K: Serialize, V: Serialize> ToResponse for HashMap<K, V> {
    fn to_response(self) -> Response {
        Ok::<HashMap<K, V>, Box<dyn Error>>(self).to_response()
    }
}

impl ToResponse for () {
    fn to_response(self) -> Response {
        StatusCode::NO_CONTENT.into_response()
    }
}

impl ToResponse for (StatusCode, [(HeaderName, HeaderValue); 1]) {
    fn to_response(self) -> Response<Body> {
        self.into_response()
    }
}

impl ToResponse for Redirect {
    fn to_response(self) -> Response<Body> {
        self.into_response()
    }
}
