use crate::mime::mime_type;
use axum::body::Body;
use axum::http;
use axum::http::StatusCode;
use axum::response::Response;
use axum::response::{IntoResponse, Json};
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;
use tokio::io::AsyncRead;

pub trait ToResponse {
    /// Create a response.
    #[must_use]
    fn to_response(self) -> Response;
}
impl<T> ToResponse for (StatusCode, T)
where
    T: Serialize,
{
    fn to_response(self) -> Response {
        let status = self.0.as_u16();
        let json = if self.0.is_success() {
            json!({
                "status": status,
                "data": self.1,
            })
        } else {
            let err = &self.1;
            json!({
                "status": status,
                "error": err,
            })
        };
        (
            StatusCode::OK,
            [(http::header::CONTENT_TYPE, "application/json")],
            Json(json),
        )
            .into_response()
    }
}
impl<T> ToResponse for (u16, T)
where
    T: Serialize,
{
    fn to_response(self) -> Response {
        (StatusCode::from_u16(self.0).expect(""), self.1).to_response()
    }
}

impl<T, E> ToResponse for Result<T, E>
where
    T: Serialize,
    E: ToString,
{
    fn to_response(self) -> Response {
        match self {
            Ok(t) => (StatusCode::OK, t).to_response(),
            Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).to_response(),
        }
    }
}
impl ToResponse for () {
    fn to_response(self) -> Response {
        Ok::<(), Box<dyn std::error::Error>>(self).to_response()
    }
}

impl<T> ToResponse for Vec<T>
where
    T: Serialize,
{
    fn to_response(self) -> Response {
        Ok::<Vec<T>, Box<dyn std::error::Error>>(self).to_response()
    }
}

impl<K, V> ToResponse for HashMap<K, V>
where
    K: Serialize,
    V: Serialize,
{
    fn to_response(self) -> Response {
        Ok::<HashMap<K, V>, Box<dyn std::error::Error>>(self).to_response()
    }
}

impl<T> ToResponse for Option<T>
where
    T: Serialize,
{
    fn to_response(self) -> Response {
        Ok::<Option<T>, Box<dyn std::error::Error>>(self).to_response()
    }
}

impl ToResponse for bool {
    fn to_response(self) -> Response {
        Ok::<bool, Box<dyn std::error::Error>>(self).to_response()
    }
}

impl ToResponse for Response {
    fn to_response(self) -> Response {
        self
    }
}

pub struct StreamingResponse<'a, R>(pub &'a str, pub u64, pub tokio_util::io::ReaderStream<R>);

impl<'a, R> IntoResponse for StreamingResponse<'a, R>
where
    R: AsyncRead + Send + Sync + 'static,
{
    fn into_response(self) -> Response {
        use percent_encoding::{NON_ALPHANUMERIC, percent_encode};
        let filename = self.0;
        let content_type = mime_type(filename);
        let body = Body::from_stream(self.2);

        Response::builder()
            .header(http::header::CONTENT_TYPE, content_type)
            .header(http::header::CONTENT_LENGTH, self.1)
            .header(http::header::CACHE_CONTROL, "no-cache")
            .header(http::header::PRAGMA, "no-cache")
            .header(
                http::header::CONTENT_DISPOSITION,
                format!(
                    "attachment; filename=\"{}\"",
                    percent_encode(filename.as_bytes(), NON_ALPHANUMERIC)
                ),
            )
            .body(body)
            .unwrap()
            .into_response()
    }
}

impl<'a, R> ToResponse for StreamingResponse<'a, R>
where
    R: AsyncRead + Send + Sync + 'static,
{
    fn to_response(self) -> Response {
        self.into_response()
    }
}

impl ToResponse for String {
    fn to_response(self) -> Response {
        Ok::<String, Box<dyn std::error::Error>>(self).to_response()
    }
}
impl ToResponse for &str {
    fn to_response(self) -> Response {
        Ok::<&str, Box<dyn std::error::Error>>(self).to_response()
    }
}
