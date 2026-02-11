use axum::response::Response;
use std::any::TypeId;
use std::env;
use std::error::Error;
use std::pin::Pin;
use tokio::signal;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::result::ToResponse;
use crate::routing::router;
use crate::state::{BeanContext, BeanFactoryBuilder};
use axum::{http, middleware};
pub use inventory;
use tokio::sync::broadcast;
use tokio::sync::broadcast::{Receiver, Sender};
use tracing::debug_span;
pub use tracing::{debug, error, info, warn};
pub use weblib_macro::*;

pub mod extract;
pub mod login;
pub mod mime;
pub mod result;
pub mod routing;
pub mod state;

pub type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {debug!("ctrl+c end this app")},
        _ = terminate => {debug!("system kill signal")},
    }
}
pub async fn serve() -> Result {
    let now = tokio::time::Instant::now();
    dotenvy::dotenv()?;
    // 1. 设置文件输出：每天滚动创建一个日志文件
    let file_appender = tracing_appender::rolling::daily(
        env::var("LOG_PATH").unwrap_or_else(|_| "./logs".to_string()),
        format!(
            "{}.log",
            env::var("LOG_NAME").unwrap_or_else(|_| "application".to_string())
        ),
    );
    let (non_blocking, _) = tracing_appender::non_blocking(file_appender);

    let console_layer = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_line_number(true)
        .pretty();

    let file_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_writer(non_blocking);
    // 2. 配置日志格式和过滤规则
    tracing_subscriber::registry()
        // 设置过滤：优先读取 RUST_LOG 环境变量，默认 info 级别
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "debug".into()))
        // 层面 1：输出到控制台（带颜色）
        .with(console_layer)
        // 层面 2：输出到文件（不带颜色，利于检索）
        .with(file_layer)
        .init();
    let bean_context = init_context().await?;

    let router = router(&bean_context)
        .await
        .route_layer(middleware::from_fn(
            async |request: axum::extract::Request, next: middleware::Next| -> Response {
                let method = request.method();
                let uri = request.uri();
                let span = debug_span!("request", %method, %uri);
                let _enter = span.enter();
                next.run(request).await
            },
        ))
        .fallback(async || ToResponse::to_response((http::StatusCode::NOT_FOUND, "NOT_FOUND")))
        .with_state(bean_context);

    let server_port = env::var("SERVER_PORT").unwrap_or_else(|_| "8080".to_string());

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", server_port))
        .await
        .inspect(|_| {
            let elapsed = now.elapsed();
            info!("webapp listening on {server_port}, elapsed {elapsed:?}, http://127.0.0.1:{server_port}/health")
        })?;
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(Into::into)
}

type InitHookInner = fn(
    BeanFactoryBuilder,
    (Sender<TypeId>, Receiver<TypeId>),
) -> Pin<Box<dyn Future<Output = Result>>>;
pub struct InitHook(pub InitHookInner);

inventory::collect!(InitHook);
async fn init_context() -> Result<BeanContext> {
    let config: BeanFactoryBuilder = Default::default();
    let (tx, _) = broadcast::channel(16);
    let tasks: Vec<_> = inventory::iter::<InitHook>
        .into_iter()
        .map(|init| {
            let rx = tx.subscribe();
            let tx = tx.clone();
            init.0(config.clone(), (tx, rx))
        })
        .collect();
    let result = futures::future::try_join_all(tasks).await;
    drop(tx);
    match result {
        Ok(_) => Ok(config.build().await),
        Err(err) => Err(err),
    }
}

#[macro_export]
macro_rules! register_bean {
    ($hook:ident, $( $ty:ty ),* $(,)?) => {
        $crate::inventory::submit! {
            $crate::InitHook(
                |builder, (tx, mut rx)| {
                    Box::pin(async move {
                        let mut __wait_for:Vec<std::any::TypeId> = vec![
                            $( std::any::TypeId::of::<$ty>(), )*
                        ];
                        while !__wait_for.is_empty() {
                            let recv =
                                tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv()).await
                                .expect(&format!("wait_for {:?} timeout", stringify!($( $ty ),*)))
                                .expect("recv timed out");
                             if let Some(index) = __wait_for.iter()
                                    .position(|p| *p == recv)
                             {__wait_for.remove(index);}
                        }
                        let result = $hook(
                            $( builder.get::<$ty>().await.unwrap() ),*
                        ).await;
                        match result {
                            Ok(result) => {
                                let type_id = std::any::Any::type_id(&result);
                                if std::any::Any::type_id(&()) != type_id {
                                    builder.put(result).await;
                                    tx.send(type_id)?;
                                }
                                Ok(())
                            },
                            Err(err) => Err(err)
                        }
                    })
                }
            )
        }
    };
}
