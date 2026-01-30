use crate::state::BeanContext;
use axum::Router;
use axum::routing::get;
pub use inventory;
use std::collections::HashMap;
use std::ops::Deref;
use std::pin::Pin;
use std::sync::Arc;

pub struct Hook<T>(pub fn() -> Pin<Box<dyn Future<Output = T>>>);

impl<T> Deref for Hook<T> {
    type Target = fn() -> Pin<Box<dyn Future<Output = T>>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

type RouterConfigHookInner = Box<
    dyn Fn(BeanContext, Router<BeanContext>) -> Pin<Box<dyn Future<Output = Router<BeanContext>>>>,
>;
pub struct RouterConfig {
    module_path: Arc<str>,
    hook: RouterConfigHookInner,
}

impl RouterConfig {
    pub fn new(module_path: &str, hook: RouterConfigHookInner) -> Self {
        RouterConfig {
            module_path: module_path.into(),
            hook,
        }
    }
}

inventory::collect!(Hook<RouterConfig>);

#[macro_export]
macro_rules! register_router_config {
    ($hook:expr) => {
        $crate::routing::inventory::submit! {
             $crate::routing::Hook(||
                 Box::pin(async {
                        $crate::routing::RouterConfig::new(
                            module_path!(),
                            Box::new(
                                |app_state, mod_routes| Box::pin(($hook)(app_state, mod_routes))
                            ),
                        )
                    }
                 )
            )
        }
    };
}
pub struct RouteHook {
    module_path: Arc<str>,
    hook: Box<dyn Fn(Router<BeanContext>) -> Router<BeanContext>>,
}

impl RouteHook {
    pub fn new(
        module_path: &str,
        hook: Box<dyn Fn(Router<BeanContext>) -> Router<BeanContext>>,
    ) -> Self {
        Self {
            module_path: module_path.into(),
            hook,
        }
    }
}
inventory::collect!(Hook<RouteHook>);

#[macro_export]
macro_rules! register_route {
    ($method:ident, $path:expr, $fn_name:expr) => {
        $crate::routing::inventory::submit! {
            $crate::routing::Hook(|| {
                Box::pin(async {
                    $crate::routing::RouteHook::new(
                        module_path!(),
                        Box::new(|router| {
                            router.route(
                                $path,
                                axum::routing::on(
                                    axum::routing::MethodFilter::$method,
                                    $fn_name,
                                ),
                            )
                        }),
                    )
                })
            })
        }
    };
}

pub async fn router(bean_context: &BeanContext) -> Router<BeanContext> {
    let mut config: HashMap<Arc<str>, RouterConfig> = HashMap::new();
    for hook in inventory::iter::<Hook<RouterConfig>> {
        let hook = hook().await;
        config.entry(Arc::clone(&hook.module_path)).or_insert(hook);
    }

    let mut router: HashMap<Arc<str>, Vec<RouteHook>> = HashMap::new();

    for hook in inventory::iter::<Hook<RouteHook>> {
        let hook = hook().await;
        router
            .entry(Arc::clone(&hook.module_path))
            .or_default()
            .insert(0, hook);
    }

    let mut result = Router::new().route(
        "/health",
        get(async || crate::result::ToResponse::to_response((axum::http::StatusCode::OK, "OK"))),
    );
    for (module, hooks) in &router {
        match config.get(module) {
            Some(config) => {
                let mut router = Router::new();
                for route_hook in hooks {
                    router = (route_hook.hook)(router);
                }
                result = result.merge((config.hook)(bean_context.clone(), router).await);
            }
            None => {
                for route_hook in hooks {
                    result = (route_hook.hook)(result);
                }
            }
        }
    }
    result
}
