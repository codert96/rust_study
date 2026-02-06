use crate::result::ToResponse;
use axum::extract::{FromRef, FromRequestParts};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::Response;
use indexmap::IndexMap;
use std::any::{Any, TypeId};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct Bean<T>(Arc<T>);
impl<T> Deref for Bean<T> {
    type Target = T;

    fn deref(&self) -> &<Self as Deref>::Target {
        self.0.deref()
    }
}

#[derive(Debug, Clone)]
pub struct BeanFactoryBuilder(Arc<RwLock<IndexMap<TypeId, Arc<dyn Any + Send + Sync>>>>);

impl Default for BeanFactoryBuilder {
    fn default() -> Self {
        Self(Arc::new(RwLock::new(IndexMap::new())))
    }
}
impl BeanFactoryBuilder {
    pub async fn get<T>(&self) -> Option<Bean<T>>
    where
        T: Send + Sync + 'static,
    {
        self.0
            .read()
            .await
            .get(&TypeId::of::<T>())
            .and_then(|data| data.clone().downcast::<T>().ok())
            .map(|data| Bean(data))
    }

    pub async fn put<T>(&self, data: impl Into<Arc<T>>) -> Option<Bean<T>>
    where
        T: Send + Sync + 'static,
    {
        self.0
            .write()
            .await
            .insert(TypeId::of::<T>(), data.into())
            .and_then(|data| data.downcast::<T>().ok())
            .map(|data| Bean(data))
    }

    pub async fn build(self) -> BeanContext {
        BeanContext(Arc::new(std::mem::take(self.0.write().await.deref_mut())))
    }
}
#[derive(Debug, Clone)]
pub struct BeanContext(Arc<IndexMap<TypeId, Arc<dyn Any + Send + Sync>>>);

impl BeanContext {
    pub fn get<T>(&self) -> Option<Bean<T>>
    where
        T: Send + Sync + 'static,
    {
        self.0
            .get(&TypeId::of::<T>())
            .and_then(|data| data.clone().downcast::<T>().ok())
            .map(|data| Bean(data))
    }
}

impl<T> FromRef<BeanContext> for Bean<T>
where
    T: Send + Sync + 'static,
{
    fn from_ref(input: &BeanContext) -> Self {
        input.get().expect("BeanContext not initialized")
    }
}
impl<T> FromRequestParts<BeanContext> for Bean<T>
where
    T: Send + Sync + 'static,
{
    type Rejection = Response;

    async fn from_request_parts(
        _: &mut Parts,
        state: &BeanContext,
    ) -> Result<Self, Self::Rejection> {
        state
            .get()
            .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "缺少必要的Bean").to_response())
    }
}
