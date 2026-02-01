use crate::user;
use crate::user::Model;
use axum::extract::{Multipart, Path, Query, Request};
use axum::middleware::Next;
use axum::{Json, Router, middleware};
use calamine::Reader;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, NotSet, PaginatorTrait,
    QueryFilter, Set,
};
use serde::Deserialize;
use std::ops::Deref;
use weblib::extract::AsTempFile;
use weblib::state::{Bean, BeanContext};
use weblib::{debug, route, router_config};

#[router_config]
async fn init_router(_: BeanContext, router: Router<BeanContext>) -> Router<BeanContext> {
    Router::new()
        .nest("/user", router)
        .route_layer(middleware::from_fn(async |req: Request, next: Next| {
            debug!("访问了user模块的api");
            next.run(req).await
        }))
}
#[route(GET, "/{id}")]
pub async fn get(Path(id): Path<i64>, db: Bean<DatabaseConnection>) -> Option<Model> {
    debug!("根据ID查询User");
    user::Entity::find_by_id(id)
        .one(db.deref())
        .await
        .ok()
        .flatten()
}
#[derive(Debug, Deserialize)]
pub struct UserDTO {
    name: String,
}
#[route(GET, "/count")]
pub async fn count(
    db: Bean<DatabaseConnection>,
    Query(query): Query<UserDTO>,
) -> Result<u64, Box<dyn std::error::Error>> {
    user::Entity::find()
        .filter(user::Column::Name.contains(query.name))
        .count(db.deref())
        .await
        .map_err(Into::into)
}

#[route(POST, "/")]
pub async fn insert(
    db: Bean<DatabaseConnection>,
    Json(user): Json<UserDTO>,
) -> Result<(), Box<dyn std::error::Error>> {
    let new_user = user::ActiveModel {
        id: NotSet,
        name: Set(user.name),
    };
    new_user.insert(&*db).await?;
    Ok(())
}

#[route(POST, "/excel")]
pub async fn excel(mut file: Multipart) -> Result<(), Box<dyn std::error::Error>> {
    // calamine::open_workbook_from_rs()
    let mut field = file.next_field().await.ok().flatten().ok_or("缺少文件")?;
    let _file_name = field.file_name().ok_or("缺少文件名")?.to_string();
    let temp_file = field.as_temp_file().await?;

    let mut workbook = calamine::open_workbook_auto(temp_file.deref())?;
    for (name, rows) in &workbook.worksheets() {
        debug!("{}", name);
        for row in rows.rows() {
            for cell in row {
                debug!("{:?}", cell);
            }
        }
    }
    Ok(())
}
