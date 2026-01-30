use redis::aio::ConnectionManager;
use sea_orm::{Database, DatabaseConnection};
use std::env;
use weblib::state::Bean;
use weblib::{bean, debug};

#[bean]
async fn orm_init() -> Result<DatabaseConnection, Box<dyn std::error::Error>> {
    debug!("开始初始化DatabaseConnection 连接");
    let url = env::var("DATABASE_URL")?;
    Database::connect(url).await.map_err(Into::into)
}

#[bean(wait_for = DatabaseConnection, ConnectionManager)]
async fn init(
    db: Bean<DatabaseConnection>,
    redis: Bean<ConnectionManager>,
) -> Result<(), Box<dyn std::error::Error>> {
    debug!("得到db和redis");
    debug!("Database connection initialized -> {:?}", db);
    debug!("Redis connection initialized -> {:?}", redis);

    Ok(())
}
