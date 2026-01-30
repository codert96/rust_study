# web 初始化的时候就会执行的钩子函数

## Example


```rust

use redis::Client;
use sea_orm::{Database, DatabaseConnection};
use std::env;
use weblib::bean;

#[bean]
async fn orm_init() -> Result<DatabaseConnection, Box<dyn std::error::Error>> {
    let url = env::var("DATABASE_URL")?;
    Database::connect(url).await.map_err(Into::into)
}

#[bean]
async fn init_redis() -> Result<Client, Box<dyn std::error::Error>> {
    let url = env::var("REDIS_URL")?;
    Client::open(url).map_err(Into::into)
}

#[bean(wait_for = DatabaseConnection, Client)]
async fn init(
    db: Bean<DatabaseConnection>,
    redis: Bean<Client>,
) -> Result<(), Box<dyn std::error::Error>> {
    debug!("得到db和redis");
    debug!("Database connection initialized -> {:?}", db);
    debug!("Redis connection initialized -> {:?}", redis);
    Ok(())
}

```