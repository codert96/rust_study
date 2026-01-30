use redis::Client;
use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use std::env;
use weblib::bean;

#[bean]
async fn init_redis() -> Result<ConnectionManager, Box<dyn std::error::Error>> {
    // debug!("测试等待2秒再开始初始化redis连接");
    // sleep(Duration::from_secs(2)).await;
    let connection_manager_config = ConnectionManagerConfig::default();
    let url = env::var("REDIS_URL")?;
    ConnectionManager::new_with_config(Client::open(url)?, connection_manager_config)
        .await
        .map_err(Into::into)
}
