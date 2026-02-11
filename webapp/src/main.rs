mod config;
mod login;
mod user;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    weblib::serve().await
}
