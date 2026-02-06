mod config;
mod user;
mod login;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    weblib::serve().await
}
