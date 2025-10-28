// examples/simple_node.rs (Standalone App Using TheNodes)

use thenodes::{config::Config, TheNodes};

#[tokio::main]
async fn main() {
    let config = Config::default();
    let node = TheNodes::new(config);

    println!("Starting TheNodes...");
    node.start().await;
}
