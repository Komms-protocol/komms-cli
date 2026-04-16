#[tokio::main]
async fn main() -> anyhow::Result<()> {
    komms_cli::run().await
}
