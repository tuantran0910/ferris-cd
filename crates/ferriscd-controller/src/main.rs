//! Binary entrypoint for running the standalone FerrisCD Kubernetes controller.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    ferriscd_controller::run().await
}
