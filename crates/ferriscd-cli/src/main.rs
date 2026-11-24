//! `ferriscd` CLI binary entrypoint.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing::info!(
        api_group = ferriscd_crd::api_group(),
        field_manager = ferriscd_engine::default_field_manager(),
        controller = ferriscd_controller::controller_name(),
        "ferriscd cli scaffold initialized"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn crate_boundaries_wire_cleanly() {
        assert_eq!(ferriscd_crd::api_group(), "ferriscd.io");
        assert_eq!(ferriscd_engine::default_field_manager(), "ferriscd");
        assert_eq!(ferriscd_controller::controller_name(), "ferriscd");
    }
}
