//! FerrisCD Kubernetes controller runtime: reconciliation loop, watch predicates,
//! dynamic discovery cache, finalizer lifecycle, and Lease-based leader election.

/// Returns the controller identifier string.
#[must_use]
pub fn controller_name() -> &'static str {
    ferriscd_engine::default_field_manager()
}

/// Runs the controller loop entrypoint (placeholder for Phase 05).
///
/// # Errors
///
/// Returns an error if controller initialization fails.
pub async fn run() -> anyhow::Result<()> {
    tracing::info!(
        controller = controller_name(),
        api_group = ferriscd_crd::api_group(),
        "ferriscd-controller initialized"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controller_name_matches_field_manager() {
        assert_eq!(controller_name(), "ferriscd");
    }
}
