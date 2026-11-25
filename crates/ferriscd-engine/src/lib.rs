//! FerrisCD core GitOps engine: repository acquisition, manifest rendering,
//! GKNN inventory tracking, SSA diffing, sync wave planning, and health evaluation.

pub mod diff;
pub mod graph;
pub mod health;
pub mod inventory;
pub mod manifest;
pub mod repo;
pub mod sync;

/// Returns the default Server-Side Apply field manager identity for FerrisCD.
#[must_use]
pub fn default_field_manager() -> &'static str {
    "ferriscd"
}

/// Returns the FerrisCD API group re-exported from [`ferriscd_crd`].
#[must_use]
pub const fn crd_api_group() -> &'static str {
    ferriscd_crd::api_group()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_manager_and_crd_group_are_consistent() {
        assert_eq!(default_field_manager(), "ferriscd");
        assert_eq!(crd_api_group(), "ferriscd.io");
    }
}
