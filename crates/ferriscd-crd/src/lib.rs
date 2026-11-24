//! FerrisCD Custom Resource Definitions (`Application`, `AppProject`),
//! status subresource models, and version-agnostic GKNN inventory types.

/// Returns the API group name for FerrisCD custom resources.
#[must_use]
pub const fn api_group() -> &'static str {
    "ferriscd.io"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_group_matches_domain() {
        assert_eq!(api_group(), "ferriscd.io");
    }
}
