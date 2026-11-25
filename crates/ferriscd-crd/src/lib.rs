//! FerrisCD Custom Resource Definitions (`Application`, `AppProject`),
//! status subresource models, and version-agnostic GKNN inventory types.

pub mod annotations;
pub mod application;
pub mod generate;
pub mod project;
pub mod status;

pub use application::{
    Application, ApplicationSpec, AutoRenderer, AutomatedSyncPolicy, DestinationSpec,
    GitSourceSpec, HelmRenderer, IgnoreDifference, KustomizeRenderer, PlainYamlRenderer,
    RendererSpec, RetryBackoff, RetryPolicy, SourceSpec, SpecValidationError, SyncOptions,
    SyncPolicy,
};
pub use project::{
    AppProject, AppProjectSpec, AppProjectStatus, GroupKind, PermissivePolicy, ProjectDestination,
};
pub use status::{
    ActiveHook, ApplicationStatus, Condition, ConditionStatus, HealthState, HealthStatus,
    InventoryEntry, OperationPhase, OperationState, ResourceStatus, RevisionHistoryEntry,
    SourceSummary, SyncPhase, SyncState, SyncStatus,
};

/// Canonical API group of every FerrisCD custom resource.
pub const API_GROUP: &str = "ferriscd.io";

/// Control-plane namespace that owns `Application` and `AppProject` objects.
pub const CONTROL_PLANE_NAMESPACE: &str = "ferriscd-system";

/// Name of the canonical `AppProject` every `Application` references by default.
pub const DEFAULT_PROJECT_NAME: &str = "default";

/// Returns the API group name for FerrisCD custom resources.
#[must_use]
pub const fn api_group() -> &'static str {
    API_GROUP
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_group_matches_domain() {
        assert_eq!(api_group(), "ferriscd.io");
        assert_eq!(API_GROUP, "ferriscd.io");
        assert_eq!(CONTROL_PLANE_NAMESPACE, "ferriscd-system");
        assert_eq!(DEFAULT_PROJECT_NAME, "default");
    }
}
