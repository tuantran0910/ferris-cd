//! Tenancy policy: `AppProject` allow-list enforcement and the Apps-in-any-namespace scope.
//!
//! Phase 12 replaces the `PermissivePolicy` stub of Phases 05–11 with two cooperating pieces that
//! stay **pure and offline** (the controller does the fetching, so everything here is a unit test):
//!
//! * [`AppProjectPolicy`] — the `AppProject` allow-lists, checked once *before* rendering and again
//!   on **every** rendered resource after Stage-2 scope normalization (`T12.1`).
//! * [`ApplicationScope`] — which namespaces may host `Application` objects at all, plus the tenant
//!   guard that refuses to reconcile a tenant `Application` without its own `serviceAccountName`
//!   (`T12.2`, ADR-007).
//!
//! Both fail closed: a missing project, an unlisted repository, a manifest that hardcodes
//! `metadata.namespace: kube-system`, or an unlisted cluster-scoped kind is a **terminal**
//! [`PolicyError`], never a silent allow.

pub mod app_project;
pub mod namespace_scope;
// `T17.4`: deployment-governance windows — a pure evaluation of `AppProject.spec.syncWindows`
// against an **injected** `jiff::Timestamp` (never a wall-clock read inside the engine).
pub mod sync_windows;

pub use app_project::{AppProjectPolicy, PolicyError, wildcard_matches};
pub use namespace_scope::{
    ALL_NAMESPACES, ApplicationNamespaces, ApplicationScope, ApplicationScopeError,
};
pub use sync_windows::{
    InvalidSyncWindow, SyncWindowDenial, SyncWindowDenialReason, SyncWindowSet, SyncWindowStatus,
    SyncWindowTarget, SyncWindowVerdict,
};
