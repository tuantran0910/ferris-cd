//! Control-plane readiness barrier (`T17.1`).
//!
//! Tracks the three startup `InitDone` gates that must complete before `GET /readyz` returns
//! `200 OK`:
//!
//! 1. **Application watches** (`ApplicationControllers::wait_until_ready()`),
//! 2. **Cluster registry seed** (`ClusterManager` initial `Secret` list / `InitDone`),
//! 3. **RBAC policy load** (initial `ferriscd-rbac-cm` load / watch `InitDone`).
//!
//! # Performance & security invariants
//!
//! - **Zero heap allocation on the steady-state `200 OK` path:** [`ControlPlaneReadiness::is_ready`]
//!   performs three `Acquire` atomic loads, and [`ControlPlaneReadiness::reason`] returns `None`
//!   without allocating whenever ready.
//! - **Secret-free by construction:** pending reasons name only the static gate identifiers
//!   (`application watches`, `cluster registry seed`, `RBAC policy`) — never user names, group
//!   names, cluster credentials, or namespace contents.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Lock-free readiness barrier shared by the controller loops, cluster registry, RBAC watcher, and
/// HTTP `/readyz` handler (`T17.1`).
///
/// Cheap to clone (`Arc` around three atomics). Starts unready across all three gates so a cold pod
/// answers `503 Service Unavailable` until every gate explicitly signals `InitDone`.
#[derive(Debug, Clone)]
pub struct ControlPlaneReadiness {
    inner: Arc<ReadinessInner>,
}

#[derive(Debug, Default)]
struct ReadinessInner {
    controllers_ready: AtomicBool,
    clusters_seeded: AtomicBool,
    rbac_loaded: AtomicBool,
}

impl Default for ControlPlaneReadiness {
    fn default() -> Self {
        Self::new()
    }
}

impl ControlPlaneReadiness {
    /// Creates a new readiness barrier with all three startup gates unready (`503`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ReadinessInner::default()),
        }
    }

    /// Signals that every `Application` watch store has completed its initial list (`InitDone`),
    /// or that an HA standby replica has entered leader-election candidacy.
    pub fn mark_controllers_ready(&self) {
        self.inner.controllers_ready.store(true, Ordering::Release);
    }

    /// Signals that the `ClusterManager` initial `Secret` seed (or watch `InitDone`) completed.
    pub fn mark_clusters_seeded(&self) {
        self.inner.clusters_seeded.store(true, Ordering::Release);
    }

    /// Signals that the initial `ferriscd-rbac-cm` load (or watch `InitDone`) completed.
    pub fn mark_rbac_loaded(&self) {
        self.inner.rbac_loaded.store(true, Ordering::Release);
    }

    /// Whether the `Application` watch gate has signalled `InitDone`.
    #[must_use]
    pub fn controllers_ready(&self) -> bool {
        self.inner.controllers_ready.load(Ordering::Acquire)
    }

    /// Whether the `ClusterManager` seed gate has signalled `InitDone`.
    #[must_use]
    pub fn clusters_seeded(&self) -> bool {
        self.inner.clusters_seeded.load(Ordering::Acquire)
    }

    /// Whether the initial RBAC policy load gate has signalled `InitDone`.
    #[must_use]
    pub fn rbac_loaded(&self) -> bool {
        self.inner.rbac_loaded.load(Ordering::Acquire)
    }

    /// Returns `true` strictly once all three startup gates have completed `InitDone`.
    ///
    /// Performs zero heap allocations and takes no locks.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.controllers_ready() && self.clusters_seeded() && self.rbac_loaded()
    }

    /// Secret-free explanation of which gates are still pending, or `None` once ready.
    ///
    /// Allocates nothing on the steady-state ready path.
    #[must_use]
    pub fn reason(&self) -> Option<String> {
        let controllers = self.controllers_ready();
        let clusters = self.clusters_seeded();
        let rbac = self.rbac_loaded();
        if controllers && clusters && rbac {
            return None;
        }
        let mut pending: [&'static str; 3] = [""; 3];
        let mut len = 0_usize;
        if !controllers {
            pending[len] = "application watches";
            len += 1;
        }
        if !clusters {
            pending[len] = "cluster registry seed";
            len += 1;
        }
        if !rbac {
            pending[len] = "RBAC policy";
            len += 1;
        }
        Some(format!(
            "waiting for initial control-plane readiness: {}",
            pending[..len].join(", ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_flips_only_after_all_three_gates_signal_init_done() {
        let readiness = ControlPlaneReadiness::new();
        assert!(!readiness.is_ready());
        let initial_reason = readiness.reason().expect("unready must explain why");
        assert!(initial_reason.contains("application watches"));
        assert!(initial_reason.contains("cluster registry seed"));
        assert!(initial_reason.contains("RBAC policy"));

        readiness.mark_clusters_seeded();
        assert!(!readiness.is_ready());
        let after_clusters = readiness.reason().expect("still missing two gates");
        assert!(!after_clusters.contains("cluster registry seed"));
        assert!(after_clusters.contains("application watches"));
        assert!(after_clusters.contains("RBAC policy"));

        readiness.mark_rbac_loaded();
        assert!(!readiness.is_ready());
        let after_rbac = readiness.reason().expect("still missing controllers");
        assert_eq!(
            after_rbac,
            "waiting for initial control-plane readiness: application watches"
        );

        // Clones share the exact same underlying atomic state.
        let handle = readiness.clone();
        handle.mark_controllers_ready();
        assert!(readiness.is_ready());
        assert_eq!(readiness.reason(), None);
    }

    #[test]
    fn readiness_stays_not_ready_if_any_single_gate_is_missing() {
        let only_controllers_and_clusters = ControlPlaneReadiness::new();
        only_controllers_and_clusters.mark_controllers_ready();
        only_controllers_and_clusters.mark_clusters_seeded();
        assert!(!only_controllers_and_clusters.is_ready());
        assert!(
            only_controllers_and_clusters
                .reason()
                .expect("missing RBAC")
                .contains("RBAC policy")
        );

        let only_controllers_and_rbac = ControlPlaneReadiness::new();
        only_controllers_and_rbac.mark_controllers_ready();
        only_controllers_and_rbac.mark_rbac_loaded();
        assert!(!only_controllers_and_rbac.is_ready());
        assert!(
            only_controllers_and_rbac
                .reason()
                .expect("missing cluster seed")
                .contains("cluster registry seed")
        );
    }
}
