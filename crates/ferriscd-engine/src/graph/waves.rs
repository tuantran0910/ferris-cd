//! Sync-wave partitioning (`T10.2`): group the permanent desired set into ordered waves.
//!
//! `ferriscd.io/sync-wave` lets an application author order a bundle without touching file names
//! or Git history: a database migration runs in wave `-1`, the `Deployment` that needs it in wave
//! `0`, the smoke test in wave `1`. Within a single wave the [`crate::graph`] tier ordering still
//! applies, so a wave can never apply a `Deployment` before the `ConfigMap` it mounts.
//!
//! ```text
//! migration.yaml  ferriscd.io/sync-wave: "-1"   Job/migrate        -> wave -1
//! config.yaml     (no annotation)               ConfigMap/settings -> wave  0
//! deployment.yaml (no annotation)               Deployment/api     -> wave  0
//! smoke.yaml      ferriscd.io/sync-wave: "1"    Job/smoke          -> wave  1
//! ```
//!
//! # Why the parse is strict
//!
//! A wave number is ordering metadata that the cluster never validates: `sync-wave: "-1x"` would
//! silently become wave `0` if it were parsed leniently, which moves a migration **behind** the
//! workload it prepares. Every unparseable value is therefore a typed, terminal
//! [`ManifestError::InvalidAnnotation`] naming the file, the resource, and the offending value.
//!
//! # Composition with hooks
//!
//! Lifecycle hooks are partitioned out first ([`crate::graph::hooks`]) because a hook is never
//! applied as part of a wave and must never enter `status.inventory`:
//!
//! ```text
//! manifest::load -> hooks::partition -> HookPartition::wave_plan -> WavePlan
//!                                 \-> HookPartition::hooks        (per phase, sorted by wave)
//! ```
//!
//! Everything here is pure: no I/O, no clock, no client. The result is fully ordered, so two
//! reconciles of the same commit always produce the same apply order.

use ferriscd_crd::annotations;

use crate::graph::{annotation, sort_by_tier};
use crate::manifest::{DesiredResource, ManifestError, ResourceKey};

/// Wave a resource belongs to when it carries no `ferriscd.io/sync-wave` annotation.
pub const DEFAULT_SYNC_WAVE: i32 = 0;

/// One wave of a sync plan: resources that may be applied together, in apply order.
#[derive(Clone, Debug)]
pub struct SyncWave {
    /// The wave number (negative, zero, or positive; ascending execution order).
    pub wave: i32,
    /// Resources of this wave, sorted by [`crate::graph::tier`] then [`ResourceKey`].
    pub resources: Vec<DesiredResource>,
}

impl SyncWave {
    /// Builds a wave from an already ordered resource slice.
    #[must_use]
    pub fn new(wave: i32, resources: Vec<DesiredResource>) -> Self {
        Self { wave, resources }
    }

    /// Returns the identity of every resource in this wave, in apply order.
    #[must_use]
    pub fn keys(&self) -> Vec<ResourceKey> {
        self.resources
            .iter()
            .map(|resource| resource.key.clone())
            .collect()
    }

    /// Returns whether the wave carries no resources.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.resources.is_empty()
    }
}

/// The permanent desired set partitioned into waves, ascending.
///
/// Construction goes through [`partition`], which is the only thing that establishes the ordering
/// invariant: `waves[i].wave < waves[i + 1].wave`, and every wave is internally ordered by
/// [`crate::graph::tier`] then [`ResourceKey`]. Callers therefore never re-sort a `WavePlan`.
#[derive(Clone, Debug, Default)]
pub struct WavePlan {
    waves: Vec<SyncWave>,
}

impl WavePlan {
    /// The waves in execution order (ascending wave number, never empty waves).
    #[must_use]
    pub fn waves(&self) -> &[SyncWave] {
        &self.waves
    }

    /// Returns whether the plan has no resources at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.waves.is_empty()
    }

    /// The wave numbers in execution order (`-1, 0, 1, …`).
    #[must_use]
    pub fn wave_numbers(&self) -> Vec<i32> {
        self.waves.iter().map(|wave| wave.wave).collect()
    }

    /// Number of resources across every wave.
    #[must_use]
    pub fn resource_count(&self) -> usize {
        self.waves.iter().map(|wave| wave.resources.len()).sum()
    }

    /// Returns the wave with the given number, if the plan contains it.
    #[must_use]
    pub fn wave(&self, wave: i32) -> Option<&SyncWave> {
        self.waves.iter().find(|entry| entry.wave == wave)
    }

    /// Returns the identities of the resources of `wave` (empty when the wave does not exist).
    ///
    /// A wave that is not part of the plan is a normal, non-error situation: the desired set of a
    /// running operation can change between requeues, and the state machine skips forward over a
    /// wave that disappeared instead of failing the operation.
    #[must_use]
    pub fn keys_in(&self, wave: i32) -> Vec<ResourceKey> {
        self.wave(wave).map(SyncWave::keys).unwrap_or_default()
    }

    /// Every resource in execution order (`wave` ascending, tier/key order inside a wave).
    pub fn resources(&self) -> impl Iterator<Item = &DesiredResource> {
        self.waves.iter().flat_map(|wave| wave.resources.iter())
    }

    /// Every resource identity in execution order.
    #[must_use]
    pub fn keys(&self) -> Vec<ResourceKey> {
        self.resources()
            .map(|resource| resource.key.clone())
            .collect()
    }
}

/// Reads `ferriscd.io/sync-wave` as a signed 32-bit integer (default [`DEFAULT_SYNC_WAVE`]).
///
/// # Errors
///
/// Returns [`ManifestError::InvalidAnnotation`] when the annotation is present but blank, or not a
/// signed `i32` (including values that only overflow `i32`, such as `2147483648`).
pub fn sync_wave(resource: &DesiredResource) -> Result<i32, ManifestError> {
    let Some(raw) = annotation(resource, annotations::SYNC_WAVE) else {
        return Ok(DEFAULT_SYNC_WAVE);
    };

    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(invalid(
            resource,
            format!(
                "{} is blank; omit the annotation or set a signed 32-bit integer (for example \"-1\")",
                annotations::SYNC_WAVE
            ),
        ));
    }

    trimmed.parse::<i32>().map_err(|_| {
        invalid(
            resource,
            format!(
                "{} must be a signed 32-bit integer, got {raw:?}",
                annotations::SYNC_WAVE
            ),
        )
    })
}

/// Orders `resources` by `(wave, tier, key)` without grouping them.
///
/// This is the single ordering rule shared by waves and lifecycle hooks: wave first (so a
/// `PreSync` migration in wave `-1` precedes the wave `0` hooks), then the [`crate::graph::tier`]
/// dependency tiers, then the deterministic [`ResourceKey`] tie-break.
///
/// # Errors
///
/// Propagates [`ManifestError::InvalidAnnotation`] from [`sync_wave`].
pub fn sort_by_wave(
    resources: Vec<DesiredResource>,
) -> Result<Vec<DesiredResource>, ManifestError> {
    Ok(group_by_wave(resources)?
        .into_iter()
        .flat_map(|wave| wave.resources)
        .collect())
}

/// Groups the **permanent** (non-hook) desired set into waves, ascending.
///
/// Resources are appended in `(wave, tier, key)` order inside each wave. Callers that own the full
/// rendered bundle must partition hooks out first (`graph::hooks`): a hook is created imperatively
/// and must never be applied as a wave member.
///
/// # Errors
///
/// Returns [`ManifestError::InvalidAnnotation`] for the first resource whose
/// `ferriscd.io/sync-wave` value is not a signed `i32`.
pub fn partition(resources: Vec<DesiredResource>) -> Result<WavePlan, ManifestError> {
    Ok(WavePlan {
        waves: group_by_wave(resources)?,
    })
}

/// Parses every wave number once, then groups and orders by `(wave, tier, key)`.
fn group_by_wave(resources: Vec<DesiredResource>) -> Result<Vec<SyncWave>, ManifestError> {
    let mut keyed: Vec<(i32, DesiredResource)> = Vec::with_capacity(resources.len());
    for resource in resources {
        let wave = sync_wave(&resource)?;
        keyed.push((wave, resource));
    }
    // Stable sort by wave only: the tier/key order inside a wave is established by
    // `sort_by_tier` below, so the result never depends on the input order.
    keyed.sort_by_key(|entry| entry.0);

    let mut waves: Vec<SyncWave> = Vec::new();
    for (wave, resource) in keyed {
        match waves.last_mut() {
            Some(current) if current.wave == wave => current.resources.push(resource),
            _ => waves.push(SyncWave::new(wave, vec![resource])),
        }
    }
    for wave in &mut waves {
        let resources = std::mem::take(&mut wave.resources);
        wave.resources = sort_by_tier(resources);
    }
    Ok(waves)
}

/// Builds the terminal, actionable error for a malformed control annotation.
fn invalid(resource: &DesiredResource, message: String) -> ManifestError {
    ManifestError::InvalidAnnotation {
        file: resource.source_file.clone(),
        message: format!("{}: {message}", resource.key.canonical()),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::manifest::types::GroupVersionKind;

    /// Builds a `DesiredResource` fixture, optionally carrying `ferriscd.io/sync-wave`.
    fn resource(kind: &str, name: &str, wave: Option<&str>) -> DesiredResource {
        let (group, version) = match kind {
            "CustomResourceDefinition" => ("apiextensions.k8s.io", "v1"),
            "Deployment" | "StatefulSet" => ("apps", "v1"),
            "Widget" => ("example.com", "v1"),
            _ => ("", "v1"),
        };
        let api_version = if group.is_empty() {
            version.to_owned()
        } else {
            format!("{group}/{version}")
        };
        let namespace = match kind {
            "Namespace" | "CustomResourceDefinition" => None,
            _ => Some("payments".to_owned()),
        };

        let mut metadata = json!({ "name": name, "namespace": namespace });
        if let Some(wave) = wave {
            metadata["annotations"] = json!({ ferriscd_crd::annotations::SYNC_WAVE: wave });
        }

        DesiredResource {
            key: ResourceKey::new(group, kind, namespace, name),
            gvk: GroupVersionKind::parse(&api_version, kind).expect("valid apiVersion"),
            object: serde_json::from_value(json!({
                "apiVersion": api_version,
                "kind": kind,
                "metadata": metadata,
            }))
            .expect("valid DynamicObject"),
            source_file: format!("{}-{name}.yaml", kind.to_lowercase()),
        }
    }

    fn waves_of(plan: &WavePlan) -> Vec<(i32, Vec<String>)> {
        plan.waves()
            .iter()
            .map(|wave| {
                (
                    wave.wave,
                    wave.keys().iter().map(ResourceKey::canonical).collect(),
                )
            })
            .collect()
    }

    #[test]
    fn resources_without_the_annotation_default_to_wave_zero() {
        let plan = partition(vec![
            resource("ConfigMap", "settings", None),
            resource("Deployment", "api", None),
        ])
        .expect("valid waves");

        assert_eq!(plan.wave_numbers(), vec![0]);
        assert_eq!(
            waves_of(&plan),
            vec![(
                0,
                vec![
                    "/ConfigMap/payments/settings".to_owned(),
                    "apps/Deployment/payments/api".to_owned(),
                ]
            )]
        );
        let untouched = resource("ConfigMap", "settings", None);
        assert!(
            untouched.object.metadata.annotations.is_none(),
            "the fixture must really carry no annotation"
        );
        assert_eq!(
            sync_wave(&untouched).expect("default wave"),
            DEFAULT_SYNC_WAVE
        );
    }

    #[test]
    fn negative_waves_sort_before_zero_and_positive_waves_after() {
        let plan = partition(vec![
            resource("Deployment", "api", Some("0")),
            resource("Job", "smoke", Some("1")),
            resource("Job", "migrate", Some("-1")),
            resource("ConfigMap", "settings", Some("-1")),
        ])
        .expect("valid waves");

        assert_eq!(plan.wave_numbers(), vec![-1, 0, 1]);
        assert_eq!(
            waves_of(&plan),
            vec![
                (
                    -1,
                    vec![
                        "/ConfigMap/payments/settings".to_owned(),
                        "/Job/payments/migrate".to_owned(),
                    ]
                ),
                (0, vec!["apps/Deployment/payments/api".to_owned()]),
                (1, vec!["/Job/payments/smoke".to_owned()]),
            ]
        );
        assert_eq!(plan.resource_count(), 4);
        assert_eq!(plan.keys_in(-1).len(), 2);
        assert!(plan.keys_in(7).is_empty(), "a missing wave is not an error");
        assert!(plan.wave(7).is_none());
    }

    #[test]
    fn tier_ordering_still_applies_inside_a_wave() {
        // Deliberately reversed: a wave must never apply a Deployment before its ConfigMap, and a
        // new CRD must precede the custom resource that needs it (T08.1's trap guard, inside a wave).
        let plan = partition(vec![
            resource("Widget", "one", Some("-2")),
            resource("Deployment", "api", Some("-2")),
            resource("ConfigMap", "settings", Some("-2")),
            resource("CustomResourceDefinition", "widgets", Some("-2")),
            resource("Namespace", "payments", Some("-2")),
        ])
        .expect("valid waves");

        let kinds: Vec<&str> = plan.waves()[0]
            .resources
            .iter()
            .map(|resource| resource.gvk.kind.as_str())
            .collect();
        assert_eq!(
            kinds,
            vec![
                "Namespace",
                "CustomResourceDefinition",
                "ConfigMap",
                "Deployment",
                "Widget",
            ]
        );
        assert_eq!(
            sort_by_wave(plan.waves()[0].resources.clone())
                .expect("valid waves")
                .iter()
                .map(|resource| resource.gvk.kind.as_str())
                .collect::<Vec<_>>(),
            kinds,
            "sort_by_wave must agree with the in-wave ordering"
        );
    }

    #[test]
    fn wave_parsing_accepts_the_full_signed_i32_range() {
        for value in [i32::MIN, -100, -1, 0, 1, 100, i32::MAX] {
            let parsed = resource("Job", "migrate", Some(&value.to_string()));
            assert_eq!(sync_wave(&parsed).expect("valid wave"), value);
            // Surrounding whitespace is tolerated (YAML quoting is easy to get wrong).
            let padded = resource("Job", "migrate", Some(&format!("  {value}\t")));
            assert_eq!(sync_wave(&padded).expect("valid wave"), value);
        }
    }

    #[test]
    fn invalid_wave_values_are_terminal_manifest_errors() {
        for value in [
            "abc",
            "",
            "   ",
            "1.5",
            "1x",
            "0x10",
            "+-1",
            "2147483648",
            "-2147483649",
            "1_000",
            "wave-1",
        ] {
            let bad = resource("Job", "migrate", Some(value));
            let err = sync_wave(&bad).expect_err("invalid wave must be rejected");
            assert!(
                matches!(err, ManifestError::InvalidAnnotation { .. }),
                "unexpected error variant for {value:?}: {err:?}"
            );
            assert!(!err.is_retryable(), "a malformed annotation is terminal");

            let text = err.to_string();
            assert!(
                text.contains("job-migrate.yaml"),
                "the error must name the source file: {text}"
            );
            assert!(
                text.contains("ferriscd.io/sync-wave"),
                "the error must name the annotation: {text}"
            );
            assert!(
                text.contains("/Job/payments/migrate"),
                "the error must name the resource: {text}"
            );

            // partition() surfaces the same error instead of silently defaulting to wave 0.
            let err = partition(vec![
                resource("ConfigMap", "settings", Some("0")),
                resource("Job", "migrate", Some(value)),
            ])
            .expect_err("partition must reject an invalid wave");
            assert!(!err.is_retryable());
        }
    }

    #[test]
    fn partition_is_deterministic_for_every_input_permutation() {
        let inputs = vec![
            resource("Namespace", "payments", None),
            resource("ConfigMap", "settings", Some("-1")),
            resource("Job", "migrate", Some("-1")),
            resource("Deployment", "api", Some("0")),
            resource("Service", "api", Some("0")),
            resource("Job", "smoke", Some("2")),
        ];
        let expected = waves_of(&partition(inputs.clone()).expect("valid waves"));

        // Every rotation of the input must produce byte-identical ordering.
        for offset in 0..inputs.len() {
            let mut rotated = inputs.clone();
            rotated.rotate_left(offset);
            assert_eq!(
                waves_of(&partition(rotated).expect("valid waves")),
                expected,
                "rotation {offset} must not change the plan"
            );
        }

        let mut reversed = inputs;
        reversed.reverse();
        assert_eq!(
            waves_of(&partition(reversed).expect("valid waves")),
            expected
        );
    }

    #[test]
    fn an_empty_desired_set_produces_an_empty_plan() {
        let plan = partition(Vec::new()).expect("valid waves");
        assert!(plan.is_empty());
        assert!(plan.waves().is_empty());
        assert_eq!(plan.resource_count(), 0);
        assert_eq!(plan.wave_numbers(), Vec::<i32>::new());
        assert_eq!(plan.keys(), Vec::<ResourceKey>::new());
        assert!(sort_by_wave(Vec::new()).expect("valid waves").is_empty());
    }

    #[test]
    fn an_explicitly_set_blank_wave_is_an_error_not_a_default() {
        // `sync-wave: ""` is almost always a typo (a templated value that rendered empty), so it
        // must fail loudly rather than land in wave 0 with the rest of the bundle.
        let blank = resource("Job", "migrate", Some(""));
        let err = sync_wave(&blank).expect_err("blank wave must be rejected");
        assert!(err.to_string().contains("is blank"), "{err}");
        assert!(err.to_string().contains("omit the annotation"), "{err}");
    }
}
