//! `v1.0` → `v2.0` CRD backward-compatibility checker (`T20.4`).
//!
//! An in-place upgrade must never break an object that a `v1.0` control plane already accepted. The
//! only way to know that is to keep the `v1.0` contract around and diff the current one against it,
//! so this test owns a frozen copy of the `v1.0` CRD manifests and a set of `v1.0`-shaped custom
//! resources (`tests/fixtures/v1_0/`, provenance in its `README.md`).
//!
//! # What it proves
//!
//! 1. **No removed fields.** Every property path in the `v1.0` schema still exists, with the same
//!    `type`/`format` and the same nullability. (Relaxing `nullable: false` → `true` is allowed;
//!    the reverse would make stored values invalid.)
//! 2. **No narrowed enums.** Every value a `v1.0` enum allowed is still allowed.
//! 3. **No newly required properties.** At every object node the current `required` set is a
//!    **subset** of the `v1.0` one, so an object stored under `v1.0` still passes admission.
//! 4. **`v1.0` objects still deserialize, validate and round-trip.** Every key of every fixture
//!    survives the trip through the current Rust types unchanged — nothing dropped, nothing
//!    renamed, and no new key invented (`sources`, `oci`, `syncWindows`, `policyRules`, …).
//! 5. **The baseline is real.** The suite fails if the frozen `v1.0` manifests are ever replaced by
//!    the current ones (which would make every assertion above vacuously true), by pinning the
//!    handful of relaxations this major version is *supposed* to have made.
//!
//! It deliberately does **not** compare `x-kubernetes-validations`: new CEL rules are the mechanism
//! of additive evolution (they must accept every stored object, which point 3 and the fixture
//! assertions cover), and the rules themselves are pinned by `ferriscd-crd`'s generation tests.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use ferriscd_crd::{AppProject, Application};
use serde_json::Value;

/// The `v1.0` CRDs this suite freezes, as `(CRD name, fixture file name)`.
///
/// `ApplicationSet` is absent on purpose: it did not exist in `v1.0`, so it cannot break an upgrade.
const V1_0_CRDS: [(&str, &str); 2] = [
    ("applications.ferriscd.io", "applications.ferriscd.io.yaml"),
    ("appprojects.ferriscd.io", "appprojects.ferriscd.io.yaml"),
];

// ---------------------------------------------------------------------------
// schema surface
// ---------------------------------------------------------------------------

/// The comparable shape of one schema node.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NodeShape {
    /// `type` (`object`, `string`, `integer`, …), when declared.
    type_name: Option<String>,
    /// `format` (`int32`, `uint32`, `date`, …), when declared.
    format: Option<String>,
    /// `enum` values, rendered as JSON scalars, when declared.
    enum_values: Option<BTreeSet<String>>,
    /// Whether the node accepts `null`.
    nullable: bool,
}

/// The flattened, path-keyed surface of one CRD's `openAPIV3Schema`.
#[derive(Debug, Default)]
struct Surface {
    /// Property path → shape (`spec.source.git.repoURL`, `spec.ignoreDifferences[].kind`, …).
    fields: BTreeMap<String, NodeShape>,
    /// Object path → the property names that node requires.
    required: BTreeMap<String, BTreeSet<String>>,
    /// Every visited node path (so an object node that *gains* a requirement is visible).
    nodes: BTreeSet<String>,
}

impl Surface {
    fn of(schema: &Value) -> Self {
        let mut surface = Self::default();
        surface.walk(schema, "");
        surface
    }

    fn walk(&mut self, node: &Value, path: &str) {
        let Some(map) = node.as_object() else {
            return;
        };
        // Children of an array or map are keyed with a shape marker so two structurally different
        // positions can never compare equal.
        if let Some(items) = map.get("items") {
            self.walk(items, &format!("{path}[]"));
        }
        if let Some(additional) = map.get("additionalProperties")
            && additional.is_object()
        {
            self.walk(additional, &format!("{path}{{}}"));
        }
        // `oneOf` arms are keyed by index: a reordering is a schema edit and should be reviewed.
        if let Some(arms) = map.get("oneOf").and_then(Value::as_array) {
            for (index, arm) in arms.iter().enumerate() {
                self.walk(arm, &format!("{path}|oneOf[{index}]"));
            }
        }
        let Some(properties) = map.get("properties").and_then(Value::as_object) else {
            self.nodes.insert(path.to_owned());
            return;
        };
        let required = map
            .get("required")
            .and_then(Value::as_array)
            .map(|names| {
                names
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        self.required.insert(path.to_owned(), required);
        self.nodes.insert(path.to_owned());
        for (name, child) in properties {
            let child_path = if path.is_empty() {
                name.clone()
            } else {
                format!("{path}.{name}")
            };
            let enum_values = child.get("enum").and_then(Value::as_array).map(|values| {
                values
                    .iter()
                    .map(|value| value.to_string())
                    .collect::<BTreeSet<_>>()
            });
            self.fields.insert(
                child_path.clone(),
                NodeShape {
                    type_name: child.get("type").and_then(Value::as_str).map(str::to_owned),
                    format: child
                        .get("format")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    enum_values,
                    nullable: child
                        .get("nullable")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                },
            );
            self.walk(child, &child_path);
        }
    }
}

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v1_0")
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the workspace root resolves")
}

/// The frozen `v1.0` CRD manifest.
fn v1_0_crd(file_name: &str) -> Value {
    let path = fixtures_root().join("crds").join(file_name);
    let document = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read '{}': {error}", path.display()));
    serde_saphyr::from_str(&document)
        .unwrap_or_else(|error| panic!("'{}' is not YAML: {error}", path.display()))
}

/// The committed `v2.0` CRD manifest (what an upgrade actually installs).
fn current_crd(crd_name: &str) -> Value {
    let path = repository_root()
        .join("deploy/crds")
        .join(format!("{crd_name}.yaml"));
    let document = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read '{}': {error}", path.display()));
    serde_saphyr::from_str(&document)
        .unwrap_or_else(|error| panic!("'{}' is not YAML: {error}", path.display()))
}

/// The `spec.versions[0].schema.openAPIV3Schema` of a CRD manifest.
fn openapi_schema(crd: &Value) -> &Value {
    &crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]
}

/// Asserts that `crd` serves exactly one version, `v1alpha1`, and that it is also the *storage*
/// version — then returns it.
///
/// Pinning the version is what makes every comparison below about the version a cluster actually
/// stores: if `v2.0` ever served a second (or renamed) version, `spec.versions[0]` would no longer be
/// the schema a `v1.0` object is read and written through, and "no removed field" would be checked
/// against the wrong contract while still passing.
fn served_storage_version(crd: &Value, crd_name: &str) -> String {
    let versions = crd["spec"]["versions"]
        .as_array()
        .unwrap_or_else(|| panic!("{crd_name}: the CRD declares no spec.versions"));
    assert_eq!(
        versions.len(),
        1,
        "{crd_name}: this suite compares one version, but the CRD serves {}",
        versions.len()
    );
    let version = &versions[0];
    assert_eq!(
        version["name"].as_str(),
        Some("v1alpha1"),
        "{crd_name}: the served version is not the one the fixture CRs are written against"
    );
    assert_eq!(
        version["served"].as_bool(),
        Some(true),
        "{crd_name}: v1alpha1 must stay served, or every stored v1.0 object becomes unreadable"
    );
    assert_eq!(
        version["storage"].as_bool(),
        Some(true),
        "{crd_name}: v1alpha1 must stay the storage version, or an upgrade rewrites every stored object"
    );
    assert_eq!(
        crd["spec"]["scope"].as_str(),
        Some("Namespaced"),
        "{crd_name}: the bundle and the types assume a namespaced CRD"
    );
    "v1alpha1".to_owned()
}

/// The `spec` schema of a CRD manifest.
fn spec_schema(crd: &Value) -> &Value {
    &openapi_schema(crd)["properties"]["spec"]
}

/// Every `resources/**.yaml` fixture, as `(relative path, parsed document)`.
fn resource_fixtures() -> Vec<(String, Value)> {
    fn collect(directory: &Path, prefix: &str, out: &mut Vec<(String, Value)>) {
        let entries = std::fs::read_dir(directory)
            .unwrap_or_else(|error| panic!("failed to list '{}': {error}", directory.display()));
        for entry in entries {
            let path = entry.expect("a fixture entry").path();
            if path.is_dir() {
                continue;
            }
            if path.extension().is_none_or(|extension| extension != "yaml") {
                continue;
            }
            let name = path.file_name().expect("a file name").to_string_lossy();
            let document = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("failed to read '{}': {error}", path.display()));
            let parsed: Value = serde_saphyr::from_str(&document)
                .unwrap_or_else(|error| panic!("'{}' is not YAML: {error}", path.display()));
            out.push((format!("{prefix}/{name}"), parsed));
        }
    }

    let mut fixtures = Vec::new();
    for kind in ["applications", "appprojects"] {
        collect(
            &fixtures_root().join("resources").join(kind),
            kind,
            &mut fixtures,
        );
    }
    fixtures.sort_by(|left, right| left.0.cmp(&right.0));
    assert!(
        !fixtures.is_empty(),
        "there must be at least one v1.0 fixture"
    );
    fixtures
}

// ---------------------------------------------------------------------------
// the checker
// ---------------------------------------------------------------------------

/// **Acceptance criterion.** No field removed or narrowed, no enum value dropped, no new required
/// property: for every `v1.0` CRD, the current schema is a strict superset of what `v1.0` admitted.
#[test]
fn the_current_schemas_are_a_superset_of_v1_0() {
    for (crd_name, file_name) in V1_0_CRDS {
        let before = v1_0_crd(file_name);
        let after = current_crd(crd_name);
        assert_eq!(before["metadata"]["name"], crd_name);
        assert_eq!(after["metadata"]["name"], crd_name);
        // Both sides are the *served and storage* version, so the diff below is the contract a real
        // cluster upgrades through.
        assert_eq!(served_storage_version(&before, crd_name), "v1alpha1");
        assert_eq!(served_storage_version(&after, crd_name), "v1alpha1");

        let before_surface = Surface::of(openapi_schema(&before));
        let after_surface = Surface::of(openapi_schema(&after));
        assert!(
            before_surface.fields.len() > 20,
            "{crd_name}: the frozen v1.0 surface looks empty ({} fields)",
            before_surface.fields.len()
        );

        // 1. No removed (or re-typed) field.
        for (path, expected) in &before_surface.fields {
            let actual = after_surface.fields.get(path).unwrap_or_else(|| {
                panic!("{crd_name}: v2.0 removed `{path}`, which a stored v1.0 object may carry")
            });
            assert_eq!(
                (path, &actual.type_name),
                (path, &expected.type_name),
                "{crd_name}: `{path}` changed type; a stored v1.0 value may no longer be valid"
            );
            assert_eq!(
                (path, &actual.format),
                (path, &expected.format),
                "{crd_name}: `{path}` changed format"
            );
            assert!(
                !expected.nullable || actual.nullable,
                "{crd_name}: `{path}` was nullable in v1.0 and is not any more"
            );
        }

        // 2. No narrowed enum.
        for (path, expected) in &before_surface.fields {
            let Some(expected_values) = &expected.enum_values else {
                continue;
            };
            let actual = after_surface
                .fields
                .get(path)
                .and_then(|shape| shape.enum_values.clone())
                .unwrap_or_else(|| {
                    panic!("{crd_name}: `{path}` lost its enum, which narrows the accepted values")
                });
            for value in expected_values {
                assert!(
                    actual.contains(value),
                    "{crd_name}: `{path}` no longer accepts `{value}` (now {actual:?})"
                );
            }
        }

        // 3. No newly required property.
        for node in &before_surface.nodes {
            let before_required = before_surface
                .required
                .get(node)
                .cloned()
                .unwrap_or_default();
            let after_required = after_surface
                .required
                .get(node)
                .cloned()
                .unwrap_or_default();
            for name in &after_required {
                assert!(
                    before_required.contains(name),
                    "{crd_name}: `{node}` now requires `{name}`, which a stored v1.0 object may omit"
                );
            }
        }
    }
}

/// **Non-vacuity guard.** The frozen baseline must really be the `v1.0` schema, and this major
/// version must really have made the additive changes the roadmap claims — otherwise the superset
/// assertions above could pass while comparing the current schema to itself.
#[test]
fn the_frozen_baseline_is_really_v1_0() {
    let v1_application = v1_0_crd("applications.ferriscd.io.yaml");
    let v2_application = current_crd("applications.ferriscd.io");
    let v1_spec = spec_schema(&v1_application);
    let v2_spec = spec_schema(&v2_application);

    let required_names = |spec: &Value| -> BTreeSet<String> {
        spec.get("required")
            .and_then(Value::as_array)
            .map(|names| {
                names
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    };

    // `v1.0` required `spec.source`; `T20.1` relaxed it to `Option` so `spec.sources` can be used.
    assert!(
        required_names(v1_spec).contains("source"),
        "the frozen baseline does not require spec.source, so it is not v1.0"
    );
    assert!(
        !required_names(v2_spec).contains("source"),
        "spec.source must stay optional for multi-source Applications"
    );
    // ...and the multi-source field is genuinely new.
    assert!(
        v1_spec["properties"].get("sources").is_none(),
        "the frozen baseline already carries spec.sources, so it is not v1.0"
    );
    assert!(
        v2_spec["properties"].get("sources").is_some(),
        "spec.sources is missing from the current schema"
    );
    // `v1.0` required `spec.source.git`; OCI sources (`T18.3`) made both arms optional.
    assert_eq!(
        v1_spec["properties"]["source"]["required"],
        serde_json::json!(["git"])
    );
    assert!(
        v2_spec["properties"]["source"].get("required").is_none(),
        "spec.source must not require `git` any more"
    );

    // `AppProject` gained exactly the two additive control blocks.
    let v1_project_crd = v1_0_crd("appprojects.ferriscd.io.yaml");
    let v2_project_crd = current_crd("appprojects.ferriscd.io");
    let v1_project = spec_schema(&v1_project_crd);
    let v2_project = spec_schema(&v2_project_crd);
    for added in ["syncWindows", "policyRules"] {
        assert!(
            v1_project["properties"].get(added).is_none(),
            "the frozen AppProject baseline already carries {added}"
        );
        assert!(
            v2_project["properties"].get(added).is_some(),
            "AppProject.{added} is missing from the current schema"
        );
    }

    // `ApplicationSet` is a whole new CRD, so it cannot break anything: it must be committed (and
    // therefore installed by `helm upgrade`) while having no v1.0 counterpart.
    let applicationset = current_crd("applicationsets.ferriscd.io");
    assert_eq!(applicationset["spec"]["names"]["kind"], "ApplicationSet");
    // The new CRD is served and stored at the same version as everything else: one CRD generation,
    // one stored shape, so no conversion webhook is needed (`v2.0` ships none).
    assert_eq!(
        served_storage_version(&applicationset, "applicationsets.ferriscd.io"),
        "v1alpha1"
    );
    assert!(
        !fixtures_root()
            .join("crds")
            .join("applicationsets.ferriscd.io.yaml")
            .exists(),
        "there must be no v1.0 ApplicationSet CRD: ApplicationSet shipped in v1.3"
    );
}

/// **Acceptance criterion.** Every `v1.0` fixture still deserializes, validates, and keeps every
/// one of its fields — the offline half of "100% v1.0 CR deserialization and validation parity".
#[test]
fn v1_0_fixture_objects_still_deserialize_validate_and_round_trip() {
    let mut applications = 0;
    let mut projects = 0;

    for (origin, document) in resource_fixtures() {
        match document["kind"]
            .as_str()
            .expect("every fixture declares a kind")
        {
            "Application" => {
                let application: Application = serde_json::from_value(document.clone())
                    .unwrap_or_else(|error| panic!("{origin} no longer deserializes: {error}"));
                application
                    .spec
                    .validate()
                    .unwrap_or_else(|error| panic!("{origin} no longer validates: {error}"));
                let serialized =
                    serde_json::to_value(&application).expect("the Application serializes");

                assert_fixture_preserved(&document, &serialized, &origin);
                // A single-source v1.0 object must never grow a multi-source or OCI block.
                assert!(
                    serialized["spec"].get("sources").is_none(),
                    "{origin}: a v1.0 Application must not gain spec.sources"
                );
                assert!(
                    serialized["spec"]["source"].get("oci").is_none(),
                    "{origin}: a v1.0 Git Application must not gain spec.source.oci"
                );
                // An omitted optional block stays omitted (no `null` and no filled-in defaults).
                if document["spec"].get("syncPolicy").is_none() {
                    assert!(
                        serialized["spec"].get("syncPolicy").is_none(),
                        "{origin}: an omitted spec.syncPolicy must stay omitted"
                    );
                }
                applications += 1;
            }
            "AppProject" => {
                let project: AppProject = serde_json::from_value(document.clone())
                    .unwrap_or_else(|error| panic!("{origin} no longer deserializes: {error}"));
                project
                    .spec
                    .validate()
                    .unwrap_or_else(|error| panic!("{origin} no longer validates: {error}"));
                let serialized = serde_json::to_value(&project).expect("the AppProject serializes");

                assert_fixture_preserved(&document, &serialized, &origin);
                // The additive control blocks must not appear on a v1.0 project.
                assert!(
                    serialized["spec"].get("syncWindows").is_none(),
                    "{origin}: a v1.0 AppProject must not gain spec.syncWindows"
                );
                assert!(
                    serialized["spec"].get("policyRules").is_none(),
                    "{origin}: a v1.0 AppProject must not gain spec.policyRules"
                );
                projects += 1;
            }
            other => panic!("{origin}: unexpected fixture kind {other}"),
        }
    }

    assert!(
        applications >= 2,
        "the suite needs both v1.0 Application shapes"
    );
    assert!(projects >= 1, "the suite needs a v1.0 AppProject");
}

/// A stored `v1.0` object must still pass the **current** schema: every property the current CRD
/// requires is present in the fixture.
#[test]
fn v1_0_fixtures_satisfy_the_current_required_properties() {
    for (origin, document) in resource_fixtures() {
        let crd_name = match document["kind"].as_str().expect("a kind") {
            "Application" => "applications.ferriscd.io",
            "AppProject" => "appprojects.ferriscd.io",
            other => panic!("{origin}: unexpected fixture kind {other}"),
        };
        let current_crd = current_crd(crd_name);
        let current_spec = spec_schema(&current_crd);
        let required = current_spec
            .get("required")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for name in required {
            let name = name.as_str().expect("a required name");
            assert!(
                document["spec"].get(name).is_some(),
                "{origin}: the current {crd_name} requires spec.{name}, which this stored v1.0 \
                 object does not set (a v1.0 object would be rejected at admission)"
            );
        }
    }
}

/// Asserts that every key of `expected` is present in `actual` with the same value.
///
/// Extras in `actual` are allowed (the current types may serialize a default the fixture omitted);
/// a missing or changed key is a compatibility break.
fn assert_fixture_preserved(expected: &Value, actual: &Value, path: &str) {
    match (expected, actual) {
        (Value::Object(expected), Value::Object(actual)) => {
            for (key, expected_value) in expected {
                let actual_value = actual
                    .get(key)
                    .unwrap_or_else(|| panic!("{path}.{key} was dropped by the current types"));
                assert_fixture_preserved(expected_value, actual_value, &format!("{path}.{key}"));
            }
        }
        (Value::Array(expected), Value::Array(actual)) => {
            assert_eq!(
                expected.len(),
                actual.len(),
                "{path}: the current types changed the element count"
            );
            for (index, (expected_item, actual_item)) in expected.iter().zip(actual).enumerate() {
                assert_fixture_preserved(expected_item, actual_item, &format!("{path}[{index}]"));
            }
        }
        (expected, actual) => assert_eq!(
            expected, actual,
            "{path}: the current types changed this value"
        ),
    }
}
