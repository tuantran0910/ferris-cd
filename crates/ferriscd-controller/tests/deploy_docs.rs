//! Guards for the operator-facing documentation in `deploy/README.md`.
//!
//! The README is the only place an operator reads the RBAC they must grant *before* turning
//! multi-tenancy on, so a regression there is a security regression that no other test would
//! catch: the Phase 12 review found the sample `ClusterRole` shipping
//! `apiGroups: ["*"], resources: ["*"]`, which grants `secrets` **cluster-wide** and directly
//! contradicts the namespaced-`Role` rule the same document states. These tests parse the
//! YAML samples in that file, so the documentation cannot drift back into that shape, and pin the
//! operational notes (the tenant-finalizer wedge and its `force-delete` escape hatch).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::Value;

const README: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../deploy/README.md"
));

/// Every fenced `yaml` block in the README.
fn yaml_blocks() -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current: Option<Vec<&str>> = None;
    for line in README.lines() {
        match (line.trim_start().starts_with("```"), &mut current) {
            (true, None) => {
                current = Some(Vec::new());
                continue;
            }
            (true, Some(_)) => {
                if let Some(lines) = current.take() {
                    blocks.push(lines.join("\n"));
                }
                continue;
            }
            (false, Some(lines)) => lines.push(line),
            (false, None) => {}
        }
    }
    blocks
}

/// Every (kind, metadata.name, rules) triple of an RBAC document in the README's YAML samples.
fn rbac_documents() -> Vec<(String, String, Vec<Value>)> {
    let mut documents = Vec::new();
    for block in yaml_blocks() {
        // The samples are multi-document (`Role` + `RoleBinding` in one block), so split on the
        // document separator before parsing.
        for document in block.split("\n---\n") {
            let Ok(parsed) = serde_saphyr::from_str::<Value>(document) else {
                continue;
            };
            let Some(kind) = parsed.get("kind").and_then(Value::as_str) else {
                continue;
            };
            if !matches!(kind, "Role" | "ClusterRole") {
                continue;
            }
            let name = parsed
                .get("metadata")
                .and_then(|metadata| metadata.get("name"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let rules = parsed
                .get("rules")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            documents.push((kind.to_owned(), name, rules));
        }
    }
    documents
}

fn contains(rule: &Value, field: &str, value: &str) -> bool {
    rule.get(field)
        .and_then(Value::as_array)
        .is_some_and(|entries| entries.iter().any(|entry| entry.as_str() == Some(value)))
}

/// **Finding M1:** the documented sample must never grant every GroupKind — that includes
/// `secrets`, i.e. cluster-wide secret reads, which `T12.4` deliberately forbids.
#[test]
fn the_documented_rbac_never_grants_cluster_wide_wildcards() {
    let documents = rbac_documents();
    assert!(
        !documents.is_empty(),
        "the README must contain at least one RBAC sample: no document was parsed"
    );
    for (kind, _name, rules) in &documents {
        for rule in rules {
            assert!(
                !(contains(rule, "apiGroups", "*") && contains(rule, "resources", "*")),
                "the {kind} sample grants `apiGroups: [\"*\"] / resources: [\"*\"]`, which includes \
                 every Secret in the cluster: {README}"
            );
        }
    }
}

/// **Finding M1 (the `secrets` half):** no `ClusterRole` sample may include `secrets`; the only
/// documented `secrets` grant is the namespaced `Role`.
#[test]
fn no_cluster_role_sample_grants_secrets() {
    let documents = rbac_documents();
    assert!(
        documents.iter().any(|(kind, _, _)| kind == "ClusterRole"),
        "the README must document at least one ClusterRole sample for this guard to mean anything"
    );
    for (kind, _name, rules) in documents {
        if kind != "ClusterRole" {
            continue;
        }
        for rule in &rules {
            assert!(
                !contains(rule, "resources", "secrets"),
                "a ClusterRole sample grants `secrets`, which must stay a namespaced Role"
            );
        }
    }
}

/// The document must state where the credential `Secret`s live, and that they are read with a
/// namespaced `Api` — the property the RBAC above is derived from.
#[test]
fn repository_credentials_are_documented_as_namespaced_only() {
    for expected in [
        "ferriscd.io/secret-type=repository",
        "control-plane namespace only",
        "namespaced",
        "Do **not** add `secrets`",
    ] {
        assert!(
            README.contains(expected),
            "deploy/README.md must document {expected:?}"
        );
    }
}

/// **`T13.1`/`T13.2`:** the remote-cluster and HA RBAC must be documented as namespaced grants, and
/// the trap guards (TLS verification, the reserved `in-cluster` name, the finalizer escape hatch)
/// must be stated where an operator reads them.
#[test]
fn the_remote_cluster_and_ha_rbac_is_documented_as_namespaced() {
    for expected in [
        "ferriscd.io/secret-type=cluster",
        "ferriscd-cluster-registry",
        "coordination.k8s.io",
        "leases",
        "--leader-election",
        "--allow-insecure-cluster-tls",
        "insecureSkipTLSVerify",
        "CleanupSkipped",
    ] {
        assert!(
            README.contains(expected),
            "deploy/README.md must document {expected:?}"
        );
    }
    // The cluster `Secret` grant must be a namespaced `Role` **named for the registry** (the
    // `no_cluster_role_sample_grants_secrets` test above already proves it is not a `ClusterRole`
    // rule). Filtering by name matters: the repository-credentials `Role` also grants `secrets`
    // (for `ferriscd.io/secret-type=repository`), so a kind-only match would let the cluster
    // registry's grant vanish from the documentation while this test still passed (finding M9).
    let documents = rbac_documents();
    let registry = documents.iter().find(|(kind, name, rules)| {
        kind == "Role"
            && name == "ferriscd-cluster-registry"
            && rules
                .iter()
                .any(|rule| contains(rule, "resources", "secrets"))
    });
    assert!(
        registry.is_some(),
        "the README must document the namespaced Secret Role the cluster registry needs \
         (`ferriscd-cluster-registry`); the repository-credentials Role cannot stand in for it"
    );
    assert!(
        README.contains("The lease needs no extra `ClusterRole` rule"),
        "the leader-election Lease must be documented as a namespaced grant"
    );
}

/// **Finding M4:** the tenant finalizer wedge and the `force-delete` escape hatch must be
/// documented for operators, not only in a code comment.
#[test]
fn the_tenant_finalizer_wedge_and_its_escape_hatch_are_documented() {
    for expected in [
        "ferriscd.io/finalizer",
        "ferriscd.io/force-delete",
        "retained",
        "allowedServiceAccounts",
        "cascade",
    ] {
        assert!(
            README.contains(expected),
            "deploy/README.md must document the finalizer wedge ({expected:?} missing)"
        );
    }
    // The wedge has to point at a real remedy, as a unit has to be named.
    assert!(
        README.contains("PolicyViolation"),
        "the operator must be told which condition reason to look for"
    );
}

/// **`T13.3`:** the sharding flags, the per-shard `Lease` naming and the refusals that make
/// "sharding plus one shared leader" unconfigurable must be documented where an operator reads them
/// — the same place the `T13.2` lease notes live — and the `leases` grant must not be duplicated:
/// every per-shard `Lease` is namespaced, so the existing `Role` covers them.
#[test]
fn the_sharding_flags_and_per_shard_leases_are_documented() {
    for expected in [
        "--shard-id",
        "--total-shards",
        "FERRISCD_SHARD_ID",
        "FERRISCD_TOTAL_SHARDS",
        "ferriscd-leader-shard-<id>",
        "sha256(namespace, name) % total-shards",
        "--leader-election-lease-name` is refused together with `--shard-id",
    ] {
        assert!(
            README.contains(expected),
            "deploy/README.md must document {expected:?}"
        );
    }
    // Sharding must be documented as *requiring* election, not as an alternative to it.
    assert!(
        README.contains("Sharding requires `--leader-election`"),
        "sharding is per-shard leader election, never a replacement for it"
    );
}

/// **`T15.1`:** the metrics listener is a documented, separate port with an env fallback, and the
/// cardinality trap guard is stated where an operator (or a future contributor) reads it — the eleven
/// families must all be listed, or a dashboard is built against metrics nothing exports.
#[test]
fn the_metrics_listener_and_its_cardinality_contract_are_documented() {
    for expected in [
        "--metrics-addr",
        "FERRISCD_METRICS_ADDR",
        "0.0.0.0:9090",
        "/metrics",
        "ferriscd_reconcile_duration_seconds",
        "ferriscd_reconcile_total",
        "ferriscd_app_sync_status",
        "ferriscd_app_health_status",
        "ferriscd_git_fetch_duration_seconds",
        "ferriscd_render_cache_total",
        "ferriscd_active_reconciles",
        "ferriscd_rbac_reload_total",
        "ferriscd_rbac_watch_errors_total",
        "ferriscd_audit_events_total",
        "ferriscd_audit_dropped_total",
    ] {
        assert!(
            README.contains(expected),
            "deploy/README.md must document {expected:?}"
        );
    }
    for forbidden in ["commit_sha", "error_message", "resource name"] {
        assert!(
            README.contains(forbidden),
            "the trap guard must name {forbidden:?}: an operator has to be told why the label is \
             absent, not left to add it"
        );
    }
    // The listener is documented as its own port, never the API one.
    assert!(
        README.contains("never on the API/webhook port"),
        "the README must state that `/metrics` is not served on the API port"
    );
}

/// **`T15.2`:** OpenTelemetry OTLP configuration, Kubernetes `events.k8s.io/v1` RBAC, and the
/// 5-minute consecutive `Warning` deduplication contract are documented in `deploy/README.md`.
#[test]
fn otlp_tracing_and_kubernetes_events_rbac_are_documented() {
    for expected in [
        "OTEL_EXPORTER_OTLP_ENDPOINT",
        "OTEL_SERVICE_NAME",
        "events.k8s.io",
        "SyncSucceeded",
        "ResourcePruned",
        "SyncFailed",
        "5-minute",
    ] {
        assert!(
            README.contains(expected),
            "deploy/README.md must document {expected:?}"
        );
    }
    let documents = rbac_documents();
    let has_events_rule = documents.iter().any(|(kind, _, rules)| {
        kind == "ClusterRole"
            && rules.iter().any(|rule| {
                contains(rule, "apiGroups", "events.k8s.io")
                    && contains(rule, "resources", "events")
                    && contains(rule, "verbs", "create")
                    && contains(rule, "verbs", "patch")
                    && contains(rule, "verbs", "get")
                    && contains(rule, "verbs", "list")
            })
    });
    assert!(
        has_events_rule,
        "the ClusterRole sample must grant create/patch/get/list on events.k8s.io/v1 events"
    );
}

/// **`T18.1`:** the ownership-label opt-in, its env fallback and the two labels it stamps must be
/// documented where an operator decides to turn it on — including the immutability trap guard, so
/// nobody "improves" the stamp by writing into `spec.selector.matchLabels`.
#[test]
fn the_ownership_labels_and_their_trap_guard_are_documented() {
    for expected in [
        "--enable-drift-watcher",
        "FERRISCD_ENABLE_DRIFT_WATCHER",
        "ferriscd.io/managed-by",
        "ferriscd.io/app-hash",
        "63-character",
        "spec.selector.matchLabels",
        "spec.template.metadata.labels",
        "422 Immutable",
        "Lifecycle hooks are never stamped",
        "additive",
        "Added",
        "Rebuilt",
        "Removed",
        "Lagged",
    ] {
        assert!(
            README.contains(expected),
            "deploy/README.md must document {expected:?} for the opt-in ownership labels"
        );
    }
}

// ---------------------------------------------------------------------------
// `T19.3`: the shipped RBAC for the opt-in `ApplicationSet` controller
// ---------------------------------------------------------------------------

const MANIFEST_RBAC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../deploy/manifests/rbac.yaml"
));

const HELM_RBAC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../deploy/helm/ferriscd/templates/rbac.yaml"
));

const HELM_VALUES: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../deploy/helm/ferriscd/values.yaml"
));

const HELM_VALUES_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../deploy/helm/ferriscd/values.schema.json"
));

/// Every `Role`/`ClusterRole` rule of the shipped Kustomize manifest, with the active ones parsed.
fn manifest_roles() -> Vec<(String, Vec<Value>)> {
    let mut roles = Vec::new();
    for document in MANIFEST_RBAC.split("\n---\n") {
        let Ok(parsed) = serde_saphyr::from_str::<Value>(document) else {
            continue;
        };
        if parsed.get("kind").and_then(Value::as_str) != Some("Role") {
            continue;
        }
        let name = parsed
            .get("metadata")
            .and_then(|metadata| metadata.get("name"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let rules = parsed
            .get("rules")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        roles.push((name, rules));
    }
    roles
}

fn grants(rule: &Value, resource: &str, verb: &str) -> bool {
    contains(rule, "resources", resource) && contains(rule, "verbs", verb)
}

/// **Finding H1:** the shipped manifest is the least-privilege default — the `ApplicationSet`
/// controller is opt-in, so nothing it needs may be granted until an operator asks for it, and the
/// opt-in block must document the verbs the code actually uses.
#[test]
fn the_shipped_manifest_documents_but_does_not_grant_the_applicationset_rbac() {
    let roles = manifest_roles();
    let (_, rules) = roles
        .iter()
        .find(|(name, _)| name == "ferriscd")
        .expect("deploy/manifests/rbac.yaml must define the ferriscd Role");

    for rule in rules {
        assert!(
            !contains(rule, "resources", "applicationsets")
                && !contains(rule, "resources", "applicationsets/status"),
            "the shipped Role must not grant `applicationsets` by default: the controller is \
             opt-in ({rule})"
        );
        if contains(rule, "resources", "applications") {
            assert!(
                !contains(rule, "verbs", "create"),
                "`create` on `applications` is only needed by the opt-in ApplicationSet controller \
                 (Server-Side Apply), so it stays in the commented block: {rule}"
            );
        }
        assert!(
            !contains(rule, "resources", "applicationsets/finalizers"),
            "the loop patches `metadata.finalizers` through the object (merge patch): the \
             subresource grant must not be documented as required: {rule}"
        );
    }

    // The opt-in block: every grant, with the exact verb list, present as documentation.
    for expected in [
        "ApplicationSet controller",
        "--enable-applicationsets",
        "resources: [\"applicationsets\"]",
        "verbs: [\"get\", \"list\", \"watch\", \"patch\"]",
        "resources: [\"applicationsets/status\"]",
        "verbs: [\"get\", \"patch\", \"update\"]",
        "verbs: [\"get\", \"list\", \"watch\", \"patch\", \"create\"]",
        "Server-Side Apply",
        "merge patch",
    ] {
        assert!(
            MANIFEST_RBAC.contains(expected),
            "deploy/manifests/rbac.yaml must document {expected:?} for the opt-in controller"
        );
    }
    assert!(
        !MANIFEST_RBAC.contains("resources: [\"applicationsets/finalizers\"]"),
        "the unused `applicationsets/finalizers` grant must not be documented at all"
    );
}

/// **Finding M-c:** the opt-in `ApplicationSet` prune (`spec.syncPolicy.prune: true`, or
/// `preserveResourcesOnDeletion: false`) is the only path that deletes generated `Application`s, so
/// `delete` must be a second, separately documented opt-in — never part of the default grant.
#[test]
fn the_applicationset_prune_grant_is_a_documented_separate_opt_in() {
    // Helm: its own value, default off, validated by the schema.
    assert!(
        HELM_VALUES.contains("applicationsetPrune: false"),
        "values.yaml must default `rbac.applicationsetPrune` to false"
    );
    assert!(
        HELM_VALUES_SCHEMA.contains("\"applicationsetPrune\": { \"type\": \"boolean\" }"),
        "values.schema.json must declare `rbac.applicationsetPrune` so `helm lint` validates it"
    );
    assert!(
        HELM_RBAC.contains("{{- if .Values.rbac.applicationsetPrune }}"),
        "templates/rbac.yaml must gate `delete` on `rbac.applicationsetPrune`"
    );
    assert!(
        HELM_RBAC
            .contains("verbs: [\"get\", \"list\", \"watch\", \"patch\", \"create\", \"delete\"]"),
        "the widened grant must be the documented six-verb list"
    );
    // The `delete` grant must stay *inside* the `applicationsets` gate: a chart that granted it
    // unconditionally would hand every installation a deletion permission nothing asked for.
    let delete_rule = HELM_RBAC
        .split("{{- if .Values.rbac.applicationsets }}")
        .nth(1)
        .expect("the applicationsets gate exists");
    assert!(
        delete_rule.contains("\"delete\""),
        "the `delete` verb must be inside the `rbac.applicationsets` gate"
    );

    // The shipped Kustomize manifest documents it but grants nothing by default.
    for expected in [
        "rbac.applicationsetPrune",
        "verbs: [\"get\", \"list\", \"watch\", \"patch\", \"create\", \"delete\"]",
    ] {
        assert!(
            MANIFEST_RBAC.contains(expected),
            "deploy/manifests/rbac.yaml must document {expected:?} for the opt-in prune"
        );
    }
    let roles = manifest_roles();
    let (_, rules) = roles
        .iter()
        .find(|(name, _)| name == "ferriscd")
        .expect("deploy/manifests/rbac.yaml must define the ferriscd Role");
    for rule in rules {
        if contains(rule, "resources", "applications") {
            assert!(
                !contains(rule, "verbs", "delete"),
                "the shipped Role must not grant `delete` on `applications`: pruning is opt-in \
                 per ApplicationSet, and the grant is namespace-wide ({rule})"
            );
        }
    }

    // The operator-facing README carries the same rule, and says which values widen it.
    for expected in [
        "rbac.applicationsetPrune",
        "spec.syncPolicy.prune",
        "preserveResourcesOnDeletion",
        "verbs: [\"get\", \"list\", \"watch\", \"patch\", \"create\", \"delete\"]",
    ] {
        assert!(
            README.contains(expected),
            "deploy/README.md must document {expected:?} for the opt-in prune grant"
        );
    }
}

/// **Finding H1 (Helm half):** the chart must keep the grants behind a value that defaults to
/// `false`, and the flag the controller reads must be nameable from `values.yaml`.
#[test]
fn the_helm_chart_gates_the_applicationset_rbac_behind_a_default_off_value() {
    assert!(
        HELM_VALUES.contains("applicationsets: false"),
        "values.yaml must default `rbac.applicationsets` to false"
    );
    assert!(
        HELM_VALUES_SCHEMA.contains("\"applicationsets\": { \"type\": \"boolean\" }"),
        "values.schema.json must declare `rbac.applicationsets` so `helm lint` validates it"
    );
    assert!(
        HELM_VALUES.contains("--enable-applicationsets"),
        "values.yaml must name the flag the grant pairs with"
    );

    assert!(
        HELM_RBAC.contains("{{- if .Values.rbac.applicationsets }}"),
        "templates/rbac.yaml must gate the grants on `rbac.applicationsets`"
    );
    assert_eq!(
        HELM_RBAC
            .matches("resources: [\"applicationsets\"]")
            .count(),
        1,
        "the `applicationsets` rule must appear exactly once (inside the gate)"
    );
    assert_eq!(
        HELM_RBAC
            .matches("resources: [\"applicationsets/status\"]")
            .count(),
        1,
        "the `applicationsets/status` rule must appear exactly once (inside the gate)"
    );
    for expected in [
        // The opt-in verb lists, exactly as the loop uses them.
        "verbs: [\"get\", \"list\", \"watch\", \"patch\"]",
        "verbs: [\"get\", \"patch\", \"update\"]",
        // Server-Side Apply: `create` on `applications` is inside the gate, `else` the old list.
        "verbs: [\"get\", \"list\", \"watch\", \"patch\", \"create\"]",
        "--enable-applicationsets",
    ] {
        assert!(
            HELM_RBAC.contains(expected),
            "templates/rbac.yaml must document {expected:?}"
        );
    }
    assert!(
        !HELM_RBAC.contains("applicationsets/finalizers"),
        "the subresource is never used, so the chart must not grant it"
    );
}

/// **Finding H1 (docs half):** the operator-facing README must carry the same grants, the
/// `in-cluster` exclusion, the non-destructive default, and the disabling caveat.
#[test]
fn the_applicationset_controller_grants_and_caveats_are_documented() {
    for expected in [
        "--enable-applicationsets",
        "FERRISCD_ENABLE_APPLICATIONSETS",
        "rbac.applicationsets",
        "resources: [\"applicationsets\"]",
        "resources: [\"applicationsets/status\"]",
        "verbs: [\"get\", \"list\", \"watch\", \"patch\", \"create\"]",
        "Server-Side Apply",
        "merge patch",
        // The reserved pseudo-cluster is never a generator parameter.
        "never yields `in-cluster`",
        // The safe deletion default, and the wedge that disabling the feature creates.
        "preserveResourcesOnDeletion",
        "ferriscd.io/applicationset-cleanup",
        "Terminating",
        "finalizers\":null",
        // Event-driven reaction instead of timer-only.
        "event-driven",
    ] {
        assert!(
            README.contains(expected),
            "deploy/README.md must document {expected:?} for the ApplicationSet controller"
        );
    }
    // The documented sample must grant the opt-in rules through a namespaced Role — never a
    // ClusterRole rule (the ApplicationSet controller only ever touches its own namespace).
    let documents = rbac_documents();
    let sample = documents
        .iter()
        .find(|(kind, name, rules)| {
            kind == "Role"
                && name == "ferriscd-applicationsets"
                && rules
                    .iter()
                    .any(|rule| grants(rule, "applicationsets", "patch"))
        })
        .is_some();
    assert!(
        sample,
        "the README must document the opt-in grants as a namespaced Role that patches \
         `applicationsets` (the finalizer is a merge patch, so `patch` — not `update`)"
    );
}
