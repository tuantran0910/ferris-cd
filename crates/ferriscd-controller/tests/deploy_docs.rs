//! Guards for the operator-facing documentation in `deploy/README.md`.
//!
//! The README is the only place an operator reads the RBAC they must grant *before* turning
//! multi-tenancy on, so a regression there is a security regression that no other test would
//! catch: the Phase 12 review found the sample `ClusterRole` shipping
//! `apiGroups: ["*"], resources: ["*"]`, which grants `secrets` **cluster-wide** and directly
//! contradicts the namespaced-`Role` rule the same document states, and the Phase 20 review found
//! the policy section redefining `ClusterRole/ferriscd-controller` (which `kubectl apply` *replaces*
//! rather than extends). These tests parse the YAML samples in that file, so the documentation cannot
//! drift back into either shape, and pin the operational notes (the tenant-finalizer wedge and its
//! `force-delete` escape hatch).

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

/// One documented RBAC object: `(kind, namespace, name)`.
///
/// A `Role`/`RoleBinding` is namespaced, so its namespace is part of its identity; a
/// `ClusterRole`/`ClusterRoleBinding` carries none (and must not, which is the point of the H1 guard
/// below).
type RbacIdentity = (String, Option<String>, String);

/// Every RBAC object the README **documents** — all four kinds — as [`RbacIdentity`].
fn rbac_identities() -> Vec<RbacIdentity> {
    let mut identities = Vec::new();
    for block in yaml_blocks() {
        for document in block.split("\n---\n") {
            let Ok(parsed) = serde_saphyr::from_str::<Value>(document) else {
                continue;
            };
            let Some(kind) = parsed.get("kind").and_then(Value::as_str) else {
                continue;
            };
            if !matches!(
                kind,
                "Role" | "ClusterRole" | "RoleBinding" | "ClusterRoleBinding"
            ) {
                continue;
            }
            let metadata = parsed.get("metadata");
            let name = metadata
                .and_then(|metadata| metadata.get("name"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let namespace = metadata
                .and_then(|metadata| metadata.get("namespace"))
                .and_then(Value::as_str)
                .map(str::to_owned);
            identities.push((kind.to_owned(), namespace, name));
        }
    }
    identities
}

/// **Finding H1:** every documented RBAC object must be a *distinct* object, and the policy
/// `ConfigMap` must be granted by a namespaced `Role` — never by redefining `ferriscd-controller`.
///
/// The Phase 20 review found the policy section shipping a second
/// `ClusterRole/metadata.name: ferriscd-controller` with a single `configmaps: get` rule. Applying
/// that document does not merge with the controller's existing `ClusterRole`: it **replaces** it,
/// silently dropping the Application, AppProject, events and workload verbs the rest of this document
/// requires. A `ClusterRole` rule is also cluster-wide by construction, so a `configmaps` `get` there
/// grants the read in every tenant namespace, not just the control plane.
#[test]
fn documented_rbac_objects_are_distinct_and_the_policy_grant_is_namespaced() {
    let identities = rbac_identities();
    assert!(
        identities.len() > 4,
        "the README must document the control-plane RBAC: only {} object(s) parsed",
        identities.len()
    );

    // (1) No object is documented twice: the same identity applied twice replaces, never merges.
    for (index, identity) in identities.iter().enumerate() {
        for other in &identities[index + 1..] {
            assert_ne!(
                identity, other,
                "the README documents {identity:?} twice: `kubectl apply` of the second sample \
                 replaces the first one's rules instead of adding to them"
            );
        }
    }

    // (2) The controller's own role is documented once, as the `ClusterRole` it is.
    let controller: Vec<&RbacIdentity> = identities
        .iter()
        .filter(|(_, _, name)| name == "ferriscd-controller")
        .collect();
    assert_eq!(
        controller.len(),
        1,
        "exactly one documented object may be named `ferriscd-controller`: {controller:?}"
    );
    assert_eq!(
        controller[0].0, "ClusterRole",
        "`ferriscd-controller` is the controller's ClusterRole; a namespaced sample must not reuse \
         its name, because applying it would replace the role's rules"
    );

    // (3) The policy `ConfigMap` read is a namespaced `Role` + `RoleBinding` in the control plane.
    assert!(
        identities.contains(&(
            "Role".to_owned(),
            Some("ferriscd-system".to_owned()),
            "ferriscd-policy-rules".to_owned()
        )),
        "the README must document the namespaced `Role` that grants the policy `ConfigMap` read"
    );
    assert!(
        identities.contains(&(
            "RoleBinding".to_owned(),
            Some("ferriscd-system".to_owned()),
            "ferriscd-policy-rules".to_owned()
        )),
        "the policy `Role` needs the `RoleBinding` that binds it to the controller ServiceAccount"
    );
    let policy = rbac_documents()
        .into_iter()
        .find(|(kind, name, _)| kind == "Role" && name == "ferriscd-policy-rules")
        .map(|(_, _, rules)| rules)
        .expect("the policy `Role` sample must carry rules");
    assert!(
        policy.iter().any(|rule| {
            contains(rule, "apiGroups", "") && contains(rule, "resources", "configmaps")
        }),
        "the policy `Role` must grant `configmaps`, not some other resource: {policy:?}"
    );
    assert!(
        policy
            .iter()
            .all(|rule| !contains(rule, "verbs", "*") && !contains(rule, "resources", "*")),
        "the policy read is one scoped `GET`: no wildcard verb or resource: {policy:?}"
    );
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

/// **`T20.2` finding N-A:** the documented policy sample must pair each `expression` with a
/// `matchKinds` list of the **same shape**.
///
/// `object` is the matched resource, so `object.spec.template.spec.containers` is meaningless for a
/// `Pod` (which keeps its containers at `spec.containers`) and `object.spec.containers` is
/// meaningless for an `apps/Deployment`. The CEL evaluator does not read that as "no match": a
/// missing field is an evaluation error, and the gate turns an evaluation error into a **blocking**
/// violation even for a `Warn` rule — so a sample that mixes the two shapes teaches an operator to
/// write a rule that refuses every `Pod` in the cluster.
#[test]
fn the_policy_sample_pairs_each_expression_with_matching_kinds() {
    // These are literal substring matches on the **dotted** spelling (`object.spec.containers`), so
    // the guard is bound to that spelling: a sample that wrote `object["spec"]["containers"]` or
    // `object.spec["containers"]` would evade it (finding N1). Widening it to a parse of the path
    // would be a second CEL front end in a docs test, so the guard is deliberately narrow and this
    // note is the trade-off — keep samples in dotted form.
    const WORKLOAD_PATH: &str = "object.spec.template.spec.";
    const POD_PATH: &str = "object.spec.containers";

    let mut rules = 0;
    for block in yaml_blocks() {
        let Ok(parsed) = serde_saphyr::from_str::<Value>(&block) else {
            continue;
        };
        if parsed.get("kind").and_then(Value::as_str) != Some("ConfigMap") {
            continue;
        }
        if parsed
            .get("metadata")
            .and_then(|metadata| metadata.get("name"))
            .and_then(Value::as_str)
            != Some("ferriscd-policies-cm")
        {
            continue;
        }
        let data = parsed
            .get("data")
            .and_then(Value::as_object)
            .expect("the policy ConfigMap sample must carry `data`");
        for (name, document) in data {
            let entry = serde_saphyr::from_str::<Value>(
                document.as_str().expect("a rule entry must be a string"),
            )
            .expect("every documented rule entry must be a valid rule document");
            let expression = entry
                .get("expression")
                .and_then(Value::as_str)
                .expect("a rule needs an expression");
            let match_kinds: Vec<&str> = entry
                .get("matchKinds")
                .and_then(Value::as_array)
                .map(|kinds| kinds.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            assert!(
                !match_kinds.is_empty(),
                "the documented rule {name:?} must name the kinds it applies to"
            );
            rules += 1;

            if expression.contains(WORKLOAD_PATH) {
                assert!(
                    !match_kinds
                        .iter()
                        .any(|kind| *kind == "Pod" || *kind == "v1/Pod"),
                    "the documented rule {name:?} reads a pod-template path \
                     (`{WORKLOAD_PATH}…`) but also matches `Pod`, whose containers live at \
                     `spec.containers`: the rule would fail to evaluate — a blocking finding — for \
                     every Pod"
                );
            }
            if expression.contains(POD_PATH) {
                assert!(
                    match_kinds
                        .iter()
                        .all(|kind| *kind == "Pod" || *kind == "v1/Pod"),
                    "the documented rule {name:?} reads `{POD_PATH}` but matches {match_kinds:?}: \
                     every non-Pod kind carries its containers under `spec.template.spec.…`, so the \
                     expression fails to evaluate — a blocking finding — for those kinds"
                );
            }
        }
    }
    assert!(
        rules > 0,
        "the README must document at least one `ConfigMap/ferriscd-policies-cm` rule sample"
    );

    // The trap guard itself is part of the contract: a missing field is a blocking error.
    assert!(
        README.contains("fails to evaluate"),
        "the policy section must warn that a path the matched kind does not carry fails to evaluate"
    );
    // ... and it is stated with **one** phrasing (finding N2) — in the annotated sample and in the
    // behaviour table row an operator skims — so the two cannot drift apart or be satisfied by a
    // half-edit of the sentence.
    assert!(
        README
            .matches("even when the rule is `enforcement: Warn`")
            .count()
            >= 2,
        "the policy section must state that an evaluation failure or a compile error blocks even \
         when the rule is `enforcement: Warn`, in the sample comment and in the behaviour table"
    );
}

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
