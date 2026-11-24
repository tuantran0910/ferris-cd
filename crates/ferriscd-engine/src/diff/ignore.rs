//! RFC 6901 `ignoreDifferences`: the user-configurable escape hatch for fields FerrisCD must
//! not report as drift.
//!
//! Real clusters constantly mutate fields nobody wrote in Git: an HPA owns
//! `/spec/replicas`, a mutating webhook injects sidecars, a controller adds annotations. A diff
//! engine that reports those as drift is unusable, so `Application.spec.ignoreDifferences`
//! removes them from **both** canonicalized sides before comparing.
//!
//! Two properties are load-bearing and are pinned by the tests:
//!
//! * **A missing pointer is a no-op, never an error.** A rule that names `/spec/replicas` must
//!   not fail reconciliation when the object (or that field) is absent — otherwise adding one
//!   ignore rule to a heterogeneous `Application` would break every other resource (trap
//!   "missing path must not error").
//! * **Only clones are touched.** [`IgnoreRuleSet::apply`] takes a `&mut Value` that the caller
//!   already cloned ([`ResourceDiff::compare`](crate::diff::ResourceDiff::compare) does), so the
//!   desired payload that gets applied is never mutated.
//!
//! Rule matching follows Argo CD's semantics: `kind` is required and exact, `group`/`name`/
//! `namespace` are optional narrowers where an **omitted** field means "any" (`group: ""`
//! explicitly means the core group). `managedFieldsManagers` is accepted in the CRD but not
//! consulted here: only JSON pointers are implemented in Phase 07.

use ferriscd_crd::IgnoreDifference;
use jsonptr::PointerBuf;
use serde_json::Value;

/// One `ignoreDifferences` rule, compiled for matching and for pointer removal.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IgnoreRule {
    group: Option<String>,
    kind: String,
    name: Option<String>,
    namespace: Option<String>,
    pointers: Vec<PointerBuf>,
    invalid_pointers: Vec<String>,
}

impl IgnoreRule {
    /// Builds a rule for `kind` that matches any group/name/namespace until narrowed.
    #[must_use]
    pub fn new(kind: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            ..Self::default()
        }
    }

    /// Narrows the rule to one API group (`""` is the core group). Builder style.
    #[must_use]
    pub fn with_group(mut self, group: impl Into<String>) -> Self {
        self.group = Some(group.into());
        self
    }

    /// Narrows the rule to one resource name. Builder style.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Narrows the rule to one namespace. Builder style.
    ///
    /// A narrow, never a wildcard: a cluster-scoped key (no namespace) does **not** match a rule
    /// that names one, exactly as [`Self::matches`] requires `Some(expected) == namespace`.
    #[must_use]
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }

    /// Adds a JSON Pointer whose value is ignored on both sides. Builder style.
    ///
    /// A pointer that is not valid RFC 6901 is recorded in
    /// [`Self::invalid_pointers`] and otherwise ignored: a typo in
    /// `spec.ignoreDifferences` must never fail a reconcile.
    #[must_use]
    pub fn with_json_pointer(mut self, pointer: impl Into<String>) -> Self {
        let pointer = pointer.into();
        match PointerBuf::parse(pointer.clone()) {
            Ok(parsed) => self.pointers.push(parsed),
            Err(_) => self.invalid_pointers.push(pointer),
        }
        self
    }

    /// Compiles one CRD [`IgnoreDifference`] into a rule.
    #[must_use]
    pub fn from_ignore_difference(difference: &IgnoreDifference) -> Self {
        let mut rule = Self::new(difference.kind.clone());
        if let Some(group) = &difference.group {
            rule.group = Some(group.clone());
        }
        if let Some(name) = &difference.name {
            rule.name = Some(name.clone());
        }
        if let Some(namespace) = &difference.namespace {
            rule.namespace = Some(namespace.clone());
        }
        for pointer in &difference.json_pointers {
            rule = rule.with_json_pointer(pointer.clone());
        }
        rule
    }

    /// Returns whether this rule applies to the given resource identity.
    #[must_use]
    pub fn matches(&self, group: &str, kind: &str, namespace: Option<&str>, name: &str) -> bool {
        self.kind == kind
            && self
                .group
                .as_deref()
                .is_none_or(|expected| expected == group)
            && self.name.as_deref().is_none_or(|expected| expected == name)
            && self
                .namespace
                .as_deref()
                .is_none_or(|expected| Some(expected) == namespace)
    }

    /// The parsed JSON pointers of this rule.
    #[must_use]
    pub fn json_pointers(&self) -> &[PointerBuf] {
        &self.pointers
    }

    /// Pointers that were not valid RFC 6901 and are therefore not applied.
    ///
    /// Surfaced for observability (`T07.5` can log them); a bad pointer never fails a sync.
    #[must_use]
    pub fn invalid_pointers(&self) -> &[String] {
        &self.invalid_pointers
    }

    /// Removes every pointer of this rule from `object`.
    ///
    /// Returns the number of pointers that resolved. A pointer that does not resolve is a
    /// no-op (the trap this module exists to guard), and removing the root pointer clears the
    /// object — both sides are treated identically, so the comparison stays symmetric.
    pub fn remove_from(&self, object: &mut Value) -> usize {
        let mut removed = 0;
        for pointer in &self.pointers {
            if pointer.delete(object).is_some() {
                removed += 1;
            }
        }
        removed
    }
}

/// The compiled `spec.ignoreDifferences` of one `Application`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IgnoreRuleSet {
    rules: Vec<IgnoreRule>,
}

impl IgnoreRuleSet {
    /// Compiles a set of rules.
    #[must_use]
    pub fn new(rules: impl IntoIterator<Item = IgnoreRule>) -> Self {
        Self {
            rules: rules.into_iter().collect(),
        }
    }

    /// Compiles `Application.spec.ignoreDifferences`.
    #[must_use]
    pub fn from_ignore_differences(differences: &[IgnoreDifference]) -> Self {
        Self::new(differences.iter().map(IgnoreRule::from_ignore_difference))
    }

    /// Returns whether no rule is configured (the common case: skip all matching work).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The compiled rules, in `spec.ignoreDifferences` order.
    #[must_use]
    pub fn rules(&self) -> &[IgnoreRule] {
        &self.rules
    }

    /// Every rule matching the given resource identity.
    pub fn matching<'a>(
        &'a self,
        group: &'a str,
        kind: &'a str,
        namespace: Option<&'a str>,
        name: &'a str,
    ) -> impl Iterator<Item = &'a IgnoreRule> + 'a {
        self.rules
            .iter()
            .filter(move |rule| rule.matches(group, kind, namespace, name))
    }

    /// Applies every matching rule to `object`, returning the number of removed pointers.
    pub fn apply(
        &self,
        group: &str,
        kind: &str,
        namespace: Option<&str>,
        name: &str,
        object: &mut Value,
    ) -> usize {
        self.matching(group, kind, namespace, name)
            .map(|rule| rule.remove_from(object))
            .sum()
    }

    /// Every invalid pointer of every rule (never applied, reported for observability).
    pub fn invalid_pointers(&self) -> impl Iterator<Item = &str> {
        self.rules
            .iter()
            .flat_map(|rule| rule.invalid_pointers().iter().map(String::as_str))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn deployment_rules() -> IgnoreRuleSet {
        IgnoreRuleSet::from_ignore_differences(&[IgnoreDifference {
            group: Some("apps".to_owned()),
            kind: "Deployment".to_owned(),
            json_pointers: vec!["/spec/replicas".to_owned()],
            ..IgnoreDifference::default()
        }])
    }

    #[test]
    fn a_matching_rule_removes_nested_object_pointers() {
        let rules = deployment_rules();
        let mut object = json!({
            "metadata": { "name": "api" },
            "spec": { "replicas": 5, "template": { "metadata": { "labels": { "app": "api" } } } },
        });

        assert_eq!(
            rules.apply("apps", "Deployment", Some("payments"), "api", &mut object),
            1
        );
        assert_eq!(
            object,
            json!({
                "metadata": { "name": "api" },
                "spec": { "template": { "metadata": { "labels": { "app": "api" } } } },
            }),
            "only the ignored pointer may be removed"
        );
    }

    #[test]
    fn escaped_json_pointer_tokens_are_resolved() {
        // RFC 6901: `~1` is `/` and `~0` is `~`. A ConfigMap key such as `app/config` or
        // `a~b` must be addressable, which a naive `split('/')` would get wrong.
        let rules = IgnoreRuleSet::new([
            IgnoreRule::new("ConfigMap").with_json_pointer("/data/app~1config"),
            IgnoreRule::new("ConfigMap").with_json_pointer("/data/a~0b"),
        ]);
        let mut object = json!({
            "data": { "app/config": "ignored", "a~b": "ignored", "keep": "kept" },
        });

        assert_eq!(
            rules.apply("", "ConfigMap", Some("payments"), "settings", &mut object),
            2
        );
        assert_eq!(object, json!({ "data": { "keep": "kept" } }));
    }

    #[test]
    fn array_indexes_are_removed_deterministically_from_both_sides() {
        let rules = IgnoreRuleSet::new([IgnoreRule::new("Deployment")
            .with_json_pointer("/spec/template/spec/containers/0/ports/0/nodePort")]);
        let mut object = json!({
            "spec": { "template": { "spec": { "containers": [
                { "name": "api", "ports": [ { "nodePort": 30080 } ] },
            ] } } },
        });

        assert_eq!(
            rules.apply("apps", "Deployment", Some("payments"), "api", &mut object),
            1
        );
        assert_eq!(
            object,
            json!({
                "spec": { "template": { "spec": { "containers": [
                    { "name": "api", "ports": [ {} ] },
                ] } } },
            })
        );
    }

    /// The trap: a pointer that resolves on neither side must be a silent no-op.
    #[test]
    fn missing_pointers_are_never_an_error() {
        let rules = IgnoreRuleSet::new([
            IgnoreRule::new("Deployment").with_json_pointer("/spec/replicas"),
            IgnoreRule::new("Deployment").with_json_pointer("/spec/no/such/field"),
            IgnoreRule::new("Deployment").with_json_pointer("/metadata/annotations/missing"),
        ]);

        let mut empty = json!({});
        assert_eq!(
            rules.apply("apps", "Deployment", Some("payments"), "api", &mut empty),
            0
        );
        assert_eq!(empty, json!({}));

        // A scalar where the pointer expects an object is also a no-op.
        let mut scalar = json!({ "spec": "not-an-object" });
        assert_eq!(
            rules.apply("apps", "Deployment", Some("payments"), "api", &mut scalar),
            0
        );
        assert_eq!(scalar, json!({ "spec": "not-an-object" }));

        // An out-of-range array index is a no-op.
        let mut array = json!({ "spec": { "containers": [] } });
        assert_eq!(
            rules.apply("apps", "Deployment", Some("payments"), "api", &mut array),
            0
        );
        assert_eq!(array, json!({ "spec": { "containers": [] } }));
    }

    #[test]
    fn malformed_pointers_are_recorded_but_never_applied() {
        let rule = IgnoreRule::new("Deployment")
            .with_json_pointer("spec/replicas")
            .with_json_pointer("/spec/replicas");
        assert_eq!(rule.invalid_pointers(), ["spec/replicas".to_owned()]);
        assert_eq!(rule.json_pointers().len(), 1);

        let rules = IgnoreRuleSet::new([rule]);
        assert_eq!(
            rules.invalid_pointers().collect::<Vec<_>>(),
            vec!["spec/replicas"]
        );

        let mut object = json!({ "spec": { "replicas": 5 } });
        assert_eq!(
            rules.apply("apps", "Deployment", Some("payments"), "api", &mut object),
            1
        );
        assert_eq!(object, json!({ "spec": {} }));
    }

    #[test]
    fn rules_match_on_group_kind_name_and_namespace() {
        let any_group = IgnoreRule::new("Deployment").with_json_pointer("/spec/replicas");
        assert!(any_group.matches("apps", "Deployment", Some("payments"), "api"));
        assert!(any_group.matches("extensions", "Deployment", None, "api"));
        assert!(!any_group.matches("apps", "StatefulSet", Some("payments"), "api"));

        let core_group = IgnoreRule::new("Secret")
            .with_group("")
            .with_json_pointer("/data");
        assert!(core_group.matches("", "Secret", Some("payments"), "creds"));
        assert!(
            !core_group.matches("example.com", "Secret", Some("payments"), "creds"),
            "an explicit group must not match another group"
        );

        let scoped = IgnoreRule::new("Deployment")
            .with_name("api")
            .with_namespace("payments")
            .with_json_pointer("/spec/replicas");
        assert!(scoped.matches("apps", "Deployment", Some("payments"), "api"));
        assert!(!scoped.matches("apps", "Deployment", Some("payments"), "web"));
        assert!(!scoped.matches("apps", "Deployment", Some("billing"), "api"));
        assert!(
            !scoped.matches("apps", "Deployment", None, "api"),
            "a namespaced narrower must not match a cluster-scoped key"
        );
    }

    #[test]
    fn multiple_rules_accumulate_and_only_matching_ones_apply() {
        let rules = IgnoreRuleSet::from_ignore_differences(&[
            IgnoreDifference {
                group: Some("apps".to_owned()),
                kind: "Deployment".to_owned(),
                json_pointers: vec!["/spec/replicas".to_owned()],
                ..IgnoreDifference::default()
            },
            IgnoreDifference {
                group: Some("apps".to_owned()),
                kind: "Deployment".to_owned(),
                name: Some("api".to_owned()),
                json_pointers: vec!["/spec/template/spec/containers/0/image".to_owned()],
                ..IgnoreDifference::default()
            },
            IgnoreDifference {
                kind: "Service".to_owned(),
                json_pointers: vec!["/spec/clusterIP".to_owned()],
                ..IgnoreDifference::default()
            },
        ]);

        assert_eq!(
            rules
                .matching("apps", "Deployment", Some("payments"), "api")
                .count(),
            2
        );
        assert_eq!(
            rules
                .matching("apps", "Deployment", Some("payments"), "web")
                .count(),
            1,
            "the name-narrowed rule must not apply to another Deployment"
        );
        assert_eq!(
            rules
                .matching("", "Service", Some("payments"), "api")
                .count(),
            1
        );

        let mut deployment = json!({
            "spec": {
                "replicas": 5,
                "template": { "spec": { "containers": [ { "image": "api:v1" } ] } },
            },
        });
        assert_eq!(
            rules.apply(
                "apps",
                "Deployment",
                Some("payments"),
                "api",
                &mut deployment
            ),
            2
        );
        assert_eq!(
            deployment,
            json!({ "spec": { "template": { "spec": { "containers": [ {} ] } } } })
        );

        let mut other = json!({
            "spec": {
                "replicas": 5,
                "template": { "spec": { "containers": [ { "image": "web:v1" } ] } },
            },
        });
        assert_eq!(
            rules.apply("apps", "Deployment", Some("payments"), "web", &mut other),
            1
        );
        assert_eq!(
            other["spec"]["template"]["spec"]["containers"][0]["image"],
            "web:v1"
        );
    }

    #[test]
    fn an_empty_rule_set_never_touches_the_object() {
        let rules = IgnoreRuleSet::default();
        assert!(rules.is_empty());
        assert_eq!(rules.invalid_pointers().count(), 0);

        let mut object = json!({ "spec": { "replicas": 5 } });
        assert_eq!(
            rules.apply("apps", "Deployment", Some("payments"), "api", &mut object),
            0
        );
        assert_eq!(object, json!({ "spec": { "replicas": 5 } }));
    }

    /// Compilation is deterministic and preserves `spec.ignoreDifferences` order.
    #[test]
    fn compilation_is_order_preserving_and_repeatable() {
        let differences = vec![
            IgnoreDifference {
                kind: "Deployment".to_owned(),
                json_pointers: vec!["/spec/replicas".to_owned(), "/spec/other".to_owned()],
                ..IgnoreDifference::default()
            },
            IgnoreDifference {
                kind: "Service".to_owned(),
                json_pointers: vec!["/spec/clusterIP".to_owned()],
                ..IgnoreDifference::default()
            },
        ];
        let first = IgnoreRuleSet::from_ignore_differences(&differences);
        let second = IgnoreRuleSet::from_ignore_differences(&differences);
        assert_eq!(first, second);
        assert_eq!(
            first
                .rules()
                .iter()
                .map(|rule| rule.json_pointers().len())
                .collect::<Vec<_>>(),
            vec![2, 1]
        );
    }
}
