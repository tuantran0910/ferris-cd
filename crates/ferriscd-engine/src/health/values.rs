//! Total (never-panicking) accessors over a live object's raw JSON payload.
//!
//! A health evaluator reads *whatever the cluster reported*, which is not a typed Kubernetes
//! struct: a `DynamicObject`'s `data` is an arbitrary `serde_json::Value`, and any field can be
//! absent, `null`, or of an unexpected type (a CRD's `status.conditions` written by a
//! third-party controller, a `string` where a number is expected). Every accessor here therefore
//! returns `Option`/a default instead of indexing: a malformed status must degrade the *verdict*
//! to `Progressing`/`Unknown`, never panic a reconcile worker.

use kube::api::DynamicObject;
use serde_json::Value;

/// Returns the value at `path` (a sequence of object keys), or `None` when any segment is absent.
pub(crate) fn field<'a>(object: &'a DynamicObject, path: &[&str]) -> Option<&'a Value> {
    let mut current = &object.data;
    for segment in path {
        current = current.get(*segment)?;
    }
    Some(current)
}

/// Returns the string at `path`, if it is a JSON string.
pub(crate) fn text<'a>(object: &'a DynamicObject, path: &[&str]) -> Option<&'a str> {
    field(object, path).and_then(Value::as_str)
}

/// Returns the integer at `path`, if it is a JSON integer.
///
/// Kubernetes serializes `int32`/`int64` fields as JSON numbers, so `as_i64` is the only
/// conversion needed; a float (which no Kubernetes status field legitimately contains) and a
/// string are both treated as absent rather than silently coerced.
pub(crate) fn int(object: &DynamicObject, path: &[&str]) -> Option<i64> {
    field(object, path).and_then(Value::as_i64)
}

/// Returns the boolean at `path`, if it is a JSON boolean.
pub(crate) fn flag(object: &DynamicObject, path: &[&str]) -> Option<bool> {
    field(object, path).and_then(Value::as_bool)
}

/// Returns a non-negative replica/container count at `path` (`None` when absent or not a number).
///
/// A negative count is impossible in Kubernetes, but clamping keeps a hostile/garbled status from
/// wrapping the `u32` conversion.
pub(crate) fn count_opt(object: &DynamicObject, path: &[&str]) -> Option<u32> {
    int(object, path).map(|value| u32::try_from(value.max(0)).unwrap_or(u32::MAX))
}

/// Returns the count at `path`, defaulting to `0`.
pub(crate) fn count(object: &DynamicObject, path: &[&str]) -> u32 {
    count_opt(object, path).unwrap_or(0)
}

/// Returns the JSON array at `path`, or an empty slice when it is absent or not an array.
pub(crate) fn entries<'a>(object: &'a DynamicObject, path: &[&str]) -> &'a [Value] {
    field(object, path)
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// A borrowed, total view of one `metav1.Condition`.
///
/// Only the fields a health decision needs are extracted; a condition missing `status` yields
/// `""` (which matches neither `True` nor `False` and is therefore treated as "not decided").
#[derive(Clone, Copy, Debug)]
pub(crate) struct ConditionView<'a> {
    /// `condition.type`.
    pub(crate) type_: &'a str,
    /// `condition.status` (`True`/`False`/`Unknown`).
    pub(crate) status: &'a str,
    /// `condition.reason`.
    pub(crate) reason: &'a str,
    /// `condition.message`. Free-form, server-authored: it names things (an image, a config map)
    /// but never contains `Secret` data, because no evaluator ever reads `Secret.data`.
    pub(crate) message: &'a str,
    /// `condition.observedGeneration`, when the controller wrote one.
    pub(crate) observed_generation: Option<i64>,
}

impl ConditionView<'_> {
    /// Returns whether the condition status is `True` (case-insensitive).
    pub(crate) fn is_true(&self) -> bool {
        self.status.eq_ignore_ascii_case("true")
    }

    /// Returns whether the condition status is `False` (case-insensitive).
    pub(crate) fn is_false(&self) -> bool {
        self.status.eq_ignore_ascii_case("false")
    }

    /// `reason` and/or `message`, whichever are present, for a human-readable health message.
    pub(crate) fn describe(&self) -> String {
        match (self.reason.is_empty(), self.message.is_empty()) {
            (false, false) => format!("{}: {}", self.reason, self.message),
            (false, true) => self.reason.to_owned(),
            (true, false) => self.message.to_owned(),
            (true, true) => self.type_.to_owned(),
        }
    }
}

/// Reads `status.conditions`, skipping entries without a `type`.
pub(crate) fn conditions(object: &DynamicObject) -> Vec<ConditionView<'_>> {
    entries(object, &["status", "conditions"])
        .iter()
        .filter_map(|value| {
            Some(ConditionView {
                type_: value.get("type").and_then(Value::as_str)?,
                status: value.get("status").and_then(Value::as_str).unwrap_or(""),
                reason: value.get("reason").and_then(Value::as_str).unwrap_or(""),
                message: value.get("message").and_then(Value::as_str).unwrap_or(""),
                observed_generation: value.get("observedGeneration").and_then(Value::as_i64),
            })
        })
        .collect()
}

/// Finds the condition of the given type (exact match, case-sensitive: Kubernetes condition types
/// are CamelCase identifiers).
pub(crate) fn condition<'v, 'a>(
    conditions: &'v [ConditionView<'a>],
    type_: &str,
) -> Option<&'v ConditionView<'a>> {
    conditions.iter().find(|condition| condition.type_ == type_)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn object(value: Value) -> DynamicObject {
        serde_json::from_value(value).expect("valid DynamicObject")
    }

    #[test]
    fn absent_and_mistyped_fields_are_none_never_a_panic() {
        let deep = object(json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "api" },
            "spec": { "replicas": "three" },
            "status": { "replicas": null, "conditions": "not-an-array" },
        }));

        assert!(field(&deep, &["spec", "replicas"]).is_some());
        assert_eq!(
            int(&deep, &["spec", "replicas"]),
            None,
            "a string is not a number"
        );
        assert_eq!(count(&deep, &["spec", "replicas"]), 0);
        assert_eq!(count(&deep, &["status", "replicas"]), 0);
        assert_eq!(count(&deep, &["status", "missing", "deep"]), 0);
        assert!(entries(&deep, &["status", "conditions"]).is_empty());
        assert!(
            conditions(&deep).is_empty(),
            "a non-array is empty, not an error"
        );
        assert_eq!(
            text(&deep, &["metadata", "name"]),
            None,
            "metadata is not in `data`"
        );
        assert_eq!(flag(&deep, &["spec", "paused"]), None);
    }

    #[test]
    fn negative_counts_clamp_and_conditions_are_total() {
        let negative = object(json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "api" },
            "status": { "replicas": -3 },
        }));
        assert_eq!(count(&negative, &["status", "replicas"]), 0);

        let with_conditions = object(json!({
            "apiVersion": "example.com/v1",
            "kind": "Widget",
            "metadata": { "name": "one" },
            "status": {
                "conditions": [
                    { "type": "Ready", "status": "False", "reason": "Reconciling",
                      "message": "rollout in progress", "observedGeneration": 4 },
                    { "status": "True" },
                ]
            },
        }));
        let parsed = conditions(&with_conditions);
        assert_eq!(parsed.len(), 1, "a condition without `type` is skipped");
        let ready = condition(&parsed, "Ready").expect("Ready condition");
        assert!(ready.is_false());
        assert!(!ready.is_true());
        assert_eq!(ready.observed_generation, Some(4));
        assert_eq!(ready.describe(), "Reconciling: rollout in progress");
        assert!(
            condition(&parsed, "ready").is_none(),
            "types are case-sensitive"
        );

        let bare = ConditionView {
            type_: "Ready",
            status: "True",
            reason: "",
            message: "",
            observed_generation: None,
        };
        assert_eq!(bare.describe(), "Ready");
    }
}
