//! Phase 07 diff engine: SSA dry-run comparison, `ignoreDifferences`, `Secret` redaction, and
//! the sync decision gate.
//!
//! The engine owns every *pure* part of drift detection; the controller owns the single
//! impure part (issuing `Patch::Apply` with `dryRun=All`):
//!
//! ```text
//! controller (T07.1)                       engine (T07.1-T07.4)
//! ------------------                       --------------------
//! LiveStateMap  --classify-->              DiffStatus::Missing / OwnershipConflict
//! Api::patch(dry_run) --predicted-->  +--> compare.rs  (canonicalize, ignore, diff)
//!             409 Conflict --causes-->  +--> FieldConflict
//!                                          redact.rs   (Secret values, trap T4)
//!                                          types.rs    (ResourceDiff, DiffSummary)
//!                                          decision.rs (should_sync, finding H7)
//! ```
//!
//! Everything here is deterministic and I/O-free (no `gix`, no `kube` client, no disk), and
//! exhaustively unit-tested, so a reconcile can be reasoned about without a cluster.
//!
//! # Invariants
//!
//! * **Nothing is mutated.** Live and predicted payloads are cloned before stripping or
//!   pointer removal, so the desired object that gets applied is byte-identical to what Git
//!   rendered.
//! * **A missing JSON Pointer is never an error** — a typo in `ignoreDifferences` must not
//!   break every other resource.
//! * **No `Secret` value leaves this module.** [`ResourceDiff::compare`] redacts `.data`,
//!   `.stringData`, and the `kubectl.kubernetes.io/last-applied-configuration` annotation (which
//!   embeds a whole document, base64 payload included) before comparing, and a [`ResourceDiff`]
//!   can only be assembled by that constructor (its parts are crate-private), so no diff preview,
//!   log line, or API response can carry a raw secret value.
//! * **The whole document is compared.** `metadata.labels`/annotations are drift; only the
//!   documented volatile fields and `.status` are stripped (finding C1).
//! * **Bounded.** At most [`MAX_FIELD_CHANGES`] field changes per resource, and a
//!   [`DiffSummary`] is counts only, so a pathological bundle can never bloat
//!   `Application.status` (trap T9).

pub mod compare;
pub mod decision;
pub mod ignore;
pub mod redact;
pub mod sha256;
pub mod types;

pub use compare::{
    MAX_FIELD_CHANGES, VOLATILE_METADATA_FIELDS, canonicalize, escape_token, strip_volatile,
};
pub use decision::{
    SkipReason, SourceSpecHashError, SyncDecision, SyncTrigger, SyncWindowGate, canonical_json,
    canonical_value, should_sync, source_spec_hash,
};
pub use ignore::{IgnoreRule, IgnoreRuleSet};
pub use redact::{
    FINGERPRINT_HEX_CHARS, LAST_APPLIED_CONFIGURATION_ANNOTATION, REDACTION_PREFIX,
    REDACTION_SUFFIX, fingerprint, is_secret, object_identity, redact_document,
    redact_last_applied_annotation, redact_object, redact_secret, redacted_value,
};
pub use types::{ChangeKind, DiffStatus, DiffSummary, FieldChange, FieldConflict, ResourceDiff};
