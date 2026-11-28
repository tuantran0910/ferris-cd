//! `ferriscd backup export` and `ferriscd backup restore` (`T20.4`).
//!
//! A disaster-recovery bundle is an **input to a restore**, so this module is written around one
//! rule: *the archive must never be able to carry a credential*. Everything else (the versioned
//! manifest, the integrity digest, the dependency ordering, the conflict policy) exists to make a
//! restore safe and boring.
//!
//! # What a bundle contains, and what it deliberately does not
//!
//! | Captured | Why |
//! |---|---|
//! | `AppProject`, `ApplicationSet`, `Application` | The control plane's own declarative state. |
//! | `ConfigMap/ferriscd-rbac-cm`, `ferriscd-notifications-cm`, `ferriscd-policies-cm` | The three control-plane policies that are **not** in Git. |
//! | A [`SecretStub`] per `ferriscd.io/secret-type={repository,cluster,oidc,notifications}` `Secret` **in the control-plane namespace** | Names, namespaces, `ferriscd.io/*` labels and **key names** only. |
//! | Nothing else | — |
//!
//! Raw `Secret` material is **never** exported: the stub records which `Secret` must exist and which
//! keys it must carry, so a restore prompts (or fails) instead of silently reconciling against a
//! cluster that lost its repository and cluster credentials. `ferriscd backup restore` refuses a
//! bundle that contains a `Secret` object at all, because such a file was not produced here and
//! almost certainly holds plaintext credentials.
//!
//! # Why the inventory is scoped to the control-plane namespace
//!
//! The inventory's only job is to name **the credentials a restored control plane will consume**, and
//! every credential type FerrisCD consumes is read from one namespace — the controller's `--namespace`
//! (`ferriscd-system` by default), through a *namespaced* `Api<Secret>`. A namespaced `list` cannot
//! observe another namespace, and the shipped RBAC is a namespaced `Role`, not a `ClusterRole` rule:
//!
//! | `secret-type` | Reader | Why it cannot live anywhere else |
//! |---|---|---|
//! | `repository` | `SecretCredentialStore` (`T12.4`) | a namespaced label-filtered list; a tenant `Secret` is invisible, so a tenant cannot inject a credential |
//! | `cluster` | `ClusterManager` seed + watch (`T13.1`) | a namespaced watch, so one tenant's registration is never another's |
//! | `oidc` | `load_oidc_ca` (`T19.1`, `T19.2`) | one `GET` in the control plane's own namespace |
//! | `notifications` | `SecretChannelSource` (`T19.4`) | a namespaced, label-filtered list of channel `Secret`s |
//!
//! So a `Secret` labelled `ferriscd.io/secret-type=…` in a *tenant* namespace is never a credential
//! FerrisCD consumes: inventorying it would invent a restore dependency the controller does not have,
//! and would copy the names and key shapes of tenant objects into a backup file for no operational
//! gain. [`secret_inventory_namespaces`] therefore returns exactly one namespace whatever
//! `--namespace` says — restoring `team-a`'s `Application`s needs `ferriscd-system`'s credentials, and
//! that is what a bundle for `team-a` records.
//!
//! # Guarantees this module provides (and how they are enforced)
//!
//! * **Versioned manifest.** [`SCHEMA_VERSION`] is written first and checked first; an unknown
//!   version is refused with a message naming what this binary understands.
//! * **Integrity.** [`Integrity::digest`] is a SHA-256 over a *canonical* rendering of the
//!   restorable content (sorted keys, no whitespace), so re-indenting the file is harmless but
//!   editing a value is not. This detects corruption and accidental edits; it is **not** a
//!   signature — anyone who can rewrite the file can recompute it. Encrypt or sign the bundle
//!   out of band (`age`, `cosign`, `git-crypt`) if it travels untrusted.
//! * **Bounded size.** [`MAX_BUNDLE_BYTES`] and [`MAX_BUNDLE_ITEMS`] bound both what export writes
//!   and what restore will read, so a hostile 4 GiB bundle (or a 4 GiB `Secret` kubeconfig) cannot
//!   exhaust memory. The same YAML parser guards the controller's manifests apply (`parse_document`
//!   budgets: duplicate keys, alias bombs, depth, node count).
//! * **Deterministic ordering.** Items are emitted in dependency order (`ConfigMap` →
//!   `AppProject` → `ApplicationSet` → `Application`), then by namespace, then by name, so a
//!   bundle committed to a DR repository produces clean diffs. The one line that cannot be
//!   deterministic on its own is `exportedAt`; `--exported-at` pins it, so re-exporting an unchanged
//!   control plane with the recorded timestamp reproduces the previous bundle byte for byte.
//! * **Self-verifying.** Export renders the bundle and then re-parses the rendered text through
//!   [`parse_bundle`] — the very function `restore` starts with, under the same budgets (duplicate
//!   keys, alias bombs, depth, node count, size, schema version, integrity digest) — and requires it
//!   to round-trip to the same content, so this tool cannot write a file [`parse_bundle`] refuses.
//! * **Idempotent, conflict-visible restore.** Every item is applied with Server-Side Apply and
//!   **`force: false`** under a dedicated field manager, so re-running a restore is a no-op and a
//!   genuine ownership conflict is reported (or skipped on request) instead of silently overwritten.
//!
//! # Deliberate exclusions
//!
//! * **`Application`s generated by an `ApplicationSet`** (they carry
//!   `ferriscd.io/applicationset=<name>`) are exported as a [`ResourceId`] list only, never as
//!   objects. Their `metadata.ownerReferences` points at a *uid* that a restore cannot reproduce;
//!   re-creating them with a stale owner reference would either be treated as foreign by the
//!   `ApplicationSet` controller (`Ready=False`) or be garbage-collected when the owner uid does not
//!   exist. The `ApplicationSet` regenerates the fleet instead, which is the only identity-safe
//!   path. (An `Application` whose generated label *and* owner reference were both removed by hand
//!   is indistinguishable from a hand-written one and is exported normally; its `ApplicationSet`
//!   will then refuse to adopt it — `Ready=False`, never a delete — which is the safe outcome.)
//! * **Objects being deleted** (`metadata.deletionTimestamp` set) are recorded as
//!   [`backup`](self) `skippedTerminating` ids and not exported: a half-deleted object is not DR
//!   material.
//! * **`metadata.ownerReferences` in general**, plus `status`, `resourceVersion`, `uid`,
//!   `creationTimestamp`, `deletionTimestamp`, `managedFields`, `generation`, `selfLink` and the
//!   `kubectl.kubernetes.io/last-applied-configuration` annotation: all server- or client-populated
//!   state that must never be replayed onto a new cluster.
//! * **Only `ferriscd.io/*` labels** are recorded on a secret stub. A user label on a credential
//!   `Secret` can carry anything — including a repository URL with an inline token — and a backup
//!   file is exactly the place that must not collect it.
//! * **`Secret`s FerrisCD never reads through the API** — the chart's `webhooks.existingSecret`, for
//!   example, which Kubernetes mounts into the pod as an environment variable — are not inventoried:
//!   there is no labelled object to verify, so a restore cannot check one. Re-create them with the
//!   chart (RUNBOOK §8.1).
//! * **Encryption.** A bundle is plaintext by design (it carries no secret material), and this
//!   command does not encrypt one. `--encrypt-secrets-with-age <pubkey>` is a future extension: it
//!   would not be needed for confidentiality (no value is ever exported) but for what the inventory
//!   does reveal — the names and key shapes of a cluster's credentials. Until then, encrypt or sign
//!   the file out of band (`age -r <recipient>`, `cosign sign-blob`, `git-crypt`).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail, ensure};
use clap::{Args, Subcommand, ValueEnum};
use k8s_openapi::api::core::v1::{ConfigMap, Namespace, Secret};
use kube::api::{Api, ApiResource, DynamicObject, ListParams, Patch, PatchParams};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use ferriscd_crd::CONTROL_PLANE_NAMESPACE;
use ferriscd_crd::applicationset::APPLICATIONSET_LABEL;

/// Schema of the bundle document this binary writes and reads.
pub const SCHEMA_VERSION: &str = "ferriscd.io/backup/v1";

/// Digest algorithm named in [`Integrity::algorithm`].
pub const DIGEST_ALGORITHM: &str = "sha256";

/// Largest bundle this command will write or read, in bytes.
///
/// A control plane with a thousand `Application`s serializes to a few MiB; anything past this is
/// either a mistake or an attack, and the limit is enforced *before* the YAML parser sees the file.
/// A larger fleet exports per namespace (`--namespace`) into several bundles.
pub const MAX_BUNDLE_BYTES: usize = 8 * 1024 * 1024;

/// Largest number of items (resources **plus** secret stubs) a bundle may carry.
///
/// Also keeps the document under `serde-saphyr`'s default node budget (250_000 nodes), so a
/// legitimate bundle is never rejected *after* it was written by the same tool.
pub const MAX_BUNDLE_ITEMS: usize = 1_000;

/// Label that declares what a `Secret` is for (`ferriscd.io/secret-type=<value>`).
pub const SECRET_TYPE_LABEL: &str = "ferriscd.io/secret-type";

/// Prefix of every label a secret stub records.
const FERRISCD_LABEL_PREFIX: &str = "ferriscd.io/";

/// The `ferriscd.io/secret-type` values whose `Secret`s a restore depends on.
pub const BACKED_UP_SECRET_TYPES: [&str; 4] = ["repository", "cluster", "oidc", "notifications"];

/// Control-plane `ConfigMap`s the bundle captures, in export order.
pub const CONTROL_PLANE_CONFIGMAPS: [&str; 3] = [
    "ferriscd-rbac-cm",
    "ferriscd-notifications-cm",
    "ferriscd-policies-cm",
];

/// Server-Side Apply field manager every restore uses.
///
/// Deliberately **not** `ferriscd` (`ferriscd_engine::default_field_manager()`): the controller
/// never applies its own custom resources, so claiming its manager name would co-mingle ownership
/// with nothing and hide which actor wrote the recovered spec. A distinct manager keeps the
/// restore's ownership visible in `metadata.managedFields` and re-running it is a no-op.
pub const RESTORE_FIELD_MANAGER: &str = "ferriscd-backup";

/// The annotation `kubectl apply` leaves behind: the *previous* object, verbatim.
const LAST_APPLIED_ANNOTATION: &str = "kubectl.kubernetes.io/last-applied-configuration";

/// `metadata` fields that are populated by the API server and must never be replayed.
///
/// `deletionTimestamp` is here as well as being the reason an object is *skipped*: a terminating
/// object is never exported (see [`is_terminating`]), and the strip is what guarantees the field
/// cannot ride along on a hand-written bundle either.
const SERVER_MANAGED_METADATA: [&str; 8] = [
    "resourceVersion",
    "uid",
    "creationTimestamp",
    "deletionTimestamp",
    "managedFields",
    "generation",
    "selfLink",
    "ownerReferences",
];

/// Arguments for `ferriscd backup`.
#[derive(Debug, Args)]
pub struct BackupArgs {
    /// The action.
    #[command(subcommand)]
    pub command: BackupCommand,
}

/// The `ferriscd backup` actions.
#[derive(Debug, Subcommand)]
pub enum BackupCommand {
    /// Export a secret-free disaster-recovery bundle (stdout unless `--output`).
    Export(ExportArgs),
    /// Restore a bundle with Server-Side Apply (`force: false`), in dependency order.
    Restore(RestoreArgs),
}

/// Arguments for `ferriscd backup export`.
#[derive(Debug, Args)]
pub struct ExportArgs {
    /// Write the bundle here instead of stdout (`0600`; the bundle names your credentials).
    #[arg(long = "output", short = 'o', value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Export only the `AppProject`/`ApplicationSet`/`Application` objects of this namespace
    /// (default: every namespace).
    ///
    /// This narrows the *objects*, never the credential inventory: the credentials a restore needs
    /// are the ones the control plane reads, and it reads them only from
    /// `--control-plane-namespace`.
    #[arg(long = "namespace", short = 'n', value_name = "NAMESPACE")]
    pub namespace: Option<String>,

    /// Namespace holding `ferriscd-rbac-cm`, `ferriscd-notifications-cm`,
    /// `ferriscd-policies-cm` **and** the `ferriscd.io/secret-type=*` credential `Secret`s.
    ///
    /// This is the controller's `--namespace`: every credential type FerrisCD consumes (repository,
    /// cluster, oidc, notifications) is read by a namespaced `Api<Secret>` in that one namespace, so
    /// this is also the only namespace the export lists `Secret`s in.
    #[arg(
        long = "control-plane-namespace",
        value_name = "NAMESPACE",
        default_value = CONTROL_PLANE_NAMESPACE
    )]
    pub control_plane_namespace: String,

    /// Do not read the `ferriscd.io/secret-type=*` `Secret`s at all.
    ///
    /// The bundle is then written **without** a secret inventory, so a restore cannot verify that
    /// the credentials exist. Only use this when the exporting identity genuinely may not list
    /// `Secret`s and the credentials are restored out of band.
    #[arg(long = "skip-secret-inventory")]
    pub skip_secret_inventory: bool,

    /// RFC 3339 timestamp to record as `exportedAt` instead of the current time.
    ///
    /// The timestamp is documentation only — it is excluded from the integrity digest and never used
    /// for a decision — but it is a line in the file, so it is what makes two exports of an
    /// unchanged control plane differ. Pass the timestamp of the *previous* export and the two
    /// bundles become byte-identical, which turns "did the control plane change?" into
    /// `git diff --exit-code`.
    #[arg(long = "exported-at", value_name = "RFC3339")]
    pub exported_at: Option<String>,
}

/// Arguments for `ferriscd backup restore`.
#[derive(Debug, Args)]
pub struct RestoreArgs {
    /// The bundle to restore.
    pub bundle: PathBuf,

    /// Validate, pre-flight and dry-run every apply (nothing is written).
    #[arg(long = "dry-run")]
    pub dry_run: bool,

    /// What to do when Server-Side Apply reports a field-ownership conflict (`409`).
    #[arg(long = "on-conflict", value_enum, default_value_t = ConflictPolicy::Abort)]
    pub on_conflict: ConflictPolicy,

    /// Continue when a `ferriscd.io/secret-type=*` `Secret` the bundle expects is absent.
    ///
    /// The affected `Application`s will report `Ready=False` until the credential exists; this flag
    /// exists so a restore can be staged *before* the credentials are copied over.
    #[arg(long = "allow-missing-secrets")]
    pub allow_missing_secrets: bool,
}

/// How a restore treats a Server-Side Apply field-ownership conflict.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum ConflictPolicy {
    /// Fail on the first conflict, naming the object (default: never overwrite another manager).
    #[default]
    Abort,
    /// Report the conflict, skip that object, and carry on with the rest of the bundle.
    Skip,
}

/// One restore action's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// The API server accepted the apply (`--dry-run` included).
    Applied,
    /// A `409` was skipped because `--on-conflict=skip`.
    Skipped,
}

/// Identity of one object inside a bundle (version-agnostic, group/kind/namespace/name shaped).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceId {
    /// Resource kind (`Application`, `AppProject`, `ApplicationSet`, `ConfigMap`).
    pub kind: String,
    /// Namespace, always present for the kinds a bundle may carry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Resource name.
    pub name: String,
}

impl ResourceId {
    /// Renders `<kind>/<namespace>/<name>` (the form every message and log line uses).
    #[must_use]
    pub fn display(&self) -> String {
        format!(
            "{}/{}/{}",
            self.kind,
            self.namespace.as_deref().unwrap_or(""),
            self.name
        )
    }
}

/// One `Secret` a restore depends on — **names, labels and key names only, never values**.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretStub {
    /// Namespace of the `Secret`.
    pub namespace: String,
    /// Name of the `Secret`.
    pub name: String,
    /// The `ferriscd.io/*` labels of the `Secret` (`secret-type` among them).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    /// Sorted names of the `data` keys the `Secret` carried. **Never** their values.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<String>,
}

impl SecretStub {
    /// The `ferriscd.io/secret-type` the stub was exported with, if any.
    #[must_use]
    pub fn secret_type(&self) -> Option<&str> {
        self.labels.get(SECRET_TYPE_LABEL).map(String::as_str)
    }

    /// Renders `<namespace>/<name>` (the form every message uses).
    #[must_use]
    pub fn display(&self) -> String {
        format!("{}/{}", self.namespace, self.name)
    }
}

/// Integrity block of a bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Integrity {
    /// Digest algorithm; only [`DIGEST_ALGORITHM`] is understood.
    pub algorithm: String,
    /// `sha256:<64 hex>` over the canonical rendering of the restorable content.
    pub digest: String,
}

/// The bundle document (`ferriscd.io/backup/v1`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupBundle {
    /// Always [`SCHEMA_VERSION`] for a bundle this binary wrote.
    pub schema_version: String,
    /// RFC 3339 UTC timestamp of the export (documentation only; never used for decisions).
    pub exported_at: String,
    /// `ferriscd/<version>` that produced the bundle.
    pub tool: String,
    /// Namespace the control-plane `ConfigMap`s were read from.
    pub control_plane_namespace: String,
    /// The restorable objects, in dependency order, with every server-managed field stripped.
    #[serde(default)]
    pub resources: Vec<Value>,
    /// The credentials a restore depends on (names/keys only).
    #[serde(default)]
    pub secrets: Vec<SecretStub>,
    /// `Application`s left out because an `ApplicationSet` regenerates them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub generated_applications: Vec<ResourceId>,
    /// Objects left out because they were terminating when the export ran.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped_terminating: Vec<ResourceId>,
    /// Digest of everything above.
    pub integrity: Integrity,
}

/// The kinds a bundle may carry, in **restore order** (the declaration order is the ranking).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RestorableKind {
    /// A control-plane policy `ConfigMap`; everything references it, so it goes first.
    ConfigMap,
    /// `AppProject` before every `Application` that names it.
    AppProject,
    /// `ApplicationSet` before the fleet it regenerates.
    ApplicationSet,
    /// `Application`s last: they are the objects with the most cross-references.
    Application,
}

impl RestorableKind {
    /// Every restorable kind, in dependency order.
    pub const ALL: [Self; 4] = [
        Self::ConfigMap,
        Self::AppProject,
        Self::ApplicationSet,
        Self::Application,
    ];

    /// The Kubernetes `kind`.
    #[must_use]
    pub fn kind(self) -> &'static str {
        match self {
            Self::ConfigMap => "ConfigMap",
            Self::AppProject => "AppProject",
            Self::ApplicationSet => "ApplicationSet",
            Self::Application => "Application",
        }
    }

    /// The dependency rank (lower applies first).
    #[must_use]
    pub fn rank(self) -> u8 {
        match self {
            Self::ConfigMap => 0,
            Self::AppProject => 1,
            Self::ApplicationSet => 2,
            Self::Application => 3,
        }
    }

    /// Resolves a bundle's `kind` to a restorable kind (`None` for anything else).
    #[must_use]
    pub fn from_kind(kind: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.kind() == kind)
    }

    /// The `ApiResource` used to talk to the API server.
    #[must_use]
    pub fn api_resource(self) -> ApiResource {
        match self {
            Self::ConfigMap => ApiResource {
                group: String::new(),
                version: "v1".to_owned(),
                api_version: "v1".to_owned(),
                kind: "ConfigMap".to_owned(),
                plural: "configmaps".to_owned(),
            },
            Self::AppProject => ApiResource {
                group: ferriscd_crd::API_GROUP.to_owned(),
                version: "v1alpha1".to_owned(),
                api_version: format!("{}/v1alpha1", ferriscd_crd::API_GROUP),
                kind: "AppProject".to_owned(),
                plural: "appprojects".to_owned(),
            },
            Self::ApplicationSet => ApiResource {
                group: ferriscd_crd::API_GROUP.to_owned(),
                version: "v1alpha1".to_owned(),
                api_version: format!("{}/v1alpha1", ferriscd_crd::API_GROUP),
                kind: "ApplicationSet".to_owned(),
                plural: "applicationsets".to_owned(),
            },
            Self::Application => ApiResource {
                group: ferriscd_crd::API_GROUP.to_owned(),
                version: "v1alpha1".to_owned(),
                api_version: format!("{}/v1alpha1", ferriscd_crd::API_GROUP),
                kind: "Application".to_owned(),
                plural: "applications".to_owned(),
            },
        }
    }
}

/// One planned Server-Side Apply, in the order the restore will issue them.
#[derive(Debug, Clone, PartialEq)]
pub struct PlannedResource {
    /// The object's identity.
    pub id: ResourceId,
    /// The kind being restored.
    pub kind: RestorableKind,
    /// The object as it will be sent (server-managed fields already stripped).
    pub object: DynamicObject,
}

/// A validated, ordered restore.
#[derive(Debug, Clone, PartialEq)]
pub struct RestorePlan {
    /// Objects to apply, in dependency order.
    pub items: Vec<PlannedResource>,
    /// Credentials the restore expects to already exist.
    pub secrets: Vec<SecretStub>,
    /// `Application`s a restore will not create (their `ApplicationSet` owns them).
    pub generated_applications: Vec<ResourceId>,
}

impl RestorePlan {
    /// The namespaces the plan writes to, sorted and deduplicated.
    #[must_use]
    pub fn namespaces(&self) -> BTreeSet<String> {
        self.items
            .iter()
            .filter_map(|item| item.id.namespace.clone())
            .collect()
    }
}

/// Everything [`build_bundle`] needs; a struct so the pure half can be tested without a cluster.
#[derive(Debug, Clone)]
pub struct ExportInput {
    /// Raw objects as read from the API server.
    pub resources: Vec<Value>,
    /// Credential stubs as read from the API server.
    pub secrets: Vec<SecretStub>,
    /// Namespace the control-plane `ConfigMap`s came from.
    pub control_plane_namespace: String,
    /// RFC 3339 UTC export timestamp.
    pub exported_at: String,
    /// `ferriscd/<version>`.
    pub tool: String,
}

/// Result of the pure secret pre-flight.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SecretVerification {
    /// Stubs whose `Secret` does not exist at all.
    pub missing: Vec<SecretStub>,
    /// Stubs whose live `ferriscd.io/secret-type` differs (or is absent).
    pub type_mismatches: Vec<(SecretStub, Option<String>)>,
    /// Stubs whose live `Secret` is missing some of the expected `data` keys.
    pub missing_keys: Vec<(SecretStub, Vec<String>)>,
}

impl SecretVerification {
    /// Whether the pre-flight found nothing to report.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.missing.is_empty() && self.type_mismatches.is_empty() && self.missing_keys.is_empty()
    }
}

/// Executes `ferriscd backup <subcommand>`.
///
/// # Errors
///
/// Any Kubernetes, filesystem, parse or integrity failure. Messages never contain a `Secret` value.
pub async fn run(args: BackupArgs) -> Result<()> {
    match args.command {
        BackupCommand::Export(args) => export(&args).await,
        BackupCommand::Restore(args) => restore(&args).await,
    }
}

// ---------------------------------------------------------------------------
// export
// ---------------------------------------------------------------------------

/// Reads the control plane and writes one bundle.
async fn export(args: &ExportArgs) -> Result<()> {
    let exported_at = export_timestamp(args.exported_at.as_deref())?;
    let client = kube_client().await?;
    let resources = collect_resources(&client, args).await?;
    let secrets = if args.skip_secret_inventory {
        eprintln!(
            "warning: --skip-secret-inventory: the bundle records no credentials, so a restore \
             cannot verify that the required Secret objects exist"
        );
        Vec::new()
    } else {
        // Deliberately *not* `args.namespace`: `--namespace` scopes objects, and the credentials a
        // restore needs are the ones the control plane reads, which is one namespace (module docs).
        collect_secrets(&client, &args.control_plane_namespace).await?
    };

    let bundle = build_bundle(ExportInput {
        resources,
        secrets,
        control_plane_namespace: args.control_plane_namespace.clone(),
        exported_at,
        tool: concat!("ferriscd/", env!("CARGO_PKG_VERSION")).to_owned(),
    })?;

    // Rendering (and re-parsing) up to 8 MiB of YAML is CPU work: keep it off the async worker,
    // exactly like the controller keeps its YAML parsing off a reconcile worker.
    let (bundle, document) = tokio::task::spawn_blocking(move || render_and_verify(bundle))
        .await
        .map_err(|_| anyhow::anyhow!("the bundle rendering task failed"))??;

    match &args.output {
        Some(path) => {
            let target = path.clone();
            let report = target.display().to_string();
            // Writing (and renaming) the bundle is blocking filesystem work.
            tokio::task::spawn_blocking(move || write_bundle_file(&target, &document))
                .await
                .map_err(|_| anyhow::anyhow!("the bundle write task failed"))??;
            eprintln!("wrote {report}");
        }
        None => print!("{document}"),
    }
    report_export(&bundle);
    Ok(())
}

/// The `exportedAt` value the bundle records: `--exported-at`, normalized, or now.
///
/// Normalizing one RFC 3339 rendering is what lets `--exported-at <the previous value>` reproduce a
/// bundle byte for byte: `2026-01-01T00:00:00+00:00` and `2026-01-01T00:00:00Z` are the same instant
/// and now also the same line.
///
/// # Errors
///
/// A `--exported-at` that is not an RFC 3339 timestamp. The value is echoed (it is an operator
/// argument, never bundle content).
fn export_timestamp(explicit: Option<&str>) -> Result<String> {
    match explicit {
        Some(text) => {
            let timestamp: jiff::Timestamp = text.parse().map_err(|error| {
                anyhow::anyhow!("--exported-at '{text}' is not an RFC 3339 timestamp: {error}")
            })?;
            Ok(timestamp.to_string())
        }
        None => Ok(jiff::Timestamp::now().to_string()),
    }
}

/// Renders a bundle, then proves the rendered text is a bundle [`parse_bundle`] accepts back.
///
/// Export is the only writer of the format, so it must not be able to produce a document
/// [`parse_bundle`] — the exact function `restore` starts with — refuses. The byte ceiling and the
/// item ceiling are checked while the bundle is built, but the *rendered* form is the thing that gets
/// written, so it is re-parsed here under the same budgets a restore uses (`parse_document`:
/// duplicate keys, alias bombs, depth, node count), through the same schema-version, algorithm,
/// size and integrity-digest checks, and the re-parsed bundle must equal the one that was rendered. A
/// lossy render (a float that comes back as a string, a key that collapses) therefore fails here
/// instead of at 3 a.m. during a recovery.
///
/// # Errors
///
/// A render failure, a document past [`MAX_BUNDLE_BYTES`], or a document that does not verify and
/// round-trip identically.
fn render_and_verify(bundle: BackupBundle) -> Result<(BackupBundle, String)> {
    let document =
        serde_saphyr::to_string(&bundle).context("the bundle could not be rendered as YAML")?;
    ensure!(
        document.len() <= MAX_BUNDLE_BYTES,
        "the bundle would be {} bytes, larger than the {MAX_BUNDLE_BYTES} byte limit: export one \
         namespace at a time with --namespace",
        document.len()
    );
    let re_parsed = parse_bundle(&document).map_err(|error| {
        anyhow::anyhow!("the rendered bundle does not verify, so it was not written: {error}")
    })?;
    ensure!(
        re_parsed == bundle,
        "the rendered bundle does not round-trip to the same content, so it was not written: this \
         is a defect in the bundle renderer (the restore would see a different control plane than \
         the one that was exported)"
    );
    Ok((bundle, document))
}

/// Prints the export summary (to stderr, so a bundle on stdout stays a clean YAML document).
fn report_export(bundle: &BackupBundle) {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for resource in &bundle.resources {
        if let Some(kind) = resource.get("kind").and_then(Value::as_str) {
            *counts.entry(kind).or_default() += 1;
        }
    }
    let summary = RestorableKind::ALL
        .iter()
        .map(|kind| {
            format!(
                "{}={}",
                kind.kind(),
                counts.get(kind.kind()).copied().unwrap_or(0)
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    eprintln!(
        "exported {} resource(s) ({summary}) and {} secret stub(s) [{}]",
        bundle.resources.len(),
        bundle.secrets.len(),
        bundle.integrity.digest,
    );
    if !bundle.generated_applications.is_empty() {
        eprintln!(
            "note: {} Application(s) are generated by an ApplicationSet and were not exported \
             (the ApplicationSet regenerates them on restore)",
            bundle.generated_applications.len()
        );
    }
    if !bundle.skipped_terminating.is_empty() {
        eprintln!(
            "warning: {} object(s) were terminating and were not exported",
            bundle.skipped_terminating.len()
        );
    }
}

/// Reads the three control-plane `ConfigMap`s and every FerrisCD custom resource.
async fn collect_resources(client: &kube::Client, args: &ExportArgs) -> Result<Vec<Value>> {
    let mut resources = Vec::new();

    let configmaps = Api::<ConfigMap>::namespaced(client.clone(), &args.control_plane_namespace);
    for name in CONTROL_PLANE_CONFIGMAPS {
        let found = configmaps.get_opt(name).await.with_context(|| {
            format!(
                "failed to read ConfigMap/{}/{}",
                args.control_plane_namespace, name
            )
        })?;
        match found {
            Some(config_map) => resources.push(
                serde_json::to_value(&config_map).context("a ConfigMap could not be serialized")?,
            ),
            None => eprintln!(
                "note: ConfigMap/{}/{} does not exist; nothing to export",
                args.control_plane_namespace, name
            ),
        }
    }

    for kind in [
        RestorableKind::AppProject,
        RestorableKind::ApplicationSet,
        RestorableKind::Application,
    ] {
        let api = scoped_dynamic_api(client, args.namespace.as_deref(), kind);
        let list = api.list(&ListParams::default()).await.with_context(|| {
            format!(
                "failed to list {} in {}",
                kind.kind(),
                args.namespace.as_deref().unwrap_or("every namespace")
            )
        })?;
        for object in list.items {
            resources.push(
                serde_json::to_value(&object)
                    .context("a custom resource could not be serialized")?,
            );
        }
    }

    Ok(resources)
}

/// The namespaces whose credential `Secret`s an export inventories: **exactly one**.
///
/// `--namespace` narrows which `AppProject`/`ApplicationSet`/`Application` objects are exported and
/// deliberately does *not* widen this. FerrisCD reads every credential type it consumes — repository
/// (`T12.4`), cluster (`T13.1`), oidc (`T19.1`) and notifications (`T19.4`) — through a namespaced
/// `Api<Secret>` in the control-plane namespace (see the module docs), so that is the only namespace
/// whose labelled `Secret`s a restored control plane can depend on, and the only one a restore can
/// meaningfully verify.
///
/// A labelled `Secret` in a tenant namespace is therefore **not** inventoried, on purpose: it is not a
/// credential FerrisCD consumes, so recording it would invent a restore dependency that does not
/// exist and copy a tenant object's name and key shape into the bundle for nothing. Even a
/// per-namespace export of `team-a` records `ferriscd-system`'s credentials, because those are what
/// `team-a`'s `Application`s authenticate with.
///
/// Returned as a list (rather than having the caller reach for the string) so "exactly one namespace,
/// whatever `--namespace` says" is a pure, testable statement.
#[must_use]
pub fn secret_inventory_namespaces(control_plane_namespace: &str) -> Vec<String> {
    vec![control_plane_namespace.to_owned()]
}

/// Reads the credential `Secret`s (names, labels and key names only — never values).
async fn collect_secrets(
    client: &kube::Client,
    control_plane_namespace: &str,
) -> Result<Vec<SecretStub>> {
    let mut stubs = Vec::new();
    for namespace in secret_inventory_namespaces(control_plane_namespace) {
        // `Api::namespaced` is the whole trap guard: the request path is
        // `/api/v1/namespaces/<control-plane>/secrets`, so no code path here can grow into the
        // cluster-wide `Secret` read the controller itself is forbidden from making.
        let api = Api::<Secret>::namespaced(client.clone(), &namespace);
        let list = api
            .list(&ListParams::default().labels(SECRET_TYPE_LABEL))
            .await
            .map_err(|error| match &error {
                kube::Error::Api(status) if status.is_forbidden() => anyhow::anyhow!(
                    "the cluster refused to list Secret objects labelled {SECRET_TYPE_LABEL} in \
                     namespace '{namespace}', so the bundle would carry no secret inventory: grant \
                     `list` on secrets in that namespace (the inventory records names and key names \
                     only), or pass --skip-secret-inventory if the credentials are restored out of \
                     band"
                ),
                _ => anyhow::anyhow!(
                    "failed to list the credential Secret objects in namespace '{namespace}': \
                     {error}"
                ),
            })?;
        stubs.extend(list.items.iter().filter_map(secret_stub));
    }
    stubs.sort();
    stubs.dedup();
    Ok(stubs)
}

// ---------------------------------------------------------------------------
// pure export half
// ---------------------------------------------------------------------------

/// Builds a bundle from raw objects: strips live fields, orders, bounds and digests it.
///
/// # Errors
///
/// A malformed object (no `kind`/`apiVersion`/`metadata.name`), an object of an unsupported kind, or
/// a bundle that exceeds [`MAX_BUNDLE_ITEMS`].
pub fn build_bundle(input: ExportInput) -> Result<BackupBundle> {
    let mut resources = Vec::with_capacity(input.resources.len());
    let mut generated_applications = Vec::new();
    let mut skipped_terminating = Vec::new();

    for raw in input.resources {
        let id = resource_identity(&raw)?;
        let kind = RestorableKind::from_kind(&id.kind).ok_or_else(|| {
            anyhow::anyhow!(
                "refusing to export {}/{}: a bundle may only carry ConfigMap, AppProject, \
                 ApplicationSet and Application",
                id.kind,
                id.name
            )
        })?;
        if is_terminating(&raw) {
            skipped_terminating.push(id);
            continue;
        }
        if kind == RestorableKind::Application && is_generated_application(&raw) {
            generated_applications.push(id);
            continue;
        }
        let mut value = raw;
        strip_server_managed_fields(&mut value)?;
        resources.push((kind, id, value));
    }

    resources.sort_by(|(left_kind, left_id, _), (right_kind, right_id, _)| {
        left_kind
            .rank()
            .cmp(&right_kind.rank())
            // `None` (a cluster-scoped object) sorts before any namespace, deterministically.
            .then_with(|| left_id.namespace.cmp(&right_id.namespace))
            .then_with(|| left_id.name.cmp(&right_id.name))
    });
    generated_applications.sort();
    skipped_terminating.sort();

    let mut secrets = input.secrets;
    secrets.sort();
    secrets.dedup();

    ensure!(
        resources.len() + secrets.len() <= MAX_BUNDLE_ITEMS,
        "the bundle would carry {} item(s), more than the {MAX_BUNDLE_ITEMS} item limit: export one \
         namespace at a time with --namespace",
        resources.len() + secrets.len()
    );

    let mut bundle = BackupBundle {
        schema_version: SCHEMA_VERSION.to_owned(),
        exported_at: input.exported_at,
        tool: input.tool,
        control_plane_namespace: input.control_plane_namespace,
        resources: resources.into_iter().map(|(_, _, value)| value).collect(),
        secrets,
        generated_applications,
        skipped_terminating,
        integrity: Integrity {
            algorithm: DIGEST_ALGORITHM.to_owned(),
            digest: String::new(),
        },
    };
    bundle.integrity.digest = bundle_digest(&bundle)?;
    Ok(bundle)
}

/// Reads the identity of a raw object.
fn resource_identity(value: &Value) -> Result<ResourceId> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("the API server returned an object that is not a map"))?;
    require_non_empty_str(object, "apiVersion")?;
    let kind = require_non_empty_str(object, "kind")?.to_owned();
    let metadata = object
        .get("metadata")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            // The `kind` of a bundle item is untrusted text until [`plan_restore`] has checked it, so
            // it is only echoed when it is a plain token.
            anyhow::anyhow!("a {} object has no metadata", quoted_identifier(&kind))
        })?;
    let name = require_non_empty_str(metadata, "name")?.to_owned();
    let namespace = metadata
        .get("namespace")
        .and_then(Value::as_str)
        .filter(|namespace| !namespace.is_empty())
        .map(str::to_owned);
    Ok(ResourceId {
        kind,
        namespace,
        name,
    })
}

/// Returns `map[key]` as a non-empty string, or a bounded error.
fn require_non_empty_str<'a>(map: &'a Map<String, Value>, key: &str) -> Result<&'a str> {
    map.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("an exported object has no non-empty `{key}`"))
}

/// Whether the object is being deleted.
fn is_terminating(value: &Value) -> bool {
    value
        .get("metadata")
        .and_then(|metadata| metadata.get("deletionTimestamp"))
        .is_some_and(|timestamp| !timestamp.is_null())
}

/// Whether an `Application` is owned by an `ApplicationSet` (label or owner reference).
fn is_generated_application(value: &Value) -> bool {
    let carries_label = value
        .get("metadata")
        .and_then(|metadata| metadata.get("labels"))
        .and_then(Value::as_object)
        .and_then(|labels| labels.get(APPLICATIONSET_LABEL))
        .and_then(Value::as_str)
        .is_some_and(|name| !name.is_empty());
    let names_an_application_set = value
        .get("metadata")
        .and_then(|metadata| metadata.get("ownerReferences"))
        .and_then(Value::as_array)
        .is_some_and(|references| {
            references.iter().any(|reference| {
                reference
                    .get("kind")
                    .and_then(Value::as_str)
                    .is_some_and(|kind| kind == "ApplicationSet")
            })
        });
    carries_label || names_an_application_set
}

/// Removes every field the API server (or a client-side apply) populated.
fn strip_server_managed_fields(value: &mut Value) -> Result<()> {
    let object = value
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("an exported object is not a map"))?;
    object.remove("status");
    let metadata = object
        .get_mut("metadata")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| anyhow::anyhow!("an exported object has no metadata"))?;
    for key in SERVER_MANAGED_METADATA {
        metadata.remove(key);
    }
    if let Some(annotations) = metadata
        .get_mut("annotations")
        .and_then(Value::as_object_mut)
    {
        annotations.remove(LAST_APPLIED_ANNOTATION);
        // An empty annotation map is dropped so two equivalent objects cannot render differently.
        let is_empty = annotations.is_empty();
        if is_empty {
            metadata.remove("annotations");
        }
    }
    Ok(())
}

/// Builds a stub for one `Secret`: labels are filtered and **values are never read**.
///
/// Returns `None` when the `Secret` is not one of [`BACKED_UP_SECRET_TYPES`].
#[must_use]
pub fn secret_stub(secret: &Secret) -> Option<SecretStub> {
    let stub = observed_stub(secret);
    let is_tracked = stub
        .secret_type()
        .is_some_and(|secret_type| BACKED_UP_SECRET_TYPES.contains(&secret_type));
    if is_tracked { Some(stub) } else { None }
}

/// Builds a stub from a live `Secret` **whatever its type** (used by the restore pre-flight).
///
/// Only `ferriscd.io/*` labels are copied, and only the *names* of the `data` keys: the values are
/// not read into any owned buffer, so they cannot reach an error message, a log line or the bundle.
#[must_use]
pub fn observed_stub(secret: &Secret) -> SecretStub {
    let name = secret.metadata.name.clone().unwrap_or_default();
    let namespace = secret.metadata.namespace.clone().unwrap_or_default();
    let labels = secret
        .metadata
        .labels
        .iter()
        .flatten()
        .filter(|(key, _)| key.starts_with(FERRISCD_LABEL_PREFIX))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut keys = secret
        .data
        .iter()
        .flatten()
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();
    keys.sort();
    SecretStub {
        namespace,
        name,
        labels,
        keys,
    }
}

// ---------------------------------------------------------------------------
// integrity
// ---------------------------------------------------------------------------

/// Renders `value` as canonical JSON: object keys sorted, no whitespace, stable numbers.
#[must_use]
pub fn canonical_json(value: &Value) -> String {
    let mut rendered = String::new();
    write_canonical(value, &mut rendered);
    rendered
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        Value::Number(number) => out.push_str(&number.to_string()),
        Value::String(text) => push_json_string(text, out),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys = map.keys().collect::<Vec<_>>();
            keys.sort();
            out.push('{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                push_json_string(key, out);
                out.push(':');
                if let Some(item) = map.get(key) {
                    write_canonical(item, out);
                }
            }
            out.push('}');
        }
    }
}

fn push_json_string(text: &str, out: &mut String) {
    match serde_json::to_string(text) {
        Ok(escaped) => out.push_str(&escaped),
        // Unreachable (serializing a `&str` cannot fail); an empty string keeps the digest
        // deterministic rather than panicking in a runtime binary.
        Err(_) => out.push_str("\"\""),
    }
}

/// The restorable content of a bundle, as the digest sees it.
///
/// The export metadata (`exportedAt`, `tool`, `controlPlaneNamespace`) is deliberately **not**
/// covered: re-exporting an unchanged control plane produces the same digest, which is what makes a
/// bundle diffable in a DR repository.
fn digest_payload(bundle: &BackupBundle) -> Value {
    serde_json::json!({
        "resources": bundle.resources,
        "secrets": bundle.secrets,
        "generatedApplications": bundle.generated_applications,
        "skippedTerminating": bundle.skipped_terminating,
    })
}

/// `sha256:<64 hex>` over the canonical rendering of the bundle's restorable content.
///
/// # Errors
///
/// Only an impossible serialization failure.
pub fn bundle_digest(bundle: &BackupBundle) -> Result<String> {
    Ok(format!(
        "{DIGEST_ALGORITHM}:{}",
        ferriscd_engine::manifest::cache::sha256_hex(
            canonical_json(&digest_payload(bundle)).as_bytes()
        )
    ))
}

// ---------------------------------------------------------------------------
// restore
// ---------------------------------------------------------------------------

/// Reads, validates and applies one bundle.
///
/// The apply loop is **not** a transaction: Server-Side Apply is per object. A conflict under
/// `--on-conflict=abort` therefore leaves the objects applied before it in place, which is safe
/// because a re-run re-applies them as an idempotent no-op once the conflict has been resolved.
async fn restore(args: &RestoreArgs) -> Result<()> {
    let text = read_bundle(&args.bundle).await?;
    // Validating an 8 MiB YAML document is CPU work: keep it off the async worker, exactly like the
    // controller keeps its YAML parsing off a reconcile worker.
    let plan = tokio::task::spawn_blocking(move || -> Result<RestorePlan> {
        let bundle = parse_bundle(&text)?;
        plan_restore(&bundle)
    })
    .await
    .map_err(|_| anyhow::anyhow!("the bundle validation task failed"))??;

    let client = kube_client().await?;
    preflight(&client, &plan, args).await?;

    let mut applied = 0usize;
    let mut skipped = Vec::new();
    for item in &plan.items {
        let outcome = apply_item(&client, item, args.dry_run, args.on_conflict).await?;
        match outcome {
            ApplyOutcome::Applied => {
                applied += 1;
                if args.dry_run {
                    println!("would apply (dry run): {}", item.id.display());
                } else {
                    println!("applied: {}", item.id.display());
                }
            }
            ApplyOutcome::Skipped => {
                eprintln!(
                    "skipped (field-ownership conflict, --on-conflict=skip): {}",
                    item.id.display()
                );
                skipped.push(item.id.display());
            }
        }
    }

    println!("{}", restore_summary(args, &plan, applied, skipped.len()));
    if !plan.generated_applications.is_empty() {
        // Silence here would read as "everything came back": these Applications are deliberately *not*
        // created, because their `ApplicationSet` regenerates them (a re-created object would carry an
        // owner reference to a uid a restore cannot reproduce).
        eprintln!(
            "note: {} Application(s) are not restored because an ApplicationSet regenerates them \
             (the bundle lists them under generatedApplications)",
            plan.generated_applications.len()
        );
    }
    Ok(())
}

/// The one-line restore summary.
///
/// Pure, so the wording — including the two counts a restore must never leave implicit, the number of
/// credential stubs it checked and the number of `Application`s it deliberately did not create — is
/// testable without a cluster.
fn restore_summary(
    args: &RestoreArgs,
    plan: &RestorePlan,
    applied: usize,
    skipped: usize,
) -> String {
    let verb = if args.dry_run {
        "would restore"
    } else {
        "restored"
    };
    format!(
        "{verb} {applied} resource(s) from {} ({skipped} skipped by --on-conflict=skip); {} \
         credential stub(s) checked; {} Application(s) left to their ApplicationSet",
        args.bundle.display(),
        plan.secrets.len(),
        plan.generated_applications.len(),
    )
}

/// The SSA parameters of one restore: `force: false` always, `dryRun=All` on request.
#[must_use]
pub fn restore_patch_params(dry_run: bool) -> PatchParams {
    let params = PatchParams::apply(RESTORE_FIELD_MANAGER);
    if dry_run { params.dry_run() } else { params }
}

/// Applies one planned object, mapping a `409` onto the conflict policy.
async fn apply_item(
    client: &kube::Client,
    item: &PlannedResource,
    dry_run: bool,
    on_conflict: ConflictPolicy,
) -> Result<ApplyOutcome> {
    let namespace = item
        .id
        .namespace
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("{} has no namespace", item.id.display()))?;
    let api =
        Api::<DynamicObject>::namespaced_with(client.clone(), namespace, &item.kind.api_resource());
    match api
        .patch(
            &item.id.name,
            &restore_patch_params(dry_run),
            &Patch::Apply(&item.object),
        )
        .await
    {
        Ok(_) => Ok(ApplyOutcome::Applied),
        Err(kube::Error::Api(status)) if status.is_conflict() => match on_conflict {
            ConflictPolicy::Abort => bail!(
                "server-side apply of {} was refused by a field-ownership conflict (409): another \
                 manager owns fields in this object. Re-run with --on-conflict=skip to restore the \
                 rest, or remove the object first (`kubectl delete`), or restore into a clean \
                 namespace. Nothing was forced.",
                item.id.display()
            ),
            ConflictPolicy::Skip => Ok(ApplyOutcome::Skipped),
        },
        Err(error) => Err(anyhow::anyhow!(
            "failed to apply {}: {error}",
            item.id.display()
        )),
    }
}

/// Checks the bundle's version, algorithm, integrity and size. Never quotes the document.
///
/// # Errors
///
/// A YAML/parse failure (reported by [`ferriscd_engine::manifest::YamlGuardError`], which quotes
/// nothing), an unsupported schema version or algorithm, an integrity mismatch, or a size breach.
pub fn parse_bundle(text: &str) -> Result<BackupBundle> {
    ensure!(
        text.len() <= MAX_BUNDLE_BYTES,
        "the bundle is {} bytes, larger than the {MAX_BUNDLE_BYTES} byte limit",
        text.len()
    );
    let bundle: BackupBundle =
        ferriscd_engine::manifest::parse_document(text).map_err(|error| {
            anyhow::anyhow!("the bundle is not a readable FerrisCD backup: {error}")
        })?;
    ensure!(
        bundle.schema_version == SCHEMA_VERSION,
        "unsupported bundle schema '{}': this ferriscd understands '{SCHEMA_VERSION}'",
        bundle.schema_version
    );
    ensure!(
        bundle.integrity.algorithm == DIGEST_ALGORITHM,
        "unsupported integrity algorithm '{}': only '{DIGEST_ALGORITHM}' is understood",
        bundle.integrity.algorithm
    );
    let expected = bundle_digest(&bundle)?;
    ensure!(
        expected == bundle.integrity.digest,
        "bundle integrity check failed: `integrity.digest` does not match the bundle's content, so \
         the file was modified or truncated after it was exported"
    );
    ensure!(
        bundle.resources.len() + bundle.secrets.len() <= MAX_BUNDLE_ITEMS,
        "the bundle carries {} item(s), more than the {MAX_BUNDLE_ITEMS} item limit",
        bundle.resources.len() + bundle.secrets.len()
    );
    Ok(bundle)
}

/// Validates the bundle's objects and returns them in dependency order.
///
/// # Errors
///
/// A name or namespace that is not a DNS-1123 name, a raw `Secret` (never produced by export), an
/// unknown kind, a missing namespace, an object that cannot be turned into a `DynamicObject`.
pub fn plan_restore(bundle: &BackupBundle) -> Result<RestorePlan> {
    let mut items = Vec::with_capacity(bundle.resources.len());
    for (index, raw) in bundle.resources.iter().enumerate() {
        let id = resource_identity(raw)?;
        // A bundle is untrusted input even though this binary is its only writer: a restore reads a
        // file an operator copied around, and `metadata.name`/`metadata.namespace` become a request
        // path (`/api/v1/namespaces/<ns>/.../<name>`) and a log line. So the identity is validated
        // *before* it can reach either — a refusal names the item's position and kind, never the
        // offending string, which is the value most likely to carry `..`, `/` or a control character.
        ensure!(
            is_dns_1123_subdomain(&id.name),
            "refusing to restore bundle item #{index} (kind {}): its metadata.name is not a valid \
             DNS-1123 subdomain, so it would build an invalid API request path",
            quoted_identifier(&id.kind)
        );
        let namespace = id.namespace.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "{} has no metadata.namespace; a restore refuses it",
                id.display()
            )
        })?;
        ensure!(
            is_dns_1123_label(&namespace),
            "refusing to restore bundle item #{index} (kind {}, name {}): its metadata.namespace is \
             not a valid DNS-1123 label, so it would build an invalid API request path",
            quoted_identifier(&id.kind),
            id.name
        );
        ensure!(
            id.kind != "Secret",
            "refusing to restore Secret/{namespace}/{}: a bundle never carries raw secret material, \
             so this file was not produced by `ferriscd backup export`",
            id.name
        );
        let kind = RestorableKind::from_kind(&id.kind).ok_or_else(|| {
            anyhow::anyhow!(
                "refusing to restore {}/{namespace}/{}: a bundle may only carry ConfigMap, \
                 AppProject, ApplicationSet and Application",
                quoted_identifier(&id.kind),
                id.name
            )
        })?;
        let mut value = raw.clone();
        strip_server_managed_fields(&mut value)?;
        let object: DynamicObject = serde_json::from_value(value)
            .with_context(|| format!("{} is not a valid Kubernetes object", id.display()))?;
        items.push(PlannedResource {
            id: ResourceId {
                namespace: Some(namespace),
                ..id
            },
            kind,
            object,
        });
    }

    // The pre-flight builds one request path per stub (`GET /api/v1/namespaces/<ns>/secrets/<name>`),
    // so a hand-edited inventory must not be able to steer that read either.
    for (index, stub) in bundle.secrets.iter().enumerate() {
        ensure!(
            is_dns_1123_label(&stub.namespace) && is_dns_1123_subdomain(&stub.name),
            "refusing to restore credential stub #{index}: its namespace/name is not a valid \
             DNS-1123 name, so the pre-flight would build an invalid API request path"
        );
    }

    items.sort_by(|left, right| {
        left.kind
            .rank()
            .cmp(&right.kind.rank())
            .then_with(|| left.id.namespace.cmp(&right.id.namespace))
            .then_with(|| left.id.name.cmp(&right.id.name))
    });

    Ok(RestorePlan {
        items,
        secrets: bundle.secrets.clone(),
        generated_applications: bundle.generated_applications.clone(),
    })
}

/// Longest DNS-1123 subdomain: the ceiling on a Kubernetes object name.
const MAX_DNS_1123_SUBDOMAIN: usize = 253;

/// Longest DNS-1123 label: the ceiling on a Kubernetes namespace.
const MAX_DNS_1123_LABEL: usize = 63;

/// Whether `text` is a DNS-1123 label (`[a-z0-9]([-a-z0-9]*[a-z0-9])?`, at most 63 characters).
///
/// This is the shape the API server requires of a namespace, and the rule the restore needs before a
/// namespace becomes a URL path segment. Written out rather than pulled from a crate: it is eight
/// lines, it has no policy of its own, and a restore must not acquire a dependency to validate input.
#[must_use]
pub fn is_dns_1123_label(text: &str) -> bool {
    if text.is_empty() || text.len() > MAX_DNS_1123_LABEL {
        return false;
    }
    let bytes = text.as_bytes();
    let alphanumeric = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    // First and last must be alphanumeric (that is what forbids a leading/trailing `-`), the middle
    // may also carry `-`.
    alphanumeric(bytes[0])
        && alphanumeric(bytes[bytes.len() - 1])
        && bytes
            .iter()
            .all(|byte| alphanumeric(*byte) || *byte == b'-')
}

/// Whether `text` is a DNS-1123 subdomain: dot-separated labels, at most 253 characters.
///
/// The shape the API server requires of an object name. Dots are allowed, `..` (an empty label), `/`,
/// whitespace and uppercase are not — which is what keeps a bundle-supplied name from being read as
/// a path.
#[must_use]
pub fn is_dns_1123_subdomain(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_DNS_1123_SUBDOMAIN
        && text.split('.').all(is_dns_1123_label)
}

/// Renders an untrusted identifier for an error message, or `<malformed>` when it is not a token.
///
/// Bundle-supplied text reaches a message before it is validated (and a refusal has to say *what* it
/// refused), so anything that is not a short ASCII alphanumeric token — a newline, a path, an ANSI
/// escape — is replaced instead of echoed.
fn quoted_identifier(value: &str) -> &str {
    if !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        value
    } else {
        "<malformed>"
    }
}

/// Lists the plan's namespaces that do not exist yet.
#[must_use]
pub fn missing_namespaces(
    plan_namespaces: &BTreeSet<String>,
    existing: &BTreeSet<String>,
) -> Vec<String> {
    plan_namespaces
        .difference(existing)
        .cloned()
        .collect::<Vec<_>>()
}

/// Compares the bundle's expected credentials against what the cluster actually has.
///
/// The comparison is on **identity and shape only** (name, `ferriscd.io/secret-type`, `data` key
/// names): no value is ever read, so nothing secret can reach a message.
#[must_use]
pub fn verify_secrets(expected: &[SecretStub], observed: &[SecretStub]) -> SecretVerification {
    let mut verification = SecretVerification::default();
    for stub in expected {
        let Some(live) = observed
            .iter()
            .find(|candidate| candidate.namespace == stub.namespace && candidate.name == stub.name)
        else {
            verification.missing.push(stub.clone());
            continue;
        };
        if live.secret_type() != stub.secret_type() {
            verification
                .type_mismatches
                .push((stub.clone(), live.secret_type().map(str::to_owned)));
        }
        let missing = stub
            .keys
            .iter()
            .filter(|key| !live.keys.contains(key))
            .cloned()
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            verification.missing_keys.push((stub.clone(), missing));
        }
    }
    verification
}

/// Runs every read-only check a restore needs before it mutates anything.
async fn preflight(client: &kube::Client, plan: &RestorePlan, args: &RestoreArgs) -> Result<()> {
    let required = plan.namespaces();
    let namespaces = Api::<Namespace>::all(client.clone());
    let mut existing = BTreeSet::new();
    for namespace in &required {
        let found = namespaces
            .get_opt(namespace)
            .await
            .with_context(|| format!("failed to read Namespace/{namespace}"))?;
        if found.is_some() {
            existing.insert(namespace.clone());
        }
    }
    let missing = missing_namespaces(&required, &existing);
    ensure!(
        missing.is_empty(),
        "these namespaces are in the bundle but do not exist, so nothing was applied: {}. Create \
         them first (`kubectl create namespace <name>`) and re-run.",
        missing.join(", ")
    );

    if plan.secrets.is_empty() {
        return Ok(());
    }

    // One `GET` per stub rather than a `list` per namespace: the minimal grant a restore needs on
    // credentials is `get`, and the pre-flights then cannot be satisfied by an object it is not
    // actually allowed to read.
    let mut observed = Vec::new();
    let mut unverifiable = Vec::new();
    for stub in &plan.secrets {
        let api = Api::<Secret>::namespaced(client.clone(), &stub.namespace);
        match api.get_opt(&stub.name).await {
            Ok(Some(secret)) => observed.push(observed_stub(&secret)),
            Ok(None) => {}
            // A backup operator that may restore a control plane but not read credentials is a
            // legitimate deployment: report it and continue rather than failing the DR.
            Err(kube::Error::Api(status)) if status.is_forbidden() => {
                unverifiable.push(stub.display());
            }
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "failed to read Secret/{}: {error}",
                    stub.display()
                ));
            }
        }
    }
    if !unverifiable.is_empty() {
        eprintln!(
            "warning: could not verify {} credential Secret(s) (the cluster refused the read): {}",
            unverifiable.len(),
            unverifiable.join(", ")
        );
    }

    let verification = verify_secrets(&plan.secrets, &observed);
    if verification.is_clean() {
        return Ok(());
    }
    if !verification.missing.is_empty() {
        let names = verification
            .missing
            .iter()
            .map(SecretStub::display)
            .collect::<Vec<_>>()
            .join(", ");
        if !args.allow_missing_secrets {
            bail!(
                "the bundle expects {} credential Secret(s) that do not exist: {names}. Recreate \
                 them (the bundle records their `{}` value and data key names, never their values), \
                 or pass --allow-missing-secrets to stage the restore before the credentials are \
                 copied over.",
                verification.missing.len(),
                SECRET_TYPE_LABEL,
            );
        }
        // `--allow-missing-secrets` is a decision, not a silencer: the operator must still see which
        // credentials are absent, because every `Application` that references one stays `Ready=False`
        // until it exists.
        eprintln!(
            "warning: {}",
            missing_secrets_warning(&verification.missing)
        );
    }
    for (stub, actual) in &verification.type_mismatches {
        eprintln!(
            "warning: Secret/{} carries {}={}, but the bundle expects {}",
            stub.display(),
            SECRET_TYPE_LABEL,
            actual.as_deref().unwrap_or("<none>"),
            stub.secret_type().unwrap_or("<none>"),
        );
    }
    for (stub, keys) in &verification.missing_keys {
        eprintln!(
            "warning: Secret/{} is missing the data key(s) {} the bundle was exported with",
            stub.display(),
            keys.join(", ")
        );
    }
    Ok(())
}

/// The warning `--allow-missing-secrets` prints for the credentials it could not find.
///
/// Pure, so the one thing that made the flag dangerous — it used to *silence* the missing-secret
/// report entirely — is testable without a cluster. It names each absent `Secret` and nothing else:
/// the stub carries names, `ferriscd.io/*` labels and key names, never a value.
fn missing_secrets_warning(missing: &[SecretStub]) -> String {
    format!(
        "--allow-missing-secrets: {} credential Secret(s) do not exist, so the restore proceeds \
         without them: {}. Each Application that references one of them stays Ready=False until it \
         is created.",
        missing.len(),
        missing
            .iter()
            .map(SecretStub::display)
            .collect::<Vec<_>>()
            .join(", "),
    )
}

// ---------------------------------------------------------------------------
// cluster & filesystem helpers
// ---------------------------------------------------------------------------

/// Builds a Kubernetes client from the ambient kubeconfig / in-cluster configuration.
async fn kube_client() -> Result<kube::Client> {
    kube::Client::try_default()
        .await
        .context("failed to build a Kubernetes client from the kubeconfig/in-cluster config")
}

/// The dynamic API for one restorable kind, optionally scoped to one namespace.
fn scoped_dynamic_api(
    client: &kube::Client,
    namespace: Option<&str>,
    kind: RestorableKind,
) -> Api<DynamicObject> {
    match namespace {
        Some(namespace) => Api::namespaced_with(client.clone(), namespace, &kind.api_resource()),
        None => Api::all_with(client.clone(), &kind.api_resource()),
    }
}

/// Reads a bundle from disk, refusing a file larger than [`MAX_BUNDLE_BYTES`].
async fn read_bundle(path: &Path) -> Result<String> {
    let metadata = tokio::fs::metadata(path)
        .await
        .with_context(|| format!("failed to read the bundle '{}'", path.display()))?;
    ensure!(
        metadata.is_file(),
        "'{}' is not a regular file",
        path.display()
    );
    ensure!(
        metadata.len() <= MAX_BUNDLE_BYTES as u64,
        "the bundle '{}' is {} bytes, larger than the {MAX_BUNDLE_BYTES} byte limit",
        path.display(),
        metadata.len()
    );
    let text = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read the bundle '{}'", path.display()))?;
    ensure!(
        text.len() <= MAX_BUNDLE_BYTES,
        "the bundle '{}' is {} bytes, larger than the {MAX_BUNDLE_BYTES} byte limit",
        path.display(),
        text.len()
    );
    Ok(text)
}

/// Writes a bundle with mode `0600`, atomically, and **never** through a symlink.
///
/// Blocking filesystem work: callers run it on the blocking pool.
///
/// Three properties, in the order they matter:
///
/// * **Never readable by another user.** The bytes go into a scratch file created `0600` (and the
///   mode is re-applied through [`crate::client::restrict_permissions`], so the property is asserted
///   here instead of inherited from a dependency's default) and then *renamed* onto `--output`. The
///   rename replaces the directory entry — the inode and therefore the mode are the scratch file's —
///   so a pre-existing `0644` bundle cannot leave the credential inventory world-readable, and unlike
///   `create`-then-`chmod` the bundle is never briefly `0644`. No post-rename `chmod` is needed (or
///   performed): it would act on the file this call just made `0600`.
/// * **Never through a symlink** — and never *into* a hardlink. A `--output` that is already a symlink
///   is refused by name, and the write itself is a `rename(2)` of a fresh sibling, which replaces the
///   directory entry instead of writing through it, so a link planted after the check cannot redirect
///   the bundle into another file (the TOCTOU window the check alone would leave open). A hardlink is
///   not detectable this way (it is indistinguishable from a second name for a file), but it needs no
///   check either: `rename(2)` replaces only *this* directory entry, so the other name keeps the old
///   inode, its old content and its own mode — nothing is ever written through it, and tightening the
///   new file cannot touch it. Both matter because the file names the cluster's credential `Secret`s:
///   writing it through a link is how a `0600` bundle ends up inside a world-readable config file it
///   was pointed at.
/// * **Never a half-written bundle.** The rename is atomic, so a concurrent reader (or a crash) sees
///   the previous bundle or the new one, never a truncated YAML document.
///
/// **Durability caveat:** neither the scratch file nor the directory is `fsync`ed, so the rename is
/// atomic but not necessarily *durable* — a power loss immediately after the command returns can lose
/// the newest bundle (and, rarely, the rename itself), leaving the previous bundle or nothing. That is
/// the deliberate trade-off for a DR export that an operator re-runs in seconds; a bundle whose
/// survival matters more than the write cost should be `sync`ed (`sync -- <path>`) or copied to the
/// DR repository before the machine is trusted again.
fn write_bundle_file(path: &Path, document: &str) -> Result<()> {
    use std::io::Write as _;

    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => bail!(
            "refusing to write '{}': it is a symbolic link, and a bundle is never written through \
             one (the mode this command applies would land on the target, not on the bundle). Pass \
             the real path, or move the bundle afterwards.",
            path.display()
        ),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(anyhow::Error::new(error).context(format!(
                "failed to inspect the output path '{}'",
                path.display()
            )));
        }
    }

    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let mut temporary = tempfile::NamedTempFile::new_in(&directory).with_context(|| {
        format!(
            "failed to create a temporary file in '{}' (the bundle is written there first, then \
             renamed into place)",
            directory.display()
        )
    })?;
    // `tempfile` creates `0600` on unix; re-applying the mode makes that a property this module
    // asserts instead of one it inherits from a dependency's default.
    let scratch = temporary.path().to_path_buf();
    crate::client::restrict_permissions(&scratch, 0o600)
        .with_context(|| format!("failed to restrict the mode of '{}'", scratch.display()))?;
    temporary
        .write_all(document.as_bytes())
        .with_context(|| format!("failed to write '{}'", scratch.display()))?;
    temporary
        .flush()
        .with_context(|| format!("failed to flush '{}'", scratch.display()))?;
    temporary
        .persist(path)
        .map_err(|error| anyhow::Error::new(error.error))
        .with_context(|| format!("failed to write '{}'", path.display()))?;
    // No post-rename `chmod`: the rename installed the scratch inode, which this call already made
    // `0600`, so a `chmod` here would only re-state what the file already is (and would follow a
    // symlink planted in the microseconds after `persist`, which the rename itself is safe from).
    Ok(())
}

#[cfg(test)]
mod tests {
    use k8s_openapi::ByteString;
    use serde_json::json;

    use super::*;

    const EXPORTED_AT: &str = "2026-01-01T00:00:00Z";

    fn input(resources: Vec<Value>, secrets: Vec<SecretStub>) -> ExportInput {
        ExportInput {
            resources,
            secrets,
            control_plane_namespace: CONTROL_PLANE_NAMESPACE.to_owned(),
            exported_at: EXPORTED_AT.to_owned(),
            tool: "ferriscd/test".to_owned(),
        }
    }

    fn application(name: &str, namespace: &str) -> Value {
        json!({
            "apiVersion": "ferriscd.io/v1alpha1",
            "kind": "Application",
            "metadata": {
                "name": name,
                "namespace": namespace,
                "uid": "6f6f1f4e-0000-4000-8000-000000000000",
                "resourceVersion": "12345",
                "generation": 7,
                "creationTimestamp": "2025-12-01T10:00:00Z",
                "managedFields": [{"manager": "kubectl", "operation": "Apply"}],
                "annotations": {"kubectl.kubernetes.io/last-applied-configuration": "{\"old\":true}"},
                "finalizers": ["ferriscd.io/finalizer"],
            },
            "spec": {
                "project": "payments",
                "source": {
                    "git": {"repoURL": "https://github.com/example/payments.git", "targetRevision": "main", "path": "deploy"},
                    "renderer": {"plainYaml": {}},
                },
                "destination": {"cluster": "in-cluster", "namespace": namespace},
                "syncPolicy": {"automated": {"prune": true, "selfHeal": true}},
            },
            "status": {"sync": {"status": "Synced"}, "health": {"status": "Healthy"}},
        })
    }

    fn app_project(name: &str, namespace: &str) -> Value {
        json!({
            "apiVersion": "ferriscd.io/v1alpha1",
            "kind": "AppProject",
            "metadata": {"name": name, "namespace": namespace, "uid": "aaaa", "resourceVersion": "9"},
            "spec": {
                "description": "payments",
                "sourceRepos": ["*"],
                "destinations": [{"cluster": "in-cluster", "namespace": "*"}],
                "allowedServiceAccounts": ["*"],
            },
            "status": {"conditions": [{"type": "Ready", "status": "True"}]},
        })
    }

    fn config_map(name: &str, namespace: &str) -> Value {
        json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            // `deletionTimestamp` is an explicit `null` here on purpose: [`is_terminating`] only
            // skips a *set* timestamp, so this object is exported and the strip list has to remove
            // the key — which is what makes the strip assertion below more than a tautology.
            "metadata": {
                "name": name,
                "namespace": namespace,
                "resourceVersion": "77",
                "uid": "cm",
                "deletionTimestamp": null,
            },
            "data": {"policy.yaml": "rules: []\n"},
        })
    }

    fn application_set(name: &str, namespace: &str) -> Value {
        json!({
            "apiVersion": "ferriscd.io/v1alpha1",
            "kind": "ApplicationSet",
            "metadata": {"name": name, "namespace": namespace, "uid": "set", "generation": 2},
            "spec": {"generators": [{"list": {"elements": [{"name": "a"}]}}], "template": {"spec": {}}},
            "status": {"generatedCount": 1},
        })
    }

    fn secret_stub_fixture(name: &str) -> SecretStub {
        SecretStub {
            namespace: "ferriscd-system".to_owned(),
            name: name.to_owned(),
            labels: BTreeMap::from([(SECRET_TYPE_LABEL.to_owned(), "repository".to_owned())]),
            keys: vec![
                "password".to_owned(),
                "username".to_owned(),
                "url".to_owned(),
            ],
        }
    }

    fn bundle_yaml(bundle: &BackupBundle) -> String {
        serde_saphyr::to_string(bundle).expect("the bundle renders")
    }

    /// **Trap guard.** A real `Secret` is read for its *shape* only: the stub carries the name, the
    /// `ferriscd.io/*` labels and the `data` key names — never a value, and never a user label
    /// (which can legitimately contain a URL with an inline token).
    #[test]
    fn a_secret_stub_records_shape_never_material() {
        let secret: Secret = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": "payments-repo",
                "namespace": "ferriscd-system",
                "labels": {
                    "ferriscd.io/secret-type": "repository",
                    "example.com/last-used-url": "https://oauth2:ghp_supersecret@github.com/x.git",
                },
            },
            "type": "Opaque",
            "data": {"url": "aHR0cHM6Ly9naXRodWIuY29t", "username": "Z2l0", "password": "Z2hwX3N1cGVyc2VjcmV0"},
            "stringData": {"token": "ghp_supersecret"},
        }))
        .expect("the fixture Secret parses");

        let stub = secret_stub(&secret).expect("a repository Secret is tracked");
        assert_eq!(stub.name, "payments-repo");
        assert_eq!(stub.namespace, "ferriscd-system");
        assert_eq!(stub.secret_type(), Some("repository"));
        assert_eq!(
            stub.labels.keys().collect::<Vec<_>>(),
            vec![SECRET_TYPE_LABEL],
            "only ferriscd.io/* labels may be recorded"
        );
        assert_eq!(
            stub.keys,
            vec![
                "password".to_owned(),
                "url".to_owned(),
                "username".to_owned()
            ],
            "the keys are recorded in sorted order"
        );

        // The rendered form contains none of the material — not the base64 values, not the
        // plaintext, not the foreign label value.
        let bundle = build_bundle(input(
            vec![config_map("ferriscd-rbac-cm", CONTROL_PLANE_NAMESPACE)],
            vec![stub],
        ))
        .expect("the bundle builds");
        let rendered = bundle_yaml(&bundle);
        for leaked in [
            "aHR0cHM6Ly9naXRodWIuY29t",
            "Z2hwX3N1cGVyc2VjcmV0",
            "ghp_supersecret",
            "Z2l0",
            "example.com/last-used-url",
            "stringData",
        ] {
            assert!(
                !rendered.contains(leaked),
                "the bundle must not contain {leaked:?}:\n{rendered}"
            );
        }
        // The output is a YAML document, and it does name the credential and its keys.
        assert!(rendered.contains("payments-repo"), "{rendered}");
        assert!(rendered.contains("password"), "{rendered}");
    }

    /// A `Secret` whose type is not one a restore depends on is not recorded at all.
    #[test]
    fn only_the_tracked_secret_types_are_exported() {
        let untracked: Secret = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": "webhook-secret",
                "namespace": "ferriscd-system",
                "labels": {"ferriscd.io/secret-type": "webhook"},
            },
            "data": {"token": "c2VjcmV0"},
        }))
        .expect("the fixture parses");
        assert!(secret_stub(&untracked).is_none());

        // ...but the pre-flight's observer still sees it, so a type mismatch is reportable.
        let observed = observed_stub(&untracked);
        assert_eq!(observed.secret_type(), Some("webhook"));
        assert_eq!(observed.keys, vec!["token".to_owned()]);
    }

    /// The export half strips every server-managed field and orders by dependency, not by input.
    #[test]
    fn export_strips_live_fields_and_is_dependency_ordered() {
        let notifications = config_map("ferriscd-notifications-cm", CONTROL_PLANE_NAMESPACE);
        let rbac = config_map("ferriscd-rbac-cm", CONTROL_PLANE_NAMESPACE);
        // The strip assertions below are only worth something if an *exported* fixture really carries
        // the fields they forbid. `deletionTimestamp` is the interesting one: a set timestamp makes an
        // object terminating (skipped, never exported), so the fixture uses an explicit `null` — which
        // is exactly the value that must not survive into the bundle.
        assert_eq!(rbac["metadata"]["deletionTimestamp"], Value::Null);
        assert_eq!(notifications["metadata"]["deletionTimestamp"], Value::Null);

        let bundle = build_bundle(input(
            vec![
                application("b-app", "team-b"),
                notifications,
                application_set("fleet", "team-a"),
                app_project("payments", "team-a"),
                application("a-app", "team-a"),
                rbac,
            ],
            Vec::new(),
        ))
        .expect("the bundle builds");

        let order = bundle
            .resources
            .iter()
            .map(|resource| {
                format!(
                    "{}/{}/{}",
                    resource["kind"].as_str().unwrap_or_default(),
                    resource["metadata"]["namespace"]
                        .as_str()
                        .unwrap_or_default(),
                    resource["metadata"]["name"].as_str().unwrap_or_default()
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            order,
            vec![
                "ConfigMap/ferriscd-system/ferriscd-notifications-cm",
                "ConfigMap/ferriscd-system/ferriscd-rbac-cm",
                "AppProject/team-a/payments",
                "ApplicationSet/team-a/fleet",
                "Application/team-a/a-app",
                "Application/team-b/b-app",
            ],
            "ConfigMaps first, then AppProjects, ApplicationSets and Applications by namespace/name"
        );

        for resource in &bundle.resources {
            assert!(resource.get("status").is_none(), "{resource}");
            let metadata = resource["metadata"].as_object().expect("metadata");
            for key in SERVER_MANAGED_METADATA {
                assert!(
                    !metadata.contains_key(key),
                    "{key} must be stripped: {resource}"
                );
            }
            if let Some(annotations) = metadata.get("annotations") {
                assert!(
                    annotations.get(LAST_APPLIED_ANNOTATION).is_none(),
                    "the last-applied annotation must be stripped: {resource}"
                );
            }
        }
        // Both exported `ConfigMap`s carried `deletionTimestamp: null` on the way in (asserted above),
        // so `deletionTimestamp` is gone from them because the strip removed it.
        assert!(
            bundle
                .resources
                .iter()
                .filter(|resource| resource["kind"] == "ConfigMap")
                .all(|resource| resource["metadata"].get("deletionTimestamp").is_none()),
            "the terminating marker must not survive even as a null"
        );

        // A spec-level field survives: the strip is narrow, not a wholesale truncation.
        let restored_application = bundle
            .resources
            .iter()
            .find(|resource| resource["metadata"]["name"] == "a-app")
            .expect("the application is exported");
        assert_eq!(
            restored_application["spec"]["destination"]["namespace"],
            "team-a"
        );
        assert_eq!(
            restored_application["spec"]["source"]["git"]["path"],
            "deploy"
        );
        // The finalizer is ours and must survive (it is not server-populated).
        assert_eq!(
            restored_application["metadata"]["finalizers"],
            json!(["ferriscd.io/finalizer"])
        );
    }

    /// **Trap guard.** Generated `Application`s are never exported as objects: their owner reference
    /// names a uid a restore cannot reproduce.
    #[test]
    fn generated_applications_are_left_to_their_applicationset() {
        let mut generated = application("fleet-app-1", "team-a");
        generated["metadata"]["labels"] = json!({APPLICATIONSET_LABEL: "fleet"});
        // The same conclusion from the owner reference alone (the label may be hand-removed).
        let mut owned = application("fleet-app-2", "team-a");
        owned["metadata"]["ownerReferences"] = json!([{"apiVersion": "ferriscd.io/v1alpha1", "kind": "ApplicationSet", "name": "fleet", "uid": "stale"}]);

        let bundle = build_bundle(input(
            vec![generated, owned, application("hand-written", "team-a")],
            Vec::new(),
        ))
        .expect("the bundle builds");

        assert_eq!(bundle.resources.len(), 1);
        assert_eq!(bundle.resources[0]["metadata"]["name"], "hand-written");
        assert_eq!(
            bundle
                .generated_applications
                .iter()
                .map(|id| id.name.as_str())
                .collect::<Vec<_>>(),
            vec!["fleet-app-1", "fleet-app-2"],
        );
    }

    /// A half-deleted object is not DR material.
    #[test]
    fn terminating_objects_are_not_exported() {
        let mut terminating = application("going-away", "team-a");
        terminating["metadata"]["deletionTimestamp"] = json!("2026-01-01T00:00:00Z");
        let bundle = build_bundle(input(
            vec![terminating, application("staying", "team-a")],
            Vec::new(),
        ))
        .expect("the bundle builds");

        assert_eq!(bundle.resources.len(), 1);
        assert_eq!(bundle.resources[0]["metadata"]["name"], "staying");
        assert_eq!(
            bundle
                .skipped_terminating
                .iter()
                .map(|id| id.name.as_str())
                .collect::<Vec<_>>(),
            vec!["going-away"]
        );
        // Nothing is asserted about `deletionTimestamp` on the *exported* object here: it never
        // carried the field, so such an assertion would be vacuous. The strip is proven in
        // `export_strips_live_fields_and_is_dependency_ordered`, whose exported `ConfigMap` fixtures
        // really do carry an explicit `deletionTimestamp: null` (and are exported, because
        // [`is_terminating`] only skips a *set* timestamp).
    }

    /// Determinism is what makes a bundle diffable in the DR repository, and the digest is what makes
    /// an edit detectable.
    #[test]
    fn the_bundle_is_deterministic_and_the_digest_detects_a_single_edit() {
        let resources = vec![
            application("a-app", "team-a"),
            app_project("payments", "team-a"),
            config_map("ferriscd-rbac-cm", CONTROL_PLANE_NAMESPACE),
        ];
        let secrets = vec![secret_stub_fixture("payments-repo")];
        let first = build_bundle(input(resources.clone(), secrets.clone())).expect("builds");
        let mut reversed = resources;
        reversed.reverse();
        let second = build_bundle(input(reversed, secrets)).expect("builds");

        assert_eq!(
            bundle_yaml(&first),
            bundle_yaml(&second),
            "the export order is the dependency order, not the API server's list order"
        );
        assert_eq!(first.integrity.digest, second.integrity.digest);
        assert_eq!(first.integrity.algorithm, DIGEST_ALGORITHM);
        assert!(
            first.integrity.digest.starts_with("sha256:")
                && first.integrity.digest.len() == "sha256:".len() + 64,
            "{}",
            first.integrity.digest
        );

        // Round-tripping through the committed YAML preserves the digest exactly.
        let text = bundle_yaml(&first);
        let parsed = parse_bundle(&text).expect("a round-tripped bundle verifies");
        assert_eq!(parsed, first);

        // One changed character in a spec value is a different bundle.
        let tampered = text.replace("deploy", "productio");
        let error = parse_bundle(&tampered).expect_err("a tampered bundle must be refused");
        assert!(
            format!("{error}").contains("integrity check failed"),
            "{error}"
        );

        // ...and so is a removed credential stub (a truncated file, or a hand-edited one).
        let truncated = text.replace("payments-repo", "payments-rep0");
        assert!(parse_bundle(&truncated).is_err());
    }

    /// Canonical JSON is sorted and whitespace-free, so re-indenting a bundle cannot change the
    /// digest while changing a value does.
    #[test]
    fn canonical_json_sorts_keys_and_omits_whitespace() {
        let value = json!({"b": [1, {"z": true, "a": null}], "a": "x\"y"});
        assert_eq!(
            canonical_json(&value),
            r#"{"a":"x\"y","b":[1,{"a":null,"z":true}]}"#
        );
        assert_eq!(canonical_json(&json!({})), "{}");
        assert_eq!(canonical_json(&json!([])), "[]");
        assert_eq!(canonical_json(&json!(1.5)), "1.5");
    }

    /// **Finding M3.** `exportedAt` is the only line that moves between two exports of an unchanged
    /// control plane, and it is excluded from the digest, so `--exported-at` makes a DR bundle
    /// diffable line-for-line.
    #[test]
    fn the_export_timestamp_never_changes_the_restorable_content() {
        let resources = vec![
            application("a-app", "team-a"),
            app_project("payments", "team-a"),
        ];
        let secrets = vec![secret_stub_fixture("payments-repo")];
        let first = build_bundle(input(resources.clone(), secrets.clone())).expect("builds");
        let mut later = input(resources, secrets);
        later.exported_at = "2031-07-04T09:00:00Z".to_owned();
        let second = build_bundle(later).expect("builds");

        assert_ne!(first.exported_at, second.exported_at);
        assert_eq!(first.resources, second.resources);
        assert_eq!(first.secrets, second.secrets);
        assert_eq!(
            first.integrity.digest, second.integrity.digest,
            "the timestamp is documentation: it must never enter the digest"
        );

        // The rendered documents differ in exactly one line — what a DR-repository diff shows.
        let without_timestamp = |bundle: &BackupBundle| {
            bundle_yaml(bundle)
                .lines()
                .filter(|line| !line.starts_with("exportedAt:"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        assert_eq!(without_timestamp(&first), without_timestamp(&second));
        assert_ne!(
            bundle_yaml(&first),
            bundle_yaml(&second),
            "the timestamps must really differ, otherwise the assertion above proves nothing"
        );
    }

    /// `--exported-at` is validated and normalized to one RFC 3339 rendering.
    #[test]
    fn the_export_timestamp_flag_is_validated_and_normalized() {
        assert_eq!(
            export_timestamp(Some("2026-01-01T00:00:00Z")).expect("a Z timestamp is accepted"),
            "2026-01-01T00:00:00Z"
        );
        // The same instant written with an offset must render identically, or two operators pinning
        // "the same time" would still produce different bytes.
        assert_eq!(
            export_timestamp(Some("2026-01-01T00:00:00+00:00")).expect("an offset timestamp"),
            "2026-01-01T00:00:00Z"
        );
        let error = export_timestamp(Some("yesterday")).expect_err("a non-timestamp is refused");
        assert!(format!("{error}").contains("--exported-at"), "{error}");
        // The default is now, and it is always a timestamp this command would accept back.
        let now = export_timestamp(None).expect("the default is produced");
        assert!(now.parse::<jiff::Timestamp>().is_ok(), "{now}");
    }

    /// **Finding M2.** Export must never emit a bundle its own restore refuses: the rendered text is
    /// re-parsed under the restore's budgets before it can reach a file or stdout.
    #[test]
    fn export_refuses_to_emit_a_bundle_it_could_not_restore() {
        // A legitimate bundle renders, verifies and round-trips identically. The fixture carries the
        // three value shapes a renderer can lose — a float, a `u64` past `i64::MAX`, and an explicit
        // `null` — so "round-trips identically" is a real assertion rather than a strings-only one.
        let mut project = app_project("payments", "team-a");
        project["spec"]["floatProbe"] = json!(1.5);
        project["spec"]["bigProbe"] = json!(u64::MAX);
        project["spec"]["nullProbe"] = Value::Null;
        let bundle = build_bundle(input(
            vec![
                config_map("ferriscd-rbac-cm", CONTROL_PLANE_NAMESPACE),
                project,
            ],
            vec![secret_stub_fixture("payments-repo")],
        ))
        .expect("the bundle builds");
        let (verified, document) = render_and_verify(bundle.clone()).expect("the bundle verifies");
        assert_eq!(verified, bundle);
        assert_eq!(
            parse_bundle(&document).expect("the document parses"),
            bundle
        );
        for probe in ["floatProbe", "bigProbe", "nullProbe"] {
            assert!(
                document.contains(probe),
                "the render dropped {probe}:\n{document}"
            );
        }

        // A value past the byte ceiling is refused *before* it is written anywhere. Export builds it
        // quite happily (one item, under the item ceiling); only the rendered form is too large —
        // which is exactly the case a restore would have rejected after the operator committed it.
        let mut oversized = config_map("ferriscd-rbac-cm", CONTROL_PLANE_NAMESPACE);
        oversized["data"] = json!({"policy.yaml": "x".repeat(MAX_BUNDLE_BYTES)});
        let huge = build_bundle(input(vec![oversized], Vec::new())).expect("the bundle builds");
        let error = render_and_verify(huge).expect_err("an unusable bundle is refused");
        assert!(format!("{error}").contains("byte limit"), "{error}");
    }

    /// **Finding M4 / trap guard.** A bundle-supplied identity becomes an API request path, so a
    /// traversal-shaped one is refused before any request is built — and the refusal does not echo
    /// the hostile string.
    #[test]
    fn a_bundle_supplied_identity_must_be_a_dns_1123_name() {
        // The validators, at their boundaries.
        for valid in ["team-a", "a", "a1-b2", "0", "a--b"] {
            assert!(
                is_dns_1123_label(valid),
                "{valid:?} is a valid DNS-1123 label"
            );
        }
        let longest_label = "a".repeat(MAX_DNS_1123_LABEL);
        assert!(is_dns_1123_label(&longest_label));
        let too_long_label = "a".repeat(MAX_DNS_1123_LABEL + 1);
        for invalid in [
            "",
            "-team",
            "team-",
            "Team",
            "team_a",
            "team/a",
            "..",
            "team a",
            "../etc",
            too_long_label.as_str(),
        ] {
            assert!(
                !is_dns_1123_label(invalid),
                "{invalid:?} is not a DNS-1123 label"
            );
        }

        assert!(is_dns_1123_subdomain("payments-api"));
        assert!(is_dns_1123_subdomain("payments-api.team-a"));
        let too_long_subdomain = "a".repeat(MAX_DNS_1123_SUBDOMAIN + 1);
        for invalid in [
            "",
            "..",
            "a..b",
            "payments/../x",
            "payments api",
            "Payments",
            too_long_subdomain.as_str(),
        ] {
            assert!(
                !is_dns_1123_subdomain(invalid),
                "{invalid:?} is not a DNS-1123 subdomain"
            );
        }

        // A traversal-shaped object name never reaches a request path.
        let traversal = build_bundle(input(
            vec![application("../../etc/passwd", "team-a")],
            Vec::new(),
        ))
        .expect("a hand-written bundle can carry anything");
        let error = plan_restore(&traversal).expect_err("a traversal-shaped name is refused");
        let rendered = format!("{error}");
        assert!(rendered.contains("DNS-1123 subdomain"), "{rendered}");
        assert!(
            !rendered.contains("etc/passwd") && !rendered.contains(".."),
            "the refusal must not echo the offending name: {rendered}"
        );

        // ...and neither does a traversal-shaped namespace (the other half of the request path).
        let bad_namespace = build_bundle(input(vec![application("app", "team/../a")], Vec::new()))
            .expect("the bundle builds");
        let error =
            plan_restore(&bad_namespace).expect_err("a traversal-shaped namespace is refused");
        assert!(format!("{error}").contains("DNS-1123 label"), "{error}");

        // ...nor a hostile credential stub, because the pre-flight reads one `Secret` per stub.
        let mut bad_stub = build_bundle(input(vec![app_project("payments", "team-a")], Vec::new()))
            .expect("the bundle builds");
        bad_stub.secrets = vec![SecretStub {
            namespace: "../kube-system".to_owned(),
            name: "stolen".to_owned(),
            labels: BTreeMap::new(),
            keys: Vec::new(),
        }];
        bad_stub.integrity.digest = bundle_digest(&bad_stub).expect("digest");
        let error = plan_restore(&bad_stub).expect_err("a hostile stub is refused");
        assert!(format!("{error}").contains("credential stub"), "{error}");

        // A legitimate bundle is unaffected (the validation is not a blanket refusal).
        let fine = build_bundle(input(
            vec![application("payments-api", "team-a")],
            vec![secret_stub_fixture("payments-repo")],
        ))
        .expect("the bundle builds");
        assert_eq!(plan_restore(&fine).expect("the plan builds").items.len(), 1);
    }

    /// **Finding M5 / trap guard.** `ferriscd.io/tracking-id` is the only ownership evidence the
    /// controller trusts before it overwrites or prunes a managed resource, so the strip list must
    /// never widen to it: it has to survive export *and* the restore plan unchanged.
    #[test]
    fn the_tracking_id_annotation_survives_export_and_the_restore_plan() {
        let tracking = ferriscd_crd::annotations::TRACKING_ID;
        assert_eq!(
            tracking, "ferriscd.io/tracking-id",
            "the assertion below is only meaningful for the label the controller really stamps"
        );
        let value = "team-a/payments-api:apps/Deployment:team-a/payments-api";

        let mut annotated = application("payments-api", "team-a");
        let mut annotations = serde_json::Map::new();
        annotations.insert(tracking.to_owned(), json!(value));
        annotations.insert(LAST_APPLIED_ANNOTATION.to_owned(), json!({"old": true}));
        annotated["metadata"]["annotations"] = Value::Object(annotations);

        let bundle = build_bundle(input(vec![annotated], Vec::new())).expect("the bundle builds");
        assert_eq!(
            bundle.resources[0]["metadata"]["annotations"][tracking],
            json!(value),
            "export must not strip the tracking-id annotation"
        );
        // The same strip that must keep it still removes the client-side apply record.
        assert!(
            bundle.resources[0]["metadata"]["annotations"]
                .get(LAST_APPLIED_ANNOTATION)
                .is_none()
        );

        let plan = plan_restore(&bundle).expect("the plan builds");
        let restored = serde_json::to_value(&plan.items[0].object).expect("the object serializes");
        assert_eq!(
            restored["metadata"]["annotations"][tracking],
            json!(value),
            "the restore plan must not strip the tracking-id annotation"
        );
    }

    /// **Finding M1.** `--allow-missing-secrets` used to omit the missing-secret report entirely, so a
    /// staged restore read as a clean one. The warning must name every credential it did not find.
    #[test]
    fn the_allow_missing_secrets_warning_names_every_absent_credential() {
        let missing = vec![
            secret_stub_fixture("payments-repo"),
            SecretStub {
                namespace: "ferriscd-system".to_owned(),
                name: "oidc".to_owned(),
                labels: BTreeMap::from([(SECRET_TYPE_LABEL.to_owned(), "oidc".to_owned())]),
                keys: vec!["clientSecret".to_owned()],
            },
        ];
        let warning = missing_secrets_warning(&missing);
        assert!(warning.contains("--allow-missing-secrets"), "{warning}");
        assert!(warning.contains("2 credential Secret(s)"), "{warning}");
        assert!(
            warning.contains("ferriscd-system/payments-repo")
                && warning.contains("ferriscd-system/oidc"),
            "both absent credentials must be named: {warning}"
        );
        assert!(warning.contains("Ready=False"), "{warning}");

        // It prints identities only — not the expected key names, and certainly not a value.
        for key in ["password", "username", "clientSecret"] {
            assert!(
                !warning.contains(key),
                "the warning must name credentials, never their key material ({key}): {warning}"
            );
        }
    }

    /// **Finding M6.** The restore summary reports the `Application`s it deliberately does not create:
    /// a restore that silently omitted a generated fleet would read as "everything came back".
    #[test]
    fn the_restore_summary_counts_what_was_left_to_an_applicationset() {
        let mut generated = application("fleet-app-1", "team-a");
        generated["metadata"]["labels"] = json!({APPLICATIONSET_LABEL: "fleet"});
        let bundle = build_bundle(input(
            vec![
                generated,
                app_project("payments", "team-a"),
                application("hand-written", "team-a"),
            ],
            vec![secret_stub_fixture("payments-repo")],
        ))
        .expect("the bundle builds");
        assert_eq!(bundle.generated_applications.len(), 1);
        let plan = plan_restore(&bundle).expect("the plan builds");
        let args = RestoreArgs {
            bundle: PathBuf::from("bundle.yaml"),
            dry_run: true,
            on_conflict: ConflictPolicy::Abort,
            allow_missing_secrets: false,
        };

        let summary = restore_summary(&args, &plan, 2, 1);
        assert!(
            summary.starts_with("would restore 2 resource(s)"),
            "{summary}"
        );
        assert!(summary.contains("bundle.yaml"), "{summary}");
        assert!(
            summary.contains("1 skipped by --on-conflict=skip"),
            "{summary}"
        );
        assert!(
            summary.contains("1 credential stub(s) checked"),
            "{summary}"
        );
        assert!(
            summary.contains("1 Application(s) left to their ApplicationSet"),
            "the generated Application must be accounted for: {summary}"
        );

        // A real restore says so, and a bundle with no generated Applications reports zero rather than
        // dropping the clause.
        let mut quiet = args;
        quiet.dry_run = false;
        quiet.allow_missing_secrets = true;
        let plain = build_bundle(input(vec![app_project("payments", "team-a")], Vec::new()))
            .expect("the bundle builds");
        let plan = plan_restore(&plain).expect("the plan builds");
        let summary = restore_summary(&quiet, &plan, 1, 0);
        assert!(summary.starts_with("restored 1 resource(s)"), "{summary}");
        assert!(
            summary.contains("0 Application(s) left to their ApplicationSet"),
            "{summary}"
        );
        assert!(
            summary.contains("0 credential stub(s) checked"),
            "{summary}"
        );
    }

    #[test]
    fn unsupported_schema_and_algorithm_are_refused_by_name() {
        let bundle = build_bundle(input(vec![app_project("payments", "team-a")], Vec::new()))
            .expect("builds");

        let mut future = bundle.clone();
        future.schema_version = "ferriscd.io/backup/v2".to_owned();
        let error = parse_bundle(&bundle_yaml(&future)).expect_err("a v2 bundle is refused");
        assert!(
            format!("{error}").contains("unsupported bundle schema"),
            "{error}"
        );
        assert!(format!("{error}").contains(SCHEMA_VERSION), "{error}");

        let mut other_hash = bundle.clone();
        other_hash.integrity.algorithm = "md5".to_owned();
        let error = parse_bundle(&bundle_yaml(&other_hash)).expect_err("md5 is refused");
        assert!(
            format!("{error}").contains("unsupported integrity algorithm"),
            "{error}"
        );
    }

    /// **Trap guard.** A bundle that carries a raw `Secret` is not one we wrote, and must never be
    /// applied (whatever the digest says).
    #[test]
    fn restore_refuses_raw_secrets_and_unknown_kinds() {
        let secret = json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "stolen", "namespace": "team-a"},
            "data": {"password": "Z2hwX3N1cGVyc2VjcmV0"},
        });
        // The export half refuses a `Secret` (it is not one of the four restorable kinds)...
        let error = build_bundle(input(vec![secret.clone()], Vec::new()))
            .expect_err("export never captures a Secret");
        assert!(format!("{error}").contains("may only carry"), "{error}");

        // ...and the restore half refuses one smuggled into a hand-written bundle.
        let mut with_secret =
            build_bundle(input(vec![app_project("payments", "team-a")], Vec::new()))
                .expect("builds");
        with_secret.resources.push(secret);
        with_secret.integrity.digest = bundle_digest(&with_secret).expect("digest");
        let error = plan_restore(&with_secret).expect_err("a raw Secret is refused");
        assert!(
            format!("{error}").contains("refusing to restore Secret"),
            "{error}"
        );
        assert!(
            !format!("{error}").contains("Z2hwX3N1cGVyc2VjcmV0"),
            "the refusal must not quote the value: {error}"
        );

        let escalation = json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "pwn", "namespace": "team-a"},
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin"},
            "subjects": [{"kind": "ServiceAccount", "name": "default", "namespace": "team-a"}],
        });
        // `build_bundle` refuses it at export time (only the four kinds may be captured)...
        let error = build_bundle(input(vec![escalation.clone()], Vec::new()))
            .expect_err("an arbitrary kind is refused at export");
        assert!(format!("{error}").contains("may only carry"), "{error}");
        // ...and the restore half refuses it too, from a hand-written bundle.
        let mut hand_written =
            build_bundle(input(vec![app_project("payments", "team-a")], Vec::new()))
                .expect("builds");
        hand_written.resources.push(escalation);
        hand_written.integrity.digest = bundle_digest(&hand_written).expect("digest");
        let error =
            plan_restore(&hand_written).expect_err("an arbitrary kind is refused at restore");
        assert!(format!("{error}").contains("may only carry"), "{error}");
    }

    /// The restore plan re-derives order and re-strips live fields, so a hand-written bundle cannot
    /// reintroduce `status`, `uid` or an out-of-order apply either.
    #[test]
    fn the_restore_plan_orders_by_dependency_and_strips_hand_written_live_fields() {
        let mut hand_written = build_bundle(input(
            vec![
                application("b-app", "team-b"),
                application("a-app", "team-a"),
                app_project("payments", "team-a"),
                config_map("ferriscd-rbac-cm", CONTROL_PLANE_NAMESPACE),
            ],
            Vec::new(),
        ))
        .expect("builds");
        // Simulate a bundle that still carries live fields (an older tool, or a hand edit).
        hand_written.resources.reverse();
        for resource in &mut hand_written.resources {
            resource["metadata"]["uid"] = json!("freshly-baked");
            resource["metadata"]["deletionTimestamp"] = json!("2026-02-02T00:00:00Z");
            resource["status"] = json!({"sync": {"status": "Synced"}});
        }
        hand_written.integrity.digest = bundle_digest(&hand_written).expect("digest");

        let plan = plan_restore(&hand_written).expect("the plan builds");
        assert_eq!(
            plan.items
                .iter()
                .map(|item| item.id.display())
                .collect::<Vec<_>>(),
            vec![
                "ConfigMap/ferriscd-system/ferriscd-rbac-cm",
                "AppProject/team-a/payments",
                "Application/team-a/a-app",
                "Application/team-b/b-app",
            ]
        );
        for item in &plan.items {
            let value = serde_json::to_value(&item.object).expect("serializes");
            assert!(value.get("status").is_none(), "{value}");
            assert!(value["metadata"].get("uid").is_none(), "{value}");
            assert!(
                value["metadata"].get("deletionTimestamp").is_none(),
                "a terminating marker must never be replayed onto a new cluster: {value}"
            );
        }
        assert_eq!(
            plan.namespaces(),
            BTreeSet::from([
                CONTROL_PLANE_NAMESPACE.to_owned(),
                "team-a".to_owned(),
                "team-b".to_owned()
            ])
        );
    }

    /// The pre-flight compares shape only and never renders a value.
    #[test]
    fn the_secret_preflight_reports_missing_secrets_types_and_keys() {
        let expected = vec![
            secret_stub_fixture("present"),
            secret_stub_fixture("absent"),
            secret_stub_fixture("wrong-type"),
            secret_stub_fixture("missing-key"),
        ];
        let mut wrong_type = secret_stub_fixture("wrong-type");
        wrong_type
            .labels
            .insert(SECRET_TYPE_LABEL.to_owned(), "cluster".to_owned());
        let mut missing_key = secret_stub_fixture("missing-key");
        missing_key.keys.retain(|key| key != "password");
        let observed = vec![secret_stub_fixture("present"), wrong_type, missing_key];

        let verification = verify_secrets(&expected, &observed);
        assert!(!verification.is_clean());
        assert_eq!(
            verification
                .missing
                .iter()
                .map(SecretStub::display)
                .collect::<Vec<_>>(),
            vec!["ferriscd-system/absent".to_owned()]
        );
        assert_eq!(
            verification
                .type_mismatches
                .iter()
                .map(|(stub, actual)| (stub.name.as_str(), actual.as_deref()))
                .collect::<Vec<_>>(),
            vec![("wrong-type", Some("cluster"))]
        );
        assert_eq!(
            verification
                .missing_keys
                .iter()
                .map(|(stub, keys)| (stub.name.as_str(), keys.clone()))
                .collect::<Vec<_>>(),
            vec![("missing-key", vec!["password".to_owned()])]
        );

        // A fully matching inventory is clean, and an absent label is a mismatch, not a crash.
        assert!(
            verify_secrets(&expected[..1], &observed[..1]).is_clean(),
            "an exact match must verify cleanly"
        );
        let mut unlabelled = secret_stub_fixture("present");
        unlabelled.labels.clear();
        let verification = verify_secrets(&expected[..1], &[unlabelled]);
        assert_eq!(verification.type_mismatches.len(), 1);
        assert_eq!(verification.type_mismatches[0].1, None);
    }

    /// **H-NEW-1.** The inventory covers the control-plane namespace and **only** that namespace,
    /// because that is the only place FerrisCD reads a credential from (`T12.4`/`T13.1`/`T19.1`/`T19.4`
    /// each hold a namespaced `Api<Secret>`).
    ///
    /// This is the deliberate answer to "why does a whole-cluster export not record
    /// `team-a/payments-repo`?": the controller never reads that `Secret`, so it is not a credential a
    /// restore can depend on, and recording it would invent a dependency (a restore that then refuses
    /// to run without it) while copying a tenant object's shape into the bundle. A per-namespace export
    /// of `team-a` is no different: what `team-a`'s `Application`s authenticate *with* lives in the
    /// control plane.
    #[test]
    fn the_secret_inventory_covers_the_control_plane_namespace_and_nothing_else() {
        // `--namespace` is not a parameter of this decision at all: the whole-cluster export and a
        // `--namespace team-a` export both inventory exactly the control plane's credentials.
        assert_eq!(
            secret_inventory_namespaces(CONTROL_PLANE_NAMESPACE),
            vec![CONTROL_PLANE_NAMESPACE.to_owned()]
        );
        // `--control-plane-namespace` *is* the scope: moving the control plane moves the inventory
        // (a single-tenant install runs the controller with `--namespace team-a`).
        assert_eq!(
            secret_inventory_namespaces("team-a"),
            vec!["team-a".to_owned()]
        );
        // ...and a tenant namespace is never scanned alongside it.
        assert!(
            !secret_inventory_namespaces(CONTROL_PLANE_NAMESPACE)
                .iter()
                .any(|ns| ns == "team-a"),
            "a labelled Secret in a tenant namespace is not a credential FerrisCD consumes"
        );
    }

    /// **H-NEW-1 (wire proof).** The one `Secret` read an export makes is a *namespaced*,
    /// label-filtered list in the control-plane namespace — the same shape the controller's own reads
    /// have, and never the cluster-wide `list` (or per-tenant `list`) that would let a bundle record
    /// credentials FerrisCD cannot use.
    #[tokio::test]
    async fn the_export_lists_credentials_in_the_control_plane_namespace_only() {
        let secrets = serde_json::json!([
            // The control plane's repository credential: inventoried (shape only).
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {
                    "name": "payments-repo",
                    "namespace": CONTROL_PLANE_NAMESPACE,
                    "labels": {SECRET_TYPE_LABEL: "repository"},
                },
                "data": {"url": "aHR0cHM6Ly9naXRodWIuY29t", "password": "c2VjcmV0"},
            },
            // A `Secret` inside the same namespace whose label is not a tracked credential type: the
            // list returns it (the selector is label *presence*), the export drops it.
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {
                    "name": "webhook-signing-key",
                    "namespace": CONTROL_PLANE_NAMESPACE,
                    "labels": {SECRET_TYPE_LABEL: "webhook"},
                },
                "data": {"token": "c2VjcmV0"},
            },
        ]);
        let (client, requests) = recording_client(&secrets);

        let stubs = collect_secrets(&client, CONTROL_PLANE_NAMESPACE)
            .await
            .expect("the namespaced list succeeds");

        assert_eq!(
            stubs.iter().map(SecretStub::display).collect::<Vec<_>>(),
            vec![format!("{CONTROL_PLANE_NAMESPACE}/payments-repo")],
            "exactly the tracked credential is inventoried"
        );
        assert_eq!(
            stubs[0].keys,
            vec!["password".to_owned(), "url".to_owned()],
            "the stub records key names, sorted"
        );
        assert!(!format!("{stubs:?}").contains("c2VjcmV0"), "{stubs:?}");

        let requests = requests.lock().expect("the request log is not poisoned");
        assert_eq!(
            requests.len(),
            1,
            "one list, not one per namespace: {requests:?}"
        );
        let uri = &requests[0];
        assert!(
            uri.starts_with("/api/v1/namespaces/ferriscd-system/secrets?"),
            "the read must be namespaced to the control plane: {uri}"
        );
        assert!(
            uri.contains("labelSelector=ferriscd.io%2Fsecret-type")
                || uri.contains("labelSelector=ferriscd.io/secret-type"),
            "the read must be label-filtered, exactly like the controller's: {uri}"
        );
        for forbidden in ["team-a", "/api/v1/secrets"] {
            assert!(
                !uri.contains(forbidden),
                "the export must never read {forbidden:?}: {uri}"
            );
        }
    }

    /// A `kube::Client` that records every request URI and answers all of them with `secrets` (serialized
    /// as a `SecretList`). No cluster, no socket: `tower::service_fn` is the whole transport.
    fn recording_client(
        secrets: &Value,
    ) -> (kube::Client, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = requests.clone();
        let body = serde_json::to_vec(&serde_json::json!({
            "apiVersion": "v1",
            "kind": "SecretList",
            "metadata": {"resourceVersion": "1"},
            "items": secrets,
        }))
        .expect("a serializable body");
        let client = kube::Client::new(
            tower::service_fn(move |request: http::Request<kube::client::Body>| {
                let recorder = recorder.clone();
                let body = body.clone();
                async move {
                    recorder
                        .lock()
                        .expect("the request log is not poisoned")
                        .push(request.uri().to_string());
                    let response = http::Response::builder()
                        .status(200)
                        .header("content-type", "application/json")
                        .body(kube::client::Body::from(body))
                        .expect("a valid response");
                    Ok::<_, std::convert::Infallible>(response)
                }
            }),
            CONTROL_PLANE_NAMESPACE,
        );
        (client, requests)
    }

    #[test]
    fn missing_namespaces_are_computed_from_the_plan() {
        let required = BTreeSet::from(["team-a".to_owned(), "team-b".to_owned()]);
        let existing = BTreeSet::from(["team-b".to_owned()]);
        assert_eq!(
            missing_namespaces(&required, &existing),
            vec!["team-a".to_owned()]
        );
        assert!(missing_namespaces(&required, &required).is_empty());
    }

    /// Every apply is `force: false` (the SSA safety default) and a dry run adds only `dryRun`.
    #[test]
    fn a_restore_never_forces_and_a_dry_run_only_sets_dry_run() {
        let dry = restore_patch_params(true);
        assert!(
            dry.dry_run,
            "a --dry-run restore asks the API server to dry-run"
        );
        assert!(!dry.force, "a restore must never force field ownership");
        assert_eq!(dry.field_manager.as_deref(), Some(RESTORE_FIELD_MANAGER));

        let real = restore_patch_params(false);
        assert!(!real.dry_run);
        assert!(!real.force);
        assert_eq!(real.field_manager.as_deref(), Some(RESTORE_FIELD_MANAGER));
        assert_ne!(
            RESTORE_FIELD_MANAGER,
            ferriscd_engine::default_field_manager(),
            "a restore must not claim the controller's field manager"
        );
        assert_eq!(ConflictPolicy::default(), ConflictPolicy::Abort);
    }

    /// Both bounds are enforced on the way in *and* on the way out.
    #[test]
    fn the_bundle_size_and_item_count_are_bounded() {
        let bundle = build_bundle(input(vec![app_project("payments", "team-a")], Vec::new()))
            .expect("builds");

        // Item bound: one more than allowed.
        let mut too_many = bundle.clone();
        too_many.resources = (0..=MAX_BUNDLE_ITEMS)
            .map(|index| {
                let mut resource = app_project(&format!("project-{index}"), "team-a");
                resource["metadata"]["name"] = json!(format!("project-{index}"));
                resource
            })
            .collect();
        too_many.integrity.digest = bundle_digest(&too_many).expect("digest");
        let text = bundle_yaml(&too_many);
        let error = parse_bundle(&text).expect_err("an oversized bundle is refused");
        assert!(format!("{error}").contains("item limit"), "{error}");

        // Byte bound: checked before the YAML parser sees the document.
        let oversized = "x".repeat(MAX_BUNDLE_BYTES + 1);
        let error = parse_bundle(&oversized).expect_err("an oversized document is refused");
        assert!(format!("{error}").contains("byte limit"), "{error}");

        // The export half refuses to *produce* one, too.
        let many = (0..=MAX_BUNDLE_ITEMS)
            .map(|index| app_project(&format!("project-{index}"), "team-a"))
            .collect::<Vec<_>>();
        let error = build_bundle(input(many, Vec::new())).expect_err("export bounds the count");
        assert!(format!("{error}").contains("item limit"), "{error}");
    }

    /// A document that is YAML but not a bundle, and a bundle that is not YAML at all, are both
    /// refused without quoting the file (it may name credentials).
    #[test]
    fn a_non_bundle_document_is_refused_content_free() {
        let error = parse_bundle("apiVersion: v1\nkind: Secret\ndata:\n  password: c2VjcmV0\n")
            .expect_err("a plain Secret is not a bundle");
        let rendered = format!("{error}");
        assert!(
            rendered.contains("not a readable FerrisCD backup"),
            "{rendered}"
        );
        assert!(!rendered.contains("c2VjcmV0"), "{rendered}");

        assert!(parse_bundle("key: [unterminated").is_err());
        // Duplicate keys are refused by the engine's parser budgets, not silently last-wins.
        assert!(parse_bundle("schemaVersion: a\nschemaVersion: b\n").is_err());
    }

    /// The CLI surface: `--on-conflict` parses, and the defaults are the safe ones.
    #[test]
    fn the_cli_defaults_are_the_safe_ones() {
        use clap::Parser as _;

        #[derive(Debug, clap::Parser)]
        #[command(name = "ferriscd")]
        struct Harness {
            #[command(subcommand)]
            command: BackupCommand,
        }

        let parsed = Harness::try_parse_from(["ferriscd", "restore", "bundle.yaml"])
            .expect("`restore <bundle>` parses");
        match parsed.command {
            BackupCommand::Restore(args) => {
                assert_eq!(args.bundle, PathBuf::from("bundle.yaml"));
                assert!(
                    !args.dry_run,
                    "a restore is real unless --dry-run is passed"
                );
                assert_eq!(args.on_conflict, ConflictPolicy::Abort);
                assert!(!args.allow_missing_secrets);
            }
            other => panic!("expected restore, got {other:?}"),
        }

        let parsed = Harness::try_parse_from([
            "ferriscd",
            "restore",
            "bundle.yaml",
            "--dry-run",
            "--on-conflict",
            "skip",
            "--allow-missing-secrets",
        ])
        .expect("the flags parse");
        match parsed.command {
            BackupCommand::Restore(args) => {
                assert!(args.dry_run);
                assert_eq!(args.on_conflict, ConflictPolicy::Skip);
                assert!(args.allow_missing_secrets);
            }
            other => panic!("expected restore, got {other:?}"),
        }

        let parsed = Harness::try_parse_from([
            "ferriscd",
            "export",
            "--control-plane-namespace",
            "ferriscd-system",
            "-n",
            "team-a",
        ])
        .expect("`export` parses");
        match parsed.command {
            BackupCommand::Export(args) => {
                assert_eq!(args.control_plane_namespace, CONTROL_PLANE_NAMESPACE);
                assert_eq!(args.namespace.as_deref(), Some("team-a"));
                assert!(args.output.is_none(), "stdout is the default sink");
                assert!(!args.skip_secret_inventory);
                assert!(
                    args.exported_at.is_none(),
                    "the timestamp is the current time unless --exported-at pins it"
                );
            }
            other => panic!("expected export, got {other:?}"),
        }

        let parsed = Harness::try_parse_from([
            "ferriscd",
            "export",
            "--exported-at",
            "2026-01-01T00:00:00Z",
        ])
        .expect("--exported-at parses");
        match parsed.command {
            BackupCommand::Export(args) => {
                assert_eq!(args.exported_at.as_deref(), Some("2026-01-01T00:00:00Z"));
            }
            other => panic!("expected export, got {other:?}"),
        }
    }

    /// **Trap guard (H1).** A bundle names the cluster's credentials, so it must be `0600` from the
    /// first byte — not `0666 & ~umask` followed by a `chmod` that may fail — and a symlink at the
    /// output path must never be followed (a hardlink is not detectable, but the rename means it is
    /// never written through either).
    #[cfg(unix)]
    #[test]
    fn a_bundle_file_is_private_from_the_first_byte_and_never_written_through_a_symlink() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        fn mode_of(path: &Path) -> u32 {
            std::fs::metadata(path)
                .expect("the file exists")
                .permissions()
                .mode()
                & 0o777
        }

        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("bundle.yaml");

        write_bundle_file(&path, "schemaVersion: ferriscd.io/backup/v1\n")
            .expect("the bundle is written");
        assert_eq!(
            std::fs::read_to_string(&path).expect("the bundle is readable"),
            "schemaVersion: ferriscd.io/backup/v1\n"
        );
        assert_eq!(
            mode_of(&path),
            0o600,
            "a bundle must never be readable by another user"
        );

        // A `--output` that already exists with a wider mode is *replaced* by a `0600` file, not
        // `chmod`ed afterwards: the rename installs the scratch inode (and therefore its mode), so the
        // old `0644` cannot survive and there is no window in which the new bundle is readable.
        std::fs::write(&path, "stale\n").expect("the stale bundle is written");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("the mode is widened");
        write_bundle_file(&path, "fresh\n").expect("the bundle is rewritten");
        assert_eq!(
            mode_of(&path),
            0o600,
            "a pre-existing 0644 bundle must be replaced by a 0600 one"
        );
        assert_eq!(std::fs::read_to_string(&path).expect("readable"), "fresh\n");

        // A hardlink is not a symlink and cannot be detected as one, but the rename makes it harmless:
        // only *this* directory entry is replaced, so the other name keeps the old content and its own
        // (wider) mode. Nothing is ever written through it, and no chmod can follow it.
        std::fs::write(&path, "old\n").expect("the old bundle is written");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("the mode is widened");
        let hardlink = directory.path().join("hardlink.yaml");
        std::fs::hard_link(&path, &hardlink).expect("the hardlink is created");
        write_bundle_file(&path, "new\n").expect("the bundle is rewritten");
        assert_eq!(std::fs::read_to_string(&path).expect("readable"), "new\n");
        assert_eq!(
            mode_of(&path),
            0o600,
            "the bundle's own name is the file this command made private"
        );
        assert_eq!(
            std::fs::read_to_string(&hardlink).expect("the other link is readable"),
            "old\n",
            "a hardlink must keep the old inode: the bundle is never written through it"
        );
        assert_eq!(
            mode_of(&hardlink),
            0o644,
            "the mode this command applies must not land on the other name either"
        );
        std::fs::remove_file(&hardlink).expect("the hardlink is removed");

        // A symlink at the output path is refused and its target is untouched: a write through it
        // would land the bundle (and the 0600 this command asks for) in whatever file the link
        // points at — a world-readable config file, for instance.
        let target = directory.path().join("world-readable-config.yaml");
        std::fs::write(&target, "untouched\n").expect("the link target is written");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644))
            .expect("the target mode is widened");
        let link = directory.path().join("link.yaml");
        symlink(&target, &link).expect("the symlink is created");

        let error = write_bundle_file(&link, "bundle\n").expect_err("a symlink is refused");
        assert!(format!("{error}").contains("symbolic link"), "{error}");
        assert_eq!(
            std::fs::read_to_string(&target).expect("the target is readable"),
            "untouched\n",
            "the bundle must never be written through a symlink"
        );
        assert_eq!(
            mode_of(&target),
            0o644,
            "the mode this command applies must not land on the symlink's target"
        );
        assert!(
            std::fs::symlink_metadata(&link)
                .expect("link metadata")
                .file_type()
                .is_symlink(),
            "the symlink itself must be left alone"
        );

        // Nothing else is left in the directory: the scratch file was renamed away or never created.
        let mut names = std::fs::read_dir(directory.path())
            .expect("the directory is readable")
            .map(|entry| {
                entry
                    .expect("a directory entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(
            names,
            vec![
                "bundle.yaml".to_owned(),
                "link.yaml".to_owned(),
                "world-readable-config.yaml".to_owned(),
            ],
            "a failed write must not leave a scratch file behind"
        );
    }

    /// `ByteString` is only used to prove the fixture carries real (base64) `data`; it keeps the
    /// test honest if `Secret` ever stops accepting plain JSON strings.
    #[test]
    fn the_fixture_secret_really_carries_bytes() {
        let secret: Secret = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "x", "namespace": "y"},
            "data": {"password": "c2VjcmV0"},
        }))
        .expect("parses");
        let data = secret.data.expect("data");
        assert_eq!(data.get("password"), Some(&ByteString(b"secret".to_vec())));
    }
}
