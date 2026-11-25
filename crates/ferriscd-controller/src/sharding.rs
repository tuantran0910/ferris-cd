//! Opt-in deterministic `Application` sharding (`T13.3`).
//!
//! Active/standby election ([`crate::leader_election`]) keeps exactly one replica busy and every
//! other one idle. That is the right shape for correctness, and the wrong shape for a control plane
//! with thousands of `Application`s: the single leader becomes CPU/IO bound while its standbys do
//! nothing. Sharding partitions the *work*: replica `i` of `N` reconciles only the `Application`s
//! whose shard is `i`.
//!
//! ## Why the assignment must be deterministic and dependency-free
//!
//! `shard = sha256(domain, namespace, name) % total_shards` is computed **locally, per watch event**,
//! from nothing but the object's own identity. There is no coordinator, no membership list and no
//! rebalancing protocol, which means:
//!
//! * every replica computes the same answer for the same `Application` without talking to anyone —
//!   a restart, a rolling update or a rescheduled pod cannot change who owns what;
//! * the assignment survives the API server, the shard count and the Go/`serde` JSON round-trip,
//!   because it depends on no state at all;
//! * the cost is one short hash per watch event, so the filter can run *before* the reconcile is
//!   queued (see [`ShardPredicate`]) instead of after a full pass has already been scheduled.
//!
//! The hash is the crate's existing dependency-free SHA-256
//! (`ferriscd_engine::manifest::cache::sha256_hex`, FIPS 180-4, pinned by published known-answer
//! vectors); no new package is involved and no cryptographic property is relied on — the digest only
//! has to spread names evenly and stay stable.
//!
//! ## Sharding is *per-shard* leader election, never a replacement for it
//!
//! A shard is only a work partition. Two replicas that were both started with `--shard-id 0` would
//! reconcile the same `Application`s twice — the exact double-apply the `T13.2` lease exists to
//! prevent — and a *single* lease shared by all shards would make shards 1..N unreachable, because
//! only one replica would ever hold it. Both mistakes are refused at startup
//! ([`ShardingConfigError::RequiresLeaderElection`],
//! [`ShardingConfigError::LeaseNameConflict`]):
//!
//! * sharding **requires** `--leader-election`, and
//! * with sharding on, the `Lease` is always the per-shard
//!   [`ferriscd-leader-shard-<id>`](SHARD_LEASE_PREFIX) — the single-leader default
//!   (`ferriscd-controller-leader`) is refused.
//!
//! So the supported deployment is `N` replicas, each with a distinct `--shard-id` and the same
//! `--total-shards`: every replica leads *its own* lease and reconciles its own slice. `N = 1` is
//! exactly "the shard is everything", which is why the default (no flags at all) is unchanged and
//! needs no `leases` RBAC it did not already have.
//!
//! ## What sharding does *not* do
//!
//! * It is not rebalancing. Changing `--total-shards` re-partitions every `Application` on the next
//!   watch event of every replica: that is safe (each `Application` is still owned exactly once, and
//!   `ferriscd.io/tracking-id` ownership is unchanged), but it is a fleet-wide restart, so treat the
//!   shard count as a capacity decision, not a knob to tune per replica.
//! * It does not partition `AppProject`s, cluster registrations or repository credentials: those are
//!   cheap, shared, read-on-demand lookups.
//! * It does not shard the *status* writer or the queue: each replica still owns its own
//!   [`kube_runtime::Controller`] per watched namespace, and filters its stream.

use std::fmt;

use ferriscd_crd::Application;
use kube::ResourceExt;

/// Prefix of the per-shard `Lease` name (`ferriscd-leader-shard-<id>`).
pub const SHARD_LEASE_PREFIX: &str = "ferriscd-leader-shard-";

/// Environment variable carrying `--shard-id`.
///
/// Useful for a `StatefulSet`, where the ordinal is available as
/// `metadata.name`/`$(POD_NAME)` and nobody wants to template `N` copies of a manifest.
pub const SHARD_ID_ENV: &str = "FERRISCD_SHARD_ID";

/// Environment variable carrying `--total-shards`.
pub const TOTAL_SHARDS_ENV: &str = "FERRISCD_TOTAL_SHARDS";

/// Domain separator mixed into every hash.
///
/// Versioned so a future change of key layout is a *different* assignment rather than a silent
/// reshuffle of a running fleet, and distinct from every other digest FerrisCD computes.
const KEY_DOMAIN: &str = "ferriscd/shard/v1";

/// The `--shard-id`/`--total-shards` pair as the operator supplied it, before validation.
///
/// Kept as a pair of `Option`s (rather than a validated [`Sharding`]) so a *half*-specified
/// configuration is representable and can be rejected with a message naming the missing flag,
/// instead of defaulting one of the two and silently sharding a fleet wrongly.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct ShardOptions {
    /// `--shard-id`: this replica's zero-based shard index.
    pub shard_id: Option<u32>,
    /// `--total-shards`: how many shards the fleet is split into.
    pub total_shards: Option<u32>,
}

impl ShardOptions {
    /// Builds the pair from explicit values.
    #[must_use]
    pub fn new(shard_id: Option<u32>, total_shards: Option<u32>) -> Self {
        Self {
            shard_id,
            total_shards,
        }
    }

    /// Resolves and validates the pair (`T13.3`).
    ///
    /// # Errors
    ///
    /// See [`from_values`].
    pub fn resolve(&self) -> Result<Option<Sharding>, ShardingConfigError> {
        from_values(self.shard_id, self.total_shards)
    }
}

/// A validated shard: replica `shard_id` of `total_shards`.
///
/// Only constructible through [`Sharding::new`] (or [`from_values`]), so `shard_id < total_shards`
/// and `total_shards >= 1` hold for every value that reaches the watch filter or the lease name.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sharding {
    shard_id: u32,
    total_shards: u32,
}

impl Sharding {
    /// Validates `shard_id` inside `0..total_shards`.
    ///
    /// # Errors
    ///
    /// [`ShardingConfigError::TotalShardsZero`] (nothing to shard into) or
    /// [`ShardingConfigError::ShardIdOutOfRange`] (`shard_id >= total_shards`): a shard index that
    /// cannot exist would make the replica reconcile *nothing*, silently.
    pub fn new(shard_id: u32, total_shards: u32) -> Result<Self, ShardingConfigError> {
        if total_shards == 0 {
            return Err(ShardingConfigError::TotalShardsZero { shard_id });
        }
        if shard_id >= total_shards {
            return Err(ShardingConfigError::ShardIdOutOfRange {
                shard_id,
                total_shards,
            });
        }
        Ok(Self {
            shard_id,
            total_shards,
        })
    }

    /// This replica's shard index.
    #[must_use]
    pub fn shard_id(&self) -> u32 {
        self.shard_id
    }

    /// How many shards the fleet is split into.
    #[must_use]
    pub fn total_shards(&self) -> u32 {
        self.total_shards
    }

    /// The `Lease` this shard's leader holds (`ferriscd-leader-shard-<id>`).
    ///
    /// Derived, never configured: a shard cannot be pointed at another shard's lease, which is what
    /// makes "sharding plus a single shared lease" unrepresentable (see the module docs).
    #[must_use]
    pub fn lease_name(&self) -> String {
        shard_lease_name(self.shard_id)
    }

    /// Whether `namespace`/`name` belongs to this shard.
    #[must_use]
    pub fn owns(&self, namespace: &str, name: &str) -> bool {
        shard_of(namespace, name, self.total_shards) == self.shard_id
    }

    /// Whether `app` belongs to this shard.
    ///
    /// The identity is the object's **own** namespace and name (what the API server uses to address
    /// it), never `spec.destination.namespace`: two `Application`s deploying into one namespace are
    /// still two units of work and must be split independently.
    #[must_use]
    pub fn owns_application(&self, app: &Application) -> bool {
        let namespace = app.namespace().unwrap_or_default();
        let name = app.name_any();
        self.owns(&namespace, &name)
    }
}

impl fmt::Debug for Sharding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "shard {}/{}", self.shard_id, self.total_shards)
    }
}

impl fmt::Display for Sharding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "shard {}/{}", self.shard_id, self.total_shards)
    }
}

/// The per-shard `Lease` name for `shard_id`.
#[must_use]
pub fn shard_lease_name(shard_id: u32) -> String {
    format!("{SHARD_LEASE_PREFIX}{shard_id}")
}

/// The shard `namespace`/`name` belongs to, for a fleet of `total_shards`.
///
/// `sha256("ferriscd/shard/v1" NUL namespace NUL name) % total_shards`, reduced over the **whole**
/// 256-bit digest (not a truncated prefix).
///
/// The key is NUL-separated on purpose: Kubernetes namespaces and names are DNS-1123 labels, which
/// cannot contain a NUL, so `("a", "b\0c")` cannot collide with `("a\0b", "c")`.
///
/// `total_shards == 0` cannot be constructed through [`Sharding`]; it is treated as a single shard
/// here so the function is total and never divides by zero.
#[must_use]
pub fn shard_of(namespace: &str, name: &str, total_shards: u32) -> u32 {
    if total_shards <= 1 {
        return 0;
    }
    let mut key = Vec::with_capacity(KEY_DOMAIN.len() + namespace.len() + name.len() + 2);
    key.extend_from_slice(KEY_DOMAIN.as_bytes());
    key.push(0);
    key.extend_from_slice(namespace.as_bytes());
    key.push(0);
    key.extend_from_slice(name.as_bytes());
    let digest = ferriscd_engine::manifest::cache::sha256_hex(&key);
    reduce_hex(&digest, total_shards)
}

/// Reduces a lowercase-hex digest modulo `modulus`, over every digit (Horner's rule).
///
/// `acc < modulus <= u32::MAX`, so `acc * 16 + 15 < 2^36` — no overflow is possible in a `u64`.
fn reduce_hex(digest: &str, modulus: u32) -> u32 {
    let modulus = u64::from(modulus.max(1));
    let remainder = digest
        .bytes()
        .filter_map(hex_digit)
        .fold(0_u64, |acc, digit| (acc * 16 + u64::from(digit)) % modulus);
    // `remainder < modulus <= u32::MAX`, so the conversion always succeeds.
    u32::try_from(remainder).unwrap_or(0)
}

/// The value of one lowercase hex digit.
fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Validates a `--shard-id`/`--total-shards` pair.
///
/// Returns `Ok(None)` when neither is set — the default single-replica behaviour, unchanged — and
/// rejects a half-specified pair: defaulting the missing half would either shard a fleet into one
/// shard (silently doing nothing) or spread a replica over a shard count nobody asked for.
///
/// # Errors
///
/// [`ShardingConfigError::MissingShardId`], [`ShardingConfigError::MissingTotalShards`],
/// [`ShardingConfigError::TotalShardsZero`], [`ShardingConfigError::ShardIdOutOfRange`].
pub fn from_values(
    shard_id: Option<u32>,
    total_shards: Option<u32>,
) -> Result<Option<Sharding>, ShardingConfigError> {
    match (shard_id, total_shards) {
        (None, None) => Ok(None),
        (Some(shard_id), None) => Err(ShardingConfigError::MissingTotalShards { shard_id }),
        (None, Some(total_shards)) => Err(ShardingConfigError::MissingShardId { total_shards }),
        (Some(shard_id), Some(total_shards)) => Ok(Some(Sharding::new(shard_id, total_shards)?)),
    }
}

/// The pure half of [`resolve`]: parses two raw values (flag or environment) and validates them.
///
/// A blank value means "not set", so `FERRISCD_SHARD_ID=""` from an unset `ConfigMap` key does not
/// become shard `0`.
///
/// # Errors
///
/// [`ShardingConfigError::InvalidValue`] for a non-numeric value, plus everything [`from_values`]
/// rejects.
pub fn from_env_values(
    shard_id: Option<&str>,
    total_shards: Option<&str>,
) -> Result<Option<Sharding>, ShardingConfigError> {
    from_values(
        parse_value(SHARD_ID_ENV, shard_id)?,
        parse_value(TOTAL_SHARDS_ENV, total_shards)?,
    )
}

/// Resolves the sharding configuration from explicit flag values, falling back to
/// [`SHARD_ID_ENV`]/[`TOTAL_SHARDS_ENV`].
///
/// The flags win per field; an explicit flag is never overridden by the environment.
///
/// # Errors
///
/// See [`from_env_values`].
pub fn resolve(
    shard_id: Option<u32>,
    total_shards: Option<u32>,
) -> Result<Option<Sharding>, ShardingConfigError> {
    let shard_id_env = std::env::var(SHARD_ID_ENV).ok();
    let total_shards_env = std::env::var(TOTAL_SHARDS_ENV).ok();
    let shard_id = match shard_id {
        Some(value) => Some(value),
        None => parse_value(SHARD_ID_ENV, shard_id_env.as_deref())?,
    };
    let total_shards = match total_shards {
        Some(value) => Some(value),
        None => parse_value(TOTAL_SHARDS_ENV, total_shards_env.as_deref())?,
    };
    from_values(shard_id, total_shards)
}

/// Parses one raw value: absent or blank is `None`.
fn parse_value(name: &str, value: Option<&str>) -> Result<Option<u32>, ShardingConfigError> {
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        None => Ok(None),
        Some(value) => {
            value
                .parse::<u32>()
                .map(Some)
                .map_err(|_| ShardingConfigError::InvalidValue {
                    name: name.to_owned(),
                    value: value.to_owned(),
                })
        }
    }
}

/// The shard decision, as a predicate the watch stream can apply.
///
/// This is the *only* shard filter in the data path: it runs on the applied-object stream, before
/// the `kube_runtime::Controller` schedules work, so an `Application` belonging to another shard
/// costs nothing (no reconcile, no queue entry, no status write) — see
/// [`crate::controller::build_controllers`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardPredicate {
    shard: Sharding,
}

impl ShardPredicate {
    /// Wraps a validated shard.
    #[must_use]
    pub fn new(shard: Sharding) -> Self {
        Self { shard }
    }

    /// The shard this predicate keeps.
    #[must_use]
    pub fn shard(&self) -> Sharding {
        self.shard
    }

    /// Whether `app` is this replica's work.
    #[must_use]
    pub fn matches(&self, app: &Application) -> bool {
        self.shard.owns_application(app)
    }

    /// Whether a watch item may reach the controller's queue.
    ///
    /// **Watch errors always pass**: a stream error is not an `Application` and must never be
    /// mistaken for somebody else's work, or a broken watch would be silently swallowed.
    #[must_use]
    pub fn keeps<E>(&self, item: &Result<Application, E>) -> bool {
        match item {
            Ok(app) => self.matches(app),
            Err(_) => true,
        }
    }
}

/// Builds the [`ShardPredicate`] for `shard`.
#[must_use]
pub fn shard_predicate(shard: Sharding) -> ShardPredicate {
    ShardPredicate::new(shard)
}

/// Sharding configuration errors (all terminal: the process must not start).
///
/// Every message names the flag the operator has to change, because a controller that starts with a
/// half-valid shard configuration looks healthy and simply reconciles the wrong slice.
#[derive(Debug, thiserror::Error)]
pub enum ShardingConfigError {
    /// `--shard-id` was given without `--total-shards`.
    #[error(
        "--shard-id {shard_id} needs --total-shards: the shard index is meaningless without the \
         shard count, and a default would silently partition the fleet the wrong way"
    )]
    MissingTotalShards {
        /// The supplied shard index.
        shard_id: u32,
    },

    /// `--total-shards` was given without `--shard-id`.
    #[error(
        "--total-shards {total_shards} needs --shard-id: every replica must know which slice it \
         owns, or the replicas overlap"
    )]
    MissingShardId {
        /// The supplied shard count.
        total_shards: u32,
    },

    /// `--total-shards 0`.
    #[error("--total-shards must be at least 1 (got 0 with --shard-id {shard_id})")]
    TotalShardsZero {
        /// The supplied shard index.
        shard_id: u32,
    },

    /// `--shard-id` is not inside `0..total_shards`.
    #[error(
        "--shard-id {shard_id} is out of range for {total_shards} shard(s): it must be less than \
         --total-shards (0..{total_shards}), otherwise this replica would watch nothing at all"
    )]
    ShardIdOutOfRange {
        /// The supplied shard index.
        shard_id: u32,
        /// The supplied shard count.
        total_shards: u32,
    },

    /// A sharding environment variable is not a non-negative integer.
    #[error("{name} must be a non-negative integer (got {value:?})")]
    InvalidValue {
        /// The variable (or flag) name.
        name: String,
        /// The rejected value.
        value: String,
    },

    /// Sharding was requested without leader election.
    #[error(
        "sharding needs --leader-election: with --shard-id {shard_id}/{total_shards} two replicas \
         can be given the same shard id, and without a per-shard Lease they would both reconcile it \
         (double applies). Enable it and each shard gets its own \
         `{prefix}<id>` Lease"
    )]
    RequiresLeaderElection {
        /// The supplied shard index.
        shard_id: u32,
        /// The supplied shard count.
        total_shards: u32,
        /// The per-shard `Lease` prefix, rendered into the message.
        prefix: &'static str,
    },

    /// Sharding was combined with the single-leader `Lease` (or any other lease name).
    #[error(
        "sharding uses the per-shard Lease {expected:?}, but --leader-election-lease-name is \
         {configured:?}: one shared Lease would make only one replica a leader and leave the other \
         shards unreconciled"
    )]
    LeaseNameConflict {
        /// The lease name the shard must use.
        expected: String,
        /// The lease name the operator configured.
        configured: String,
    },
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use ferriscd_crd::application::{
        DEFAULT_REQUEUE_AFTER_SECONDS, DEFAULT_REVISION_HISTORY_LIMIT,
    };
    use ferriscd_crd::{
        ApplicationSpec, DEFAULT_PROJECT_NAME, DestinationSpec, GitSourceSpec, RendererSpec,
        SourceSpec,
    };

    use super::*;

    /// The roadmap's verification set: 1,000 synthetic `(namespace, name)` pairs.
    ///
    /// 17 namespaces × ~59 names each, so a real fleet's shape (many names per namespace, a handful
    /// of namespaces) is represented rather than 1,000 names in one namespace.
    fn synthetic_pairs() -> Vec<(String, String)> {
        (0..1_000)
            .map(|index| (format!("team-{}", index % 17), format!("app-{index}")))
            .collect()
    }

    fn assignment(
        pairs: &[(String, String)],
        total_shards: u32,
    ) -> BTreeMap<(String, String), u32> {
        pairs
            .iter()
            .map(|(namespace, name)| {
                (
                    (namespace.clone(), name.clone()),
                    shard_of(namespace, name, total_shards),
                )
            })
            .collect()
    }

    /// **`T13.3` verification:** for `N = 1, 3, 5` the assignment is 100% disjoint, covers every
    /// `Application` exactly once, and leaves no shard empty.
    #[test]
    fn a_thousand_applications_are_partitioned_disjointly_and_completely() {
        let pairs = synthetic_pairs();
        assert_eq!(pairs.len(), 1_000);

        for total_shards in [1_u32, 3, 5] {
            let assignment = assignment(&pairs, total_shards);
            assert_eq!(
                assignment.len(),
                1_000,
                "N={total_shards}: every pair must be assigned"
            );

            // Disjoint: no pair appears in two shards, and no shard repeats a pair.
            let mut seen: BTreeMap<u32, BTreeSet<(String, String)>> = BTreeMap::new();
            for (pair, shard) in &assignment {
                assert!(
                    *shard < total_shards,
                    "N={total_shards}: {pair:?} landed in shard {shard}, outside 0..{total_shards}"
                );
                assert!(
                    seen.entry(*shard).or_default().insert(pair.clone()),
                    "N={total_shards}: {pair:?} was assigned twice"
                );
            }
            // Complete: the shards' contents are exactly the input, once each.
            let union: BTreeSet<(String, String)> = seen.values().flatten().cloned().collect();
            assert_eq!(
                union,
                pairs.iter().cloned().collect::<BTreeSet<_>>(),
                "N={total_shards}: the union of the shards must be exactly the input set"
            );
            let total: usize = seen.values().map(BTreeSet::len).sum();
            assert_eq!(total, 1_000, "N={total_shards}: an Application was lost");

            // Non-vacuous: every shard actually exists, i.e. the filter cannot be a no-op that
            // keeps everything (N=1) or drops a shard's applications entirely (N>1).
            assert_eq!(
                seen.len(),
                usize::try_from(total_shards).expect("a small shard count"),
                "N={total_shards}: every shard must own at least one Application"
            );
            for (shard, members) in &seen {
                assert!(
                    members.len()
                        >= 1_000 / usize::try_from(total_shards).expect("shard count") / 4,
                    "N={total_shards} shard {shard} holds only {} of 1,000 Applications: the hash \
                     is not spreading",
                    members.len()
                );
            }
        }
    }

    /// The assignment is a pure function of `(namespace, name, N)`: recomputing it, in a different
    /// order, yields the same map — so no replica depends on iteration order, arrival order or
    /// process state.
    #[test]
    fn the_assignment_is_stable_across_runs_and_reordering() {
        let pairs = synthetic_pairs();
        let baseline = assignment(&pairs, 3);

        // A different insertion order: reversed, then interleaved.
        let mut reordered: Vec<(String, String)> = pairs.iter().rev().cloned().collect();
        reordered.rotate_left(37);
        assert_ne!(reordered, pairs, "the second order must actually differ");
        assert_eq!(
            assignment(&reordered, 3),
            baseline,
            "the mapping must not depend on the order the Applications are observed in"
        );

        // And a second, independent computation for every pair.
        for (pair, shard) in &baseline {
            assert_eq!(
                shard_of(&pair.0, &pair.1, 3),
                *shard,
                "shard_of must be deterministic for {pair:?}"
            );
        }
    }

    /// **Known-answer vectors**, computed independently with
    /// `python3 -c 'hashlib.sha256(b"ferriscd/shard/v1\0<ns>\0<name>").hexdigest()'` and reduced
    /// modulo N. They pin the *key layout*: a silently changed separator, domain tag or reduction
    /// would reshuffle every running fleet on upgrade, so it must fail here first.
    #[test]
    fn the_shard_key_layout_matches_an_independently_computed_sha256() {
        for (namespace, name, shard_three, shard_five) in [
            ("team-0", "app-0", 1, 0),
            ("ferriscd-system", "demo-app", 0, 0),
            ("team-a", "app", 0, 3),
            ("team-17", "app-999", 1, 2),
        ] {
            assert_eq!(
                shard_of(namespace, name, 3),
                shard_three,
                "{namespace}/{name} mod 3"
            );
            assert_eq!(
                shard_of(namespace, name, 5),
                shard_five,
                "{namespace}/{name} mod 5"
            );
        }
        // The digest is reduced over all 256 bits: the shard is not the low (or high) nibble of a
        // truncated prefix. `team-a/app` and `team-b/app` differ at N=5, so the namespace is part of
        // the key and not just the name.
        assert_ne!(shard_of("team-a", "app", 5), shard_of("team-b", "app", 5));
        // One shard is always shard 0 for every input.
        for index in 0..100 {
            assert_eq!(shard_of("team-a", &format!("app-{index}"), 1), 0);
        }
    }

    fn application(namespace: &str, name: &str) -> Application {
        let spec = ApplicationSpec {
            project: DEFAULT_PROJECT_NAME.to_owned(),
            service_account_name: None,
            source: SourceSpec {
                git: GitSourceSpec {
                    repo_url: "https://example.com/repo.git".to_owned(),
                    target_revision: "HEAD".to_owned(),
                    path: String::new(),
                },
                renderer: RendererSpec::default(),
            },
            destination: DestinationSpec {
                cluster: "in-cluster".to_owned(),
                namespace: "payments".to_owned(),
            },
            sync_policy: None,
            ignore_differences: Vec::new(),
            requeue_after_seconds: DEFAULT_REQUEUE_AFTER_SECONDS,
            revision_history_limit: DEFAULT_REVISION_HISTORY_LIMIT,
        };
        let mut app = Application::new(name, spec);
        app.metadata.namespace = Some(namespace.to_owned());
        app
    }

    /// The predicate keys on the object's **own** namespace/name, never on
    /// `spec.destination.namespace`.
    #[test]
    fn the_predicate_keys_on_the_applications_own_identity() {
        let shard = Sharding::new(0, 2).expect("valid shard");
        let owned = shard.owns("ferriscd-system", "demo-app");
        assert!(owned, "the fixture must be in shard 0 for this assertion");
        assert!(
            shard_predicate(shard).matches(&application("ferriscd-system", "demo-app")),
            "an Application is owned exactly when (metadata.namespace, metadata.name) hashes to it"
        );
        // Both Applications deploy into the same destination namespace; their identity still
        // decides, so one of them belongs to the other shard.
        let other = Sharding::new(1, 2).expect("valid shard");
        assert!(
            other.owns_application(&application("ferriscd-system", "demo-app"))
                != shard.owns_application(&application("ferriscd-system", "demo-app")),
            "exactly one of the two shards owns the Application"
        );
        assert_eq!(shard_predicate(shard).shard(), shard);
    }

    /// **Watch errors always pass:** a shard filter must never swallow a stream error.
    #[test]
    fn shard_errors_are_never_filtered() {
        let shard = Sharding::new(1, 3).expect("valid shard");
        let predicate = shard_predicate(shard);
        let error: Result<Application, std::io::Error> = Err(std::io::Error::other("watch died"));
        assert!(
            predicate.keeps(&error),
            "a watch error must reach the controller, not be mistaken for a foreign shard"
        );
        let app = application("ferriscd-system", "demo-app");
        let item: Result<Application, std::io::Error> = Ok(app.clone());
        assert_eq!(predicate.keeps(&item), shard.owns_application(&app));
    }

    #[test]
    fn a_shard_names_its_own_lease() {
        let shard = Sharding::new(2, 5).expect("valid shard");
        assert_eq!(shard.lease_name(), "ferriscd-leader-shard-2");
        assert_eq!(shard_lease_name(0), "ferriscd-leader-shard-0");
        // The name must be a DNS-1123 subdomain, or every `Lease` write would 404/422.
        for index in [0_u32, 7, 4_095] {
            let name = shard_lease_name(index);
            assert!(
                name.len() <= 63,
                "{name} must be a DNS label, not a long name: {} chars",
                name.len()
            );
            assert!(
                name.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "{name} must be a valid DNS subdomain"
            );
        }
        assert_eq!(shard.shard_id(), 2);
        assert_eq!(shard.total_shards(), 5);
        assert_eq!(shard.to_string(), "shard 2/5");
        assert_eq!(format!("{shard:?}"), "shard 2/5");
    }

    /// **Trap guard (`T13.3`):** a half-specified or impossible sharding configuration is rejected
    /// instead of being defaulted into a fleet that silently watches nothing (or everything).
    #[test]
    fn invalid_sharding_configurations_are_rejected() {
        assert_eq!(
            from_values(None, None).expect("no flags is the default"),
            None
        );

        let err = from_values(Some(0), None).expect_err("a shard id without a count is invalid");
        assert!(matches!(
            err,
            ShardingConfigError::MissingTotalShards { shard_id: 0 }
        ));
        assert!(err.to_string().contains("--total-shards"), "{err}");

        let err = from_values(None, Some(3)).expect_err("a count without a shard id is invalid");
        assert!(matches!(
            err,
            ShardingConfigError::MissingShardId { total_shards: 3 }
        ));
        assert!(err.to_string().contains("--shard-id"), "{err}");

        let err = from_values(Some(0), Some(0)).expect_err("zero shards is invalid");
        assert!(matches!(
            err,
            ShardingConfigError::TotalShardsZero { shard_id: 0 }
        ));

        for (shard_id, total_shards) in [(3, 3), (4, 3), (1, 0), (u32::MAX, u32::MAX - 1)] {
            let err = Sharding::new(shard_id, total_shards)
                .expect_err("shard_id must be inside 0..total_shards");
            assert!(
                matches!(
                    err,
                    ShardingConfigError::ShardIdOutOfRange { .. }
                        | ShardingConfigError::TotalShardsZero { .. }
                ),
                "{shard_id}/{total_shards}: {err:?}"
            );
        }
        // The boundary is legal, and the largest possible index is representable.
        assert_eq!(Sharding::new(2, 3).expect("2 of 3 is valid").shard_id(), 2);
        assert_eq!(
            Sharding::new(u32::MAX - 1, u32::MAX)
                .expect("the last shard of a huge fleet is valid")
                .lease_name(),
            format!("ferriscd-leader-shard-{}", u32::MAX - 1)
        );
    }

    #[test]
    fn environment_values_are_parsed_and_blank_means_unset() {
        assert_eq!(
            from_env_values(None, None).expect("unset is the default"),
            None
        );
        assert_eq!(
            from_env_values(Some("  "), Some("")).expect("blank means unset"),
            None
        );
        assert_eq!(
            from_env_values(Some("1"), Some("3"))
                .expect("numeric values parse")
                .expect("both set")
                .shard_id(),
            1
        );
        for (shard_id, total_shards) in [
            (Some("one"), Some("3")),
            (Some("0"), Some("three")),
            (Some("-1"), Some("3")),
            (Some("0"), Some("3.5")),
        ] {
            let err = from_env_values(shard_id, total_shards).expect_err("must be rejected");
            assert!(
                matches!(err, ShardingConfigError::InvalidValue { .. }),
                "{shard_id:?}/{total_shards:?}: {err:?}"
            );
            assert!(err.to_string().contains("non-negative integer"), "{err}");
        }
        // A partially set environment is a partial configuration, not a default.
        assert!(matches!(
            from_env_values(Some("1"), None),
            Err(ShardingConfigError::MissingTotalShards { .. })
        ));
    }

    /// The JSON-ish shard count from a `ConfigMap` can also be whitespace-padded.
    #[test]
    fn padded_values_are_trimmed() {
        let shard = from_env_values(Some(" 1 "), Some(" 3 "))
            .expect("recoverable")
            .expect("both set");
        assert_eq!((shard.shard_id(), shard.total_shards()), (1, 3));
    }

    #[test]
    fn shard_options_resolve_through_the_same_validation() {
        assert_eq!(
            ShardOptions::default()
                .resolve()
                .expect("the default is valid"),
            None
        );
        let resolved = ShardOptions::new(Some(1), Some(4))
            .resolve()
            .expect("valid pair")
            .expect("sharding on");
        assert_eq!(resolved, Sharding::new(1, 4).expect("valid"));
        assert!(
            ShardOptions::new(Some(1), None).resolve().is_err(),
            "the builder must not be able to skip validation"
        );
    }
}
