//! Collision-free, bounded LRU cache for rendered manifests, plus a self-contained SHA-256.
//!
//! # Why the key is a *tuple*, not a commit
//!
//! A rendered result depends on far more than the commit SHA. Two `Application`s in one monorepo
//! can point at the same commit with different `path`s, different destinations, or different
//! renderer options, and Helm output additionally depends on `.Release.Name`,
//! `.Release.Namespace`, and `.Capabilities.KubeVersion`. Keying a cache on the commit alone
//! silently deploys one tenant's manifests to another tenant's namespace (Finding M1), so the key
//! is the canonical tuple:
//!
//! ```text
//! SHA-256(repo_url, commit_sha, source_path, app_namespace, app_name,
//!         destination_namespace, cluster_kube_version, canonical_renderer_config)
//! ```
//!
//! Every field is length-prefixed before hashing, so no combination of user-controlled values can
//! produce the same pre-image as a different tuple (a `path` containing `;` cannot forge two
//! fields).
//!
//! # Counters
//!
//! [`RenderCache::stats`] exposes `hits`/`misses` (Phase 15 turns these into metrics) plus the
//! current entry count. A cache hit performs **zero** subprocess invocations — the tests prove it
//! with an invocation counter rather than assuming it.
//!
//! # SHA-256 without a new dependency
//!
//! `sha2` is not in the workspace lock file, so this module carries the ~70-line FIPS 180-4
//! implementation and pins it with the NIST test vectors. It is used only for cache-key derivation
//! and is not a security boundary by itself.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use super::error::ManifestError;
use super::renderer::{
    RedactedUrl, RenderContext, RendererBinaries, encode_fields, render_desired,
};
use super::types::DesiredResource;
use crate::graph::sort_by_tier;

/// Default number of rendered results retained by [`RenderCache`].
pub const DEFAULT_CACHE_CAPACITY: usize = 128;

/// Identity of one rendered result.
///
/// Construct with [`RenderCacheKey::from_context`] in production; the identity fields are public
/// so in-crate tests can build keys directly. The renderer configuration is private (see below).
///
/// The renderer configuration is deliberately **private**: its canonical form embeds Helm inline
/// `values` and `--set`/`--set-string` pairs, which are exactly where repository-held secrets live
/// (finding H1). [`fmt::Debug`] therefore prints only a SHA-256 digest of it.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RenderCacheKey {
    /// Repository URL the checkout came from.
    pub repo_url: String,
    /// Resolved commit SHA of the checkout.
    pub commit_sha: String,
    /// `spec.source.git.path` of the rendered sub-path.
    pub source_path: String,
    /// Namespace of the `Application`.
    pub app_namespace: String,
    /// Name of the `Application` (also the default Helm release name).
    pub app_name: String,
    /// `spec.destination.namespace`.
    pub destination_namespace: String,
    /// Destination cluster server version used for Helm capabilities.
    pub cluster_kube_version: String,
    /// Canonical form of the renderer configuration
    /// ([`super::renderer::RendererConfig::canonical`]): the hash pre-image, never printed.
    renderer_config: String,
}

impl fmt::Debug for RenderCacheKey {
    /// Redacts credentials embedded in `repo_url` and replaces the renderer pre-image with its
    /// digest: the canonical string contains inline Helm values and `--set` values verbatim.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RenderCacheKey")
            .field("repo_url", &RedactedUrl::new(&self.repo_url))
            .field("commit_sha", &self.commit_sha)
            .field("source_path", &self.source_path)
            .field("app_namespace", &self.app_namespace)
            .field("app_name", &self.app_name)
            .field("destination_namespace", &self.destination_namespace)
            .field("cluster_kube_version", &self.cluster_kube_version)
            .field("renderer_config_digest", &self.renderer_config_digest())
            .finish()
    }
}

impl RenderCacheKey {
    /// Derives the key for one render context.
    #[must_use]
    pub fn from_context(ctx: &RenderContext) -> Self {
        Self {
            repo_url: ctx.repo_url.clone(),
            commit_sha: ctx.commit_sha.clone(),
            source_path: ctx.source_path.clone(),
            app_namespace: ctx.app_namespace.clone(),
            app_name: ctx.app_name.clone(),
            destination_namespace: ctx.destination_namespace.clone(),
            cluster_kube_version: ctx.cluster_kube_version.clone(),
            renderer_config: ctx.renderer.canonical(),
        }
    }

    /// SHA-256 digest of the canonical renderer configuration, safe to log.
    #[must_use]
    fn renderer_config_digest(&self) -> String {
        sha256_hex(self.renderer_config.as_bytes())
    }

    /// Unambiguous, length-prefixed pre-image of the key.
    ///
    /// Private on purpose: it embeds the credentialed `repo_url` and the canonical renderer
    /// configuration, so it must never be formatted, logged, or returned to a caller (finding H1).
    /// [`Self::digest`] is the only exposure.
    fn canonical_input(&self) -> String {
        let mut input = String::new();
        encode_fields(
            &mut input,
            &[
                &self.repo_url,
                &self.commit_sha,
                &self.source_path,
                &self.app_namespace,
                &self.app_name,
                &self.destination_namespace,
                &self.cluster_kube_version,
                &self.renderer_config,
            ],
        );
        input
    }

    /// Lowercase hex SHA-256 of the canonical pre-image.
    #[must_use]
    pub fn digest(&self) -> String {
        sha256_hex(self.canonical_input().as_bytes())
    }
}

/// Cache counters for Phase 15 metrics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RenderCacheStats {
    /// Lookups served from the cache.
    pub hits: u64,
    /// Lookups that had to render.
    pub misses: u64,
    /// Entries currently retained.
    pub entries: usize,
    /// Configured bound (`0` means caching is disabled).
    pub capacity: usize,
}

impl RenderCacheStats {
    /// Fraction of lookups served from the cache (`0.0` when no lookup has happened yet).
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            return 0.0;
        }
        self.hits as f64 / total as f64
    }
}

/// One retained render result.
struct CacheEntry {
    resources: Arc<Vec<DesiredResource>>,
    tick: u64,
}

impl fmt::Debug for CacheEntry {
    /// Prints the retained size, never the objects: a rendered `Secret` is a plaintext credential
    /// in `.data` by the time it reaches the cache (finding M2).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CacheEntry")
            .field("resource_count", &self.resources.len())
            .field("tick", &self.tick)
            .finish()
    }
}

/// Shared bookkeeping, guarded by a short-lived `std::sync::Mutex`.
#[derive(Default)]
struct CacheState {
    entries: HashMap<RenderCacheKey, CacheEntry>,
    tick: u64,
}

impl fmt::Debug for CacheState {
    /// Keys redact themselves and entries print sizes only, so this leaks no manifest content.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CacheState")
            .field("entry_count", &self.entries.len())
            .field("tick", &self.tick)
            .finish()
    }
}

/// Bounded LRU cache of normalized render results.
pub struct RenderCache {
    capacity: usize,
    state: Mutex<CacheState>,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl fmt::Debug for RenderCache {
    /// Counters only: the retained `DesiredResource`s may contain `Secret` bodies (finding M2).
    /// `try_lock` keeps `Debug` from ever blocking a worker behind a busy cache.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let entries = self.state.try_lock().map(|state| state.entries.len()).ok();
        f.debug_struct("RenderCache")
            .field("capacity", &self.capacity)
            .field("entries", &entries)
            .field("hits", &self.hits.load(Ordering::Relaxed))
            .field("misses", &self.misses.load(Ordering::Relaxed))
            .finish()
    }
}

impl RenderCache {
    /// Creates a cache bounded to `capacity` entries (`0` disables caching entirely).
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            state: Mutex::new(CacheState::default()),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Configured bound.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Looks `key` up, bumping the hit/miss counters and the LRU position.
    #[must_use]
    pub fn get(&self, key: &RenderCacheKey) -> Option<Arc<Vec<DesiredResource>>> {
        let Ok(mut state) = self.state.lock() else {
            tracing::warn!("render cache mutex was poisoned; treating the lookup as a miss");
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        };

        state.tick += 1;
        let tick = state.tick;
        match state.entries.get_mut(key) {
            Some(entry) => {
                entry.tick = tick;
                let resources = Arc::clone(&entry.resources);
                drop(state);
                self.hits.fetch_add(1, Ordering::Relaxed);
                Some(resources)
            }
            None => {
                drop(state);
                self.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    /// Stores `resources` under `key`, evicting the least-recently-used entry when over capacity.
    pub fn insert(&self, key: RenderCacheKey, resources: Arc<Vec<DesiredResource>>) {
        if self.capacity == 0 {
            return;
        }
        let Ok(mut state) = self.state.lock() else {
            tracing::warn!("render cache mutex was poisoned; skipping the cache insert");
            return;
        };

        state.tick += 1;
        let tick = state.tick;
        state.entries.insert(key, CacheEntry { resources, tick });

        while state.entries.len() > self.capacity {
            let victim = state
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.tick)
                .map(|(key, _)| key.clone());
            match victim {
                Some(victim) => {
                    state.entries.remove(&victim);
                }
                None => break,
            }
        }
    }

    /// Returns current counters.
    #[must_use]
    pub fn stats(&self) -> RenderCacheStats {
        let entries = match self.state.lock() {
            Ok(state) => state.entries.len(),
            Err(_) => 0,
        };
        RenderCacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            entries,
            capacity: self.capacity,
        }
    }

    /// Number of retained entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.stats().entries
    }

    /// Returns `true` when nothing is retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drops every entry, leaving the counters untouched.
    pub fn clear(&self) {
        match self.state.lock() {
            Ok(mut state) => {
                state.entries.clear();
                state.tick = 0;
            }
            Err(_) => tracing::warn!("render cache mutex was poisoned; nothing was cleared"),
        }
    }
}

/// Render entry point that consults a [`RenderCache`].
///
/// This is the seam the controller calls instead of
/// [`render_desired`](super::renderer::render_desired): a periodic requeue at an unchanged commit
/// then costs one hash lookup instead of a `helm`/`kustomize` subprocess.
///
/// **Output is tier-sorted** ([`sort_by_tier`](crate::graph::sort_by_tier)): the pipeline returns
/// apply-ordered resources, so a caller must not sort them again and the cached and uncached paths
/// can never disagree about order (finding M8).
///
/// The cache is **not single-flight**: two concurrent misses for the same key each render. A
/// reconcile worker serializes per `Application`, so the duplicate work only happens across
/// distinct Applications that share a key — and only until one of them inserts.
#[derive(Debug)]
pub struct RenderPipeline {
    cache: RenderCache,
    /// `kustomize`/`helm` binary overrides applied to every context that does not name one.
    binaries: RendererBinaries,
}

impl RenderPipeline {
    /// Creates a pipeline with a cache bounded to `capacity` entries.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            cache: RenderCache::new(capacity),
            binaries: RendererBinaries::default(),
        }
    }

    /// Wraps an existing cache (useful for sharing one cache between callers).
    #[must_use]
    pub fn with_cache(cache: RenderCache) -> Self {
        Self {
            cache,
            binaries: RendererBinaries::default(),
        }
    }

    /// Overrides the renderer binaries (operator/test seam; never part of the cache key).
    #[must_use]
    pub fn with_binaries(mut self, binaries: RendererBinaries) -> Self {
        self.binaries = binaries;
        self
    }

    /// Returns the underlying cache (counters, `len`, `clear`).
    #[must_use]
    pub fn cache(&self) -> &RenderCache {
        &self.cache
    }

    /// Renders `ctx`, reusing a cached result when the full key matches.
    ///
    /// A context without a resolved commit SHA is **never** cached: an empty SHA cannot
    /// distinguish commits, so caching it would risk exactly the cross-app contamination the key
    /// exists to prevent.
    ///
    /// # Errors
    ///
    /// Propagates every renderer, parser, normalizer, and duplicate-key error. Failures are never
    /// cached.
    pub async fn render(
        &self,
        ctx: &RenderContext,
    ) -> Result<Arc<Vec<DesiredResource>>, ManifestError> {
        let overridden = self.overridden(ctx);
        let ctx = overridden.as_ref().unwrap_or(ctx);

        if ctx.commit_sha.is_empty() {
            tracing::debug!(
                app = %ctx.app_name,
                namespace = %ctx.app_namespace,
                "rendering without a resolved commit SHA; the render cache is bypassed"
            );
            return Ok(Arc::new(render_sorted(ctx).await?));
        }

        let key = RenderCacheKey::from_context(ctx);
        if let Some(hit) = self.cache.get(&key) {
            return Ok(hit);
        }

        let resources = Arc::new(render_sorted(ctx).await?);
        self.cache.insert(key, Arc::clone(&resources));
        Ok(resources)
    }

    /// Returns `ctx` with this pipeline's binary overrides applied, or `None` when it has none.
    ///
    /// The overrides are excluded from [`super::renderer::RendererConfig::canonical`], so the cache
    /// key is identical with or without them.
    fn overridden(&self, ctx: &RenderContext) -> Option<RenderContext> {
        if self.binaries.is_empty() {
            return None;
        }
        let mut binaries = ctx.binaries.clone();
        if binaries.kustomize.is_none() {
            binaries.kustomize.clone_from(&self.binaries.kustomize);
        }
        if binaries.helm.is_none() {
            binaries.helm.clone_from(&self.binaries.helm);
        }
        let mut overridden = ctx.clone();
        overridden.binaries = binaries;
        Some(overridden)
    }
}

/// Renders `ctx` and returns the bundle in tier (apply) order.
async fn render_sorted(ctx: &RenderContext) -> Result<Vec<DesiredResource>, ManifestError> {
    Ok(sort_by_tier(render_desired(ctx).await?))
}

impl Default for RenderPipeline {
    fn default() -> Self {
        Self::new(DEFAULT_CACHE_CAPACITY)
    }
}

/// SHA-256 round constants (FIPS 180-4 §4.2.2).
const SHA256_K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// SHA-256 initial hash values (FIPS 180-4 §5.3.3).
const SHA256_H0: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// Returns the lowercase hex SHA-256 digest of `input`.
#[must_use]
pub fn sha256_hex(input: &[u8]) -> String {
    let digest = sha256(input);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        hex.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        hex.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    hex
}

/// Computes the SHA-256 digest of `input`.
fn sha256(input: &[u8]) -> [u8; 32] {
    let mut state = SHA256_H0;

    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(input.len() + 72);
    padded.extend_from_slice(input);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.as_chunks::<64>().0 {
        compress(&mut state, chunk);
    }

    let mut digest = [0u8; 32];
    for (index, word) in state.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

/// One SHA-256 compression round over a 64-byte block.
fn compress(state: &mut [u32; 8], block: &[u8]) {
    let mut words = [0u32; 64];
    for (index, word) in words.iter_mut().take(16).enumerate() {
        let start = index * 4;
        *word = u32::from_be_bytes([
            block[start],
            block[start + 1],
            block[start + 2],
            block[start + 3],
        ]);
    }
    for index in 16..64 {
        let s0 = words[index - 15].rotate_right(7)
            ^ words[index - 15].rotate_right(18)
            ^ (words[index - 15] >> 3);
        let s1 = words[index - 2].rotate_right(17)
            ^ words[index - 2].rotate_right(19)
            ^ (words[index - 2] >> 10);
        words[index] = words[index - 16]
            .wrapping_add(s0)
            .wrapping_add(words[index - 7])
            .wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for index in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(SHA256_K[index])
            .wrapping_add(words[index]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *slot = slot.wrapping_add(value);
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use serde_json::json;
    use tempfile::TempDir;

    use super::*;
    use crate::manifest::DesiredResource;
    use crate::manifest::fake_runner::FakeBinary;
    use crate::manifest::helm::HelmOptions;
    use crate::manifest::kustomize::KustomizeOptions;
    use crate::manifest::renderer::RendererConfig;
    use crate::manifest::types::{GroupVersionKind, ResourceKey};
    use kube::api::DynamicObject;

    fn write(root: &Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent dirs");
        }
        fs::write(path, contents).expect("write fixture file");
    }

    fn resource(name: &str, namespace: &str) -> DesiredResource {
        let object: DynamicObject = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": name, "namespace": namespace },
        }))
        .expect("valid DynamicObject");
        DesiredResource {
            key: ResourceKey::new("", "ConfigMap", Some(namespace.to_owned()), name),
            gvk: GroupVersionKind::parse("v1", "ConfigMap").expect("gvk"),
            object,
            source_file: format!("kustomize:app-{name}"),
        }
    }

    fn key(source_path: &str, destination_namespace: &str) -> RenderCacheKey {
        RenderCacheKey {
            repo_url: "https://example.com/monorepo.git".to_owned(),
            commit_sha: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            source_path: source_path.to_owned(),
            app_namespace: "ferriscd-system".to_owned(),
            app_name: "demo".to_owned(),
            destination_namespace: destination_namespace.to_owned(),
            cluster_kube_version: "1.35.0".to_owned(),
            renderer_config: RendererConfig::Auto.canonical(),
        }
    }

    #[test]
    fn sha256_matches_nist_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        // FIPS 180-4 §B.3 / the NIST CAVP vector: 1,000,000 repetitions of 'a'. This is the
        // multi-block case (15,625 blocks), and it is an *external* expected value — comparing the
        // implementation against itself would pass for any hash.
        let million = "a".repeat(1_000_000);
        assert_eq!(
            sha256_hex(million.as_bytes()),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
        assert_ne!(sha256_hex(b"abc"), sha256_hex(b"abd"));
    }

    #[test]
    fn cache_key_digest_changes_for_every_field() {
        let base = key("apps/a", "payments");
        let mut seen = std::collections::HashSet::new();
        assert!(seen.insert(base.digest()));

        let mut variants = Vec::new();
        let mut variant = base.clone();
        variant.repo_url = "https://example.com/other.git".to_owned();
        variants.push(variant);
        let mut variant = base.clone();
        variant.commit_sha = "fedcba9876543210fedcba9876543210fedcba98".to_owned();
        variants.push(variant);
        variants.push(key("apps/b", "payments"));
        let mut variant = base.clone();
        variant.app_namespace = "team-a".to_owned();
        variants.push(variant);
        let mut variant = base.clone();
        variant.app_name = "other".to_owned();
        variants.push(variant);
        variants.push(key("apps/a", "billing"));
        let mut variant = base.clone();
        variant.cluster_kube_version = "1.34.0".to_owned();
        variants.push(variant);
        let mut variant = base.clone();
        variant.renderer_config = RendererConfig::PlainYaml(Default::default()).canonical();
        variants.push(variant);

        for variant in variants {
            assert!(
                seen.insert(variant.digest()),
                "digest collision for {variant:?} vs {base:?}"
            );
        }
    }

    #[test]
    fn cache_key_encoding_cannot_be_forged_by_delimiter_injection() {
        let split = RenderCacheKey {
            source_path: "apps/a".to_owned(),
            destination_namespace: "b".to_owned(),
            ..key("", "")
        };
        let merged = RenderCacheKey {
            source_path: "apps/a\u{1}1:b".to_owned(),
            destination_namespace: String::new(),
            ..key("", "")
        };
        assert_ne!(split.digest(), merged.digest());
    }

    #[test]
    fn cache_key_debug_redacts_embedded_credentials() {
        let mut with_credentials = key("apps/a", "payments");
        with_credentials.repo_url =
            "https://robot:s3cr3t-token@example.com/monorepo.git".to_owned();
        let rendered = format!("{with_credentials:?}");
        assert!(!rendered.contains("s3cr3t-token"), "{rendered}");
        assert!(rendered.contains("robot:***@"), "{rendered}");

        // Finding C1: a *bare* userinfo is a token (`https://ghp_…@github.com/...`), not a
        // username, so printing it as one would leak the credential.
        let mut bare = key("apps/a", "payments");
        bare.repo_url = "https://ghp_16C7e42Ftoken@github.com/org/repo.git".to_owned();
        let rendered = format!("{bare:?}");
        assert!(!rendered.contains("ghp_16C7e42Ftoken"), "{rendered}");
        assert!(rendered.contains("https://***@github.com"), "{rendered}");

        assert_eq!(
            crate::manifest::renderer::redact_repo_url("ssh://user@host/repo.git"),
            "ssh://***@host/repo.git",
            "no colon means no username worth keeping"
        );
        assert_eq!(
            crate::manifest::renderer::redact_repo_url("git@github.com:org/repo.git"),
            "git@github.com:org/repo.git"
        );
    }

    /// Finding H1: the key's canonical renderer configuration contains Helm inline values and
    /// `--set` pairs verbatim, so `Debug` must print a digest instead of the pre-image.
    #[test]
    fn cache_key_debug_hides_inline_values_and_the_renderer_pre_image() {
        let ctx = RenderContext::new("/repo")
            .with_repo_url("https://ghp_16C7e42Ftoken@github.com/org/repo.git")
            .with_app("ferriscd-system", "demo")
            .with_renderer(RendererConfig::Helm(HelmOptions {
                inline_values: Some("password: hunter2\n".to_owned()),
                set: vec!["db.password=hunter2".to_owned()],
                set_string: vec!["api.key=hunter2".to_owned()],
                ..HelmOptions::default()
            }));
        let key = RenderCacheKey::from_context(&ctx);

        let rendered = format!("{key:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(!rendered.contains("ghp_16C7e42Ftoken"), "{rendered}");
        assert!(!rendered.contains("inline_values"), "{rendered}");
        assert!(
            rendered.contains(&key.renderer_config_digest()),
            "the digest is the only renderer information printed: {rendered}"
        );
        assert_eq!(
            key.renderer_config_digest().len(),
            64,
            "the digest must be a SHA-256 hex string"
        );
        assert_eq!(
            key.renderer_config_digest(),
            sha256_hex(
                RendererConfig::Helm(HelmOptions {
                    inline_values: Some("password: hunter2\n".to_owned()),
                    set: vec!["db.password=hunter2".to_owned()],
                    set_string: vec!["api.key=hunter2".to_owned()],
                    ..HelmOptions::default()
                })
                .canonical()
                .as_bytes()
            ),
            "the printed value is the digest of the canonical configuration"
        );

        // Two renderer configurations must still be distinguishable from the digest alone.
        let other = RenderCacheKey::from_context(&RenderContext {
            renderer: RendererConfig::Auto,
            ..ctx.clone()
        });
        assert_ne!(key.renderer_config_digest(), other.renderer_config_digest());
    }

    /// Finding M2: `RenderCache`/`CacheState`/`CacheEntry` must not print rendered objects.
    #[test]
    fn cache_debug_prints_counters_not_rendered_objects() {
        let cache = RenderCache::new(4);
        let object: DynamicObject = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": { "name": "app-secret", "namespace": "payments" },
            "data": { "token": "czNjcjN0LXRva2Vu" },
        }))
        .expect("valid DynamicObject");
        cache.insert(
            key("apps/a", "payments"),
            Arc::new(vec![DesiredResource {
                key: ResourceKey::new("", "Secret", Some("payments".to_owned()), "app-secret"),
                gvk: GroupVersionKind::parse("v1", "Secret").expect("gvk"),
                object,
                source_file: "kustomize:apps/a".to_owned(),
            }]),
        );

        let rendered = format!("{cache:?}");
        assert!(!rendered.contains("czNjcjN0LXRva2Vu"), "{rendered}");
        assert!(!rendered.contains("app-secret"), "{rendered}");
        assert!(rendered.contains("entries: Some(1)"), "{rendered}");
        assert!(rendered.contains("capacity: 4"), "{rendered}");
    }

    #[test]
    fn lru_evicts_the_least_recently_used_entry() {
        let cache = RenderCache::new(2);
        let first = key("apps/a", "payments");
        let second = key("apps/b", "payments");
        let third = key("apps/c", "payments");

        cache.insert(first.clone(), Arc::new(vec![resource("a", "payments")]));
        cache.insert(second.clone(), Arc::new(vec![resource("b", "payments")]));
        // Touch `first` so `second` becomes the least recently used victim.
        assert!(cache.get(&first).is_some());

        cache.insert(third.clone(), Arc::new(vec![resource("c", "payments")]));
        assert_eq!(cache.len(), 2);
        assert!(cache.get(&first).is_some(), "recently used entry survives");
        assert!(cache.get(&third).is_some(), "newest entry survives");
        assert!(cache.get(&second).is_none(), "LRU entry was evicted");

        let stats = cache.stats();
        assert_eq!(stats.capacity, 2);
        assert_eq!(stats.entries, 2);
        assert_eq!(stats.misses, 1);
        assert!(stats.hit_rate() > 0.0);
    }

    #[test]
    fn zero_capacity_disables_caching() {
        let cache = RenderCache::new(0);
        let entry = key("apps/a", "payments");
        cache.insert(entry.clone(), Arc::new(vec![resource("a", "payments")]));
        assert!(cache.is_empty());
        assert!(cache.get(&entry).is_none());
        assert_eq!(cache.stats().misses, 1);
    }

    /// Minimal monorepo fixture: two app directories, each with its own manifest.
    fn monorepo(root: &Path) {
        for (app, name) in [("app-a", "alpha"), ("app-b", "beta")] {
            write(
                root,
                &format!("{app}/kustomization.yaml"),
                "resources:\n  - manifest.yaml\n",
            );
            write(
                root,
                &format!("{app}/manifest.yaml"),
                &format!("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {name}\n"),
            );
        }
    }

    fn kustomize_context(root: &Path, source_path: &str, binary: &Path) -> RenderContext {
        RenderContext::new(root)
            .with_repo_url("https://example.com/monorepo.git")
            .with_commit_sha("0123456789abcdef0123456789abcdef01234567")
            .with_app("ferriscd-system", "demo")
            .with_destination_namespace("payments")
            .with_kube_version("1.35.0")
            .with_source_path(source_path)
            .with_renderer(RendererConfig::Kustomize(KustomizeOptions {
                binary: Some(binary.to_path_buf()),
                ..KustomizeOptions::default()
            }))
    }

    #[tokio::test]
    async fn repeat_render_hits_the_cache_and_spawns_no_subprocess() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();
        monorepo(root);
        let fake = FakeBinary::mirroring("kustomize", 2);
        let pipeline = RenderPipeline::new(8);
        let ctx = kustomize_context(root, "app-a", fake.path());

        let first = pipeline.render(&ctx).await.expect("first render");
        assert_eq!(fake.invocations(), 1);
        assert_eq!(first.len(), 1);

        for _ in 0..3 {
            let again = pipeline.render(&ctx).await.expect("cached render");
            assert_eq!(again.len(), first.len());
            assert_eq!(
                again[0].key.canonical(),
                first[0].key.canonical(),
                "cached resources must be identical"
            );
        }

        assert_eq!(
            fake.invocations(),
            1,
            "a cache hit must not run kustomize again"
        );
        let stats = pipeline.cache().stats();
        assert_eq!(stats.hits, 3);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.entries, 1);
    }

    #[tokio::test]
    async fn monorepo_apps_at_the_same_commit_do_not_contaminate_each_other() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();
        monorepo(root);
        let fake = FakeBinary::mirroring("kustomize", 2);
        let pipeline = RenderPipeline::new(8);

        let app_a = kustomize_context(root, "app-a", fake.path());
        let app_b = kustomize_context(root, "app-b", fake.path());

        let rendered_a = pipeline.render(&app_a).await.expect("render app-a");
        let rendered_b = pipeline.render(&app_b).await.expect("render app-b");
        assert_eq!(
            rendered_a[0].key.name, "alpha",
            "app-a must render its own path"
        );
        assert_eq!(
            rendered_b[0].key.name, "beta",
            "app-b must render its own path"
        );
        assert_eq!(fake.invocations(), 2, "distinct keys must both render");

        // Repeating either render stays pinned to its own key.
        let again_a = pipeline.render(&app_a).await.expect("cached app-a");
        let again_b = pipeline.render(&app_b).await.expect("cached app-b");
        assert_eq!(again_a[0].key.name, "alpha");
        assert_eq!(again_b[0].key.name, "beta");
        assert_eq!(fake.invocations(), 2);
        assert_eq!(pipeline.cache().stats().entries, 2);
    }

    #[tokio::test]
    async fn destination_namespace_changes_the_key_and_the_rendered_output() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();
        write(
            root,
            "chart/Chart.yaml",
            "apiVersion: v2\nname: demo\nversion: 0.1.0\n",
        );
        let fake = FakeBinary::helm_namespaced("helm");

        let pipeline = RenderPipeline::new(8);
        let build = |namespace: &str| {
            RenderContext::new(root)
                .with_repo_url("https://example.com/monorepo.git")
                .with_commit_sha("0123456789abcdef0123456789abcdef01234567")
                .with_app("ferriscd-system", "demo")
                .with_destination_namespace(namespace)
                .with_kube_version("1.35.0")
                .with_source_path("chart")
                .with_renderer(RendererConfig::Helm(HelmOptions {
                    binary: Some(fake.path().to_path_buf()),
                    ..HelmOptions::default()
                }))
        };

        let payments = pipeline.render(&build("payments")).await.expect("render");
        let billing = pipeline.render(&build("billing")).await.expect("render");
        assert_eq!(
            payments[0].key.namespace.as_deref(),
            Some("payments"),
            "`.Release.Namespace` must come from the destination namespace"
        );
        assert_eq!(billing[0].key.namespace.as_deref(), Some("billing"));
        assert_eq!(fake.invocations(), 2);

        // Cache hits keep returning the caller's own namespace, never the other app's.
        for _ in 0..2 {
            let again = pipeline.render(&build("payments")).await.expect("cached");
            assert_eq!(again[0].key.namespace.as_deref(), Some("payments"));
        }
        assert_eq!(fake.invocations(), 2);
        assert_eq!(pipeline.cache().stats().entries, 2);
    }

    #[tokio::test]
    async fn render_failures_are_never_cached() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();
        monorepo(root);
        let fake = FakeBinary::failing("kustomize", "", "boom: chart not found");
        let pipeline = RenderPipeline::new(8);
        let ctx = kustomize_context(root, "app-a", fake.path());

        for _ in 0..2 {
            let err = pipeline.render(&ctx).await.expect_err("render must fail");
            assert!(err.to_string().contains("boom: chart not found"), "{err}");
        }
        assert_eq!(
            fake.invocations(),
            2,
            "a failure must be retried, not cached"
        );
        assert!(pipeline.cache().is_empty());
        assert_eq!(pipeline.cache().stats().misses, 2);
    }

    #[tokio::test]
    async fn missing_commit_sha_bypasses_the_cache() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();
        monorepo(root);
        let fake = FakeBinary::mirroring("kustomize", 2);
        let pipeline = RenderPipeline::new(8);
        let mut ctx = kustomize_context(root, "app-a", fake.path());
        ctx.commit_sha = String::new();

        pipeline.render(&ctx).await.expect("first render");
        pipeline.render(&ctx).await.expect("second render");

        assert_eq!(
            fake.invocations(),
            2,
            "an unresolved commit must never be cached"
        );
        assert!(pipeline.cache().is_empty());
        assert_eq!(pipeline.cache().stats().hits, 0);
    }

    /// Finding M8: the pipeline returns tier (apply) order on both the render and the cache path,
    /// so no caller has to sort — and the two paths cannot disagree about order.
    #[tokio::test]
    async fn pipeline_output_is_tier_sorted() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();
        // Repository file order deliberately disagrees with apply order.
        write(
            root,
            "app/00-deployment.yaml",
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\n",
        );
        write(
            root,
            "app/10-configmap.yaml",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: settings\n",
        );
        write(
            root,
            "app/20-namespace.yaml",
            "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: payments\n",
        );

        let pipeline = RenderPipeline::new(8);
        let ctx = RenderContext::new(root)
            .with_repo_url("https://example.com/monorepo.git")
            .with_commit_sha("0123456789abcdef0123456789abcdef01234567")
            .with_app("ferriscd-system", "demo")
            .with_destination_namespace("payments")
            .with_source_path("app");

        let rendered = pipeline.render(&ctx).await.expect("render");
        let kinds: Vec<&str> = rendered
            .iter()
            .map(|resource| resource.gvk.kind.as_str())
            .collect();
        assert_eq!(kinds, vec!["Namespace", "ConfigMap", "Deployment"]);

        let cached = pipeline.render(&ctx).await.expect("cached render");
        let cached_kinds: Vec<&str> = cached
            .iter()
            .map(|resource| resource.gvk.kind.as_str())
            .collect();
        assert_eq!(cached_kinds, kinds, "a cache hit keeps the apply order");
        assert_eq!(pipeline.cache().stats().hits, 1);
    }

    /// The binary override is an operator/test seam: it reaches an *auto-detected* renderer and is
    /// deliberately absent from the cache key.
    #[tokio::test]
    async fn pipeline_binary_overrides_apply_to_auto_detected_renderers() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();
        monorepo(root);
        let fake = FakeBinary::mirroring("kustomize", 2);
        let pipeline = RenderPipeline::new(8).with_binaries(RendererBinaries {
            kustomize: Some(fake.path().to_path_buf()),
            ..RendererBinaries::default()
        });

        let ctx = RenderContext::new(root)
            .with_repo_url("https://example.com/monorepo.git")
            .with_commit_sha("0123456789abcdef0123456789abcdef01234567")
            .with_app("ferriscd-system", "demo")
            .with_destination_namespace("payments")
            .with_source_path("app-a");

        let rendered = pipeline.render(&ctx).await.expect("auto-detected render");
        assert_eq!(rendered[0].key.name, "alpha");
        assert_eq!(
            fake.invocations(),
            1,
            "the override must replace `kustomize`"
        );

        pipeline.render(&ctx).await.expect("cached render");
        assert_eq!(
            fake.invocations(),
            1,
            "the binary override is not part of the cache key"
        );
    }
}
