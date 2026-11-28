//! OCI artifact sources (`spec.source.oci`, `T18.3`): the registry-client seam, digest
//! verification, and safe streaming extraction of a Helm chart or manifest bundle.
//!
//! ## Why the seam mirrors [`GitClient`](super::GitClient)
//!
//! A GitOps controller needs two things from any source: an **immutable identity** for what it is
//! about to render (a commit SHA, or an OCI manifest digest), and a **read-only checkout** of that
//! identity on local disk. [`OciClient`] is the same two-method contract for registries, so the
//! render/diff/sync pipeline never learns that it is not looking at Git. Any third-party OCI
//! registry crate stays strictly behind this module, exactly like `gix` stays behind
//! [`GixGitClient`](super::GixGitClient).
//!
//! ## Untrusted archives
//!
//! An artifact layer is attacker-controlled input that reaches the renderer, so extraction is
//! deny-by-default rather than "unpack and then look":
//!
//! * the **manifest** and **layer** SHA-256 digests are verified before a single archive byte is
//!   interpreted ([`verify_digest`], [`extract_layer`]'s spool-then-verify order), and the layer's
//!   declared `size` must match the blob exactly — a `Content-Length` header is never trusted;
//! * decompression is **streaming and bounded**: every byte the gzip decoder produces is charged
//!   against [`WorktreeLimits::max_bytes`] as it is read, so a decompression bomb stops at the
//!   budget instead of filling the disk (the compressed blob is bounded too, by the same budget
//!   plus a small, documented tar-overhead allowance);
//! * the tar reader here understands **only** plain files (`'0'`/`NUL`) and directories (`'5'`).
//!   Symlinks, hardlinks, character/block devices, FIFOs, PAX/GNU extension records and every other
//!   entry type are rejected by name — a denylist on an unpacker we do not own would not be
//!   exhaustive, so this module parses tar itself;
//! * entry paths must be relative, `..`-free, UTF-8 and duplicate-free, and are joined onto a
//!   directory this module created;
//! * the extracted tree is handed through [`sanitize_worktree`] (the same walk the Git path uses)
//!   before it is returned, and a Helm chart's single top-level directory is unwrapped **only** when
//!   it contains a `Chart.yaml` — so a bundle with a `charts/` sub-directory is never mistaken for a
//!   wrapped chart.
//!
//! ## Async hygiene
//!
//! Everything here is blocking (`flate2`, `sha2`, and `std::fs`). Callers must run
//! [`extract_artifact`]/[`extract_layer`] inside [`tokio::task::spawn_blocking`]; the bundled
//! [`FakeOciClient`] does exactly that so the pattern is demonstrated rather than documented.

use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::error::RepoError;
use super::sanitize::{WorktreeLimits, sanitize_worktree};
use super::types::{
    RepoCheckout, RepoCredentials, redact_oci_url_credentials, validate_authority_host,
    validate_source_path,
};

/// Media type of a Helm chart OCI artifact layer.
pub const HELM_CHART_MEDIA_TYPE: &str = "application/vnd.cncf.helm.chart.content.v1.tar+gzip";

/// Media type of a generic (Kustomize/plain YAML) OCI image layer.
pub const OCI_IMAGE_LAYER_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

/// Media type of a Flux OCI artifact layer.
pub const FLUX_BUNDLE_MEDIA_TYPE: &str = "application/vnd.cncf.flux.content.v1.tar+gzip";

/// Prefix of every accepted OCI digest (`sha256:<64-hex>`).
pub const DIGEST_PREFIX: &str = "sha256:";

/// Number of hexadecimal characters in an accepted OCI digest.
pub const DIGEST_HEX_LEN: usize = 64;

/// Largest manifest document this module will parse (4 MiB).
///
/// A manifest is a small JSON document; the cap keeps a hostile registry from making the
/// controller buffer an arbitrarily large body before validation can reject it.
pub const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;

/// Bytes allowed on top of [`WorktreeLimits::max_bytes`] for tar headers and padding when bounding
/// the **compressed** blob.
///
/// A gzip stream of incompressible data is marginally larger than its payload, and a tar stream
/// carries a 512-byte header plus padding per entry. Both are bounded by this allowance; the
/// authoritative budget is still the decompressed byte counter.
pub const ARCHIVE_OVERHEAD_BYTES: u64 = 1024 * 1024;

/// Size of one tar record block.
const TAR_BLOCK: usize = 512;

/// Media types this module can extract.
#[must_use]
pub fn is_supported_layer_media_type(media_type: &str) -> bool {
    matches!(
        media_type,
        HELM_CHART_MEDIA_TYPE | OCI_IMAGE_LAYER_MEDIA_TYPE | FLUX_BUNDLE_MEDIA_TYPE
    )
}

/// Policy controlling which `spec.source.oci.url` schemes are accepted.
///
/// Mirrors [`RepoUrlPolicy`](super::RepoUrlPolicy): production traffic is HTTPS-only, and plaintext
/// is available **only** through an explicit local-development opt-in (a `kind`-hosted registry at
/// `http://localhost:5000`), never by simply writing `http://` in an `Application`.
///
/// **Deferred to `T18.4`:** nothing plumbs the local-development opt-in yet — there is no controller
/// flag that selects [`OciUrlPolicy::AllowLocal`], because `T18.3` ships only the CRD schema, the
/// extraction pipeline, and this policy type. Until `T18.4` wires the flag, every production caller
/// (and the `FakeOciClientConfig` default) uses [`OciUrlPolicy::Production`], so a
/// plaintext registry stays impossible outside a test that opts in explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OciUrlPolicy {
    /// Production policy: `oci://` and `https://` only; `http://` is rejected.
    #[default]
    Production,
    /// Local development: additionally allows plaintext `http://` registries.
    AllowLocal,
}

/// Declarative reference to an OCI artifact (`spec.source.oci`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OciSource {
    /// Artifact reference (`oci://<registry>/<repository>`, or `https://` for the same registry).
    pub url: String,
    /// Tag to resolve; [`None`] when the reference is digest-pinned only.
    pub tag: Option<String>,
    /// Immutable manifest digest (`sha256:<64-hex>`), when pinned.
    pub digest: Option<String>,
    /// Relative sub-directory inside the extracted artifact (`""` for its root).
    pub path: String,
}

impl OciSource {
    /// Constructs an [`OciSource`].
    #[must_use]
    pub fn new(
        url: impl Into<String>,
        tag: Option<String>,
        digest: Option<String>,
        path: impl Into<String>,
    ) -> Self {
        Self {
            url: url.into(),
            tag,
            digest,
            path: path.into(),
        }
    }

    /// The reference to resolve: the tag when set, else the pinned digest.
    #[must_use]
    pub fn requested_reference(&self) -> Option<&str> {
        self.tag.as_deref().or(self.digest.as_deref())
    }

    /// Validates the URL against `policy`, the reference (`tag`/`digest`), and `path`.
    ///
    /// # Errors
    ///
    /// [`RepoError::InvalidUrl`] for an unusable reference, [`RepoError::InvalidRevision`] for a
    /// malformed digest, and [`RepoError::InvalidSource`] for a path that could escape the
    /// extracted root.
    pub fn validate(&self, policy: OciUrlPolicy) -> Result<(), RepoError> {
        validate_oci_url(&self.url, policy)?;
        if let Some(digest) = self.digest.as_deref() {
            validate_digest(digest)?;
        }
        if self.tag.is_none() && self.digest.is_none() {
            return Err(RepoError::InvalidSource {
                reason: "spec.source.oci must set a tag or a digest".to_owned(),
            });
        }
        if let Some(tag) = self.tag.as_deref() {
            validate_oci_tag(tag)?;
        }
        validate_source_path(&self.path)?;
        Ok(())
    }
}

/// Validates a registry URL under `policy`.
///
/// The rejected URL is echoed into [`RepoError::InvalidUrl`], which reaches `Application.status`,
/// Events, and logs — so it goes through [`redact_oci_url_credentials`] first. A userinfo-carrying
/// reference is refused *here*, and the refusal must not be the thing that publishes the token.
///
/// The registry-specific redactor (not [`redact_url_credentials`](super::types)) is what makes the
/// "must be absolute" branch safe: it fires on a URL with no scheme at all, so `token@ghcr.io/repo`
/// — the shape a forgotten `oci://` leaves behind — is exactly the case the generic Git rule (which
/// keeps SCP-style `git@host:path`) would pass through (finding M-A).
fn validate_oci_url(url: &str, policy: OciUrlPolicy) -> Result<(), RepoError> {
    let invalid = |url: &str, reason: &str| RepoError::InvalidUrl {
        url: redact_oci_url_credentials(url),
        reason: reason.to_owned(),
    };

    if url.trim().is_empty() {
        return Err(invalid("", "registry URL must not be empty"));
    }
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(invalid(
            url,
            "registry URL must not contain whitespace or control characters",
        ));
    }
    if url.starts_with('-') {
        return Err(invalid(url, "registry URL must not start with '-'"));
    }
    let Some((scheme, rest)) = url.split_once("://") else {
        return Err(invalid(
            url,
            "registry URL must be absolute, e.g. oci://ghcr.io/org/chart",
        ));
    };
    match scheme.to_ascii_lowercase().as_str() {
        // `oci://` is the GitOps spelling of "this registry over HTTPS"; its transport is decided
        // here, not by the spelling.
        "oci" | "https" => {}
        "http" => {
            if policy != OciUrlPolicy::AllowLocal {
                return Err(invalid(
                    url,
                    "plaintext http:// registries are disallowed; use oci:// or https:// (plaintext \
                     is available only with the explicit local-development opt-in)",
                ));
            }
        }
        other => {
            return Err(invalid(
                url,
                &format!("unsupported registry URL scheme '{other}'"),
            ));
        }
    }

    let (authority, repository) = rest.split_once('/').ok_or_else(|| {
        invalid(
            url,
            "registry URL must be oci://<registry>/<repository> (a repository is required)",
        )
    })?;
    if authority.contains('@') {
        return Err(invalid(
            url,
            "embedded credentials in registry URLs are disallowed; use a \
             ferriscd.io/secret-type=repository Secret",
        ));
    }
    validate_authority_host(url, authority)?;
    if repository.is_empty() || repository.ends_with('/') {
        return Err(invalid(
            url,
            "the repository path must not be empty or end with '/'",
        ));
    }
    if repository
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(invalid(
            url,
            "the repository path must not contain empty, '.' or '..' segments",
        ));
    }
    Ok(())
}

/// Validates an OCI tag against the distribution reference grammar.
fn validate_oci_tag(tag: &str) -> Result<(), RepoError> {
    let invalid = |reason: &str| RepoError::InvalidRevision {
        revision: tag.to_owned(),
        reason: reason.to_owned(),
    };
    let mut chars = tag.chars();
    let Some(first) = chars.next() else {
        return Err(invalid("an OCI tag must not be empty"));
    };
    if tag.len() > 128 {
        return Err(invalid("an OCI tag must be at most 128 characters"));
    }
    if !(first.is_ascii_alphanumeric() || first == '_') {
        return Err(invalid(
            "an OCI tag must start with an alphanumeric character or '_'",
        ));
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')) {
        return Err(invalid(
            "an OCI tag may contain only alphanumeric characters, '.', '_', and '-'",
        ));
    }
    Ok(())
}

/// Validates `digest` as `sha256:<64 lowercase hex>`.
///
/// This is the authoritative transport-side check. `ferriscd_crd::OciSourceSpec::validate` makes
/// the same check offline (the CRD cannot depend on this crate), so the two must stay in sync — they
/// are pinned by tests on both sides.
///
/// # Errors
///
/// [`RepoError::InvalidRevision`] naming the digest and the expected shape.
pub fn validate_digest(digest: &str) -> Result<(), RepoError> {
    let invalid = |reason: &str| RepoError::InvalidRevision {
        revision: digest.to_owned(),
        reason: reason.to_owned(),
    };
    let Some(hex) = digest.strip_prefix(DIGEST_PREFIX) else {
        return Err(invalid("a digest must start with 'sha256:'"));
    };
    if hex.len() != DIGEST_HEX_LEN
        || !hex
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(invalid(
            "'sha256:' must be followed by exactly 64 lowercase hexadecimal characters",
        ));
    }
    Ok(())
}

/// Returns the `sha256:<hex>` digest of `bytes`.
#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{DIGEST_PREFIX}{:x}", hasher.finalize())
}

/// Verifies that `bytes` hash to `expected`.
///
/// # Errors
///
/// [`RepoError::InvalidRevision`] when `expected` is not a valid digest, and
/// [`RepoError::OciDigestMismatch`] when the content does not match it.
pub fn verify_digest(expected: &str, bytes: &[u8]) -> Result<(), RepoError> {
    validate_digest(expected)?;
    let actual = sha256_digest(bytes);
    if actual != expected {
        return Err(RepoError::OciDigestMismatch {
            expected: expected.to_owned(),
            actual,
        });
    }
    Ok(())
}

/// One blob descriptor from an OCI manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciDescriptor {
    /// Layer media type (see [`is_supported_layer_media_type`]).
    pub media_type: String,
    /// `sha256:<64-hex>` digest of the stored (compressed) blob.
    pub digest: String,
    /// Exact size of the stored blob, when the manifest declares one.
    pub size: Option<u64>,
}

impl OciDescriptor {
    /// Constructs a descriptor.
    #[must_use]
    pub fn new(
        media_type: impl Into<String>,
        digest: impl Into<String>,
        size: Option<u64>,
    ) -> Self {
        Self {
            media_type: media_type.into(),
            digest: digest.into(),
            size,
        }
    }
}

/// The parts of an OCI image manifest this module needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciManifest {
    /// Manifest media type as declared by the registry body (informational).
    pub media_type: Option<String>,
    /// The artifact's layers.
    pub layers: Vec<OciDescriptor>,
}

/// Wire shape of the manifest fields this module reads.
#[derive(Deserialize)]
struct RawManifest {
    #[serde(default, rename = "schemaVersion")]
    schema_version: Option<u32>,
    #[serde(default, rename = "mediaType")]
    media_type: Option<String>,
    #[serde(default)]
    layers: Vec<RawDescriptor>,
}

/// Wire shape of a descriptor inside [`RawManifest`].
#[derive(Deserialize)]
struct RawDescriptor {
    #[serde(default, rename = "mediaType")]
    media_type: String,
    #[serde(default)]
    digest: String,
    #[serde(default)]
    size: Option<u64>,
}

impl OciManifest {
    /// Parses an OCI image manifest document.
    ///
    /// # Errors
    ///
    /// [`RepoError::OciInvalidArtifact`] for an oversized, malformed, non-v2, or layer-less
    /// document, and [`RepoError::InvalidRevision`] for a layer digest that is not
    /// `sha256:<64-hex>`.
    pub fn parse(bytes: &[u8]) -> Result<Self, RepoError> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(RepoError::OciInvalidArtifact {
                reason: format!(
                    "manifest is {} bytes, which exceeds the {MAX_MANIFEST_BYTES}-byte limit",
                    bytes.len()
                ),
            });
        }
        let raw: RawManifest =
            serde_json::from_slice(bytes).map_err(|source| RepoError::OciInvalidArtifact {
                reason: format!("manifest is not valid OCI image manifest JSON: {source}"),
            })?;
        match raw.schema_version {
            Some(2) => {}
            other => {
                return Err(RepoError::OciInvalidArtifact {
                    reason: format!("manifest schemaVersion must be 2, got {other:?}"),
                });
            }
        }
        if raw.layers.is_empty() {
            return Err(RepoError::OciInvalidArtifact {
                reason: "manifest declares no layers, so there is no artifact to extract"
                    .to_owned(),
            });
        }
        let mut layers = Vec::with_capacity(raw.layers.len());
        for layer in raw.layers {
            validate_digest(&layer.digest)?;
            layers.push(OciDescriptor::new(
                layer.media_type,
                layer.digest,
                layer.size,
            ));
        }
        Ok(Self {
            media_type: raw.media_type,
            layers,
        })
    }

    /// Returns the artifact's single layer.
    ///
    /// # Errors
    ///
    /// [`RepoError::OciInvalidArtifact`] when the manifest carries zero or more than one layer: an
    /// artifact whose content would be the union of several layers cannot be rendered as one
    /// directory without ambiguity.
    pub fn single_layer(&self) -> Result<&OciDescriptor, RepoError> {
        match self.layers.as_slice() {
            [layer] => Ok(layer),
            other => Err(RepoError::OciInvalidArtifact {
                reason: format!(
                    "an artifact layer must carry exactly one layer, got {}",
                    other.len()
                ),
            }),
        }
    }
}

/// Verifies an artifact's manifest digest, parses it, and extracts its single layer into `dest`.
///
/// This is the whole "fetch an artifact" pipeline minus the network: a registry client
/// ([`OciClient`]) fetches the manifest and layer bytes, and hands them here.
///
/// # Errors
///
/// Every failure is terminal and is reported before anything is handed to a renderer:
/// [`RepoError::OciDigestMismatch`] (manifest or layer digest), [`RepoError::OciInvalidArtifact`]
/// (malformed/wrapped manifest), [`RepoError::OciUnsupportedMediaType`],
/// [`RepoError::UnsafeArchive`] (tar-slip, link, device node, duplicate entry),
/// [`RepoError::CheckoutLimitExceeded`] (file-count/byte/decompression budget), and
/// [`RepoError::UnsafeSymlink`] (the post-extraction sanitizer).
///
/// # Blocking
///
/// Performs blocking filesystem and CPU work: call it inside [`tokio::task::spawn_blocking`].
pub fn extract_artifact(
    manifest_bytes: &[u8],
    expected_manifest_digest: &str,
    layer: impl Read,
    dest: &Path,
    limits: &WorktreeLimits,
) -> Result<PathBuf, RepoError> {
    // 1. The manifest is verified *before* it is interpreted: a registry (or a proxy) that serves a
    //    manifest for the digest we pinned cannot be trusted to serve the body we asked for.
    verify_digest(expected_manifest_digest, manifest_bytes)?;
    let manifest = OciManifest::parse(manifest_bytes)?;
    let layer_descriptor = manifest.single_layer()?;
    extract_layer(layer, layer_descriptor, dest, limits)
}

/// Spools `raw` to a temporary file, verifies it against `layer`, then extracts the gzip tar into
/// `dest`.
///
/// The order matters: the blob is hashed **while it is spooled**, the digest is compared before the
/// spool is decompressed, and only a verified blob reaches the tar reader. `dest` is created when
/// missing and must be empty, must be a real directory rather than a symlink, and its parent must
/// exist; the returned root is `dest` itself, or the chart directory inside it when a Helm layer is
/// unwrapped.
///
/// A failure **after** `dest` is proven usable restores it: the directory is removed again when
/// this call created it, and only emptied when it pre-existed. A half-extracted tree would
/// otherwise be refused terminally as "must be empty" on the next attempt, hiding the retryable
/// cause (a full disk, a busy device, a cancelled worker) — and deleting a caller-owned directory
/// would take storage this module never owned.
///
/// # Errors
///
/// See [`extract_artifact`].
///
/// # Blocking
///
/// Performs blocking I/O and CPU work: call it inside [`tokio::task::spawn_blocking`].
pub fn extract_layer(
    raw: impl Read,
    layer: &OciDescriptor,
    dest: &Path,
    limits: &WorktreeLimits,
) -> Result<PathBuf, RepoError> {
    if !is_supported_layer_media_type(&layer.media_type) {
        return Err(RepoError::OciUnsupportedMediaType {
            media_type: layer.media_type.clone(),
        });
    }
    validate_digest(&layer.digest)?;
    // The compressed blob is bounded by the same budget as the checkout, plus a documented
    // allowance for tar headers/padding and gzip framing.
    let spool_limit = limits.max_bytes.saturating_add(ARCHIVE_OVERHEAD_BYTES);

    let mut spool = tempfile::NamedTempFile::new().map_err(|source| RepoError::Io {
        context: "creating the OCI layer spool file".to_owned(),
        source,
    })?;
    let (spooled, actual_digest) = {
        let mut writer = BufWriter::new(spool.as_file_mut());
        let mut hasher = Sha256::new();
        let mut input = raw;
        let mut buffer = vec![0u8; 64 * 1024];
        let mut spooled = 0u64;
        loop {
            let read = input.read(&mut buffer).map_err(|source| RepoError::Io {
                context: "reading the OCI artifact layer".to_owned(),
                source,
            })?;
            if read == 0 {
                break;
            }
            spooled = spooled.saturating_add(read as u64);
            if spooled > spool_limit {
                return Err(RepoError::CheckoutLimitExceeded {
                    reason: format!(
                        "OCI artifact layer exceeds the {spool_limit}-byte compressed budget \
                         ({})",
                        limits.max_bytes
                    ),
                });
            }
            hasher.update(&buffer[..read]);
            writer
                .write_all(&buffer[..read])
                .map_err(|source| RepoError::Io {
                    context: "spooling the OCI artifact layer".to_owned(),
                    source,
                })?;
        }
        writer.flush().map_err(|source| RepoError::Io {
            context: "flushing the OCI artifact layer spool".to_owned(),
            source,
        })?;
        let digest = format!("{DIGEST_PREFIX}{:x}", hasher.finalize());
        (spooled, digest)
    };

    // 2. Digest and size are checked against the (verified) manifest descriptor before the spool is
    //    interpreted. A registry cannot smuggle extra bytes in: anything beyond the declared size
    //    changes the digest, which is fatal.
    if actual_digest != layer.digest {
        return Err(RepoError::OciDigestMismatch {
            expected: layer.digest.clone(),
            actual: actual_digest,
        });
    }
    if let Some(expected) = layer.size
        && expected != spooled
    {
        return Err(RepoError::OciInvalidArtifact {
            reason: format!(
                "layer descriptor declares {expected} bytes but the registry served {spooled}"
            ),
        });
    }

    let mut reader = spool.reopen().map_err(|source| RepoError::Io {
        context: "reopening the OCI layer spool".to_owned(),
        source,
    })?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|source| RepoError::Io {
            context: "rewinding the OCI layer spool".to_owned(),
            source,
        })?;

    // Everything below runs against a directory this call created or proved empty. A failure
    // there (an I/O error, a rejected entry, a budget overrun, a cancelled worker) must not leave a
    // half-extracted tree behind: `create_empty_directory` refuses a non-empty `dest`, so a retry
    // would otherwise turn a *retryable* I/O error into a terminal "must be empty" refusal.
    let created = create_empty_directory(dest)?;
    let extracted = extract_into(reader, dest, limits, &layer.media_type);
    if extracted.is_err() {
        // The rollback is only ever allowed to remove what this call created. `dest` may be a
        // caller-owned directory that merely *happened* to be empty (the fake client extracts into
        // the root of a `tempfile::TempDir`), and deleting it would take the caller's storage with
        // it — so the pre-existing case is restored to the empty directory it was instead.
        if created {
            let _ = std::fs::remove_dir_all(dest);
        } else {
            remove_directory_contents(dest);
        }
    }
    extracted
}

/// Extracts the spooled layer into the (already created, empty) `dest` and returns the effective
/// root.
///
/// Split out of [`extract_layer`] so the "remove a partial extraction" cleanup lives on exactly one
/// error path, and a later step can never be added that bypasses it.
fn extract_into(
    reader: impl Read,
    dest: &Path,
    limits: &WorktreeLimits,
    media_type: &str,
) -> Result<PathBuf, RepoError> {
    let budget = Budget::new(*limits);
    extract_tar_gzip(BufReader::new(reader), dest, budget)?;

    // 3. Reject anything the tar reader accepted that the worktree walk would not: this is the same
    //    pass the Git path runs, so both sources reach a renderer under identical guarantees.
    sanitize_worktree(dest, limits)?;

    // 4. Helm charts wrap their files in `<chart-name>/`; ORAS/Flux bundles usually do not.
    effective_root(dest, media_type)
}

/// Shared resource budget for one extraction.
#[derive(Debug)]
struct Budget {
    limits: WorktreeLimits,
    /// Filesystem entries created so far.
    files: usize,
    /// Decompressed bytes read from the archive, headers and padding included.
    decompressed: u64,
    /// Regular-file bytes written.
    content: u64,
}

impl Budget {
    fn new(limits: WorktreeLimits) -> Self {
        Self {
            limits,
            files: 0,
            decompressed: 0,
            content: 0,
        }
    }

    /// Charges `bytes` of the decompressed stream.
    fn charge_stream(&mut self, bytes: u64) -> Result<(), RepoError> {
        self.decompressed = self.decompressed.saturating_add(bytes);
        if self.decompressed > self.limits.max_bytes {
            return Err(RepoError::CheckoutLimitExceeded {
                reason: format!(
                    "OCI artifact decompresses to more than {} bytes",
                    self.limits.max_bytes
                ),
            });
        }
        Ok(())
    }

    /// Charges one filesystem entry.
    fn charge_entry(&mut self) -> Result<(), RepoError> {
        self.files = self.files.saturating_add(1);
        if self.files > self.limits.max_files {
            return Err(RepoError::CheckoutLimitExceeded {
                reason: format!(
                    "OCI artifact contains more than {} filesystem entries",
                    self.limits.max_files
                ),
            });
        }
        Ok(())
    }

    /// Charges `bytes` of entry content about to be written.
    fn charge_content(&mut self, bytes: u64) -> Result<(), RepoError> {
        self.content = self.content.saturating_add(bytes);
        if self.content > self.limits.max_bytes {
            return Err(RepoError::CheckoutLimitExceeded {
                reason: format!(
                    "OCI artifact regular-file content exceeds {} bytes",
                    self.limits.max_bytes
                ),
            });
        }
        Ok(())
    }
}

/// One parsed tar header.
struct TarEntry {
    path: PathBuf,
    kind: EntryKind,
    size: u64,
}

/// Entry kinds this module accepts.
enum EntryKind {
    File,
    Directory,
    /// A directory entry that names the archive root itself (`./`), which `tar -C dir -cf - .`
    /// emits. It carries no content, so it is skipped rather than rejected: rejecting it would make
    /// a perfectly ordinary bundle unpackable.
    Root,
}

/// Streams a gzip-compressed tar archive into `dest`, enforcing `budget` and rejecting every entry
/// type that is not a plain file or a directory.
fn extract_tar_gzip(reader: impl Read, dest: &Path, mut budget: Budget) -> Result<(), RepoError> {
    let mut decoder = flate2::read::GzDecoder::new(reader);
    let mut header = [0u8; TAR_BLOCK];

    loop {
        // A clean end-of-stream at a block boundary ends the archive; a *partial* header does not.
        if matches!(
            read_block(&mut decoder, &mut header, &mut budget)?,
            BlockRead::EndOfStream
        ) {
            break;
        }

        let Some(entry) = parse_header(&header)? else {
            // An all-zero block is the tar end-of-archive marker.
            break;
        };

        let target = dest.join(&entry.path);
        // Defense in depth, and deliberately *not* the tar-slip guard: `sanitize_entry_path` has
        // already rejected absolute, `..`, and non-UTF-8 names, so this comparison can never fire
        // for a path that reached it. It is kept because it is the only check that compares against
        // the real `dest`, and [`Path::starts_with`] is component-aware — `../artifact-evil` would
        // not satisfy it, whereas a string-prefix test would.
        if !target.starts_with(dest) {
            return Err(RepoError::UnsafeArchive {
                path: entry.path.clone(),
                reason: "archive entry escapes the extraction root".to_owned(),
            });
        }

        match entry.kind {
            // The archive root already exists (it is `dest`).
            EntryKind::Root => {}
            EntryKind::Directory => {
                budget.charge_entry()?;
                std::fs::create_dir_all(&target).map_err(|source| {
                    entry_fs_error(
                        source,
                        &entry.path,
                        format!("creating archive directory '{}'", entry.path.display()),
                    )
                })?;
            }
            EntryKind::File => {
                budget.charge_entry()?;
                budget.charge_content(entry.size)?;
                write_file(&mut decoder, &entry, &target, &mut budget)?;
            }
        }

        skip_padding(&mut decoder, entry.size, &mut budget)?;
    }

    Ok(())
}

/// Outcome of reading one tar block.
enum BlockRead {
    /// A full block was read.
    Block,
    /// The archive ended exactly at a block boundary.
    EndOfStream,
}

/// Reads one 512-byte block, charging it against the decompression budget.
fn read_block(
    reader: &mut impl Read,
    buffer: &mut [u8; TAR_BLOCK],
    budget: &mut Budget,
) -> Result<BlockRead, RepoError> {
    let mut filled = 0usize;
    while filled < TAR_BLOCK {
        let read = reader
            .read(&mut buffer[filled..])
            .map_err(|source| RepoError::Io {
                context: "decompressing an OCI artifact layer".to_owned(),
                source,
            })?;
        if read == 0 {
            if filled == 0 {
                return Ok(BlockRead::EndOfStream);
            }
            return Err(RepoError::OciInvalidArtifact {
                reason: format!("tar archive is truncated inside a {TAR_BLOCK}-byte header block"),
            });
        }
        budget.charge_stream(read as u64)?;
        filled += read;
    }
    Ok(BlockRead::Block)
}

/// Parses one tar header block, or returns `None` for the end-of-archive marker.
fn parse_header(block: &[u8; TAR_BLOCK]) -> Result<Option<TarEntry>, RepoError> {
    if block.iter().all(|byte| *byte == 0) {
        return Ok(None);
    }
    verify_checksum(block)?;

    let name = field(block, 0, 100);
    let prefix = field(block, 345, 500);
    let mut raw_path = Vec::with_capacity(prefix.len() + name.len() + 1);
    if !prefix.is_empty() {
        raw_path.extend_from_slice(prefix);
        raw_path.push(b'/');
    }
    raw_path.extend_from_slice(name);
    let path =
        PathBuf::from(
            String::from_utf8(raw_path).map_err(|_| RepoError::UnsafeArchive {
                path: PathBuf::from("<non-utf8>"),
                reason: "archive entry name is not valid UTF-8".to_owned(),
            })?,
        );

    let kind = match block[156] {
        b'0' | 0 => EntryKind::File,
        b'5' => EntryKind::Directory,
        other => {
            return Err(RepoError::UnsafeArchive {
                path,
                reason: format!(
                    "unsupported archive entry type '{}' (only plain files and directories are \
                     accepted)",
                    describe_entry_type(other)
                ),
            });
        }
    };

    let size = parse_octal(block, 124, 136)?;
    if matches!(kind, EntryKind::Directory) && size != 0 {
        return Err(RepoError::UnsafeArchive {
            path,
            reason: "directory entry declares a non-zero size".to_owned(),
        });
    }
    let Some(path) = sanitize_entry_path(&path)? else {
        // Only a directory may name the archive root (`./`); a *file* named `.` is malformed.
        if matches!(kind, EntryKind::Directory) && size == 0 {
            return Ok(Some(TarEntry {
                path: PathBuf::new(),
                kind: EntryKind::Root,
                size: 0,
            }));
        }
        return Err(RepoError::UnsafeArchive {
            path,
            reason: "archive entry name resolves to the extraction root".to_owned(),
        });
    };
    Ok(Some(TarEntry { path, kind, size }))
}

/// Returns the bytes of `block[start..end]`, trailing NULs and spaces removed.
fn field(block: &[u8; TAR_BLOCK], start: usize, end: usize) -> &[u8] {
    let slice = &block[start..end];
    let len = slice
        .iter()
        .rposition(|byte| *byte != 0 && *byte != b' ')
        .map_or(0, |index| index + 1);
    &slice[..len]
}

/// Decodes an octal numeric field, rejecting the GNU base-256 extension.
fn parse_octal(block: &[u8; TAR_BLOCK], start: usize, end: usize) -> Result<u64, RepoError> {
    let raw = field(block, start, end);
    if raw.is_empty() {
        return Ok(0);
    }
    if raw[0] & 0x80 != 0 {
        return Err(RepoError::UnsafeArchive {
            path: PathBuf::from("<base-256>"),
            reason: "GNU base-256 numeric tar fields are not supported".to_owned(),
        });
    }
    let text = std::str::from_utf8(raw).map_err(|_| RepoError::UnsafeArchive {
        path: PathBuf::from("<octal>"),
        reason: "tar numeric field is not ASCII".to_owned(),
    })?;
    // Some writers space-pad instead of NUL-padding; both spellings mean the same number.
    let text = text.trim();
    // `u64::from_str_radix` accepts a leading `'+'`, but a tar numeric field is never signed: a
    // signed one is a mis-framed header, and reading `+00000000010` as the same size a real writer
    // would spell `00000000010` would hide exactly the framing damage the parser exists to catch.
    if text.starts_with('+') {
        return Err(RepoError::UnsafeArchive {
            path: PathBuf::from("<octal>"),
            reason: format!("tar numeric field {text:?} must not carry a sign"),
        });
    }
    u64::from_str_radix(text, 8).map_err(|_| RepoError::UnsafeArchive {
        path: PathBuf::from("<octal>"),
        reason: format!("tar numeric field {text:?} is not octal"),
    })
}

/// Verifies the header checksum, which catches a mis-framed archive (and therefore any attempt to
/// sneak a second archive into a stream this parser would otherwise misread).
fn verify_checksum(block: &[u8; TAR_BLOCK]) -> Result<(), RepoError> {
    let expected = parse_octal(block, 148, 156)?;
    let actual: u64 = block
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (148..156).contains(&index) {
                u64::from(b' ')
            } else {
                u64::from(*byte)
            }
        })
        .sum();
    if expected != actual {
        return Err(RepoError::OciInvalidArtifact {
            reason: format!(
                "tar header checksum mismatch: header declares {expected}, computed {actual}"
            ),
        });
    }
    Ok(())
}

/// Human-readable label for a rejected tar entry type.
fn describe_entry_type(typeflag: u8) -> String {
    let name = match typeflag {
        b'1' => "hardlink",
        b'2' => "symlink",
        b'3' => "character device",
        b'4' => "block device",
        b'6' => "FIFO",
        b'7' => "contiguous file",
        b'L' => "GNU long name",
        b'K' => "GNU long link",
        b'x' | b'X' => "PAX extended header",
        b'g' => "PAX global header",
        b'S' => "GNU sparse file",
        b'V' => "GNU volume header",
        _ => return format!("0x{typeflag:02x}"),
    };
    format!("{name} ('{}')", typeflag as char)
}

/// Rejects absolute, escaping, non-UTF-8-ish, or control-character entry paths.
///
/// Returns `Ok(None)` when the name resolves to nothing but `.` components (the archive root).
fn sanitize_entry_path(path: &Path) -> Result<Option<PathBuf>, RepoError> {
    let unsafe_path = |reason: &str| RepoError::UnsafeArchive {
        path: path.to_path_buf(),
        reason: reason.to_owned(),
    };
    if path.as_os_str().is_empty() {
        return Err(unsafe_path("archive entry name is empty"));
    }
    let raw = path.to_string_lossy();
    if raw.chars().any(|c| c.is_control()) {
        return Err(unsafe_path(
            "archive entry name contains control characters",
        ));
    }
    if raw.contains('\\') {
        return Err(unsafe_path("archive entry name contains '\\'"));
    }
    if path.is_absolute() {
        return Err(unsafe_path("archive entry name is absolute"));
    }
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(segment) => clean.push(segment),
            Component::RootDir | Component::Prefix(_) => {
                return Err(unsafe_path("archive entry name is absolute"));
            }
            Component::ParentDir => {
                return Err(unsafe_path(
                    "archive entry name contains a '..' traversal segment",
                ));
            }
        }
    }
    if clean.as_os_str().is_empty() {
        return Ok(None);
    }
    Ok(Some(clean))
}

/// Writes one regular-file entry from the archive into `target`.
fn write_file(
    decoder: &mut impl Read,
    entry: &TarEntry,
    target: &Path,
    budget: &mut Budget,
) -> Result<(), RepoError> {
    let parent = target.parent().ok_or_else(|| RepoError::UnsafeArchive {
        path: entry.path.clone(),
        reason: "archive entry has no parent directory".to_owned(),
    })?;
    std::fs::create_dir_all(parent).map_err(|source| {
        entry_fs_error(
            source,
            &entry.path,
            format!("creating '{}' for an archive entry", parent.display()),
        )
    })?;

    // `create_new` refuses a duplicate entry instead of overwriting it: two entries claiming the
    // same path make "which one did the renderer see?" unanswerable. The same call fails when the
    // path exists as a *directory* (or when an earlier entry was a file where this one needs a
    // directory), so the message names the collision, not only duplication.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target)
        .map_err(|source| match source.kind() {
            std::io::ErrorKind::AlreadyExists => RepoError::UnsafeArchive {
                path: entry.path.clone(),
                reason: "archive entry collides with a path that already exists in the extraction \
                         root (a duplicate entry path, or a file where a directory is required)"
                    .to_owned(),
            },
            _ => RepoError::Io {
                context: format!("creating archive entry '{}'", entry.path.display()),
                source,
            },
        })?;

    let mut remaining = entry.size;
    let mut buffer = vec![0u8; 64 * 1024];
    while remaining > 0 {
        let want = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        let read = decoder
            .read(&mut buffer[..want])
            .map_err(|source| RepoError::Io {
                context: "decompressing an OCI artifact layer".to_owned(),
                source,
            })?;
        if read == 0 {
            return Err(RepoError::OciInvalidArtifact {
                reason: format!(
                    "tar archive is truncated inside entry '{}'",
                    entry.path.display()
                ),
            });
        }
        budget.charge_stream(read as u64)?;
        file.write_all(&buffer[..read])
            .map_err(|source| RepoError::Io {
                context: format!("writing archive entry '{}'", entry.path.display()),
                source,
            })?;
        remaining -= read as u64;
    }
    Ok(())
}

/// Reads and counts the zero padding that follows a `size`-byte entry.
fn skip_padding(decoder: &mut impl Read, size: u64, budget: &mut Budget) -> Result<(), RepoError> {
    let remainder = size % TAR_BLOCK as u64;
    if remainder == 0 {
        return Ok(());
    }
    let padding = (TAR_BLOCK as u64 - remainder) as usize;
    let mut buffer = [0u8; TAR_BLOCK];
    let mut filled = 0usize;
    while filled < padding {
        let read = decoder
            .read(&mut buffer[filled..padding])
            .map_err(|source| RepoError::Io {
                context: "decompressing an OCI artifact layer".to_owned(),
                source,
            })?;
        if read == 0 {
            return Err(RepoError::OciInvalidArtifact {
                reason: "tar archive is truncated inside entry padding".to_owned(),
            });
        }
        budget.charge_stream(read as u64)?;
        filled += read;
    }
    Ok(())
}

/// Classifies a filesystem failure met while writing an archive entry.
///
/// A conflict (`NotADirectory`/`IsADirectory`, or the `AlreadyExists` that `create_dir_all` reports
/// when an ancestor is a regular file) means the archive itself is malformed — one entry is a file
/// where another needs a directory — so it is a terminal [`RepoError::UnsafeArchive`]. Classifying
/// it as retryable I/O would make a hostile archive retry forever. Genuinely transient I/O (a full
/// disk, a busy device) stays retryable.
fn entry_fs_error(source: std::io::Error, path: &Path, context: String) -> RepoError {
    match source.kind() {
        std::io::ErrorKind::NotADirectory
        | std::io::ErrorKind::IsADirectory
        | std::io::ErrorKind::AlreadyExists => RepoError::UnsafeArchive {
            path: path.to_path_buf(),
            reason: "archive entry conflicts with another entry (a file where a directory is \
                     required, or the reverse)"
                .to_owned(),
        },
        _ => RepoError::Io { context, source },
    }
}

/// Creates `dest` after proving it is empty, and reports whether **this call** created it.
///
/// The return value is what keeps [`extract_layer`]'s rollback honest: a caller-supplied directory
/// that merely happened to be empty (a `TempDir` root, a lease directory) must survive a failed
/// extraction, so only a directory this call created is removed again.
///
/// A `dest` that is a **symlink** is refused outright. `create_dir` reports `AlreadyExists` for it
/// and `read_dir` follows the link, so an empty directory *behind* the link would be extracted into
/// — writing outside the root this module believes it owns — and a non-empty one would report a
/// misleading "must be empty". `symlink_metadata` is the only lookup that does not follow it, and it
/// runs **twice** (finding M-C): before `create_dir` and again in the `AlreadyExists` arm, because a
/// link swapped in between those two calls would otherwise be the one `read_dir` follows. That
/// second inspection *narrows* the window rather than closing it — the full fix (`openat` +
/// `O_NOFOLLOW` on one descriptor) is deferred, see the arm's own comment.
///
/// A `dest` that exists as anything other than a directory is a **terminal** refusal, not an I/O
/// error (finding N-A): `read_dir` would report `NotADirectory`, which `RepoError::Io` classifies as
/// retryable, and no number of retries turns a file into a directory.
fn create_empty_directory(dest: &Path) -> Result<bool, RepoError> {
    match std::fs::symlink_metadata(dest) {
        Ok(metadata) => inspect_existing_root(dest, &metadata)?,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(RepoError::Io {
                context: format!("inspecting extraction root '{}'", dest.display()),
                source,
            });
        }
    }

    // Test seam (finding M-3): the gap between the two lookups is a few microseconds wide, so the
    // `AlreadyExists` arm below cannot be reached deterministically from outside — arranging the
    // filesystem beforehand is exactly what the pre-check catches. This hook is compiled in for
    // `cfg(test)` only and runs the installed closure exactly inside that gap.
    run_pre_create_seam(dest);

    match std::fs::create_dir(dest) {
        Ok(()) => Ok(true),
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
            // M-C: re-inspect rather than assume. The pre-check above ran *before* `create_dir`, so
            // this arm catches a link (or a file) that appeared in between, and refuses it exactly
            // like one that was there all along.
            //
            // TODO(M-C): full fix is openat + O_NOFOLLOW on one descriptor (deferred).
            // This **narrows** the swap window, it does not close it: `symlink_metadata` here and
            // the `read_dir` below are still two separate lookups, so the entry can be swapped again
            // in the gap between them and the second lookup follows the new link. Closing the window
            // needs both inspections *and* the listing to happen through one directory handle
            // (`openat` + `O_NOFOLLOW`, i.e. `open` the root with `O_DIRECTORY | O_NOFOLLOW` and
            // `read_dir` from that `File`), which needs a platform flag constant (`libc`-style, a new
            // dependency) plus per-platform `cfg` code. Deferred.
            let metadata = std::fs::symlink_metadata(dest).map_err(|source| RepoError::Io {
                context: format!("re-inspecting extraction root '{}'", dest.display()),
                source,
            })?;
            inspect_existing_root(dest, &metadata)?;

            let mut entries = std::fs::read_dir(dest).map_err(|source| {
                if source.kind() == std::io::ErrorKind::NotADirectory {
                    // N-A: the root cannot become a directory by being retried.
                    not_a_directory_root(dest)
                } else {
                    RepoError::Io {
                        context: format!("reading extraction root '{}'", dest.display()),
                        source,
                    }
                }
            })?;
            if entries.next().is_some() {
                return Err(RepoError::OciInvalidArtifact {
                    reason: format!(
                        "extraction root '{}' must be empty, otherwise an earlier artifact's files \
                         could be rendered as part of this one",
                        dest.display()
                    ),
                });
            }
            Ok(false)
        }
        Err(source) => Err(RepoError::Io {
            context: format!("creating extraction root '{}'", dest.display()),
            source,
        }),
    }
}

/// Installs the [`run_pre_create_seam`] hook of the current thread (finding M-3).
///
/// Compiled in for `cfg(test)` only; production builds have no seam to install. A test calls this
/// immediately before [`create_empty_directory`], so the closure runs inside the gap between the
/// pre-check and `create_dir` and can put a symlink (or a file, or a non-empty directory) where the
/// `AlreadyExists` arm will meet it.
#[cfg(test)]
mod seam {
    use std::cell::RefCell;
    use std::path::Path;

    type Hook = Box<dyn FnOnce(&Path)>;

    thread_local! {
        /// The hook the running test installed; `run` takes it so it fires at most once.
        static HOOK: RefCell<Option<Hook>> = RefCell::new(None);
    }

    /// Queues `hook` for the next `create_dir` attempt on this thread.
    pub(super) fn install(hook: impl FnOnce(&Path) + 'static) {
        HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    }

    /// Runs and clears the queued hook, if any.
    pub(super) fn run(dest: &Path) {
        let hook = HOOK.with(|slot| slot.borrow_mut().take());
        if let Some(hook) = hook {
            hook(dest);
        }
    }
}

/// Runs the [`seam`] hook a test installed, if any (see the `cfg(test)` twin below it).
#[cfg(test)]
fn run_pre_create_seam(dest: &Path) {
    seam::run(dest);
}

/// No-op in every non-test build.
///
/// The seam exists only so the `AlreadyExists` arm of [`create_empty_directory`] is reachable from a
/// deterministic test; production keeps a single call and no hook storage.
#[cfg(not(test))]
fn run_pre_create_seam(_dest: &Path) {}

/// Refuses an existing `dest` that cannot be an extraction root: a symlink, or a non-directory.
///
/// Used on **both** inspections in [`create_empty_directory`] (finding M-C), so the two cannot
/// drift: whatever is refused before `create_dir` is refused again after an `AlreadyExists`.
fn inspect_existing_root(dest: &Path, metadata: &std::fs::Metadata) -> Result<(), RepoError> {
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        let target = std::fs::read_link(dest).map_err(|source| RepoError::Io {
            context: format!("reading the extraction root symlink '{}'", dest.display()),
            source,
        })?;
        return Err(RepoError::UnsafeSymlink {
            path: dest.to_path_buf(),
            target,
            reason: "the extraction root must be a real directory, not a symlink".to_owned(),
        });
    }
    if !file_type.is_dir() {
        return Err(not_a_directory_root(dest));
    }
    Ok(())
}

/// Terminal error for an extraction root that exists as something other than a directory.
///
/// `OciInvalidArtifact` and not `Io`: an `Io` error is retryable, and a root that is a regular file
/// (or a device node, or a FIFO) will still not be a directory on the next attempt — the reconcile
/// loop would retry forever instead of surfacing the misconfiguration (finding N-A).
fn not_a_directory_root(dest: &Path) -> RepoError {
    RepoError::OciInvalidArtifact {
        reason: format!(
            "extraction root '{}' must be a directory, but it exists as a non-directory",
            dest.display()
        ),
    }
}

/// Empties `dest` without removing it, restoring the empty directory a caller handed us.
///
/// Only called on a `dest` that was proven empty before extraction started, so every entry inside
/// it is one this attempt wrote. Failures are ignored on purpose: this runs on an error path that
/// has already decided what to report, and a leftover file only costs a retry, not correctness.
fn remove_directory_contents(dest: &Path) {
    let Ok(entries) = std::fs::read_dir(dest) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
            let _ = std::fs::remove_dir_all(&path);
        } else {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// Returns the directory a renderer should treat as the artifact root.
///
/// Helm charts published to a registry wrap their content in a single `<chart-name>/` directory;
/// ORAS/Flux bundles usually do not. The unwrap therefore requires **all** of: the Helm media type,
/// exactly one top-level entry, that entry being a directory, and a regular `Chart.yaml` inside it.
fn effective_root(root: &Path, media_type: &str) -> Result<PathBuf, RepoError> {
    if media_type != HELM_CHART_MEDIA_TYPE {
        return Ok(root.to_path_buf());
    }
    let mut entries = std::fs::read_dir(root)
        .map_err(|source| RepoError::Io {
            context: format!("reading extraction root '{}'", root.display()),
            source,
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| RepoError::Io {
            context: format!("reading extraction root '{}'", root.display()),
            source,
        })?;
    if entries.len() != 1 {
        return Ok(root.to_path_buf());
    }
    let entry = entries.pop().ok_or_else(|| RepoError::OciInvalidArtifact {
        reason: "extraction root is empty".to_owned(),
    })?;
    let file_type = entry.file_type().map_err(|source| RepoError::Io {
        context: format!("inspecting '{}'", entry.path().display()),
        source,
    })?;
    if !file_type.is_dir() {
        return Ok(root.to_path_buf());
    }
    let chart = entry.path().join("Chart.yaml");
    match std::fs::symlink_metadata(&chart) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(entry.path()),
        _ => Ok(root.to_path_buf()),
    }
}

/// Boxed `Send` future returned by object-safe [`OciClient`] methods.
pub type OciFuture<'a, T> = std::pin::Pin<
    std::boxed::Box<dyn std::future::Future<Output = Result<T, RepoError>> + Send + 'a>,
>;

/// Immutable identity of a resolved OCI artifact.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResolvedDigest {
    /// Canonical `sha256:<64-hex>` manifest digest.
    pub manifest_digest: String,
    /// The tag or digest the caller asked for (`"1.4.2"`, `"sha256:…"`).
    pub requested_ref: String,
}

/// Asynchronous, object-safe interface for resolving an OCI artifact to a digest and fetching it as
/// a read-only checkout.
///
/// Mirrors [`GitClient`](super::GitClient) deliberately: `resolve_digest` is the "what immutable
/// revision does this reference mean?" half, and `fetch_artifact` is the "materialize exactly that
/// revision" half. No registry-client type appears in this signature, so a third-party OCI crate
/// (or a fake) stays entirely behind this module.
pub trait OciClient: Send + Sync {
    /// Resolves `src` (tag and/or pinned digest) into an immutable manifest digest.
    ///
    /// When `src.digest` is set the returned digest must equal it; a tag that moved is an error, not
    /// a silent re-resolution.
    fn resolve_digest<'a>(
        &'a self,
        src: &'a OciSource,
        creds: &'a RepoCredentials,
    ) -> OciFuture<'a, ResolvedDigest>;

    /// Materializes the artifact at `digest` as a read-only checkout.
    fn fetch_artifact<'a>(
        &'a self,
        src: &'a OciSource,
        digest: &'a str,
        creds: &'a RepoCredentials,
    ) -> OciFuture<'a, RepoCheckout>;
}

#[cfg(any(test, feature = "test-utils"))]
pub use fake::{FakeOciClient, FakeOciClientConfig};

/// Deterministic, hermetic [`OciClient`] for tests and downstream crates.
#[cfg(any(test, feature = "test-utils"))]
mod fake {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use super::{
        OCI_IMAGE_LAYER_MEDIA_TYPE, OciClient, OciFuture, OciSource, OciUrlPolicy, RepoCheckout,
        RepoCredentials, RepoError, ResolvedDigest, WorktreeLimits, extract_artifact,
        redact_oci_url_credentials, validate_digest,
    };

    /// The `<url>:<reference>` string a fake records, with any embedded userinfo redacted.
    ///
    /// The redaction lives in this one helper (finding M-B), not at the two call sites — `fetches()`
    /// and the `RevisionNotFound` message — so a caller this fake grows later cannot format
    /// `src.url` unredacted. That is a **structural** guarantee; it is not observable through today's
    /// call sites, because `resolve_digest`/`fetch_artifact` both `validate` first and
    /// `validate_oci_url` refuses embedded userinfo, so a credentialed `src.url` never reaches them
    /// at all (the fake-client test below pins that ordering as well as this helper).
    pub(super) fn fake_reference(url: &str, reference: &str) -> String {
        format!("{}:{reference}", redact_oci_url_credentials(url))
    }

    /// Configuration of a [`FakeOciClient`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct FakeOciClientConfig {
        /// Budgets enforced while extracting a registered artifact.
        pub limits: WorktreeLimits,
        /// URL policy `resolve_digest`/`fetch_artifact` validate `src` with.
        ///
        /// [`OciUrlPolicy::Production`] (the default) is what a real caller uses, so a test that
        /// wants a plaintext `http://` registry has to ask for
        /// [`OciUrlPolicy::AllowLocal`] explicitly — exactly like the production opt-in.
        pub url_policy: OciUrlPolicy,
    }

    /// One registered artifact: the exact bytes a registry would serve.
    #[derive(Debug, Clone)]
    struct FakeArtifact {
        manifest: Vec<u8>,
        layer: Vec<u8>,
        manifest_digest: String,
    }

    /// An [`OciClient`] over in-memory artifacts, keyed by `(<url>, <reference>)`.
    ///
    /// `fetch_artifact` runs the **real** extraction pipeline
    /// ([`extract_artifact`](super::extract_artifact)) inside
    /// [`tokio::task::spawn_blocking`], so tests that drive it exercise digest verification,
    /// tar-entry rejection, budgets, and the post-extraction sanitizer rather than a stub.
    #[derive(Debug, Clone, Default)]
    pub struct FakeOciClient {
        config: FakeOciClientConfig,
        artifacts: BTreeMap<(String, String), FakeArtifact>,
        fetches: Arc<Mutex<Vec<String>>>,
    }

    impl FakeOciClient {
        /// Creates a client with default limits.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Creates a client with `config`.
        #[must_use]
        pub fn with_config(config: FakeOciClientConfig) -> Self {
            Self {
                config,
                ..Self::default()
            }
        }

        /// Registers a pre-built tar+gzip layer under `(url, reference)`.
        ///
        /// The manifest is synthesized (one layer, generic OCI image layer media type) and its
        /// digest is computed, so the client always serves a *self-consistent* artifact — a test
        /// that wants a corrupt one registers a raw manifest instead.
        #[must_use]
        pub fn with_layer(mut self, url: &str, reference: &str, layer: Vec<u8>) -> Self {
            // Assembled as text, not through a map: the manifest bytes (and therefore the digest)
            // must be byte-stable, and there is no fallible step to paper over.
            let manifest = format!(
                concat!(
                    r#"{{"schemaVersion":2,"#,
                    r#""mediaType":"application/vnd.oci.image.manifest.v1+json","#,
                    r#""layers":[{{"mediaType":"{media_type}","digest":"{digest}","size":{size}}}]}}"#
                ),
                media_type = OCI_IMAGE_LAYER_MEDIA_TYPE,
                digest = super::sha256_digest(&layer),
                size = layer.len(),
            )
            .into_bytes();
            self.register(url, reference, manifest, layer);
            self
        }

        /// Registers an artifact from raw bytes, so a test can serve a manifest whose digest does
        /// not match its layer.
        pub fn register(
            &mut self,
            url: &str,
            reference: &str,
            manifest: Vec<u8>,
            layer: Vec<u8>,
        ) -> &mut Self {
            let manifest_digest = super::sha256_digest(&manifest);
            self.artifacts.insert(
                (url.to_owned(), reference.to_owned()),
                FakeArtifact {
                    manifest,
                    layer,
                    manifest_digest,
                },
            );
            self
        }

        /// The `(url, reference)` pairs `fetch_artifact` was called with, in order.
        #[must_use]
        pub fn fetches(&self) -> Vec<String> {
            self.fetches
                .lock()
                .map(|fetches| fetches.clone())
                .unwrap_or_default()
        }

        fn artifact(&self, src: &OciSource, reference: &str) -> Result<FakeArtifact, RepoError> {
            self.artifacts
                .get(&(src.url.clone(), reference.to_owned()))
                .cloned()
                .ok_or_else(|| RepoError::RevisionNotFound {
                    revision: fake_reference(&src.url, reference),
                })
        }
    }

    impl OciClient for FakeOciClient {
        fn resolve_digest<'a>(
            &'a self,
            src: &'a OciSource,
            _creds: &'a RepoCredentials,
        ) -> OciFuture<'a, ResolvedDigest> {
            Box::pin(async move {
                src.validate(self.config.url_policy)?;
                let requested_ref = src
                    .requested_reference()
                    .ok_or_else(|| RepoError::InvalidSource {
                        reason: "spec.source.oci must set a tag or a digest".to_owned(),
                    })?
                    .to_owned();
                let artifact = self.artifact(src, &requested_ref)?;
                if let Some(pinned) = src.digest.as_deref()
                    && pinned != artifact.manifest_digest
                {
                    return Err(RepoError::OciDigestMismatch {
                        expected: pinned.to_owned(),
                        actual: artifact.manifest_digest.clone(),
                    });
                }
                Ok(ResolvedDigest {
                    manifest_digest: artifact.manifest_digest.clone(),
                    requested_ref,
                })
            })
        }

        fn fetch_artifact<'a>(
            &'a self,
            src: &'a OciSource,
            digest: &'a str,
            _creds: &'a RepoCredentials,
        ) -> OciFuture<'a, RepoCheckout> {
            Box::pin(async move {
                src.validate(self.config.url_policy)?;
                validate_digest(digest)?;
                let reference = src
                    .requested_reference()
                    .ok_or_else(|| RepoError::InvalidSource {
                        reason: "spec.source.oci must set a tag or a digest".to_owned(),
                    })?
                    .to_owned();
                let artifact = self.artifact(src, &reference)?;
                if let Ok(mut fetches) = self.fetches.lock() {
                    fetches.push(fake_reference(&src.url, &reference));
                }

                let limits = self.config.limits;
                let expected = digest.to_owned();
                let verify_against = expected.clone();
                let FakeArtifact {
                    manifest, layer, ..
                } = artifact;
                // The blocking half (hash, gunzip, tar, filesystem, sanitize) must never run on a
                // Tokio worker.
                let extracted = tokio::task::spawn_blocking(move || {
                    let temp = tempfile::tempdir().map_err(|source| RepoError::Io {
                        context: "creating an OCI extraction root".to_owned(),
                        source,
                    })?;
                    let root = extract_artifact(
                        &manifest,
                        &verify_against,
                        layer.as_slice(),
                        temp.path(),
                        &limits,
                    )?;
                    Ok::<_, RepoError>((temp, root))
                })
                .await
                .map_err(|error| RepoError::TaskCancelled {
                    message: format!("OCI extraction worker failed: {error}"),
                })??;
                let (temp, root) = extracted;
                let lease: Arc<dyn std::any::Any + Send + Sync> = Arc::new(temp);
                Ok(RepoCheckout::with_lease(root, expected, lease))
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------
    // Fixtures: a minimal, strict tar writer
    // ---------------------------------------------------------------------

    /// Builds a decimal-ASCII, fixed-width tar numeric field.
    fn octal_field(value: u64, width: usize) -> Vec<u8> {
        let mut digits = format!("{value:o}");
        while digits.len() + 1 < width {
            digits.insert(0, '0');
        }
        digits.push('\0');
        digits.into_bytes()
    }

    /// Builds one 512-byte ustar header block.
    ///
    /// Deliberately explicit rather than crates.io's `tar`, so a test can produce exactly the
    /// hostile header it means to test (a symlink, a device node, a 1 GiB declared size).
    fn header(name: &str, typeflag: u8, linkname: &str, size: u64) -> [u8; TAR_BLOCK] {
        header_bytes(name.as_bytes(), typeflag, linkname, size)
    }

    /// Builds one 512-byte ustar header block from raw name bytes.
    ///
    /// A non-UTF-8 entry name cannot be written through `&str`, and that is precisely the case a
    /// hostile archive can use, so the byte-level form is a first-class fixture.
    fn header_bytes(name: &[u8], typeflag: u8, linkname: &str, size: u64) -> [u8; TAR_BLOCK] {
        let mut block = [0u8; TAR_BLOCK];
        assert!(name.len() <= 100, "test entry name too long");
        block[..name.len()].copy_from_slice(name);
        block[100..108].copy_from_slice(&octal_field(0o644, 8));
        block[108..116].copy_from_slice(&octal_field(0, 8));
        block[116..124].copy_from_slice(&octal_field(0, 8));
        block[124..136].copy_from_slice(&octal_field(size, 12));
        block[136..148].copy_from_slice(&octal_field(0, 12));
        block[148..156].copy_from_slice(b"        ");
        block[156] = typeflag;
        let link_bytes = linkname.as_bytes();
        assert!(link_bytes.len() <= 100, "test link name too long");
        block[157..157 + link_bytes.len()].copy_from_slice(link_bytes);
        block[257..263].copy_from_slice(b"ustar\0");
        block[263..265].copy_from_slice(b"00");
        let checksum: u64 = block.iter().map(|byte| u64::from(*byte)).sum();
        let checksum_field = format!("{checksum:06o}\0 ");
        block[148..156].copy_from_slice(checksum_field.as_bytes());
        block
    }

    /// Accumulates tar entries into a complete archive.
    #[derive(Default)]
    struct Tar {
        bytes: Vec<u8>,
    }

    impl Tar {
        fn new() -> Self {
            Self::default()
        }

        /// Appends a regular file entry.
        fn file(mut self, name: &str, data: &[u8]) -> Self {
            self.push(&header(name, b'0', "", data.len() as u64), data);
            self
        }

        /// Appends a regular file entry whose name is raw bytes (a non-UTF-8 entry name).
        fn raw_file(mut self, name: &[u8], data: &[u8]) -> Self {
            self.push(&header_bytes(name, b'0', "", data.len() as u64), data);
            self
        }

        /// Appends a directory entry.
        fn dir(mut self, name: &str) -> Self {
            self.push(&header(name, b'5', "", 0), &[]);
            self
        }

        /// Appends an arbitrary entry type (symlink, device, PAX record, ...).
        fn typed(mut self, name: &str, typeflag: u8, data: &[u8]) -> Self {
            let linkname = if matches!(typeflag, b'1' | b'2') {
                "../../etc/shadow"
            } else {
                ""
            };
            self.push(&header(name, typeflag, linkname, data.len() as u64), data);
            self
        }

        /// Appends a header that *declares* `size` bytes without a payload (a tar bomb's shape).
        fn declared(mut self, name: &str, size: u64) -> Self {
            self.bytes.extend_from_slice(&header(name, b'0', "", size));
            self
        }

        fn push(&mut self, header: &[u8; TAR_BLOCK], data: &[u8]) {
            self.bytes.extend_from_slice(header);
            self.bytes.extend_from_slice(data);
            let remainder = data.len() % TAR_BLOCK;
            if remainder != 0 {
                self.bytes
                    .extend(std::iter::repeat_n(0u8, TAR_BLOCK - remainder));
            }
        }

        /// Terminates the archive with the two zero blocks a real writer emits.
        fn finish(mut self) -> Vec<u8> {
            self.bytes.extend(std::iter::repeat_n(0u8, TAR_BLOCK * 2));
            self.bytes
        }
    }

    /// Gzip-compresses `bytes`.
    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(bytes).expect("gzip write");
        encoder.finish().expect("gzip finish")
    }

    /// Wraps `layer` (compressed bytes) in a one-layer manifest with `media_type`.
    fn manifest_for(layer: &[u8], media_type: &str) -> OciDescriptor {
        OciDescriptor::new(media_type, sha256_digest(layer), Some(layer.len() as u64))
    }

    /// Extracts `layer` into a fresh directory and returns it (kept alive by the caller).
    fn extract(
        layer_bytes: &[u8],
        descriptor: &OciDescriptor,
        limits: &WorktreeLimits,
    ) -> (tempfile::TempDir, Result<PathBuf, RepoError>) {
        let temp = tempfile::tempdir().expect("tempdir");
        let dest = temp.path().join("artifact");
        let result = extract_layer(layer_bytes, descriptor, &dest, limits);
        (temp, result)
    }

    // ---------------------------------------------------------------------
    // Digests & manifests
    // ---------------------------------------------------------------------

    #[test]
    fn sha256_digests_match_the_reference_vectors_and_validation_is_strict() {
        // NIST reference vector for "abc".
        assert_eq!(
            sha256_digest(b"abc"),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(validate_digest(&sha256_digest(b"abc")).is_ok());
        for rejected in [
            "",
            "sha256",
            "sha256:",
            "sha256:abc",
            "sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert!(
                matches!(
                    validate_digest(rejected),
                    Err(RepoError::InvalidRevision { .. })
                ),
                "{rejected:?} must be rejected"
            );
        }

        let pinned = sha256_digest(b"layer");
        assert!(verify_digest(&pinned, b"layer").is_ok());
        match verify_digest(&pinned, b"tampered") {
            Err(RepoError::OciDigestMismatch { expected, actual }) => {
                assert_eq!(expected, pinned);
                assert_eq!(actual, sha256_digest(b"tampered"));
            }
            other => panic!("expected OciDigestMismatch, got {other:?}"),
        }
    }

    #[test]
    fn manifests_are_parsed_strictly_and_must_carry_exactly_one_layer() {
        let layer = gzip(&Tar::new().file("a.yaml", b"kind: ConfigMap\n").finish());
        let body = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "layers": [{
                "mediaType": OCI_IMAGE_LAYER_MEDIA_TYPE,
                "digest": sha256_digest(&layer),
                "size": layer.len(),
            }],
        });
        let parsed = OciManifest::parse(&serde_json::to_vec(&body).expect("json"))
            .expect("a well-formed manifest must parse");
        assert_eq!(
            parsed.media_type.as_deref(),
            Some("application/vnd.oci.image.manifest.v1+json")
        );
        let single = parsed.single_layer().expect("exactly one layer");
        assert_eq!(single.media_type, OCI_IMAGE_LAYER_MEDIA_TYPE);
        assert_eq!(single.digest, sha256_digest(&layer));
        assert_eq!(single.size, Some(layer.len() as u64));

        // Rejections: schema version, no layers, several layers, malformed JSON, a bad digest.
        for (label, body, expected) in [
            (
                "schemaVersion 1",
                serde_json::json!({"schemaVersion": 1, "layers": [{
                    "mediaType": OCI_IMAGE_LAYER_MEDIA_TYPE,
                    "digest": sha256_digest(&layer), "size": 1}]}),
                "schemaVersion",
            ),
            (
                "no layers",
                serde_json::json!({"schemaVersion": 2, "layers": []}),
                "no layers",
            ),
            (
                "bad layer digest",
                serde_json::json!({"schemaVersion": 2, "layers": [{
                    "mediaType": OCI_IMAGE_LAYER_MEDIA_TYPE, "digest": "sha256:zz"}]}),
                "",
            ),
        ] {
            let bytes = serde_json::to_vec(&body).expect("json");
            let err = OciManifest::parse(&bytes)
                .err()
                .unwrap_or_else(|| panic!("{label} must be rejected"));
            match (label, &err) {
                ("bad layer digest", RepoError::InvalidRevision { .. }) => {}
                (_, RepoError::OciInvalidArtifact { reason }) => {
                    assert!(
                        reason.contains(expected),
                        "{label}: expected {expected:?} in {reason}"
                    );
                }
                _ => panic!("{label}: unexpected error {err:?}"),
            }
        }

        let malformed =
            OciManifest::parse(b"{ not json").expect_err("malformed JSON must be rejected");
        assert!(matches!(malformed, RepoError::OciInvalidArtifact { .. }));

        let oversized = vec![b' '; MAX_MANIFEST_BYTES + 1];
        let err = OciManifest::parse(&oversized).expect_err("oversized manifest");
        assert!(err.to_string().contains("exceeds"), "{err}");

        // Several layers: parsed, but not renderable as one directory.
        let two_layers = serde_json::json!({"schemaVersion": 2, "layers": [
            {"mediaType": OCI_IMAGE_LAYER_MEDIA_TYPE, "digest": sha256_digest(&layer)},
            {"mediaType": OCI_IMAGE_LAYER_MEDIA_TYPE, "digest": sha256_digest(&layer)},
        ]});
        let manifest = OciManifest::parse(&serde_json::to_vec(&two_layers).expect("json"))
            .expect("two layers still parse");
        let err = manifest
            .single_layer()
            .expect_err("two layers are not renderable");
        assert!(err.to_string().contains("exactly one layer"), "{err}");
    }

    #[test]
    fn every_supported_media_type_is_recognised_and_others_are_refused() {
        for media_type in [
            HELM_CHART_MEDIA_TYPE,
            OCI_IMAGE_LAYER_MEDIA_TYPE,
            FLUX_BUNDLE_MEDIA_TYPE,
        ] {
            assert!(is_supported_layer_media_type(media_type), "{media_type}");
        }
        assert!(!is_supported_layer_media_type(
            "application/vnd.oci.image.layer.v1.tar+zstd"
        ));
        assert!(!is_supported_layer_media_type(""));

        let layer = gzip(&Tar::new().file("a.yaml", b"kind: ConfigMap\n").finish());
        let descriptor = manifest_for(&layer, "application/vnd.oci.image.layer.v1.tar+zstd");
        let (_temp, result) = extract(&layer, &descriptor, &WorktreeLimits::default());
        match result {
            Err(RepoError::OciUnsupportedMediaType { media_type }) => {
                assert_eq!(media_type, "application/vnd.oci.image.layer.v1.tar+zstd");
            }
            other => panic!("expected OciUnsupportedMediaType, got {other:?}"),
        }
    }

    // ---------------------------------------------------------------------
    // `OciSource` validation
    // ---------------------------------------------------------------------

    #[test]
    fn oci_sources_enforce_https_transport_unless_explicitly_local() {
        let accepted_both = [
            "oci://ghcr.io/example/payments",
            "oci://ghcr.io:443/example/payments",
            "oci://localhost:5000/example/payments",
            "https://ghcr.io/example/payments",
        ];
        for url in accepted_both {
            let source = OciSource::new(url, Some("1.4.2".to_owned()), None, "");
            assert!(
                source.validate(OciUrlPolicy::Production).is_ok(),
                "expected Production to accept {url}"
            );
            assert!(source.validate(OciUrlPolicy::AllowLocal).is_ok());
        }

        // Plaintext is a local-development-only policy: it must never pass silently in production.
        let plaintext = OciSource::new(
            "http://localhost:5000/example/payments",
            Some("1.4.2".to_owned()),
            None,
            "",
        );
        match plaintext.validate(OciUrlPolicy::Production) {
            Err(RepoError::InvalidUrl { url, reason }) => {
                assert_eq!(url, "http://localhost:5000/example/payments");
                assert!(reason.contains("plaintext"), "{reason}");
            }
            other => panic!("expected InvalidUrl, got {other:?}"),
        }
        assert!(plaintext.validate(OciUrlPolicy::AllowLocal).is_ok());

        let rejected = [
            "",
            "   ",
            "ghcr.io/example/payments",
            "ssh://ghcr.io/example/payments",
            "file:///tmp/payments",
            "oci://",
            "oci://ghcr.io",
            "oci://ghcr.io/",
            "oci://ghcr.io//payments",
            "oci://ghcr.io/example/../evil",
            "oci://user:token@ghcr.io/example/payments",
            "oci://ghcr.io/example/pay ments",
            "oci://ghcr.io:0/example/payments",
            "oci://[not-ipv6]/example/payments",
            "-oci://ghcr.io/example/payments",
        ];
        for url in rejected {
            let source = OciSource::new(url, Some("1.4.2".to_owned()), None, "");
            for policy in [OciUrlPolicy::Production, OciUrlPolicy::AllowLocal] {
                assert!(
                    matches!(source.validate(policy), Err(RepoError::InvalidUrl { .. })),
                    "expected {policy:?} to reject {url:?}"
                );
            }
        }
    }

    /// **Finding H-2.** A registry URL with embedded userinfo is refused, and the refusal is echoed
    /// into `RepoError::InvalidUrl` — which reaches `Application.status`, Events, and logs. The echo
    /// must therefore be credential-free: the redaction, not the rejection, is what keeps the token
    /// out of cluster state.
    #[test]
    fn a_rejected_registry_url_never_echoes_embedded_credentials() {
        const SECRET: &str = "s3cr3t-registry-token";
        const REDACTED: &str = "oci://[REDACTED]@ghcr.io/example/payments";
        const REDACTED_HTTPS: &str = "https://[REDACTED]@ghcr.io/example/payments";

        let cases: &[(&str, &str, &[OciUrlPolicy])] = &[
            // The authority carries userinfo: refused as an embedded credential.
            (
                "oci://user:s3cr3t-registry-token@ghcr.io/example/payments",
                REDACTED,
                &[OciUrlPolicy::Production, OciUrlPolicy::AllowLocal],
            ),
            (
                "https://user:s3cr3t-registry-token@ghcr.io/example/payments",
                REDACTED_HTTPS,
                &[OciUrlPolicy::Production, OciUrlPolicy::AllowLocal],
            ),
            // A bare token (`token@host`) is userinfo too, with no password to give it away.
            (
                "oci://s3cr3t-registry-token@ghcr.io/example/payments",
                REDACTED,
                &[OciUrlPolicy::Production],
            ),
            // The whitespace branch fires *before* the scheme/authority split, so it redacts too.
            (
                "oci://user:s3cr3t-registry-token@ghcr.io/example/payments ",
                "oci://[REDACTED]@ghcr.io/example/payments ",
                &[OciUrlPolicy::Production],
            ),
            // Plaintext refused by policy: the reason is the scheme, but the URL is still echoed.
            (
                "http://user:s3cr3t-registry-token@ghcr.io/example/payments",
                "http://[REDACTED]@ghcr.io/example/payments",
                &[OciUrlPolicy::Production],
            ),
            // **Finding M-A.** A reference that forgot its scheme is rejected by the "must be
            // absolute" branch — which is the one branch whose input has no authority to redact
            // under the old rule. Both userinfo shapes must still come back redacted, and
            // `token@host` is the one the generic Git rule (SCP-style `git@host:path`) keeps.
            (
                "user:s3cr3t-registry-token@ghcr.io/example/payments",
                "[REDACTED]@ghcr.io/example/payments",
                &[OciUrlPolicy::Production, OciUrlPolicy::AllowLocal],
            ),
            (
                "s3cr3t-registry-token@ghcr.io/example/payments",
                "[REDACTED]@ghcr.io/example/payments",
                &[OciUrlPolicy::Production, OciUrlPolicy::AllowLocal],
            ),
            // The whitespace branch fires first, so this pins the scheme-less redaction on a URL
            // that never reaches the "must be absolute" check at all.
            (
                "user:s3cr3t-registry-token@ghcr.io/example/payments ",
                "[REDACTED]@ghcr.io/example/payments ",
                &[OciUrlPolicy::Production],
            ),
        ];

        for (url, expected, policies) in cases {
            let source = OciSource::new(*url, Some("1.4.2".to_owned()), None, "");
            for policy in *policies {
                let err = source
                    .validate(*policy)
                    .expect_err(&format!("{policy:?} must refuse {url:?}"));
                let RepoError::InvalidUrl {
                    url: echoed,
                    reason,
                } = &err
                else {
                    panic!("{policy:?} must report InvalidUrl for {url:?}, got {err:?}");
                };
                assert_eq!(
                    echoed, expected,
                    "{policy:?}: the echo must be the redacted form"
                );
                assert!(
                    echoed.contains("[REDACTED]@"),
                    "{policy:?}: the redaction must be visible in {echoed:?}"
                );
                assert!(!reason.contains(SECRET), "{policy:?}: {reason}");

                // Neither rendering may carry the token: these are exactly what lands in
                // `/status`, in an Event, and in a log line.
                let display = err.to_string();
                let debug = format!("{err:?}");
                for rendered in [&display, &debug] {
                    assert!(
                        !rendered.contains(SECRET),
                        "{policy:?}: the credential leaked into {rendered:?}"
                    );
                }
                assert!(display.contains(expected), "{display}");
            }
        }
    }

    /// Pins the `url` field of [`RepoError::InvalidUrl`] for a blank registry URL, which takes the
    /// `trim().is_empty()` branch: **nothing** of a whitespace-only reference is echoed, the field is
    /// the empty string. Two reasons to pin it: that branch is the only one that does not echo a
    /// (redacted) input, so it must not silently start echoing a whitespace run into `/status`; and
    /// a reference that merely *contains* whitespace still echoes itself, because the operator has
    /// to see which reference was refused.
    #[test]
    fn a_blank_registry_url_echoes_an_empty_url_and_whitespace_alone_is_not_echoed() {
        for blank in ["", " ", "   ", "\t", "\n", " \t\r\n "] {
            let source = OciSource::new(blank, Some("1.4.2".to_owned()), None, "");
            for policy in [OciUrlPolicy::Production, OciUrlPolicy::AllowLocal] {
                let err = source
                    .validate(policy)
                    .expect_err(&format!("{policy:?} must refuse {blank:?}"));
                let RepoError::InvalidUrl { url, reason } = &err else {
                    panic!("{policy:?} must report InvalidUrl for {blank:?}, got {err:?}");
                };
                assert_eq!(
                    url, "",
                    "{policy:?}: a blank reference echoes nothing: {err:?}"
                );
                assert!(
                    reason.contains("must not be empty"),
                    "{policy:?}: the blank branch is the one that fired: {reason}"
                );
                assert!(!err.is_retryable(), "{policy:?}: {err}");
            }
        }

        // The neighbouring branch still echoes the offending reference (here: a trailing space), so
        // "nothing is echoed" is a property of the blank input, not of the whole validator.
        let source = OciSource::new(
            "oci://ghcr.io/example/payments ",
            Some("1.4.2".to_owned()),
            None,
            "",
        );
        let err = source
            .validate(OciUrlPolicy::Production)
            .expect_err("a reference with an embedded space must be refused");
        let RepoError::InvalidUrl { url, reason } = &err else {
            panic!("expected InvalidUrl, got {err:?}");
        };
        assert_eq!(url, "oci://ghcr.io/example/payments ");
        assert!(reason.contains("whitespace"), "{reason}");
    }

    #[test]
    fn oci_sources_require_an_immutable_reference_and_a_safe_path() {
        let digest = format!("sha256:{}", "0123456789abcdef".repeat(4));

        let no_reference = OciSource::new("oci://ghcr.io/example/payments", None, None, "");
        let err = no_reference
            .validate(OciUrlPolicy::Production)
            .expect_err("a floating reference must be refused");
        assert!(
            err.to_string().contains("must set a tag or a digest"),
            "{err}"
        );

        let bad_digest = OciSource::new(
            "oci://ghcr.io/example/payments",
            None,
            Some("sha256:ABC".to_owned()),
            "",
        );
        assert!(matches!(
            bad_digest.validate(OciUrlPolicy::Production),
            Err(RepoError::InvalidRevision { .. })
        ));

        let bad_tag = OciSource::new(
            "oci://ghcr.io/example/payments",
            Some("^1.4.0".to_owned()),
            None,
            "",
        );
        assert!(matches!(
            bad_tag.validate(OciUrlPolicy::Production),
            Err(RepoError::InvalidRevision { .. })
        ));

        // A digest-pinned source needs no tag, and both together are accepted (tag + pin).
        assert!(
            OciSource::new(
                "oci://ghcr.io/example/payments",
                None,
                Some(digest.clone()),
                ""
            )
            .validate(OciUrlPolicy::Production)
            .is_ok()
        );
        assert!(
            OciSource::new(
                "oci://ghcr.io/example/payments",
                Some("1.4.2".to_owned()),
                Some(digest),
                ""
            )
            .validate(OciUrlPolicy::Production)
            .is_ok()
        );

        // `path` may not escape the extracted root.
        for path in ["/etc", "../secrets", "a/../../b", "C:\\manifests", "a\\b"] {
            let source = OciSource::new(
                "oci://ghcr.io/example/payments",
                Some("1.4.2".to_owned()),
                None,
                path,
            );
            assert!(
                matches!(
                    source.validate(OciUrlPolicy::Production),
                    Err(RepoError::InvalidSource { .. })
                ),
                "expected {path:?} to be refused"
            );
        }
    }

    // ---------------------------------------------------------------------
    // Safe extraction
    // ---------------------------------------------------------------------

    #[test]
    fn a_bundle_is_extracted_with_content_and_digest_verified() {
        let archive = Tar::new()
            .dir("apps")
            .file("apps/deployment.yaml", b"kind: Deployment\n")
            .file("kustomization.yaml", b"resources:\n- apps\n")
            .finish();
        let layer = gzip(&archive);
        let descriptor = manifest_for(&layer, OCI_IMAGE_LAYER_MEDIA_TYPE);
        let (temp, result) = extract(&layer, &descriptor, &WorktreeLimits::default());
        let root = result.expect("a well-formed bundle must extract");

        assert_eq!(
            root,
            temp.path().join("artifact"),
            "bundle root is the root"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("apps/deployment.yaml")).expect("read"),
            "kind: Deployment\n"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("kustomization.yaml")).expect("read"),
            "resources:\n- apps\n"
        );
    }

    /// A bundle produced by `tar -C dir -cf - .` carries a `./` root entry; it must unpack (the
    /// root already exists) rather than be rejected as "resolves to the root".
    #[test]
    fn a_dot_root_entry_is_skipped_and_a_dot_file_is_rejected() {
        let archive = Tar::new()
            .dir("./")
            .dir("./apps")
            .file("./apps/deployment.yaml", b"kind: Deployment\n")
            .finish();
        let layer = gzip(&archive);
        let descriptor = manifest_for(&layer, OCI_IMAGE_LAYER_MEDIA_TYPE);
        let (temp, result) = extract(&layer, &descriptor, &WorktreeLimits::default());
        let root = result.expect("a `./`-rooted bundle must extract");
        assert_eq!(root, temp.path().join("artifact"));
        assert_eq!(
            std::fs::read_to_string(root.join("apps/deployment.yaml")).expect("read"),
            "kind: Deployment\n"
        );

        // A *file* whose name resolves to the root is malformed, not a silent no-op.
        let archive = Tar::new().file(".", b"kind: ConfigMap\n").finish();
        let layer = gzip(&archive);
        let descriptor = manifest_for(&layer, OCI_IMAGE_LAYER_MEDIA_TYPE);
        let (_temp, result) = extract(&layer, &descriptor, &WorktreeLimits::default());
        match result {
            Err(RepoError::UnsafeArchive { reason, .. }) => {
                assert!(reason.contains("extraction root"), "{reason}");
            }
            other => panic!("expected UnsafeArchive, got {other:?}"),
        }
    }

    /// An archive that is a file where it also needs a directory is malformed. It must be a
    /// *terminal* unsafe-archive error, never a retryable I/O error that loops forever.
    #[test]
    fn a_file_directory_conflict_is_terminal() {
        let archive = Tar::new()
            .file("apps", b"not a directory\n")
            .file("apps/deployment.yaml", b"kind: Deployment\n")
            .finish();
        let layer = gzip(&archive);
        let descriptor = manifest_for(&layer, OCI_IMAGE_LAYER_MEDIA_TYPE);
        let (_temp, result) = extract(&layer, &descriptor, &WorktreeLimits::default());
        match result {
            Err(RepoError::UnsafeArchive { path, reason }) => {
                assert_eq!(path.to_string_lossy(), "apps/deployment.yaml");
                assert!(reason.contains("conflicts"), "{reason}");
            }
            other => panic!("expected UnsafeArchive, got {other:?}"),
        }
    }

    /// **Finding H1.** A failed extraction must not leave a partial tree behind.
    ///
    /// `create_empty_directory` refuses a non-empty `dest`, so a half-written extraction would turn
    /// the *next* attempt — including the retry after a genuinely transient I/O error — into a
    /// terminal "must be empty" refusal that no retry can clear. Mirror of
    /// [`a_file_directory_conflict_is_terminal`]: a two-entry archive whose second entry cannot be
    /// written.
    #[test]
    fn a_failed_extraction_leaves_no_partial_extraction_root() {
        let archive = Tar::new()
            .file("apps", b"not a directory\n")
            .file("apps/deployment.yaml", b"kind: Deployment\n")
            .finish();
        let layer = gzip(&archive);
        let descriptor = manifest_for(&layer, OCI_IMAGE_LAYER_MEDIA_TYPE);
        let (temp, result) = extract(&layer, &descriptor, &WorktreeLimits::default());
        assert!(
            matches!(result, Err(RepoError::UnsafeArchive { .. })),
            "{result:?}"
        );

        let dest = temp.path().join("artifact");
        assert!(
            !dest.exists(),
            "a failed extraction must remove the root it created, otherwise the retry is refused \
             as 'must be empty' instead of retrying the real cause"
        );

        // The same archive extracts cleanly once the conflict is gone, which is what the cleanup
        // buys: a retry starts from exactly the state the first attempt saw.
        let good = gzip(
            &Tar::new()
                .file("apps/deployment.yaml", b"kind: Deployment\n")
                .finish(),
        );
        let descriptor = manifest_for(&good, OCI_IMAGE_LAYER_MEDIA_TYPE);
        let root = extract_layer(
            good.as_slice(),
            &descriptor,
            &dest,
            &WorktreeLimits::default(),
        )
        .expect("the retry must not be refused for a root the failed attempt left behind");
        assert_eq!(
            std::fs::read_to_string(root.join("apps/deployment.yaml")).expect("read"),
            "kind: Deployment\n"
        );
    }

    /// **Finding M-6.** `dest` may be a caller-owned directory that merely *happened* to be empty —
    /// the fake client extracts into the root of a `tempfile::TempDir`, and a lease directory is
    /// the same shape. A failed extraction may not delete it, and may not leave the half-written
    /// tree that would turn the next attempt into a terminal "must be empty" refusal.
    #[test]
    fn a_failed_extraction_restores_a_pre_existing_empty_root_without_deleting_it() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dest = temp.path().join("caller-owned");
        std::fs::create_dir(&dest).expect("a destination the extractor did not create");

        // Fails *after* writing the `apps` file (the second entry needs it to be a directory).
        let archive = Tar::new()
            .file("apps", b"not a directory\n")
            .file("apps/deployment.yaml", b"kind: Deployment\n")
            .finish();
        let layer = gzip(&archive);
        let descriptor = manifest_for(&layer, OCI_IMAGE_LAYER_MEDIA_TYPE);
        let err = extract_layer(
            layer.as_slice(),
            &descriptor,
            &dest,
            &WorktreeLimits::default(),
        )
        .expect_err("the file/directory conflict must be refused");
        assert!(matches!(err, RepoError::UnsafeArchive { .. }), "{err:?}");

        assert!(
            dest.is_dir(),
            "a directory this call did not create must survive a failed extraction"
        );
        assert_eq!(
            std::fs::read_dir(&dest).expect("read").count(),
            0,
            "the failed attempt must not leave its partial tree in the caller's directory"
        );

        // ...and the retry therefore starts from exactly the state the first attempt saw.
        let good = gzip(
            &Tar::new()
                .file("apps/deployment.yaml", b"kind: Deployment\n")
                .finish(),
        );
        let descriptor = manifest_for(&good, OCI_IMAGE_LAYER_MEDIA_TYPE);
        let root = extract_layer(
            good.as_slice(),
            &descriptor,
            &dest,
            &WorktreeLimits::default(),
        )
        .expect("the retry into the restored empty root must not be refused");
        assert_eq!(root, dest);
        assert_eq!(
            std::fs::read_to_string(dest.join("apps/deployment.yaml")).expect("read"),
            "kind: Deployment\n"
        );
    }

    /// **Finding N-1.** `dest` may be a **symlink**: `create_dir` reports `AlreadyExists` for it and
    /// `read_dir` follows the link, so an *empty* directory behind it would be extracted into —
    /// writing outside the root this module believes it owns. It is refused by name, and neither
    /// the link nor its target is touched.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_extraction_root_is_refused_and_its_target_is_untouched() {
        let layer = gzip(&Tar::new().file("a.yaml", b"kind: ConfigMap\n").finish());
        let descriptor = manifest_for(&layer, OCI_IMAGE_LAYER_MEDIA_TYPE);
        let temp = tempfile::tempdir().expect("tempdir");
        let target = temp.path().join("elsewhere");
        std::fs::create_dir(&target).expect("mkdir");
        let link = temp.path().join("artifact");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        let err = extract_layer(
            layer.as_slice(),
            &descriptor,
            &link,
            &WorktreeLimits::default(),
        )
        .expect_err("a symlinked extraction root must be refused");
        match err {
            RepoError::UnsafeSymlink {
                path,
                target: reported,
                reason,
            } => {
                assert_eq!(path, link);
                assert_eq!(reported, target);
                assert!(reason.contains("symlink"), "{reason}");
            }
            other => panic!("expected UnsafeSymlink, got {other:?}"),
        }

        assert_eq!(
            std::fs::read_dir(&target).expect("read").count(),
            0,
            "nothing may be written through the link"
        );
        assert!(
            std::fs::symlink_metadata(&link)
                .expect("metadata")
                .file_type()
                .is_symlink(),
            "the extraction root itself must not be replaced"
        );
    }

    /// **Acceptance criterion (3a).** `../../etc/passwd` (and an absolute path) never reaches the
    /// filesystem: the archive is rejected by name and nothing is written outside the root.
    ///
    /// Finding M3: the *name* itself is part of the attack surface, so this also covers a NUL in the
    /// name, a Windows-style separator (`a\b`, which an extractor running on Windows would treat as
    /// a separator), and a name that is not valid UTF-8 at all.
    #[test]
    fn tar_slip_and_absolute_paths_are_rejected_before_anything_is_written() {
        let cases: &[(&str, &str)] = &[
            ("../../etc/passwd", "traversal"),
            ("../escape.yaml", "traversal"),
            ("a/../../escape.yaml", "traversal"),
            ("/etc/passwd", "absolute"),
            // A NUL truncates the name for any C API downstream (`open(2)`, `helm template`), so a
            // parser that accepted it would extract one name and hand the renderer another.
            ("evil\0.yaml", "control characters"),
            // Rejected rather than normalized: `a\b` is one segment on Unix and two on Windows, so
            // the same archive would mean two different trees.
            ("a\\b.yaml", "contains '\\'"),
        ];
        for (name, expected) in cases {
            let archive = Tar::new().file(name, b"root:x:0:0\n").finish();
            let layer = gzip(&archive);
            let descriptor = manifest_for(&layer, OCI_IMAGE_LAYER_MEDIA_TYPE);
            let (temp, result) = extract(&layer, &descriptor, &WorktreeLimits::default());
            match result {
                Err(RepoError::UnsafeArchive { path, reason }) => {
                    assert_eq!(path.to_string_lossy(), *name);
                    assert!(
                        reason.contains(expected),
                        "{name:?}: expected {expected:?} in {reason}"
                    );
                }
                other => panic!("{name:?} must be rejected, got {other:?}"),
            }
            assert_nothing_was_written(&temp, name);
        }

        // A non-UTF-8 name cannot be expressed through `&str`, and it is rejected before the path
        // is ever joined: the reported path is the `<non-utf8>` placeholder, never a lossy string
        // that might name a different file.
        let archive = Tar::new()
            .raw_file(b"gr\xffn.yaml", b"root:x:0:0\n")
            .finish();
        let layer = gzip(&archive);
        let descriptor = manifest_for(&layer, OCI_IMAGE_LAYER_MEDIA_TYPE);
        let (temp, result) = extract(&layer, &descriptor, &WorktreeLimits::default());
        match result {
            Err(RepoError::UnsafeArchive { path, reason }) => {
                assert_eq!(path.to_string_lossy(), "<non-utf8>");
                assert!(reason.contains("not valid UTF-8"), "{reason}");
            }
            other => panic!("a non-UTF-8 entry name must be rejected, got {other:?}"),
        }
        assert_nothing_was_written(&temp, "gr\\xffn.yaml");
    }

    /// Asserts a rejected extraction wrote nothing: no entry under the root, no root at all, and
    /// nothing beside the tempdir.
    fn assert_nothing_was_written(temp: &tempfile::TempDir, case: &str) {
        let root = temp.path().join("artifact");
        assert!(
            !root.exists(),
            "{case}: a rejected entry must leave no extraction root behind"
        );
        assert_eq!(
            std::fs::read_dir(temp.path())
                .expect("read tempdir")
                .count(),
            0,
            "{case}: a rejected entry must not be materialized anywhere"
        );
        assert!(
            !temp.path().join("etc").exists(),
            "{case}: tar-slip wrote outside the root"
        );
    }

    /// **Acceptance criterion (3b).** Symlinks, hardlinks, devices, FIFOs, and PAX/GNU extension
    /// records are all refused — the extractor understands plain files and directories only.
    #[test]
    fn links_devices_and_extension_records_are_rejected() {
        for (typeflag, label) in [
            (b'2', "symlink"),
            (b'1', "hardlink"),
            (b'3', "character device"),
            (b'4', "block device"),
            (b'6', "FIFO"),
            (b'7', "contiguous file"),
            (b'x', "PAX extended header"),
            (b'L', "GNU long name"),
            (b'S', "GNU sparse file"),
        ] {
            let archive = Tar::new().typed("evil", typeflag, b"").finish();
            let layer = gzip(&archive);
            let descriptor = manifest_for(&layer, OCI_IMAGE_LAYER_MEDIA_TYPE);
            let (temp, result) = extract(&layer, &descriptor, &WorktreeLimits::default());
            match result {
                Err(RepoError::UnsafeArchive { path, reason }) => {
                    assert_eq!(path.to_string_lossy(), "evil");
                    assert!(
                        reason.contains(label),
                        "typeflag {typeflag:?}: expected {label:?} in {reason}"
                    );
                }
                other => panic!("typeflag {typeflag:?} must be rejected, got {other:?}"),
            }
            // H1: the extraction root this call created is removed again, so storage is the
            // observable proof that nothing from the archive was materialized.
            assert!(
                !temp.path().join("artifact").exists(),
                "a {label} entry must not be materialized"
            );
        }
    }

    #[test]
    fn duplicate_entry_paths_are_rejected_instead_of_overwritten() {
        let archive = Tar::new()
            .file("values.yaml", b"first\n")
            .file("values.yaml", b"second\n")
            .finish();
        let layer = gzip(&archive);
        let descriptor = manifest_for(&layer, OCI_IMAGE_LAYER_MEDIA_TYPE);
        let (temp, result) = extract(&layer, &descriptor, &WorktreeLimits::default());
        match result {
            Err(RepoError::UnsafeArchive { path, reason }) => {
                assert_eq!(path.to_string_lossy(), "values.yaml");
                // N-4: the message names the collision rather than assuming duplication — the same
                // `create_new` failure also covers a file/directory type conflict.
                assert!(reason.contains("collides"), "{reason}");
            }
            other => panic!("expected UnsafeArchive, got {other:?}"),
        }
        // H1 removes the partial root, so "the second entry never overwrote the first" is asserted
        // on the extractor itself (`write_file`'s `create_new`), one layer down from the cleanup.
        let dest = temp.path().join("artifact");
        assert!(
            !dest.exists(),
            "a failed extraction must leave no root behind"
        );
        std::fs::create_dir(&dest).expect("an empty extraction root");
        let err = extract_tar_gzip(
            layer.as_slice(),
            &dest,
            Budget::new(WorktreeLimits::default()),
        )
        .expect_err("the duplicate entry must be refused");
        assert!(matches!(err, RepoError::UnsafeArchive { .. }), "{err:?}");
        // The first (verified) copy is what remains — the second never silently replaced it.
        assert_eq!(
            std::fs::read_to_string(dest.join("values.yaml")).expect("read"),
            "first\n"
        );
    }

    /// **Acceptance criterion (3c).** A layer whose content does not hash to the pinned digest is
    /// rejected, and the mismatch is reported with both digests.
    #[test]
    fn a_layer_that_does_not_match_its_digest_is_rejected() {
        let archive = Tar::new().file("a.yaml", b"kind: ConfigMap\n").finish();
        let layer = gzip(&archive);
        let mut descriptor = manifest_for(&layer, OCI_IMAGE_LAYER_MEDIA_TYPE);
        descriptor.digest = sha256_digest(b"a different artifact");

        let (temp, result) = extract(&layer, &descriptor, &WorktreeLimits::default());
        match result {
            Err(RepoError::OciDigestMismatch { expected, actual }) => {
                assert_eq!(expected, sha256_digest(b"a different artifact"));
                assert_eq!(actual, sha256_digest(&layer));
            }
            other => panic!("expected OciDigestMismatch, got {other:?}"),
        }
        assert!(
            !temp.path().join("artifact").exists(),
            "nothing may be extracted from an unverified layer"
        );

        // The manifest digest is verified before the manifest is even parsed: a hostile body
        // reports a digest mismatch, not a parse error.
        let temp = tempfile::tempdir().expect("tempdir");
        let err = extract_artifact(
            b"{ not a manifest",
            &sha256_digest(b"the real manifest"),
            layer.as_slice(),
            &temp.path().join("artifact"),
            &WorktreeLimits::default(),
        )
        .expect_err("an unverified manifest must be refused");
        assert!(
            matches!(err, RepoError::OciDigestMismatch { .. }),
            "{err:?}"
        );

        // ...and a *verified* but malformed manifest is reported as such.
        let garbage = b"{ not a manifest".to_vec();
        let temp = tempfile::tempdir().expect("tempdir");
        let err = extract_artifact(
            &garbage,
            &sha256_digest(&garbage),
            layer.as_slice(),
            &temp.path().join("artifact"),
            &WorktreeLimits::default(),
        )
        .expect_err("a malformed manifest must be refused");
        assert!(
            matches!(err, RepoError::OciInvalidArtifact { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn a_layer_larger_than_its_descriptor_is_rejected() {
        // The registry serves *more* than the manifest declared: a proxy adding bytes must be
        // caught, never tolerated because the gzip stream happens to decode.
        let layer = gzip(&Tar::new().file("a.yaml", b"kind: ConfigMap\n").finish());
        let mut descriptor = manifest_for(&layer, OCI_IMAGE_LAYER_MEDIA_TYPE);
        descriptor.size = Some(layer.len() as u64 - 1);

        let (_temp, result) = extract(&layer, &descriptor, &WorktreeLimits::default());
        match result {
            Err(RepoError::OciInvalidArtifact { reason }) => {
                assert!(reason.contains("declares"), "{reason}");
                assert!(reason.contains("served"), "{reason}");
            }
            other => panic!("expected OciInvalidArtifact, got {other:?}"),
        }
    }

    /// **Acceptance criterion (3d).** A gzip tar bomb (a 1 GiB layer) is rejected from its header,
    /// before a single byte of it is written — and a stream that decompresses past the budget is
    /// stopped by the streaming counter.
    #[test]
    fn decompression_and_tar_bombs_are_stopped_by_the_worktree_budget() {
        // (d1) A header that declares a 1 GiB member: rejected from the declaration alone, so the
        // archive is never inflated.
        let archive = Tar::new().declared("bomb.bin", 1024 * 1024 * 1024).finish();
        let layer = gzip(&archive);
        let descriptor = manifest_for(&layer, OCI_IMAGE_LAYER_MEDIA_TYPE);
        assert!(
            layer.len() < 4096,
            "fixture precondition: the compressed bomb must be tiny ({} bytes)",
            layer.len()
        );
        let (temp, result) = extract(&layer, &descriptor, &WorktreeLimits::default());
        match result {
            Err(RepoError::CheckoutLimitExceeded { reason }) => {
                assert!(reason.contains("content"), "{reason}");
            }
            other => panic!("expected CheckoutLimitExceeded, got {other:?}"),
        }
        assert!(
            !temp.path().join("artifact/bomb.bin").exists(),
            "a rejected bomb entry must not be materialized"
        );

        // (d2) A stream that decompresses past `max_bytes` is stopped by the decompressed byte
        // counter even though every entry fits on its own.
        let mut tar = Tar::new();
        for index in 0..64 {
            tar = tar.file(&format!("file-{index}.yaml"), &[b'a'; 4096]);
        }
        let archive = tar.finish();
        let layer = gzip(&archive);
        let descriptor = manifest_for(&layer, OCI_IMAGE_LAYER_MEDIA_TYPE);
        let (_temp, result) = extract(
            &layer,
            &descriptor,
            &WorktreeLimits::new().with_max_bytes(8 * 1024),
        );
        match result {
            Err(RepoError::CheckoutLimitExceeded { reason }) => {
                assert!(
                    reason.contains("decompresses to") || reason.contains("content"),
                    "{reason}"
                );
            }
            other => panic!("expected CheckoutLimitExceeded, got {other:?}"),
        }

        // (d3) The compressed blob itself is bounded, so a registry cannot make the controller
        // spool an unbounded body (the guard that must not trust `Content-Length`): a small valid
        // gzip member followed by trailing junk is refused while it is spooled, before any
        // decompression work happens.
        let mut layer = gzip(&Tar::new().file("a.yaml", b"kind: ConfigMap\n").finish());
        layer.extend(std::iter::repeat_n(0u8, 3 * 1024 * 1024));
        let descriptor =
            OciDescriptor::new(OCI_IMAGE_LAYER_MEDIA_TYPE, sha256_digest(&layer), None);
        let (_temp, result) = extract(
            &layer,
            &descriptor,
            &WorktreeLimits::new().with_max_bytes(1024 * 1024),
        );
        match result {
            Err(RepoError::CheckoutLimitExceeded { reason }) => {
                assert!(reason.contains("compressed budget"), "{reason}");
            }
            other => panic!("expected CheckoutLimitExceeded, got {other:?}"),
        }
    }

    #[test]
    fn the_entry_count_budget_is_enforced() {
        let mut tar = Tar::new();
        for index in 0..8 {
            tar = tar.file(&format!("f{index}.yaml"), b"x");
        }
        let archive = tar.finish();
        let layer = gzip(&archive);
        let descriptor = manifest_for(&layer, OCI_IMAGE_LAYER_MEDIA_TYPE);
        let (_temp, result) = extract(
            &layer,
            &descriptor,
            &WorktreeLimits::new().with_max_files(4),
        );
        match result {
            Err(RepoError::CheckoutLimitExceeded { reason }) => {
                assert!(reason.contains("filesystem entries"), "{reason}");
            }
            other => panic!("expected CheckoutLimitExceeded, got {other:?}"),
        }
    }

    #[test]
    fn a_truncated_or_corrupt_archive_is_rejected() {
        // Ends inside an entry's data.
        let archive = Tar::new()
            .file("a.yaml", &[b'x'; 2048])
            .finish()
            .split_at(512 + 100)
            .0
            .to_vec();
        let layer = gzip(&archive);
        let descriptor = manifest_for(&layer, OCI_IMAGE_LAYER_MEDIA_TYPE);
        let (_temp, result) = extract(&layer, &descriptor, &WorktreeLimits::default());
        assert!(
            matches!(result, Err(RepoError::OciInvalidArtifact { .. })),
            "{result:?}"
        );

        // A header whose checksum does not match is not a tar header at all.
        let mut block = header("a.yaml", b'0', "", 0);
        block[0] = b'b';
        let mut corrupt = block.to_vec();
        corrupt.extend(std::iter::repeat_n(0u8, TAR_BLOCK * 2));
        let layer = gzip(&corrupt);
        let descriptor = manifest_for(&layer, OCI_IMAGE_LAYER_MEDIA_TYPE);
        let (_temp, result) = extract(&layer, &descriptor, &WorktreeLimits::default());
        match result {
            Err(RepoError::OciInvalidArtifact { reason }) => {
                assert!(reason.contains("checksum"), "{reason}");
            }
            other => panic!("expected OciInvalidArtifact, got {other:?}"),
        }

        // A gzip stream that is not a tar archive at all.
        let layer = gzip(b"definitely not a tar archive");
        let descriptor = manifest_for(&layer, OCI_IMAGE_LAYER_MEDIA_TYPE);
        let (_temp, result) = extract(&layer, &descriptor, &WorktreeLimits::default());
        assert!(
            matches!(result, Err(RepoError::OciInvalidArtifact { .. })),
            "{result:?}"
        );
    }

    /// A tar numeric field is unsigned. `+00000000010` is not the size `00000000010` spells — no tar
    /// writer emits a sign, so a signed field means the header was assembled by something that is
    /// not a tar writer (or is mis-framed), and it is refused rather than read as the same number.
    #[test]
    fn a_signed_tar_numeric_field_is_rejected() {
        let mut block = header("a.yaml", b'0', "", 0);
        block[124..136].copy_from_slice(b"+0000000001\0");
        // Re-checksum, so the only thing wrong with the header is the sign.
        block[148..156].copy_from_slice(b"        ");
        let checksum: u64 = block.iter().map(|byte| u64::from(*byte)).sum();
        block[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());

        let mut archive = block.to_vec();
        archive.extend(std::iter::repeat_n(0u8, TAR_BLOCK * 2));
        let layer = gzip(&archive);
        let descriptor = manifest_for(&layer, OCI_IMAGE_LAYER_MEDIA_TYPE);
        let (_temp, result) = extract(&layer, &descriptor, &WorktreeLimits::default());
        match result {
            Err(RepoError::UnsafeArchive { path, reason }) => {
                assert_eq!(path.to_string_lossy(), "<octal>");
                assert!(reason.contains("must not carry a sign"), "{reason}");
            }
            other => panic!("expected UnsafeArchive, got {other:?}"),
        }
    }

    #[test]
    fn a_non_empty_destination_is_refused() {
        let layer = gzip(&Tar::new().file("a.yaml", b"kind: ConfigMap\n").finish());
        let descriptor = manifest_for(&layer, OCI_IMAGE_LAYER_MEDIA_TYPE);
        let temp = tempfile::tempdir().expect("tempdir");
        let dest = temp.path().join("artifact");
        std::fs::create_dir_all(&dest).expect("mkdir");
        std::fs::write(dest.join("stale.yaml"), b"kind: Secret\n").expect("write");

        let err = extract_layer(
            layer.as_slice(),
            &descriptor,
            &dest,
            &WorktreeLimits::default(),
        )
        .expect_err("a dirty extraction root must be refused");
        assert!(
            matches!(err, RepoError::OciInvalidArtifact { .. }),
            "{err:?}"
        );
        assert_eq!(
            std::fs::read_to_string(dest.join("stale.yaml")).expect("read"),
            "kind: Secret\n",
            "the stale file must not be touched"
        );
    }

    /// **Finding N-A.** A `dest` that exists as a *file* used to reach `read_dir`, report
    /// `NotADirectory`, and be wrapped in the retryable `RepoError::Io` — a reconcile loop that can
    /// never succeed. It is a terminal refusal now, and the file itself is left untouched.
    #[test]
    fn an_extraction_root_that_is_a_file_is_refused_terminally() {
        let layer = gzip(&Tar::new().file("a.yaml", b"kind: ConfigMap\n").finish());
        let descriptor = manifest_for(&layer, OCI_IMAGE_LAYER_MEDIA_TYPE);
        let temp = tempfile::tempdir().expect("tempdir");
        let dest = temp.path().join("artifact");
        std::fs::write(&dest, b"not a directory").expect("write");

        let err = extract_layer(
            layer.as_slice(),
            &descriptor,
            &dest,
            &WorktreeLimits::default(),
        )
        .expect_err("a file extraction root must be refused");
        match &err {
            RepoError::OciInvalidArtifact { reason } => {
                assert!(reason.contains("must be a directory"), "{reason}");
            }
            other => panic!("expected a terminal OciInvalidArtifact, got {other:?}"),
        }
        assert!(
            !err.is_retryable(),
            "a root that is a file must not be retried forever: {err}"
        );
        assert_eq!(
            std::fs::read(&dest).expect("read"),
            b"not a directory",
            "the file must not be touched"
        );
    }

    /// **Finding M-C.** The symlink check must not be a one-shot *before* `create_dir`: a link
    /// swapped in afterwards is the one `read_dir` would follow, and the extraction would write
    /// outside the root this module believes it owns.
    ///
    /// What this test covers, precisely: an *already linked* root — refused by the pre-check, which
    /// runs first and is the same helper the `AlreadyExists` arm uses — and the helper itself. It
    /// does **not** reach the `AlreadyExists` arm, because the pre-check refuses the link before
    /// `create_dir` is ever attempted; that arm has its own test
    /// ([`the_already_exists_arm_refuses_whatever_appears_after_the_precheck`]), which uses the
    /// `cfg(test)` seam to land inside the gap.
    #[cfg(unix)]
    #[test]
    fn a_swapped_in_symlink_root_is_refused_by_the_reinspection() {
        let temp = tempfile::tempdir().expect("tempdir");
        let elsewhere = temp.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).expect("mkdir");
        let root = temp.path().join("artifact");
        std::fs::create_dir(&root).expect("mkdir");

        // An existing empty directory is accepted without being created by this call …
        assert!(matches!(super::create_empty_directory(&root), Ok(false)));
        // … then the root is swapped for a link to an empty directory, which is exactly the shape
        // `read_dir` would have followed into.
        std::fs::remove_dir(&root).expect("rmdir");
        std::os::unix::fs::symlink(&elsewhere, &root).expect("symlink");

        // The verdict comes from the re-inspection helper, not from the pre-check that already ran.
        let metadata = std::fs::symlink_metadata(&root).expect("metadata");
        let err = super::inspect_existing_root(&root, &metadata)
            .expect_err("a swapped-in link must be refused by the re-inspection");
        assert!(matches!(err, RepoError::UnsafeSymlink { .. }), "{err:?}");
        assert!(!err.is_retryable(), "a link root is terminal: {err}");

        // The whole entry point refuses it too, and never reports a misleading "must be empty".
        let err = super::create_empty_directory(&root).expect_err("must be refused");
        assert!(matches!(err, RepoError::UnsafeSymlink { .. }), "{err:?}");
        assert_eq!(
            std::fs::read_dir(&elsewhere).expect("read").count(),
            0,
            "nothing may be written through the link"
        );
    }

    /// **Findings M-C / M-3.** The `AlreadyExists` arm of `create_empty_directory` — the one that
    /// re-inspects a root that appeared *after* the pre-check — has to refuse exactly what the
    /// pre-check refuses, and it is unreachable from outside: arranging the root beforehand is what
    /// the pre-check catches, and no portable test can win a race against two adjacent syscalls.
    ///
    /// The `cfg(test)` seam ([`super::seam`]) runs a hook inside that gap, so each shape the arm can
    /// meet — a symlink, a regular file, a **non-empty** directory — is asserted here rather than
    /// merely documented. The last case is the one the arm's `read_dir` half exists for.
    #[test]
    fn the_already_exists_arm_refuses_whatever_appears_after_the_precheck() {
        let temp = tempfile::tempdir().expect("tempdir");
        let elsewhere = temp.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).expect("mkdir");
        std::fs::write(elsewhere.join("keep.txt"), b"do not touch").expect("write");

        // (0) A no-op hook proves the seam does not disturb the ordinary path: the root is created
        //     and reported as created-by-this-call.
        let fresh = temp.path().join("fresh");
        super::seam::install(|_root| {});
        assert!(matches!(super::create_empty_directory(&fresh), Ok(true)));
        assert!(fresh.is_dir());

        // (1) A symlink swapped in after the pre-check: refused, not followed. `read_dir` on the
        //     link would list `elsewhere`, so a successful `create_empty_directory` here would mean
        //     the extraction writes outside the root.
        #[cfg(unix)]
        {
            let root = temp.path().join("linked");
            let link_target = elsewhere.clone();
            super::seam::install(move |root| {
                std::os::unix::fs::symlink(&link_target, root).expect("symlink");
            });
            let err = super::create_empty_directory(&root)
                .expect_err("a link that appears after the pre-check must be refused");
            assert!(matches!(err, RepoError::UnsafeSymlink { .. }), "{err:?}");
            assert!(!err.is_retryable(), "a link root is terminal: {err}");
            assert!(
                std::fs::symlink_metadata(&root)
                    .expect("metadata")
                    .file_type()
                    .is_symlink(),
                "the refusal must not replace the link"
            );
        }

        // (2) A regular file swapped in: terminal, and not misreported as a retryable I/O error.
        let file_root = temp.path().join("filed");
        super::seam::install(|root| {
            std::fs::write(root, b"not a directory").expect("write");
        });
        let err = super::create_empty_directory(&file_root)
            .expect_err("a file that appears after the pre-check must be refused");
        assert!(
            matches!(err, RepoError::OciInvalidArtifact { .. }),
            "{err:?}"
        );
        assert!(!err.is_retryable(), "a file root is terminal: {err}");

        // (3) A **non-empty** directory swapped in: the arm's `read_dir` half. A previous artifact's
        //     files would otherwise be rendered as part of this one, so it is a terminal refusal.
        let dirty_root = temp.path().join("dirty");
        super::seam::install(|root| {
            std::fs::create_dir(root).expect("mkdir");
            std::fs::write(root.join("leftover.yaml"), b"kind: ConfigMap\n").expect("write");
        });
        let err = super::create_empty_directory(&dirty_root)
            .expect_err("a non-empty root that appears after the pre-check must be refused");
        match &err {
            RepoError::OciInvalidArtifact { reason } => {
                assert!(reason.contains("must be empty"), "{reason}");
            }
            other => panic!("expected OciInvalidArtifact, got {other:?}"),
        }
        assert_eq!(
            std::fs::read(dirty_root.join("leftover.yaml")).expect("read"),
            b"kind: ConfigMap\n",
            "the conflicting entry must be left alone"
        );
        assert_eq!(
            std::fs::read_dir(&elsewhere).expect("read").count(),
            1,
            "nothing may be written or removed through the previous cases"
        );
    }

    // ---------------------------------------------------------------------
    // Helm single-root unwrapping
    // ---------------------------------------------------------------------

    #[test]
    fn a_helm_chart_single_root_is_unwrapped_only_for_a_real_chart() {
        let chart = Tar::new()
            .file("payments/Chart.yaml", b"apiVersion: v2\nname: payments\n")
            .file("payments/templates/config.yaml", b"kind: ConfigMap\n")
            .finish();

        // (1) Helm media type + one chart directory + Chart.yaml: unwrapped, so `path: ""` is the
        //     chart root a Helm renderer needs.
        let layer = gzip(&chart);
        let descriptor = manifest_for(&layer, HELM_CHART_MEDIA_TYPE);
        let (temp, result) = extract(&layer, &descriptor, &WorktreeLimits::default());
        let root = result.expect("a helm chart must extract");
        assert_eq!(root, temp.path().join("artifact/payments"));
        assert!(root.join("Chart.yaml").is_file());

        // (2) The same archive under a bundle media type is *not* unwrapped: a Kustomize bundle
        //     with a `charts/` (or any single) sub-directory keeps its root.
        let descriptor = manifest_for(&layer, OCI_IMAGE_LAYER_MEDIA_TYPE);
        let (temp, result) = extract(&layer, &descriptor, &WorktreeLimits::default());
        assert_eq!(
            result.expect("a bundle must extract"),
            temp.path().join("artifact")
        );

        // (3) A Helm-typed archive whose single directory has no Chart.yaml is not a chart.
        let not_a_chart = Tar::new()
            .file("payments/values.yaml", b"replicaCount: 1\n")
            .finish();
        let layer = gzip(&not_a_chart);
        let descriptor = manifest_for(&layer, HELM_CHART_MEDIA_TYPE);
        let (temp, result) = extract(&layer, &descriptor, &WorktreeLimits::default());
        assert_eq!(result.expect("must extract"), temp.path().join("artifact"));

        // (4) Two top-level entries are never unwrapped, even with a Chart.yaml present.
        let two_roots = Tar::new()
            .file("payments/Chart.yaml", b"apiVersion: v2\nname: payments\n")
            .file("README.md", b"# payments\n")
            .finish();
        let layer = gzip(&two_roots);
        let descriptor = manifest_for(&layer, HELM_CHART_MEDIA_TYPE);
        let (temp, result) = extract(&layer, &descriptor, &WorktreeLimits::default());
        assert_eq!(result.expect("must extract"), temp.path().join("artifact"));
    }

    // ---------------------------------------------------------------------
    // The `OciClient` seam
    // ---------------------------------------------------------------------

    #[test]
    fn the_oci_client_trait_is_object_safe() {
        fn assert_object_safe(_: &dyn OciClient) {}
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<FakeOciClient>();
        assert_send_sync::<OciSource>();
        assert_send_sync::<ResolvedDigest>();
        assert_object_safe(&FakeOciClient::new());

        let client: std::sync::Arc<dyn OciClient> = std::sync::Arc::new(FakeOciClient::new());
        assert!(std::sync::Arc::strong_count(&client) == 1);
    }

    /// **Finding M-B.** Two things are pinned here, and they are different claims.
    ///
    /// 1. `fake_reference` — the only formatter of `src.url` in the fake — redacts unconditionally:
    ///    `fetches()` and the `RevisionNotFound` message both go through it, so neither can carry a
    ///    credential.
    /// 2. That helper is **not** reachable with a credential today, because both entry points call
    ///    `validate` first and `validate_oci_url` refuses embedded userinfo. So the redaction is
    ///    defence in depth for the next call site, not an observable property of today's `fetches()`:
    ///    the second half of the test drives a credentialed source and asserts it never gets that far
    ///    (nothing recorded, and the refusal it does get is itself redacted).
    #[test]
    fn the_fake_client_redacts_credentials_whenever_it_names_a_url() {
        const SECRET: &str = "s3cr3t-registry-token";

        for (url, expected) in [
            (
                "oci://s3cr3t-registry-token@ghcr.io/example/private",
                "oci://[REDACTED]@ghcr.io/example/private",
            ),
            (
                "https://user:s3cr3t-registry-token@ghcr.io/example/private",
                "https://[REDACTED]@ghcr.io/example/private",
            ),
            // No scheme: the shape a forgotten `oci://` leaves behind, and the one the old
            // "userinfo must contain ':'" rule would keep.
            (
                "s3cr3t-registry-token@ghcr.io/example/private",
                "[REDACTED]@ghcr.io/example/private",
            ),
        ] {
            let recorded = super::fake::fake_reference(url, "1.0.0");
            assert_eq!(recorded, format!("{expected}:1.0.0"));
            assert!(
                !recorded.contains(SECRET),
                "the credential leaked: {recorded}"
            );
        }

        // A credential-free reference is recorded verbatim: the redaction is not a rewrite.
        assert_eq!(
            super::fake::fake_reference("oci://ghcr.io/example/private", "1.0.0"),
            "oci://ghcr.io/example/private:1.0.0"
        );
    }

    /// The other half of finding M-B: a credentialed `src.url` is refused by `validate` **before**
    /// the fake names it, so `fetches()` stays empty and the only echo the caller gets is the
    /// redacted `InvalidUrl`. This is what makes the helper's unconditional redaction defence in
    /// depth rather than the sole protection on today's paths — and it fails loudly if that ordering
    /// is ever reversed.
    #[tokio::test]
    async fn the_fake_client_never_names_a_credentialed_url_at_all() {
        const SECRET: &str = "s3cr3t-registry-token";

        let mut client = FakeOciClient::new();
        let layer = gzip(&Tar::new().file("a.yaml", b"kind: ConfigMap\n").finish());
        client.register(
            "oci://s3cr3t-registry-token@ghcr.io/example/private",
            "1.0.0",
            Vec::new(),
            layer,
        );
        let source = OciSource::new(
            "oci://s3cr3t-registry-token@ghcr.io/example/private",
            Some("1.0.0".to_owned()),
            None,
            "",
        );

        let err = client
            .fetch_artifact(&source, "sha256:0000", &RepoCredentials::Anonymous)
            .await
            .expect_err("a credentialed reference must be refused");
        assert!(matches!(err, RepoError::InvalidUrl { .. }), "{err:?}");
        assert!(
            !err.to_string().contains(SECRET) && !format!("{err:?}").contains(SECRET),
            "neither rendering may carry the token: {err}"
        );
        assert!(
            client.fetches().is_empty(),
            "nothing may be recorded for a refused source: {:?}",
            client.fetches()
        );

        // The same holds for `resolve_digest`: the refusal is `InvalidUrl`, so no `RevisionNotFound`
        // (whose message is the second place `fake_reference` names the URL) is ever produced.
        let err = client
            .resolve_digest(&source, &RepoCredentials::Anonymous)
            .await
            .expect_err("a credentialed reference must be refused");
        assert!(matches!(err, RepoError::InvalidUrl { .. }), "{err:?}");
        assert!(!err.to_string().contains(SECRET), "{err}");
    }

    fn fake_artifact() -> (FakeOciClient, Vec<u8>) {
        let layer = gzip(
            &Tar::new()
                .file("deployment.yaml", b"kind: Deployment\n")
                .finish(),
        );
        let client = FakeOciClient::new().with_layer(
            "oci://ghcr.io/example/payments",
            "1.4.2",
            layer.clone(),
        );
        (client, layer)
    }

    fn oci_source(tag: Option<&str>, digest: Option<&str>) -> OciSource {
        OciSource::new(
            "oci://ghcr.io/example/payments",
            tag.map(str::to_owned),
            digest.map(str::to_owned),
            "",
        )
    }

    /// The whole `resolve_digest` → `fetch_artifact` path, through the trait, with the real
    /// extractor behind it.
    #[tokio::test]
    async fn the_fake_client_resolves_and_fetches_a_verified_artifact() {
        let (client, _layer) = fake_artifact();
        let source = oci_source(Some("1.4.2"), None);

        let resolved = client
            .resolve_digest(&source, &RepoCredentials::Anonymous)
            .await
            .expect("resolve must succeed");
        assert_eq!(resolved.requested_ref, "1.4.2");
        // A real immutable digest, served back under exactly that identity: `fetch_artifact`
        // re-verifies it (manifest *and* layer) before extracting, so a mismatch fails the next
        // assertion instead of producing a checkout.
        assert!(resolved.manifest_digest.starts_with(DIGEST_PREFIX));
        assert!(validate_digest(&resolved.manifest_digest).is_ok());
        assert!(
            client
                .fetch_artifact(
                    &source,
                    &format!("sha256:{}", "0".repeat(64)),
                    &RepoCredentials::Anonymous,
                )
                .await
                .is_err(),
            "a wrong digest must never produce a checkout"
        );

        let checkout = client
            .fetch_artifact(
                &source,
                &resolved.manifest_digest,
                &RepoCredentials::Anonymous,
            )
            .await
            .expect("fetch must succeed");
        assert_eq!(checkout.commit_sha(), resolved.manifest_digest);
        assert_eq!(
            std::fs::read_to_string(checkout.root_dir().join("deployment.yaml")).expect("read"),
            "kind: Deployment\n"
        );
        // One *successful* fetch, plus the deliberately wrong-digest attempt above: both are
        // recorded so a test can tell how many times the registry was asked for a blob.
        assert_eq!(
            client.fetches(),
            vec!["oci://ghcr.io/example/payments:1.4.2".to_owned(); 2]
        );
    }

    #[tokio::test]
    async fn the_fake_client_reports_a_moved_tag_against_a_digest_pin() {
        let (client, _layer) = fake_artifact();
        let source = oci_source(Some("1.4.2"), Some(&format!("sha256:{}", "0".repeat(64))));
        let err = client
            .resolve_digest(&source, &RepoCredentials::Anonymous)
            .await
            .expect_err("a digest pin that does not match the tag must be refused");
        match err {
            RepoError::OciDigestMismatch { expected, actual } => {
                assert_eq!(expected, format!("sha256:{}", "0".repeat(64)));
                assert_ne!(actual, expected);
            }
            other => panic!("expected OciDigestMismatch, got {other:?}"),
        }

        // An unknown artifact is `RevisionNotFound`, never an empty checkout.
        let missing = OciSource::new(
            "oci://ghcr.io/example/missing",
            Some("1.0.0".to_owned()),
            None,
            "",
        );
        let err = client
            .resolve_digest(&missing, &RepoCredentials::Anonymous)
            .await
            .expect_err("an unknown artifact must be refused");
        assert!(matches!(err, RepoError::RevisionNotFound { .. }), "{err:?}");
    }

    /// The configured `WorktreeLimits` are the ones actually applied to a fetched artifact, so a
    /// hostile artifact is refused at the seam a controller uses.
    #[tokio::test]
    async fn the_fake_client_enforces_limits_and_rejects_unsafe_artifacts() {
        let layer = gzip(
            &Tar::new()
                .file("../../etc/passwd", b"root:x:0:0\n")
                .finish(),
        );
        let client = FakeOciClient::new().with_layer("oci://ghcr.io/example/evil", "1.0.0", layer);
        let source = OciSource::new(
            "oci://ghcr.io/example/evil",
            Some("1.0.0".to_owned()),
            None,
            "",
        );
        let resolved = client
            .resolve_digest(&source, &RepoCredentials::Anonymous)
            .await
            .expect("resolve must succeed");
        let err = client
            .fetch_artifact(
                &source,
                &resolved.manifest_digest,
                &RepoCredentials::Anonymous,
            )
            .await
            .expect_err("a tar-slip artifact must never produce a checkout");
        assert!(matches!(err, RepoError::UnsafeArchive { .. }), "{err:?}");

        // A budget configured on the client is enforced during extraction.
        let layer = gzip(&Tar::new().file("big.yaml", &[b'x'; 4096]).finish());
        let client = FakeOciClient::with_config(FakeOciClientConfig {
            limits: WorktreeLimits::new().with_max_bytes(64),
            ..FakeOciClientConfig::default()
        })
        .with_layer("oci://ghcr.io/example/big", "1.0.0", layer);
        let source = OciSource::new(
            "oci://ghcr.io/example/big",
            Some("1.0.0".to_owned()),
            None,
            "",
        );
        let resolved = client
            .resolve_digest(&source, &RepoCredentials::Anonymous)
            .await
            .expect("resolve must succeed");
        let err = client
            .fetch_artifact(
                &source,
                &resolved.manifest_digest,
                &RepoCredentials::Anonymous,
            )
            .await
            .expect_err("the byte budget must be enforced");
        assert!(
            matches!(err, RepoError::CheckoutLimitExceeded { .. }),
            "{err:?}"
        );
    }

    /// **Finding M2.** The fake applies the *production* URL policy unless a test opts in.
    ///
    /// A fake that silently allowed plaintext would let a test (and, through `test-utils`, any
    /// downstream crate) prove an `http://` registry works while production refuses it — the two
    /// halves of a `kind`-only path drifting apart invisibly.
    #[tokio::test]
    async fn the_fake_client_applies_the_production_url_policy_by_default() {
        assert_eq!(
            FakeOciClientConfig::default().url_policy,
            OciUrlPolicy::Production,
            "the default must be the production policy"
        );

        let plaintext = OciSource::new(
            "http://localhost:5000/example/payments",
            Some("1.4.2".to_owned()),
            None,
            "",
        );
        let client = FakeOciClient::new();
        match client
            .resolve_digest(&plaintext, &RepoCredentials::Anonymous)
            .await
        {
            Err(RepoError::InvalidUrl { url, reason }) => {
                assert_eq!(url, "http://localhost:5000/example/payments");
                assert!(reason.contains("plaintext"), "{reason}");
            }
            other => panic!("a plaintext registry must be refused by default, got {other:?}"),
        }
        assert!(
            matches!(
                client
                    .fetch_artifact(
                        &plaintext,
                        &format!("sha256:{}", "0".repeat(64)),
                        &RepoCredentials::Anonymous,
                    )
                    .await,
                Err(RepoError::InvalidUrl { .. })
            ),
            "fetch must apply the same policy"
        );

        // With the explicit local-development opt-in the same URL gets past the policy and fails
        // only because no artifact is registered for it.
        let local = FakeOciClient::with_config(FakeOciClientConfig {
            url_policy: OciUrlPolicy::AllowLocal,
            ..FakeOciClientConfig::default()
        });
        assert!(
            matches!(
                local
                    .resolve_digest(&plaintext, &RepoCredentials::Anonymous)
                    .await,
                Err(RepoError::RevisionNotFound { .. })
            ),
            "AllowLocal must be the only thing standing between the URL and the registry lookup"
        );
    }
}
