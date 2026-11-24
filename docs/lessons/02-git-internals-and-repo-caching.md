# Lesson 02: Git Internals, Protocol v2, and Concurrent Repository Caching

> **Phase:** 02 — Git Repository Engine
> **Related ADRs:** [ADR-0002: Modular Monolith Workspace](../adr/0002-modular-monolith-workspace.md)
> **Code Walkthrough:** [`repo/gix_client.rs`](../../crates/ferriscd-engine/src/repo/gix_client.rs) · [`repo/cache.rs`](../../crates/ferriscd-engine/src/repo/cache.rs) · [`repo/sanitize.rs`](../../crates/ferriscd-engine/src/repo/sanitize.rs) · [`repo/fake.rs`](../../crates/ferriscd-engine/src/repo/fake.rs)

---

## 1. Why FerrisCD Owns a Git Layer At All

A GitOps controller is, at its core, a machine that answers one question over and over: *"what does commit `X` of repository `R` look like right now?"* Everything downstream — YAML parsing, Kustomize/Helm rendering, SSA diffing, sync waves, rollback — operates on the answer to that question.

Phase 02 builds that answer as a **pure-Rust, `gix`-backed acquisition layer behind an object-safe trait**:

```rust
pub trait GitClient: Send + Sync {
    fn resolve_revision(&'a self, src: &'a GitSource, creds: &'a RepoCredentials)
        -> RepoFuture<'a, ResolvedRevision>;
    fn checkout<'a>(&'a self, src: &'a GitSource, sha: &'a str, creds: &'a RepoCredentials)
        -> RepoFuture<'a, RepoCheckout>;
}
```

Three invariants make this layering worth the abstraction:

1. **No `gix` types leak.** `GitSource`, `ResolvedRevision`, `RepoCheckout`, and `RepoError` are plain domain types ([`repo/types.rs`](../../crates/ferriscd-engine/src/repo/types.rs), [`repo/error.rs`](../../crates/ferriscd-engine/src/repo/error.rs)). Transport backends can be swapped, and tests can substitute a fake with zero network.
2. **Blocking I/O never runs on a Tokio worker.** Every `gix` disk/network call sits inside `tokio::task::spawn_blocking` (`run_blocking` in [`repo/gix_client.rs`](../../crates/ferriscd-engine/src/repo/gix_client.rs)).
3. **Errors are classified for the reconcile loop.** `RepoError::is_retryable()` separates transient transport failures (`Network`, `Timeout`, retryable `Io`, `TaskCancelled`, `RemoteServerError` with `None`/`408`/`429`/`5xx`) from terminal ones (`InvalidUrl`, `InvalidSource`, `InvalidRevision`, `RevisionNotFound`, `AuthFailed`, `HostKeyVerificationFailed`, `UnsafeSymlink`, `CheckoutLimitExceeded`, `RepositoryError`). A terminal error must never be retried with backoff — retrying a symlink escape just burns the queue.

---

## 2. The Git Object Model: Refs Move, Commits Do Not

Git stores a content-addressed DAG. A commit points at a **tree**, a tree points at blobs and subtrees, and every object is named by the SHA-1 of its own content. Reproduced locally (`git 2.54.0`, Rust 1.99.0, macOS):

```bash
git init -q --initial-branch=main .
mkdir -p apps/base && printf 'resources: []\n' > apps/base/kustomization.yaml
git add . && git commit -qm c1
printf 'resources: []\n# c2\n' > apps/base/kustomization.yaml
git add . && git commit -qm c2

git rev-parse HEAD      # dcad10171bb06a67ad9230188a07d3eff26bbdb8
git symbolic-ref HEAD   # refs/heads/main
git cat-file -p HEAD
```

**Observed output:**

```text
tree dd088206ee934d4ba816538c78e9a3d4ed70e8c4
parent 0c4dae126028ec24739f8d1c96bf2491e0be6487
author Ferris Test <ferris@example.com> 1795514217 +0700
committer Ferris Test <ferris@example.com> 1795514217 +0700

c2
```

(Commit ids are content-addressed over the author/committer identity and timestamps, so your hashes will differ unless you pin the same identity and date. The repository's own tests pin `GIT_CONFIG_NOSYSTEM`, `GIT_CONFIG_GLOBAL=/dev/null`, and a fixed `GIT_*_DATE` for exactly this reason.)

The commit body itself contains no ref name — only a tree id, a parent id, and metadata. `refs/heads/main` is a *separate, mutable* pointer:

| Concept | Mutable? | Example | FerrisCD handling |
|---|---|---|---|
| Branch (`refs/heads/main`) | **Yes** — moves on every push | `refs/heads/main` | resolved to a SHA first, never cached as a name |
| Lightweight tag (`refs/tags/v1.2.3`) | No (by convention) | points straight at a commit | resolved, then checkout by SHA |
| Annotated tag | No | tag **object** → peeled to a commit | peeled (bounded to `MAX_TAG_PEEL_DEPTH`), never checked out as an object |
| `HEAD` | **Yes** — symbolic ref, or detached | `refs/heads/main` or a raw SHA | resolved through `symbolic-ref` then to a commit |
| Commit SHA | **No** — immutable | `dcad1017…` | the only cache key the engine ever uses |

This asymmetry is the entire reason [`ResolvedRevision`](../../crates/ferriscd-engine/src/repo/types.rs) exists: **the engine resolves once, then works exclusively in immutable SHAs.** `ResolvedRevision { commit_sha, requested_ref }` records both, so status messages can say *"`main` → `dcad1017…`"* while every subsequent operation (cache lookup, checkout, sanitization, renderer, diff, rollback) is keyed by the SHA. Rollback is then just "check out an older SHA that is still in `status.history`" — no ref archaeology, no force-push surprises.

`GixGitClient::resolve_revision` accepts branches (`refs/heads/*` and short names), tags (`refs/tags/*`, annotated tags peeled), `HEAD`, and full 40-character hex SHAs. Unknown refs are a terminal `RepoError::RevisionNotFound`.

---

## 3. Protocol v2, Shallow Packfiles, and Why "Clone" Is the Wrong Primitive

Modern Git negotiates **protocol v2** (`GIT_PROTOCOL=version=2`), which replaces the old grab-bag ref advertisement with capability-scoped commands such as `ls-refs` and `fetch`. The practical differences for a controller:

- **Refs are filtered by ref-prefix**, so a resolver interested in one branch does not need the full ref list.
- **Fetch negotiation is server-driven**, so a controller can ask for *exactly* `refs/heads/main` or a single wanted OID instead of downloading every branch and tag.
- **Shallow requests (`deepen` / `depth`) are part of the request**, which is what makes a "tip only" fetch cheap.

FerrisCD never runs a full history clone for reconciliation. `GixGitClient` fetches with `Shallow::DepthAtRemote(NonZeroU32::MIN)` (depth 1) using a *narrow, revision-derived* refspec set rather than the full ref advertisement: `HEAD` for `HEAD`, the literal `target_revision` when it is already a 40-hex SHA or already starts with `refs/`, and — for a bare name — **two** explicit refspecs, `refs/heads/<rev>` *and* `refs/tags/<rev>`. The resolved ref is then picked from the returned ref map by exact name, branches first. Every one of those specs names a single ref (no globs, no `fetch_tags`), so the transferred pack is still shallow and tip-only; the cost of the bare-name case is one extra ref line in `ls-refs`, not a wider object set.

Measured on a 40-commit repository that rewrites one file per commit:

```bash
git clone -q --bare work remote.git
git clone -q file://"$PWD/remote.git" full
git clone -q --depth 1 file://"$PWD/remote.git" shallow
git -C full    cat-file --batch-all-objects --batch-check | wc -l   # 200
git -C shallow cat-file --batch-all-objects --batch-check | wc -l   #   5
stat -f%z full/.git/objects/pack/*.pack                             # 93204
stat -f%z shallow/.git/objects/pack/*.pack                          #  2360
```

*(Outputs captured on macOS with `git 2.54.0`; `stat -f%z` is the BSD form — use `stat -c%s` on Linux.)*

**Reproducibility caveat:** only the *object* columns are structural (they follow from the fixture's tree shape given the commands above: one rewritten file per commit). The **byte** columns are not reproducible from this lesson — packfile size depends on the exact blob contents, the Git/zlib version, and the compression level, none of which are pinned here. Read `93,204` / `2,360` as illustrative, not as an expected value; the durable claim is the ratio and the object counts.

**Observed output:** a full clone of the 40-commit history holds **200 objects / 93,204 bytes** of packfile; a depth-1 clone of the same tip holds **5 objects / 2,360 bytes**. The shallow clone records its boundary in `.git/shallow` (here `44e19513f17c27c993128912a516d981e9d521e8`, i.e. content-dependent too), which is why `git rev-list --count HEAD` reports `1` in that clone and `40` in the full one.

Two consequences drive the design:

1. **Shallow is the right default, but it is a one-commit store.** Asking a shallow repository for an arbitrary historical SHA fails, because the objects simply are not there. `GixGitClient` therefore implements *shallow first, fall back to a full fetch* (`fetch_sha_shallow_then_fallback`): if the depth-1 fetch does not bring the target OID into the object database — a server may reject an unadvertised SHA-in-want, sometimes by closing the pipe mid-request — it drops that temporary repository and performs a full fetch across branches and tags (`Shallow::NoChange`, refspecs from `build_fallback_refspecs`). Treating the racy broken-pipe case as recoverable rather than fatal is deliberate.
2. **Shallow does not deduplicate across commits.** Every materialization of a *different* commit is another fetch. That is exactly the gap `RepoCache` closes at the process level (§4), and the gap a persistent per-URL bare mirror (`T02.7`) will close at the disk level.

> **Not yet implemented:** there is no persistent bare mirror today. [`RepoCache`](../../crates/ferriscd-engine/src/repo/cache.rs) provides the per-repository lock and the commit-keyed worktree cache only; the injected `GitClient` still re-fetches per materialization. Do not assume mirror-level object deduplication.

---

## 4. Worktree Isolation: One Immutable Directory Per `(repo, commit)`

### 4.1 The bug this prevents

Fifteen `Application` resources pointing at the same monorepo — `apps/base`, `apps/prod`, and a `platform` tree, at three different revisions — would share one scratch clone if the engine were naive. Two reconciles then race: one checks out commit A, the other commit B, in the same directory. The first renderer reads a half-written tree; a renderer that shells out to `kustomize` sees paths vanish mid-build. The failure is intermittent, silent, and unreproducible, which is the worst possible category for a delivery controller.

### 4.2 The layout

```text
<work_root>/
└── worktrees/
    └── <repo_hash>/                # 32 lowercase hex chars, FNV-1a of the normalized URL
        └── <commit_sha>/           # immutable, complete, sanitized worktree
```

`repo_hash` is derived from `normalize_repo_url(repo_url)` — whitespace and trailing separators only, deliberately conservative: collapsing case or `.git` suffixes risks conflating two *distinct* repositories onto one lock and one directory, which is far worse than a missed cache hit. The digest is FNV-1a-64 over two independent seeds, formatted as `{h1:016x}{h2:016x}`, so it can never inject `..` or absolute components into the layout.

### 4.3 The protocol inside `RepoCache::checkout`

```text
validate_commit_sha(sha)                       // terminal InvalidRevision, zero I/O
  │
  ├─ try_cache_hit()  ──────────────────────── hit ──► RepoCheckout + lease (refcount++)
  │     (only EntryState::Ready entries are leasable)
  ▼
repo_lock(repo_key).lock().await               // per-URL async mutex (DashMap<String, Arc<Mutex<()>>>)
  │
  ├─ try_cache_hit()  ──────────────────────── hit ──► RepoCheckout + lease (double-checked locking)
  ▼
client.checkout(src, sha, creds).await         // blocking gix work on the blocking pool
  │  (a client that returns a different commit_sha is a terminal RepositoryError)
  ▼
reserve_entry(repo_hash, sha)                  // EntryState::Materializing, refcount = 1
  ▼  spawn_blocking
create_dir_all(<work_root>/worktrees/<repo_hash>)
remove_stale_target(...)                       // crash leftovers, only for a key we own
rename(temp_dir, dest)                         // atomic publish; EXDEV => terminal, needs same FS
sanitize_worktree(dest, worktree_limits)       // escape check BEFORE the entry is leasable
mark_ready(...)                                // the only transition to EntryState::Ready
  ▼
drop(guard); reservation.publish(); RepoCheckout::with_lease(...)
  ▼
collect_garbage().await                        // LRU / TTL sweep, never touches leased entries
```

The important details, all of which exist because their absence was a real bug class:

- **Publish is an atomic rename.** A reader can never observe a partially written tree, so a lock-free `try_cache_hit` fast path is safe. Because publish is `rename(2)`, the client's temporary directory must live on the same filesystem as `RepoCacheConfig::work_root`; `EXDEV` is reported as a *terminal* `RepositoryError` with an explicit message instead of a retryable `Io` error that would loop forever.
- **Sanitize before publish, not after.** A renamed tree stays `Materializing` until `sanitize_worktree` accepts it. Only then does `mark_ready` make it leasable. A rejected tree is deleted, its reservation is rolled back, and the terminal error propagates — so no caller can ever lease an unverified checkout, and no cache entry outlives a failed verification.
- **Leases are refcounts, not deletion.** `RepoCheckout` holds an opaque `Arc<dyn Any + Send + Sync>` lease (`RepoCheckout::with_lease`). Dropping the handle decrements the refcount; only `collect_garbage` deletes directories, and only for entries with a zero refcount. With `max_entries = 0` / `max_age = ZERO` the cache can therefore temporarily exceed its bound instead of yanking a directory out from under an in-flight renderer.
- **Cancellation is safe.** A `checkout` future can be dropped at any `.await`; the `ReservationGuard` then releases the refcount and removes the placeholder entry, so a cancelled materialization cannot leave a permanently un-evictable `Materializing` entry.
- **Poisoning is not a panic.** The cache state mutex maps poisoning to a terminal `RepositoryError`; a `MutexGuard` is never held across an `.await`.

`RepoCache::len()` counts only `Ready` entries, and `RepoCacheConfig::new()` defaults to `max_entries = 64`, `max_age = 1h`, and `WorktreeLimits::default()` (100,000 filesystem entries / 512 MiB of regular-file content).

---

## 5. Experiment (a): Concurrent Monorepo Checkouts Yield One Cached Tree Per Commit

This reproduces the concurrency invariant end to end with `RepoCache` and the deterministic `FakeGitClient` harness from §7 — no network, no `git` binary, no sleeps. Create the harness as a scratch integration test (it needs the `test-utils` feature for the fake; the file is deliberately **not** committed):

`crates/ferriscd-engine/tests/lesson02_experiment.rs`

```rust
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ferriscd_engine::repo::{
    FakeGitClient, FakeGitClientConfig, GitClient, GitSource, RepoCache, RepoCacheConfig,
    RepoCredentials,
};
use tokio::task::JoinSet;

/// Every `<work_root>/worktrees/<repo_hash>/<sha>` directory on disk.
fn worktree_listing(work_root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut pending = vec![work_root.join("worktrees")];
    while let Some(dir) = pending.pop() {
        let Ok(read) = std::fs::read_dir(&dir) else { continue };
        for entry in read.flatten() {
            let path = entry.path();
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            if path.file_name().is_some_and(|name| name.len() == 40) {
                out.push(path.strip_prefix(work_root).unwrap_or(&path).display().to_string());
            } else {
                pending.push(path);
            }
        }
    }
    out.sort();
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_monorepo_checkouts_share_one_tree_per_commit() {
    let work_root = tempfile::tempdir().expect("work root");
    // Same root for the client and the cache, so publish is a same-filesystem rename.
    let fake = FakeGitClient::with_config(
        FakeGitClientConfig::new().with_work_root(work_root.path()),
    );
    let c1 = fake.add_commit("main", [
        ("apps/base/kustomization.yaml", "resources:\n- deployment.yaml\n"),
        ("apps/base/deployment.yaml", "kind: Deployment\n"),
        ("apps/prod/patch.yaml", "replicas: 3\n"),
    ]);
    let c2 = fake.add_commit("main", [
        ("apps/base/kustomization.yaml", "resources:\n- deployment.yaml\n"),
        ("apps/base/deployment.yaml", "kind: Deployment\n# c2\n"),
    ]);
    let c3 = fake.add_commit("main", [
        ("apps/base/kustomization.yaml", "resources:\n- deployment.yaml\n"),
        ("apps/base/deployment.yaml", "kind: Deployment\n# c3\n"),
    ]);

    let cache = Arc::new(RepoCache::new(
        Arc::new(fake.clone()) as Arc<dyn GitClient>,
        RepoCacheConfig::new(work_root.path()).with_max_entries(64),
    ));
    let src = Arc::new(GitSource::new(
        "https://github.com/ferris-cd/monorepo.git",
        "main",
        "apps/base",
    ));
    let commits = [c1.clone(), c2.clone(), c3.clone()];

    let mut tasks = JoinSet::new();
    for index in 0..16usize {
        let cache = Arc::clone(&cache);
        let src = Arc::clone(&src);
        let sha = commits[index % commits.len()].clone();
        tasks.spawn(async move {
            let checkout = cache
                .checkout(&src, &sha, &RepoCredentials::Anonymous)
                .await
                .unwrap_or_else(|err| panic!("checkout {sha}: {err}"));
            (sha, checkout.root_dir().to_path_buf())
        });
    }

    let mut roots: Vec<(String, PathBuf)> = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        roots.push(joined.expect("task must not panic"));
    }

    let mut per_commit: std::collections::BTreeMap<String, u32> = Default::default();
    for (sha, root) in &roots {
        assert!(root.is_dir(), "cached worktree must exist");
        assert!(!root.join(".git").exists(), "cache must never expose .git");
        let first = roots
            .iter()
            .find(|(other, _)| other == sha)
            .map(|(_, root)| root.clone())
            .expect("first entry");
        assert_eq!(&first, root, "commit {sha} mapped to two roots");
        *per_commit.entry(sha.clone()).or_default() += 1;
    }

    println!("== (a) concurrent monorepo checkouts ==");
    println!("tokens requesting checkouts : 16");
    println!("distinct commits requested  : {}", per_commit.len());
    println!("GitClient::checkout calls    : {}", fake.checkout_calls());
    println!("RepoCache entries            : {}", cache.len());
    for (sha, count) in &per_commit {
        println!("commit {sha} -> {count} handles");
    }
    println!("cached worktrees under work_root:");
    for path in worktree_listing(work_root.path()) {
        println!("  {path}");
    }

    assert_eq!(fake.checkout_calls(), 3, "one materialization per commit");
    assert_eq!(cache.len(), 3);
    assert_eq!(worktree_listing(work_root.path()).len(), 3);
}
```

Run it:

```bash
cargo test --workspace --features ferriscd-engine/test-utils \
  --test lesson02_experiment -- --nocapture
```

*(If you run the engine crate alone, add `K8S_OPENAPI_ENABLED_VERSION=1.35`: `ferriscd-engine` is a library crate and therefore never enables a `k8s-openapi` version feature itself — AGENTS.md invariant — so the feature has to come from a binary crate or that env var.)*

**Observed output:**

```text
== (a) concurrent monorepo checkouts ==
tokens requesting checkouts : 16
distinct commits requested  : 3
GitClient::checkout calls    : 3
RepoCache entries            : 3
commit 1cdb83440c8ac706d35094f4745e46b600000002 -> 5 handles
commit 3e066c34ee20594b88c59c9be44a749b00000001 -> 5 handles
commit fd8964247ad08041f5314e2a000dd9b100000000 -> 6 handles
cached worktrees under work_root:
  worktrees/81468ef71aa2781ece1fcab2954aa78e/1cdb83440c8ac706d35094f4745e46b600000002
  worktrees/81468ef71aa2781ece1fcab2954aa78e/3e066c34ee20594b88c59c9be44a749b00000001
  worktrees/81468ef71aa2781ece1fcab2954aa78e/fd8964247ad08041f5314e2a000dd9b100000000
test concurrent_monorepo_checkouts_share_one_tree_per_commit ... ok
```

Read the numbers carefully — they are the whole point:

- **16 tokens wanted a checkout, but the client was called 3 times.** The per-repository async mutex serialized the materializations and the double-checked cache hit absorbed the other 13 requests.
- **One directory per commit, not per request.** `worktrees/81468ef7…/` is the single `repo_hash` for that URL; beneath it exactly three SHAs exist on disk.
- **Handle counts (5 + 5 + 6) sum to 16.** Every token got a lease on the correct commit's tree, and 13 of them leased an already-verified directory.
- **No `.git` anywhere.** The cached trees are plain files: renderers cannot `git checkout`, run hooks, or read credentials out of repository config.

The same invariant is asserted permanently against a **real** `gix` clone in the crate's own test suite (no feature flag needed):

```bash
cargo test --workspace --lib sixteen_concurrent
# test repo::cache::tests::sixteen_concurrent_checkouts_across_three_commits_are_corruption_free ... ok
```

That test spawns 16 tasks over 3 commits of a temp bare repository and asserts `client.checkout_count() == 3`; `repo::cache::tests::concurrent_gc_never_deletes_a_live_worktree` additionally hammers `collect_garbage` concurrently with acquisition to prove the lease refcount.

---

## 6. Experiment (b): Symlink Escape Rejection

### 6.1 The attack

A worktree is untrusted input. Consider a repository whose `apps/base` tree contains:

```text
120000 blob 3594e94c04db171e2767224db355f514b13715c5	apps/base/values.yaml
```

Mode `120000` is a symlink. If that link points at `/var/run/secrets/kubernetes.io/serviceaccount/token`, then a Helm value file, a Kustomize included file, or any plugin that reads `values.yaml` exfiltrates the controller's cluster credentials — no exploit code required, just a manifest tree. This is finding **C7** in [`docs/REVIEW_LOG.md`](../REVIEW_LOG.md).

### 6.2 The defense

Immediately after materialization, and **before** a `RepoCheckout` is returned, [`sanitize_worktree`](../../crates/ferriscd-engine/src/repo/sanitize.rs) walks the entire tree (iteratively, never following a symlink) and:

- canonicalizes the root, then compares every symlink's canonical target against it with **component-aware** `Path::starts_with` — never a string prefix, so a sibling directory `worktree-evil/` is not "inside" `worktree/`;
- rejects absolute targets outside the root, chained `../../` escapes, broken links, and symlink loops;
- rejects a link that resolves to its own parent or an ancestor (`link -> .`, `sub/link -> ..`), which would make a link-following traversal recurse forever;
- **accepts** symlinks that resolve strictly inside the root, including absolute targets that point inside it;
- enforces `WorktreeLimits` (`max_files`, `max_bytes`) so a checkout bomb fails terminally;
- treats an unreadable or vanishing directory as a terminal `RepositoryError` — a tree that cannot be fully verified must never reach a renderer.

Every rejection is a terminal `RepoError::UnsafeSymlink` (or `CheckoutLimitExceeded`), i.e. `is_retryable() == false`.

### 6.3 Reproduce it with real Git and the real client

Same scratch harness file as §5; add:

```rust
use std::process::Command;
use ferriscd_engine::repo::{GixGitClient, GixGitClientConfig, RepoError, RepoUrlPolicy};

fn git(cwd: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .current_dir(cwd)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Ferris Test")
        .env("GIT_AUTHOR_EMAIL", "ferris@example.com")
        .env("GIT_COMMITTER_NAME", "Ferris Test")
        .env("GIT_COMMITTER_EMAIL", "ferris@example.com")
        .output()
        .expect("git must execute");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

#[tokio::test]
async fn symlink_escape_is_rejected_before_a_checkout_is_returned() {
    let tmp = tempfile::tempdir().expect("fixture root");
    let work = tmp.path().join("work");
    let bare = tmp.path().join("remote.git");
    std::fs::create_dir_all(work.join("apps/base")).expect("mkdir");
    git(&work, &["init", "--initial-branch=main"]);
    std::fs::write(work.join("apps/base/kustomization.yaml"), "resources: []\n").expect("write");
    git(&work, &["add", "."]);
    git(&work, &["commit", "-m", "safe tree"]);
    // The attack: a symlink that resolves outside the worktree.
    std::os::unix::fs::symlink("/etc/passwd", work.join("apps/base/values.yaml")).expect("symlink");
    git(&work, &["add", "."]);
    git(&work, &["commit", "-m", "add escaping symlink"]);
    let sha = git(&work, &["rev-parse", "HEAD"]);
    println!("== (b) symlink escape rejection ==");
    println!("commit: {sha}");
    println!("tree entry modes (120000 == symlink):");
    println!("{}", git(&work, &["ls-tree", "-r", "HEAD"]));

    git(tmp.path(), &[
        "clone", "--bare",
        work.to_str().expect("utf8"),
        bare.to_str().expect("utf8"),
    ]);

    let work_root = tempfile::tempdir().expect("work root");
    let client = GixGitClient::new(
        GixGitClientConfig::new()
            .with_url_policy(RepoUrlPolicy::AllowLocal)
            .with_work_root(work_root.path().to_path_buf()),
    );
    let cache = RepoCache::new(
        Arc::new(client) as Arc<dyn GitClient>,
        RepoCacheConfig::new(work_root.path()),
    );
    let src = GitSource::new(bare.to_str().expect("utf8"), "main", "apps/base");
    let err = cache
        .checkout(&src, &sha, &RepoCredentials::Anonymous)
        .await
        .expect_err("symlink escape must be rejected");

    println!("error   : {err}");
    println!("retryable: {}", err.is_retryable());
    println!("cache entries after rejection: {}", cache.len());
    println!("worktrees left on disk: {}", worktree_listing(work_root.path()).len());
    match &err {
        RepoError::UnsafeSymlink { path, target, .. } => {
            println!("path    : {}", path.display());
            println!("target  : {}", target.display());
        }
        other => panic!("expected UnsafeSymlink, got {other:?}"),
    }
    assert!(!err.is_retryable());
    assert!(cache.is_empty());
    assert!(worktree_listing(work_root.path()).is_empty());
}
```

**Observed output:**

```text
== (b) symlink escape rejection ==
commit: 7b296cc93bef65f3530fa67f1fc41646db5f40aa
tree entry modes (120000 == symlink):
100644 blob e584213cf674d164cae882252e3c43fd11012291	apps/base/kustomization.yaml
120000 blob 3594e94c04db171e2767224db355f514b13715c5	apps/base/values.yaml
error   : unsafe symlink at '/private/var/folders/…/T/.tmpgJ38JX/ferriscd-git-Ewx6k6/apps/base/values.yaml' -> '/etc/passwd': symlink target escapes the checkout root
retryable: false
cache entries after rejection: 0
worktrees left on disk: 0
path    : /private/var/folders/…/T/.tmpgJ38JX/ferriscd-git-Ewx6k6/apps/base/values.yaml
target  : /etc/passwd
test symlink_escape_is_rejected_before_a_checkout_is_returned ... ok
```

Four properties are visible in that output:

1. **The failure is terminal** (`retryable: false`), so the reconcile loop will surface it instead of retrying forever.
2. **The offending path and target are named** — an operator can fix the repository, and the message contains no secret material.
3. **`cache entries after rejection: 0` and no worktree left on disk** — the rejected tree was deleted and its reservation rolled back before it could become `EntryState::Ready`.
4. **The path is a `ferriscd-git-*` temporary directory**, i.e. it was rejected inside the client's own checkout, before the cache's publish step. Both layers run the sanitizer: `GixGitClient::checkout` sanitizes its own worktree, and `RepoCache` re-sanitizes every materialization, because the cache cannot know which backend produced the tree (or whether it sanitized at all — see §7, the fake materializes plain files). Duplicate work on a bounded tree is a cheap price for "no unverified tree is ever leasable".

The permanent unit tests for this live in [`repo/sanitize.rs`](../../crates/ferriscd-engine/src/repo/sanitize.rs) and cover the valid intra-repo link, `/etc/passwd`, the chained `../../outside/secret.txt` escape, the sibling `worktree-evil` string-prefix trap, absolute targets inside the root, loops, ancestor links, broken links, and the budget limits:

```bash
cargo test --workspace --lib repo::sanitize::tests
```

---

## 7. The `FakeGitClient` Harness: Deterministic Fixtures for Phases 03–15

Every later phase needs Git fixtures: renders, diffs, sync ordering, partial failures, outages, rollbacks. Shelling out to `git` in those tests is slow, network-dependent, and non-deterministic. [`repo/fake.rs`](../../crates/ferriscd-engine/src/repo/fake.rs) provides an in-memory `GitClient` with **real on-disk checkouts**:

```rust
use ferriscd_engine::repo::{FakeGitClient, FakeStage, GitSource, RepoCredentials, RepoError};

let client = FakeGitClient::new();
let c1 = client.add_commit("main", [("apps/base/deployment.yaml", "kind: Deployment\n")]);
let c2 = client.add_commit("main", [("apps/base/deployment.yaml", "kind: Deployment\n# v2\n")]);
client.add_tag("v1.0.0", c1.clone());           // lightweight tag
client.set_head_branch("main");                  // or client.detach_head(&c1)
assert_eq!(client.branch_tip("main"), Some(c2.clone()));

// Resolve exactly like production code does.
let src = GitSource::new("https://github.com/ferris-cd/monorepo.git", "HEAD", "apps/base");
let resolved = client.resolve_revision(&src, &RepoCredentials::Anonymous).await?;
assert_eq!(resolved.commit_sha, c2);

// Script an outage: one transient failure, then success (no sleeps).
client.fail_once_then_succeed(FakeStage::Resolve, RepoError::Network {
    message: "connection reset by peer".to_owned(),
});
let first = client.resolve_revision(&src, &RepoCredentials::Anonymous).await;
assert!(first.unwrap_err().is_retryable());
let second = client.resolve_revision(&src, &RepoCredentials::Anonymous).await;
assert_eq!(second?.commit_sha, c2);
assert!(client.faults_exhausted());
```

Design rules that make it trustworthy:

- **Deterministic SHAs.** `add_commit` derives a 40-character lowercase hex SHA from `(parent, branch, call ordinal, files)` with FNV-1a, so replaying the same script on any machine yields the same SHAs, and every SHA satisfies `validate_commit_sha`. That is what makes cache keys and `status.history` assertions stable. (The observable tell in §5: a trailing `00000000`, `00000001`, `00000002` ordinal.)
- **Immutable, addressable history.** Commits are stored by SHA and never mutated, so a pre-tip commit stays checkable after the branch advances. A commit is a *full tree snapshot* like Git, not a delta: a path omitted from a commit is absent from it.
- **Real checkouts, no `.git`.** Files are written into a `tempfile::TempDir` created under `FakeGitClientConfig::work_root` (default: system temp) and returned as `RepoCheckout::with_lease(root, sha, Arc<TempDir>)`, so dropping the handle deletes the directory. Pointing `work_root` at `RepoCacheConfig::work_root` lets `RepoCache` publish it with an atomic same-filesystem rename — the fake is drop-in substitutable for `GixGitClient` on the cache path (§5 proves it).
- **Faults are per stage and consumed in order.** `FakeStage::Resolve` and `FakeStage::Checkout` have independent queues, so a resolve outage never leaks into a checkout. Arbitrary `RepoError`s work, which is how retry loops get tested against both retryable (`Network`, `Timeout`, `RemoteServerError { status: Some(503) }`) and terminal (`RevisionNotFound`, `AuthFailed`, `UnsafeSymlink`) classifications.
- **Validation is uniform.** `GitSource::validate(url_policy)` runs at the start of every operation — *before* a queued fault is consumed — so a fake and the real client classify a `file://` URL or a bad `target_revision` identically, and a test never confuses "bad input" with "injected outage".
- **Refs only resolve to real commits.** Every ref-derived SHA (branch, tag, `HEAD`, short name) passes the same predicate as a literal SHA — canonical 40-hex *and* present in the fixture — so `resolve_revision` can never return a `ResolvedRevision::commit_sha` that a later `checkout` would reject. `add_tag("v-bogus", "not-a-sha")` or a tag pointing at a foreign SHA is a terminal `RevisionNotFound`, which is what a real `ls-remote`/peel would produce. Within one operation the order is validate → queued fault → lookup, so an injected fault deliberately masks the lookup error.
- **Calls are recorded.** `resolve_calls()`, `checkout_calls()`, `resolve_log()`, and `checkout_log()` let cache tests prove hit/miss behaviour (`client.checkout_calls() == 3` in §5).
- **No panics, no path escapes.** A poisoned state mutex is recovered (`PoisonError::into_inner`), and a commit path that is absolute or contains `..` fails checkout with a terminal `RepoError::InvalidSource` instead of writing outside the checkout root.
- **Symlinks are deliberately not modellable.** Crafted symlink trees are the sanitizer's job and are built with real `git` (§6). Never "test" the escape defense with a fake that cannot express the escape.

Availability is feature-gated so downstream crates reuse the harness instead of hand-rolling stubs:

```toml
# Cargo.toml of a downstream crate (ferriscd-controller, integration tests)
[dev-dependencies]
ferriscd-engine = { path = "../ferriscd-engine", features = ["test-utils"] }
```

The module is compiled for `ferriscd-engine`'s own tests unconditionally and for everyone else only under `test-utils`, so production builds never carry it.

---

## 8. Invariants to Carry Forward

| Invariant | Where it is enforced | Failure it prevents |
|---|---|---|
| Resolve refs to immutable SHAs before caching or reporting | `ResolvedRevision`, `RepoCache` keys | a moved `main` silently changing what "deployed" means |
| One lock per normalized `repo_url`, one directory per `(repo_hash, commit_sha)` | `RepoCache` | concurrent reconciles corrupting a shared worktree |
| Publish by atomic rename on one filesystem | `RepoCache::checkout`, `EXDEV => terminal` | renderers observing partially written trees |
| Sanitize the whole tree before it is leasable; reject terminal | `sanitize_worktree`, `mark_ready` ordering | secret exfiltration via `values.yaml -> /var/run/…/token` (C7) |
| Leases are refcounts; GC never deletes a leased directory | `CheckoutLease`, `collect_garbage` | yanking a worktree out from under an active renderer |
| Blocking `gix`/disk work only in `spawn_blocking` | `run_blocking`, cache publish | starving the Tokio reactor under reconcile load |
| Classify errors retryable vs terminal | `RepoError::is_retryable` | infinite backoff on a permanently broken repo |
| Never print credentials | `RepoCredentials` `Debug`/`Display`, no `gix` types in signatures | token/key leakage in logs and status conditions |

## 9. Cleanup

The harness file from §5/§6 is a scratch artifact — delete it after the experiment so the workspace stays at its committed state:

```bash
rm crates/ferriscd-engine/tests/lesson02_experiment.rs
```

The equivalent permanent coverage stays in the crate: `repo::cache::tests` (cache hits, GC vs. leases, the 16-task concurrency test), `repo::sanitize::tests` (escape matrix), `repo::fake::tests` (determinism, ref resolution, fault injection, concurrent checkouts), and `repo::gix_client` integration tests against a temp bare repository.
