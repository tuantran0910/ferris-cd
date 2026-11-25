//! Test-only fake `kustomize` / `helm` binaries.
//!
//! `make gate` must never depend on the real ecosystem tools, so every unit test that exercises
//! the renderer → parser → normalizer pipeline points a renderer at a small POSIX shell script
//! generated here. Each fake:
//!
//! * appends one line per invocation to an invocation counter (so a test can prove a cache hit
//!   spawned the subprocess zero times),
//! * records its argv and the `kustomization.yaml` inside the directory it was asked to build (so
//!   a test can assert the *exact* flags and the generated overlay content), and
//! * prints a caller-supplied manifest bundle on stdout (or a value derived from its arguments).
//!
//! These scripts are `#[cfg(test)]`-only and never ship in a binary.

use std::fs;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

/// A generated fake renderer binary plus its invocation recorder.
pub struct FakeBinary {
    dir: TempDir,
    path: PathBuf,
}

impl FakeBinary {
    /// Fake that always prints `stdout` and exits 0.
    pub fn new(name: &str, stdout: &str) -> Self {
        Self::build(name, &record_header(), stdout, "")
    }

    /// Fake that prints `stdout`/`stderr` and exits 1.
    pub fn failing(name: &str, stdout: &str, stderr: &str) -> Self {
        Self::build_with_exit(name, &record_header(), stdout, stderr, 1)
    }

    /// Fake that emits `<target>/manifest.yaml`, where `target_arg_index` is the 1-based argv
    /// position of the directory/file the renderer was asked to render.
    ///
    /// This makes the rendered output provably path-dependent, which is what the render-cache
    /// tests need to detect cross-application contamination.
    pub fn mirroring(name: &str, target_arg_index: usize) -> Self {
        let body = format!(
            "{header}cat \"${{{target_arg_index}}}/manifest.yaml\"\n",
            header = record_header()
        );
        Self::build(name, &body, "", "")
    }

    /// Fake that behaves like `helm template` for namespace purposes: it emits a `ConfigMap`
    /// whose `metadata.namespace` is the value passed to `--namespace`.
    ///
    /// Real charts derive `.Release.Namespace` this way, so the output must change whenever the
    /// destination namespace changes.
    pub fn helm_namespaced(name: &str) -> Self {
        let body = format!(
            "{header}\
namespace=''
previous=''
for argument in \"$@\"; do
  if [ \"$previous\" = '--namespace' ]; then namespace=\"$argument\"; fi
  previous=\"$argument\"
done
cat <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: release-config
  namespace: $namespace
data:
  rendered: 'true'
EOF
",
            header = record_header()
        );
        Self::build(name, &body, "", "")
    }

    /// Fake that emits a `helm.sh/hook` Job unless `--no-hooks` is passed.
    ///
    /// `helm template` inlines hook resources by default, so this mirrors the real behaviour the
    /// renderer must suppress (finding M4): the Job is exactly what would otherwise enter the
    /// managed inventory as an ordinary workload.
    pub fn helm_hook_conditional(name: &str) -> Self {
        let body = format!(
            "{header}\
no_hooks='false'
for argument in \"$@\"; do
  if [ \"$argument\" = '--no-hooks' ]; then no_hooks='true'; fi
done
cat <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: chart-config
---
EOF
if [ \"$no_hooks\" = 'false' ]; then
cat <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: chart-migrate
  annotations:
    \"helm.sh/hook\": pre-install
EOF
fi
",
            header = record_header()
        );
        Self::build(name, &body, "", "")
    }

    /// Fake that emits a chart CRD only when `--include-crds` is present.
    ///
    /// This lets the CRD opt-in test assert the *rendered output*, not just the argv.
    pub fn helm_crd_conditional(name: &str) -> Self {
        let body = format!(
            "{header}\
include='false'
for argument in \"$@\"; do
  if [ \"$argument\" = '--include-crds' ]; then include='true'; fi
done
cat <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: chart-config
---
EOF
if [ \"$include\" = 'true' ]; then
cat <<EOF
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: widgets.example.com
spec:
  group: example.com
  names:
    kind: Widget
    plural: widgets
  scope: Namespaced
  versions:
    - name: v1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
EOF
fi
",
            header = record_header()
        );
        Self::build(name, &body, "", "")
    }

    /// Absolute path to pass as the renderer `binary` option.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Number of times the fake has been executed.
    pub fn invocations(&self) -> usize {
        match fs::read_to_string(self.dir.path().join("invocations")) {
            Ok(contents) => contents.lines().filter(|line| !line.is_empty()).count(),
            Err(_) => 0,
        }
    }

    /// Every recorded argv element, flattened across invocations (`---` separates invocations).
    pub fn recorded_args(&self) -> Vec<String> {
        self.recorded("args")
    }

    /// Contents of the `kustomization.yaml` inside each directory the fake was asked to build,
    /// one entry per invocation that had one.
    pub fn recorded_kustomizations(&self) -> Vec<String> {
        match fs::read_to_string(self.dir.path().join("kustomizations")) {
            Ok(contents) => contents
                .split("\n---\n")
                .map(str::trim)
                .filter(|block| !block.is_empty())
                .map(str::to_owned)
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    fn recorded(&self, file: &str) -> Vec<String> {
        match fs::read_to_string(self.dir.path().join(file)) {
            Ok(contents) => contents
                .lines()
                .map(str::to_owned)
                .filter(|line| !line.is_empty() && line != "---")
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    fn build(name: &str, body: &str, stdout: &str, stderr: &str) -> Self {
        Self::build_with_exit(name, body, stdout, stderr, 0)
    }

    fn build_with_exit(name: &str, body: &str, stdout: &str, stderr: &str, exit_code: i32) -> Self {
        let dir = tempfile::tempdir().expect("create fake binary directory");
        let path = dir.path().join(name);
        let script = format!(
            "#!/bin/sh\n{body}\ncat <<'FERRISCD_FAKE_STDOUT'\n{stdout}\nFERRISCD_FAKE_STDOUT\n\
             cat >&2 <<'FERRISCD_FAKE_STDERR'\n{stderr}\nFERRISCD_FAKE_STDERR\nexit {exit_code}\n",
        );
        fs::write(&path, script).expect("write fake binary");
        make_executable(&path);
        Self { dir, path }
    }
}

/// Shell preamble recording the invocation count, argv, and the built kustomization.
fn record_header() -> String {
    // `$2` is the directory argument of `kustomize build <dir> ...`; templates that do not pass a
    // build target simply leave the kustomization log empty.
    "printf 'x\\n' >> \"$(dirname \"$0\")/invocations\"\n\
     { printf '%s\\n' \"$@\"; printf -- '---\\n'; } >> \"$(dirname \"$0\")/args\"\n\
     if [ -r \"$2/kustomization.yaml\" ]; then\n\
       printf -- '---\\n' >> \"$(dirname \"$0\")/kustomizations\"\n\
       cat \"$2/kustomization.yaml\" >> \"$(dirname \"$0\")/kustomizations\"\n\
     fi\n"
        .to_owned()
}

/// Marks `path` executable (no-op best effort on platforms without Unix modes).
fn make_executable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = fs::metadata(path)
            .expect("fake binary metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).expect("chmod fake binary");
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}
