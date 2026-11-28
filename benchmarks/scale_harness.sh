#!/usr/bin/env bash
# FerrisCD Phase 15 (T15.3) — 50-Application / 500-Resource Scale & Memory Soak Harness.
#
# Modes:
#   --dry-run    Offline manifest generation & validation (zero cluster calls).
#   --self-test  Deterministic offline unit tests for safety guard, counts,
#                Prometheus histogram quantiles, and RSS/FD flatness checks.
#   --cleanup    Delete benchmark Applications, AppProject, and destination namespaces on kind.
#   (default)    Live benchmark & soak run against a local kind-* cluster.
#
# Safety invariant:
#   Every live or cleanup operation asserts that `kubectl config current-context`
#   begins with `kind-` before executing any cluster command.

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
MODE="live"
APP_COUNT=50
RESOURCES_PER_APP=10
SOAK_MINUTES=30
WARMUP_MINUTES=5
SAMPLE_INTERVAL_SECS=30
REQUEUE_SECONDS=30
CONVERGENCE_TIMEOUT_SECS=600
CONTROL_PLANE_NS="ferriscd-system"
BENCHMARK_PROJECT_NAME="bench-scale"
BENCHMARK_LABEL_KEY="ferriscd.io/benchmark"
BENCHMARK_LABEL_VAL="scale-v1"
METRICS_URL="http://127.0.0.1:9090/metrics"
CONTROLLER_PID=""
CONTROLLER_SELECTOR="app.kubernetes.io/name=ferriscd-controller"
REPO_URL=""
TARGET_REVISION="main"
DEPLOYMENT_REPLICAS=1
PAUSE_IMAGE="registry.k8s.io/pause:3.10"
MAX_RSS_GROWTH_PCT="10.0"
MAX_FD_GROWTH=16
ALLOW_MISSING_FD=0
OUTPUT_DIR=""
RESULTS_DIR=""
KEEP_TEMP=0

CLEANUP_TEMP_DIRS=()

cleanup_temp_dirs() {
  if [[ "$KEEP_TEMP" -eq 1 ]]; then
    return 0
  fi
  local dir
  for dir in "${CLEANUP_TEMP_DIRS[@]:-}"; do
    if [[ -n "$dir" && -d "$dir" ]]; then
      rm -rf "$dir"
    fi
  done
}
trap cleanup_temp_dirs EXIT

# ---------------------------------------------------------------------------
# Logging & Usage
# ---------------------------------------------------------------------------
log_info() {
  printf '[INFO]  %s\n' "$*"
}

log_pass() {
  printf '[PASS]  %s\n' "$*"
}

log_warn() {
  printf '[WARN]  %s\n' "$*" >&2
}

log_err() {
  printf '[ERROR] %s\n' "$*" >&2
}

usage() {
  cat <<'EOF'
Usage: benchmarks/scale_harness.sh [OPTIONS]

Modes (mutually exclusive; default is live benchmark on kind):
  --dry-run                       Generate 50 Applications (500 resources) + AppProject offline and validate.
  --self-test                     Run offline unit tests (safety guard, counts, p50/p95, RSS/FD).
  --cleanup                       Remove benchmark Applications, AppProject, and namespaces from kind.

Scale & Soak Options:
  --apps N                        Number of Application CRs to generate (default: 50).
  --resources-per-app N           Workload resources per Application, >= 4 (default: 10).
  --soak-minutes M                Soak test duration in minutes (default: 30).
  --warmup-minutes W              Warm-up window before RSS/FD baseline in minutes (default: 5).
  --sample-interval S             RSS/FD sampling interval in seconds (default: 30).
  --requeue-seconds S             Application spec.requeueAfterSeconds (default: 30).
  --convergence-timeout S         Cold convergence timeout in seconds (default: 600).
  --deployment-replicas N         Replicas per app Deployment (default: 1; pause image).

Cluster & Controller Options:
  --namespace NS                  Control-plane namespace for Application CRs (default: ferriscd-system).
  --metrics-url URL               Prometheus /metrics endpoint (default: http://127.0.0.1:9090/metrics).
  --controller-pid PID            Local controller PID for direct RSS/FD sampling.
  --controller-selector SEL       Pod label selector when controller runs in-cluster
                                  (default: app.kubernetes.io/name=ferriscd-controller).
  --repo-url URL                  Git repoURL to write into Applications (default: local file:// fixture).
  --target-revision REV           Git branch/revision (default: main).

Pass/Fail Thresholds & Output:
  --max-rss-growth-pct PCT        Max allowed post-warmup RSS growth % (default: 10.0).
  --max-fd-growth N               Max allowed post-warmup open FD delta (default: 16).
  --allow-missing-fd              Allow missing (-1) FD telemetry instead of failing (e.g. distroless pods).
  --output-dir DIR                Write generated manifests into DIR (implies --keep-temp for DIR).
  --results-dir DIR               Directory to store live soak CSVs and metric snapshots
                                  (default: persistent temp dir not deleted on exit).
  --keep-temp                     Do not delete temporary working directories on exit.
  -h, --help                      Show this help text.
EOF
}

# ---------------------------------------------------------------------------
# Argument Parsing
# ---------------------------------------------------------------------------
require_positive_int() {
  local flag="$1"
  local val="$2"
  if [[ ! "$val" =~ ^[0-9]+$ ]] || [[ "$val" -le 0 ]]; then
    log_err "$flag requires a positive integer (got: '$val')"
    exit 2
  fi
}

require_nonneg_int() {
  local flag="$1"
  local val="$2"
  if [[ ! "$val" =~ ^[0-9]+$ ]]; then
    log_err "$flag requires a non-negative integer (got: '$val')"
    exit 2
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dry-run)
        MODE="dry-run"
        shift
        ;;
      --self-test)
        MODE="self-test"
        shift
        ;;
      --cleanup)
        MODE="cleanup"
        shift
        ;;
      --apps)
        [[ $# -ge 2 ]] || { log_err "--apps requires a value"; exit 2; }
        require_positive_int "--apps" "$2"
        APP_COUNT="$2"
        shift 2
        ;;
      --resources-per-app)
        [[ $# -ge 2 ]] || { log_err "--resources-per-app requires a value"; exit 2; }
        require_positive_int "--resources-per-app" "$2"
        if [[ "$2" -lt 4 ]]; then
          log_err "--resources-per-app must be >= 4 (ServiceAccount, Deployment, Service, Secret, plus ConfigMaps)"
          exit 2
        fi
        RESOURCES_PER_APP="$2"
        shift 2
        ;;
      --soak-minutes)
        [[ $# -ge 2 ]] || { log_err "--soak-minutes requires a value"; exit 2; }
        require_positive_int "--soak-minutes" "$2"
        SOAK_MINUTES="$2"
        shift 2
        ;;
      --warmup-minutes)
        [[ $# -ge 2 ]] || { log_err "--warmup-minutes requires a value"; exit 2; }
        require_nonneg_int "--warmup-minutes" "$2"
        WARMUP_MINUTES="$2"
        shift 2
        ;;
      --sample-interval)
        [[ $# -ge 2 ]] || { log_err "--sample-interval requires a value"; exit 2; }
        require_positive_int "--sample-interval" "$2"
        SAMPLE_INTERVAL_SECS="$2"
        shift 2
        ;;
      --requeue-seconds)
        [[ $# -ge 2 ]] || { log_err "--requeue-seconds requires a value"; exit 2; }
        require_positive_int "--requeue-seconds" "$2"
        REQUEUE_SECONDS="$2"
        shift 2
        ;;
      --convergence-timeout)
        [[ $# -ge 2 ]] || { log_err "--convergence-timeout requires a value"; exit 2; }
        require_positive_int "--convergence-timeout" "$2"
        CONVERGENCE_TIMEOUT_SECS="$2"
        shift 2
        ;;
      --deployment-replicas)
        [[ $# -ge 2 ]] || { log_err "--deployment-replicas requires a value"; exit 2; }
        require_nonneg_int "--deployment-replicas" "$2"
        DEPLOYMENT_REPLICAS="$2"
        shift 2
        ;;
      --namespace)
        [[ $# -ge 2 ]] || { log_err "--namespace requires a value"; exit 2; }
        CONTROL_PLANE_NS="$2"
        shift 2
        ;;
      --metrics-url)
        [[ $# -ge 2 ]] || { log_err "--metrics-url requires a value"; exit 2; }
        METRICS_URL="$2"
        shift 2
        ;;
      --controller-pid)
        [[ $# -ge 2 ]] || { log_err "--controller-pid requires a value"; exit 2; }
        require_positive_int "--controller-pid" "$2"
        CONTROLLER_PID="$2"
        shift 2
        ;;
      --controller-selector)
        [[ $# -ge 2 ]] || { log_err "--controller-selector requires a value"; exit 2; }
        CONTROLLER_SELECTOR="$2"
        shift 2
        ;;
      --repo-url)
        [[ $# -ge 2 ]] || { log_err "--repo-url requires a value"; exit 2; }
        REPO_URL="$2"
        shift 2
        ;;
      --target-revision)
        [[ $# -ge 2 ]] || { log_err "--target-revision requires a value"; exit 2; }
        TARGET_REVISION="$2"
        shift 2
        ;;
      --max-rss-growth-pct)
        [[ $# -ge 2 ]] || { log_err "--max-rss-growth-pct requires a value"; exit 2; }
        if [[ ! "$2" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
          log_err "--max-rss-growth-pct requires a non-negative number (got: '$2')"
          exit 2
        fi
        MAX_RSS_GROWTH_PCT="$2"
        shift 2
        ;;
      --max-fd-growth)
        [[ $# -ge 2 ]] || { log_err "--max-fd-growth requires a value"; exit 2; }
        require_nonneg_int "--max-fd-growth" "$2"
        MAX_FD_GROWTH="$2"
        shift 2
        ;;
      --allow-missing-fd)
        ALLOW_MISSING_FD=1
        shift
        ;;
      --output-dir)
        [[ $# -ge 2 ]] || { log_err "--output-dir requires a value"; exit 2; }
        OUTPUT_DIR="$2"
        shift 2
        ;;
      --results-dir)
        [[ $# -ge 2 ]] || { log_err "--results-dir requires a value"; exit 2; }
        RESULTS_DIR="$2"
        shift 2
        ;;
      --keep-temp)
        KEEP_TEMP=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        log_err "Unknown argument: $1"
        usage >&2
        exit 2
        ;;
    esac
  done
}

# ---------------------------------------------------------------------------
# Safety Guard: kind-* kubectl context enforcement
# ---------------------------------------------------------------------------
validate_kind_context() {
  local ctx="${1:-}"
  if [[ -z "$ctx" ]]; then
    log_err "SAFETY GUARD: kubectl current-context is empty. Refusing to run against an unknown cluster."
    return 1
  fi
  if [[ "$ctx" != kind-* ]]; then
    log_err "SAFETY GUARD: refusing to run against non-kind kubectl context '${ctx}' (must start with 'kind-')."
    return 1
  fi
  return 0
}

require_kind_context() {
  if ! command -v kubectl >/dev/null 2>&1; then
    log_err "kubectl is required for live/cleanup mode but was not found on PATH."
    return 1
  fi
  local current_ctx
  current_ctx="$(kubectl config current-context 2>/dev/null || true)"
  validate_kind_context "$current_ctx" || return 1
  log_info "Verified kind kubectl context: ${current_ctx}"
}

# ---------------------------------------------------------------------------
# Manifest & Fixture Generation (50 Applications × 10 Resources = 500)
# ---------------------------------------------------------------------------
# Generates:
#   <work_dir>/appproject.yaml (dedicated bench-scale AppProject CR)
#   <work_dir>/repo/apps/bench-app-XX/{serviceaccount,deployment,service,secret,configmaps}.yaml
#   <work_dir>/applications/bench-app-XX.yaml
generate_fixtures() {
  local work_dir="$1"
  local repo_url="$2"
  local app_count="$3"
  local resources_per_app="$4"

  local repo_dir="${work_dir}/repo"
  local apps_cr_dir="${work_dir}/applications"
  mkdir -p "${repo_dir}/apps" "${apps_cr_dir}"

  # Dedicated AppProject CR (matches ferriscd.io/v1alpha1 AppProjectSpec exactly)
  cat > "${work_dir}/appproject.yaml" <<EOF
apiVersion: ferriscd.io/v1alpha1
kind: AppProject
metadata:
  name: ${BENCHMARK_PROJECT_NAME}
  namespace: ${CONTROL_PLANE_NS}
  labels:
    app.kubernetes.io/part-of: ferriscd-scale-benchmark
    ${BENCHMARK_LABEL_KEY}: ${BENCHMARK_LABEL_VAL}
spec:
  description: "Dedicated FerrisCD v1.0 scale & soak benchmark project (T15.3)"
  sourceRepos:
    - "${repo_url}"
  sourceNamespaces:
    - "${CONTROL_PLANE_NS}"
  destinations:
    - cluster: in-cluster
      namespace: "ferriscd-bench-*"
  clusterResourceWhitelist: []
  namespaceResourceWhitelist:
    - group: ""
      kind: ServiceAccount
    - group: apps
      kind: Deployment
    - group: ""
      kind: Service
    - group: ""
      kind: Secret
    - group: ""
      kind: ConfigMap
  namespaceResourceBlacklist: []
  allowedServiceAccounts: []
EOF

  local cm_count=$((resources_per_app - 4))
  local i idx app_name dest_ns app_dir cm_idx cm_num

  for ((i = 1; i <= app_count; i++)); do
    idx="$(printf '%02d' "$i")"
    app_name="bench-app-${idx}"
    dest_ns="ferriscd-bench-${idx}"
    app_dir="${repo_dir}/apps/${app_name}"
    mkdir -p "$app_dir"

    # 1. ServiceAccount
    cat > "${app_dir}/01-serviceaccount.yaml" <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ${app_name}-sa
  namespace: ${dest_ns}
  labels:
    app.kubernetes.io/name: ${app_name}
    app.kubernetes.io/part-of: ferriscd-scale-benchmark
    ${BENCHMARK_LABEL_KEY}: ${BENCHMARK_LABEL_VAL}
EOF

    # 2. Deployment (lightweight pause container pre-cached in kind nodes)
    cat > "${app_dir}/02-deployment.yaml" <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${app_name}-app
  namespace: ${dest_ns}
  labels:
    app.kubernetes.io/name: ${app_name}
    app.kubernetes.io/part-of: ferriscd-scale-benchmark
    ${BENCHMARK_LABEL_KEY}: ${BENCHMARK_LABEL_VAL}
spec:
  replicas: ${DEPLOYMENT_REPLICAS}
  selector:
    matchLabels:
      app.kubernetes.io/name: ${app_name}
  template:
    metadata:
      labels:
        app.kubernetes.io/name: ${app_name}
        app.kubernetes.io/part-of: ferriscd-scale-benchmark
        ${BENCHMARK_LABEL_KEY}: ${BENCHMARK_LABEL_VAL}
    spec:
      serviceAccountName: ${app_name}-sa
      automountServiceAccountToken: false
      containers:
        - name: pause
          image: ${PAUSE_IMAGE}
          imagePullPolicy: IfNotPresent
          resources:
            requests:
              cpu: 1m
              memory: 4Mi
            limits:
              cpu: 20m
              memory: 16Mi
EOF

    # 3. Service (ClusterIP)
    cat > "${app_dir}/03-service.yaml" <<EOF
apiVersion: v1
kind: Service
metadata:
  name: ${app_name}-svc
  namespace: ${dest_ns}
  labels:
    app.kubernetes.io/name: ${app_name}
    app.kubernetes.io/part-of: ferriscd-scale-benchmark
    ${BENCHMARK_LABEL_KEY}: ${BENCHMARK_LABEL_VAL}
spec:
  type: ClusterIP
  selector:
    app.kubernetes.io/name: ${app_name}
  ports:
    - name: http
      port: 80
      targetPort: 8080
      protocol: TCP
EOF

    # 4. Secret (synthetic placeholder exercising Secret.stringData normalization & redaction)
    cat > "${app_dir}/04-secret.yaml" <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: ${app_name}-secret
  namespace: ${dest_ns}
  labels:
    app.kubernetes.io/name: ${app_name}
    app.kubernetes.io/part-of: ferriscd-scale-benchmark
    ${BENCHMARK_LABEL_KEY}: ${BENCHMARK_LABEL_VAL}
type: Opaque
stringData:
  BENCHMARK_SYNTHETIC_KEY: "benchmark-placeholder-${idx}"
EOF

    # 5..(4+cm_count). ConfigMaps (6 by default -> 10 total resources per app)
    if [[ "$cm_count" -gt 0 ]]; then
      : > "${app_dir}/05-configmaps.yaml"
      for ((cm_idx = 1; cm_idx <= cm_count; cm_idx++)); do
        cm_num="$(printf '%02d' "$cm_idx")"
        if [[ "$cm_idx" -gt 1 ]]; then
          printf '%s\n' '---' >> "${app_dir}/05-configmaps.yaml"
        fi
        cat >> "${app_dir}/05-configmaps.yaml" <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: ${app_name}-cm-${cm_num}
  namespace: ${dest_ns}
  labels:
    app.kubernetes.io/name: ${app_name}
    app.kubernetes.io/part-of: ferriscd-scale-benchmark
    ${BENCHMARK_LABEL_KEY}: ${BENCHMARK_LABEL_VAL}
data:
  APP_NAME: "${app_name}"
  SHARD_INDEX: "${idx}"
  CONFIG_SLICE: "${cm_num}"
  BENCHMARK_SUITE: "${BENCHMARK_LABEL_VAL}"
EOF
      done
    else
      rm -f "${app_dir}/05-configmaps.yaml"
    fi

    # Application CR (matches ferriscd.io/v1alpha1 ApplicationSpec exactly)
    cat > "${apps_cr_dir}/${app_name}.yaml" <<EOF
apiVersion: ferriscd.io/v1alpha1
kind: Application
metadata:
  name: ${app_name}
  namespace: ${CONTROL_PLANE_NS}
  labels:
    app.kubernetes.io/part-of: ferriscd-scale-benchmark
    ${BENCHMARK_LABEL_KEY}: ${BENCHMARK_LABEL_VAL}
spec:
  project: ${BENCHMARK_PROJECT_NAME}
  source:
    git:
      repoURL: "${repo_url}"
      targetRevision: "${TARGET_REVISION}"
      path: apps/${app_name}
    renderer:
      plainYaml:
        recursive: true
  destination:
    cluster: in-cluster
    namespace: ${dest_ns}
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      createNamespace: true
      pruneLast: true
      pruneCRDs: false
      pruneNamespaces: false
      serverSideForce: false
      applyOutOfSyncOnly: true
  requeueAfterSeconds: ${REQUEUE_SECONDS}
  revisionHistoryLimit: 10
EOF
  done
}

# Initialize a clean local Git repository fixture on branch TARGET_REVISION.
init_git_repo_fixture() {
  local repo_dir="$1"
  if ! command -v git >/dev/null 2>&1; then
    log_err "git is required to initialize the benchmark repository fixture."
    return 1
  fi
  if [[ ! -d "${repo_dir}/.git" ]]; then
    git -C "$repo_dir" init -q -b "$TARGET_REVISION"
  fi
  git -C "$repo_dir" config user.name "FerrisCD Benchmark"
  git -C "$repo_dir" config user.email "benchmark@ferriscd.local"
  git -C "$repo_dir" config commit.gpgsign false
  git -C "$repo_dir" add -A
  if ! git -C "$repo_dir" diff --cached --quiet; then
    git -C "$repo_dir" commit -q -m "seed scale benchmark fixture (${APP_COUNT} apps x ${RESOURCES_PER_APP} resources)"
  fi
}

# ---------------------------------------------------------------------------
# Offline YAML & Count Validation (Ruby YAML.load_stream)
# ---------------------------------------------------------------------------
validate_generated_fixtures() {
  local work_dir="$1"
  local expected_apps="$2"
  local expected_per_app="$3"
  local expected_resources=$((expected_apps * expected_per_app))

  if ! command -v ruby >/dev/null 2>&1; then
    log_err "ruby is required to validate YAML streams (YAML.load_stream)."
    return 1
  fi

  ruby -ryaml - "$work_dir" "$expected_apps" "$expected_per_app" "$expected_resources" "$CONTROL_PLANE_NS" "$BENCHMARK_PROJECT_NAME" "$BENCHMARK_LABEL_KEY" "$BENCHMARK_LABEL_VAL" <<'RUBY'
work_dir = ARGV[0]
expected_apps = ARGV[1].to_i
expected_per_app = ARGV[2].to_i
expected_resources = ARGV[3].to_i
control_plane_ns = ARGV[4]
project_name = ARGV[5]
bench_label_key = ARGV[6]
bench_label_val = ARGV[7]

project_file = File.join(work_dir, "appproject.yaml")
abort "Missing AppProject manifest: #{project_file}" unless File.exist?(project_file)
project_docs = YAML.load_stream(File.read(project_file)).compact
abort "#{project_file}: expected 1 document, got #{project_docs.length}" unless project_docs.length == 1
proj = project_docs.first
abort "#{project_file}: invalid apiVersion #{proj['apiVersion'].inspect}" unless proj['apiVersion'] == 'ferriscd.io/v1alpha1'
abort "#{project_file}: invalid kind #{proj['kind'].inspect}" unless proj['kind'] == 'AppProject'
abort "#{project_file}: expected metadata.name=#{project_name.inspect}, got #{proj.dig('metadata', 'name').inspect}" unless proj.dig('metadata', 'name') == project_name
abort "#{project_file}: expected metadata.namespace=#{control_plane_ns.inspect}, got #{proj.dig('metadata', 'namespace').inspect}" unless proj.dig('metadata', 'namespace') == control_plane_ns
abort "#{project_file}: missing benchmark label #{bench_label_key}=#{bench_label_val}" unless proj.dig('metadata', 'labels', bench_label_key) == bench_label_val

source_repos = proj.dig('spec', 'sourceRepos') || []
abort "#{project_file}: spec.sourceRepos must be non-empty" unless source_repos.is_a?(Array) && !source_repos.empty?
source_namespaces = proj.dig('spec', 'sourceNamespaces') || []
abort "#{project_file}: spec.sourceNamespaces must include #{control_plane_ns.inspect}" unless source_namespaces.include?(control_plane_ns)
destinations = proj.dig('spec', 'destinations') || []
has_bench_dest = destinations.any? { |d| d.is_a?(Hash) && d['cluster'] == 'in-cluster' && d['namespace'] == 'ferriscd-bench-*' }
abort "#{project_file}: spec.destinations must allow cluster=in-cluster, namespace=ferriscd-bench-*" unless has_bench_dest

expected_whitelist = [
  ['', 'ServiceAccount'],
  ['apps', 'Deployment'],
  ['', 'Service'],
  ['', 'Secret'],
  ['', 'ConfigMap']
]
whitelist = (proj.dig('spec', 'namespaceResourceWhitelist') || []).map { |e| [e['group'].to_s, e['kind'].to_s] }
expected_whitelist.each do |gk|
  abort "#{project_file}: spec.namespaceResourceWhitelist missing #{gk.inspect}" unless whitelist.include?(gk)
end

app_files = Dir.glob(File.join(work_dir, "applications", "*.yaml")).sort
workload_files = Dir.glob(File.join(work_dir, "repo", "apps", "*", "*.yaml")).sort

if app_files.empty?
  abort "No Application YAML files generated in #{work_dir}/applications"
end

app_names = {}
dest_namespaces = {}
app_docs = 0

app_files.each do |file|
  docs = YAML.load_stream(File.read(file)).compact
  abort "#{file}: expected 1 document, got #{docs.length}" unless docs.length == 1
  doc = docs.first
  abort "#{file}: invalid apiVersion #{doc['apiVersion'].inspect}" unless doc['apiVersion'] == 'ferriscd.io/v1alpha1'
  abort "#{file}: invalid kind #{doc['kind'].inspect}" unless doc['kind'] == 'Application'
  abort "#{file}: expected spec.project=#{project_name.inspect}, got #{doc.dig('spec', 'project').inspect}" unless doc.dig('spec', 'project') == project_name

  name = doc.dig('metadata', 'name')
  ns = doc.dig('spec', 'destination', 'namespace')
  repo_url = doc.dig('spec', 'source', 'git', 'repoURL')
  target_rev = doc.dig('spec', 'source', 'git', 'targetRevision')
  abort "#{file}: missing metadata.name" if name.nil? || name.empty?
  abort "#{file}: missing spec.destination.namespace" if ns.nil? || ns.empty?
  abort "#{file}: missing spec.source.git.repoURL" unless repo_url.is_a?(String) && !repo_url.empty?
  abort "#{file}: missing spec.source.git.targetRevision" unless target_rev.is_a?(String) && !target_rev.empty?
  abort "#{file}: spec.source.git.repoURL #{repo_url.inspect} not allowed by AppProject sourceRepos #{source_repos.inspect}" unless source_repos.include?('*') || source_repos.include?(repo_url)
  abort "#{file}: duplicate Application name #{name}" if app_names.key?(name)
  abort "#{file}: duplicate destination namespace #{ns}" if dest_namespaces.key?(ns)

  sync_opts = doc.dig('spec', 'syncPolicy', 'syncOptions') || {}
  abort "#{file}: serverSideForce must default to false" unless sync_opts['serverSideForce'] == false
  abort "#{file}: pruneCRDs must default to false" unless sync_opts['pruneCRDs'] == false
  abort "#{file}: pruneNamespaces must default to false" unless sync_opts['pruneNamespaces'] == false

  app_names[name] = true
  dest_namespaces[ns] = true
  app_docs += 1
end

resource_docs = 0
per_app_counts = Hash.new(0)
kind_counts = Hash.new(0)

workload_files.each do |file|
  app_dir_name = File.basename(File.dirname(file))
  docs = YAML.load_stream(File.read(file)).compact
  abort "#{file}: empty YAML stream" if docs.empty?
  docs.each do |doc|
    abort "#{file}: document is not a mapping" unless doc.is_a?(Hash)
    abort "#{file}: missing apiVersion" unless doc['apiVersion'].is_a?(String) && !doc['apiVersion'].empty?
    abort "#{file}: missing kind" unless doc['kind'].is_a?(String) && !doc['kind'].empty?
    abort "#{file}: missing metadata.name" unless doc.dig('metadata', 'name').is_a?(String)
    per_app_counts[app_dir_name] += 1
    kind_counts[doc['kind']] += 1
    resource_docs += 1
  end
end

abort "Application count mismatch: expected #{expected_apps}, got #{app_docs}" unless app_docs == expected_apps
abort "Distinct app name mismatch: expected #{expected_apps}, got #{app_names.size}" unless app_names.size == expected_apps
abort "Distinct destination namespace mismatch: expected #{expected_apps}, got #{dest_namespaces.size}" unless dest_namespaces.size == expected_apps
abort "Total workload resource count mismatch: expected #{expected_resources}, got #{resource_docs}" unless resource_docs == expected_resources

app_names.each_key do |name|
  cnt = per_app_counts[name]
  abort "App #{name}: expected #{expected_per_app} resources, got #{cnt}" unless cnt == expected_per_app
end

summary = kind_counts.sort.map { |k, v| "#{k}=#{v}" }.join(", ")
puts "Validated 1 AppProject (#{project_name}), #{app_docs} Applications (#{dest_namespaces.size} distinct namespaces), and #{resource_docs} workload resources across #{1 + app_files.length + workload_files.length} YAML files (#{summary})."
RUBY
}

# ---------------------------------------------------------------------------
# Prometheus Histogram Quantile Calculator (exact Prometheus linear interpolation)
# ---------------------------------------------------------------------------
# Extracts cumulative buckets for `<metric>_bucket` matching `label_filter`
# (independent of label ordering), optionally subtracting a baseline scrape,
# and outputs the interpolated quantile in seconds (6 decimal places) or "N/A".
extract_histogram_buckets() {
  local metrics_file="$1"
  local metric_name="$2"
  local label_filter="$3"

  awk -v bucket_metric="${metric_name}_bucket" -v filter="$label_filter" '
    /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
    {
      line = $0
      prefix = bucket_metric "{"
      if (index(line, prefix) != 1) next

      rest = substr(line, length(prefix) + 1)
      close_idx = index(rest, "}")
      if (close_idx == 0) next

      labels = substr(rest, 1, close_idx - 1)
      tail = substr(rest, close_idx + 1)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", tail)
      split(tail, parts, /[[:space:]]+/)
      val = parts[1] + 0.0

      wrapped = "," labels ","
      if (filter != "" && index(wrapped, "," filter ",") == 0) next

      le_pos = index(wrapped, ",le=\"")
      if (le_pos == 0) next
      after_le = substr(wrapped, le_pos + 5)
      quote_pos = index(after_le, "\"")
      if (quote_pos == 0) next
      le = substr(after_le, 1, quote_pos - 1)

      if (le == "+Inf") {
        printf "1|%s|%.12g\n", le, val
      } else {
        printf "0|%.12g|%.12g\n", le + 0.0, val
      }
    }
  ' "$metrics_file" | sort -t'|' -k1,1n -k2,2g
}

compute_histogram_quantile() {
  local metrics_file="$1"
  local metric_name="$2"
  local label_filter="$3"
  local quantile="$4"
  local baseline_file="${5:-}"

  local cur_buckets base_buckets
  cur_buckets="$(extract_histogram_buckets "$metrics_file" "$metric_name" "$label_filter")"
  if [[ -z "$cur_buckets" ]]; then
    printf 'N/A\n'
    return 0
  fi

  if [[ -n "$baseline_file" && -f "$baseline_file" ]]; then
    base_buckets="$(extract_histogram_buckets "$baseline_file" "$metric_name" "$label_filter")"
  else
    base_buckets=""
  fi

  {
    if [[ -n "$base_buckets" ]]; then
      printf '%s\n' "$base_buckets" | sed 's/^/BASE|/'
    fi
    printf '%s\n' "$cur_buckets" | sed 's/^/CUR|/'
  } | awk -F'|' -v q="$quantile" '
    BEGIN {
      n = 0
    }
    $1 == "BASE" {
      base_map[$2 "|" $3] = $4 + 0.0
      next
    }
    $1 == "CUR" {
      key = $2 "|" $3
      cur = $4 + 0.0
      base = (key in base_map) ? base_map[key] : 0.0
      delta = cur - base
      if (delta < 0) delta = 0.0
      n++
      is_inf[n] = $2 + 0
      le[n] = $3
      cnt[n] = delta
    }
    END {
      if (n == 0) {
        print "N/A"
        exit 0
      }
      total = cnt[n]
      if (total <= 0) {
        print "N/A"
        exit 0
      }
      if (q <= 0) {
        printf "%.6f\n", 0.0
        exit 0
      }
      rank = q * total
      prev_cnt = 0.0
      prev_bound = 0.0
      for (i = 1; i <= n; i++) {
        if (cnt[i] >= rank) {
          if (is_inf[i] == 1) {
            printf "%.6f\n", prev_bound
            exit 0
          }
          bound = le[i] + 0.0
          bucket_cnt = cnt[i] - prev_cnt
          if (bucket_cnt <= 0) {
            printf "%.6f\n", prev_bound
            exit 0
          }
          frac = (rank - prev_cnt) / bucket_cnt
          val = prev_bound + (bound - prev_bound) * frac
          printf "%.6f\n", val
          exit 0
        }
        prev_cnt = cnt[i]
        if (is_inf[i] == 0) {
          prev_bound = le[i] + 0.0
        }
      }
      printf "%.6f\n", prev_bound
    }
  '
}

# Read a counter or gauge sample matching exact metric name and optional label filter.
extract_scalar_metric() {
  local metrics_file="$1"
  local metric_name="$2"
  local label_filter="${3:-}"

  awk -v metric="$metric_name" -v filter="$label_filter" '
    /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
    {
      line = $0
      if (filter == "") {
        if (index(line, metric " ") == 1 || index(line, metric "\t") == 1) {
          split(line, parts, /[[:space:]]+/)
          print parts[2]
          found = 1
          exit 0
        }
      } else {
        prefix = metric "{"
        if (index(line, prefix) != 1) next
        rest = substr(line, length(prefix) + 1)
        close_idx = index(rest, "}")
        if (close_idx == 0) next
        labels = substr(rest, 1, close_idx - 1)
        wrapped = "," labels ","
        if (index(wrapped, "," filter ",") == 0) next
        tail = substr(rest, close_idx + 1)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", tail)
        split(tail, parts, /[[:space:]]+/)
        print parts[1]
        found = 1
        exit 0
      }
    }
    END {
      if (!found) print "0"
    }
  ' "$metrics_file"
}

# ---------------------------------------------------------------------------
# RSS Flatness & Open FD Stability Evaluator
# ---------------------------------------------------------------------------
# Reads a CSV file with header:
#   timestamp_epoch,elapsed_sec,rss_kb,fd_count
# Evaluates post-warmup samples (elapsed_sec >= warmup_sec) and prints
# key=value metrics. Returns 0 on PASS, 1 on FAIL.
evaluate_rss_flatness() {
  local csv_file="$1"
  local warmup_sec="$2"
  local max_rss_growth_pct="$3"
  local max_fd_growth="$4"
  local allow_missing_fd="${5:-0}"

  awk -F',' \
    -v warmup="$warmup_sec" \
    -v max_rss_pct="$max_rss_growth_pct" \
    -v max_fd_delta="$max_fd_growth" \
    -v allow_missing_fd="$allow_missing_fd" '
    NR == 1 { next }
    /^[[:space:]]*$/ { next }
    {
      t = $2 + 0.0
      rss = $3 + 0.0
      fd = $4 + 0
      if (rss <= 0) {
        invalid_rss = 1
      }
      all_n++
      all_t[all_n] = t
      all_rss[all_n] = rss
      all_fd[all_n] = fd
      if (t >= warmup) {
        n++
        xs[n] = t / 60.0
        ys[n] = rss
        fds[n] = fd
      }
    }
    END {
      if (invalid_rss) {
        print "status=FAIL"
        print "reason=invalid_rss_sample"
        exit 1
      }
      if (n < 2) {
        # Fallback when soak window is shorter than warmup: evaluate full series
        n = 0
        for (i = 1; i <= all_n; i++) {
          n++
          xs[n] = all_t[i] / 60.0
          ys[n] = all_rss[i]
          fds[n] = all_fd[i]
        }
      }
      if (n < 2) {
        print "status=FAIL"
        print "reason=insufficient_samples"
        exit 1
      }

      base_rss = ys[1]
      end_rss = ys[n]
      min_rss = ys[1]
      peak_rss = ys[1]
      base_fd = fds[1]
      end_fd = fds[n]
      peak_fd = fds[1]
      fd_valid = (base_fd >= 0 && end_fd >= 0 && peak_fd >= 0) ? 1 : 0

      sum_x = 0.0; sum_y = 0.0; sum_xx = 0.0; sum_xy = 0.0
      for (i = 1; i <= n; i++) {
        if (ys[i] <= 0) {
          print "status=FAIL"
          print "reason=invalid_rss_sample"
          exit 1
        }
        if (fds[i] < 0) fd_valid = 0
        if (ys[i] < min_rss) min_rss = ys[i]
        if (ys[i] > peak_rss) peak_rss = ys[i]
        if (fds[i] > peak_fd) peak_fd = fds[i]
        sum_x += xs[i]
        sum_y += ys[i]
        sum_xx += xs[i] * xs[i]
        sum_xy += xs[i] * ys[i]
      }
      if (base_fd < 0 || end_fd < 0 || peak_fd < 0) fd_valid = 0

      denom = n * sum_xx - sum_x * sum_x
      slope = (denom > 0) ? ((n * sum_xy - sum_x * sum_y) / denom) : 0.0

      end_growth_pct = ((end_rss - base_rss) / base_rss) * 100.0
      peak_growth_pct = ((peak_rss - base_rss) / base_rss) * 100.0

      rss_ok = (end_growth_pct <= max_rss_pct && peak_growth_pct <= max_rss_pct)
      if (fd_valid) {
        fd_delta = end_fd - base_fd
        fd_peak_delta = peak_fd - base_fd
        fd_ok = (fd_delta <= max_fd_delta && fd_peak_delta <= max_fd_delta)
      } else {
        fd_ok = (allow_missing_fd == 1) ? 1 : 0
      }

      printf "samples=%d\n", n
      printf "baseline_rss_kb=%.0f\n", base_rss
      printf "baseline_rss_mb=%.2f\n", base_rss / 1024.0
      printf "end_rss_kb=%.0f\n", end_rss
      printf "end_rss_mb=%.2f\n", end_rss / 1024.0
      printf "min_rss_kb=%.0f\n", min_rss
      printf "peak_rss_kb=%.0f\n", peak_rss
      printf "peak_rss_mb=%.2f\n", peak_rss / 1024.0
      printf "end_rss_growth_pct=%.2f\n", end_growth_pct
      printf "peak_rss_growth_pct=%.2f\n", peak_growth_pct
      printf "rss_slope_kb_per_min=%.2f\n", slope
      printf "fd_valid=%d\n", fd_valid
      printf "baseline_fd=%d\n", base_fd
      printf "end_fd=%d\n", end_fd
      printf "peak_fd=%d\n", peak_fd
      if (fd_valid) {
        printf "fd_delta=%d\n", fd_delta
        printf "fd_peak_delta=%d\n", fd_peak_delta
      } else {
        print "fd_delta=N/A"
        print "fd_peak_delta=N/A"
      }

      if (rss_ok && fd_ok) {
        print "status=PASS"
        exit 0
      } else {
        print "status=FAIL"
        if (!rss_ok) print "reason=rss_growth_exceeded"
        if (!fd_valid && allow_missing_fd != 1) {
          print "reason=missing_fd_telemetry"
        } else if (fd_valid && !fd_ok) {
          print "reason=fd_growth_exceeded"
        }
        exit 1
      }
    }
  ' "$csv_file"
}

# ---------------------------------------------------------------------------
# Process / Pod Telemetry Samplers (Live Mode)
# ---------------------------------------------------------------------------
discover_controller_pod() {
  kubectl get pods -n "$CONTROL_PLANE_NS" -l "$CONTROLLER_SELECTOR" \
    --field-selector=status.phase=Running \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true
}

sample_rss_and_fd() {
  local pod_name="$1"
  local rss_kb="-1"
  local fd_count="-1"

  if [[ -n "$CONTROLLER_PID" ]]; then
    if ! kill -0 "$CONTROLLER_PID" 2>/dev/null; then
      log_err "Controller process PID ${CONTROLLER_PID} exited unexpectedly!"
      return 1
    fi
    local raw_rss raw_fd fd_list lsof_out
    raw_rss="$(ps -o rss= -p "$CONTROLLER_PID" 2>/dev/null | tr -d '[:space:]' || true)"
    if [[ "$raw_rss" =~ ^[0-9]+$ ]] && [[ "$raw_rss" -gt 0 ]]; then
      rss_kb="$raw_rss"
    fi
    if [[ -r "/proc/${CONTROLLER_PID}/fd" ]]; then
      if fd_list="$(ls -1 "/proc/${CONTROLLER_PID}/fd" 2>/dev/null)"; then
        raw_fd="$(printf '%s\n' "$fd_list" | awk 'NF { c++ } END { print c + 0 }' || true)"
        if [[ "$raw_fd" =~ ^[0-9]+$ ]]; then
          fd_count="$raw_fd"
        fi
      fi
    elif command -v lsof >/dev/null 2>&1; then
      if lsof_out="$(lsof -n -P -p "$CONTROLLER_PID" 2>/dev/null)"; then
        raw_fd="$(printf '%s\n' "$lsof_out" | awk 'NR > 1 && $4 ~ /^[0-9]/ { c++ } END { print c + 0 }' || true)"
        if [[ "$raw_fd" =~ ^[0-9]+$ ]]; then
          fd_count="$raw_fd"
        fi
      fi
    fi
  elif [[ -n "$pod_name" ]]; then
    # Attempt to read /proc/1/status & /proc/1/fd inside pod; fallback gracefully on distroless.
    local stats raw_rss raw_fd
    stats="$(kubectl exec -n "$CONTROL_PLANE_NS" "$pod_name" -- \
      sh -c 'rss=$(awk "/^VmRSS:/ {print \$2}" /proc/1/status 2>/dev/null || true); [ -n "$rss" ] || rss=-1; if [ -r /proc/1/fd ] && fd_list=$(ls -1 /proc/1/fd 2>/dev/null); then fd=$(printf "%s\n" "$fd_list" | awk "NF { c++ } END { print c + 0 }"); else fd=-1; fi; echo "${rss},${fd}"' \
      2>/dev/null || true)"
    if [[ "$stats" =~ ^(-1|[0-9]+),(-1|[0-9]+)$ ]]; then
      raw_rss="${stats%%,*}"
      raw_fd="${stats##*,}"
      if [[ "$raw_rss" =~ ^[0-9]+$ ]] && [[ "$raw_rss" -gt 0 ]]; then
        rss_kb="$raw_rss"
      fi
      if [[ "$raw_fd" =~ ^[0-9]+$ ]]; then
        fd_count="$raw_fd"
      fi
    else
      # Fallback: kubectl top pod (Mi -> KiB)
      local mem_mi
      mem_mi="$(kubectl top pod -n "$CONTROL_PLANE_NS" "$pod_name" --no-headers 2>/dev/null | awk '{print $3}' | sed 's/Mi$//' || true)"
      if [[ "$mem_mi" =~ ^[0-9]+$ ]] && [[ "$mem_mi" -gt 0 ]]; then
        rss_kb=$((mem_mi * 1024))
      fi
    fi
  fi

  printf '%s,%s\n' "${rss_kb:--1}" "${fd_count:--1}"
}

get_pod_restart_count() {
  local pod_name="$1"
  if [[ -z "$pod_name" ]]; then
    return 1
  fi
  local restarts
  if ! restarts="$(kubectl get pod -n "$CONTROL_PLANE_NS" "$pod_name" \
    -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null)"; then
    return 1
  fi
  if [[ ! "$restarts" =~ ^[0-9]+$ ]]; then
    return 1
  fi
  printf '%s\n' "$restarts"
}

scrape_metrics() {
  local dest_file="$1"
  if ! command -v curl >/dev/null 2>&1; then
    log_err "curl is required to scrape ${METRICS_URL}."
    return 1
  fi
  curl -fsS --max-time 10 "$METRICS_URL" -o "$dest_file"
}

# ---------------------------------------------------------------------------
# Mode: --dry-run (Offline Validation)
# ---------------------------------------------------------------------------
make_temp_dir() {
  local prefix="$1"
  local tmp_base="${TMPDIR:-/tmp}"
  tmp_base="${tmp_base%/}"
  mktemp -d "${tmp_base}/${prefix}.XXXXXX"
}

run_dry_run() {
  local work_dir
  if [[ -n "$OUTPUT_DIR" ]]; then
    work_dir="$OUTPUT_DIR"
    mkdir -p "$work_dir"
  else
    work_dir="$(make_temp_dir "ferriscd-scale-dryrun")"
    CLEANUP_TEMP_DIRS+=("$work_dir")
  fi

  local repo_url="${REPO_URL:-file://${work_dir}/repo}"
  log_info "Dry-run mode: generating ${APP_COUNT} Applications x ${RESOURCES_PER_APP} resources ($((APP_COUNT * RESOURCES_PER_APP)) total) in ${work_dir}"

  generate_fixtures "$work_dir" "$repo_url" "$APP_COUNT" "$RESOURCES_PER_APP"
  init_git_repo_fixture "${work_dir}/repo"

  local validation_out
  validation_out="$(validate_generated_fixtures "$work_dir" "$APP_COUNT" "$RESOURCES_PER_APP")"
  log_pass "$validation_out"

  local commit_sha
  commit_sha="$(git -C "${work_dir}/repo" rev-parse HEAD)"
  log_pass "Initialized local Git fixture repo on branch '${TARGET_REVISION}' at commit ${commit_sha:0:12}."
  log_pass "Dry-run completed cleanly with zero cluster calls."
}

# ---------------------------------------------------------------------------
# Mode: --self-test (Offline Deterministic Unit Tests)
# ---------------------------------------------------------------------------
run_self_test() {
  local test_dir
  test_dir="$(make_temp_dir "ferriscd-scale-selftest")"
  CLEANUP_TEMP_DIRS+=("$test_dir")

  local passed=0
  local failed=0

  assert_eq() {
    local label="$1"
    local expected="$2"
    local actual="$3"
    if [[ "$expected" == "$actual" ]]; then
      log_pass "self-test: ${label} (got '${actual}')"
      passed=$((passed + 1))
    else
      log_err "self-test FAILED: ${label} — expected '${expected}', got '${actual}'"
      failed=$((failed + 1))
    fi
  }

  log_info "Running scale_harness.sh offline self-test suite..."

  # (a) Non-kind context rejection & kind-* acceptance
  local bad_ctx
  for bad_ctx in "prod-us-east-1" "minikube" "docker-desktop" "arn:aws:eks:us-east-1:123:cluster/prod" ""; do
    if validate_kind_context "$bad_ctx" 2>/dev/null; then
      log_err "self-test FAILED: non-kind context '${bad_ctx}' was unexpectedly accepted"
      failed=$((failed + 1))
    else
      log_pass "self-test: rejected non-kind context '${bad_ctx:-<empty>}'"
      passed=$((passed + 1))
    fi
  done

  local good_ctx
  for good_ctx in "kind-ferriscd" "kind-kind"; do
    if validate_kind_context "$good_ctx" 2>/dev/null; then
      log_pass "self-test: accepted kind context '${good_ctx}'"
      passed=$((passed + 1))
    else
      log_err "self-test FAILED: valid kind context '${good_ctx}' was rejected"
      failed=$((failed + 1))
    fi
  done

  # End-to-end check: mock kubectl returning a non-kind context must abort before any cluster call.
  mkdir -p "${test_dir}/mockbin"
  cat > "${test_dir}/mockbin/kubectl" <<'MOCK'
#!/usr/bin/env bash
if [[ "$*" == "config current-context" ]]; then
  echo "gke_prod_us-central1_cluster"
  exit 0
fi
echo "UNEXPECTED KUBECTL CALL: $*" >&2
exit 99
MOCK
  chmod +x "${test_dir}/mockbin/kubectl"
  local guard_rc=0
  PATH="${test_dir}/mockbin:${PATH}" require_kind_context >/dev/null 2>&1 || guard_rc=$?
  assert_eq "require_kind_context rejects mocked non-kind kubectl context" "1" "$guard_rc"

  # (b) Manifest generation produces exact 50 Applications, 1 AppProject, and 500 workload resources
  local gen_dir="${test_dir}/fixtures"
  generate_fixtures "$gen_dir" "file://${gen_dir}/repo" 50 10
  if validate_generated_fixtures "$gen_dir" 50 10 >/dev/null; then
    log_pass "self-test: generated 1 AppProject, 50 Applications, and 500 workload resources (all YAML valid via Ruby YAML.load_stream)"
    passed=$((passed + 1))
  else
    log_err "self-test FAILED: fixture manifest validation failed"
    failed=$((failed + 1))
  fi

  # (b2) --resources-per-app 4 (cm_count=0) omits empty 05-configmaps.yaml and validates cleanly
  local gen_min_dir="${test_dir}/fixtures_min"
  generate_fixtures "$gen_min_dir" "file://${gen_min_dir}/repo" 2 4
  if validate_generated_fixtures "$gen_min_dir" 2 4 >/dev/null && [[ ! -e "${gen_min_dir}/repo/apps/bench-app-01/05-configmaps.yaml" ]]; then
    log_pass "self-test: --resources-per-app 4 omits empty 05-configmaps.yaml and passes YAML validation"
    passed=$((passed + 1))
  else
    log_err "self-test FAILED: --resources-per-app 4 check failed"
    failed=$((failed + 1))
  fi

  # (b3) Re-running init_git_repo_fixture on an existing output directory is idempotent
  init_git_repo_fixture "${gen_min_dir}/repo"
  generate_fixtures "$gen_min_dir" "file://${gen_min_dir}/repo" 2 4
  if init_git_repo_fixture "${gen_min_dir}/repo"; then
    log_pass "self-test: init_git_repo_fixture is idempotent on existing directory"
    passed=$((passed + 1))
  else
    log_err "self-test FAILED: second init_git_repo_fixture run failed"
    failed=$((failed + 1))
  fi

  # (c) Prometheus histogram quantile calculator (direct, reversed label order, and delta)
  cat > "${test_dir}/metrics_base.prom" <<'PROM'
# HELP ferriscd_reconcile_duration_seconds Wall-clock duration of one Application reconcile, by result
# TYPE ferriscd_reconcile_duration_seconds histogram
ferriscd_reconcile_duration_seconds_bucket{result="success",le="0.005"} 0
ferriscd_reconcile_duration_seconds_bucket{result="success",le="0.01"} 5
ferriscd_reconcile_duration_seconds_bucket{result="success",le="0.02"} 20
ferriscd_reconcile_duration_seconds_bucket{result="success",le="0.04"} 40
ferriscd_reconcile_duration_seconds_bucket{result="success",le="0.08"} 48
ferriscd_reconcile_duration_seconds_bucket{result="success",le="0.16"} 50
ferriscd_reconcile_duration_seconds_bucket{result="success",le="+Inf"} 50
ferriscd_reconcile_duration_seconds_bucket{result="retryable",le="0.005"} 0
ferriscd_reconcile_duration_seconds_bucket{result="retryable",le="+Inf"} 2
PROM

  # Reversed label order (`le` before `result`) + steady-state delta of exactly 100 samples:
  # delta buckets: 0.005->0, 0.01->10, 0.02->50, 0.04->90, 0.08->98, 0.16->100, +Inf->100
  # Expected delta p50 = 0.020000s, delta p95 = 0.04 + 0.04*(5/8) = 0.065000s
  cat > "${test_dir}/metrics_end.prom" <<'PROM'
# TYPE ferriscd_reconcile_duration_seconds histogram
ferriscd_reconcile_duration_seconds_bucket{le="0.005",result="success"} 0
ferriscd_reconcile_duration_seconds_bucket{le="0.01",result="success"} 15
ferriscd_reconcile_duration_seconds_bucket{le="0.02",result="success"} 70
ferriscd_reconcile_duration_seconds_bucket{le="0.04",result="success"} 130
ferriscd_reconcile_duration_seconds_bucket{le="0.08",result="success"} 146
ferriscd_reconcile_duration_seconds_bucket{le="0.16",result="success"} 150
ferriscd_reconcile_duration_seconds_bucket{le="+Inf",result="success"} 150
ferriscd_reconcile_duration_seconds_bucket{le="0.005",result="retryable"} 0
ferriscd_reconcile_duration_seconds_bucket{le="+Inf",result="retryable"} 2
ferriscd_render_cache_total{outcome="hit"} 2950
ferriscd_render_cache_total{outcome="miss"} 50
PROM

  local p50 p95 hits
  p50="$(compute_histogram_quantile "${test_dir}/metrics_end.prom" "ferriscd_reconcile_duration_seconds" 'result="success"' "0.50" "${test_dir}/metrics_base.prom")"
  p95="$(compute_histogram_quantile "${test_dir}/metrics_end.prom" "ferriscd_reconcile_duration_seconds" 'result="success"' "0.95" "${test_dir}/metrics_base.prom")"
  hits="$(extract_scalar_metric "${test_dir}/metrics_end.prom" "ferriscd_render_cache_total" 'outcome="hit"')"

  assert_eq "histogram steady-state delta p50" "0.020000" "$p50"
  assert_eq "histogram steady-state delta p95" "0.065000" "$p95"
  assert_eq "scalar metric render_cache_total hit" "2950" "$hits"

  # Zero-delta guard must return N/A (not divide by zero)
  local zero_p50
  zero_p50="$(compute_histogram_quantile "${test_dir}/metrics_base.prom" "ferriscd_reconcile_duration_seconds" 'result="success"' "0.50" "${test_dir}/metrics_base.prom")"
  assert_eq "histogram zero-delta returns N/A" "N/A" "$zero_p50"

  # (d) RSS flatness & FD stability checker: flat series MUST PASS, leaking series MUST FAIL
  cat > "${test_dir}/rss_flat.csv" <<'CSV'
timestamp_epoch,elapsed_sec,rss_kb,fd_count
1700000000,0,22000,30
1700000180,180,38000,44
1700000300,300,40000,46
1700000600,600,40400,47
1700000900,900,40200,46
1700001200,1200,40600,48
1700001500,1500,40500,47
1700001800,1800,40800,47
CSV

  cat > "${test_dir}/rss_leak.csv" <<'CSV'
timestamp_epoch,elapsed_sec,rss_kb,fd_count
1700000000,0,22000,30
1700000300,300,40000,46
1700000600,600,44000,50
1700000900,900,48500,56
1700001200,1200,53000,62
1700001500,1500,58000,70
1700001800,1800,64000,82
CSV

  cat > "${test_dir}/fd_leak.csv" <<'CSV'
timestamp_epoch,elapsed_sec,rss_kb,fd_count
1700000300,300,40000,46
1700000600,600,40100,55
1700000900,900,40200,68
1700001200,1200,40150,80
CSV

  cat > "${test_dir}/fd_peak_spike.csv" <<'CSV'
timestamp_epoch,elapsed_sec,rss_kb,fd_count
1700000300,300,40000,46
1700000600,600,40100,80
1700000900,900,40200,48
1700001200,1200,40150,47
CSV

  cat > "${test_dir}/fd_missing.csv" <<'CSV'
timestamp_epoch,elapsed_sec,rss_kb,fd_count
1700000300,300,40000,-1
1700000600,600,40100,-1
1700000900,900,40200,-1
1700001200,1200,40150,-1
CSV

  cat > "${test_dir}/rss_invalid.csv" <<'CSV'
timestamp_epoch,elapsed_sec,rss_kb,fd_count
1700000300,300,40000,46
1700000600,600,-1,46
1700000900,900,40200,47
1700001200,1200,40150,47
CSV

  local flat_out leak_rc fd_leak_rc fd_peak_rc fd_missing_rc fd_missing_allow_rc rss_invalid_rc
  if flat_out="$(evaluate_rss_flatness "${test_dir}/rss_flat.csv" 300 10.0 16)"; then
    log_pass "self-test: flat RSS/FD series passed ($(printf '%s' "$flat_out" | tr '\n' ' '))"
    passed=$((passed + 1))
  else
    log_err "self-test FAILED: flat RSS/FD series unexpectedly failed"
    failed=$((failed + 1))
  fi

  leak_rc=0
  evaluate_rss_flatness "${test_dir}/rss_leak.csv" 300 10.0 16 >/dev/null || leak_rc=$?
  assert_eq "leaking RSS series rejected (exit 1)" "1" "$leak_rc"

  fd_leak_rc=0
  evaluate_rss_flatness "${test_dir}/fd_leak.csv" 300 10.0 16 >/dev/null || fd_leak_rc=$?
  assert_eq "leaking FD series rejected (exit 1)" "1" "$fd_leak_rc"

  fd_peak_rc=0
  evaluate_rss_flatness "${test_dir}/fd_peak_spike.csv" 300 10.0 16 >/dev/null || fd_peak_rc=$?
  assert_eq "fd_peak_delta breach rejected (exit 1)" "1" "$fd_peak_rc"

  fd_missing_rc=0
  evaluate_rss_flatness "${test_dir}/fd_missing.csv" 300 10.0 16 >/dev/null || fd_missing_rc=$?
  assert_eq "-1 FD series rejected by default (exit 1)" "1" "$fd_missing_rc"

  fd_missing_allow_rc=0
  evaluate_rss_flatness "${test_dir}/fd_missing.csv" 300 10.0 16 1 >/dev/null || fd_missing_allow_rc=$?
  assert_eq "-1 FD series accepted with --allow-missing-fd (exit 0)" "0" "$fd_missing_allow_rc"

  rss_invalid_rc=0
  evaluate_rss_flatness "${test_dir}/rss_invalid.csv" 300 10.0 16 >/dev/null || rss_invalid_rc=$?
  assert_eq "-1 RSS sample rejected (exit 1)" "1" "$rss_invalid_rc"

  # (e) Missing controller pod must fail get_pod_restart_count (never silently report 0)
  local missing_pod_rc=0
  PATH="${test_dir}/mockbin:${PATH}" get_pod_restart_count "ferriscd-controller-gone" >/dev/null 2>&1 || missing_pod_rc=$?
  assert_eq "get_pod_restart_count fails when pod is missing (exit 1)" "1" "$missing_pod_rc"

  # (f) Summary flatness header uses `printf --` so leading `---` never triggers invalid option
  local hdr_out hdr_rc=0
  hdr_out="$(printf -- '--- RSS & FD Flatness Report ---\n%s\n' "status=PASS" 2>&1)" || hdr_rc=$?
  assert_eq "printf -- handles leading dashes in flatness header (exit 0)" "0" "$hdr_rc"
  if [[ "$hdr_out" == *"--- RSS & FD Flatness Report ---"* ]]; then
    log_pass "self-test: flatness summary header renders cleanly"
    passed=$((passed + 1))
  else
    log_err "self-test FAILED: unexpected flatness summary header output: ${hdr_out}"
    failed=$((failed + 1))
  fi

  log_info "Self-test summary: ${passed} passed, ${failed} failed."
  if [[ "$failed" -ne 0 ]]; then
    return 1
  fi
}

# ---------------------------------------------------------------------------
# Mode: --cleanup (Safe Teardown on kind)
# ---------------------------------------------------------------------------
run_cleanup() {
  require_kind_context

  log_info "Deleting benchmark Application CRs in namespace '${CONTROL_PLANE_NS}' (selector: ${BENCHMARK_LABEL_KEY}=${BENCHMARK_LABEL_VAL})..."
  kubectl delete applications.ferriscd.io \
    -n "$CONTROL_PLANE_NS" \
    -l "${BENCHMARK_LABEL_KEY}=${BENCHMARK_LABEL_VAL}" \
    --ignore-not-found=true \
    --wait=true \
    --timeout=180s

  log_info "Deleting benchmark AppProject CRs in namespace '${CONTROL_PLANE_NS}' (selector: ${BENCHMARK_LABEL_KEY}=${BENCHMARK_LABEL_VAL})..."
  kubectl delete appprojects.ferriscd.io \
    -n "$CONTROL_PLANE_NS" \
    -l "${BENCHMARK_LABEL_KEY}=${BENCHMARK_LABEL_VAL}" \
    --ignore-not-found=true \
    --wait=true \
    --timeout=60s

  log_info "Deleting benchmark destination namespaces (selector: ${BENCHMARK_LABEL_KEY}=${BENCHMARK_LABEL_VAL})..."
  kubectl delete namespaces \
    -l "${BENCHMARK_LABEL_KEY}=${BENCHMARK_LABEL_VAL}" \
    --ignore-not-found=true \
    --wait=true \
    --timeout=180s

  # Also clean up any numbered namespaces created by createNamespace:true (which lack benchmark labels).
  local i idx ns
  local to_delete=()
  for ((i = 1; i <= APP_COUNT; i++)); do
    idx="$(printf '%02d' "$i")"
    ns="ferriscd-bench-${idx}"
    if kubectl get namespace "$ns" >/dev/null 2>&1; then
      to_delete+=("$ns")
    fi
  done
  if [[ "${#to_delete[@]}" -gt 0 ]]; then
    log_info "Deleting ${#to_delete[@]} auto-created destination namespace(s)..."
    kubectl delete namespace "${to_delete[@]}" --ignore-not-found=true --wait=true --timeout=180s
  fi

  log_pass "Benchmark cleanup complete."
}

# ---------------------------------------------------------------------------
# Mode: live benchmark & soak against kind-*
# ---------------------------------------------------------------------------
wait_for_convergence() {
  local expected_apps="$1"
  local timeout_secs="$2"
  local start_epoch now elapsed synced_healthy

  start_epoch="$(date +%s)"
  while true; do
    synced_healthy="$(kubectl get applications.ferriscd.io \
      -n "$CONTROL_PLANE_NS" \
      -l "${BENCHMARK_LABEL_KEY}=${BENCHMARK_LABEL_VAL}" \
      -o jsonpath='{range .items[*]}{.status.sync.status}{":"}{.status.health.status}{"\n"}{end}' \
      2>/dev/null | awk '$0 == "Synced:Healthy" { c++ } END { print c + 0 }')"

    now="$(date +%s)"
    elapsed=$((now - start_epoch))

    if [[ "$synced_healthy" -ge "$expected_apps" ]]; then
      printf '%d\n' "$elapsed"
      return 0
    fi

    if [[ "$elapsed" -ge "$timeout_secs" ]]; then
      log_err "Cold convergence timed out after ${elapsed}s (${synced_healthy}/${expected_apps} Synced+Healthy)."
      return 1
    fi

    log_info "Convergence progress: ${synced_healthy}/${expected_apps} Synced+Healthy (${elapsed}s elapsed)..." >&2
    sleep 2
  done
}

run_live_benchmark() {
  require_kind_context

  # Verify control-plane namespace and both CRDs exist before deploying.
  local crd
  for crd in applications.ferriscd.io appprojects.ferriscd.io; do
    if ! kubectl get crd "$crd" >/dev/null 2>&1; then
      log_err "CRD ${crd} is not installed on this kind cluster. Run 'kubectl apply -f deploy/crds/' first."
      return 1
    fi
  done
  if ! kubectl get namespace "$CONTROL_PLANE_NS" >/dev/null 2>&1; then
    log_err "Control-plane namespace '${CONTROL_PLANE_NS}' does not exist."
    return 1
  fi

  local work_dir
  if [[ -n "$OUTPUT_DIR" ]]; then
    work_dir="$OUTPUT_DIR"
    mkdir -p "$work_dir"
  else
    work_dir="$(make_temp_dir "ferriscd-scale-live")"
    CLEANUP_TEMP_DIRS+=("$work_dir")
  fi

  local out_results
  if [[ -n "$RESULTS_DIR" ]]; then
    out_results="$RESULTS_DIR"
    mkdir -p "$out_results"
  else
    # Persist live results outside CLEANUP_TEMP_DIRS so artifacts remain after exit.
    out_results="$(make_temp_dir "ferriscd-scale-results")"
  fi

  local repo_url="${REPO_URL:-file://${work_dir}/repo}"
  log_info "Generating AppProject '${BENCHMARK_PROJECT_NAME}' + ${APP_COUNT} Applications x ${RESOURCES_PER_APP} resources ($((APP_COUNT * RESOURCES_PER_APP)) total)..."
  generate_fixtures "$work_dir" "$repo_url" "$APP_COUNT" "$RESOURCES_PER_APP"
  init_git_repo_fixture "${work_dir}/repo"
  validate_generated_fixtures "$work_dir" "$APP_COUNT" "$RESOURCES_PER_APP"

  local pod_name=""
  local initial_restarts=0
  if [[ -z "$CONTROLLER_PID" ]]; then
    pod_name="$(discover_controller_pod)"
    if [[ -z "$pod_name" ]]; then
      log_warn "No controller pod found via selector '${CONTROLLER_SELECTOR}' in '${CONTROL_PLANE_NS}', and --controller-pid not provided; RSS/FD sampling will report -1."
    else
      if ! initial_restarts="$(get_pod_restart_count "$pod_name")"; then
        log_err "Failed to read initial restartCount for controller pod '${CONTROL_PLANE_NS}/${pod_name}'."
        return 1
      fi
      log_info "Monitoring controller pod: ${CONTROL_PLANE_NS}/${pod_name} (initial restarts: ${initial_restarts})"
    fi
  else
    log_info "Monitoring local controller process PID: ${CONTROLLER_PID}"
  fi

  # Verify /metrics is reachable before deploying load.
  scrape_metrics "${out_results}/metrics_pre.prom"
  log_info "Scraped pre-benchmark metrics from ${METRICS_URL}."

  # Apply benchmark AppProject before Application CRs so AppProjectPolicy permits every app.
  log_info "Applying benchmark AppProject '${BENCHMARK_PROJECT_NAME}' to namespace '${CONTROL_PLANE_NS}'..."
  kubectl apply -f "${work_dir}/appproject.yaml" >/dev/null

  # Deploy all Applications and measure cold convergence.
  log_info "Applying ${APP_COUNT} Application CRs to namespace '${CONTROL_PLANE_NS}'..."
  kubectl apply -f "${work_dir}/applications" >/dev/null

  local convergence_secs
  convergence_secs="$(wait_for_convergence "$APP_COUNT" "$CONVERGENCE_TIMEOUT_SECS")"
  log_pass "Cold convergence reached (${APP_COUNT}/${APP_COUNT} Synced+Healthy) in ${convergence_secs}s."

  # Baseline metrics immediately after cold convergence -> isolates steady-state latency.
  scrape_metrics "${out_results}/metrics_post_converge.prom"

  # Steady-state soak loop sampling RSS and open FDs.
  local soak_secs=$((SOAK_MINUTES * 60))
  local warmup_secs=$((WARMUP_MINUTES * 60))
  if [[ "$warmup_secs" -ge "$soak_secs" ]]; then
    warmup_secs=$((soak_secs / 3))
  fi

  local csv_file="${out_results}/soak_samples.csv"
  printf 'timestamp_epoch,elapsed_sec,rss_kb,fd_count\n' > "$csv_file"

  log_info "Starting ${SOAK_MINUTES}-minute soak (${soak_secs}s total, ${warmup_secs}s warm-up, ${SAMPLE_INTERVAL_SECS}s sampling interval)..."
  local soak_start now elapsed sample_pair
  soak_start="$(date +%s)"

  while true; do
    now="$(date +%s)"
    elapsed=$((now - soak_start))
    sample_pair="$(sample_rss_and_fd "$pod_name")"
    printf '%d,%d,%s\n' "$now" "$elapsed" "$sample_pair" >> "$csv_file"
    log_info "Soak sample t=${elapsed}s/${soak_secs}s rss_kb=${sample_pair%%,*} fd=${sample_pair##*,}"

    if [[ "$elapsed" -ge "$soak_secs" ]]; then
      break
    fi

    local remaining=$((soak_secs - elapsed))
    local sleep_for="$SAMPLE_INTERVAL_SECS"
    if [[ "$remaining" -lt "$sleep_for" ]]; then
      sleep_for="$remaining"
    fi
    sleep "$sleep_for"
  done

  # Final metrics scrape.
  scrape_metrics "${out_results}/metrics_final.prom"

  # Compute steady-state metrics (delta from post-convergence to end of soak).
  local steady_p50 steady_p95 git_p50 git_p95
  steady_p50="$(compute_histogram_quantile "${out_results}/metrics_final.prom" "ferriscd_reconcile_duration_seconds" 'result="success"' "0.50" "${out_results}/metrics_post_converge.prom")"
  steady_p95="$(compute_histogram_quantile "${out_results}/metrics_final.prom" "ferriscd_reconcile_duration_seconds" 'result="success"' "0.95" "${out_results}/metrics_post_converge.prom")"
  git_p50="$(compute_histogram_quantile "${out_results}/metrics_final.prom" "ferriscd_git_fetch_duration_seconds" "" "0.50" "${out_results}/metrics_post_converge.prom")"
  git_p95="$(compute_histogram_quantile "${out_results}/metrics_final.prom" "ferriscd_git_fetch_duration_seconds" "" "0.95" "${out_results}/metrics_post_converge.prom")"

  local rec_ok_end rec_ok_base rec_retry_end rec_retry_base rec_term_end rec_term_base
  rec_ok_end="$(extract_scalar_metric "${out_results}/metrics_final.prom" "ferriscd_reconcile_total" 'result="success"')"
  rec_ok_base="$(extract_scalar_metric "${out_results}/metrics_post_converge.prom" "ferriscd_reconcile_total" 'result="success"')"
  rec_retry_end="$(extract_scalar_metric "${out_results}/metrics_final.prom" "ferriscd_reconcile_total" 'result="retryable"')"
  rec_retry_base="$(extract_scalar_metric "${out_results}/metrics_post_converge.prom" "ferriscd_reconcile_total" 'result="retryable"')"
  rec_term_end="$(extract_scalar_metric "${out_results}/metrics_final.prom" "ferriscd_reconcile_total" 'result="terminal"')"
  rec_term_base="$(extract_scalar_metric "${out_results}/metrics_post_converge.prom" "ferriscd_reconcile_total" 'result="terminal"')"

  local cache_hit_end cache_hit_base cache_miss_end cache_miss_base
  cache_hit_end="$(extract_scalar_metric "${out_results}/metrics_final.prom" "ferriscd_render_cache_total" 'outcome="hit"')"
  cache_hit_base="$(extract_scalar_metric "${out_results}/metrics_post_converge.prom" "ferriscd_render_cache_total" 'outcome="hit"')"
  cache_miss_end="$(extract_scalar_metric "${out_results}/metrics_final.prom" "ferriscd_render_cache_total" 'outcome="miss"')"
  cache_miss_base="$(extract_scalar_metric "${out_results}/metrics_post_converge.prom" "ferriscd_render_cache_total" 'outcome="miss"')"

  local hit_rate
  hit_rate="$(awk -v h1="$cache_hit_end" -v h0="$cache_hit_base" -v m1="$cache_miss_end" -v m0="$cache_miss_base" '
    BEGIN {
      dh = h1 - h0; dm = m1 - m0; tot = dh + dm
      if (tot <= 0) { print "N/A" } else { printf "%.2f%%", (dh / tot) * 100.0 }
    }
  ')"

  # Check controller restarts & panics.
  local final_restarts=0
  local restart_delta=0
  local panic_lines=0
  local pod_missing=0
  local controller_status_line=""
  if [[ -n "$CONTROLLER_PID" ]]; then
    controller_status_line="0 (panics=N/A (local PID mode))"
  elif [[ -n "$pod_name" ]]; then
    if final_restarts="$(get_pod_restart_count "$pod_name")"; then
      restart_delta=$((final_restarts - initial_restarts))
      local pod_logs
      if pod_logs="$(kubectl logs -n "$CONTROL_PLANE_NS" "$pod_name" --since="$((SOAK_MINUTES + 15))m" 2>/dev/null)"; then
        panic_lines="$(printf '%s\n' "$pod_logs" | grep -ciE 'panicked at|fatal runtime error' || true)"
        controller_status_line="${restart_delta} (panics in logs: ${panic_lines})"
      else
        pod_missing=1
        log_err "Failed to fetch logs from monitored controller pod '${CONTROL_PLANE_NS}/${pod_name}'."
        controller_status_line="${restart_delta} (panics: FAILED TO READ POD LOGS)"
      fi
    else
      pod_missing=1
      log_err "Monitored controller pod '${CONTROL_PLANE_NS}/${pod_name}' disappeared during soak!"
      controller_status_line="MISSING POD (pod '${CONTROL_PLANE_NS}/${pod_name}' disappeared)"
    fi
  else
    controller_status_line="N/A (no controller PID or pod monitored)"
  fi

  # Evaluate RSS flatness and FD stability.
  local flatness_report flatness_rc=0
  flatness_report="$(evaluate_rss_flatness "$csv_file" "$warmup_secs" "$MAX_RSS_GROWTH_PCT" "$MAX_FD_GROWTH" "$ALLOW_MISSING_FD")" || flatness_rc=$?

  local rec_ok_delta rec_retry_delta rec_term_delta
  rec_ok_delta="$(awk -v a="$rec_ok_end" -v b="$rec_ok_base" 'BEGIN { d = a - b; printf "%.0f", (d < 0 ? 0 : d) }')"
  rec_retry_delta="$(awk -v a="$rec_retry_end" -v b="$rec_retry_base" 'BEGIN { d = a - b; printf "%.0f", (d < 0 ? 0 : d) }')"
  rec_term_delta="$(awk -v a="$rec_term_end" -v b="$rec_term_base" 'BEGIN { d = a - b; printf "%.0f", (d < 0 ? 0 : d) }')"

  printf '\n================ FerrisCD Scale & Soak Summary ================\n'
  printf 'Scale:                  %d Applications / %d Kubernetes resources\n' "$APP_COUNT" "$((APP_COUNT * RESOURCES_PER_APP))"
  printf 'Cold convergence:       %ds\n' "$convergence_secs"
  printf 'Steady-state p50:       %s s\n' "$steady_p50"
  printf 'Steady-state p95:       %s s\n' "$steady_p95"
  printf 'Git fetch p50 / p95:    %s s / %s s\n' "$git_p50" "$git_p95"
  printf 'Reconciles (soak delta): success=%s retryable=%s terminal=%s\n' \
    "$rec_ok_delta" "$rec_retry_delta" "$rec_term_delta"
  printf 'RenderCache hit rate:   %s (steady-state soak window)\n' "$hit_rate"
  printf 'Controller restarts:    %s\n' "$controller_status_line"
  printf -- '--- RSS & FD Flatness Report ---\n%s\n' "$flatness_report"
  printf 'Artifacts saved under:  %s\n' "$out_results"
  printf '===============================================================\n'

  if [[ "$flatness_rc" -ne 0 || "$pod_missing" -ne 0 || "$restart_delta" -ne 0 || "$panic_lines" -ne 0 ]]; then
    log_err "Soak benchmark FAILED stability checks (flatness_rc=${flatness_rc}, pod_missing=${pod_missing}, restarts=${restart_delta}, panics=${panic_lines})."
    return 1
  fi
  log_pass "Soak benchmark PASSED all convergence, RSS flatness, FD stability, and zero-panic checks."
}

# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
main() {
  parse_args "$@"
  case "$MODE" in
    dry-run)
      run_dry_run
      ;;
    self-test)
      run_self_test
      ;;
    cleanup)
      run_cleanup
      ;;
    live)
      run_live_benchmark
      ;;
    *)
      log_err "Unsupported mode: ${MODE}"
      exit 2
      ;;
  esac
}

# `T20.5`: the 250-app / 3-shard harness (`benchmarks/scale_250_sharded.sh`) **sources** this file to
# reuse the `kind` safety guard, the manifest generator/validator, the Prometheus histogram-quantile
# math and the RSS/FD flatness evaluator instead of forking them. Sourcing must therefore define the
# helpers without running the CLI: this guard is the only change the sharded harness needed here, and
# `bash benchmarks/scale_harness.sh ...` keeps behaving exactly as before (the `--self-test` case
# below still proves the whole v1.0 path).
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
