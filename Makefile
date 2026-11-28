.PHONY: fmt fmt-check lint test gate gate-fast kind-up kind-down test-integration test-integration-twice

KIND_CLUSTER_NAME := ferriscd-dev
KIND_CONTEXT := kind-$(KIND_CLUSTER_NAME)

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

lint:
	cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings

test:
	cargo test --workspace

# Single pre-review gate: mirrors the CI workflow exactly.
# The `crd generate --check` step is the deterministic CRD drift check (finding M-10):
# regenerating the committed manifests must be a no-op.
# The `opa-policy` lines (findings M4, H3) compile and test the optional embedded Rego engine
# (`ferriscd-engine/opa-policy` -> `regorus`, and the controller wiring on top of it). It is
# default-off, so a feature build is the only way CI sees that code — and a policy engine that is
# never compiled in CI is a policy engine nobody has audited. The `ferriscd-cli` check is what keeps
# the feature reachable from the shipped binary (the image's `FERRISCD_FEATURES` build arg).
gate:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings
	K8S_OPENAPI_ENABLED_VERSION=1.35 cargo clippy -p ferriscd-engine --features test-utils,opa-policy --all-targets -- -D warnings
	K8S_OPENAPI_ENABLED_VERSION=1.35 cargo clippy -p ferriscd-controller --features opa-policy --all-targets -- -D warnings
	cargo run -q -p ferriscd-cli -- crd generate --check
	cargo test --workspace
	K8S_OPENAPI_ENABLED_VERSION=1.35 cargo test -p ferriscd-engine --features opa-policy
	cargo test -p ferriscd-controller --features opa-policy
	cargo check -p ferriscd-cli --features opa-policy

# Fast inner-loop check: formatting + lints only (no test run).
gate-fast:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings

kind-up:
	@if ! kind get clusters | grep -qx '$(KIND_CLUSTER_NAME)'; then \
		kind create cluster --config deploy/kind-config.yaml; \
	else \
		echo "kind cluster '$(KIND_CLUSTER_NAME)' already exists"; \
	fi
	kubectl config use-context $(KIND_CONTEXT)

kind-down:
	kind delete cluster --name $(KIND_CLUSTER_NAME)

test-integration:
	kubectl config current-context | grep -q '^kind-' || { echo "ABORT: non-kind context!"; exit 1; }
	cargo test --workspace -- --ignored

# The `T10.6` trap guard: the live suite must pass TWICE back-to-back on the same cluster.
# Each test still starts from its own `ClusterCleanup`, which deletes the `Application` and blocks
# on the target namespace delete, so the second run does NOT converge from the first run's
# `/status`. What this proves is idempotency against the leftovers that cleanup cannot remove — the
# CRDs (and any namespace the delete could not finish) — and that no test depends on a pristine
# cluster: a timing or ordering assumption that only holds on a first run shows up as a red second
# run.
test-integration-twice:
	kubectl config current-context | grep -q '^kind-' || { echo "ABORT: non-kind context!"; exit 1; }
	cargo test --workspace -- --ignored
	cargo test --workspace -- --ignored
