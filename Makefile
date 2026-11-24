.PHONY: fmt fmt-check lint test gate gate-fast kind-up kind-down test-integration

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
gate:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings
	K8S_OPENAPI_ENABLED_VERSION=1.35 cargo clippy -p ferriscd-engine --features test-utils --all-targets -- -D warnings
	cargo test --workspace

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
