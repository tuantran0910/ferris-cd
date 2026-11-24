.PHONY: fmt fmt-check lint test kind-up kind-down test-integration

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
