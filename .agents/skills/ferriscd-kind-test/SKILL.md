---
name: ferriscd-kind-test
description: >-
  Safe runbook for running live Kubernetes v1.35 integration and E2E tests against
  a local kind cluster for FerrisCD. Activate before executing any kubectl or
  cargo integration test targeting a live cluster.
---

# FerrisCD Live `kind` Testing Runbook

## 1. Mandatory Cluster Context Safety Check
**NEVER** run integration tests or `kubectl apply`/`delete` against a non-`kind` cluster.
Before any live test command, verify the active kubeconfig context starts with `kind-`:

```bash
kubectl config current-context | grep -q '^kind-' || { echo "ABORT: non-kind context!"; exit 1; }
```

## 2. Ensure `kind-ferriscd-dev` Cluster Exists
```bash
kind get clusters | grep -q '^ferriscd-dev$' || kind create cluster --name ferriscd-dev --config deploy/kind-config.yaml
kubectl config use-context kind-ferriscd-dev
kubectl get nodes
```
*(If `deploy/kind-config.yaml` does not exist yet in `T01.2`, create a default cluster with `kind create cluster --name ferriscd-dev`.)*

## 3. Apply CRDs (Phase 04+)
```bash
kubectl apply --server-side -f deploy/crds/
kubectl wait --for=condition=Established crd/applications.ferriscd.io crd/appprojects.ferriscd.io --timeout=30s
```

## 4. Run Integration Tests
- Keep every integration test isolated in its own unique namespace (e.g., `test-<name>-<short-rand>`) and clean up the namespace on exit.
- Run with single-threaded or scoped test flags when testing cluster-scoped resources (CRDs, ClusterRoles):
  ```bash
  cargo test --test <integration_test_name> -- --nocapture
  ```
- Inspect live SSA field ownership when debugging diff/conflict tests:
  ```bash
  kubectl get <kind> <name> -n <ns> -o yaml --show-managed-fields
  ```

## 5. Sandbox Note
Live `kind` API calls use local loopback networking (`127.0.0.1:<port>`). If sandboxed network isolation blocks access to the local `kind` API server, retry only the single `kubectl`/`cargo test` command outside the sandbox after verifying `cargo check`/`cargo test --lib` pass inside the sandbox.
