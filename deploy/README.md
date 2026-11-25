# FerrisCD deployment notes

This directory holds the manifests an operator applies **before** the controller can reconcile
anything:

| Path | What it is |
|---|---|
| `crds/applications.ferriscd.io.yaml` | `Application` CRD (`ferriscd.io/v1alpha1`) |
| `crds/appprojects.ferriscd.io.yaml` | `AppProject` CRD — the multi-tenancy boundary (`T12.1`) |
| `manifests/default-project.yaml` | the permissive single-tenant `default` project every `Application` falls back to |
| `kind-config.yaml` | local development cluster definition (`make kind-up`) |

Both CRDs must be installed. A cluster that does not serve `AppProject` cannot reconcile
anything: project lookups are **never** treated as permissive, and the failure names
`deploy/crds/appprojects.ferriscd.io.yaml` instead of pretending the project is missing
(finding M3).

---

## Controller `ClusterRole`

The controller authenticates as its own ServiceAccount. Everything below is required by the
code that ships today (Phases 06–12); the last block is only needed once you turn
Apps-in-any-namespace on.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ferriscd-controller
rules:
  # --- Application lifecycle (control-plane namespace) ------------------------------
  - apiGroups: ["ferriscd.io"]
    resources: ["applications"]
    verbs: ["get", "list", "watch", "patch"]
  - apiGroups: ["ferriscd.io"]
    resources: ["applications/status"]
    verbs: ["get", "patch", "update"]
  - apiGroups: ["ferriscd.io"]
    resources: ["applications/finalizers"]
    verbs: ["update"]

  # --- AppProject policy (read-only; `get` per reconcile, never a cluster-wide watch)
  - apiGroups: ["ferriscd.io"]
    resources: ["appprojects"]
    verbs: ["get"]

  # --- The workloads the Applications declare (`T06`–`T08`) -------------------------
  # Enumerated on purpose. Do NOT write `apiGroups: ["*"] / resources: ["*"]` here: that also
  # grants `secrets` **cluster-wide**, which is precisely the grant the repository-credential
  # section below forbids. Enumerate the GroupKinds your Applications actually declare and
  # extend the list as you add kinds.
  #
  # With impersonation on (`T12.3`), the workload verbs are used *by the impersonated tenant
  # ServiceAccount*, not by this ClusterRole: the rules below therefore only have to cover the
  # Applications that keep the controller's identity (the control-plane ones). Grant each tenant
  # ServiceAccount its own, narrower `Role` in its destination namespace.
  - apiGroups: [""]
    resources:
      - configmaps
      - services
      - serviceaccounts
      - persistentvolumeclaims
      - namespaces         # only when a project whitelists `Namespace` (namespace pruning is opt-in)
    verbs: ["get", "list", "watch", "create", "patch", "update", "delete"]
  - apiGroups: ["apps"]
    resources: ["deployments", "statefulsets", "daemonsets", "replicasets"]
    verbs: ["get", "list", "watch", "create", "patch", "update", "delete"]
  - apiGroups: ["batch"]
    resources: ["jobs", "cronjobs"]
    verbs: ["get", "list", "watch", "create", "patch", "update", "delete"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["ingresses", "networkpolicies"]
    verbs: ["get", "list", "watch", "create", "patch", "update", "delete"]
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]
    verbs: ["get", "list", "watch", "create", "patch", "update", "delete"]
  - apiGroups: ["apiextensions.k8s.io"]
    resources: ["customresourcedefinitions"]
    verbs: ["get", "list", "watch", "create", "patch", "update", "delete"]


  # --- Apps-in-any-namespace + ServiceAccount impersonation (`T12.2`, `T12.3`) ------
  # `impersonate` is what lets the controller act as a tenant's ServiceAccount. It must be
  # granted on `users` AND `groups`: Kubernetes authorizes groups, so a `RoleBinding` that
  # names `system:serviceaccounts:<ns>` only applies if the groups are impersonated too.
  - apiGroups: [""]
    resources: ["users", "groups"]
    verbs: ["impersonate"]
  # Impersonating `system:serviceaccount:<ns>:<name>` is additionally checked against
  # `serviceaccounts` in the *destination* namespace.
  - apiGroups: [""]
    resources: ["serviceaccounts"]
    verbs: ["impersonate"]
```

> **`secrets` is deliberately absent from that `ClusterRole`.** A wildcard
> `apiGroups: ["*"] / resources: ["*"]` rule — the shape earlier drafts of this file shipped —
> grants `get`/`list` on **every `Secret` in the cluster**, which contradicts
> `ferriscd.io/secret-type=repository` being read from one namespace (below). If the manifests your
> Applications declare contain `Secret`s, use one of these instead, and never a cluster-wide
> `secrets` rule:
>
> 1. **Impersonated tenants (recommended).** Give each tenant `ServiceAccount` a namespaced `Role`
>    with `secrets` verbs in its *destination* namespace; the apply runs as that identity, so the
>    controller's own role never needs `secrets`.
> 2. **Control-plane Applications.** Bind a namespaced `Role` with `secrets` verbs in each
>    destination namespace the project allows, to the controller's `ServiceAccount` — never a
>    `ClusterRole` rule, and never `clusterRole`-wide `get`.

### Repository credential Secrets (`T12.4`) — namespaced, never cluster-wide

Git credentials (HTTPS tokens/basic auth and SSH deploy keys) live in `Secret`s labeled
`ferriscd.io/secret-type=repository` **in the control-plane namespace only**. The controller holds a
*namespaced* `Api<Secret>`, so every read is a label-filtered list inside that one namespace; it
can never observe a `Secret` anywhere else, and it never asks for cluster-wide `Secret` RBAC.

Grant exactly this, and nothing wider:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ferriscd-repository-credentials
  namespace: ferriscd-system          # the control-plane namespace, never another one
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    # `get`/`list` cover the scoped read the controller performs; `watch` is what a future
    # informer-based store would need and costs nothing to grant now.
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ferriscd-repository-credentials
  namespace: ferriscd-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: ferriscd-repository-credentials
subjects:
  - kind: ServiceAccount
    name: ferriscd-controller
    namespace: ferriscd-system
```

Do **not** add `secrets` to the controller's `ClusterRole`, and do not bind this `Role` across
namespaces: a `Secret` a tenant writes in its own namespace must never become a credential FerrisCD
uses (that is the whole point of scoping it to `ferriscd-system`).

#### What a credential `Secret` looks like

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: repo-git-example-com
  namespace: ferriscd-system
  labels:
    ferriscd.io/secret-type: repository
stringData:
  url: https://git.example.com        # exact URL, or a prefix (longest prefix wins)
  username: ferriscd-bot              # optional (basic auth)
  token: ghp_…                        # or `password:`; `username` + `token` = basic auth w/ token
```

| Key | Meaning |
|---|---|
| `url` | repository URL or prefix. `https://` and `ssh://` only (SCP-style `git@host:org/repo` is accepted and normalized to `ssh://`). Plaintext `http://` is refused. |
| `username`, `password` | HTTPS basic auth. `username` + `token` is the GitHub/GitLab "user + PAT" form. |
| `token` | HTTPS bearer/PAT (sent as basic auth with the token as the user, which is what the hosts expect). |
| `sshPrivateKey`, `knownHosts` | SSH deploy key. The key **must be unencrypted** (no passphrase is read); `knownHosts` is required unless the controller explicitly allows missing host keys (test/dev only). |

Matching is predictable: the **whole normalized URL is lowercased — the path included** — one
trailing `.git` and trailing slashes are ignored, userinfo is dropped (so
`git@github.com:org/repo.git` and `ssh://github.com/org/repo` are the same repository), the default
port is ignored, an exact match beats any prefix, and a prefix only matches on a path boundary
(`https://git.example.com/org` does not match `https://git.example.com/organization/repo`).
Lowercasing the path is deliberate: Git hosting paths are conventionally case-insensitive, and it
means one `Secret` covers one repository even when a URL is copied with different casing. The cost
is documented rather than hidden — on a self-hosted server that *does* distinguish `/Org/Repo` from
`/org/repo`, both are treated as the same repository (and therefore use the same credential). A URL that matches nothing is cloned **anonymously**;
a `Secret` that cannot be used (no `url`, ambiguous `password`+`token`, an SSH key on an `https://`
URL, two `Secret`s claiming the same URL) is a **terminal** `Ready=False` error naming the `Secret`
— never a silent fallback.

Credential values never reach the logs or `Application.status`: the `Secret` name and the
credential *kind* are logged, the values are not, and repository URLs are quoted through the shared
redaction helper (`https://robot:***@host/...`).

### Multi-tenancy RBAC matrix

| Controller verb (`T12.2`/`T12.3`) | Why | Scope |
|---|---|---|
| `applications` `get`, `list`, `watch` | one `Controller`/watcher/store per `--application-namespaces` entry (a merged store would let one namespace's `InitDone` truncate the others) | one entry per tenant namespace; **cluster-wide** when the flag is `*` |
| `applications` `patch` | the rollback path removes `spec.syncPolicy.automated` and consumes `ferriscd.io/operation` (`T10.5`) | the tenant namespaces |
| `applications/status` `patch`, `update` | always-update-status: `/status` is patched on success **and** failure (trap T3) | the tenant namespaces |
| `applications/finalizers` `update` | the finalizer helper adds/removes `ferriscd.io/finalizer` **on the object it was handed**, which lives in the tenant namespace (`T12.2`) | the tenant namespaces |
| `applications` `get`, `patch` on a *deleting* object | a cascade cleanup re-reads the project and the tracked objects before deleting anything (finding H1) | the tenant namespaces |
| `appprojects` `get` | one scoped read per reconcile, from the control-plane namespace (`T12.1`) | the control-plane namespace |
| `users`, `groups` `impersonate` | `Impersonate-User` + the three `Impersonate-Group` headers (`T12.3`, finding H5) | cluster-scoped (impersonation is not namespaced) |
| `serviceaccounts` `impersonate` | Kubernetes checks the impersonated `system:serviceaccount:<ns>:<name>` against this resource | the destination namespaces |
| `secrets` `get`, `list`, `watch` | repository credential `Secret`s (`T12.4`); granted through a namespaced `Role`/`RoleBinding`, **never** a `ClusterRole` rule | the control-plane namespace only |
| workload verbs | the actual applies/diffs/prunes, now executed as the tenant's ServiceAccount | whatever the project's `destinations` allow |

Notes that matter operationally:

* **`system:masters` is never impersonated.** The group set is exactly
  `system:serviceaccounts`, `system:serviceaccounts:<destination namespace>` and
  `system:authenticated`, and the code refuses `system:masters` outright (trap T12). Granting
  the controller `impersonate` on `users`/`groups` lets it become *those* ServiceAccounts — so
  keep `AppProject.spec.allowedServiceAccounts` curated, and never allow `*` in a shared
  cluster.
* **A tenant `Application` without `spec.serviceAccountName` is refused** with
  `Ready=False, reason=PolicyViolation`; it is never deployed with the controller's identity.
* **The project allow-lists remain the boundary.** Impersonation narrows what a tenant *can* do;
  it does not authorize anything. An empty `spec.destinations`, `spec.sourceNamespaces`,
  `spec.allowedServiceAccounts`, or `spec.clusterResourceWhitelist` permits nothing
  (finding M2). Only `namespaceResourceWhitelist` is "empty means everything", matching Argo CD.
* **The `Application` object itself stays on the controller's identity** for `/status` and the
  finalizer: the tenant's ServiceAccount must not need RBAC on the `Application` CR (it usually
  only has RBAC in its destination namespace), while the controller must always be able to
  record what happened.
* **A cascade never runs as an unauthorized identity.** Deleting an `Application` with
  `ferriscd.io/cascade-delete: "true"` re-checks `AppProject.spec.allowedServiceAccounts` before
  the ServiceAccount is resolved (finding H1): a tenant that retargets `spec.serviceAccountName`
  and then deletes the object is refused, and nothing is deleted.
* **The tenant finalizer can wedge, on purpose.** If a tenant `Application` is deleted while it
  references a `ServiceAccount` the project no longer allows (or the `AppProject` itself is gone,
  or the `ServiceAccount` is refused as invalid), the reconcile fails with
  `Ready=False, reason=PolicyViolation` and the `ferriscd.io/finalizer` is **retained** — deleting
  with an identity no project authorized is the privilege escalation this phase exists to prevent,
  so the safe direction is to keep the object rather than to guess. The remedies are, in order:
  re-add the ServiceAccount to `spec.allowedServiceAccounts` (or recreate the project); set
  `spec.serviceAccountName` to an allowed account; or, to abandon the cascade entirely, annotate
  the object with `ferriscd.io/force-delete: "true"` — the finalizer is then released **without
  pruning**, and any managed objects must be removed by hand. `kubectl describe application` shows
  the reason and the offending name.
* **Remote clusters (`T13.1`)** will need the same `impersonate` rules on their own
  kubeconfigs; the pool builds one connector per cluster and reuses it for every
  ServiceAccount (no connector per reconcile, trap T12 / finding H5). At most 64 impersonated
  clients are cached per cluster (finding M2): the cache key is
  `(destination namespace, ServiceAccount)`, so it is bounded rather than tenant-controlled, and a
  miss rebuilds a middleware stack over the same connector.
* **Repository credentials are controller-side only.** They are read from `ferriscd-system` under
  the controller's own identity, *before* a clone, and are never copied into a tenant namespace,
  an `Application`, or a `status` field — so a tenant's RBAC on its destination namespaces never
  includes the token, and a tenant cannot read another tenant's credential.
