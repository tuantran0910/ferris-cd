# Security Policy

## Supported Versions

FerrisCD is currently in active pre-`v1.0` development on the `main` branch. Security fixes are applied directly to `main`.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please use GitHub's **Private Vulnerability Reporting** ("Report a vulnerability" under the **Security** tab of `tuantran0910/ferris-cd`). Include:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a minimal proof of concept
- Any affected crate, manifest, or renderer configuration

We aim to acknowledge reports within 72 hours and provide a remediation timeline after triage.

## Security Design Invariants

FerrisCD treats Git repositories and rendered manifests as untrusted inputs by default:

- **Untrusted repository defense:** Worktree-wide symlink sanitization rejects symlinks escaping the checkout root before any parser or renderer runs; `serde-saphyr` parser budgets defend against YAML bombs.
- **Renderer isolation:** Subprocess renderers (`kustomize`, `helm`) execute with cleared environments, timeouts, output caps, and SSRF/remote-base blocking.
- **Secret & credential hygiene:** `Secret` `.data`/`.stringData` values are redacted in diffs and logs; `RepoCredentials` redacts secrets in `Debug`/`Display`; SSH private keys use ephemeral `0600` files with `known_hosts` verification and RAII zeroization.
- **Least privilege:** `Application` reconciliation respects `AppProject` allow-lists on every rendered resource's actual namespace and supports `ServiceAccount` impersonation (`Impersonate-User` + `Impersonate-Group`).
