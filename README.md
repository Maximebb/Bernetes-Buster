# Bernetes-Buster

**LinPEAS-style Kubernetes misconfiguration & privilege-escalation explorer.**  
Drop it in a Job (or a compromised pod), get **FOUND / NOT FOUND** signals, walk away with a JSON report.

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![CI](https://github.com/Maximebb/Bernetes-Buster/actions/workflows/ci.yml/badge.svg)](https://github.com/Maximebb/Bernetes-Buster/actions/workflows/ci.yml)

> **Authorized use only.** Run only on clusters you own or have explicit permission to assess.

## Why this exists

Most K8s security tooling falls into one of these buckets:

| Tool | Style | Gap |
|------|--------|-----|
| [kube-bench](https://github.com/aquasecurity/kube-bench) | CIS Job in-cluster | Compliance, not foothold privesc |
| [Trivy](https://github.com/aquasecurity/trivy) / Kubescape | Broad scanner | Great coverage, heavier ops footprint |
| [kube-hunter](https://github.com/aquasecurity/kube-hunter) | Attacker view | Archived; Aqua recommends Trivy |
| [kdigger](https://github.com/quarkslab/kdigger) / [Peirates](https://github.com/inguardians/peirates) | In-pod pentest | Plugin/exploit workflows, not “signal report” |
| [k8s-enum.sh](https://github.com/ahrixia/k8s-enum.sh) | LinPEAS-inspired scripts | Enum-focused; limited Job packaging |

**Bernetes-Buster** sits where LinPEAS sits for Linux: fast, opinionated, color-coded **FOUND / NOT FOUND** signals you can paste into a ticket — plus first-class **Kubernetes Job** deployment for security engineering, developers, and red team foothold checks.

## Profiles

| Profile | Audience | Intent |
|---------|----------|--------|
| `developer` | App / platform engineers | Hygiene: root, writable FS, `:latest`, default SA, NetworkPolicies |
| `security-eng` *(default)* | Blue team / SecEng | Full read-only audit: RBAC, privileged workloads, PSA, admission, exposure |
| `red-team` | Offensive (authorized) | Foothold enumeration: sockets, host mounts, cloud metadata, kubelet, creds |

All profiles are **read-only by default** (no pod creation, no exploitation).

## Quick start

### A) Run as a cluster Job (recommended for SecEng)

```bash
kubectl apply -f deploy/rbac-readonly.yaml
kubectl apply -f deploy/job-from-git.yaml   # no custom image required
kubectl logs -f job/bernetes-buster-git -n bernetes-buster
```

Or with the container image:

```bash
docker build -t ghcr.io/maximebb/bernetes-buster:latest .
# push, then:
kubectl apply -f deploy/rbac-readonly.yaml
kubectl apply -f deploy/job.yaml
kubectl logs -f job/bernetes-buster -n bernetes-buster
```

### B) Red-team foothold Job (minimal RBAC)

```bash
kubectl apply -f deploy/rbac-foothold.yaml
kubectl apply -f deploy/job-foothold.yaml
kubectl logs -f job/bernetes-buster-foothold -n bernetes-buster
```

### C) Run the script locally / inside any pod

```bash
./bbuster.sh --profile security-eng
./bbuster.sh --profile developer --json report.json
./bbuster.sh --profile red-team --quiet --json -
```

Exit codes: `0` = no CRITICAL findings, `2` = one or more CRITICAL **FOUND** signals (CI-friendly).

## What it checks (signals)

Each check emits a structured signal:

```text
FOUND  [CRITICAL] container.runtime_socket: Container runtime socket accessible: /var/run/docker.sock
  > Remediation: Never mount runtime sockets into application pods
NOT FOUND  rbac.create.pods: No permission: create pods in ns/default
```

Categories:

1. **Identity & foothold** — in-cluster SA token, namespace, whoami  
2. **Container exposure** — privileged caps, docker.sock, hostPath, hostPID/Network, root, seccomp  
3. **RBAC** — dangerous `can-i` verbs (secrets, exec, impersonate, bind roles, …)  
4. **Secrets & cloud** — sensitive env names, kubeconfig, IMDS (AWS/GCP/Azure)  
5. **Network** — kubelet ports, NodePort/LB services, NetworkPolicy presence  
6. **Workload hygiene** — privileged/hostNetwork pods, `:latest`, default SA  
7. **Cluster posture** — PSA labels, admission webhooks, anonymous bindings  

JSON report shape (see `examples/reports/`):

```json
{
  "tool": "bernetes-buster",
  "profile": "security-eng",
  "summary": { "found": 3, "not_found": 40, "critical": 1, "high": 1, "medium": 1, "low": 0 },
  "signals": [
    { "id": "container.runtime_socket", "status": "FOUND", "severity": "CRITICAL", "message": "...", "remediation": "..." }
  ]
}
```

## Repository layout

```text
bbuster.sh              # entrypoint (LinPEAS-style)
lib/common.sh           # helpers
lib/report.sh           # FOUND/NOT_FOUND aggregation + JSON
lib/checks/*.sh         # ordered check modules
profiles/*.sh           # developer | security-eng | red-team
deploy/                 # RBAC + Job manifests
Dockerfile              # image with bash + kubectl
test/smoke.sh           # offline CI smoke tests
```

## Security notes

- Prefer `deploy/rbac-readonly.yaml` for audits — it can **list** Secrets metadata; it does not need `get` on secret data for most signals.  
- The foothold Job intentionally has **no** ClusterRole so you can see a realistic blast radius.  
- Do not run red-team profile on production without change control; logs may contain sensitive hostnames / RBAC details.

## Contributing

This repository is public for transparency and reuse under **AGPL-3.0**, but **direct pushes to `main` are blocked**. Pull requests require:

- Code owner review (`@Maximebb`)
- Green CI (`Build, unit tests, smoke test`)
- Resolved review threads

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[GNU Affero General Public License v3.0](LICENSE) (or later).  
If you modify and run Bernetes-Buster as a network-facing service, AGPL requires you to offer the corresponding source to users of that service.
