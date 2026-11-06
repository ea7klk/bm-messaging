# BM Messaging agent instructions

These instructions apply to the entire repository.

## Development and Git workflow

- For now, work directly on `main`. Do not create feature branches or require pull requests unless the user changes this policy.
- Use test-driven development for behavior changes: write a meaningful failing test, confirm the expected failure, implement the smallest working change, then refactor with tests passing. Cover bugs with regression tests and test failure paths as well as successful behavior.
- Run the relevant tests, linting, type checks, and build before committing. For documentation-only changes, review accuracy and formatting; do not add artificial tests. Report unavailable checks and unresolved failures honestly.
- Group related changes into coherent, reviewable commits. Keep unrelated changes and user edits out of each commit. Avoid both unrelated bulk commits and a stream of trivial checkpoint commits.
- Use extended commit messages: a concise imperative subject, a blank line, then a body explaining the problem, resulting behavior, design decisions, validation performed, and material limitations or migration impact.
- Push each completed, validated commit to `origin/main` immediately. Inspect the staged diff before committing and verify the push succeeded. If the remote advances, integrate its changes safely and repeat affected checks; never force-push shared history.
- Keep code simple, dependencies justified, and configuration explicit. Document setup, supported configuration, operation, and recovery alongside the implementation. Never commit credentials, kubeconfigs, private keys, database dumps, or secret payloads.

## PostgreSQL

- PostgreSQL is the database of choice. Use it for persistent relational application data unless the user explicitly approves another database.
- Version schema changes as migrations in Git. Test migrations and database behavior against PostgreSQL, including constraints, transactions, and rollback or forward-recovery behavior; do not substitute SQLite for PostgreSQL integration tests.
- Use parameterized queries, appropriate constraints and indexes, bounded connection pools, and least-privilege application credentials. Read credentials from existing Kubernetes Secrets or protected local configuration.
- Make migrations compatible with the deployment sequence. Back up data before destructive changes and document recovery. Run migrations as a controlled deployment step or Job, avoiding concurrent migration races between replicas.
- Keep PostgreSQL on private cluster networking. Persist its data on an explicitly selected PVC, and define backup, retention, and restore procedures before production use. Verify restores; a PVC is not a backup.

## Container images

- Prefer small Alpine-style runtime images. Use a minimal compatible alternative when musl or native dependencies make Alpine unsuitable, and document the reason.
- Use multi-stage builds and copy only runtime artifacts and dependencies into the final image. Exclude source-control metadata, tests, caches, build tools, and secrets with an appropriate `.dockerignore`.
- Run as a non-root user, drop unnecessary Linux capabilities, disable privilege escalation, and use a read-only root filesystem where supported. Provide explicitly writable temporary or data mounts as needed.
- Pin base image versions and production images by immutable digest; never deploy `latest`. Keep dependencies and base images maintained, scan images, and verify startup and health checks using the final runtime image.
- Build for the cluster's `linux/amd64` architecture. Publish the image before updating its digest in Fleet deployment configuration, and retain the previous working digest for rollback.

## Current K3s cluster conventions

Verified on 2026-11-06 against the live cluster and `/root/infra`. Recheck live configuration before deployment because this snapshot can change.

- Cluster: a single Ready `spainip-k3s` node using K3s and containerd on `amd64`. Do not assume multi-node availability; node-local storage and all workloads share one failure domain.
- Shared GitOps source: `spainip/infra` (`/root/infra` locally). Its bootstrap Fleet GitRepo is `fleet-local/infra`, tracks `main`, and reconciles the `fleet/` directory.
- Existing `ea7klk` applications are registered in the `ea7klk` Fleet workspace. The Fleet workspace namespace and application workload namespace are distinct concerns; use a dedicated `bm-messaging` workload namespace.
- Traefik is Fleet-managed in namespace `traefik`; the bundled K3s Traefik is disabled. The ingress class is `traefik` and is intentionally not the default. Its LoadBalancer exposes HTTP and HTTPS with dual-stack addressing.
- The default `local-path` StorageClass dynamically provisions under `/var/lib/rancher/k3s/storage`, uses `WaitForFirstConsumer`, and has reclaim policy `Delete`. Retained storage classes also exist; inspect their provisioners and ownership before choosing one. In particular, `retained-local` uses static provisioning and requires matching PV definitions.

## Fleet deployment standards

- Make lasting deployment changes through the owning Git repository and Rancher Fleet. Use `kubectl` for inspection and troubleshooting; avoid unmanaged `kubectl apply`, Helm installs, or live edits that conflict with reconciliation.
- Keep application deployment sources in a clear bundle path such as `fleet/bm-messaging`, with a `fleet.yaml` and a Helm chart or Kubernetes manifests. Maintain one authoritative definition of each resource.
- Register this repository through a `GitRepo` manifest in `spainip/infra/fleet/`, using the existing `ea7klk` workspace conventions, `branch: main`, the exact bundle path, and deliberate cluster targeting. For private sources, the workspace uses `github-auth`; public source repositories do not require repository credentials.
- Use `defaultNamespace: bm-messaging` for application resources and ensure the namespace is managed. Scope RBAC and service accounts to the minimum required permissions. Do not modify shared cluster controllers or other applications as part of an app deployment.
- Pin external Helm chart versions and application image digests. When using Helm, expose supported configuration through a documented `values.yaml`: images, replicas, resources, probes, ports, ingress, persistence, security contexts, and existing Secret references.
- Reference existing Secrets by name. The cluster convention for private image pulls is `registry-credentials` in the application namespace; verify it exists when needed. Never put plaintext or base64-encoded secret payloads into Git or Helm values.
- Define realistic CPU and memory requests and limits, startup/readiness/liveness probes, graceful shutdown, and an update strategy suited to the workload. Size the workload for the single node and its existing services. Keep services internal unless public exposure is required.
- Prefer a namespace-local `traefik.io/v1alpha1` `IngressRoute` with `entryPoints: [websecure]`, an explicit hostname rule, and `tls.certResolver: acmeresolver`. The `web` entry point redirects HTTP to HTTPS globally.
- For standard Kubernetes Ingress, explicitly set `spec.ingressClassName: traefik` and the appropriate HTTPS/TLS resolver annotations. Do not rely on a default ingress class.
- Keep routes, referenced Services, and Middleware in the same namespace: Traefik has `allowCrossNamespace: false`. Use unique hostnames, correct Service ports, and authentication for administrative routes. Shared Traefik configuration belongs in `spainip/infra`.
- Declare PVCs for persistent application data. Use dynamic `local-path` provisioning for ordinary volumes unless explicit retention requirements call for another storage design. Never assume `Delete` volumes survive PVC removal. Preserve database data through upgrades and document off-node backups and restore steps.
- Set Fleet `keepResources` and drift correction deliberately, following the owning infrastructure conventions. `keepResources: true` can leave orphaned resources; `false` can remove resources on bundle deletion. Inspect PVC/PV retention and data ownership before removal. Fix drift at its source rather than hiding unexplained differences with comparison patches.
- Before publishing deployment changes, render and validate manifests or run Helm lint/template checks as applicable; check namespace ownership, Secret references, image availability, migration order, and storage behavior.
- After Fleet reconciliation, verify the relevant GitRepo, Bundle, and BundleDeployment revision and readiness, workload rollout, probes, logs, ingress/TLS, and PostgreSQL connectivity. Validate application behavior and data persistence; a Bound PVC or aggregate Fleet status alone is insufficient evidence.
- Record the deployed commit, image digest, validation, and rollback procedure. Roll back through Git/Fleet with a known working image and configuration; assess schema compatibility before reverting an application.
- Creating or pushing repository content does not itself authorize initial production activation. Prepare and validate deployment artifacts within the requested scope, and register or activate the workload when the user requests deployment.
