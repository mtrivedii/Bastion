# Bastion

A secure delivery platform built around a small app called Drydock. Drydock takes a CycloneDX SBOM, checks every package in it against the OSV.dev vulnerability database, and keeps a record of what was found and when it was fixed.

The app is small on purpose. The point of the project is the pipeline and the security controls around it: every build is linted, tested, scanned, turned into an SBOM, signed and only then published. The pipeline produces SBOMs in the same format that Drydock accepts.

**Status:** the app, pipeline, Helm chart, admission policies, monitoring and a threat model are done and checked in CI. The Helm chart and policies are validated in CI and are also installed on a real kind cluster (with Calico and Kyverno) by the `Cluster test (kind)` workflow, which runs the demo and checks that an unsafe pod is refused. Terraform for an optional AWS cluster is written and validated but has never been applied. See [What is tested and what is not](#what-is-tested-and-what-is-not).

## What Drydock does

1. You upload a CycloneDX JSON SBOM, optionally naming a project (`?project=my-app`).
2. You trigger a scan. Drydock sends the packages to OSV.dev in batches, follows result paging, and stores the vulnerabilities it gets back with a Critical/High/Medium/Low rating calculated from the CVSS vector.
3. You read the findings report for that SBOM.
4. When you upload a newer SBOM for the same project and scan it, findings that are gone are marked resolved with a timestamp, and a reason: `fixed` (the package is still there but no longer vulnerable) or `removed` (the package is gone). Those timestamps feed the time-to-remediate numbers.

Findings are matched by project, package name, ecosystem and vulnerability id, not by upload.

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Liveness check (no API key needed) |
| POST | `/sboms?project=` | Upload an SBOM (multipart file field named `file`) |
| GET | `/sboms?project=&limit=` | List submissions |
| POST | `/sboms/{id}/scan` | Start a scan in the background. Only the newest submission of a project can be scanned |
| GET | `/sboms/{id}/findings?state=` | Findings (state is all, open or resolved) with severity, discovered time, resolved time and reason |
| GET | `/projects` | Project names |
| GET | `/projects/{project}/summary` | Open findings by severity, resolved counts, mean and median time to remediate, oldest open finding |
| GET | `/metrics` | Prometheus metrics |

### Settings

All optional. Set them as environment variables.

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | local SQLite file | Use a Postgres URL for anything shared |
| `DRYDOCK_API_KEY` | unset | When set, every endpoint except `/health` needs `X-API-Key: <key>` or `Authorization: Bearer <key>` |
| `DRYDOCK_RATE_LIMIT_PER_MINUTE` | 60 | Per client address, for uploads and scan triggers. 0 turns it off. Counted per process |
| `DRYDOCK_MAX_UPLOAD_BYTES` | 5000000 | Larger uploads get a 413 |
| `DRYDOCK_MAX_PACKAGES` | 20000 | SBOMs with more packages get a 413 |
| `DRYDOCK_LOG_LEVEL` | INFO | |

## Run it locally

Needs Python 3.12 and internet access (it calls api.osv.dev).

```bash
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

By default it uses a local SQLite file. Set `DATABASE_URL` to a Postgres URL such as `postgresql+asyncpg://user:pass@host:5432/drydock` to use Postgres.

Interactive API docs are at http://127.0.0.1:8000/docs.

### Try the seed-and-fix demo

`demo/` has two tiny SBOMs. The first contains PyYAML 5.3, which has known vulnerabilities. The second contains PyYAML 6.0.

```bash
curl -F file=@demo/seed_vulnerable_sbom.json http://127.0.0.1:8000/sboms
curl -X POST http://127.0.0.1:8000/sboms/1/scan
curl http://127.0.0.1:8000/sboms/1/findings     # open findings

curl -F file=@demo/seed_fixed_sbom.json http://127.0.0.1:8000/sboms
curl -X POST http://127.0.0.1:8000/sboms/2/scan
curl http://127.0.0.1:8000/sboms/2/findings     # the same findings, now with resolved_at set
```

On Windows use `127.0.0.1` rather than `localhost`, because `localhost` can resolve to IPv6 while uvicorn listens on IPv4.

## Tests

```bash
pip install -r requirements-dev.txt
pytest --cov --cov-fail-under=90
```

76 tests, about 97 percent line coverage, on an in-memory database. HTTP calls to OSV.dev are faked, including retries, paging and server errors. CI fails below 90 percent.

## Pipeline

`.github/workflows/ci.yml` has three jobs. Each one only starts if the one before it passed.

1. **Lint, test, static analysis:** ruff, pytest with a coverage gate, Bandit, pip-audit, hadolint.
2. **Build, scan, smoke test, DAST:** build the image, Trivy (fails on fixable CRITICAL and HIGH), generate a CycloneDX SBOM with Syft, start the container and check it runs as a non-root user with the API key enforced, scan Drydock's own SBOM with Drydock, then an OWASP ZAP API scan against the running container.
3. **Push, sign, attest** (main only): push to GitHub Container Registry, sign the image digest with Cosign (keyless), attach the SBOM as a signed attestation, and verify the signature.

Other workflows:

- `infra.yml`: `helm lint`, render the chart, kubeconform, Kyverno policy tests, check that the rendered chart passes the policies, Trivy config scan, `terraform validate`, shellcheck.
- `codeql.yml`: CodeQL on every push and weekly.
- `scheduled-scan.yml`: weekly rescan, because new CVEs appear after a build.
- Dependabot for pip, Docker, GitHub Actions and Terraform.

In its first run the Trivy gate found vulnerabilities in pip, setuptools and wheel that ship with the base image. The runtime image does not need them, so they are removed from it.

## Kubernetes

`deploy/helm/drydock` is the chart. The pod runs as non-root with a read-only filesystem, no Linux capabilities, a seccomp profile and resource limits. A default-deny NetworkPolicy only allows DNS, HTTPS out and the database. `deploy/kyverno` holds admission policies with CLI tests, and a policy that requires a valid Cosign signature on the image.

To run all of it on your own computer for free, follow [docs/RUNBOOK.md](docs/RUNBOOK.md). It starts from nothing and needs no cloud account.

`infra/terraform` can build a small EKS cluster, but that costs money and nothing runs it automatically.

## What is tested and what is not

| Part | Checked how |
|---|---|
| App | 76 tests, 97 percent coverage, run in CI |
| Container, pipeline, signing | Run on GitHub Actions on every push to main |
| Helm chart | `helm lint`, render, schema check and policy checks in CI. Installed on a kind cluster with Postgres in CI, and the demo runs against it |
| Kyverno policies | CLI tests in CI. Installed on the kind cluster in CI: an `nginx:latest` pod is rejected and the chart's own pods still pass after a restart |
| Terraform | `fmt`, `validate`, Trivy in CI. **Never applied** |
| Argo CD, Grafana dashboard | Written, **not run** |
| Scan against the real OSV.dev | The tests fake OSV.dev. The CI self-scan and `scripts/demo.sh` use the real one |

## Threat model

[THREAT_MODEL.md](THREAT_MODEL.md) is a STRIDE analysis of the app and the pipeline: 18 findings, of which 5 are mitigated, 7 are accepted, 5 are open and 1 is partial. It only covers what exists today and lists the later phases as not yet modelled.

[LEARNING_LOG.md](LEARNING_LOG.md) records design decisions and the bugs found along the way.

## Known limits

- One shared API key, not per-user accounts. There is no TLS inside the app. Use an ingress with TLS (the chart supports it) or keep the service private.
- The rate limiter and the "scan already running" guard are per process. Run one replica, or add a shared store first.
- Scans run inside the process that received the request. If that pod is restarted mid-scan, the submission shows as scanning until the stale-scan timeout passes, then it can be started again.
- There are no database migrations. Tables are created on start. Changing a model needs a migration tool such as Alembic first.
- If one SBOM lists the same package twice with different versions, the findings of both are treated as one set.
- Only the newest submission of a project can be scanned.

## Layout

```
app/            FastAPI app, database models, OSV client, scan, severity and metrics logic
tests/          pytest suite
demo/           two sample SBOMs for the seed-and-fix demo
scripts/        demo.sh (end-to-end demo), CI self-scan
deploy/         Helm chart, Kyverno policies, kind config, Argo CD, monitoring
infra/          Terraform for the optional EKS cluster
docs/           RUNBOOK.md (start from zero, free)
Makefile        shortcuts for all of the above
Dockerfile      multi-stage, non-root image
THREAT_MODEL.md STRIDE analysis
LEARNING_LOG.md Design decisions and bugs
```
