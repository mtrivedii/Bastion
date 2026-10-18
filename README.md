# Bastion

A secure delivery platform built around a small app called Drydock. Drydock takes a CycloneDX SBOM, checks every package in it against the OSV.dev vulnerability database, and keeps a record of what was found and when it was fixed.

The app is small on purpose. The point of the project is the pipeline and the security controls around it: every build is linted, tested, scanned, turned into an SBOM, signed and only then published. The pipeline produces SBOMs in the same format that Drydock accepts.

**Status:** Phase 1 (app, pipeline, threat model) is done. Kubernetes, Terraform and AWS work is planned and not in this repo yet. See [Roadmap](#roadmap).

## What Drydock does

1. You upload a CycloneDX JSON SBOM.
2. You trigger a scan. Drydock sends the packages to OSV.dev in batches and stores the vulnerabilities it gets back.
3. You read the findings report for that SBOM.
4. When you upload a newer SBOM and scan it, findings that no longer appear are marked as resolved, with a timestamp. That timestamp is the base for time-to-remediate numbers.

Findings are matched by package name and ecosystem across uploads, not by upload. This was a bug in the first version: a fix in a later upload never showed as resolved. A test now covers it.

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Liveness check |
| POST | `/sboms` | Upload an SBOM (multipart file field named `file`) |
| POST | `/sboms/{id}/scan` | Start a scan in the background |
| GET | `/sboms/{id}/findings` | Findings with discovered and resolved times |

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
pytest
```

19 tests cover SBOM parsing, the OSV client (HTTP is faked, including retries on timeouts and 5xx), the endpoints, and finding resolution across uploads. They run on an in-memory database.

## Pipeline

GitHub Actions (`.github/workflows/ci.yml`) runs these steps in order and stops at the first failure:

1. Lint with ruff
2. Tests with pytest
3. Static analysis with Bandit
4. Dependency audit with pip-audit
5. Docker build (multi-stage, runs as a non-root user)
6. Image scan with Trivy. Fails on fixable CRITICAL and HIGH findings only
7. SBOM generation with Syft (CycloneDX, kept as a workflow artifact)
8. On `main` only: push to GitHub Container Registry and sign the image with Cosign (keyless, using the workflow's OIDC identity)

To check that the gate really blocks things, a throwaway pull request added `pyyaml==5.3`. It failed at pip-audit and never reached the build.

## Threat model

[THREAT_MODEL.md](THREAT_MODEL.md) is a STRIDE analysis of the app and the pipeline: 18 findings, of which 5 are mitigated, 7 are accepted, 5 are open and 1 is partial. It only covers what exists today and lists the later phases as not yet modelled.

[LEARNING_LOG.md](LEARNING_LOG.md) records design decisions and the bugs found along the way.

## Known limits

- The API has no authentication, TLS or rate limiting. Do not expose it to the internet.
- A vulnerable package that is removed from a later SBOM (instead of upgraded) is never marked as resolved.
- The severity field stores the first CVSS vector string OSV returns, not a Low/High/Critical rating.
- All uploads are treated as one project. Two unrelated projects with the same package names would be matched to each other.
- OSV.dev results for a single package are not paged, so an extremely vulnerable package could show a truncated list.

## Roadmap

| Phase | Content | Status |
|---|---|---|
| 1 | App, tests, pipeline with security gates, SBOM, signing, threat model | Done |
| 2 | Helm chart on a local kind cluster, Terraform foundations on AWS | Planned |
| 3 | Short-lived EKS cluster built with Terraform, policy enforcement with Kyverno | Planned |
| 4 | GitOps with ArgoCD, Prometheus and Grafana, ZAP baseline scan in CI | Planned |
| 5 | Security metrics report and architecture diagram | Planned |

The whole project has a budget of under 20 euros per month, so the EKS cluster is only created for a work session and destroyed afterwards.

## Layout

```
app/            FastAPI app, database models, OSV client, scan logic
tests/          pytest suite
demo/           two sample SBOMs for the seed-and-fix demo
Dockerfile      multi-stage, non-root image
THREAT_MODEL.md STRIDE analysis
LEARNING_LOG.md Design decisions and bugs
```
