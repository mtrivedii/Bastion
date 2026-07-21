# Project Context: Secure Delivery Platform (DevSecOps Portfolio Project)
 
## Purpose of this document
This is the context file for a personal portfolio project. It exists so that any assistant working in this project folder understands the goal, the constraints, the plan, and how I like to work. Read it before giving advice or writing anything.
 
---
 
## About me
Recent BSc ICT & Infrastructure graduate (Fontys, graduated April 2026), based in Eindhoven, Netherlands. Job hunting for junior roles in DevSecOps, security engineering, cloud/infrastructure, and SRE/platform engineering. On a zoekjaar visa, so no employer sponsorship needed.
 
Existing hands-on background: Python/FastAPI, GitHub Actions CI/CD with security scanning (Bandit, TruffleHog, Safety), Docker, Azure (WAF, Front Door, App Service, Bicep IaC), CodeQL, OWASP ZAP as a one-off scan, Azure Monitor, penetration testing (Metasploit, Wireshark), and NIS2 compliance work.
 
## Why this project exists
It closes specific, named gaps in my CV that keep coming up in job descriptions:
- No production Kubernetes
- No Terraform in practice (I have used Bicep and Docker instead)
- No supply chain / SBOM work
- No formal threat modeling
- No security metrics reporting to leadership
It also builds directly on tools I want to be strong in for my career: AWS, Kubernetes, and Python.
 
## Goal
Build and operate one real, secure cloud-native system end to end, deployed on AWS, over July to December 2026. Not a tutorial follow-along. Something I designed, deployed, hardened, and can defend in an interview.
 
---
 
## Constraints (these are hard)
- **Budget:** under 20 euros per month, all in. Set an AWS Budgets alert at 15 euros before creating any billable resource.
- **Time:** 5 to 10 hours per week.
- **Timeline:** July through December 2026.
- **Lean:** security-first (DevSecOps direction), not platform/SRE-first.
### Cost discipline
EKS control plane runs about 73 dollars a month if left on. It will not be left on. Everything is in Terraform so the cluster can be created for a work session and destroyed after. Spot instances for nodes. Daily development happens on a free local kind cluster. Real EKS is only spun up when a phase needs it.
 
---
 
## The application (kept deliberately small)
A FastAPI "dependency watchdog" service:
- Accepts an SBOM upload
- Stores it in Postgres
- Checks packages against the free OSV.dev vulnerability API
- Serves a findings report
The app is real Python work (async, Pydantic, background jobs, tests) but it is not the star. The platform, pipeline, and security controls around it are the star. The nice narrative: my own pipeline generates SBOMs that my own app then analyzes.
 
---
 
## Target architecture and tooling
- **Language:** Python / FastAPI
- **Container:** multi-stage Docker
- **Local dev cluster:** kind (free)
- **Cloud:** AWS (EKS, ECR, S3, VPC, Secrets Manager)
- **IaC:** Terraform (remote state in S3, GitHub-to-AWS OIDC federation, no long-lived keys)
- **Packaging/deploy:** Helm
- **CI/CD:** GitHub Actions
- **Supply chain security:** Trivy (scan), Syft (SBOM), Cosign (image signing), Bandit, pip-audit
- **Policy enforcement:** Kyverno (block non-root, unsigned images, `latest` tags)
- **GitOps:** ArgoCD
- **Observability:** kube-prometheus-stack (Prometheus + Grafana)
- **DAST:** OWASP ZAP baseline scan in CI
- **Registry:** GitHub Container Registry (free) early, ECR later
Deliberately excluded: service mesh, multi-cloud, and any real frontend. They add weeks and no interview value at my hours.
 
---
 
## Phase plan
Each phase ends in something postable on LinkedIn and leaves the repo in a finished state. If I get hired mid-project, it still stands on its own.
 
**Phase 1 (mid-July to end of August): secure delivery pipeline.**
Build the app, Dockerfile, pytest. GitHub Actions: lint, tests, Bandit, pip-audit, Trivy, Syft SBOM, Cosign signing, push to GHCR. Write and commit a STRIDE threat model of the architecture.
 
**Phase 2 (September): Kubernetes locally + Terraform foundations.**
Helm chart deployed on kind: non-root securityContext, read-only filesystem, resource limits, probes, NetworkPolicies. Terraform basics on AWS: S3 remote state, VPC, ECR, GitHub-to-AWS OIDC.
 
**Phase 3 (October): EKS.**
Terraform module for an ephemeral EKS cluster with spot nodes. Deploy via Helm, IRSA for pod permissions, secrets via AWS Secrets Manager or SOPS, Kyverno policies. One command up, one command down, with a cost screenshot.
 
**Phase 4 (November): GitOps + observability.**
ArgoCD for deployments. kube-prometheus-stack for dashboards and alerts. ZAP baseline scan in CI against the deployed app. If time is tight, drop ArgoCD before dropping monitoring.
 
**Phase 5 (December): metrics + polish.**
Executive-style security report: vulnerabilities found and fixed, time-to-remediate, policy violations blocked, pipeline gates. Architecture diagram, full README, CV bullets, wrap-up post.
 
## CV gaps mapped to phases
- Production Kubernetes: Phases 2 and 3
- Terraform in practice: Phases 2 and 3
- Supply chain / SBOM: Phase 1
- Threat modeling: Phase 1
- Security metrics reporting: Phase 5
## LinkedIn cadence
One post per phase milestone plus optional mini-posts (threat model, cost breakdown). Target six to eight posts by December.
 
---
 
## How I want the assistant to work with me
- Plain, human, professional English. No em dashes. No AI-sounding or corporate phrasing. No flowery or emotive language. Confident and direct.
- Do not name-drop tools unless directly relevant.
- Give honest, unfiltered critical feedback. Do not soften things. Flag genuine problems and mismatches directly.
- I prefer a solid base draft I can personalize myself over multiple full rewrites.
- Keep clarifying questions minimal for straightforward requests. Use this context and produce a ready answer.
- Verify technical accuracy before including it. Do not invent tool behavior or config.
 