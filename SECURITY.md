# Security policy

Bastion is a personal portfolio project. It is a working example of a secure delivery pipeline, not a production service, and it is maintained by one person on a best-effort basis.

## Reporting a vulnerability

Please report security problems privately, not in a public issue.

Use GitHub's private reporting: open the **Security** tab of this repository, choose **Report a vulnerability**, and describe the problem. That keeps the report visible only to the maintainer until it is fixed.

Helpful things to include:

- What the problem is and where it is (file, workflow, endpoint or chart setting)
- Steps to reproduce it, or a short proof of concept
- What an attacker could do with it
- The commit or version you tested

Please do not test against systems you do not own, and do not include real secrets or personal data in a report.

## What is in scope

- The Drydock app in `app/` (API key handling, upload limits, rate limiting, input handling)
- The CI pipeline in `.github/workflows/` (for example, ways to skip a gate, leak a token or get an unsigned image published)
- The Helm chart in `deploy/helm/` and the Kyverno policies in `deploy/kyverno/`

## What is out of scope

- Issues already listed under "Known limits" in the README or marked as accepted or open in [THREAT_MODEL.md](THREAT_MODEL.md)
- The optional Terraform in `infra/terraform/`, which has never been applied to a real AWS account
- Vulnerabilities in third-party packages that have no fix available yet. Dependabot, Trivy and CodeQL already track these

## Supported versions

Only the latest commit on `main` is supported. There are no release branches.
