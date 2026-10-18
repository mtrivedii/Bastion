# Runbook: run Bastion from zero, for free

You do not need AWS or an existing Kubernetes cluster. Everything below runs on your own computer. Nothing here costs money.

The EKS path at the bottom is optional, costs money, and is never started by anything in this repository.

## 1. What you need on your computer

- Docker (Docker Desktop on Windows or macOS, or Docker Engine on Linux). On Windows use WSL2.
- `kubectl`, `helm`, `kind`, `make`, `curl`, `jq`.

Check they work: `docker version`, `kubectl version --client`, `helm version`, `kind version`.

## 2. Run the app without Kubernetes (fastest)

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
make test
make run
```

In another terminal:

```bash
scripts/demo.sh
```

The demo uploads a vulnerable SBOM, scans it, uploads a fixed one, scans again and checks the old findings are marked resolved. It needs internet access, because Drydock asks api.osv.dev about each package.

## 3. Run it in a local Kubernetes cluster

```bash
make kind-up      # creates the cluster and installs Calico, which enforces NetworkPolicy
make deploy       # builds the image, loads it into the cluster, installs the Helm chart
make forward      # leave this running; the API is now at http://127.0.0.1:8000
```

In another terminal: `make demo-k8s`.

The chart generates an API key and a database password on first install. To read the key:

```bash
kubectl -n drydock get secret drydock -o jsonpath='{.data.api-key}' | base64 -d
```

Note: the default network policy only lets the pod talk to DNS, HTTPS (for api.osv.dev) and its database. If scans fail on your machine, check `kubectl -n drydock logs deploy/drydock`.

## 4. Add admission policies (Kyverno)

```bash
make kyverno
make policies
```

Try to run an unsafe pod and watch it be refused:

```bash
kubectl run bad --image=nginx:latest
```

`verify-image-signature.yaml` is not applied by `make policies`. It checks the Cosign signature that CI attaches to the image in GHCR, so it only makes sense once you deploy that published image instead of the locally built one.

## 5. Add monitoring

```bash
make monitoring
```

This installs Prometheus and Grafana. Turn on scraping in the chart and open Grafana:

```bash
helm upgrade drydock deploy/helm/drydock -n drydock --reuse-values --set monitoring.enabled=true
kubectl -n monitoring port-forward svc/monitoring-grafana 3000:80
```

Log in at http://127.0.0.1:3000 as `admin` with the password from `deploy/monitoring/kube-prometheus-stack-values.yaml`. The "Drydock" dashboard is already loaded.

## 6. GitOps with Argo CD (optional)

```bash
kubectl create namespace argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
kubectl apply -f deploy/argocd/application.yaml
```

Argo CD then keeps the cluster in line with `deploy/helm/drydock` on `main`. The chart's default image comes from GHCR, so on kind set `image.pullPolicy`/`image.tag` in the Application to match what you loaded, or push the image and let it pull.

## 7. Clean up

```bash
make kind-down
```

## 8. Optional: a real cluster on AWS (costs money)

You do not need this to use or show Bastion. Read this fully before you decide.

- EKS charges for the control plane every hour, even when idle. Add two worker nodes and a NAT gateway and a month of running costs well over 100 USD, far more than the 20 EUR budget this project aims for.
- The budget alert in `infra/terraform` emails you at 80 percent of the limit but does not stop anything.
- Create an AWS account, enable MFA on the root user, and create an IAM user or role for Terraform. Do not use root keys.
- Then: `cd infra/terraform && cp terraform.tfvars.example terraform.tfvars`, edit it, run `terraform init`, `terraform plan`, read the plan, and only then `terraform apply`.
- When you are done, `terraform destroy`. Check the AWS billing page afterwards.

CI only runs `terraform validate` and a Trivy scan on this folder. It never applies anything.
