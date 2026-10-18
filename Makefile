# Local workflow. Everything here runs on your own machine and costs nothing.
# Needs: docker, kind, kubectl, helm. Tested on Linux and WSL2.

CLUSTER   ?= bastion
NAMESPACE ?= drydock
IMAGE     ?= ghcr.io/mtrivedii/bastion:local
CALICO    ?= https://raw.githubusercontent.com/projectcalico/calico/v3.28.2/manifests/calico.yaml

.PHONY: monitoring help test lint run image kind-up kind-down kind-load deploy undeploy kyverno policies forward demo-k8s

help:
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*## /\t/'

test: ## Run the test suite with the coverage gate
	pytest --cov --cov-fail-under=90

lint: ## ruff, bandit, pip-audit
	ruff check .
	bandit -q -r app/
	pip-audit -r requirements-dev.txt

run: ## Run the app locally with SQLite
	uvicorn app.main:app --host 127.0.0.1 --port 8000

image: ## Build the container image
	docker build -t $(IMAGE) .

kind-up: ## Create the local cluster with Calico (enforces NetworkPolicy)
	kind create cluster --config deploy/kind/kind-config.yaml
	kubectl apply -f $(CALICO)
	kubectl -n kube-system rollout status daemonset/calico-node --timeout=300s
	kubectl create namespace $(NAMESPACE) --dry-run=client -o yaml | kubectl apply -f -

kind-down: ## Delete the local cluster
	kind delete cluster --name $(CLUSTER)

kind-load: image ## Load the image into the cluster
	kind load docker-image $(IMAGE) --name $(CLUSTER)

deploy: kind-load ## Install the Helm chart
	helm upgrade --install drydock deploy/helm/drydock \
	  --namespace $(NAMESPACE) --create-namespace \
	  -f deploy/helm/drydock/values-kind.yaml --wait --timeout 5m

undeploy: ## Remove the Helm release
	helm uninstall drydock --namespace $(NAMESPACE)

kyverno: ## Install Kyverno
	helm repo add kyverno https://kyverno.github.io/kyverno/
	helm upgrade --install kyverno kyverno/kyverno --namespace kyverno --create-namespace --wait --timeout 5m

policies: ## Apply the admission policies that work offline
	kubectl apply -f deploy/kyverno/policies/disallow-latest-tag.yaml \
	  -f deploy/kyverno/policies/require-non-root.yaml \
	  -f deploy/kyverno/policies/require-hardened-container.yaml \
	  -f deploy/kyverno/policies/require-resource-limits.yaml \
	  -f deploy/kyverno/policies/restrict-image-registries.yaml

forward: ## Forward the API to http://127.0.0.1:8000
	kubectl -n $(NAMESPACE) port-forward svc/drydock 8000:80

demo-k8s: ## Run the seed-and-fix demo against the cluster (run `make forward` in another terminal)
	DRYDOCK_API_KEY=$$(kubectl -n $(NAMESPACE) get secret drydock -o jsonpath='{.data.api-key}' | base64 -d) scripts/demo.sh

monitoring: ## Install Prometheus and Grafana, plus the Drydock dashboard
	helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
	helm upgrade --install monitoring prometheus-community/kube-prometheus-stack \
	  --namespace monitoring --create-namespace -f deploy/monitoring/kube-prometheus-stack-values.yaml --wait --timeout 10m
	kubectl -n monitoring create configmap drydock-dashboard \
	  --from-file=drydock.json=deploy/monitoring/grafana-dashboard.json --dry-run=client -o yaml \
	  | kubectl label --local -f - grafana_dashboard=1 -o yaml | kubectl apply -f -
