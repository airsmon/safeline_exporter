# Production deployment

Copy the public example to the ignored production values file, then replace the
example address, image and selector labels for the target cluster:

```bash
cp ./deploy/production-values.example.yaml ./deploy/production-values.yaml
```

Create the SafeLine API-token Secret separately. Do not place the token in the
values file or pass it with `--set-string`, because Helm stores release values:

```bash
kubectl -n monitoring create secret generic safeline-exporter \
  --from-file=api-token=/path/to/safeline-token-file
```

Install or upgrade from the repository root:

```bash
helm lint ./charts/safeline-exporter \
  -f ./deploy/production-values.yaml \
  --set-file grafanaDashboard.content=./grafana/safeline-exporter-overview.json

helm upgrade --install safeline-exporter ./charts/safeline-exporter \
  --namespace monitoring \
  -f ./deploy/production-values.yaml \
  --set-file grafanaDashboard.content=./grafana/safeline-exporter-overview.json \
  --rollback-on-failure --wait --timeout 10m
```

Use an immutable image tag or digest from a registry reachable by every cluster
node. The CI workflow publishes multi-architecture images to this repository's
GitHub Container Registry package.

Check the release:

```bash
kubectl -n monitoring rollout status deployment/safeline-exporter --timeout=5m
kubectl -n monitoring get pod,service,servicemonitor,configmap \
  -l app.kubernetes.io/instance=safeline-exporter
helm -n monitoring status safeline-exporter
```

Review history and roll back when necessary:

```bash
helm -n monitoring history safeline-exporter
helm -n monitoring rollback safeline-exporter REVISION --wait --timeout 10m
```

After replacing the external Secret, restart the Deployment so the process
receives the new environment variable:

```bash
kubectl -n monitoring rollout restart deployment/safeline-exporter
```
