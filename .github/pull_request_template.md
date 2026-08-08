## Summary

Describe the user-visible change and why it is needed.

## Validation

- [ ] `go test -race ./...`
- [ ] `go vet ./...`
- [ ] Docker changes were built or smoke-tested
- [ ] Helm changes pass `helm lint` and `helm template`
- [ ] Dashboard changes were validated

## Exporter compatibility

- [ ] The change only uses read-only SafeLine APIs
- [ ] Metric names, types, labels and stale-data behavior remain compatible, or the breaking change is documented
- [ ] API calls remain bounded by the configured request and scrape timeouts and pagination cap
- [ ] No API token, production URL, source IP, payload or production configuration is committed
