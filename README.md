# Assessment Spec

[![Go CI][go-ci-svg]][go-ci-url]
[![Go Lint][go-lint-svg]][go-lint-url]
[![Go SAST][go-sast-svg]][go-sast-url]
[![Docs][docs-godoc-svg]][docs-godoc-url]
[![License][license-svg]][license-url]

 [go-ci-svg]: https://github.com/opensecurity-dev/assessment-spec/actions/workflows/go-ci.yaml/badge.svg?branch=main
 [go-ci-url]: https://github.com/opensecurity-dev/assessment-spec/actions/workflows/go-ci.yaml
 [go-lint-svg]: https://github.com/opensecurity-dev/assessment-spec/actions/workflows/go-lint.yaml/badge.svg?branch=main
 [go-lint-url]: https://github.com/opensecurity-dev/assessment-spec/actions/workflows/go-lint.yaml
 [go-sast-svg]: https://github.com/opensecurity-dev/assessment-spec/actions/workflows/go-sast-codeql.yaml/badge.svg?branch=main
 [go-sast-url]: https://github.com/opensecurity-dev/assessment-spec/actions/workflows/go-sast-codeql.yaml
 [docs-godoc-svg]: https://pkg.go.dev/badge/github.com/opensecurity-dev/assessment-spec
 [docs-godoc-url]: https://pkg.go.dev/github.com/opensecurity-dev/assessment-spec
 [license-svg]: https://img.shields.io/badge/license-MIT-blue.svg
 [license-url]: https://github.com/opensecurity-dev/assessment-spec/blob/main/LICENSE

A framework-neutral format for the records a security assessment is built
from: the evidence a tool collected, the systems and shared platforms it is
about, and how each control is implemented, inherited and attested.

Collectors write these records. Compliance engines read them and export to
FedRAMP, SOC 2, ISO 27001, OSCAL or a published security document set.

It is built for one team running several separately marketed products on one
shared platform: a platform control is recorded once and inherited by each
product, and each product gets its own assessment and audience without naming
the others.

## Status

Early development. Available now:

- **`evidence`:** the evidence manifest, set loading, SHA-256 verification and
  freshness (artifact age and vulnerability-database age, per tool).
- **`schema`:** the generated, embedded evidence manifest schema.

Scope and per-system views, control records with inheritance, crosswalks and
an OSCAL export follow; see the
[roadmap](docs/specs/initiatives/INIT-ASSESSMENTSPEC-001/ROADMAP.md).

## Evidence manifest

A collector writes `<name>.manifest.json` beside each artifact:

```json
{
  "schemaVersion": "evidence-manifest/v1",
  "tool": "govulncheck",
  "toolVersion": "v1.9.0",
  "generatedAt": "2026-01-09T12:00:00Z",
  "databaseUpdatedAt": "2026-01-09T00:00:00Z",
  "artifactPath": "govulncheck.json",
  "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
  "kind": "findings",
  "target": { "system": "notes", "revision": "v1.4.2", "environment": "prod" },
  "controls": ["RA-5", "SI-2"]
}
```

Only `tool`, `generatedAt` and `artifactPath` are required. A manifest never
holds credentials.

```go
set, err := evidence.LoadSet("evidence/notes/v1.4.2")
if err != nil {
	return err
}
if errs := set.VerifyHashes(); len(errs) > 0 {
	return errors.Join(errs...)
}
report, err := set.Freshness(time.Now(), evidence.DefaultPolicy(), "govulncheck", "syft")
if err != nil {
	return err
}
if !report.OK() {
	return fmt.Errorf("stale or missing evidence: %v", report.Failing())
}
```

A scan run with an out-of-date vulnerability database is stale even when the
scan itself is new.

## Specifications

- [PRD](docs/specs/initiatives/INIT-ASSESSMENTSPEC-001/PRD.md)
- [TRD](docs/specs/initiatives/INIT-ASSESSMENTSPEC-001/TRD.md)
- [PLAN](docs/specs/initiatives/INIT-ASSESSMENTSPEC-001/PLAN.md)
- [ROADMAP](docs/specs/initiatives/INIT-ASSESSMENTSPEC-001/ROADMAP.md)

## Development

```bash
go test ./...
golangci-lint run
go generate ./schema
schemakit lint --property-case camelCase schema/evidence-manifest.schema.json
```

## License

MIT
