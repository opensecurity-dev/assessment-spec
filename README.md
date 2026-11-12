# Assessment Spec

[![Go CI][go-ci-svg]][go-ci-url]
[![Go Lint][go-lint-svg]][go-lint-url]
[![Go SAST][go-sast-svg]][go-sast-url]
[![Coverage][coverage-svg]][coverage-url]
[![Docs][docs-godoc-svg]][docs-godoc-url]
[![License][license-svg]][license-url]

 [go-ci-svg]: https://github.com/opensecurity-dev/assessment-spec/actions/workflows/go-ci.yaml/badge.svg?branch=main
 [go-ci-url]: https://github.com/opensecurity-dev/assessment-spec/actions/workflows/go-ci.yaml
 [go-lint-svg]: https://github.com/opensecurity-dev/assessment-spec/actions/workflows/go-lint.yaml/badge.svg?branch=main
 [go-lint-url]: https://github.com/opensecurity-dev/assessment-spec/actions/workflows/go-lint.yaml
 [go-sast-svg]: https://github.com/opensecurity-dev/assessment-spec/actions/workflows/go-sast-codeql.yaml/badge.svg?branch=main
 [go-sast-url]: https://github.com/opensecurity-dev/assessment-spec/actions/workflows/go-sast-codeql.yaml
 [coverage-svg]: https://img.shields.io/badge/coverage-91.3%25-brightgreen
 [coverage-url]: https://github.com/opensecurity-dev/assessment-spec
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

v0.1.0. The format is versioned (`evidence-manifest/v1`, `scope/v1`,
`controls/v1`, `crosswalk/v1`); fields may still be added before v1.0.0.

- **`evidence`:** the evidence manifest, set loading, SHA-256 verification and
  freshness (artifact age and vulnerability-database age, per tool).
- **`scope`:** the scope document (providers, shared platforms, systems),
  validation of it and of evidence against it, per-system views for each
  audience, and markers that detect which systems content names.
- **`controls`:** implementation records for systems, platforms and
  providers, validated against the scope, and resolution into each system's
  effective status for an audience.
- **`crosswalk`:** framework criterion IDs mapped to control IDs, and a
  system's coverage of a framework from its resolution.
- **`audience`:** public, NDA and internal.
- **`schema`:** the generated, embedded evidence manifest, scope, controls
  and crosswalk schemas.
- **`cmd/assessment`:** a CLI to validate the documents and print views,
  resolutions, coverage and evidence freshness.
- **`oscal`** (a separate module): OSCAL component definitions per system
  and audience.

See the [CHANGELOG](CHANGELOG.md) and the
[v0.1.0 release notes](docs/releases/v0.1.0.md).

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

## Several products on one platform

A scope document declares the shared platform once and each product as a
system on it. `NewView` returns, for one system and one audience, the
evidence about that system and its platforms. For a public or NDA audience it
withholds, with the reason, any artifact that names another system, and any
platform artifact whose collector has not declared which systems it names:

```go
s, err := scope.Load("scope.json")
if err != nil {
	return err
}
view, err := s.NewView(set, "notes", audience.Public)
if err != nil {
	return err
}
for _, w := range view.Withheld {
	fmt.Println(w.Manifest, w.Reason, w.Detail) // platform-proxy-config.manifest.json names-other-systems names ledger
}
```

## Controls, recorded once

A control is recorded on the scope that implements it. A system inherits its
platforms' and providers' records unless it records the control itself; a
hybrid record takes the weaker of its own status and its sources'. A control
nothing records is `unassessed`, never `implemented`:

```go
doc, err := controls.Load("controls.json")
if err != nil {
	return err
}
res, err := controls.Resolve(s, doc, view, baseline) // baseline from a NIST SP 800-53 catalog
if err != nil {
	return err
}
for _, c := range res.Controls {
	fmt.Println(c.Control, c.Status, c.Via) // RA-5 partial [system:notes platform:shared-hosting]
}
```

For a public or NDA audience, prose is shown only when its record's
visibility allows and it names no other system; evidence only when the view
includes it; findings never.

## Framework coverage

A crosswalk maps a framework's criteria to controls, by identifier only, and
records who made the mapping and its licence:

```json
{
  "schemaVersion": "crosswalk/v1",
  "framework": "iso-27001-2022",
  "source": "operator",
  "license": "CC0-1.0",
  "mappings": [{ "criterion": "A.8.8", "controls": ["RA-5", "SI-2"] }]
}
```

`Coverage` gives each criterion the weakest status among its controls. A
control the resolution does not cover is `unassessed`; add it to the
system's `addedControls` to assess it. This repository ships no crosswalk
for a real framework.

## OSCAL

The `github.com/opensecurity-dev/assessment-spec/oscal` module writes one
system's OSCAL component definition for one audience. Each scope the system
relies on (the system itself, its platforms and its providers) becomes a
component, with an implemented requirement per record. The same audience
rules as resolution apply, and findings are never exported. Assessment
results and POA&M are not exported yet.

```go
cd, err := oscal.ComponentDefinition(s, doc, view, oscal.Options{
	Source:       profileHref,
	LastModified: lastChanged,
	Version:      "1.0.0",
})
```

## CLI

```bash
go install github.com/opensecurity-dev/assessment-spec/cmd/assessment@v0.1.0

assessment validate --scope scope.json --evidence evidence --controls controls.json --crosswalk iso.json
assessment freshness --evidence evidence --require govulncheck --require syft
assessment view     --scope scope.json --evidence evidence --system notes --audience public
assessment resolve  --scope scope.json --evidence evidence --controls controls.json --baseline low.json --system notes --audience nda
assessment coverage --scope scope.json --evidence evidence --controls controls.json --baseline low.json --system notes --audience public --crosswalk iso.json
```

`validate` also reads every artifact and fails on one that names a system its
manifest does not declare. `freshness` fails when a tool's evidence is stale
or missing. A baseline file is `{"controls": ["AC-2", ...]}`.

## Example

[`examples/example-co`](examples/example-co) has one platform, two systems,
seven artifacts, fifteen control records and an illustrative crosswalk. It
includes every system's view and resolution for every audience, plus
coverage and OSCAL exports.

## Documentation

- [Format reference](docs/format.md)
- [Adopting it as a collector](docs/collectors.md)
- [Adopting it as an engine](docs/engines.md)
- [Walkthrough: two products on one platform](docs/walkthrough.md)
- [Sources and licensing](docs/licensing.md)

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
go test ./scope ./controls ./crosswalk -update    # after a deliberate change to the example
(cd oscal && go test ./...)                       # the OSCAL module; -update rewrites its golden exports
for f in schema/*.schema.json; do schemakit lint --property-case camelCase "$f"; done
```

## License

MIT
