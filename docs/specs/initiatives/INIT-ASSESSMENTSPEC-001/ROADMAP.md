# ROADMAP — Assessment Spec: Evidence, Scope and Control Records

**Initiative:** `INIT-ASSESSMENTSPEC-001`
**Repository:** `github.com/opensecurity-dev/assessment-spec`

Specs: [PRD](PRD.md), [TRD](TRD.md), [PLAN](PLAN.md). Items carry stable IDs,
are reviewed and executed by phase, and commits implementing one carry
`Refs: RMI-<REPOSLUG>-<NNN>`. Phase status is derived from its items.

## Phase 1 — Evidence Manifest

**Theme:** The record collectors and engines already exchange, public and with provenance.

- [ ] `RMI-ASSESSMENTSPEC-001` Module scaffold: MIT licence, README, CI (build, tests, golangci-lint, CodeQL), lint configuration
- [x] `RMI-ASSESSMENTSPEC-002` Evidence manifest types and validation: required tool, generatedAt and artifactPath; optional provenance, target, mentions and control hints
  - Depends on: `RMI-ASSESSMENTSPEC-001`
- [x] `RMI-ASSESSMENTSPEC-003` Evidence set loader and SHA-256 verification
  - Depends on: `RMI-ASSESSMENTSPEC-002`
- [x] `RMI-ASSESSMENTSPEC-004` Freshness: per-tool thresholds, database age limits, missing required tools, injected clock
  - Depends on: `RMI-ASSESSMENTSPEC-003`
- [x] `RMI-ASSESSMENTSPEC-005` Generated evidence-manifest schema: embedded, currency test, `schemakit` camelCase lint
  - Depends on: `RMI-ASSESSMENTSPEC-002`

## Phase 2 — Scope & Per-System Views

**Theme:** Several products on one platform, each assessed on its own.

- [ ] `RMI-ASSESSMENTSPEC-006` Scope types: organization, providers, platforms, systems, components, baselines, added controls, disclosure; referential validation
  - Depends on: `RMI-ASSESSMENTSPEC-002`
- [ ] `RMI-ASSESSMENTSPEC-007` Audience-filtered views: a system's own, platform and provider evidence, with artifacts naming other systems withheld from public and NDA views and listed with the reason
  - Depends on: `RMI-ASSESSMENTSPEC-006`
- [ ] `RMI-ASSESSMENTSPEC-008` Generated scope schema with currency and lint tests
  - Depends on: `RMI-ASSESSMENTSPEC-006`
- [ ] `RMI-ASSESSMENTSPEC-009` Synthetic example organization: one platform, two systems, one provider, golden views per system and audience
  - Depends on: `RMI-ASSESSMENTSPEC-007`
- [ ] `RMI-ASSESSMENTSPEC-010` Audience type shared in meaning with `security-docs-spec`: public, NDA, internal
  - Depends on: `RMI-ASSESSMENTSPEC-001`

## Phase 3 — Control Records & Inheritance

**Theme:** A control implemented once on the platform is inherited by every system on it.

- [ ] `RMI-ASSESSMENTSPEC-011` Control implementation and attestation types: status, origination, inheritance, statement, gap, justification, evidence and finding references
  - Depends on: `RMI-ASSESSMENTSPEC-006`
- [ ] `RMI-ASSESSMENTSPEC-012` Inheritance resolution: effective status per system, hybrid takes the weaker status, no record is unassessed
  - Depends on: `RMI-ASSESSMENTSPEC-011`
- [ ] `RMI-ASSESSMENTSPEC-013` Findings and evidence in the resolved view, with the same mentions filtering as evidence
  - Depends on: `RMI-ASSESSMENTSPEC-012`
  - Depends on: `RMI-ASSESSMENTSPEC-007`
- [ ] `RMI-ASSESSMENTSPEC-014` Generated controls schema with currency and lint tests
  - Depends on: `RMI-ASSESSMENTSPEC-011`

## Phase 4 — Interoperability

**Theme:** Framework criteria by identifier, OSCAL as an export, and a CLI.

- [ ] `RMI-ASSESSMENTSPEC-015` Crosswalk files: criterion IDs to control IDs, with source and licence recorded; coverage of a framework from a resolved view
  - Depends on: `RMI-ASSESSMENTSPEC-012`
- [ ] `RMI-ASSESSMENTSPEC-016` OSCAL export as a nested module over `go-oscal`: component definitions from platform and system records
  - Depends on: `RMI-ASSESSMENTSPEC-012`
- [ ] `RMI-ASSESSMENTSPEC-017` `assessment` CLI: `validate`, `freshness`, `view --system --audience`
  - Depends on: `RMI-ASSESSMENTSPEC-007`
  - Depends on: `RMI-ASSESSMENTSPEC-004`

## Phase 5 — Release

**Theme:** Usable by a collector and an engine that did not write it.

- [ ] `RMI-ASSESSMENTSPEC-018` Documentation: format reference, adoption guide for collectors and engines, multi-product walkthrough
  - Depends on: `RMI-ASSESSMENTSPEC-009`
- [ ] `RMI-ASSESSMENTSPEC-019` v0.1 release: CHANGELOG, coverage badge, publication scan, tag after CI passes
  - Depends on: `RMI-ASSESSMENTSPEC-018`
