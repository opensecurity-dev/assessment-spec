# PRD — Assessment Spec: Evidence, Scope and Control Records

**Initiative:** `INIT-ASSESSMENTSPEC-001`
**Home repo:** `github.com/opensecurity-dev/assessment-spec`

## Summary

A small, framework-neutral format for the records a security assessment is
built from: the evidence a tool collected, the systems and shared platforms
that evidence is about, and how each control is implemented, inherited and
attested. Go types are the source of truth; JSON Schemas are generated from
them.

Collectors write these records; compliance engines read them and export to
FedRAMP, SOC 2, ISO 27001 or a published security document set. The format
sits between the two so that neither has to depend on the other.

The format is built for a common shape that framework formats handle poorly:
**one team running several separately marketed products on one shared
platform.** A control implemented once on the platform is inherited by every
product on it, and each product gets its own assessment, its own documents and
its own audience, without naming the others.

## Problem

- **Evidence has no shared contract.** A collector and the engine that reads
  its output agree on a manifest privately; a second collector or engine has
  to reverse-engineer it.
- **Freshness is not recorded.** A manifest that holds only a timestamp cannot
  say which tool version produced the artifact or how old its vulnerability
  database was, so a stale scanner's clean result passes as evidence.
- **Framework formats assume one system.** A FedRAMP package, a SOC 2 system
  description and an ISO 27001 Statement of Applicability each describe one
  offering. A shared platform's controls get copied into each, and drift.
- **Shared evidence leaks across products.** A platform artifact (a web server
  configuration, a database role listing, a firewall rule set) often names
  every product on the platform. Attaching it to one product's assessment
  discloses the others.
- **OSCAL is complete but heavy.** It models all of this, but is hard to write
  by hand and lacks first-class fields for tool provenance and freshness.

## Users

- **Collector authors** (scanners, agent teams, CI jobs) who write evidence
  manifests.
- **Compliance engine authors** who read evidence, scope and control records
  and export to framework formats.
- **Operators** of a small fleet who declare their platform and products once
  and want an assessment per product.

## Goals

1. **Evidence manifest:** one record per artifact with the tool, its version,
   its database date, the target, the revision, the hash and the scope it
   covers; a loader, hash verification and a freshness evaluation.
2. **Scope model:** an organization, its shared platforms, its systems
   (products) and external providers, and which systems run on which
   platforms.
3. **Per-system views:** for any system, the evidence that applies to it (its
   own, its platforms', its providers'), filtered for an audience so a public
   or NDA view never includes an artifact that names another system.
4. **Control records:** per system or platform, each control's implementation
   status, origination (system-specific, inherited, hybrid) and attestations,
   resolved into an effective status per system.
5. **Interoperability:** identifiers only for framework criteria, crosswalk
   files to map them, and an OSCAL export in a separate module so the core
   stays dependency-light.

## Non-goals

- **A compliance engine.** No framework documents are produced here; engines
  read these records and produce them.
- **Framework text.** No NIST, AICPA, ISO, CIS or CSA text is included; the
  format carries identifiers.
- **A collector.** Nothing here runs a tool.
- **Replacing findings.** Security findings use `findingspec`; records here
  reference finding IDs as strings.
- **Certification claims.** The format records self-assessed status; it has
  no field that asserts an authorization, certification or audit opinion.

## Principles

- **Go types are the source of truth.** Schemas are generated, linted with
  `schemakit` (camelCase) and embedded.
- **Minimal dependencies.** The core module imports only the standard library
  and the schema generator; identifiers are strings validated by consumers.
- **Declare once, inherit everywhere.** A platform control is recorded once;
  systems inherit it by reference, never by copy.
- **Disclosure is data.** Which systems an artifact names is recorded, so
  views can filter by audience mechanically, not by review alone.
- **Superset, not rewrite.** The first evidence manifest version reads the
  fields existing collectors already write.

## Success criteria

- An evidence manifest written by an existing collector, with only `tool`,
  `generatedAt`, `artifactPath` and `sha256`, still validates.
- A manifest whose tool database is older than its policy fails freshness with
  the reason.
- A synthetic organization with one platform and two systems produces, for
  each system, a public view containing no artifact that names the other.
- A control implemented on the platform appears as inherited in both systems'
  effective status, and changing it once changes both.
- Every schema is generated from Go types, embedded, current (a test fails if
  stale) and lint-clean.
