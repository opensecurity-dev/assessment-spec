# TRD — Assessment Spec: Evidence, Scope and Control Records

**Initiative:** `INIT-ASSESSMENTSPEC-001`
**Home repo:** `github.com/opensecurity-dev/assessment-spec`

Technical design for [PRD.md](PRD.md). Process is in [PLAN.md](PLAN.md); work
items are in [ROADMAP.md](ROADMAP.md).

## 1. Position

```text
collectors (scanners, agent teams, CI)
        │ write
        ▼
assessment-spec        evidence manifests · scope · control records   (THIS)
findingspec            security findings and exceptions
        │ read
        ▼
compliance engines ──► FedRAMP · SOC 2 · ISO 27001 · security-docs-spec · OSCAL
```

The core module (`github.com/opensecurity-dev/assessment-spec`) depends only
on the standard library and `invopop/jsonschema`. The OSCAL export is a nested
module (`.../assessment-spec/oscal`) so that its dependencies do not reach
collectors.

## 2. Packages

| Package | Responsibility |
|---|---|
| `evidence` | `Manifest`, `LoadSet`, `VerifyHashes`, `Freshness` |
| `scope` | `Scope` document: organization, platforms, systems, providers; validation; `View` per system and audience |
| `controls` | `Implementation` records, `Attestation`, inheritance resolution into effective status per system |
| `crosswalk` | Crosswalk files: framework criterion IDs to control IDs, identifiers only |
| `audience` | `public`, `nda`, `internal`, ordered, with the same meaning as in `security-docs-spec` |
| `schema` | Generated, embedded schemas: `evidence-manifest`, `scope`, `controls`, `crosswalk` |
| `cmd/assessment` | Thin cobra CLI: `validate`, `freshness`, `view` |
| `oscal` (nested module) | Export of a system's resolved view to OSCAL component definitions, assessment results and POA&M |

## 3. Evidence manifest

One `<name>.manifest.json` beside each artifact, written once by the
collector and never edited.

| Field | Required | Meaning |
|---|---|---|
| `tool` | yes | The program that produced the artifact (`govulncheck`, `syft`, `powerpipe`) |
| `generatedAt` | yes | RFC 3339 time the artifact was produced |
| `artifactPath` | yes | The artifact, relative to the manifest's directory |
| `sha256` | no | Lowercase hex SHA-256 of the artifact |
| `toolVersion` | no | The tool's version string |
| `databaseUpdatedAt` | no | RFC 3339 time of the tool's vulnerability database or rule set, when it has one |
| `kind` | no | `sbom`, `vex`, `findings`, `scan-report`, `config-snapshot`, `benchmark`, `attestation`, `other` |
| `mediaType` | no | e.g. `application/vnd.cyclonedx+json` |
| `target` | no | `system` or `platform` ID, `components`, `revision`, `environment` |
| `mentions` | no | IDs of systems whose names appear in the artifact's content |
| `controls` | no | Control IDs the artifact supports, as a hint; engines decide |

The four required fields are the fields existing collectors already write;
every addition is optional, so version 1 reads their output unchanged.

A manifest never holds credentials. Collectors that record a command line
redact it first; the format has no `command` field for this reason.

### Freshness

`Set.Freshness(now, policy, required...)` reports per tool:

- `fresh`, `warn` or `stale` by artifact age against the tool's thresholds
  (policy default, per-tool override);
- `stale` when `databaseUpdatedAt` is older than the tool's database limit,
  with the reason, even if the artifact itself is new;
- `missing` for a required tool with no artifact.

`stale` and `missing` fail the report. The clock is injected.

## 4. Scope

One `scope.json` per organization.

```json
{
  "organization": { "id": "example-co", "name": "Example Co." },
  "providers": [
    { "id": "cloud", "name": "Example Cloud", "kind": "iaas", "attestations": ["SOC 2 Type II report, under NDA"] }
  ],
  "platforms": [
    {
      "id": "shared-hosting",
      "name": "Shared hosting platform",
      "providers": ["cloud"],
      "components": [
        { "id": "web-proxy", "kind": "service" },
        { "id": "db-server", "kind": "database" }
      ]
    }
  ],
  "systems": [
    {
      "id": "notes",
      "name": "Notes",
      "platforms": ["shared-hosting"],
      "components": [{ "id": "notes-app", "kind": "service" }],
      "baseline": "low",
      "addedControls": ["PT-2", "PT-3"],
      "disclosure": {
        "sharedPlatformStatement": "Runs on infrastructure the company operates for its own products, isolated per product at the database and process level."
      }
    },
    { "id": "ledger", "name": "Ledger", "platforms": ["shared-hosting"], "components": [{ "id": "ledger-app", "kind": "service" }], "baseline": "low" }
  ]
}
```

- **Systems** are what an audience buys: each gets its own assessment and its
  own document set. **Platforms** are operated by the same team and shared;
  they are never assessed alone. **Providers** are external and supply
  inherited controls and their own attestations.
- A system may add controls to its baseline (`addedControls`), for example the
  PT family for a system that handles children's data.
- `disclosure.sharedPlatformStatement` is how a system's public documents
  describe the shared platform without naming other systems. Sharing is
  material to an assessment and is stated; the co-tenants are not.

### Views

`scope.View(scope, evidence, systemID, audience)` returns the artifacts that
apply to a system:

1. artifacts whose `target` is the system;
2. artifacts whose `target` is a platform the system runs on;
3. provider attestations for those platforms.

For `public` and `nda`, any artifact whose `mentions` names another system is
excluded and listed in the view's `withheld` set with the reason, so a
reviewer can supply a redacted artifact or a written claim instead. `internal`
includes everything. An artifact with no `mentions` field is treated as naming
no system; collectors of platform-wide artifacts are expected to set it.

## 5. Control records

`controls.json` per organization holds implementation records:

| Field | Meaning |
|---|---|
| `control` | Control ID (`AC-2`, `SC-7(5)`) |
| `scope` | A system or platform ID |
| `status` | OSCAL implementation-status words: `implemented`, `partial`, `planned`, `alternative`, `not-applicable` |
| `origination` | `system-specific`, `inherited`, `hybrid` |
| `inheritsFrom` | Platform or provider IDs, for `inherited` and `hybrid` |
| `statement` | How the control is met, as reviewed prose |
| `gap` | Required when `partial` or `planned` |
| `justification` | Required when `not-applicable` |
| `evidence` | Manifest references (artifact path or hash) |
| `findings` | `findingspec` finding IDs that bear on it |
| `attestations` | Who approved the statement, when, and at what verification level |
| `visibility` | `public`, `nda` or `internal`; default `internal` |

`controls.Resolve(scope, records, systemID)` yields each control in the
system's baseline plus its added controls, with an effective status:

- a system record wins over an inherited one;
- `inherited` takes the platform's (or provider's) status;
- `hybrid` takes the weaker of the system's and the platform's status;
- a control with no record is `unassessed`, never `implemented`.

A platform record is written once and appears in every system that runs on the
platform. A finding on a platform component appears in every such system's
resolved view, subject to the same `mentions` filtering as evidence.

## 6. Crosswalks

```json
{ "framework": "iso-27001-2022", "source": "operator", "mappings": [ { "criterion": "A.8.8", "controls": ["RA-5", "SI-2"] } ] }
```

Criteria are identifiers only. The repository ships no crosswalk whose terms
do not allow redistribution; it may ship crosswalks from public-domain
sources, recording the source.

## 7. Schemas and conventions

- One generated schema per document type, `$id` under the repository URL,
  embedded with `//go:embed`; a test fails when an embedded schema is stale.
- `schemakit lint --property-case camelCase` on every schema in CI.
- Each document carries `schemaVersion` (e.g. `evidence-manifest/v1`);
  readers reject unknown major versions.

## 8. Open decisions

| Decision | Options | Needed by |
|---|---|---|
| `mentions` when absent on a platform artifact | Treat as naming no system (lenient), or withhold from public views until set (strict) | `RMI-ASSESSMENTSPEC-007` |
| Attestation verification levels | Reuse `security-docs-spec` levels, or define a smaller set here | `RMI-ASSESSMENTSPEC-011` |
| OSCAL export scope | Component definitions only, or also assessment results and POA&M | `RMI-ASSESSMENTSPEC-016` |
