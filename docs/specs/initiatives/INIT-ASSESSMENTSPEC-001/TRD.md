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

The core module's library packages (`github.com/opensecurity-dev/assessment-spec`)
import only the standard library and `invopop/jsonschema`; the CLI adds
`cobra`, which a library importer does not build. The OSCAL export is a nested
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
| `cmd/assessment` | Thin cobra CLI: `validate`, `freshness`, `view`, `resolve`, `coverage` |
| `oscal` (nested module) | Export of a system's records, for one audience, to an OSCAL component definition |

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
| `mentions` | no | IDs of systems whose names appear in the artifact's content; `[]` declares none, absence declares nothing |
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

For `public` and `nda`, an artifact is excluded and listed in the view's
`withheld` set with the reason, so a reviewer can supply a redacted artifact
or a written claim instead, when:

- its `mentions` names another system (`names-other-systems`); or
- it targets a platform and has no `mentions` field at all
  (`mentions-undeclared`). A platform-wide artifact may name every system on
  the platform, so silence is not taken as "names none". An explicit empty
  list declares that it names none; the field uses `omitzero` so that Go
  writers keep the distinction.

`internal` includes every applicable artifact. Artifacts with no target apply
to no system and appear in no view. A view is built only from evidence that
passes `CheckEvidence`: targets name known systems or platforms, components
belong to their target, and mentions name known systems.

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

`controls.Resolve(scope, doc, view, baseline)` yields each control in the
baseline (supplied by the caller from a catalog; none ships here) plus the
system's added controls, in catalog order, with an effective status:

- a system record wins; `system-specific` gives its own status, `inherited`
  its sources' status, and `hybrid` the weaker of its own and its sources';
- with no system record, the system inherits implicitly from its platforms
  and its direct providers, and a platform with no record from its
  providers, so a provider record reaches every system through the platform;
- several sources give the weakest status, and `not-applicable` yields to
  any other;
- a control no record reaches is `unassessed`, never `implemented`.

Each resolved control lists the scopes that produced it (`via`) and the
weakest verification among their attestations, so a statement no person has
checked is visibly `unverified`.

A platform record is written once and appears in every system that runs on
the platform. The view decides what an audience sees:

- **Status** is always shown.
- **Prose** (statement, gap, justification) is shown only when the record's
  visibility allows and, for external audiences, when it names no other
  system by marker; otherwise it is withheld with the reason.
- **Evidence** is shown only when the system's view includes it; otherwise it
  is withheld with the view's reason, or `not-in-view`.
- **Findings** are shown only to the internal audience.

### Markers and mention detection

A system may list `markers`: distinctive strings (domains, host names,
database names, service users) of at least four characters, unique across
systems. `DetectMentions` finds them in any text, ignoring case;
`UndeclaredMentions` reads every artifact in a set and reports those whose
content names a system that the manifest's `mentions` omits, the safety net
under audience-filtered views. Resolution uses markers to withhold prose that
names another system.

## 6. Crosswalks

```json
{ "schemaVersion": "crosswalk/v1", "framework": "iso-27001-2022", "source": "operator", "license": "CC0-1.0",
  "mappings": [ { "criterion": "A.8.8", "controls": ["RA-5", "SI-2"] } ] }
```

Criteria are identifiers only; the format has no field for criterion text.
`source` and `license` are required. The repository ships no crosswalk whose
terms do not allow redistribution; it may ship crosswalks from public-domain
sources, recording the source. The example crosswalk is illustrative.

Coverage is derived from a system's resolution for one audience. A criterion
takes the weakest status among its mapped controls, not-applicable yielding
as in resolution, so it is implemented only when every mapped control is. A
mapped control outside the resolution (neither in the baseline nor in the
system's added controls) is `unassessed` and flagged `outsideBaseline`.

## 6a. OSCAL export

`oscal.ComponentDefinition(scope, controls, view, options)` writes an OSCAL
1.2.3 component definition for the view's system and audience:

- one `service` component each for the system, its platforms and its
  providers, with an implemented requirement per record at that scope;
  provider attestations become properties;
- record fields map to properties in the
  `https://github.com/opensecurity-dev/assessment-spec/ns/oscal` namespace:
  `implementation-status`, `origination`, `inherits-from`, `verification`;
  inherited and hybrid system records also carry `effective-status`, the
  status resolution gives;
- prose follows `controls.ProseWithheld`; withheld prose is replaced by a
  fixed sentence and a `prose-withheld` property with the reason; gaps and
  justifications go to remarks; evidence links only to manifests in the view;
  findings are never exported;
- UUIDs are name-based (UUIDv5 over the organization, object kind and IDs),
  and the caller supplies the catalog or profile source, last-modified time
  and version, so the same inputs give the same document.

Exports are validated against the OSCAL schema in tests. The module requires
a tagged core version once the core is released.

## 7. Schemas and conventions

- One generated schema per document type, `$id` under the repository URL,
  embedded with `//go:embed`; a test fails when an embedded schema is stale.
- `schemakit lint --property-case camelCase` on every schema in CI.
- Each document carries `schemaVersion` (e.g. `evidence-manifest/v1`);
  readers reject unknown major versions.

## 8. Open decisions

| Decision | Options | Needed by |
|---|---|---|
| OSCAL assessment results and POA&M | Export from findingspec findings referenced by records, or leave to compliance engines | After v0.1 |

Decided: the OSCAL export writes component definitions only for v0.1.
Assessment results and POA&M are built from findings, which this format
references but does not hold.

Decided: attestations use `security-docs-spec`'s verification levels
(`unverified`, `reviewed`, `verified`), so claims and records read the same.

Decided: a platform artifact without `mentions` is withheld from external
views (strict), with the reason, until its collector declares what it names
(§4).
