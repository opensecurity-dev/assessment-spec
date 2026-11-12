# Format Reference

assessment-spec defines five JSON documents. Each has a schema generated
from its Go type, embedded in the `schema` package and published under
`https://github.com/opensecurity-dev/assessment-spec/schema/`.

| Document | File | Schema | Version |
|---|---|---|---|
| Evidence manifest | `<name>.manifest.json`, beside each artifact | `evidence-manifest.schema.json` | `evidence-manifest/v1` |
| Scope | `scope.json` | `scope.schema.json` | `scope/v1` |
| Controls | `controls.json` | `controls.schema.json` | `controls/v1` |
| Crosswalk | one file per framework | `crosswalk.schema.json` | `crosswalk/v1` |
| Baseline | one file per baseline | none | none |

Every document except the baseline may carry `schemaVersion`. A reader
assumes version 1 when it is absent and rejects any other version. Readers
reject unknown fields, so a misspelt field is an error, not a silent omission.
Times are RFC 3339. IDs are lowercase letters, digits and hyphens, starting
with a letter or digit.

## Evidence manifest

A collector writes one manifest beside each artifact, once, and never edits
it. A manifest never holds credentials.

| Field | Required | Meaning |
|---|---|---|
| `tool` | yes | The program that produced the artifact, such as `govulncheck` |
| `toolVersion` | | The tool's version |
| `generatedAt` | yes | When the artifact was produced |
| `databaseUpdatedAt` | | When the tool's vulnerability database or rule set was last updated |
| `artifactPath` | yes | The artifact file, relative to the manifest's directory, slash-separated, never leaving that directory |
| `sha256` | | Lowercase hex SHA-256 of the artifact |
| `kind` | | `sbom`, `vex`, `findings`, `scan-report`, `config-snapshot`, `benchmark`, `attestation` or `other` |
| `mediaType` | | The artifact's media type, such as `application/vnd.cyclonedx+json` |
| `target` | | What the artifact is about (below) |
| `mentions` | | IDs of the systems whose names appear in the artifact (below) |
| `controls` | | Control IDs the artifact supports, as a hint; an engine decides |

`target` names exactly one of `system` and `platform`, and optionally
`components` (IDs owned by that system or platform), `revision` and
`environment`. An artifact with no target, such as an organization-wide
secret scan, belongs to no system's view.

`mentions` has three states:

- **absent:** the collector declares nothing. A platform artifact without
  `mentions` is withheld from every external audience, because a platform-wide
  artifact may name every system on the platform.
- **`[]`:** the artifact names no system.
- **a list:** the artifact names these systems. External audiences of any
  other system do not see it.

An evidence set is a directory of manifests. Loading it validates every
manifest; `VerifyHashes` checks the artifacts against `sha256`.

## Freshness

`Freshness` takes each tool's newest artifact and reports it `fresh`, `warn`,
`stale` or `missing`. By default a tool warns at 24 hours and is stale at 48.
It is also stale when its database was more than seven days older than the
artifact: a new scan with an old database is not fresh evidence. A required
tool with no artifact is missing. Stale and missing fail the report.

## Scope

The scope says who operates what, and which products run where.

| Field | Required | Meaning |
|---|---|---|
| `organization` | yes | `id` and `name` of the operator |
| `providers` | | External services built on, and inherited from |
| `platforms` | | Shared infrastructure the organization operates |
| `systems` | yes | What an audience buys or uses; each gets its own assessment |

Providers, platforms and systems share one ID namespace, and all components
share another, so a manifest's target and mentions are unambiguous.

**Provider:** `id`, `name`, `kind` (`iaas`, `paas`, `saas`, `cdn`,
`code-host`, `other`) and `attestations`, the provider's own reports that
inherited controls rest on, such as "SOC 2 Type II report, under NDA".

**Platform:** `id`, `name`, `description`, `providers` and `components`. A
platform is never assessed alone; the systems on it inherit its controls.

**System:**

| Field | Meaning |
|---|---|
| `id`, `name`, `description` | Identity |
| `platforms` | The platforms the system runs on |
| `providers` | Providers the system uses directly, beyond its platforms' |
| `components` | Parts the system owns |
| `baseline` | `low`, `moderate` or `high`: which baseline it is assessed against |
| `addedControls` | Controls assessed beyond the baseline, such as the PT family |
| `disclosure.sharedPlatformStatement` | How external documents describe the shared platform without naming other systems |
| `markers` | Distinctive strings that show an artifact or statement names this system |

**Component:** `id`, optional `name`, and `kind` (`service`, `database`,
`host`, `network`, `storage`, `pipeline`, `other`).

### Markers

Markers are the strings that identify a system in content: domains, host
names, database names, service users. Each is at least four characters and
belongs to one system; matching ignores case. Choose strings that appear only
when the system is meant: `notes.example.test` rather than `notes`.

Markers are used twice:

- to find artifacts whose content names a system that `mentions` omits;
- to withhold a control record's prose from an external audience when it
  names another system.

A system without markers is never detected, so add them before relying on
either check.

## Views

A view is the evidence for one system and one audience. An artifact applies
when it targets the system or a platform the system runs on. Every audience
sees the system's own artifacts. Public and NDA audiences do not see:

- an artifact whose `mentions` names another system (`names-other-systems`);
- a platform artifact without `mentions` (`mentions-undeclared`).

Withheld artifacts are listed with the reason, so a reviewer can supply a
redacted artifact or a written claim instead. The internal audience sees
everything.

## Controls

A control is recorded once, on the scope that implements it.

| Field | Required | Meaning |
|---|---|---|
| `control` | yes | A NIST SP 800-53 ID, such as `AC-2` or `SC-7(5)` |
| `scope` | yes | The system, platform or provider the record is for |
| `origination` | yes | `system-specific`, `inherited` or `hybrid` |
| `status` | except inherited | `implemented`, `partial`, `planned`, `alternative` or `not-applicable` |
| `inheritsFrom` | inherited, hybrid | Platforms or providers relied on |
| `statement` | | How the control is met |
| `gap` | partial, planned | What is missing |
| `justification` | not-applicable | Why the control does not apply |
| `evidence` | | `{manifest, sha256}` references to manifests by file name |
| `findings` | | Finding IDs; shown only to the internal audience |
| `attestations` | | `{by, role, at, verification}` approvals |
| `visibility` | | Widest audience that may read the prose; defaults to `internal` |

A system may inherit from its platforms and its own providers; a platform
from its providers; a provider from nothing. There is at most one record per
control and scope.

`verification` is `unverified`, `reviewed` or `verified`, the same levels as
security-docs-spec claims. A record's verification is its strongest
attestation's, or `unverified` with none.

### Resolution

`Resolve` gives a system's effective status, for one audience, for every
control in a baseline plus the system's `addedControls`:

1. A record on the system wins. A system-specific record gives its status; an
   inherited record gives its sources' combined status; a hybrid record gives
   the weaker of its own and its sources'.
2. With no system record, the system inherits from its platforms and its own
   providers, and a platform with no record from its providers.
3. Several sources combine to the weakest status:
   `implemented` > `alternative` > `partial` > `planned` > `unassessed`.
   `not-applicable` yields to any other status.
4. A control no record reaches is `unassessed`, never `implemented`.

Each resolved control lists `via` (the records that produced it, such as
`platform:shared-hosting`) and the weakest verification among them. For an
external audience a record's prose appears only if its visibility allows and
it names no other system; evidence appears only if the view includes it;
findings never appear. What is withheld is listed with the reason.

## Crosswalk

| Field | Required | Meaning |
|---|---|---|
| `framework` | yes | Framework and edition, lowercase, such as `iso-27001-2022` |
| `source` | yes | Who made the mapping |
| `license` | yes | Terms the mapping is shared under, as SPDX or a short statement |
| `mappings` | yes | `{criterion, controls}` pairs; each criterion once |

Criteria are identifiers only. The format has no field for criterion text.

Coverage gives each criterion the weakest status among its controls, from one
system's resolution. A control outside the resolution is `unassessed` and
flagged `outsideBaseline`.

## Baseline

```json
{ "description": "NIST SP 800-53 Rev 5 Low", "controls": ["AC-1", "AC-2", "..."] }
```

A list of control IDs, supplied by the caller, for example exported from a
catalog. The system's `baseline` field says which list applies; the format
ships none.
