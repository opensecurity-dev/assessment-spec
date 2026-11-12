# Adopting assessment-spec as a Collector

A collector is anything that produces evidence: a scanner wrapper, a CI job,
an agent team. It writes one artifact and one manifest per run and never
edits either afterwards.

## 1. Write the artifact, then the manifest

Write the tool's output as it is, then a manifest beside it named
`<name>.manifest.json`:

```json
{
  "schemaVersion": "evidence-manifest/v1",
  "tool": "govulncheck",
  "toolVersion": "v1.1.4",
  "generatedAt": "2026-02-01T06:00:00Z",
  "databaseUpdatedAt": "2026-01-31T22:10:00Z",
  "artifactPath": "notes-govulncheck.json",
  "sha256": "…",
  "kind": "findings",
  "mediaType": "application/json",
  "target": { "system": "notes", "revision": "v1.4.2", "environment": "prod" },
  "mentions": [],
  "controls": ["RA-5", "SI-2"]
}
```

In Go, build an `evidence.Manifest`, compute the hash with
`evidence.HashFile`, and check it with `Manifest.Validate` before writing.

Rules that are easy to miss:

- **`generatedAt` is when the tool ran,** not when the file was copied.
- **Record `databaseUpdatedAt`** for any tool with a vulnerability database
  or rule set. Without it, freshness cannot tell a new scan with an old
  database from a current one.
- **Never put credentials, tokens or command lines** in a manifest. Redact
  them from the artifact too; manifests and artifacts are meant to be shared.
- **`artifactPath` is relative** to the manifest's directory and may not
  leave it.

## 2. Target the right scope

Use the IDs from the organization's scope document.

- Evidence about one product targets its `system`.
- Evidence about shared infrastructure, such as a host benchmark, a proxy
  configuration or database roles, targets the `platform`. Name
  `components` when the artifact covers only some of them.
- Organization-wide evidence, such as a secret scan across all repositories,
  has no target. It supports controls but appears in no system's view.

## 3. Declare mentions

`mentions` decides which audiences may see a platform artifact, so declare it
deliberately:

- `[]` when the artifact names no system. A host benchmark usually names
  none.
- The system IDs it names, when it names some. A reverse-proxy
  configuration that lists every product's host name names them all.
- Omit the field only when the collector cannot tell. External audiences
  then never see the platform artifact.

The organization's markers back this up: `assessment validate` reads every
artifact and fails on one that names a system its `mentions` omits. A
collector that knows the markers can run the same check before writing, with
`Scope.DetectMentions`.

## 4. Keep evidence fresh

Engines judge freshness per tool, from the newest artifact. Run collectors on
a schedule shorter than the freshness limit (48 hours by default) and keep
earlier runs if your retention policy wants them; only the newest counts.

## 5. Check your output

```bash
assessment validate  --scope scope.json --evidence evidence
assessment freshness --evidence evidence --require govulncheck --require syft
```

`validate` checks each manifest against the scope, the artifact hashes and
undeclared mentions. `freshness` fails when a required tool's evidence is
stale or missing.
