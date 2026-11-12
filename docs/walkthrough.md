# Walkthrough: Two Products on One Platform

This walkthrough runs the CLI over [`examples/example-co`](../examples/example-co).
Example Co. sells two products, Notes and Ledger, separately. Both run on one
shared hosting platform built on a cloud provider, a CDN and a Git host.
Each product's customers should learn how their product is secured, including
the platform it shares, without learning about the other product.

Install the CLI, then run the commands from the example directory:

```bash
go install github.com/opensecurity-dev/assessment-spec/cmd/assessment@latest
cd examples/example-co
```

## 1. The scope

`scope.json` declares the organization, three providers, the
`shared-hosting` platform and the two systems. Each system has markers, the
strings that show content names it:

```json
{ "id": "notes",  "platforms": ["shared-hosting"], "markers": ["notes.example.test", "notes_db", "notes_app"],
  "addedControls": ["PT-2", "PT-3", "PT-5"] }
{ "id": "ledger", "platforms": ["shared-hosting"], "markers": ["ledger.example.test", "ledger_db", "ledger_app"] }
```

Notes handles children's data, so it adds three PT controls to its baseline.

## 2. Validate

```console
$ assessment validate --scope scope.json --evidence evidence --controls controls.json --crosswalk crosswalks/example-framework.json
scope: ok (2 systems)
evidence: 7 artifacts checked
controls: 15 records checked
crosswalk example-framework: 6 criteria checked
```

Validation also read all seven artifacts and found none that names a system
its manifest leaves out.

## 3. The evidence each audience sees

There are four platform artifacts. Their manifests say which systems they
name:

| Artifact | `mentions` | Why |
|---|---|---|
| `platform-benchmark` | `[]` | A host benchmark names no product |
| `platform-db-roles` | `["notes"]` | The role export covers Notes' database only |
| `platform-proxy-config` | `["notes", "ledger"]` | The proxy lists both host names |
| `platform-host-scan` | absent | Its collector did not say |

The public view for Notes:

```console
$ assessment view --scope scope.json --evidence evidence --system notes --audience public
```

| Included | Withheld, reason |
|---|---|
| `notes-govulncheck` | `platform-proxy-config`: `names-other-systems` (names ledger) |
| `platform-benchmark` | `platform-host-scan`: `mentions-undeclared` |
| `platform-db-roles` | |

Ledger's public view includes `ledger-govulncheck` and `platform-benchmark`,
and withholds the database roles as well, because they name Notes. The
internal view of either product includes all five artifacts that apply to it.

## 4. Controls, recorded once

`controls.json` has fifteen records: two on the cloud provider, seven on the
platform and six on the products. The platform's records are written
once and reach both products. For RA-5 the platform and Notes each record
their part:

```json
{ "control": "RA-5", "scope": "shared-hosting", "status": "partial", "origination": "system-specific",
  "gap": "Weekly re-scans of deployed releases are not yet scheduled.", "findings": ["FIND-0007"], "visibility": "nda" }
{ "control": "RA-5", "scope": "notes", "status": "implemented", "origination": "hybrid",
  "inheritsFrom": ["shared-hosting"], "visibility": "public" }
```

Resolving Notes for the public:

```console
$ assessment resolve --scope scope.json --evidence evidence --controls controls.json --baseline baseline.json --system notes --audience public
```

| Control | Status | Via | Note |
|---|---|---|---|
| AC-2 | partial | notes, shared-hosting | Hybrid: Notes' part is partial |
| AU-2 | unassessed | | Nothing records it |
| CM-6 | planned | shared-hosting | Platform prose is internal; host scan withheld |
| CP-9 | implemented | shared-hosting, example-cloud | Inherited from the provider's backups |
| IA-2 | implemented | notes | |
| PE-3 | implemented | example-cloud | Reached through the platform |
| PT-2 | implemented | notes | Added control |
| PT-3 | partial | notes | Prose is for NDA readers |
| PT-5 | unassessed | | Added, but not recorded yet |
| RA-5 | partial | notes, shared-hosting | Hybrid: weaker of implemented and partial |
| SC-7 | implemented | shared-hosting | Proxy configuration withheld: names Ledger |
| SC-8 | implemented | shared-hosting | Prose withheld: names Ledger's host |
| SI-2 | implemented | shared-hosting | Verified |

The summary is 7 implemented, 3 partial, 1 planned and 2 unassessed. Three
things to notice:

- **RA-5 is partial for the public too.** The status is never hidden. Only
  the platform's gap text, which is visible to NDA readers, is withheld.
- **SC-8 keeps its status but loses its sentence.** The platform statement
  "TLS terminates … for notes.example.test and ledger.example.test" names
  both products, so neither product's public readers see it.
- **The finding FIND-0007 appears only in the internal resolution.**

## 5. Coverage of a framework

`crosswalks/example-framework.json` maps six illustrative criteria to
controls. Ledger's coverage:

```console
$ assessment coverage --scope scope.json --evidence evidence --controls controls.json --baseline baseline.json \
    --system ledger --audience public --crosswalk crosswalks/example-framework.json
```

| Criterion | Controls | Status |
|---|---|---|
| EX-1 | AC-2, IA-2 | planned |
| EX-2 | RA-5, SI-2 | partial |
| EX-3 | SC-7, SC-8 | implemented |
| EX-4 | PE-3 | implemented |
| EX-5 | AU-2, AU-6 | unassessed |
| EX-6 | PT-2, PT-3 | unassessed, outside Ledger's baseline |

## 6. Freshness

All seven artifacts were generated at `2026-02-01T06:00:00Z`. Two and a half
days later they are past the 48-hour limit, and a required tool with no
evidence is missing:

```console
$ assessment freshness --evidence evidence --now 2026-02-03T12:00:00Z --require zap
…
    {
      "tool": "govulncheck",
      "status": "stale",
      "reason": "artifact is 54h0m0s old; limit 48h0m0s",
      "generatedAt": "2026-02-01T06:00:00Z",
      "age": "54h0m0s"
    },
…
Error: 7 tools stale or missing: check failed
```

The command exits non-zero, so a pipeline can stop before publishing stale
evidence.

## 7. OSCAL

`examples/example-co/oscal` holds the OSCAL component definitions the `oscal`
module writes for Notes (public) and Ledger (internal). In the public Notes
document, the platform's SC-8 requirement reads "Withheld for this audience."
with a `prose-withheld` property of `names-other-systems`, and RA-5 carries
both Notes' own `implementation-status` (`implemented`) and its
`effective-status` (`partial`).
