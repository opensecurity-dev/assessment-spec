# Sources and Licensing

assessment-spec is MIT licensed and meant to be reused freely, including in
commercial tools. It therefore embeds only material whose terms allow that,
and names other frameworks by identifier only.

## What the format builds on

| Source | Terms | Used for |
|---|---|---|
| NIST SP 800-53 Rev 5 and NIST OSCAL | US government work, public domain in the US, with a CC0 1.0 waiver for the OSCAL content | Control IDs, status words, the OSCAL export |

The format carries control IDs, never control text, and ships no catalog or
baseline. A baseline file is supplied by its user.

## Crosswalks

A crosswalk holds criterion identifiers, never criterion text, and must name
its `source` and `license`. Identifiers alone are generally safe to use for
reference, but check the framework publisher's terms before you publish a
crosswalk, and keep crosswalks whose terms do not allow redistribution out
of public repositories.

This repository ships only an illustrative crosswalk for a made-up framework.

## Dependencies

| Module | Licence | Where |
|---|---|---|
| `github.com/invopop/jsonschema` | MIT | Core module, schema generation |
| `github.com/spf13/cobra` | Apache-2.0 | `cmd/assessment` only |
| `github.com/defenseunicorns/go-oscal` | Apache-2.0 | `oscal` module only |
| `github.com/google/uuid` | BSD-3-Clause | `oscal` module only |

Indirect dependencies are listed in each module's `go.sum`.
