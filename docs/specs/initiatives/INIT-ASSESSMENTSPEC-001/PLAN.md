# PLAN — Assessment Spec: Evidence, Scope and Control Records

**Initiative:** `INIT-ASSESSMENTSPEC-001`

## Approach

Start with the record two existing tools already exchange, the evidence
manifest, and make it public so a collector and an engine can share it. Then
add scope, because per-system views are what makes shared evidence usable;
then control records, which depend on both.

1. **Evidence manifest.** Types, loader, hashes, freshness, schema.
2. **Scope and views.** Platforms, systems and providers; per-system views
   filtered by audience.
3. **Control records.** Implementation records, attestations and inheritance
   resolution.
4. **Interoperability.** Crosswalk files, the OSCAL export module, a CLI.
5. **Release.** Examples, documentation, v0.1.

## Dependencies

- **`invopop/jsonschema`:** schema generation from Go types.
- **`schemakit`:** schema linting (development only).
- **`findingspec`:** referenced by ID only; not imported.
- **`go-oscal`:** in the nested `oscal` module only.

## Adoption

- A collector adopts the manifest by writing the four fields it already
  writes, then adding `toolVersion`, `databaseUpdatedAt` and `target`.
- A compliance engine adopts it by importing `evidence` in place of its own
  manifest type; the JSON is unchanged.

## Testing

- Unit tests for every validator and resolver, with an injected clock.
- A synthetic organization in `examples/` (one platform, two systems, one
  provider) with golden views per system and audience.
- Schema currency and shape tests; `schemakit` in CI.

## Risks

| Risk | Mitigation |
|---|---|
| The format grows into a second OSCAL | Fields are added only when a consumer needs them; OSCAL is an export target |
| A platform artifact discloses co-tenants | `mentions`, audience-filtered views with a withheld list, and a strictness decision |
| Inheritance hides a weak platform control | `hybrid` takes the weaker status; no record means `unassessed` |
| Framework text enters through crosswalks | Identifiers only; source and licence recorded per crosswalk |
| Breaking existing collectors | Version 1 requires only the fields they already write |
