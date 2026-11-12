# Adopting assessment-spec as an Engine

An engine reads the records and produces something for an audience: a
security page, a trust portal, an auditor's package, an OSCAL document. It
never edits evidence.

## 1. Load and check everything first

```go
s, err := scope.Load("scope.json")
if err != nil {
	return err
}
if err := s.Validate(); err != nil {
	return err
}
set, err := evidence.LoadSet("evidence")
if err != nil {
	return err
}
if err := s.CheckEvidence(set); err != nil {
	return err
}
if errs := set.VerifyHashes(); len(errs) > 0 {
	return errors.Join(errs...)
}
problems, err := s.UndeclaredMentions(set)
if err != nil {
	return err
}
if len(problems) > 0 {
	return fmt.Errorf("artifacts name systems they do not declare: %v", problems)
}
doc, err := controls.Load("controls.json")
if err != nil {
	return err
}
if err := doc.Validate(s); err != nil {
	return err
}
```

Do not skip `UndeclaredMentions`. Views trust `mentions`; this check is what
catches a collector that forgot one before an external audience sees another
product's name.

## 2. Work per system and audience

Everything an engine publishes is for one system and one audience:

```go
view, err := s.NewView(set, "notes", audience.Public)
if err != nil {
	return err
}
base, err := controls.LoadBaseline("low.json")
if err != nil {
	return err
}
res, err := controls.Resolve(s, doc, view, base.Controls)
if err != nil {
	return err
}
```

Publish only what the view and the resolution contain. Both have already
removed what the audience may not see, and both list it under `withheld`
with a reason, so a reviewer can fill the gap with a redacted artifact or a
reviewed statement.

Rules an engine must keep:

- **Never combine two systems' outputs** into one external document. Each
  product is assessed and disclosed on its own.
- **Never treat `unassessed` as passing.** It means no record reaches the
  control.
- **Report verification with status.** An `implemented` control that is
  `unverified` is a self-assessment nobody has checked; say so.
- **Use the system's `sharedPlatformStatement`** when describing shared
  infrastructure, rather than naming other products.
- **Use cautious readiness language.** A resolution supports "self-assessed
  against the NIST SP 800-53 Low baseline", not certification or
  authorization claims.

## 3. Map to frameworks

A crosswalk maps a framework's criteria to controls:

```go
cw, err := crosswalk.Load("iso-27001-2022.json")
if err != nil {
	return err
}
cov, err := cw.Coverage(res)
if err != nil {
	return err
}
```

Criteria carry identifiers only. Where a framework's text is licensed, show
the identifier and point readers to the publisher. A criterion is only as
strong as its weakest control, and controls outside the system's baseline
come back `unassessed` with `outsideBaseline` set; add them to the system's
`addedControls` to assess them.

## 4. Export OSCAL

The `oscal` module writes a component definition for one system and
audience, applying the same rules:

```go
cd, err := oscal.ComponentDefinition(s, doc, view, oscal.Options{
	Source:       profileHref, // the catalog or profile the controls come from
	LastModified: lastChanged,
	Version:      "1.0.0",
})
if err != nil {
	return err
}
b, err := oscal.Marshal(cd)
```

Pass a `LastModified` that changes when the inputs change, such as the
latest commit time of the records, so the same inputs give the same file.
Assessment results and POA&M are not exported yet.

## 5. From the command line

```bash
assessment view     --scope scope.json --evidence evidence --system notes --audience public
assessment resolve  --scope scope.json --evidence evidence --controls controls.json --baseline low.json --system notes --audience nda
assessment coverage --scope scope.json --evidence evidence --controls controls.json --baseline low.json --system notes --audience public --crosswalk iso.json
```

Each prints JSON. The walkthrough shows the output for the example.
