# Demo 07 — Early-stage vendor that left most controls blank

**SeedStage Labs** is a promising young vendor, but their security
questionnaire is mostly empty — they answered only 3 of 14 controls and
left the rest blank. They'd handle **confidential** data.

vendorvet treats **unanswered controls as risk** (half-weight penalty,
"unknown == risk"). An immature posture with eleven blanks is itself a
finding, even before any vulnerability scan.

## Files

- `questionnaire.json` — only `encryption_in_transit`, `mfa_enforced`, and a
  *failing* `incident_response_plan` are answered.

## Run it

```bash
python -m vendorvet questionnaire demos/07-startup-unanswered/questionnaire.json
```

List just the unanswered gaps:

```bash
python -m vendorvet --format json questionnaire demos/07-startup-unanswered/questionnaire.json \
    | jq -r '.gaps[] | select(endswith("(unanswered)"))'
```

## Expected outcome

Residual score **48.83/100 → HIGH**, exit code **2**. Each blank control
shows up in the gap list tagged `(unanswered)`. Recommendation: **do not
approve until material gaps are remediated** — i.e., send the vendor back to
complete the questionnaire and provide evidence. This shows how vendorvet
penalizes incomplete disclosure rather than rewarding it.
