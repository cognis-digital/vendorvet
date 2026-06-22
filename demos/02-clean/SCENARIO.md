# Demo 02 — Fully-attested vendor (zero gaps)

**Harbor CDN** answered every control satisfactorily for an `internal`-data
engagement. There are no gaps and no adverse answers — the expected clean
baseline.

## Files

- `questionnaire.json` — all 14 controls answered and satisfied.

## Run it

```bash
python -m vendorvet questionnaire demos/02-clean/questionnaire.json
```

## Expected outcome

Residual score **0.0/100 → LOW**, no gaps, exit code **0**. Recommendation:
**approve, standard annual re-review**.
