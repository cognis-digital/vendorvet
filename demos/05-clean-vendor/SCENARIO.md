# Demo 05 — Clean, low-risk vendor (the approve path)

**Northwind Status Page** is a public-facing status/uptime service. It only
ever touches **public** data, all controls are satisfied, and its SBOM ships
fully patched dependencies (log4j-core 2.23.1, OpenSSL 3.0.13, jackson 2.17.0
— all past the affected ranges in the advisory feed).

This is the baseline you want every vendor to look like.

## Files

- `questionnaire.json` — all controls satisfied.
- `sbom.json` — patched component versions.
- `advisories.json` — the same advisory feed used elsewhere; nothing matches.

## Run it

```bash
python -m vendorvet assess demos/05-clean-vendor/questionnaire.json \
    --sbom demos/05-clean-vendor/sbom.json \
    --advisories demos/05-clean-vendor/advisories.json
```

## Expected outcome

Overall score **0.0/100 → LOW**, recommendation **"Approve. Standard annual
re-review."**, exit code **0**. The `public` data class (x0.6) keeps inherent
risk low and no vulnerable components are found. Use this as the regression
fixture for "a known-good vendor must not get flagged."
