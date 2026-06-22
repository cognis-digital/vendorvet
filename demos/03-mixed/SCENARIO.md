# Demo 03 — Mixed posture (approve with conditions)

**Cobalt Marketing Suite** would process `confidential` data. They hold a
SOC 2 Type II and encrypt everything, but they have a handful of real gaps:
no ISO 27001, **no MFA**, no recent pen test, no security-awareness training,
and they **share data with third parties**.

A common real-world mid-tier vendor: not a reject, not a clean approve.

## Files

- `questionnaire.json` — mixed control answers.

## Run it

```bash
python -m vendorvet questionnaire demos/03-mixed/questionnaire.json
```

## Expected outcome

Residual score **37.04/100 → MODERATE**, exit code **0**. Recommendation:
**approve with conditions; track remediation of gaps** — prioritize
enforcing MFA and scheduling an independent pen test.
