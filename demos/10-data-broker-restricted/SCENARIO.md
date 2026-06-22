# Demo 10 — Data broker with a recent breach (negative-polarity controls)

**Apex Data Enrichment** is a third-party data broker that would receive
**restricted** customer records to enrich. They have some controls (MFA,
encryption, IR plan) but: no SOC 2, no ISO 27001, no recent pen test, no
retention policy — and crucially they answered **"yes"** to two controls
where *yes is bad*: they **share data with third parties** and **disclosed a
breach in the last 24 months**.

This demonstrates the catalog's negative-polarity controls: for
`shares_data_with_third_parties` and `prior_breach_24mo`, a `true` answer
*adds* risk.

## Files

- `questionnaire.json` — mixed controls including two adverse "yes" answers.

## Run it

```bash
python -m vendorvet questionnaire demos/10-data-broker-restricted/questionnaire.json
```

```bash
python -m vendorvet --format json questionnaire demos/10-data-broker-restricted/questionnaire.json | jq .tier
```

## Expected outcome

Residual score **67.5/100 → HIGH** (exit code 2). The `restricted` multiplier
(x1.35) combined with missing attestations and the adverse breach/data-sharing
answers pushes this just below CRITICAL. Recommendation: **do not approve
until material gaps are remediated** — require SOC 2, a recent pen test, a
retention policy, and a full write-up of the prior breach.
