# Demo 04 — Payroll SaaS handling restricted PII

Your finance team wants to adopt **PayStream HR**, a payroll/HRIS SaaS that
would process employee SSNs, bank details, and compensation — **restricted**
data. The vendor returned a strong questionnaire: SOC 2 Type II, ISO 27001,
MFA, annual pen test, encryption everywhere.

Two things still stand out: there is **no contractual breach-notification
SLA**, and the vendor **shares customer data with third parties** without
publishing a subprocessor list.

## Files

- `questionnaire.json` — the vendor's completed control answers.

## Run it

```bash
python -m vendorvet questionnaire demos/04-payroll-saas/questionnaire.json
```

Machine-readable for your GRC tracker:

```bash
python -m vendorvet --format json questionnaire demos/04-payroll-saas/questionnaire.json | jq '{tier, residual_score, gaps}'
```

## Expected outcome

Residual score **26.18/100 → MODERATE** (exit code 0). The `restricted`
data classification (x1.35 inherent multiplier) amplifies otherwise small
gaps. The verdict: **approve with conditions** — get a breach-notification
SLA into the contract and request the subprocessor list before go-live.
This is the common "good vendor, fix the paper" outcome a TPRM program sees
most often.
