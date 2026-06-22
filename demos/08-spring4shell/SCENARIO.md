# Demo 08 — Good paperwork, vulnerable code (Spring4Shell)

**Orchard Commerce API** looks great on paper: the questionnaire scores
**LOW** (6.73/100, only missing ISO 27001). But their SBOM pins
`spring-beans 5.3.17` and `spring-webmvc 5.3.17`, both within the affected
range of **CVE-2022-22965 ("Spring4Shell", CVSS 9.8)** — an unauthenticated
RCE in Spring MVC on JDK 9+.

This is the scenario that justifies pairing a questionnaire with an SBOM:
self-attestation alone would have approved this vendor.

## Files

- `questionnaire.json` — near-clean control answers.
- `sbom.json` — ships vulnerable Spring components.
- `advisories.json` — your advisory feed.

## Run it

```bash
python -m vendorvet assess demos/08-spring4shell/questionnaire.json \
    --sbom demos/08-spring4shell/sbom.json \
    --advisories demos/08-spring4shell/advisories.json
```

## Expected outcome

The questionnaire alone is **LOW**, but the SBOM's CVSS 9.8 finding drives
the combined verdict to **overall score 98.0/100 → CRITICAL**, exit code
**2**. `assess` takes the **max** of questionnaire-residual and SBOM-derived
risk, so a single critical dependency overrides a clean questionnaire.
Action: reject/escalate until Spring is patched to 5.3.18+ / 5.2.20+.
