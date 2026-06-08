# Demo 01 - Basic vendor vetting

A growing SMB is evaluating **Acme Analytics**, a SaaS vendor that will
process **confidential** customer data. Procurement collected a security
questionnaire and the vendor's SBOM.

## Files

- `questionnaire.json` - the vendor's answers to the security control set.
- `sbom.json` - CycloneDX-lite component list from the vendor.
- `advisories.json` - the SMB's local known-vulnerability feed.

## Run it

Score just the questionnaire:

```
python -m vendorvet questionnaire demos/01-basic/questionnaire.json
```

Cross-reference the SBOM against the advisory feed:

```
python -m vendorvet sbom demos/01-basic/sbom.json demos/01-basic/advisories.json
```

Full combined verdict (machine-readable):

```
python -m vendorvet --format json assess demos/01-basic/questionnaire.json \
    --sbom demos/01-basic/sbom.json --advisories demos/01-basic/advisories.json
```

## Expected outcome

Acme has MFA disabled, no recent pen test, and ships a log4j-core version
with CVE-2021-44228 (CVSS 10.0). The SBOM critical vuln dominates the
verdict, so the overall tier is **CRITICAL** and the tool exits with code 2
("Reject / escalate"). This is the signal a procurement gate should block on.
