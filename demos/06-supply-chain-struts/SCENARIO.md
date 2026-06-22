# Demo 06 — SBOM-only supply-chain check (Apache Struts RCE)

A vendor (**LegacyDocs Portal**) hasn't returned a questionnaire yet, but
they did hand over a CycloneDX SBOM. Before scheduling the security review,
you run a quick dependency cross-reference against your advisory feed.

The SBOM pins `struts2-core 2.5.10`, which is within the affected range of
**CVE-2017-5638** (the Apache Struts Jakarta-multipart RCE, CVSS 10.0 — the
same class of flaw behind the 2017 Equifax breach).

## Files

- `sbom.json` — the vendor's component list (no questionnaire needed).
- `advisories.json` — your local known-vulnerability feed.

## Run it

```bash
python -m vendorvet sbom demos/06-supply-chain-struts/sbom.json \
    demos/06-supply-chain-struts/advisories.json
```

Export as SARIF to attach to the vendor's ticket / code-scanning dashboard:

```bash
python -m vendorvet --format sarif sbom demos/06-supply-chain-struts/sbom.json \
    demos/06-supply-chain-struts/advisories.json > struts.sarif
```

## Expected outcome

One vulnerable component: **struts2-core@2.5.10 → CVE-2017-5638, CVSS 10.0
(critical)**. The `sbom` subcommand exits **2** on high/critical severity, so
this fails any CI gate. Note that `commons-fileupload 1.3.2` is *not* flagged
— it sits above the affected range — demonstrating exact-version matching.
Action: block onboarding until Struts is upgraded.
