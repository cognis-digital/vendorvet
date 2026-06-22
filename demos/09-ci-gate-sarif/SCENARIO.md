# Demo 09 — CI gate with SARIF upload to code scanning

You vet vendors in CI. On every change to your vendor registry, a pipeline
runs vendorvet and **uploads the findings to GitHub code scanning** so they
appear in the Security tab and annotate the PR.

**Meridian Logging Cloud** has a near-clean questionnaire (one MFA gap) but
ships `log4j-core 2.15.0` — affected by **CVE-2021-45046 (CVSS 9.0)**, the
incomplete-fix follow-up to Log4Shell — plus a medium Netty DoS
(**CVE-2023-34462**).

## Files

- `questionnaire.json`, `sbom.json`, `advisories.json` — the assessment inputs.

## Run it

Human-readable verdict + CI exit code:

```bash
python -m vendorvet assess demos/09-ci-gate-sarif/questionnaire.json \
    --sbom demos/09-ci-gate-sarif/sbom.json \
    --advisories demos/09-ci-gate-sarif/advisories.json
```

Emit SARIF 2.1.0 for the Security tab:

```bash
python -m vendorvet --format sarif assess demos/09-ci-gate-sarif/questionnaire.json \
    --sbom demos/09-ci-gate-sarif/sbom.json \
    --advisories demos/09-ci-gate-sarif/advisories.json > vendorvet.sarif
```

### GitHub Actions

```yaml
- name: Vet vendor
  run: |
    python -m vendorvet --format sarif assess vendor/questionnaire.json \
      --sbom vendor/sbom.json --advisories advisories.json > vendorvet.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: vendorvet.sarif
```

## Expected outcome

Overall **CRITICAL** (score 90.0), exit code **2** (the build fails). The
SARIF log carries: a `note` for the LOW questionnaire residual, a `warning`
for the MFA gap, an `error` for CVE-2021-45046 (`security-severity 9.0`), and
a `warning` for the medium Netty CVE. Each result includes a
`security-severity` property so GitHub renders the correct severity badge.
