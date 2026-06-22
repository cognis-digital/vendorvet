# Demo 11 — Legacy appliance still shipping Heartbleed-era OpenSSL

**FieldGate Appliance** is an on-prem hardware vendor. Their firmware SBOM
still pins `openssl 1.0.1f`, which is within the affected range of
**CVE-2014-0160 ("Heartbleed", CVSS 7.5)** — the OpenSSL TLS heartbeat
memory-disclosure bug. The other components (nginx 1.24.0, zlib 1.3.1) are
current.

This is the classic embedded/IoT supply-chain finding: modern app code, but
a decade-old crypto library baked into the image.

## Files

- `sbom.json` — firmware component list.
- `advisories.json` — advisory feed scoped to the affected OpenSSL 1.0.1
  series.

## Run it

```bash
python -m vendorvet sbom demos/11-heartbleed-legacy/sbom.json \
    demos/11-heartbleed-legacy/advisories.json
```

## Expected outcome

One vulnerable component: **openssl@1.0.1f → CVE-2014-0160, CVSS 7.5
(high)**. Max severity is `high`, so the `sbom` subcommand exits **2** and
fails a CI gate. Note the patched nginx/zlib are correctly **not** flagged.
Action: require the vendor to rebuild firmware against a supported OpenSSL
3.x branch before procurement signs off.
