# Ports of vendorvet

The vendorvet questionnaire risk engine, ported across languages so you can drop
it into any stack or ship a single static binary. **Every port mirrors the
reference Python `vendorvet questionnaire <file>` command** — the same weighted
control catalog, the same `unanswered = half-penalty` rule, the same
data-classification multiplier (`public 0.6 / internal 0.85 / confidential 1.1 /
restricted 1.35`), and the same tier thresholds (`>=70 critical, >=45 high,
>=20 moderate, else low`). They are verified to produce the **same residual score
and tier** as Python on the bundled demos, and the same CI exit code (`0`
low/moderate, `2` high/critical, `1` usage/IO error).

| Language | Path | Run |
|---|---|---|
| Python (reference) | `../vendorvet/` | `vendorvet questionnaire q.json` |
| JavaScript / Node | `javascript/` | `node ports/javascript/index.js questionnaire q.json` |
| Shell (POSIX + jq) | `shell/` | `sh ports/shell/vendorvet.sh questionnaire q.json` |
| Go | `go/` | `cd ports/go && go run . questionnaire ../../q.json` |
| Rust | `rust/` | `cd ports/rust && cargo run -- questionnaire ../../q.json` |

Add `--format json` to any port for machine-readable output. The Go and Rust
ports are **zero-dependency** (Rust ships a tiny built-in JSON reader, no serde),
so they build offline with only the standard toolchain.

### Verify parity

```bash
scripts/ports-test.sh        # runs every installed port against a fixture
```

CI builds and smoke-tests all four ports on every push — see
[`.github/workflows/ports.yml`](../.github/workflows/ports.yml). Each job builds
the port from source (`go build`, `cargo build --release`) and asserts it returns
tier `high` and exit `2` on the bundled high-risk questionnaire, so the ports are
real and continuously verified, not vaporware.

Contributions of additional ports (Ruby, C#, Bun, Deno, WASM) are welcome — see
../CONTRIBUTING.md.
