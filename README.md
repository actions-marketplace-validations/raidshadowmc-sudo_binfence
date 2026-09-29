# relgate

Binary release security gate & mitigation regression auditor for CI/CD pipelines.

[![CI](https://github.com/raidshadowmc-sudo/relgate/actions/workflows/ci.yml/badge.svg)](https://github.com/raidshadowmc-sudo/relgate/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/raidshadowmc-sudo/relgate?include_prereleases)](https://github.com/raidshadowmc-sudo/relgate/releases)

`relgate` audits compiled release assets (PE, ELF, Mach-O) in CI/CD before they hit production. It guards against accidental compiler or linker regressions that strip exploit mitigations, violate `W^X` memory protection, corrupt Authenticode digests, or inject abnormal entropy.

Powered by [`binlens`](https://github.com/raidshadowmc-sudo/binlens).

---

## Why relgate?

Linter and dependency checkers (`cargo audit`, `npm audit`, CodeQL) audit source code and dependency lockfiles. **Almost nobody audits the compiled binary artifact itself.**

A routine dependency bump or toolchain update can silently:
* Drop **ASLR / PIE** layout randomization.
* Disable **DEP / NX** stack protection.
* Introduce simultaneously writable and executable (**RWX**) sections violating `W^X`.
* Invalidate or tamper with **Authenticode** signatures post-build.
* Inflate Shannon entropy through unexpected packing or crypto payloads.

`relgate` acts as the final gate between your build pipeline and your GitHub Releases.

---

## GitHub Action Usage

Add `relgate` to your build or release workflow:

```yaml
name: Release Gate

on:
  release:
    types: [published]
  push:
    tags: ['v*']

permissions:
  contents: read
  security-events: write

jobs:
  audit-release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build production binary
        run: cargo build --release

      - name: Run Binary Release Gate
        uses: raidshadowmc-sudo/relgate@v0.1.0
        with:
          binary: target/release/my_app
          fail-on-degraded: true
          fail-on-rwx: true
          require-aslr: true
          require-dep: true

      - name: Upload SARIF to GitHub Security tab
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: relgate.sarif
```


### Comparing Against Baseline (Differential Gate)

To catch regressions between consecutive releases:

```yaml
- name: Download Previous Release Asset
  run: gh release download v1.0.0 --pattern "my_app" --output old_app
  env:
    GH_TOKEN: ${{ github.token }}

- name: Audit Against Baseline
  uses: raidshadowmc-sudo/relgate@v0.1.0
  with:
    binary: target/release/my_app
    baseline: old_app
    fail-on-degraded: true
```

---

## GitHub Step Summary Output

`relgate` automatically posts a rich Markdown table into `$GITHUB_STEP_SUMMARY`:

```markdown
### 🟢 Relgate Security Gate: PASSED

| Metric | Target Asset | Baseline (Previous) | Status |
| :--- | :--- | :--- | :--- |
| **Binary Name** | `my_app` | `old_app` | - |
| **Format / Arch** | ELF64 / x86_64 | ELF64 / x86_64 | - |
| **File Size** | 1,420,896 bytes | 1,398,120 bytes | +22,776 bytes |
| **Shannon Entropy** | 6.210 / 8.000 | 6.195 | 🟢 Normal |
| **ASLR / PIE** | 🟢 Enabled | 🟢 Enabled | ⚪ Unchanged |
| **DEP / NX** | 🟢 Enabled | 🟢 Enabled | ⚪ Unchanged |
| **W^X (No RWX)** | 🟢 Enforced | 🟢 Enforced | 🟢 OK |
| **Authenticode** | ⚪ Unsigned | ⚪ Unsigned | ⚪ |
```

---

## CLI Usage

`relgate` can also be run locally on your development machine:

```bash
# Install directly from Git repository
cargo install --git https://github.com/raidshadowmc-sudo/relgate.git --locked

# Audit binary against default security policies
relgate --binary ./app.exe

# Differential audit against previous build
relgate --binary ./build/new_app.exe --baseline ./build/old_app.exe

# Enforce strict policy flags
relgate --binary ./dist/app \
  --fail-on-degraded \
  --require-aslr \
  --require-dep \
  --disallow-rwx \
  --fail-on-tampered \
  --max-entropy 7.2 \
  --sarif-file release.sarif
```

---

## Security Rules Evaluated

| Rule ID | Name | Severity | Description |
| :--- | :--- | :--- | :--- |
| `REL001-*` | `SecurityMitigationDegraded` | 🔴 Error | An enabled mitigation (`ASLR`, `DEP`, `CFG`, `RELRO`, `Canary`, `FORTIFY`, `SafeSEH`) was dropped compared to baseline. |
| `REL002-NO-ASLR` | `RequireASLR` | 🔴 Error | Binary was linked without dynamic base or position-independent executable (PIE) support. |
| `REL003-NO-DEP` | `RequireDEP` | 🔴 Error | Binary does not enforce non-executable stack/heap protection (`NX_COMPAT` or `PT_GNU_STACK`). |
| `REL004-RWX-SECTION` | `DisallowRWXSections` | 🔴 Error | Binary contains simultaneously writable and executable sections (`W^X` violation). |
| `REL005-AUTHENTICODE-TAMPERED` | `AuthenticodeDigestMismatch` | 🔴 Error | PE Authenticode digest does not match embedded signature, indicating binary tampering. |
| `REL005-AUTHENTICODE-MALFORMED`| `AuthenticodeMalformed` | 🔴 Error | Embedded PKCS#7 certificate directory is corrupt or malformed. |
| `REL006-UNSIGNED-BINARY` | `RequireAuthenticode` | 🔴 Error | Policy requires an embedded Authenticode signature, but binary is unsigned (opt-in for PE). |
| `REL007-HIGH-ENTROPY` | `HighEntropyWarning` | ⚠️ Warning | Shannon entropy exceeds threshold (default: 7.5), signaling possible packing or hidden payload. (Emits advisory warning; does not block release gate). |
| `REL008-YARA-*` | `YaraSignatureMatch` | 🔴 Error | Target binary matched a prohibited YARA signature rule. |
| `REL009-NO-CFG` | `RequireControlFlowGuard` | 🔴 Error | Policy requires Control Flow Guard (`/guard:cf`) on Windows PE binaries. |
| `REL010-NO-STACK-CANARY` | `RequireStackCanary` | 🔴 Error | Policy requires stack smash buffer security checks (`/GS` or `-fstack-protector`). |
| `REL011-EXCESS-NEW-SECTIONS` | `ExcessiveNewSections` | 🔴 Error | Number of newly added sections exceeds allowable threshold. |


---

## License

Licensed under the [MIT License](LICENSE).
