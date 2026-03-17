# QED-Lite

A lightweight PQC (Post-Quantum Cryptography) vulnerability detector for ELF binaries.
Based on [QED](https://github.com/norrathep/qed) by Rattanavipanon et al.

## What is QED-Lite?

QED-Lite detects ELF binaries that depend on cryptographic libraries, assesses their PQC migration risk based on library version fingerprinting, and automatically provides migration guidance.

Unlike the original QED, QED-Lite removes the angr-based static callgraph analysis (P3) and replaces it with a version-based risk judgment. This makes QED-Lite significantly faster and lighter while maintaining practical detection accuracy.

## Risk Postures

| Posture | Meaning |
|---------|---------|
| `QUANTUM_VULNERABLE` | Linked to a crypto library with no PQC support |
| `HYBRID` | Linked to a transitional version (partial PQC support) |
| `PQC_READY` | Linked to a crypto library with full PQC support (FIPS 203/204/205) |
| `NO_CRYPTO_DEP` | No crypto library dependency detected |

## Supported Libraries

OpenSSL, wolfSSL, mbedTLS, BoringSSL, LibreSSL, libsodium, Botan, GnuTLS, NSS, liboqs, libgcrypt

## Usage
```bash
# Install dependency
python3 -m venv .venv
.venv/bin/pip install pyelftools

# Run
.venv/bin/python3 qed_lite.py <scan_folder> <output_folder>

# Example
.venv/bin/python3 qed_lite.py /usr/bin/ output/
```

## Output

| File | Description |
|------|-------------|
| `result.json` | Detection results with posture per binary |
| `result.prof` | Profiling results |
| `migration_guide.json` | PQC migration guidance per library |

Migration guidance is also printed to the terminal, including current version recommendations and step-by-step upgrade paths.
