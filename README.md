# QED-Lite

A lightweight PQC (Post-Quantum Cryptography) vulnerability detector for ELF binaries.  
Based on [QED](https://github.com/norrathep/qed) by Rattanavipanon et al.

## What is QED-Lite?

QED-Lite detects ELF binaries that depend on cryptographic libraries, and assesses their PQC migration risk based on library version fingerprinting.

Unlike the original QED, QED-Lite removes the angr-based static callgraph analysis (P3) and replaces it with a version-based risk judgment. This makes QED-Lite significantly faster and lighter while maintaining practical detection accuracy.

**Risk postures:**
- `QUANTUM_VULNERABLE` — linked to a crypto library with no PQC support
- `HYBRID` — linked to a transitional version (partial PQC support)
- `PQC_READY` — linked to a crypto library with full PQC support (FIPS 203/204/205)
- `NO_CRYPTO_DEP` — no crypto library dependency detected

**Supported libraries:** OpenSSL, wolfSSL, mbedTLS, BoringSSL, LibreSSL, libsodium, Botan, GnuTLS, NSS, liboqs, libgcrypt

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

Results are saved to `<output_folder>/dependency.txt` in JSON format.
