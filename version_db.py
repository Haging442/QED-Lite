"""
PQC Library Version Database for QED-Lite.
Defines risk posture per library version based on official release notes.
Reference: NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)
"""

# Risk posture constants
QUANTUM_VULNERABLE = "QUANTUM_VULNERABLE"
HYBRID             = "HYBRID"
PQC_READY          = "PQC_READY"
NO_CRYPTO_DEP      = "NO_CRYPTO_DEP"

# Priority for composite judgment (pessimistic: lowest = worst)
RISK_PRIORITY = {
    QUANTUM_VULNERABLE: 0,
    HYBRID:             1,
    PQC_READY:          2,
    NO_CRYPTO_DEP:      3,
}

def composite_posture(posture_list):
    """Return the worst-case posture across all linked libraries."""
    return min(posture_list, key=lambda p: RISK_PRIORITY.get(p, 0))

PQC_LIBRARY_DB = {

    "libssl": {
        "display_name": "OpenSSL",
        "so_patterns": [
            "libssl.so", "libssl.so.3",
            "libssl.so.1.1", "libssl.so.1.0",
            "libssl.so.1.0.0", "libssl.so.1.0.2",
        ],
        "pqc_ready_from":     (3, 5, 0),
        "transitioning_from": (3, 0, 0),
        "vulnerable_below":   (3, 0, 0),
        "default_posture":    None,
        "is_research_grade":  False,
        "notes": (
            "OpenSSL 3.5.0 (2025-04-08, LTS): native ML-KEM/ML-DSA/SLH-DSA. "
            "3.0-3.4: oqs-provider can add PQC but not statically detectable. "
            "All 1.x: QUANTUM_VULNERABLE."
        ),
    },

    "libwolfssl": {
        "display_name": "wolfSSL",
        "so_patterns": ["libwolfssl.so"],
        "pqc_ready_from":     (5, 8, 0),
        "transitioning_from": (0, 0, 1),
        "vulnerable_below":   None,
        "default_posture":    None,
        "is_research_grade":  False,
        "notes": (
            "wolfSSL 5.8.0 (2025-05): self-contained ML-KEM/ML-DSA/SLH-DSA. "
            "All versions < 5.8: HYBRID. "
            "PQC requires compile-time flags — version alone is not definitive."
        ),
    },

    "libmbedtls": {
        "display_name": "mbedTLS",
        "so_patterns": [
            "libmbedtls.so", "libmbedtls.so.14", "libmbedtls.so.21",
        ],
        "pqc_ready_from":     None,
        "transitioning_from": None,
        "vulnerable_below":   (9999, 0, 0),
        "default_posture":    None,
        "is_research_grade":  False,
        "notes": (
            "mbedTLS: no ML-KEM/ML-DSA as of 2026-03. "
            "All versions: QUANTUM_VULNERABLE."
        ),
    },

    "libboringssl": {
        "display_name": "BoringSSL",
        "so_patterns": ["libboringssl.so"],
        "pqc_ready_from":     None,
        "transitioning_from": None,
        "vulnerable_below":   None,
        "default_posture":    PQC_READY,
        "is_research_grade":  False,
        "notes": (
            "BoringSSL: no semantic versioning. "
            "ML-KEM and ML-DSA in production via Chrome 131+. "
            "Treat as PQC_READY by default."
        ),
    },

    "libressl": {
        "display_name": "LibreSSL",
        "so_patterns": ["libssl.so"],
        "pqc_ready_from":     None,
        "transitioning_from": (4, 1, 0),
        "vulnerable_below":   (4, 1, 0),
        "default_posture":    None,
        "is_research_grade":  False,
        "notes": (
            "LibreSSL 4.1.0: ML-KEM 768/1024 from BoringSSL, not yet public API. "
            "Distinguish from OpenSSL via 'LibreSSL' version string."
        ),
    },

    "libsodium": {
        "display_name": "libsodium",
        "so_patterns": ["libsodium.so", "libsodium.so.23"],
        "pqc_ready_from":     None,
        "transitioning_from": None,
        "vulnerable_below":   (9999, 0, 0),
        "default_posture":    None,
        "is_research_grade":  False,
        "notes": (
            "libsodium: modern classical crypto only. "
            "No NIST PQC API confirmed as of 2026-03."
        ),
    },

    "libbotan": {
        "display_name": "Botan",
        "so_patterns": ["libbotan-3.so", "libbotan-2.so", "libbotan.so"],
        "pqc_ready_from":     (3, 6, 0),
        "transitioning_from": (2, 0, 0),
        "vulnerable_below":   (2, 0, 0),
        "default_posture":    None,
        "is_research_grade":  False,
        "notes": (
            "Botan 3.6.0: FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA. "
            "3.0-3.5: pre-standard Kyber/Dilithium. "
            "libbotan-2.so: max HYBRID (EOL 2025-01-01)."
        ),
    },

    "libgnutls": {
        "display_name": "GnuTLS",
        "so_patterns": ["libgnutls.so", "libgnutls.so.30"],
        "pqc_ready_from":     None,
        "transitioning_from": (3, 8, 8),
        "vulnerable_below":   (3, 8, 8),
        "default_posture":    None,
        "is_research_grade":  False,
        "notes": (
            "GnuTLS 3.8.8: experimental X25519MLKEM768 in TLS 1.3. "
            "< 3.8.8: QUANTUM_VULNERABLE."
        ),
    },

    "libnss3": {
        "display_name": "NSS",
        "so_patterns": ["libnss3.so"],
        "pqc_ready_from":     (3, 105, 0),
        "transitioning_from": (3, 97, 0),
        "vulnerable_below":   (3, 97, 0),
        "default_posture":    None,
        "is_research_grade":  False,
        "notes": (
            "NSS 3.97: pre-standard Kyber opt-in. "
            "NSS 3.105: FIPS 203 ML-KEM-768 in TLS. "
            "< 3.97: QUANTUM_VULNERABLE."
        ),
    },

    "liboqs": {
        "display_name": "liboqs (OQS)",
        "so_patterns": ["liboqs.so"],
        "pqc_ready_from":     None,
        "transitioning_from": (0, 1, 0),
        "vulnerable_below":   None,
        "default_posture":    HYBRID,
        "is_research_grade":  True,
        "notes": (
            "liboqs: research/prototype only (OQS official). "
            "All versions: HYBRID + is_research_grade=True."
        ),
    },

    "libgcrypt": {
        "display_name": "libgcrypt",
        "so_patterns": ["libgcrypt.so", "libgcrypt.so.20"],
        "pqc_ready_from":     None,
        "transitioning_from": (1, 11, 0),
        "vulnerable_below":   (1, 11, 0),
        "default_posture":    None,
        "is_research_grade":  False,
        "notes": (
            "libgcrypt 1.11.0: Kyber KEM + sntrup761 (pre-FIPS 203). "
            "< 1.11.0: QUANTUM_VULNERABLE."
        ),
    },
}

# SO name to library key mapping
SO_TO_LIBRARY_MAP = {
    "libssl.so":          "libssl",
    "libssl.so.3":        "libssl",
    "libssl.so.1.1":      "libssl",
    "libssl.so.1.0":      "libssl",
    "libssl.so.1.0.0":    "libssl",
    "libssl.so.1.0.2":    "libssl",
    "libcrypto.so":       "libssl",
    "libcrypto.so.3":     "libssl",
    "libcrypto.so.1.1":   "libssl",
    "libcrypto.so.1.0":   "libssl",
    "libcrypto.so.1.0.0": "libssl",
    "libcrypto.so.1.0.2": "libssl",
    "libwolfssl.so":      "libwolfssl",
    "libmbedtls.so":        "libmbedtls",
    "libmbedtls.so.14":     "libmbedtls",
    "libmbedtls.so.21":     "libmbedtls",
    "libmbedcrypto.so":     "libmbedtls",
    "libmbedcrypto.so.7":   "libmbedtls",
    "libmbedcrypto.so.14":  "libmbedtls",
    "libmbedx509.so":       "libmbedtls",
    "libmbedx509.so.7":     "libmbedtls",
    "libboringssl.so":    "libboringssl",
    "libsodium.so":       "libsodium",
    "libsodium.so.23":    "libsodium",
    "libbotan-3.so":      "libbotan",
    "libbotan-2.so":      "libbotan",
    "libbotan.so":        "libbotan",
    "libgnutls.so":       "libgnutls",
    "libgnutls.so.30":    "libgnutls",
    "libnss3.so":         "libnss3",
    "liboqs.so":          "liboqs",
    "libgcrypt.so":       "libgcrypt",
    "libgcrypt.so.20":    "libgcrypt",
}
