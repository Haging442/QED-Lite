"""
QED-Lite Migration Guide Generator.
Groups scan results by library/version and provides remediation guidance
based on the PQC_LIBRARY_DB posture ratings.
"""

import os
import json
from datetime import datetime

from version_db import (
    QUANTUM_VULNERABLE, HYBRID, PQC_READY, NO_CRYPTO_DEP,
    PQC_LIBRARY_DB, SO_TO_LIBRARY_MAP,
)

# Current-version remediation notes keyed by (lib_key, posture_range_tag)
IMMEDIATE_MITIGATION = {
    ("libssl", "1.x"): (
        "OpenSSL 1.x does not support OQS-Provider plugin. "
        "PQC cannot be applied without upgrading to 3.x."
    ),
    ("libssl", "3.0-3.4"): (
        "OQS-Provider plugin can be applied on this version. "
        "Build and install oqs-provider, then load via openssl.cnf. "
        "Refer to: https://github.com/open-quantum-safe/oqs-provider"
    ),
    ("libwolfssl", "<5.8"): (
        "PQC support depends on compile-time flags (--enable-kyber, --enable-dilithium). "
        "Verify build options and recompile if needed."
    ),
    ("libmbedtls", "all"): (
        "mbedTLS does not support ML-KEM/ML-DSA as of 2026. "
        "Consider migration to an alternative library."
    ),
    ("libbotan", "2.x-3.5"): (
        "Pre-standard Kyber/Dilithium only. "
        "Upgrade to Botan 3.6.0+ for FIPS 203/204/205 support."
    ),
    ("libgnutls", ">=3.8.8"): (
        "Experimental X25519MLKEM768 available. "
        "Enable via build configuration."
    ),
    ("libnss3", "3.97-3.104"): (
        "Pre-standard Kyber available as opt-in. "
        "Upgrade to NSS 3.105+ for FIPS 203 ML-KEM-768."
    ),
    ("libgcrypt", ">=1.11"): (
        "Pre-standard Kyber KEM available. Not yet FIPS 203 compliant."
    ),
    ("libsodium", "all"): (
        "libsodium does not provide NIST PQC APIs. "
        "Consider adding liboqs as a companion library."
    ),
    ("liboqs", "all"): (
        "[CAUTION] this library is for research/prototype use only"
    ),
    ("_default", "all"): (
        "Version could not be determined. Manual inspection is recommended."
    ),
}

# Step-by-step upgrade paths keyed by (lib_key, posture_range_tag)
UPGRADE_PATH = {
    ("libssl", "1.x"): [
        "Step 1. OpenSSL 1.x -> OpenSSL 3.3.x (security patches, API migration required)",
        "Step 2. OpenSSL 3.3.x -> OpenSSL 3.5.x (native ML-KEM/ML-DSA/SLH-DSA support)",
    ],
    ("libssl", "3.0-3.4"): [
        "Step 1. OpenSSL 3.x -> OpenSSL 3.5.x (native ML-KEM/ML-DSA/SLH-DSA support)",
    ],
    ("libwolfssl", "<5.8"): [
        "Step 1. Recompile wolfSSL with --enable-kyber --enable-dilithium flags",
        "Step 2. Upgrade to wolfSSL 5.8.0+ for full ML-KEM/ML-DSA/SLH-DSA production support",
    ],
    ("libmbedtls", "all"): [
        "Step 1. Upgrade to mbedTLS 3.x (PSA Crypto API, code changes required)",
        "Step 2. Integrate liboqs with mbedTLS 3.x for PQC support",
        "Alternative: Migrate to wolfSSL (mbedTLS-compatible API layer available)",
    ],
    ("libbotan", "2.x-3.5"): [
        "Step 1. Upgrade to Botan 3.6.0+ (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA)",
    ],
    ("libgnutls", "<3.8.8"): [
        "Step 1. Upgrade to GnuTLS 3.8.8+ for experimental PQC support",
    ],
    ("libnss3", "<3.97"): [
        "Step 1. Upgrade to NSS 3.97+ (pre-standard Kyber)",
        "Step 2. Upgrade to NSS 3.105+ (FIPS 203 ML-KEM-768)",
    ],
    ("libnss3", "3.97-3.104"): [
        "Step 1. Upgrade to NSS 3.105+ (FIPS 203 ML-KEM-768)",
    ],
    ("libgcrypt", "<1.11"): [
        "Step 1. Upgrade to libgcrypt 1.11.0+ (Kyber KEM, pre-FIPS 203)",
    ],
    ("libsodium", "all"): [
        "Step 1. Add liboqs as companion library for PQC operations (research-grade)",
        "Step 2. Monitor libsodium roadmap for official PQC API support",
    ],
    ("liboqs", "all"): [
        "Step 1. Replace with production-ready PQC library "
        "(e.g. OpenSSL 3.5+, wolfSSL 5.8+, Botan 3.6+)",
    ],
}


def _range_tag(lib_key, version):
    """Return the range tag string used as key in IMMEDIATE_MITIGATION / UPGRADE_PATH."""
    if lib_key == "libssl":
        if version and version[0] == 1:
            return "1.x"
        if version and version[0] == 3 and version < (3, 5, 0):
            return "3.0-3.4"
    elif lib_key == "libwolfssl":
        if version is None or version < (5, 8, 0):
            return "<5.8"
    elif lib_key == "libmbedtls":
        return "all"
    elif lib_key == "libbotan":
        if version and version < (3, 6, 0):
            return "2.x-3.5"
    elif lib_key == "libgnutls":
        if version and version >= (3, 8, 8):
            return ">=3.8.8"
        return "<3.8.8"
    elif lib_key == "libnss3":
        if version and version >= (3, 97, 0) and version < (3, 105, 0):
            return "3.97-3.104"
        if version and version < (3, 97, 0):
            return "<3.97"
    elif lib_key == "libgcrypt":
        if version and version >= (1, 11, 0):
            return ">=1.11"
        return "<1.11"
    elif lib_key == "libsodium":
        return "all"
    elif lib_key == "liboqs":
        return "all"
    return "all"


def _get_mitigation(lib_key, version):
    """Look up IMMEDIATE_MITIGATION for a given library key and version tuple."""
    tag = _range_tag(lib_key, version)
    msg = IMMEDIATE_MITIGATION.get((lib_key, tag))
    if msg is None:
        msg = IMMEDIATE_MITIGATION.get(("_default", "all"), "")
    return msg


def _get_upgrade_path(lib_key, version):
    """Look up UPGRADE_PATH for a given library key and version tuple."""
    tag = _range_tag(lib_key, version)
    return UPGRADE_PATH.get((lib_key, tag), [])


def _resolve_lib_key(so_name):
    """Resolve SO basename to library key with prefix-match fallback."""
    key = SO_TO_LIBRARY_MAP.get(so_name)
    if key is None:
        prefix = so_name.split(".so")[0]
        for known_so, k in SO_TO_LIBRARY_MAP.items():
            if known_so.startswith(prefix):
                key = k
                break
    return key


def generate_guide(report, output_folder):
    """
    Generate migration guidance from a QED-Lite report list.

    Parameters
    ----------
    report       : list — full_report["report"] from FileDependencyAnalysis.gen_report()
    output_folder: str  — directory where migration_guide.json is written
    """
    pqc_ready_apps = []
    no_dep_apps = []
    # Groups dict: (lib_key, version_tuple_or_None, so_name) -> list of app paths
    groups = {}
    group_meta = {}  # same key -> (posture, lib_key, version, so_name, is_research_grade)

    for entry in report:
        posture = entry.get("posture", NO_CRYPTO_DEP)
        elf = entry.get("elf", "")
        etype = entry.get("type", "")

        if posture == PQC_READY:
            if etype == "leaf":
                pqc_ready_apps.append(elf)
            continue
        if posture == NO_CRYPTO_DEP:
            no_dep_apps.append(elf)
            continue
        if etype != "leaf":
            continue  # Skip root/interm entries from grouping

        # Determine group key from the linked library path
        path = entry.get("path", [])
        lib_path = path[-1] if len(path) > 1 else ""
        so_name = os.path.basename(lib_path) if lib_path else "unknown"
        lib_key = _resolve_lib_key(so_name)

        version = entry.get("version")
        version_tuple = tuple(version) if version else None
        is_research = entry.get("is_research_grade", False)

        group_key = (lib_key, version_tuple, so_name)
        if group_key not in groups:
            groups[group_key] = []
            group_meta[group_key] = (posture, lib_key, version_tuple, so_name, is_research)
        groups[group_key].append(elf)

    # Sort groups: QUANTUM_VULNERABLE first, then HYBRID
    posture_order = {QUANTUM_VULNERABLE: 0, HYBRID: 1}
    sorted_keys = sorted(
        groups.keys(),
        key=lambda k: posture_order.get(group_meta[k][0], 99)
    )

    # Terminal output
    SEP = "-" * 60
    HEADER = "=" * 60
    print(HEADER)
    print("        QED-Lite Migration Guide")
    print(HEADER)

    guidance_list = []

    for idx, gkey in enumerate(sorted_keys, start=1):
        posture, lib_key, version_tuple, so_name, is_research = group_meta[gkey]
        apps = groups[gkey]

        # Print posture header for every entry
        print(f"\n[{posture}]")

        # Display name and version string
        db_entry = PQC_LIBRARY_DB.get(lib_key or "", {})
        display_name = db_entry.get("display_name", lib_key or so_name)
        ver_str = ".".join(str(v) for v in version_tuple) if version_tuple else "unknown"

        mitigation = _get_mitigation(lib_key, version_tuple)
        upgrade = _get_upgrade_path(lib_key, version_tuple)

        print(f"\n[{idx}] {so_name}  ({display_name}  {ver_str})")
        print(f"    Apps: {apps[0]}")
        print(f"    [Current Version Recommendation]")
        print(f"    {mitigation}")
        if upgrade:
            print(f"    [Upgrade Path]")
            for step in upgrade:
                print(f"    {step}")
        if len(apps) > 1:
            others = [os.path.basename(a) for a in apps[1:]]
            # Print up to 5 app names per line; indent continuation lines by 12 spaces
            indent = " " * 12
            chunks = [others[i:i+5] for i in range(0, len(others), 5)]
            first_line = "    [INFO] same library, same guidance: " + ", ".join(chunks[0])
            print(first_line)
            for chunk in chunks[1:]:
                print(indent + ", ".join(chunk))
        print(SEP)

        guidance_list.append({
            "posture": posture,
            "library": display_name,
            "library_key": lib_key,
            "detected_version": list(version_tuple) if version_tuple else None,
            "so_name": so_name,
            "is_research_grade": is_research,
            "apps": apps,
            "current_version_recommendation": mitigation,
            "upgrade_path": upgrade,
        })

    # Footer
    guide_path = os.path.join(output_folder, "migration_guide.json")
    print(f"\nMigration guide saved: {guide_path}")

    # Build summary
    summary = {}
    for gkey in sorted_keys:
        p = group_meta[gkey][0]
        summary[p] = summary.get(p, 0) + len(groups[gkey])
    if pqc_ready_apps:
        summary[PQC_READY] = len(pqc_ready_apps)
    if no_dep_apps:
        summary[NO_CRYPTO_DEP] = len(no_dep_apps)

    output = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "summary": summary,
        "guidance": guidance_list,
        "pqc_ready": {
            "count": len(pqc_ready_apps),
            "apps": pqc_ready_apps,
        },
        "no_crypto_dep": {
            "count": len(no_dep_apps),
            "apps": no_dep_apps,
        },
    }

    os.makedirs(output_folder, exist_ok=True)
    with open(guide_path, "w") as f:
        json.dump(output, f, indent=4)

    return output
