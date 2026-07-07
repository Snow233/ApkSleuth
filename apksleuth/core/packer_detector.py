from __future__ import annotations

import zipfile

from apksleuth.models import ManifestSummary, PackerFinding


PACKER_PATTERNS = [
    ("360 Jiagu", ["libjiagu.so", "libjiagu_art.so", "com.qihoo.util.StubApplication", "qihoo"]),
    ("Tencent Legu", ["libshell-super", "com.tencent.StubShell", "legu"]),
    ("Bangcle", ["com.secneo.apkwrapper", "libsecexe", "bangcle"]),
    ("Ijiami", ["ijiami", "libexec.so", "libexecmain.so"]),
    ("Naga", ["libnqshield", "naga"]),
    ("SecNeo", ["secneo", "libDexHelper.so"]),
    ("DexGuard", ["dexguard", "com.guardsquare"]),
    ("ProGuard/R8", ["META-INF/proguard", "proguard.map", "proguard_mapping", "com.guardsquare"]),
]


def detect_packers(apk: zipfile.ZipFile, manifest: ManifestSummary) -> list[PackerFinding]:
    entries = [name.lower() for name in apk.namelist()]
    string_values: list[str] = []
    if manifest.application_class:
        string_values.append(manifest.application_class.lower())
    evidence_pool = entries + string_values

    results: list[PackerFinding] = []
    for name, patterns in PACKER_PATTERNS:
        matched: list[str] = []
        evidence: list[str] = []
        for pattern in patterns:
            lower_pattern = pattern.lower()
            for candidate in evidence_pool:
                if lower_pattern in candidate:
                    matched.append(pattern)
                    evidence.append(_truncate(candidate))
                    break
        if matched:
            confidence = "high" if len(set(matched)) >= 2 else "medium"
            results.append(PackerFinding(name, sorted(set(matched)), sorted(set(evidence))[:5], confidence))
    return results


def _truncate(value: str, length: int = 160) -> str:
    return value if len(value) <= length else f"{value[:length]}..."
