from __future__ import annotations

import zipfile

from apksleuth.models import ManifestSummary, SdkFinding, StringFinding


SDK_PATTERNS = [
    ("WeChat SDK", "social-payment", ["com.tencent.mm.opensdk", "wechat", "wxapi"]),
    ("Alipay SDK", "payment", ["com.alipay", "alipaysdk"]),
    ("Tencent Bugly", "crash-reporting", ["com.tencent.bugly", "bugly"]),
    ("Umeng Analytics", "analytics", ["com.umeng", "umeng_appkey", "umsocial"]),
    ("JPush", "push", ["cn.jpush", "jpush_appkey", "jcore"]),
    ("Getui", "push", ["com.igexin", "getui"]),
    ("Baidu Map", "map-location", ["com.baidu.mapapi", "baidumap"]),
    ("Amap", "map-location", ["com.amap.api", "com.autonavi", "amap"]),
    ("Tencent Map", "map-location", ["com.tencent.tencentmap", "tencentmap"]),
    ("Pangle Ads", "advertising", ["com.bytedance.sdk.openadsdk", "pangle", "ttad"]),
    ("Youlianghui Ads", "advertising", ["com.qq.e.ads", "gdtad", "ylh"]),
    ("Kuaishou Ads", "advertising", ["com.kwad", "ksad"]),
    ("Firebase", "cloud-analytics", ["com.google.firebase", "firebaseio.com", "google_app_id"]),
    ("Google Ads", "advertising", ["com.google.android.gms.ads", "admob"]),
    ("Facebook SDK", "social-analytics", ["com.facebook", "facebook_app_id"]),
]


def detect_sdks(apk: zipfile.ZipFile, strings: list[StringFinding], manifest: ManifestSummary | None = None) -> list[SdkFinding]:
    entries = [name.lower() for name in apk.namelist()]
    string_values = [item.value.lower() for item in strings[:1000]]
    manifest_values = _manifest_evidence(manifest)
    evidence_pool = entries + string_values + manifest_values

    results: list[SdkFinding] = []
    for name, sdk_type, patterns in SDK_PATTERNS:
        matched_patterns: list[str] = []
        evidence: list[str] = []
        for pattern in patterns:
            lower_pattern = pattern.lower()
            for candidate in evidence_pool:
                if lower_pattern in candidate:
                    matched_patterns.append(pattern)
                    evidence.append(_truncate(candidate))
                    break
        if matched_patterns:
            results.append(
                SdkFinding(
                    name=name,
                    type=sdk_type,
                    matched_patterns=sorted(set(matched_patterns)),
                    evidence=sorted(set(evidence))[:5],
                    risk="Review SDK data collection, privacy disclosure, and required permissions.",
                )
            )
    return results


def _truncate(value: str, length: int = 160) -> str:
    return value if len(value) <= length else f"{value[:length]}..."


def _manifest_evidence(manifest: ManifestSummary | None) -> list[str]:
    if manifest is None:
        return []
    values = [
        manifest.package_name,
        manifest.app_name,
        manifest.application_class,
        *manifest.permissions,
        *manifest.provider_authorities,
    ]
    for component in manifest.components:
        values.extend([component.name, component.permission, component.authorities])
    return [value.lower() for value in values if value]
