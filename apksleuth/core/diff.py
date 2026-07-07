from __future__ import annotations

import json
from collections import Counter
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from apksleuth.core.analyzer import analyze_apk
from apksleuth.models import AnalysisReport, Component


DIFF_FORMATS = {"json", "markdown", "summary", "summary-json"}


LABELS = {
    "en": {
        "title": "ApkSleuth Diff Report",
        "summary_title": "ApkSleuth Diff Brief",
        "overview": "Overview",
        "risk_changes": "Risk Changes",
        "added": "Added",
        "removed": "Removed",
        "permissions": "Permissions",
        "components": "Components",
        "urls": "URLs",
        "sdks": "SDKs",
        "packers": "Packers",
        "native_libraries": "Native Libraries",
        "signatures": "Signatures",
        "old": "Old",
        "new": "New",
        "delta": "Delta",
        "package": "Package",
        "version": "Version",
        "app": "App",
        "file": "File",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
        "total": "Total",
        "none": "none",
        "changed": "changed",
        "unchanged": "unchanged",
        "generated": "Generated",
        "samples_note": "Only the first items are shown in this brief. JSON contains the full diff.",
    },
    "zh": {
        "title": "ApkSleuth Diff 报告",
        "summary_title": "ApkSleuth Diff 简报",
        "overview": "概览",
        "risk_changes": "风险变化",
        "added": "新增",
        "removed": "移除",
        "permissions": "权限",
        "components": "组件",
        "urls": "URL",
        "sdks": "SDK",
        "packers": "加固/混淆",
        "native_libraries": "Native 库",
        "signatures": "签名",
        "old": "旧版本",
        "new": "新版本",
        "delta": "变化",
        "package": "包名",
        "version": "版本",
        "app": "应用",
        "file": "文件",
        "high": "高危",
        "medium": "中危",
        "low": "低危",
        "info": "信息",
        "total": "总计",
        "none": "无",
        "changed": "有变化",
        "unchanged": "无变化",
        "generated": "生成时间",
        "samples_note": "简报仅展示部分样例，完整差异请查看 JSON。",
    },
}


def diff_apks(
    old_apk: str | Path,
    new_apk: str | Path,
    max_entry_bytes: int = 4 * 1024 * 1024,
    progress: Callable[[str], None] | None = None,
) -> dict[str, object]:
    _progress(progress, "Analyzing old APK")
    old_report = analyze_apk(old_apk, max_entry_bytes=max_entry_bytes)
    _progress(progress, "Analyzing new APK")
    new_report = analyze_apk(new_apk, max_entry_bytes=max_entry_bytes)
    _progress(progress, "Computing diff")
    return build_diff_payload(old_report, new_report)


def build_diff_payload(old: AnalysisReport, new: AnalysisReport) -> dict[str, object]:
    old_risk = _risk_counts(old)
    new_risk = _risk_counts(new)
    old_urls = _string_values(old, "url")
    new_urls = _string_values(new, "url")
    old_components = _component_map(old)
    new_components = _component_map(new)
    old_native = {item.path for item in old.native_libraries}
    new_native = {item.path for item in new.native_libraries}
    old_sdks = {item.name for item in old.sdks}
    new_sdks = {item.name for item in new.sdks}
    old_packers = {item.name for item in old.packers}
    new_packers = {item.name for item in new.packers}
    old_schemes = set(old.certificate.schemes)
    new_schemes = set(new.certificate.schemes)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "old": _apk_payload(old),
        "new": _apk_payload(new),
        "risk": {
            "old": old_risk,
            "new": new_risk,
            "delta": {key: new_risk.get(key, 0) - old_risk.get(key, 0) for key in ("high", "medium", "low", "info", "total")},
            "finding_ids": _counter_diff(Counter(item.id for item in old.findings), Counter(item.id for item in new.findings)),
        },
        "permissions": _set_diff(set(old.manifest.permissions), set(new.manifest.permissions)),
        "components": {
            "added": [new_components[key] for key in sorted(set(new_components) - set(old_components))],
            "removed": [old_components[key] for key in sorted(set(old_components) - set(new_components))],
            "exported_old": _exported_count(old),
            "exported_new": _exported_count(new),
            "exported_delta": _exported_count(new) - _exported_count(old),
        },
        "urls": _set_diff(old_urls, new_urls),
        "sdks": _set_diff(old_sdks, new_sdks),
        "packers": _set_diff(old_packers, new_packers),
        "native_libraries": _set_diff(old_native, new_native),
        "signatures": {
            "schemes": _set_diff(old_schemes, new_schemes),
            "apk_sha256_changed": old.apk.hashes.sha256 != new.apk.hashes.sha256,
        },
        "errors": {
            "old": old.errors,
            "new": new.errors,
        },
    }


def render_diff(payload: dict[str, object], output_format: str = "summary", language: str = "zh") -> str:
    normalized = output_format.lower()
    if normalized in {"json", "summary-json"}:
        rendered = {"language": _normalize_language(language), **payload}
        return json.dumps(rendered, ensure_ascii=False, indent=2)
    if normalized in {"summary", "markdown"}:
        return render_diff_markdown(payload, language=language, brief=normalized == "summary")
    raise ValueError(f"Unsupported diff report format: {output_format}")


def render_diff_markdown(payload: dict[str, object], language: str = "zh", brief: bool = True) -> str:
    lang = _normalize_language(language)
    old = payload.get("old", {}) if isinstance(payload.get("old"), dict) else {}
    new = payload.get("new", {}) if isinstance(payload.get("new"), dict) else {}
    risk = payload.get("risk", {}) if isinstance(payload.get("risk"), dict) else {}
    risk_delta = risk.get("delta", {}) if isinstance(risk.get("delta"), dict) else {}

    lines = [f"# {_label(lang, 'summary_title' if brief else 'title')}", ""]
    lines.extend([
        f"- {_label(lang, 'generated')}: {payload.get('generated_at')}",
        f"- {_label(lang, 'old')}: {old.get('file_name')} | {old.get('app_name') or ''} | `{old.get('package_name') or ''}` | {old.get('version_name') or ''} ({old.get('version_code') or ''})",
        f"- {_label(lang, 'new')}: {new.get('file_name')} | {new.get('app_name') or ''} | `{new.get('package_name') or ''}` | {new.get('version_name') or ''} ({new.get('version_code') or ''})",
        f"- {_label(lang, 'package')}: {_changed_text(old.get('package_name'), new.get('package_name'), lang)}",
        f"- {_label(lang, 'version')}: {_changed_text(str(old.get('version_name')), str(new.get('version_name')), lang)}",
        "",
        f"## {_label(lang, 'risk_changes')}",
        "",
        f"| {_label(lang, 'risk_changes')} | {_label(lang, 'old')} | {_label(lang, 'new')} | {_label(lang, 'delta')} |",
        "| --- | ---: | ---: | ---: |",
    ])
    for key in ("high", "medium", "low", "info", "total"):
        lines.append(f"| {_label(lang, key)} | {risk.get('old', {}).get(key, 0)} | {risk.get('new', {}).get(key, 0)} | {_signed(risk_delta.get(key, 0))} |")
    lines.append("")

    lines.extend(_diff_section(_label(lang, "permissions"), payload.get("permissions", {}), lang, brief))
    component_summary = payload.get("components", {}) if isinstance(payload.get("components"), dict) else {}
    lines.extend([
        f"## {_label(lang, 'components')}",
        "",
        f"- {_label(lang, 'added')}: {len(component_summary.get('added', []))}",
        f"- {_label(lang, 'removed')}: {len(component_summary.get('removed', []))}",
        f"- Exported: {component_summary.get('exported_old', 0)} -> {component_summary.get('exported_new', 0)} ({_signed(component_summary.get('exported_delta', 0))})",
        "",
    ])
    lines.extend(_list_samples(_label(lang, "added"), _component_lines(component_summary.get("added", [])), lang, brief))
    lines.extend(_list_samples(_label(lang, "removed"), _component_lines(component_summary.get("removed", [])), lang, brief))
    lines.extend(_diff_section(_label(lang, "urls"), payload.get("urls", {}), lang, brief))
    lines.extend(_diff_section(_label(lang, "sdks"), payload.get("sdks", {}), lang, brief))
    lines.extend(_diff_section(_label(lang, "packers"), payload.get("packers", {}), lang, brief))
    lines.extend(_diff_section(_label(lang, "native_libraries"), payload.get("native_libraries", {}), lang, brief))

    signatures = payload.get("signatures", {}) if isinstance(payload.get("signatures"), dict) else {}
    lines.extend([f"## {_label(lang, 'signatures')}", ""])
    schemes = signatures.get("schemes", {}) if isinstance(signatures.get("schemes"), dict) else {}
    lines.extend(_list_samples(f"{_label(lang, 'added')} schemes", schemes.get("added", []), lang, brief))
    lines.extend(_list_samples(f"{_label(lang, 'removed')} schemes", schemes.get("removed", []), lang, brief))
    lines.append(f"- APK SHA256: {_label(lang, 'changed') if signatures.get('apk_sha256_changed') else _label(lang, 'unchanged')}")
    lines.append("")

    if brief:
        lines.extend([f"> {_label(lang, 'samples_note')}", ""])
    return "\n".join(lines).rstrip() + "\n"


def _apk_payload(report: AnalysisReport) -> dict[str, object]:
    return {
        "file_name": report.apk.file_name,
        "file_path": report.apk.file_path,
        "file_size": report.apk.file_size,
        "app_name": report.apk.app_name,
        "package_name": report.apk.package_name,
        "version_name": report.apk.version_name,
        "version_code": report.apk.version_code,
        "min_sdk": report.apk.min_sdk,
        "target_sdk": report.apk.target_sdk,
        "compile_sdk": report.apk.compile_sdk,
        "sha256": report.apk.hashes.sha256,
    }


def _risk_counts(report: AnalysisReport) -> dict[str, int]:
    counts = report.statistics.get("findings_by_severity", {}) if report.statistics else {}
    return {
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
        "info": counts.get("info", 0),
        "total": len(report.findings),
    }


def _set_diff(old: set[str], new: set[str]) -> dict[str, list[str]]:
    return {
        "added": sorted(new - old),
        "removed": sorted(old - new),
        "unchanged": sorted(old & new),
    }


def _counter_diff(old: Counter[str], new: Counter[str]) -> dict[str, dict[str, int]]:
    keys = sorted(set(old) | set(new))
    return {key: {"old": old.get(key, 0), "new": new.get(key, 0), "delta": new.get(key, 0) - old.get(key, 0)} for key in keys}


def _string_values(report: AnalysisReport, finding_type: str) -> set[str]:
    return {item.value for item in report.strings if item.type == finding_type}


def _component_map(report: AnalysisReport) -> dict[str, dict[str, object]]:
    output: dict[str, dict[str, object]] = {}
    for component in report.manifest.components:
        key = _component_key(component)
        output[key] = {
            "type": component.type,
            "name": component.name,
            "exported": component.exported,
            "enabled": component.enabled,
            "permission": component.permission,
            "authorities": component.authorities,
        }
    return output


def _component_key(component: Component) -> str:
    return f"{component.type}:{component.name}"


def _exported_count(report: AnalysisReport) -> int:
    return int(report.statistics.get("exported_components", 0)) if report.statistics else 0


def _diff_section(title: str, value: object, language: str, brief: bool) -> list[str]:
    diff = value if isinstance(value, dict) else {}
    lines = [f"## {title}", ""]
    lines.extend(_list_samples(_label(language, "added"), diff.get("added", []), language, brief))
    lines.extend(_list_samples(_label(language, "removed"), diff.get("removed", []), language, brief))
    return lines


def _list_samples(title: str, values: object, language: str, brief: bool) -> list[str]:
    items = [str(item) for item in values] if isinstance(values, list) else []
    limit = 20 if brief else len(items)
    lines = [f"### {title}", ""]
    if not items:
        lines.extend([f"- {_label(language, 'none')}", ""])
        return lines
    for item in items[:limit]:
        lines.append(f"- {item}")
    if brief and len(items) > limit:
        lines.append(f"- ... +{len(items) - limit}")
    lines.append("")
    return lines


def _component_lines(values: object) -> list[str]:
    if not isinstance(values, list):
        return []
    lines: list[str] = []
    for item in values:
        if isinstance(item, dict):
            permission = f", permission={item.get('permission')}" if item.get("permission") else ""
            lines.append(f"{item.get('type')} {item.get('name')} (exported={item.get('exported')}{permission})")
    return lines


def _changed_text(old: object, new: object, language: str) -> str:
    if old == new:
        return _label(language, "unchanged")
    return f"{old} -> {new}"


def _signed(value: object) -> str:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return str(value)
    return f"+{number}" if number > 0 else str(number)


def _normalize_language(language: str) -> str:
    normalized = (language or "zh").lower()
    return normalized if normalized in LABELS else "zh"


def _label(language: str, key: str) -> str:
    lang = _normalize_language(language)
    return LABELS[lang].get(key, LABELS["en"].get(key, key))


def _progress(progress: Callable[[str], None] | None, message: str) -> None:
    if progress is not None:
        progress(message)
