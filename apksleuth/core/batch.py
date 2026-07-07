from __future__ import annotations

import json
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import re

from apksleuth.core.analyzer import AnalysisError, analyze_apk
from apksleuth.core.report_generator import render_report
from apksleuth.models import AnalysisReport


FORMAT_EXTENSIONS = {
    "html": "html",
    "json": "json",
    "markdown": "md",
    "summary": "summary.md",
    "summary-json": "summary.json",
}


@dataclass
class BatchItem:
    apk_path: str
    report_path: str | None
    file_name: str
    app_name: str | None = None
    package_name: str | None = None
    version_name: str | None = None
    version_code: str | None = None
    file_size: int | None = None
    sha256: str | None = None
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total_findings: int = 0
    exported_components: int = 0
    http_urls: int = 0
    possible_secrets: int = 0
    native_libraries: int = 0
    sdks: list[str] | None = None
    packers: list[str] | None = None
    errors: list[str] | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "apk_path": self.apk_path,
            "report_path": self.report_path,
            "file_name": self.file_name,
            "app_name": self.app_name,
            "package_name": self.package_name,
            "version_name": self.version_name,
            "version_code": self.version_code,
            "file_size": self.file_size,
            "sha256": self.sha256,
            "risk": {
                "total": self.total_findings,
                "high": self.high,
                "medium": self.medium,
                "low": self.low,
                "info": self.info,
            },
            "signals": {
                "exported_components": self.exported_components,
                "http_urls": self.http_urls,
                "possible_secrets": self.possible_secrets,
                "native_libraries": self.native_libraries,
            },
            "sdks": self.sdks or [],
            "packers": self.packers or [],
            "errors": self.errors or [],
        }


def run_batch_scan(
    input_dir: str | Path,
    output_dir: str | Path,
    report_format: str = "summary",
    language: str = "zh",
    recursive: bool = False,
    max_entry_bytes: int = 4 * 1024 * 1024,
    progress: Callable[[str], None] | None = None,
) -> dict[str, object]:
    source = Path(input_dir).expanduser().resolve()
    destination = Path(output_dir).expanduser().resolve()
    normalized_format = report_format.lower()
    if normalized_format not in FORMAT_EXTENSIONS:
        raise AnalysisError(f"Unsupported batch report format: {report_format}")
    if not source.exists():
        raise AnalysisError(f"APK directory does not exist: {source}")
    if not source.is_dir():
        raise AnalysisError(f"APK directory path is not a directory: {source}")

    apks = sorted(source.rglob("*.apk") if recursive else source.glob("*.apk"))
    if not apks:
        raise AnalysisError(f"No APK files were found in: {source}")

    destination.mkdir(parents=True, exist_ok=True)
    used_names: set[str] = set()
    items: list[BatchItem] = []

    for index, apk_path in enumerate(apks, start=1):
        _progress(progress, f"[{index}/{len(apks)}] Scanning {apk_path.name}")
        try:
            report = analyze_apk(apk_path, max_entry_bytes=max_entry_bytes)
            report_path = destination / _report_file_name(apk_path, normalized_format, used_names)
            report_path.write_text(render_report(report, normalized_format, language=language), encoding="utf-8")
            items.append(_item_from_report(apk_path, report_path, report))
        except AnalysisError as exc:
            items.append(
                BatchItem(
                    apk_path=str(apk_path),
                    report_path=None,
                    file_name=apk_path.name,
                    errors=[str(exc)],
                )
            )
            _progress(progress, f"Failed to scan {apk_path.name}: {exc}")

    payload = _batch_payload(source, destination, normalized_format, language, recursive, items)
    (destination / "index.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    (destination / "index.md").write_text(_render_index_markdown(payload, language), encoding="utf-8")
    _progress(progress, f"Batch complete: {payload['succeeded']} succeeded, {payload['failed']} failed")
    return payload


def _item_from_report(apk_path: Path, report_path: Path, report: AnalysisReport) -> BatchItem:
    counts = report.statistics.get("findings_by_severity", {}) if report.statistics else {}
    string_counts = report.statistics.get("strings", {}) if report.statistics else {}
    return BatchItem(
        apk_path=str(apk_path),
        report_path=str(report_path),
        file_name=apk_path.name,
        app_name=report.apk.app_name,
        package_name=report.apk.package_name,
        version_name=report.apk.version_name,
        version_code=report.apk.version_code,
        file_size=report.apk.file_size,
        sha256=report.apk.hashes.sha256,
        high=counts.get("high", 0),
        medium=counts.get("medium", 0),
        low=counts.get("low", 0),
        info=counts.get("info", 0),
        total_findings=len(report.findings),
        exported_components=int(report.statistics.get("exported_components", 0)) if report.statistics else 0,
        http_urls=sum(1 for item in report.strings if item.type == "url" and item.value.lower().startswith("http://")),
        possible_secrets=string_counts.get("possible_secret", 0) + string_counts.get("jwt", 0),
        native_libraries=len(report.native_libraries),
        sdks=[item.name for item in report.sdks],
        packers=[item.name for item in report.packers],
        errors=report.errors,
    )


def _batch_payload(
    source: Path,
    destination: Path,
    report_format: str,
    language: str,
    recursive: bool,
    items: list[BatchItem],
) -> dict[str, object]:
    succeeded = [item for item in items if not item.errors]
    failed = [item for item in items if item.errors]
    severity_totals = Counter()
    sdk_totals = Counter()
    packer_totals = Counter()
    for item in succeeded:
        severity_totals.update({"high": item.high, "medium": item.medium, "low": item.low, "info": item.info})
        sdk_totals.update(item.sdks or [])
        packer_totals.update(item.packers or [])

    ranked = sorted(succeeded, key=lambda item: (item.high, item.medium, item.total_findings), reverse=True)
    return {
        "language": language,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_dir": str(source),
        "output_dir": str(destination),
        "report_format": report_format,
        "recursive": recursive,
        "total": len(items),
        "succeeded": len(succeeded),
        "failed": len(failed),
        "risk_totals": dict(severity_totals),
        "sdk_totals": dict(sdk_totals.most_common()),
        "packer_totals": dict(packer_totals.most_common()),
        "risk_ranking": [item.to_dict() for item in ranked],
        "items": [item.to_dict() for item in items],
    }


def _render_index_markdown(payload: dict[str, object], language: str) -> str:
    is_zh = language == "zh"
    title = "ApkSleuth 批量扫描总览" if is_zh else "ApkSleuth Batch Summary"
    overview = "概览" if is_zh else "Overview"
    ranking = "风险排行" if is_zh else "Risk Ranking"
    sdks = "SDK 统计" if is_zh else "SDK Statistics"
    failures = "失败项" if is_zh else "Failures"
    labels = {
        "generated": "生成时间" if is_zh else "Generated",
        "input": "输入目录" if is_zh else "Input Directory",
        "output": "输出目录" if is_zh else "Output Directory",
        "format": "报告格式" if is_zh else "Report Format",
        "total": "APK 总数" if is_zh else "Total APKs",
        "succeeded": "成功" if is_zh else "Succeeded",
        "failed": "失败" if is_zh else "Failed",
        "app": "应用" if is_zh else "App",
        "package": "包名" if is_zh else "Package",
        "high": "高危" if is_zh else "High",
        "medium": "中危" if is_zh else "Medium",
        "low": "低危" if is_zh else "Low",
        "report": "报告" if is_zh else "Report",
        "count": "数量" if is_zh else "Count",
        "error": "错误" if is_zh else "Error",
    }

    lines = [f"# {title}", "", f"## {overview}", ""]
    for key, field in (
        ("generated", "generated_at"),
        ("input", "input_dir"),
        ("output", "output_dir"),
        ("format", "report_format"),
        ("total", "total"),
        ("succeeded", "succeeded"),
        ("failed", "failed"),
    ):
        lines.append(f"- {labels[key]}: {payload.get(field)}")
    risk_totals = payload.get("risk_totals", {})
    if isinstance(risk_totals, dict):
        lines.extend([
            f"- {labels['high']}: {risk_totals.get('high', 0)}",
            f"- {labels['medium']}: {risk_totals.get('medium', 0)}",
            f"- {labels['low']}: {risk_totals.get('low', 0)}",
        ])
    lines.extend(["", f"## {ranking}", ""])
    lines.append(f"| {labels['app']} | {labels['package']} | {labels['high']} | {labels['medium']} | {labels['low']} | {labels['report']} |")
    lines.append("| --- | --- | ---: | ---: | ---: | --- |")
    for item in payload.get("risk_ranking", []):
        if not isinstance(item, dict):
            continue
        risk = item.get("risk", {}) if isinstance(item.get("risk"), dict) else {}
        report_path = item.get("report_path") or ""
        report_name = Path(str(report_path)).name if report_path else ""
        report_cell = f"[{report_name}]({report_name})" if report_name else ""
        lines.append(
            f"| {item.get('app_name') or item.get('file_name') or ''} | `{item.get('package_name') or ''}` | "
            f"{risk.get('high', 0)} | {risk.get('medium', 0)} | {risk.get('low', 0)} | {report_cell} |"
        )

    sdk_totals = payload.get("sdk_totals", {})
    if isinstance(sdk_totals, dict) and sdk_totals:
        lines.extend(["", f"## {sdks}", "", f"| SDK | {labels['count']} |", "| --- | ---: |"])
        for name, count in sdk_totals.items():
            lines.append(f"| {name} | {count} |")

    failed_items = [item for item in payload.get("items", []) if isinstance(item, dict) and item.get("errors")]
    if failed_items:
        lines.extend(["", f"## {failures}", "", f"| APK | {labels['error']} |", "| --- | --- |"])
        for item in failed_items:
            lines.append(f"| {item.get('file_name')} | {'; '.join(item.get('errors', []))} |")

    return "\n".join(lines).rstrip() + "\n"


def _report_file_name(apk_path: Path, report_format: str, used_names: set[str]) -> str:
    extension = FORMAT_EXTENSIONS[report_format]
    base = _safe_stem(apk_path.stem)
    candidate = f"{base}.{extension}"
    counter = 2
    while candidate.lower() in used_names:
        candidate = f"{base}-{counter}.{extension}"
        counter += 1
    used_names.add(candidate.lower())
    return candidate


def _safe_stem(value: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip(".-")
    return sanitized or "apk"


def _progress(progress: Callable[[str], None] | None, message: str) -> None:
    if progress is not None:
        progress(message)
