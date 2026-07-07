from __future__ import annotations

import zipfile
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from apksleuth import __version__
from apksleuth.core.certificate_analyzer import analyze_certificates
from apksleuth.core.manifest_analyzer import parse_manifest
from apksleuth.core.native_analyzer import analyze_native_libraries
from apksleuth.core.packer_detector import detect_packers
from apksleuth.core.permission_analyzer import analyze_permissions
from apksleuth.core.risk_engine import confidence_counts, run_risk_engine, severity_counts
from apksleuth.core.resources import ResourceTableError, parse_resource_table
from apksleuth.core.sdk_detector import detect_sdks
from apksleuth.core.string_extractor import extract_strings
from apksleuth.core.utils import hash_file
from apksleuth.models import AnalysisReport, ApkInfo, ManifestSummary


class AnalysisError(RuntimeError):
    """Raised for user-facing APK analysis failures."""


def analyze_apk(
    apk_path: str | Path,
    max_entry_bytes: int = 4 * 1024 * 1024,
    progress: Callable[[str], None] | None = None,
) -> AnalysisReport:
    path = Path(apk_path).expanduser().resolve()
    if not path.exists():
        raise AnalysisError(f"APK file does not exist: {path}")
    if not path.is_file():
        raise AnalysisError(f"APK path is not a file: {path}")

    hashes = hash_file(path)
    apk_info = ApkInfo(
        file_name=path.name,
        file_path=str(path),
        file_size=path.stat().st_size,
        hashes=hashes,
    )
    errors: list[str] = []

    if not zipfile.is_zipfile(path):
        raise AnalysisError(f"Not a valid APK/ZIP file: {path}")

    try:
        with zipfile.ZipFile(path) as apk:
            _progress(progress, "Reading AndroidManifest.xml")
            manifest = _read_manifest(apk, errors)
            _progress(progress, "Resolving resources.arsc values")
            _resolve_manifest_resources(apk, manifest, errors)
            _copy_manifest_fields(apk_info, manifest)

            _progress(progress, "Analyzing permissions")
            permissions = analyze_permissions(manifest.permissions)
            _progress(progress, "Extracting URLs, IPs, emails, and secrets")
            strings = extract_strings(apk, max_entry_bytes=max_entry_bytes, progress=progress)
            _progress(progress, "Analyzing APK signatures")
            certificate = analyze_certificates(apk, path)
            _progress(progress, "Analyzing native libraries")
            native_libraries = analyze_native_libraries(apk)
            _progress(progress, "Detecting SDK fingerprints")
            sdks = detect_sdks(apk, strings, manifest)
            _progress(progress, "Detecting packer fingerprints")
            packers = detect_packers(apk, manifest)

            report = AnalysisReport(
                tool_name="ApkSleuth",
                tool_version=__version__,
                generated_at=datetime.now(timezone.utc).isoformat(),
                apk=apk_info,
                manifest=manifest,
                permissions=permissions,
                strings=strings,
                certificate=certificate,
                native_libraries=native_libraries,
                sdks=sdks,
                packers=packers,
                errors=errors,
            )
            _progress(progress, "Running risk rules")
            report.findings = run_risk_engine(report)
            report.statistics = _statistics(report)
            _progress(progress, "Analysis complete")
            return report
    except zipfile.BadZipFile as exc:
        raise AnalysisError(f"Failed to read APK ZIP structure: {exc}") from exc


def _read_manifest(apk: zipfile.ZipFile, errors: list[str]) -> ManifestSummary:
    try:
        data = apk.read("AndroidManifest.xml")
    except KeyError:
        errors.append("AndroidManifest.xml was not found in the APK.")
        return ManifestSummary(parse_error="AndroidManifest.xml was not found in the APK.")
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        errors.append(f"Failed to read AndroidManifest.xml: {exc}")
        return ManifestSummary(parse_error=str(exc))

    manifest = parse_manifest(data)
    if manifest.parse_error:
        errors.append(f"Manifest parse error: {manifest.parse_error}")
    return manifest


def _resolve_manifest_resources(apk: zipfile.ZipFile, manifest: ManifestSummary, errors: list[str]) -> None:
    if not _looks_like_resource_ref(manifest.app_name):
        return
    try:
        data = apk.read("resources.arsc")
    except KeyError:
        return
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        errors.append(f"Failed to read resources.arsc: {exc}")
        return

    try:
        resources = parse_resource_table(data)
    except ResourceTableError as exc:
        errors.append(f"Failed to parse resources.arsc: {exc}")
        return

    resolved_app_name = resources.resolve(manifest.app_name)
    if resolved_app_name and resolved_app_name != manifest.app_name:
        manifest.app_name = resolved_app_name


def _looks_like_resource_ref(value: str | None) -> bool:
    return bool(value and value.startswith("@0x"))


def _progress(progress: Callable[[str], None] | None, message: str) -> None:
    if progress is not None:
        progress(message)


def _copy_manifest_fields(apk_info: ApkInfo, manifest: ManifestSummary) -> None:
    apk_info.package_name = manifest.package_name
    apk_info.app_name = manifest.app_name
    apk_info.version_name = manifest.version_name
    apk_info.version_code = manifest.version_code
    apk_info.min_sdk = manifest.min_sdk
    apk_info.target_sdk = manifest.target_sdk
    apk_info.compile_sdk = manifest.compile_sdk


def _statistics(report: AnalysisReport) -> dict[str, object]:
    string_counts: dict[str, int] = {}
    for item in report.strings:
        string_counts[item.type] = string_counts.get(item.type, 0) + 1

    component_counts: dict[str, int] = {}
    exported_components = 0
    for component in report.manifest.components:
        component_counts[component.type] = component_counts.get(component.type, 0) + 1
        if component.externally_reachable:
            exported_components += 1

    return {
        "findings_by_severity": severity_counts(report.findings),
        "findings_by_confidence": confidence_counts(report.findings),
        "permissions": len(report.manifest.permissions),
        "components": component_counts,
        "exported_components": exported_components,
        "strings": string_counts,
        "native_libraries": len(report.native_libraries),
        "sdks": len(report.sdks),
        "packers": len(report.packers),
        "signature_schemes": report.certificate.schemes,
    }
