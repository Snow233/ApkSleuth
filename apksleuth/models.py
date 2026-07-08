from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class FileHashes:
    md5: str
    sha1: str
    sha256: str


@dataclass
class ApkInfo:
    file_name: str
    file_path: str
    file_size: int
    hashes: FileHashes
    package_name: str | None = None
    app_name: str | None = None
    version_name: str | None = None
    version_code: str | None = None
    min_sdk: str | None = None
    target_sdk: str | None = None
    compile_sdk: str | None = None


@dataclass
class IntentFilter:
    actions: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    data: list[dict[str, str]] = field(default_factory=list)


@dataclass
class Component:
    type: str
    name: str
    exported: bool | None = None
    enabled: bool | None = None
    permission: str | None = None
    read_permission: str | None = None
    write_permission: str | None = None
    authorities: str | None = None
    grant_uri_permissions: bool | None = None
    intent_filters: list[IntentFilter] = field(default_factory=list)

    @property
    def has_intent_filters(self) -> bool:
        return bool(self.intent_filters)

    @property
    def externally_reachable(self) -> bool:
        return self.enabled is not False and (self.exported is True or (self.exported is None and self.has_intent_filters))


@dataclass
class ManifestSummary:
    package_name: str | None = None
    app_name: str | None = None
    version_name: str | None = None
    version_code: str | None = None
    min_sdk: str | None = None
    target_sdk: str | None = None
    compile_sdk: str | None = None
    application_class: str | None = None
    permissions: list[str] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)
    debuggable: bool | None = None
    allow_backup: bool | None = None
    uses_cleartext_traffic: bool | None = None
    network_security_config: str | None = None
    deep_links: list[dict[str, str]] = field(default_factory=list)
    provider_authorities: list[str] = field(default_factory=list)
    parse_error: str | None = None


@dataclass
class PermissionAnalysis:
    name: str
    level: str
    description: str
    recommendation: str


@dataclass
class StringFinding:
    type: str
    value: str
    source: str
    severity: str


@dataclass
class SignatureFile:
    path: str
    size: int
    hashes: FileHashes


@dataclass
class CertificateInfo:
    subject: str | None = None
    issuer: str | None = None
    serial_number: str | None = None
    not_valid_before: str | None = None
    not_valid_after: str | None = None
    signature_algorithm: str | None = None
    sha1: str | None = None
    sha256: str | None = None
    is_debug: bool = False


@dataclass
class SignatureInfo:
    schemes: list[str] = field(default_factory=list)
    signature_files: list[SignatureFile] = field(default_factory=list)
    certificates: list[CertificateInfo] = field(default_factory=list)
    signing_block_ids: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class NativeLibrary:
    path: str
    abi: str
    name: str
    size: int
    hashes: FileHashes
    stripped: bool | None = None


@dataclass
class SdkFinding:
    name: str
    type: str
    matched_patterns: list[str]
    evidence: list[str]
    risk: str


@dataclass
class PackerFinding:
    name: str
    matched_patterns: list[str]
    evidence: list[str]
    confidence: str


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    category: str
    description: str
    evidence: str
    recommendation: str
    confidence: str = "medium"
    review_hint: str | None = None


@dataclass
class AnalysisReport:
    tool_name: str
    tool_version: str
    generated_at: str
    apk: ApkInfo
    manifest: ManifestSummary
    permissions: list[PermissionAnalysis] = field(default_factory=list)
    strings: list[StringFinding] = field(default_factory=list)
    certificate: SignatureInfo = field(default_factory=SignatureInfo)
    native_libraries: list[NativeLibrary] = field(default_factory=list)
    sdks: list[SdkFinding] = field(default_factory=list)
    packers: list[PackerFinding] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    statistics: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
