from __future__ import annotations

import re
import zipfile
from collections import defaultdict
from collections.abc import Callable
from urllib.parse import urlparse

from apksleuth.models import StringFinding


URL_RE = re.compile(
    rb"https?://(?:"
    rb"(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}"
    rb"|(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}"
    rb"|localhost"
    rb")(?::\d{1,5})?(?:/[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]*)?",
    re.IGNORECASE,
)
IP_RE = re.compile(rb"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])")
EMAIL_RE = re.compile(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
JWT_RE = re.compile(rb"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
BASE64_RE = re.compile(rb"\b(?:[A-Za-z0-9+/]{40,}={0,2})\b")
SECRET_RE = re.compile(
    r"(?i)['\"]?\b(api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|secret|password|passwd)\b['\"]?"
    r"\s*(?::|=(?!=))\s*['\"]?([A-Za-z0-9_\-./+=]{8,})"
)

TRAILING = ".,);]}>'\""
SKIP_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".markdown",
    ".md",
    ".mp3",
    ".mp4",
    ".ogg",
    ".org",
    ".wav",
    ".arsc",
    ".dtd",
    ".java",
    ".xsd",
    ".ttf",
    ".otf",
    ".woff",
    ".woff2",
    ".eot",
    ".svg",
    ".bks",
    ".cer",
    ".crt",
    ".der",
    ".pem",
    ".so",
}
SKIP_BASENAMES = {
    "license",
    "license.txt",
    "notice",
    "notice.txt",
    "copying",
    "copying.txt",
    "effective_tld_names.dat",
    "public_suffix_list.dat",
    "readme",
    "readme.txt",
}
URL_NOISE_PREFIXES = (
    "http://schemas.android.com/",
    "https://schemas.android.com/",
    "http://schemas.xmlsoap.org/",
    "https://schemas.xmlsoap.org/",
    "http://www.w3.org/",
    "https://www.w3.org/",
)
URL_NOISE_HOSTS = {
    "apache.org",
    "almworks.com",
    "commonmark.org",
    "daringfireball.net",
    "creativecommons.org",
    "en.wikipedia.org",
    "fsf.org",
    "github.com",
    "gnu.org",
    "inkscape.org",
    "jmathtex.sourceforge.net",
    "jcip.net",
    "jeffreymartin.ca",
    "joda-time.sourceforge.net",
    "localhost",
    "lua-users.org",
    "mina.apache.org",
    "mozilla.org",
    "ns.adobe.com",
    "opensource.org",
    "orgmode.org",
    "protobuf.dev",
    "semver.org",
    "sodipodi.sourceforge.net",
    "stackoverflow.com",
    "todotxt.org",
    "tools.ietf.org",
    "underscorejs.org",
    "wikipedia.org",
    "www.allette.com.au",
    "www.apache.org",
    "www.creativecommons.org",
    "www.fsf.org",
    "www.gnu.org",
    "www.inf.puc-rio.br",
    "www.inkscape.org",
    "www.jcip.net",
    "www.lua-users.org",
    "www.mozilla.org",
    "www.opensource.org",
    "www.stackoverflow.com",
    "www.todotxt.org",
    "xml.org",
    "xmlpull.org",
    "engelschall.com",
}


def extract_strings(
    apk: zipfile.ZipFile,
    max_entry_bytes: int = 4 * 1024 * 1024,
    limit_per_type: int = 300,
    progress: Callable[[str], None] | None = None,
    progress_interval: int = 1000,
) -> list[StringFinding]:
    findings: list[StringFinding] = []
    seen: set[tuple[str, str, str]] = set()
    counts: dict[str, int] = defaultdict(int)
    entries = apk.infolist()
    total_entries = len(entries)

    for index, info in enumerate(entries, start=1):
        if info.is_dir() or _skip(info.filename):
            _emit_progress(progress, index, total_entries, findings, progress_interval)
            continue
        try:
            with apk.open(info) as file:
                data = file.read(max_entry_bytes)
        except (OSError, RuntimeError, zipfile.BadZipFile):
            _emit_progress(progress, index, total_entries, findings, progress_interval)
            continue
        if _skip_data(info.filename, data):
            _emit_progress(progress, index, total_entries, findings, progress_interval)
            continue

        _collect_bytes(findings, seen, counts, info.filename, "url", URL_RE, data, limit_per_type)
        _collect_bytes(findings, seen, counts, info.filename, "ip", IP_RE, data, limit_per_type)
        _collect_bytes(findings, seen, counts, info.filename, "email", EMAIL_RE, data, limit_per_type)
        _collect_bytes(findings, seen, counts, info.filename, "jwt", JWT_RE, data, limit_per_type)
        _collect_bytes(findings, seen, counts, info.filename, "base64", BASE64_RE, data, min(50, limit_per_type))
        _collect_secrets(findings, seen, counts, info.filename, data, limit_per_type)
        _emit_progress(progress, index, total_entries, findings, progress_interval)

    return sorted(findings, key=lambda item: (item.type, item.source, item.value))


def _collect_bytes(
    findings: list[StringFinding],
    seen: set[tuple[str, str, str]],
    counts: dict[str, int],
    source: str,
    finding_type: str,
    regex: re.Pattern[bytes],
    data: bytes,
    limit: int,
) -> None:
    if counts[finding_type] >= limit:
        return
    for match in regex.finditer(data):
        value = _clean(match.group(0).decode("utf-8", errors="ignore"))
        if not value or _is_noise(finding_type, value):
            continue
        key = (finding_type, value, source)
        if key in seen:
            continue
        seen.add(key)
        findings.append(StringFinding(finding_type, value, source, _severity(finding_type, value)))
        counts[finding_type] += 1
        if counts[finding_type] >= limit:
            break


def _collect_secrets(
    findings: list[StringFinding],
    seen: set[tuple[str, str, str]],
    counts: dict[str, int],
    source: str,
    data: bytes,
    limit: int,
) -> None:
    if counts["possible_secret"] >= limit:
        return
    text = data.decode("utf-8", errors="ignore")
    for match in SECRET_RE.finditer(text):
        secret_value = match.group(2)
        if _looks_like_code_reference(secret_value) or not _looks_like_secret_value(secret_value):
            continue
        value = _clean(match.group(0))
        key = ("possible_secret", value, source)
        if key in seen:
            continue
        seen.add(key)
        findings.append(StringFinding("possible_secret", value, source, "high"))
        counts["possible_secret"] += 1
        if counts["possible_secret"] >= limit:
            break


def _clean(value: str) -> str:
    return value.strip().strip(TRAILING)


def _severity(finding_type: str, value: str) -> str:
    if finding_type in {"jwt", "possible_secret"}:
        return "high"
    if finding_type == "url" and value.lower().startswith("http://"):
        return "medium"
    if finding_type in {"ip", "email", "base64"}:
        return "low"
    return "info"


def _skip(filename: str) -> bool:
    lower = filename.lower()
    basename = lower.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    if basename in SKIP_BASENAMES or any(lower.endswith(ext) for ext in SKIP_EXTENSIONS):
        return True
    if any(part in lower for part in ("/licenses/", "/licences/", "\\licenses\\", "\\licences\\")):
        return True
    if any(part in lower for part in ("/fonts/", "\\fonts\\", "/font/", "\\font\\")):
        return True
    return any(marker in basename for marker in ("license", "licence", "notice", "copying", "readme"))


def _skip_data(filename: str, data: bytes) -> bool:
    lower = filename.lower()
    if lower.endswith(".xml") and data.lstrip() and not data.lstrip().startswith(b"<"):
        return True
    if lower.endswith(".json") and _looks_like_dependency_notice_json(data):
        return True
    return False


def _looks_like_dependency_notice_json(data: bytes) -> bool:
    sample = data[:8192]
    return b'"libraries"' in sample and b'"uniqueId"' in sample and b'"licenses"' in sample


def _emit_progress(
    progress: Callable[[str], None] | None,
    index: int,
    total_entries: int,
    findings: list[StringFinding],
    progress_interval: int,
) -> None:
    if progress is None:
        return
    if index == total_entries or index % progress_interval == 0:
        progress(f"String extraction: {index}/{total_entries} entries, {len(findings)} artifacts")


def _is_noise(finding_type: str, value: str) -> bool:
    if finding_type == "url":
        return _is_noise_url(value)
    if finding_type == "base64":
        return len(set(value)) < 8
    if finding_type == "ip":
        return value in {"0.0.0.0", "255.255.255.255"}
    return False


def _is_noise_url(value: str) -> bool:
    lower = value.lower()
    if lower.startswith(URL_NOISE_PREFIXES):
        return True
    parsed = urlparse(lower)
    host = parsed.hostname or ""
    return host in URL_NOISE_HOSTS


def _looks_like_code_reference(value: str) -> bool:
    lower = value.strip().lower()
    if lower.startswith(("this.", "self.", "window.", "global.", "process.")):
        return True
    if re.fullmatch(r"[a-z_$][\w$]{0,3}(?:\.[a-z_$][\w$]*)+", lower):
        return True
    if lower in {"undefined", "null", "true", "false", "password", "token", "secret"}:
        return True
    if lower.startswith(("encodeuricomponent", "decodeuricomponent")):
        return True
    if lower.startswith(("==", "=>")):
        return True
    return False


def _looks_like_secret_value(value: str) -> bool:
    stripped = value.strip().strip("'\"")
    if len(stripped) < 12:
        return False
    has_alpha = any(char.isalpha() for char in stripped)
    has_digit = any(char.isdigit() for char in stripped)
    has_symbol = any(char in "_-./+=" for char in stripped)
    if has_alpha and (has_digit or has_symbol):
        return True
    return len(stripped) >= 32
