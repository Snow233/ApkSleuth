from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

from apksleuth.core.analyzer import AnalysisError
from apksleuth.core.web_models import WebConfig


def extract_boundary(content_type: str) -> bytes:
    match = re.search(r"boundary=(?P<boundary>[^;]+)", content_type)
    if not match:
        raise AnalysisError("multipart/form-data 缺少 boundary。")
    boundary = match.group("boundary").strip().strip('"')
    return boundary.encode("utf-8")


def parse_multipart(body: bytes, boundary: bytes) -> tuple[dict[str, str], dict[str, list[dict[str, Any]]]]:
    marker = b"--" + boundary
    fields: dict[str, str] = {}
    files: dict[str, list[dict[str, Any]]] = {}
    for part in body.split(marker):
        part = part.strip(b"\r\n")
        if not part or part == b"--":
            continue
        if b"\r\n\r\n" not in part:
            continue
        raw_headers, content = part.split(b"\r\n\r\n", 1)
        if content.endswith(b"\r\n"):
            content = content[:-2]
        headers = raw_headers.decode("utf-8", errors="replace")
        disposition = next((line for line in headers.split("\r\n") if line.lower().startswith("content-disposition:")), "")
        name = disposition_value(disposition, "name")
        filename = disposition_value(disposition, "filename")
        if not name:
            continue
        if filename is not None:
            files.setdefault(name, []).append({"filename": filename, "content": content})
        else:
            fields[name] = content.decode("utf-8", errors="replace")
    return fields, files


def disposition_value(disposition: str, key: str) -> str | None:
    match = re.search(rf'{key}="([^"]*)"', disposition)
    return match.group(1) if match else None


def validate_local_apk(value: str) -> Path:
    path = Path(value).expanduser().resolve()
    if not path.exists() or not path.is_file():
        raise AnalysisError(f"APK 文件不存在: {path}")
    if path.suffix.lower() != ".apk":
        raise AnalysisError(f"不是 APK 文件: {path}")
    return path


def validate_local_apks(value: str) -> list[Path]:
    paths = [validate_local_apk(item) for item in split_local_paths(value)]
    if not paths:
        raise AnalysisError("请上传 APK 文件，或填写本机 APK 路径。")
    return paths


def split_local_paths(value: str) -> list[str]:
    return [item.strip().strip('"') for item in re.split(r"[\r\n]+", value) if item.strip()]


def save_upload(config: WebConfig, file_part: dict[str, Any]) -> Path:
    filename = safe_filename(str(file_part.get("filename") or "upload.apk"))
    if not filename.lower().endswith(".apk"):
        filename += ".apk"
    destination = config.workdir / "uploads" / f"{int(time.time())}-{uuid4().hex[:8]}-{filename}"
    destination.write_bytes(file_part["content"])
    return destination


def safe_filename(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", Path(value).name).strip(".-")
    return cleaned or "upload.apk"


def safe_segment(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "", value)


def content_type(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".html":
        return "text/html; charset=utf-8"
    if suffix == ".json":
        return "application/json; charset=utf-8"
    if suffix == ".md":
        return "text/markdown; charset=utf-8"
    return "application/octet-stream"


def path_under(path: Path, root: Path) -> bool:
    return path == root or root in path.parents
