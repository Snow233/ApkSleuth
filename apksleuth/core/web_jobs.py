from __future__ import annotations

import json
import re
import shutil
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from uuid import uuid4

from apksleuth.core.analyzer import analyze_apk
from apksleuth.core.report_generator import render_report
from apksleuth.core.web_models import WebConfig, WebJob
from apksleuth.core.web_utils import path_under, safe_segment


WEB_METADATA_FILE = "metadata.json"


def create_web_reports(
    apk_path: str | Path,
    report_dir: str | Path,
    language: str = "zh",
    max_entry_bytes: int = 4 * 1024 * 1024,
    progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    report_path = Path(report_dir)
    report_path.mkdir(parents=True, exist_ok=True)
    report = analyze_apk(apk_path, max_entry_bytes=max_entry_bytes, progress=progress)

    outputs = {
        "summary_md": "report.summary.md",
        "summary_json": "report.summary.json",
        "html": "report.html",
        "json": "report.json",
    }
    (report_path / outputs["summary_md"]).write_text(render_report(report, "summary", language=language), encoding="utf-8")
    summary_json = render_report(report, "summary-json", language=language)
    (report_path / outputs["summary_json"]).write_text(summary_json, encoding="utf-8")
    (report_path / outputs["html"]).write_text(render_report(report, "html", language=language), encoding="utf-8")
    (report_path / outputs["json"]).write_text(render_report(report, "json", language=language), encoding="utf-8")

    payload = json.loads(summary_json)
    payload["files"] = outputs
    return payload


def create_job(config: WebConfig, job_id: str, apk_name: str, report_dir: Path, apk_path: Path | None = None) -> None:
    report_dir.mkdir(parents=True, exist_ok=True)
    write_job_metadata(config, job_id, apk_name, report_dir, apk_path)
    with config.lock:
        config.jobs[job_id] = WebJob(job_id=job_id, apk_name=apk_name, report_dir=str(report_dir))


def start_analysis_job(config: WebConfig, apk_path: Path) -> str:
    job_id = f"{int(time.time())}-{uuid4().hex[:8]}"
    report_dir = config.workdir / "reports" / job_id
    create_job(config, job_id, apk_path.name, report_dir, apk_path)
    thread = threading.Thread(target=run_analysis_job, args=(config, job_id, apk_path, report_dir), daemon=True)
    thread.start()
    return job_id


def update_job(config: WebConfig, job_id: str, **updates: object) -> None:
    with config.lock:
        job = config.jobs.get(job_id)
        if job is None:
            return
        for key, value in updates.items():
            if hasattr(job, key):
                setattr(job, key, value)
        job.updated_at = time.time()


def get_job(config: WebConfig, job_id: str) -> WebJob | None:
    with config.lock:
        return config.jobs.get(job_id)


def delete_analysis(config: WebConfig, job_id: str) -> bool:
    safe_job_id = safe_segment(job_id)
    if not safe_job_id:
        return False
    reports_root = (config.workdir / "reports").resolve()
    report_dir = (reports_root / safe_job_id).resolve()
    if not path_under(report_dir, reports_root) or not report_dir.is_dir():
        return False
    delete_managed_upload(config, report_dir)
    shutil.rmtree(report_dir)
    with config.lock:
        config.jobs.pop(job_id, None)
    return True


def write_job_metadata(config: WebConfig, job_id: str, apk_name: str, report_dir: Path, apk_path: Path | None) -> None:
    upload_path = managed_upload_path(config, apk_path) if apk_path else None
    payload = {
        "job_id": job_id,
        "apk_name": apk_name,
        "created_at": time.time(),
        "source_apk_path": str(apk_path.resolve()) if apk_path else None,
        "managed_upload_path": str(upload_path) if upload_path else None,
    }
    (report_dir / WEB_METADATA_FILE).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def delete_managed_upload(config: WebConfig, report_dir: Path) -> None:
    upload_path = metadata_upload_path(config, report_dir) or legacy_upload_path(config, report_dir)
    if upload_path and upload_path.is_file():
        try:
            upload_path.unlink()
        except OSError:
            pass


def metadata_upload_path(config: WebConfig, report_dir: Path) -> Path | None:
    try:
        data = json.loads((report_dir / WEB_METADATA_FILE).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    value = data.get("managed_upload_path") if isinstance(data, dict) else None
    return managed_upload_path(config, Path(value)) if value else None


def legacy_upload_path(config: WebConfig, report_dir: Path) -> Path | None:
    try:
        data = json.loads((report_dir / "report.summary.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    apk = data.get("apk", {}) if isinstance(data, dict) else {}
    file_name = str(apk.get("file_name") or "") if isinstance(apk, dict) else ""
    if not re.match(r"^\d+-[0-9a-f]{8}-.+\.apk$", file_name):
        return None
    uploads_root = (config.workdir / "uploads").resolve()
    path = (uploads_root / file_name).resolve()
    return path if path_under(path, uploads_root) else None


def managed_upload_path(config: WebConfig, apk_path: Path) -> Path | None:
    uploads_root = (config.workdir / "uploads").resolve()
    path = apk_path.expanduser().resolve()
    return path if path_under(path, uploads_root) else None


def job_payload(config: WebConfig, job_id: str) -> dict[str, Any]:
    job = get_job(config, job_id)
    if job is None:
        report_dir = config.workdir / "reports" / job_id
        if (report_dir / "report.summary.json").exists():
            return {
                "job_id": job_id,
                "status": "done",
                "message": "分析完成",
                "analysis_url": f"/analysis/{job_id}",
                "error": None,
            }
        return {
            "job_id": job_id,
            "status": "missing",
            "message": "任务不存在",
            "analysis_url": None,
            "error": "job not found",
        }
    return {
        "job_id": job.job_id,
        "apk_name": job.apk_name,
        "status": job.status,
        "message": job.message,
        "created_at": job.created_at,
        "updated_at": job.updated_at,
        "analysis_url": f"/analysis/{job_id}" if job.status == "done" else None,
        "error": job.error,
    }


def run_analysis_job(config: WebConfig, job_id: str, apk_path: Path, report_dir: Path) -> None:
    def progress(message: str) -> None:
        update_job(config, job_id, status="running", message=message)

    try:
        update_job(config, job_id, status="running", message="开始分析")
        create_web_reports(
            apk_path,
            report_dir,
            language=config.language,
            max_entry_bytes=config.max_entry_bytes,
            progress=progress,
        )
        update_job(config, job_id, status="done", message="分析完成")
    except Exception as exc:  # noqa: BLE001 - report failures to browser.
        update_job(config, job_id, status="error", message="分析失败", error=str(exc))


def active_jobs(config: WebConfig) -> list[WebJob]:
    with config.lock:
        jobs = list(config.jobs.values())
    return sorted(jobs, key=lambda item: item.created_at, reverse=True)[:20]
