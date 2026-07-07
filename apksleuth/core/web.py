from __future__ import annotations

import json
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from apksleuth.core.analyzer import AnalysisError
from apksleuth.core.web_jobs import create_job as _create_job
from apksleuth.core.web_jobs import create_web_reports, delete_analysis as _delete_analysis
from apksleuth.core.web_jobs import job_payload as _job_payload
from apksleuth.core.web_jobs import run_analysis_job as _run_analysis_job
from apksleuth.core.web_jobs import start_analysis_job as _start_analysis_job
from apksleuth.core.web_models import WebConfig
from apksleuth.core.web_render import _recent_analyses, _render_analysis, _render_error, _render_index, _render_job
from apksleuth.core.web_utils import content_type as _content_type
from apksleuth.core.web_utils import extract_boundary as _extract_boundary
from apksleuth.core.web_utils import parse_multipart as _parse_multipart
from apksleuth.core.web_utils import path_under as _path_under
from apksleuth.core.web_utils import safe_segment as _safe_segment
from apksleuth.core.web_utils import save_upload as _save_upload
from apksleuth.core.web_utils import split_local_paths as _split_local_paths
from apksleuth.core.web_utils import validate_local_apks as _validate_local_apks


__all__ = [
    "WebConfig",
    "create_web_reports",
    "run_web_server",
    "_create_job",
    "_delete_analysis",
    "_job_payload",
    "_parse_multipart",
    "_recent_analyses",
    "_render_analysis",
    "_render_index",
    "_render_job",
    "_run_analysis_job",
    "_split_local_paths",
]


def run_web_server(
    host: str = "127.0.0.1",
    port: int = 8765,
    workdir: str | Path = ".apksleuth-web",
    language: str = "zh",
    max_entry_bytes: int = 4 * 1024 * 1024,
    open_browser: bool = False,
) -> None:
    config = WebConfig(host=host, port=port, workdir=Path(workdir).resolve(), language=language, max_entry_bytes=max_entry_bytes)
    config.workdir.mkdir(parents=True, exist_ok=True)
    (config.workdir / "uploads").mkdir(exist_ok=True)
    (config.workdir / "reports").mkdir(exist_ok=True)

    handler = _handler_factory(config)
    server = ThreadingHTTPServer((config.host, config.port), handler)
    url = f"http://{config.host}:{server.server_port}/"
    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    print(f"ApkSleuth Web UI running at {url}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping ApkSleuth Web UI...")
    finally:
        server.server_close()


def _handler_factory(config: WebConfig):
    class ApkSleuthHandler(BaseHTTPRequestHandler):
        server_version = "ApkSleuthWeb/0.1"

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            parsed = urlparse(self.path)
            if parsed.path == "/":
                self._send_html(_render_index(config))
                return
            if parsed.path.startswith("/jobs/"):
                job_id = _safe_segment(parsed.path.removeprefix("/jobs/"))
                self._send_html(_render_job(config, job_id))
                return
            if parsed.path.startswith("/api/jobs/"):
                job_id = _safe_segment(parsed.path.removeprefix("/api/jobs/"))
                self._send_json(_job_payload(config, job_id))
                return
            if parsed.path.startswith("/analysis/"):
                job_id = _safe_segment(parsed.path.removeprefix("/analysis/"))
                self._send_html(_render_analysis(config, job_id))
                return
            if parsed.path.startswith("/files/"):
                self._serve_file(config, parsed.path)
                return
            self._send_html(_render_error("页面不存在", "The requested page was not found."), status=404)

        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            parsed = urlparse(self.path)
            if parsed.path.startswith("/delete/"):
                job_id = _safe_segment(parsed.path.removeprefix("/delete/"))
                if not job_id:
                    self._send_html(_render_error("历史记录无效", "Invalid analysis history id."), status=400)
                    return
                _delete_analysis(config, job_id)
                self.send_response(303)
                self.send_header("Location", "/")
                self.end_headers()
                return

            if parsed.path != "/scan":
                self._send_html(_render_error("路径不支持", "Unsupported POST path."), status=404)
                return

            try:
                job_ids = [_start_analysis_job(config, apk_path) for apk_path in self._receive_apks(config)]
                self.send_response(303)
                self.send_header("Location", f"/jobs/{job_ids[0]}" if len(job_ids) == 1 else "/")
                self.end_headers()
            except Exception as exc:  # noqa: BLE001 - web UI should render user-facing failures.
                self._send_html(_render_error("分析失败", str(exc)), status=500)

        def log_message(self, format: str, *args: object) -> None:
            print(f"[{self.log_date_time_string()}] {format % args}")

        def _receive_apks(self, config: WebConfig) -> list[Path]:
            length = int(self.headers.get("Content-Length", "0"))
            content_type = self.headers.get("Content-Type", "")
            body = self.rfile.read(length)

            if content_type.startswith("multipart/form-data"):
                boundary = _extract_boundary(content_type)
                fields, files = _parse_multipart(body, boundary)
                local_path = fields.get("apk_path", "").strip()
                uploaded = [_save_upload(config, part) for part in files.get("apk", []) if part.get("content")]
                if uploaded:
                    return uploaded
                if local_path:
                    return _validate_local_apks(local_path)
            elif content_type.startswith("application/x-www-form-urlencoded"):
                fields = parse_qs(body.decode("utf-8", errors="replace"))
                local_path = fields.get("apk_path", [""])[0].strip()
                if local_path:
                    return _validate_local_apks(local_path)
            raise AnalysisError("请上传 APK 文件，或填写本机 APK 路径。")

        def _serve_file(self, config: WebConfig, request_path: str) -> None:
            parts = [unquote(part) for part in request_path.split("/") if part]
            if len(parts) != 3:
                self._send_html(_render_error("文件路径无效", "Invalid file path."), status=400)
                return
            _, job_id, filename = parts
            job_id = _safe_segment(job_id)
            filename = _safe_segment(filename)
            file_path = (config.workdir / "reports" / job_id / filename).resolve()
            reports_root = (config.workdir / "reports").resolve()
            if not _path_under(file_path, reports_root) or not file_path.is_file():
                self._send_html(_render_error("文件不存在", "File not found."), status=404)
                return
            self.send_response(200)
            self.send_header("Content-Type", _content_type(file_path))
            self.send_header("Content-Disposition", f'inline; filename="{file_path.name}"')
            self.send_header("Content-Length", str(file_path.stat().st_size))
            self.end_headers()
            with file_path.open("rb") as file:
                self.wfile.write(file.read())

        def _send_html(self, html: str, status: int = 200) -> None:
            data = html.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _send_json(self, payload: dict[str, Any], status: int = 200) -> None:
            data = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return ApkSleuthHandler
