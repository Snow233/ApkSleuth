from __future__ import annotations

import argparse
import sys
from pathlib import Path

from apksleuth import __version__
from apksleuth.core.analyzer import AnalysisError, analyze_apk
from apksleuth.core.batch import run_batch_scan
from apksleuth.core.diff import DIFF_FORMATS, diff_apks, render_diff
from apksleuth.core.report_generator import SUPPORTED_FORMATS, SUPPORTED_LANGUAGES, render_report
from apksleuth.core.web import run_web_server


CLI_LOGO = r"""
    ___          __   _____ __          __  __
   /   |  ____  / /__/ ___// /__  __  __/ /_/ /_
  / /| | / __ \/ //_ /\__ \/ / _ \/ / / / __/ __ \
 / ___ |/ /_/ / ,<   ___/ / /  __/ /_/ / /_/ / / /
/_/  |_/ .___/_/|_| /____/_/\___/\__,_/\__/_/ /_/
      /_/
""".strip("\n")


def main(argv: list[str] | None = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not hasattr(args, "handler"):
        parser.print_help()
        raise SystemExit(0)

    _print_logo()
    try:
        args.handler(args)
    except AnalysisError as exc:
        print(f"apksleuth: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    except BrokenPipeError:
        raise SystemExit(1) from None


def _print_logo(stream: object | None = None) -> None:
    target = stream if stream is not None else sys.stderr
    print(CLI_LOGO, file=target)
    print(f"  ApkSleuth v{__version__} | Local-first Android APK static analysis", file=target)
    print(file=target)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apksleuth",
        description="Local-first Android APK static analysis CLI.",
    )
    parser.add_argument("--version", action="version", version=f"ApkSleuth {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="Analyze one APK and generate a report.")
    scan.add_argument("apk", help="Path to the APK file.")
    scan.add_argument(
        "--format",
        choices=sorted(SUPPORTED_FORMATS),
        default="json",
        help="Report output format. Default: json.",
    )
    scan.add_argument("--output", "-o", help="Write the report to this file instead of stdout.")
    scan.add_argument(
        "--lang",
        choices=sorted(SUPPORTED_LANGUAGES),
        default="zh",
        help="Report language. Default: zh.",
    )
    scan.add_argument(
        "--max-entry-bytes",
        type=int,
        default=4 * 1024 * 1024,
        help="Maximum bytes to scan per APK entry for string extraction. Default: 4194304.",
    )
    scan.add_argument("--progress", action="store_true", help="Print scan progress to stderr.")
    scan.set_defaults(handler=_scan)

    batch = subparsers.add_parser("batch", help="Analyze all APK files in a directory and generate an index.")
    batch.add_argument("directory", help="Directory containing APK files.")
    batch.add_argument("--output", "-o", default="reports", help="Output directory. Default: reports.")
    batch.add_argument(
        "--format",
        choices=sorted(SUPPORTED_FORMATS),
        default="summary",
        help="Per-APK report output format. Default: summary.",
    )
    batch.add_argument(
        "--lang",
        choices=sorted(SUPPORTED_LANGUAGES),
        default="zh",
        help="Report language. Default: zh.",
    )
    batch.add_argument("--recursive", action="store_true", help="Scan APK files recursively.")
    batch.add_argument(
        "--max-entry-bytes",
        type=int,
        default=4 * 1024 * 1024,
        help="Maximum bytes to scan per APK entry for string extraction. Default: 4194304.",
    )
    batch.add_argument("--progress", action="store_true", help="Print batch progress to stderr.")
    batch.set_defaults(handler=_batch)

    diff = subparsers.add_parser("diff", help="Compare two APK files and report changes.")
    diff.add_argument("old_apk", help="Path to the old APK file.")
    diff.add_argument("new_apk", help="Path to the new APK file.")
    diff.add_argument(
        "--format",
        choices=sorted(DIFF_FORMATS),
        default="summary",
        help="Diff output format. Default: summary.",
    )
    diff.add_argument("--output", "-o", help="Write the diff report to this file instead of stdout.")
    diff.add_argument(
        "--lang",
        choices=sorted(SUPPORTED_LANGUAGES),
        default="zh",
        help="Report language. Default: zh.",
    )
    diff.add_argument(
        "--max-entry-bytes",
        type=int,
        default=4 * 1024 * 1024,
        help="Maximum bytes to scan per APK entry for string extraction. Default: 4194304.",
    )
    diff.add_argument("--progress", action="store_true", help="Print diff progress to stderr.")
    diff.set_defaults(handler=_diff)

    web = subparsers.add_parser("web", help="Start a local Web UI for APK upload and analysis.")
    web.add_argument("--host", default="127.0.0.1", help="Host to bind. Default: 127.0.0.1.")
    web.add_argument("--port", type=int, default=8765, help="Port to bind. Default: 8765.")
    web.add_argument("--workdir", default=".apksleuth-web", help="Directory for uploaded APKs and generated reports. Default: .apksleuth-web.")
    web.add_argument(
        "--lang",
        choices=sorted(SUPPORTED_LANGUAGES),
        default="zh",
        help="Report language. Default: zh.",
    )
    web.add_argument(
        "--max-entry-bytes",
        type=int,
        default=4 * 1024 * 1024,
        help="Maximum bytes to scan per APK entry for string extraction. Default: 4194304.",
    )
    web.add_argument("--open", action="store_true", help="Open the Web UI in the default browser.")
    web.set_defaults(handler=_web)
    return parser


def _scan(args: argparse.Namespace) -> None:
    progress = (lambda message: print(f"[apksleuth] {message}", file=sys.stderr)) if args.progress else None
    report = analyze_apk(args.apk, max_entry_bytes=args.max_entry_bytes, progress=progress)
    output = render_report(report, args.format, language=args.lang)
    if args.output:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(output, encoding="utf-8")
        print(f"Report written to {path}")
    else:
        print(output, end="")


def _batch(args: argparse.Namespace) -> None:
    progress = (lambda message: print(f"[apksleuth] {message}", file=sys.stderr)) if args.progress else None
    payload = run_batch_scan(
        args.directory,
        args.output,
        report_format=args.format,
        language=args.lang,
        recursive=args.recursive,
        max_entry_bytes=args.max_entry_bytes,
        progress=progress,
    )
    print(
        f"Batch complete: {payload['succeeded']} succeeded, {payload['failed']} failed. "
        f"Index written to {Path(args.output) / 'index.md'}"
    )


def _diff(args: argparse.Namespace) -> None:
    progress = (lambda message: print(f"[apksleuth] {message}", file=sys.stderr)) if args.progress else None
    payload = diff_apks(args.old_apk, args.new_apk, max_entry_bytes=args.max_entry_bytes, progress=progress)
    output = render_diff(payload, args.format, language=args.lang)
    if args.output:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(output, encoding="utf-8")
        print(f"Diff report written to {path}")
    else:
        print(output, end="")


def _web(args: argparse.Namespace) -> None:
    run_web_server(
        host=args.host,
        port=args.port,
        workdir=args.workdir,
        language=args.lang,
        max_entry_bytes=args.max_entry_bytes,
        open_browser=args.open,
    )
