from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class WebConfig:
    host: str = "127.0.0.1"
    port: int = 8765
    workdir: Path = Path(".apksleuth-web")
    language: str = "zh"
    max_entry_bytes: int = 4 * 1024 * 1024
    jobs: dict[str, "WebJob"] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)


@dataclass
class WebJob:
    job_id: str
    apk_name: str
    status: str = "pending"
    message: str = "等待分析"
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    report_dir: str | None = None
    error: str | None = None
