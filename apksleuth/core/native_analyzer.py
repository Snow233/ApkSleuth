from __future__ import annotations

import zipfile
from pathlib import PurePosixPath

from apksleuth.core.utils import hash_bytes
from apksleuth.models import NativeLibrary


def analyze_native_libraries(apk: zipfile.ZipFile) -> list[NativeLibrary]:
    libraries: list[NativeLibrary] = []
    for item in apk.infolist():
        if item.is_dir() or not item.filename.startswith("lib/") or not item.filename.endswith(".so"):
            continue
        path = PurePosixPath(item.filename)
        if len(path.parts) < 3:
            continue
        try:
            data = apk.read(item)
        except (OSError, RuntimeError, zipfile.BadZipFile):
            data = b""
        libraries.append(
            NativeLibrary(
                path=item.filename,
                abi=path.parts[1],
                name=path.name,
                size=item.file_size,
                hashes=hash_bytes(data),
                stripped=_looks_stripped(data) if data else None,
            )
        )
    return sorted(libraries, key=lambda item: (item.abi, item.name))


def _looks_stripped(data: bytes) -> bool | None:
    if not data.startswith(b"\x7fELF"):
        return None
    return b".symtab" not in data and b".strtab" not in data
