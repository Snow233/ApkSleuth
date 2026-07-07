from __future__ import annotations

import struct
import zipfile
from pathlib import Path

from apksleuth.core.utils import hash_bytes
from apksleuth.models import CertificateInfo, SignatureFile, SignatureInfo


APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
APK_SIG_V2_ID = 0x7109871A
APK_SIG_V3_ID = 0xF05368C0
APK_SIG_V31_ID = 0x1B93AD61
APK_SIG_SOURCE_STAMP_ID = 0x6DFF800D

SIGNATURE_EXTENSIONS = (".RSA", ".DSA", ".EC")


def analyze_certificates(apk: zipfile.ZipFile, apk_path: Path) -> SignatureInfo:
    info = SignatureInfo()

    for item in apk.infolist():
        upper_name = item.filename.upper()
        if not upper_name.startswith("META-INF/") or not upper_name.endswith(SIGNATURE_EXTENSIONS):
            continue
        try:
            data = apk.read(item)
        except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
            info.notes.append(f"Failed to read signature file {item.filename}: {exc}")
            continue
        info.signature_files.append(SignatureFile(item.filename, item.file_size, hash_bytes(data)))
        info.certificates.extend(_parse_pkcs7_certificates(data, item.filename, info))

    if info.signature_files:
        info.schemes.append("v1-jar-signing")

    signing_ids = _read_apk_signing_block_ids(apk_path, info)
    info.signing_block_ids = [f"0x{item:08x}" for item in signing_ids]
    if APK_SIG_V2_ID in signing_ids:
        info.schemes.append("v2-apk-signing")
    if APK_SIG_V3_ID in signing_ids or APK_SIG_V31_ID in signing_ids:
        info.schemes.append("v3-apk-signing")
    if APK_SIG_SOURCE_STAMP_ID in signing_ids:
        info.schemes.append("source-stamp")

    if not info.signature_files and not signing_ids:
        info.notes.append("No APK signature metadata was found. The file may be unsigned or malformed.")
    elif info.signature_files and not info.certificates:
        info.notes.append("Install the optional 'cryptography' dependency to parse X.509 certificate details from V1 signature files.")

    return info


def _parse_pkcs7_certificates(data: bytes, source: str, info: SignatureInfo) -> list[CertificateInfo]:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.serialization import pkcs7
    except ImportError:
        return []

    try:
        certificates = pkcs7.load_der_pkcs7_certificates(data)
    except ValueError:
        try:
            certificates = [x509.load_der_x509_certificate(data)]
        except ValueError as exc:
            info.notes.append(f"Could not parse certificate from {source}: {exc}")
            return []

    parsed: list[CertificateInfo] = []
    for cert in certificates:
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        sig_alg = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
        parsed.append(
            CertificateInfo(
                subject=subject,
                issuer=issuer,
                serial_number=hex(cert.serial_number),
                not_valid_before=_date_to_iso(cert.not_valid_before_utc),
                not_valid_after=_date_to_iso(cert.not_valid_after_utc),
                signature_algorithm=sig_alg,
                sha1=cert.fingerprint(hashes.SHA1()).hex(),
                sha256=cert.fingerprint(hashes.SHA256()).hex(),
                is_debug="Android Debug" in subject or "Android Debug" in issuer,
            )
        )
    return parsed


def _read_apk_signing_block_ids(apk_path: Path, info: SignatureInfo) -> list[int]:
    try:
        data = apk_path.read_bytes()
    except OSError as exc:
        info.notes.append(f"Failed to read APK signing block: {exc}")
        return []

    eocd_offset = _find_eocd(data)
    if eocd_offset is None or eocd_offset + 20 > len(data):
        info.notes.append("ZIP end of central directory was not found.")
        return []

    central_directory_offset = struct.unpack_from("<I", data, eocd_offset + 16)[0]
    footer_offset = central_directory_offset - 24
    if footer_offset < 0 or footer_offset + 24 > len(data):
        return []
    size2 = struct.unpack_from("<Q", data, footer_offset)[0]
    magic = data[footer_offset + 8 : footer_offset + 24]
    if magic != APK_SIG_BLOCK_MAGIC:
        return []

    total_size = size2 + 8
    block_offset = central_directory_offset - total_size
    if block_offset < 0 or block_offset + 8 > len(data):
        info.notes.append("APK signing block has an invalid size.")
        return []
    size1 = struct.unpack_from("<Q", data, block_offset)[0]
    if size1 != size2:
        info.notes.append("APK signing block size fields do not match.")
        return []

    ids: list[int] = []
    cursor = block_offset + 8
    pairs_end = footer_offset
    while cursor + 8 <= pairs_end:
        pair_size = struct.unpack_from("<Q", data, cursor)[0]
        cursor += 8
        if pair_size < 4 or cursor + pair_size > pairs_end:
            break
        pair_id = struct.unpack_from("<I", data, cursor)[0]
        ids.append(pair_id)
        cursor += pair_size
    return ids


def _find_eocd(data: bytes) -> int | None:
    start = max(0, len(data) - (65535 + 22))
    signature = b"PK\x05\x06"
    for offset in range(len(data) - 22, start - 1, -1):
        if data[offset : offset + 4] == signature:
            return offset
    return None


def _date_to_iso(value: object) -> str:
    return value.isoformat() if hasattr(value, "isoformat") else str(value)
