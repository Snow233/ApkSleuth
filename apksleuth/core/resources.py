from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from


RES_STRING_POOL_TYPE = 0x0001
RES_TABLE_TYPE = 0x0002
RES_TABLE_PACKAGE_TYPE = 0x0200
RES_TABLE_TYPE_TYPE = 0x0201

UTF8_FLAG = 0x00000100
NO_ENTRY = 0xFFFFFFFF
FLAG_COMPLEX = 0x0001

TYPE_REFERENCE = 0x01
TYPE_STRING = 0x03


class ResourceTableError(ValueError):
    """Raised when resources.arsc cannot be parsed."""


@dataclass
class StringPool:
    strings: list[str]
    size: int


class ResourceTable:
    def __init__(self, data: bytes):
        self.data = data
        self.global_strings: list[str] = []
        self.values: dict[int, str] = {}
        self.references: dict[int, int] = {}
        self._parse()

    def resolve(self, value: str | None) -> str | None:
        resource_id = _parse_resource_reference(value)
        if resource_id is None:
            return value
        resolved = self._resolve_id(resource_id, seen=set())
        return resolved if resolved is not None else value

    def _resolve_id(self, resource_id: int, seen: set[int]) -> str | None:
        if resource_id in self.values:
            return self.values[resource_id]
        if resource_id in seen or resource_id not in self.references:
            return None
        seen.add(resource_id)
        return self._resolve_id(self.references[resource_id], seen)

    def _parse(self) -> None:
        chunk_type, header_size, table_size = _chunk_header(self.data, 0)
        if chunk_type != RES_TABLE_TYPE:
            raise ResourceTableError("resources.arsc does not start with a resource table chunk.")
        table_size = min(table_size, len(self.data))
        offset = header_size

        if offset + 8 <= table_size and _chunk_header(self.data, offset)[0] == RES_STRING_POOL_TYPE:
            pool = _parse_string_pool(self.data, offset)
            self.global_strings = pool.strings
            offset += pool.size

        while offset + 8 <= table_size:
            chunk_type, _, chunk_size = _chunk_header(self.data, offset)
            if chunk_size <= 0 or offset + chunk_size > len(self.data):
                break
            if chunk_type == RES_TABLE_PACKAGE_TYPE:
                self._parse_package(offset, chunk_size)
            offset += chunk_size

    def _parse_package(self, offset: int, chunk_size: int) -> None:
        _, header_size, _ = _chunk_header(self.data, offset)
        if header_size < 284:
            return
        package_id = _u32(self.data, offset + 8)
        cursor = offset + header_size
        end = offset + chunk_size

        while cursor + 8 <= end:
            chunk_type, _, child_size = _chunk_header(self.data, cursor)
            if child_size <= 0 or cursor + child_size > len(self.data):
                break
            if chunk_type == RES_TABLE_TYPE_TYPE:
                self._parse_type_chunk(cursor, package_id)
            cursor += child_size

    def _parse_type_chunk(self, offset: int, package_id: int) -> None:
        _, header_size, chunk_size = _chunk_header(self.data, offset)
        if offset + 20 > len(self.data):
            return
        type_id = self.data[offset + 8]
        entry_count = _u32(self.data, offset + 12)
        entries_start = _u32(self.data, offset + 16)
        offsets_start = offset + header_size
        entries_base = offset + entries_start
        chunk_end = offset + chunk_size

        for entry_index in range(entry_count):
            item_offset = offsets_start + entry_index * 4
            if item_offset + 4 > len(self.data):
                break
            entry_offset = _u32(self.data, item_offset)
            if entry_offset == NO_ENTRY:
                continue

            entry_abs = entries_base + entry_offset
            if entry_abs + 16 > chunk_end or entry_abs + 16 > len(self.data):
                continue
            entry_size = _u16(self.data, entry_abs)
            flags = _u16(self.data, entry_abs + 2)
            if flags & FLAG_COMPLEX:
                continue

            value_abs = entry_abs + entry_size
            if value_abs + 8 > chunk_end or value_abs + 8 > len(self.data):
                continue
            data_type = self.data[value_abs + 3]
            data_value = _u32(self.data, value_abs + 4)
            resource_id = (package_id << 24) | (type_id << 16) | entry_index

            if data_type == TYPE_STRING and data_value < len(self.global_strings):
                self.values.setdefault(resource_id, self.global_strings[data_value])
            elif data_type == TYPE_REFERENCE:
                self.references.setdefault(resource_id, data_value)


def parse_resource_table(data: bytes) -> ResourceTable:
    return ResourceTable(data)


def _parse_string_pool(data: bytes, offset: int) -> StringPool:
    _, header_size, chunk_size = _chunk_header(data, offset)
    if header_size < 28:
        raise ResourceTableError("Invalid string pool header.")
    string_count = _u32(data, offset + 8)
    flags = _u32(data, offset + 16)
    strings_start = _u32(data, offset + 20)
    offsets_start = offset + header_size
    is_utf8 = bool(flags & UTF8_FLAG)

    strings: list[str] = []
    for index in range(string_count):
        item_offset = offsets_start + index * 4
        if item_offset + 4 > len(data):
            break
        string_offset = _u32(data, item_offset)
        absolute = offset + strings_start + string_offset
        strings.append(_decode_string(data, absolute, is_utf8))
    return StringPool(strings=strings, size=chunk_size)


def _parse_resource_reference(value: str | None) -> int | None:
    if not value or not value.startswith("@0x"):
        return None
    try:
        return int(value[1:], 16)
    except ValueError:
        return None


def _chunk_header(data: bytes, offset: int) -> tuple[int, int, int]:
    if offset + 8 > len(data):
        raise ResourceTableError("Unexpected end of resource chunk header.")
    return unpack_from("<HHI", data, offset)


def _u16(data: bytes, offset: int) -> int:
    return unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return unpack_from("<I", data, offset)[0]


def _decode_string(data: bytes, offset: int, is_utf8: bool) -> str:
    if offset >= len(data):
        return ""
    if is_utf8:
        _, next_offset = _decode_length8(data, offset)
        byte_length, string_offset = _decode_length8(data, next_offset)
        return data[string_offset : string_offset + byte_length].decode("utf-8", errors="replace")

    utf16_length, string_offset = _decode_length16(data, offset)
    raw = data[string_offset : string_offset + utf16_length * 2]
    return raw.decode("utf-16le", errors="replace")


def _decode_length8(data: bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    if first & 0x80:
        return ((first & 0x7F) << 8) | data[offset + 1], offset + 2
    return first, offset + 1


def _decode_length16(data: bytes, offset: int) -> tuple[int, int]:
    first = _u16(data, offset)
    if first & 0x8000:
        return ((first & 0x7FFF) << 16) | _u16(data, offset + 2), offset + 4
    return first, offset + 2
