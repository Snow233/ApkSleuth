from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from


RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_RESOURCE_MAP_TYPE = 0x0180
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103

UTF8_FLAG = 0x00000100
NO_INDEX = 0xFFFFFFFF

TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12
TYPE_FIRST_COLOR_INT = 0x1C
TYPE_LAST_COLOR_INT = 0x1F


ANDROID_ATTRS = {
    0x01010001: "label",
    0x01010002: "icon",
    0x01010003: "name",
    0x01010006: "permission",
    0x0101000E: "enabled",
    0x0101000F: "debuggable",
    0x01010010: "exported",
    0x01010018: "authorities",
    0x0101001B: "grantUriPermissions",
    0x01010026: "scheme",
    0x01010027: "host",
    0x01010028: "port",
    0x0101002A: "path",
    0x0101002B: "pathPrefix",
    0x0101002C: "pathPattern",
    0x0101002D: "mimeType",
    0x0101020C: "minSdkVersion",
    0x0101021B: "versionCode",
    0x0101021C: "versionName",
    0x01010270: "targetSdkVersion",
    0x01010271: "maxSdkVersion",
    0x01010280: "allowBackup",
    0x010103D0: "installLocation",
    0x010104EC: "usesCleartextTraffic",
    0x010104F2: "networkSecurityConfig",
    0x01010572: "compileSdkVersion",
    0x01010573: "compileSdkVersionCodename",
}


class AxmlParseError(ValueError):
    """Raised when a binary Android XML file cannot be parsed."""


@dataclass
class AxmlNode:
    name: str
    attrs: dict[str, str] = field(default_factory=dict)
    children: list["AxmlNode"] = field(default_factory=list)


def parse_binary_xml(data: bytes) -> AxmlNode:
    return BinaryXmlParser(data).parse()


class BinaryXmlParser:
    def __init__(self, data: bytes):
        self.data = data
        self.strings: list[str] = []
        self.resource_map: list[int] = []

    def parse(self) -> AxmlNode:
        if len(self.data) < 8:
            raise AxmlParseError("AXML data is too small.")

        chunk_type, header_size, file_size = self._chunk_header(0)
        if chunk_type != RES_XML_TYPE:
            raise AxmlParseError("Not an Android binary XML document.")
        if file_size > len(self.data):
            file_size = len(self.data)

        root: AxmlNode | None = None
        stack: list[AxmlNode] = []
        offset = header_size
        while offset + 8 <= file_size:
            chunk_type, header_size, chunk_size = self._chunk_header(offset)
            if chunk_size <= 0 or offset + chunk_size > len(self.data):
                raise AxmlParseError(f"Invalid AXML chunk at offset {offset}.")

            if chunk_type == RES_STRING_POOL_TYPE:
                self.strings = self._parse_string_pool(offset)
            elif chunk_type == RES_XML_RESOURCE_MAP_TYPE:
                self.resource_map = self._parse_resource_map(offset, header_size, chunk_size)
            elif chunk_type == RES_XML_START_ELEMENT_TYPE:
                node = self._parse_start_element(offset, chunk_size)
                if stack:
                    stack[-1].children.append(node)
                else:
                    root = node
                stack.append(node)
            elif chunk_type == RES_XML_END_ELEMENT_TYPE:
                if stack:
                    stack.pop()

            offset += chunk_size

        if root is None:
            raise AxmlParseError("AXML document does not contain a root element.")
        return root

    def _chunk_header(self, offset: int) -> tuple[int, int, int]:
        if offset + 8 > len(self.data):
            raise AxmlParseError("Unexpected end of AXML chunk header.")
        return unpack_from("<HHI", self.data, offset)

    def _u16(self, offset: int) -> int:
        return unpack_from("<H", self.data, offset)[0]

    def _u32(self, offset: int) -> int:
        return unpack_from("<I", self.data, offset)[0]

    def _parse_string_pool(self, offset: int) -> list[str]:
        _, header_size, chunk_size = self._chunk_header(offset)
        if header_size < 28:
            raise AxmlParseError("Invalid string pool header.")

        string_count = self._u32(offset + 8)
        style_count = self._u32(offset + 12)
        flags = self._u32(offset + 16)
        strings_start = self._u32(offset + 20)
        offsets_start = offset + header_size
        is_utf8 = bool(flags & UTF8_FLAG)

        strings: list[str] = []
        for index in range(string_count):
            string_offset = self._u32(offsets_start + index * 4)
            absolute = offset + strings_start + string_offset
            strings.append(self._decode_string(absolute, is_utf8))

        # Keep validation strict enough to catch shifted offsets without failing on style pools.
        if style_count and offset + chunk_size > len(self.data):
            raise AxmlParseError("Invalid styled string pool size.")
        return strings

    def _parse_resource_map(self, offset: int, header_size: int, chunk_size: int) -> list[int]:
        start = offset + header_size
        end = offset + chunk_size
        resource_ids: list[int] = []
        for item_offset in range(start, end, 4):
            if item_offset + 4 <= len(self.data):
                resource_ids.append(self._u32(item_offset))
        return resource_ids

    def _parse_start_element(self, offset: int, chunk_size: int) -> AxmlNode:
        if offset + 36 > len(self.data):
            raise AxmlParseError("Invalid start element chunk.")

        name_index = self._u32(offset + 20)
        name = self._string(name_index) or f"element_{name_index}"
        attr_start = self._u16(offset + 24)
        attr_size = self._u16(offset + 26) or 20
        attr_count = self._u16(offset + 28)

        attrs_offset = offset + attr_start
        if attrs_offset < offset + 36 or attrs_offset + attr_count * attr_size > offset + chunk_size:
            attrs_offset = offset + 16 + attr_start

        attrs: dict[str, str] = {}
        for index in range(attr_count):
            attr_offset = attrs_offset + index * attr_size
            if attr_offset + 20 > len(self.data):
                break
            attr_name, attr_value = self._parse_attribute(attr_offset)
            if attr_name:
                attrs[attr_name] = attr_value

        return AxmlNode(name=name, attrs=attrs)

    def _parse_attribute(self, offset: int) -> tuple[str | None, str]:
        namespace_index = self._u32(offset)
        name_index = self._u32(offset + 4)
        raw_value_index = self._u32(offset + 8)
        data_type = self.data[offset + 15]
        data_value = self._u32(offset + 16)

        name = self._attribute_name(name_index)
        namespace = self._string(namespace_index)
        if namespace == "http://schemas.android.com/apk/res/android" and name and not name.startswith("android:"):
            name = f"android:{name}"

        value = self._format_value(data_type, data_value, raw_value_index)
        return name, value

    def _attribute_name(self, name_index: int) -> str | None:
        name = self._string(name_index)
        if name:
            return name
        if name_index != NO_INDEX and name_index < len(self.resource_map):
            resource_id = self.resource_map[name_index]
            return ANDROID_ATTRS.get(resource_id, f"android:attr_{resource_id:08x}")
        return None

    def _format_value(self, data_type: int, data_value: int, raw_value_index: int) -> str:
        if data_type == TYPE_STRING:
            return self._string(data_value) or ""
        if data_type == TYPE_INT_BOOLEAN:
            return "true" if data_value != 0 else "false"
        if data_type == TYPE_INT_DEC:
            return str(data_value)
        if data_type == TYPE_INT_HEX:
            return f"0x{data_value:08x}"
        if data_type in (TYPE_REFERENCE, TYPE_ATTRIBUTE):
            prefix = "@" if data_type == TYPE_REFERENCE else "?"
            return f"{prefix}0x{data_value:08x}"
        if TYPE_FIRST_COLOR_INT <= data_type <= TYPE_LAST_COLOR_INT:
            return f"#{data_value:08x}"
        raw_value = self._string(raw_value_index)
        if raw_value is not None:
            return raw_value
        if data_type == TYPE_NULL:
            return ""
        if data_type == TYPE_FLOAT:
            return str(unpack_from("<f", data_value.to_bytes(4, "little"))[0])
        return str(data_value)

    def _string(self, index: int) -> str | None:
        if index == NO_INDEX or index < 0 or index >= len(self.strings):
            return None
        return self.strings[index]

    def _decode_string(self, offset: int, is_utf8: bool) -> str:
        if offset >= len(self.data):
            return ""
        if is_utf8:
            _, next_offset = self._decode_length8(offset)
            byte_length, string_offset = self._decode_length8(next_offset)
            raw = self.data[string_offset : string_offset + byte_length]
            return raw.decode("utf-8", errors="replace")

        utf16_length, string_offset = self._decode_length16(offset)
        raw = self.data[string_offset : string_offset + utf16_length * 2]
        return raw.decode("utf-16le", errors="replace")

    def _decode_length8(self, offset: int) -> tuple[int, int]:
        first = self.data[offset]
        if first & 0x80:
            second = self.data[offset + 1]
            return ((first & 0x7F) << 8) | second, offset + 2
        return first, offset + 1

    def _decode_length16(self, offset: int) -> tuple[int, int]:
        first = self._u16(offset)
        if first & 0x8000:
            second = self._u16(offset + 2)
            return ((first & 0x7FFF) << 16) | second, offset + 4
        return first, offset + 2
