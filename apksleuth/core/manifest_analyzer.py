from __future__ import annotations

from dataclasses import dataclass, field
from xml.etree import ElementTree

from apksleuth.core.axml import AxmlNode, parse_binary_xml
from apksleuth.core.utils import normalize_android_name, unique_preserve_order
from apksleuth.models import Component, IntentFilter, ManifestSummary


ANDROID_NS = "http://schemas.android.com/apk/res/android"
COMPONENT_TAGS = {
    "activity": "activity",
    "activity-alias": "activity-alias",
    "service": "service",
    "receiver": "receiver",
    "provider": "provider",
}


@dataclass
class XmlNode:
    name: str
    attrs: dict[str, str] = field(default_factory=dict)
    children: list["XmlNode"] = field(default_factory=list)


def parse_manifest(data: bytes) -> ManifestSummary:
    try:
        root = _load_manifest(data)
        return _analyze_tree(root)
    except Exception as exc:  # noqa: BLE001 - a parse error should be reported, not crash analysis.
        return ManifestSummary(parse_error=str(exc))


def _load_manifest(data: bytes) -> XmlNode:
    stripped = data.lstrip()
    if stripped.startswith(b"<"):
        element = ElementTree.fromstring(data.decode("utf-8", errors="replace"))
        return _from_element(element)

    return _from_axml(parse_binary_xml(data))


def _from_element(element: ElementTree.Element) -> XmlNode:
    return XmlNode(
        name=_local_name(element.tag),
        attrs={_local_name(key): value for key, value in element.attrib.items()},
        children=[_from_element(child) for child in list(element)],
    )


def _from_axml(node: AxmlNode) -> XmlNode:
    return XmlNode(
        name=_local_name(node.name),
        attrs={_local_name(key): value for key, value in node.attrs.items()},
        children=[_from_axml(child) for child in node.children],
    )


def _analyze_tree(root: XmlNode) -> ManifestSummary:
    if root.name != "manifest":
        manifest_nodes = [node for node in _walk(root) if node.name == "manifest"]
        if not manifest_nodes:
            raise ValueError("Manifest root element was not found.")
        root = manifest_nodes[0]

    package_name = _attr(root, "package")
    summary = ManifestSummary(
        package_name=package_name,
        version_name=_attr(root, "versionName"),
        version_code=_attr(root, "versionCode"),
        compile_sdk=_attr(root, "compileSdkVersion"),
    )

    uses_sdk = _first_child(root, "uses-sdk")
    if uses_sdk:
        summary.min_sdk = _attr(uses_sdk, "minSdkVersion")
        summary.target_sdk = _attr(uses_sdk, "targetSdkVersion")

    permissions: list[str] = []
    for child in root.children:
        if child.name in {"uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m"}:
            permission_name = _attr(child, "name")
            if permission_name:
                permissions.append(permission_name)
    summary.permissions = unique_preserve_order(permissions)

    application = _first_child(root, "application")
    if application:
        summary.app_name = _attr(application, "label")
        summary.application_class = normalize_android_name(_attr(application, "name"), package_name)
        summary.debuggable = _parse_bool(_attr(application, "debuggable"))
        summary.allow_backup = _parse_bool(_attr(application, "allowBackup"))
        summary.uses_cleartext_traffic = _parse_bool(_attr(application, "usesCleartextTraffic"))
        summary.network_security_config = _attr(application, "networkSecurityConfig")
        summary.components = _parse_components(application, package_name, summary)

    return summary


def _parse_components(application: XmlNode, package_name: str | None, summary: ManifestSummary) -> list[Component]:
    components: list[Component] = []
    for child in application.children:
        component_type = COMPONENT_TAGS.get(child.name)
        if not component_type:
            continue

        raw_name = _attr(child, "name") or _attr(child, "targetActivity")
        name = normalize_android_name(raw_name, package_name) or "<unknown>"
        component = Component(
            type=component_type,
            name=name,
            exported=_parse_bool(_attr(child, "exported")),
            enabled=_parse_bool(_attr(child, "enabled")),
            permission=_attr(child, "permission"),
            authorities=_attr(child, "authorities"),
        )

        if component.authorities:
            summary.provider_authorities.extend([item for item in component.authorities.split(";") if item])

        for intent_node in _children(child, "intent-filter"):
            intent_filter = IntentFilter()
            for item in intent_node.children:
                if item.name == "action":
                    value = _attr(item, "name")
                    if value:
                        intent_filter.actions.append(value)
                elif item.name == "category":
                    value = _attr(item, "name")
                    if value:
                        intent_filter.categories.append(value)
                elif item.name == "data":
                    data_item = _data_attributes(item)
                    if data_item:
                        intent_filter.data.append(data_item)
                        if data_item.get("scheme") or data_item.get("host"):
                            summary.deep_links.append({"component": component.name, **data_item})
            component.intent_filters.append(intent_filter)

        components.append(component)

    summary.provider_authorities = unique_preserve_order(summary.provider_authorities)
    return components


def _data_attributes(node: XmlNode) -> dict[str, str]:
    keys = ["scheme", "host", "port", "path", "pathPrefix", "pathPattern", "mimeType"]
    return {key: value for key in keys if (value := _attr(node, key))}


def _walk(node: XmlNode) -> list[XmlNode]:
    nodes = [node]
    for child in node.children:
        nodes.extend(_walk(child))
    return nodes


def _first_child(node: XmlNode, name: str) -> XmlNode | None:
    return next((child for child in node.children if child.name == name), None)


def _children(node: XmlNode, name: str) -> list[XmlNode]:
    return [child for child in node.children if child.name == name]


def _attr(node: XmlNode, name: str) -> str | None:
    for key in (name, f"android:{name}", f"{{{ANDROID_NS}}}{name}"):
        if key in node.attrs:
            return node.attrs[key]
    for key, value in node.attrs.items():
        if _local_name(key) == name:
            return value
    return None


def _parse_bool(value: str | None) -> bool | None:
    if value is None or value == "":
        return None
    return value.strip().lower() in {"true", "1", "0xffffffff"}


def _local_name(name: str) -> str:
    if name.startswith("{") and "}" in name:
        return name.split("}", 1)[1]
    if name.startswith("android:"):
        return name.split(":", 1)[1]
    return name
