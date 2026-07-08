from __future__ import annotations

from apksleuth.models import AnalysisReport, Component, Finding


LAUNCHER_ACTION = "android.intent.action.MAIN"
LAUNCHER_CATEGORY = "android.intent.category.LAUNCHER"
BROWSABLE_CATEGORY = "android.intent.category.BROWSABLE"
MEDIA_ACTIONS = {"android.intent.action.MEDIA_BUTTON", "android.media.browse.MediaBrowserService"}
SHARE_ACTIONS = {"android.intent.action.SEND", "android.intent.action.SEND_MULTIPLE"}
FILE_HANDLER_SCHEMES = {"file", "content"}


def run_risk_engine(report: AnalysisReport) -> list[Finding]:
    findings: list[Finding] = []
    manifest = report.manifest

    if manifest.debuggable is True:
        findings.append(
            Finding(
                id="android-debuggable-enabled",
                title="Debuggable Enabled",
                severity="high",
                category="manifest",
                description="The application enables android:debuggable.",
                evidence='android:debuggable="true"',
                recommendation="Disable debuggable in release builds.",
                confidence="high",
                review_hint="Confirm whether this APK is a release build. Debuggable should not be enabled for distributed builds.",
            )
        )

    if manifest.allow_backup is True:
        findings.append(
            Finding(
                id="android-allow-backup-enabled",
                title="Allow Backup Enabled",
                severity="medium",
                category="manifest",
                description="The application allows adb backup.",
                evidence='android:allowBackup="true"',
                recommendation='Set android:allowBackup="false" unless backup is explicitly required and protected.',
                confidence="high",
                review_hint="Review whether sensitive local data can be backed up or restored on the target Android versions.",
            )
        )

    if manifest.uses_cleartext_traffic is True:
        findings.append(
            Finding(
                id="cleartext-traffic-enabled",
                title="Cleartext Traffic Enabled",
                severity="medium",
                category="network",
                description="The application allows cleartext network traffic.",
                evidence='android:usesCleartextTraffic="true"',
                recommendation="Use HTTPS endpoints and restrict cleartext traffic with network security config.",
                confidence="high",
                review_hint="Check network security config and runtime endpoints to confirm whether cleartext traffic is reachable in production.",
            )
        )

    for component in manifest.components:
        finding = _exported_component_finding(component)
        if finding:
            findings.append(finding)

    for permission in report.permissions:
        if permission.level == "high":
            findings.append(
                Finding(
                    id="high-risk-permission",
                    title="High-Risk Permission",
                    severity="medium",
                    category="permission",
                    description=permission.description,
                    evidence=permission.name,
                    recommendation=permission.recommendation,
                    confidence="high",
                    review_hint="Confirm the permission is required for core functionality and protected by runtime permission flow or feature gating.",
                )
            )

    for item in report.strings:
        if item.type == "url" and item.value.lower().startswith("http://"):
            findings.append(
                Finding(
                    id="http-url-found",
                    title="Cleartext HTTP URL Found",
                    severity="medium",
                    category="network",
                    description="A cleartext HTTP endpoint was found in APK contents.",
                    evidence=f"{item.value} ({item.source})",
                    recommendation="Use HTTPS endpoints and remove unused debug or staging URLs.",
                    confidence="medium",
                    review_hint="Confirm whether the URL is reachable in production code; static strings may include legacy or plugin endpoints.",
                )
            )
        elif item.type in {"possible_secret", "jwt"}:
            findings.append(
                Finding(
                    id="hardcoded-secret",
                    title="Possible Hardcoded Secret",
                    severity="high",
                    category="secret",
                    description="A token, API key, JWT, or secret-like value was found in APK contents.",
                    evidence=f"{item.value} ({item.source})",
                    recommendation="Move secrets to a backend service or rotate exposed credentials if confirmed.",
                    confidence="medium",
                    review_hint="Validate whether the value is an active credential or token. Rotate it if exposure is confirmed.",
                )
            )

    for cert in report.certificate.certificates:
        if cert.is_debug:
            findings.append(
                Finding(
                    id="debug-certificate",
                    title="Debug Certificate",
                    severity="high",
                    category="certificate",
                    description="The APK appears to be signed with an Android debug certificate.",
                    evidence=cert.subject or "Android Debug certificate",
                    recommendation="Sign release builds with a protected release signing key.",
                    confidence="high",
                    review_hint="Confirm the APK is not a release artifact. Debug certificates should not be used for production distribution.",
                )
            )

    return findings


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def confidence_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {"high": 0, "medium": 0, "low": 0}
    for finding in findings:
        counts[finding.confidence] = counts.get(finding.confidence, 0) + 1
    return counts


def _exported_component_finding(component: Component) -> Finding | None:
    if not component.externally_reachable:
        return None
    if _is_launcher_activity(component):
        return None

    if _is_media_component(component):
        return Finding(
            id="exported-media-component",
            title="Exported Media Component",
            severity="low",
            category="manifest",
            description="The component is exported for Android media controls or media browsing.",
            evidence=f"{component.type} {component.name} exposes standard media control actions.",
            recommendation="Confirm the component only handles standard media intents and validates external input.",
            confidence="medium",
            review_hint="Review intent handling code and ensure only expected media actions are accepted.",
        )

    if _is_quick_settings_tile(component):
        return Finding(
            id="exported-quick-settings-tile",
            title="Exported Quick Settings Tile",
            severity="low",
            category="manifest",
            description="The service is exported for Android Quick Settings tile integration.",
            evidence=f"service {component.name} is exported for Quick Settings tile binding.",
            recommendation="Keep the tile service exported only when the OS binding requires it and avoid sensitive work before user confirmation.",
            confidence="medium",
            review_hint="Review tile click handling and ensure it does not execute sensitive actions without user intent.",
        )

    if _is_autofill_service(component):
        return Finding(
            id="exported-autofill-service",
            title="Exported Autofill Service",
            severity="low",
            category="manifest",
            description="The service is exported for Android Autofill framework integration.",
            evidence=f"service {component.name} is exported for Autofill binding.",
            recommendation="Confirm the service is protected by the Android Autofill binding permission and validates all fill requests.",
            confidence="medium",
            review_hint="Review Autofill dataset handling and ensure only trusted framework calls can reach sensitive data.",
        )

    if _is_documents_provider(component):
        return Finding(
            id="exported-documents-provider",
            title="Exported Documents Provider",
            severity="low",
            category="manifest",
            description="The provider is exported for Android Storage Access Framework integration.",
            evidence=f"provider {component.name} is exported as a DocumentsProvider.",
            recommendation="Confirm document roots, URI grants, and access checks expose only intended files.",
            confidence="medium",
            review_hint="Review query/openDocument/deleteDocument handlers and verify access is scoped to user-approved documents.",
        )

    if component.permission:
        return Finding(
            id="exported-protected-component",
            title="Protected Exported Component",
            severity="low",
            category="manifest",
            description=f"The exported {component.type} component is protected by a permission.",
            evidence=f"{component.type} {component.name} is exported with permission {component.permission}.",
            recommendation="Verify the protection level of the permission and keep the component exported only if external access is required.",
            confidence="medium",
            review_hint="Check the permission protectionLevel. Normal or dangerous permissions may not be enough for sensitive exported components.",
        )

    if component.type == "provider":
        if _provider_has_partial_permissions(component):
            return Finding(
                id="exported-provider-partial-permission",
                title="Exported Provider With Partial Permissions",
                severity="medium",
                category="manifest",
                description="An exported ContentProvider uses read/write specific permissions instead of a single provider permission.",
                evidence=f"provider {component.name} is exported with read/write permission split.",
                recommendation="Verify both readPermission and writePermission are strong enough for exposed data and operations.",
                confidence="high",
                review_hint="Review readPermission/writePermission protectionLevel and confirm unprotected operations cannot be reached.",
            )
        if component.grant_uri_permissions is True:
            return Finding(
                id="exported-provider-grant-uri",
                title="Exported Provider Grants URI Permissions",
                severity="medium",
                category="manifest",
                description="An exported ContentProvider can grant URI permissions to other apps.",
                evidence=f"provider {component.name} is exported with grantUriPermissions enabled.",
                recommendation="Review provider path scope and only grant URI permissions for intended files or records.",
                confidence="high",
                review_hint="Review path-permission/meta-data/provider paths and ensure grants cannot expose broad app-private data.",
            )
        if _is_file_provider(component):
            return Finding(
                id="exported-file-provider",
                title="Exported File Provider Without Permission",
                severity="high",
                category="manifest",
                description="An exported FileProvider-like provider without permission protection may expose files or URI grants.",
                evidence=f"provider {component.name} is exported without permission.",
                recommendation="Set android:exported=\"false\" unless the provider is intentionally public and fully permission-gated.",
                confidence="high",
                review_hint="Review provider paths, URI grants, MIME handling, and all openFile/openAssetFile paths.",
            )
        return Finding(
            id="exported-provider",
            title="Exported Provider Without Permission",
            severity="high",
            category="manifest",
            description="An exported ContentProvider without permission protection may expose app data or operations.",
            evidence=f"provider {component.name} is exported without permission.",
            recommendation="Set android:exported=\"false\" or protect the provider with a signature-level permission.",
            confidence="high",
            review_hint="Review provider authorities, path permissions, grantUriPermissions, and query/insert/update/delete handlers.",
        )

    if _is_deep_link_activity(component):
        return Finding(
            id="exported-deep-link-activity",
            title="Exported Deep Link Activity",
            severity="high",
            category="manifest",
            description="An exported deep link Activity may be reachable from browsers or other applications.",
            evidence=f"activity {component.name} exposes deep link intent filters without permission.",
            recommendation="Validate all deep link parameters, require authentication for sensitive flows, and restrict exported access where possible.",
            confidence="high",
            review_hint="Review scheme/host/path filters, authentication requirements, and parameter validation for all deep link entry points.",
        )

    if _is_share_target_activity(component):
        return Finding(
            id="exported-share-target-activity",
            title="Exported Share Target Activity",
            severity="medium",
            category="manifest",
            description="The activity accepts external share intents.",
            evidence=f"activity {component.name} accepts external share intents.",
            recommendation="Validate shared MIME types, URI permissions, file sizes, and content before processing.",
            confidence="high",
            review_hint="Review ACTION_SEND/ACTION_SEND_MULTIPLE handling and reject unexpected MIME types or oversized inputs.",
        )

    if _is_file_handler_activity(component):
        return Finding(
            id="exported-file-handler-activity",
            title="Exported File Handler Activity",
            severity="medium",
            category="manifest",
            description="The activity handles external file or content URIs.",
            evidence=f"activity {component.name} accepts file/content input.",
            recommendation="Validate URI schemes, MIME types, file size, and parser behavior before opening external content.",
            confidence="high",
            review_hint="Review ACTION_VIEW handling for file/content URIs and ensure parsing cannot trigger unsafe file access.",
        )

    if component.type == "service":
        if _is_custom_tabs_service(component):
            return Finding(
                id="exported-custom-tabs-service",
                title="Exported Custom Tabs Service",
                severity="medium",
                category="manifest",
                description="The service is exported for browser Custom Tabs integration.",
                evidence=f"service {component.name} is exported for Custom Tabs.",
                recommendation="Confirm exposed Custom Tabs methods do not leak browsing state or privileged actions.",
                confidence="high",
                review_hint="Review Custom Tabs binding behavior and ensure callers cannot access sensitive browser internals.",
            )
        if _is_car_service(component):
            return Finding(
                id="exported-car-service",
                title="Exported Car Integration Service",
                severity="medium",
                category="manifest",
                description="The service is exported for Android Auto or car integration.",
                evidence=f"service {component.name} is exported for car integration.",
                recommendation="Validate car-app entry points and avoid sensitive actions without explicit user interaction.",
                confidence="high",
                review_hint="Review Android Auto session handling, navigation intents, and caller assumptions.",
            )
        return Finding(
            id="exported-service",
            title="Exported Service Without Permission",
            severity="high",
            category="manifest",
            description="An exported Service without permission protection can be invoked by other applications.",
            evidence=f"service {component.name} is exported without permission.",
            recommendation="Set android:exported=\"false\" or require a signature-level permission for the service.",
            confidence="high",
            review_hint="Review service entry points, accepted intents, binder exposure, and whether callers are authenticated.",
        )

    if component.type == "receiver":
        if _is_widget_receiver(component):
            return Finding(
                id="exported-widget-receiver",
                title="Exported App Widget Receiver",
                severity="low",
                category="manifest",
                description="The receiver is exported for Android app widget integration.",
                evidence=f"receiver {component.name} is exported for app widget updates.",
                recommendation="Ensure widget broadcasts do not trigger sensitive actions without validating action and extras.",
                confidence="medium",
                review_hint="Review accepted widget actions and ignore unexpected broadcasts or untrusted extras.",
            )
        return Finding(
            id="exported-receiver",
            title="Exported Receiver Without Permission",
            severity="medium",
            category="manifest",
            description="An exported BroadcastReceiver without permission protection may receive external broadcasts.",
            evidence=f"receiver {component.name} is exported without permission.",
            recommendation="Restrict the receiver, validate incoming intents, or require a permission for external broadcasts.",
            confidence="high",
            review_hint="Review accepted broadcast actions and ensure untrusted extras cannot trigger sensitive behavior.",
        )

    if component.exported is None and component.has_intent_filters:
        return Finding(
            id="implicit-exported-component",
            title="Implicitly Exported Component",
            severity="medium",
            category="manifest",
            description="A component with intent filters and no explicit exported value may be externally reachable on older Android versions.",
            evidence=f"{component.type} {component.name} has intent filters and no explicit exported value.",
            recommendation="Set android:exported explicitly and keep it false unless external access is required.",
            confidence="medium",
            review_hint="Confirm target platform behavior and explicitly set android:exported for predictable exposure.",
        )

    return Finding(
        id="exported-activity",
        title="Exported Activity Without Permission",
        severity="medium",
        category="manifest",
        description="An exported Activity without permission protection may be started by other applications.",
        evidence=f"activity {component.name} is exported without permission.",
        recommendation="Set android:exported=\"false\" unless the Activity is intended as a public entry point, and validate all intent input.",
        confidence="high",
        review_hint="Review whether the Activity is a deliberate public entry point and validate all intent extras and data URIs.",
    )


def _is_launcher_activity(component: Component) -> bool:
    if component.type not in {"activity", "activity-alias"}:
        return False
    for intent_filter in component.intent_filters:
        if LAUNCHER_ACTION in intent_filter.actions and LAUNCHER_CATEGORY in intent_filter.categories:
            return True
    return False


def _is_media_component(component: Component) -> bool:
    if component.type not in {"receiver", "service"}:
        return False
    return any(action in MEDIA_ACTIONS for intent_filter in component.intent_filters for action in intent_filter.actions)


def _has_action(component: Component, actions: set[str]) -> bool:
    return any(action in actions for intent_filter in component.intent_filters for action in intent_filter.actions)


def _has_data_scheme(component: Component, schemes: set[str]) -> bool:
    return any((item.get("scheme") or "").lower() in schemes for intent_filter in component.intent_filters for item in intent_filter.data)


def _has_mime_type(component: Component) -> bool:
    return any(item.get("mimeType") for intent_filter in component.intent_filters for item in intent_filter.data)


def _is_quick_settings_tile(component: Component) -> bool:
    return component.type == "service" and component.permission == "android.permission.BIND_QUICK_SETTINGS_TILE"


def _is_autofill_service(component: Component) -> bool:
    return component.type == "service" and component.permission == "android.permission.BIND_AUTOFILL_SERVICE"


def _is_documents_provider(component: Component) -> bool:
    return component.type == "provider" and component.permission == "android.permission.MANAGE_DOCUMENTS"


def _is_file_provider(component: Component) -> bool:
    return component.type == "provider" and ("fileprovider" in component.name.lower() or "fileprovider" in (component.authorities or "").lower())


def _provider_has_partial_permissions(component: Component) -> bool:
    return component.type == "provider" and not component.permission and bool(component.read_permission or component.write_permission)


def _is_share_target_activity(component: Component) -> bool:
    return component.type in {"activity", "activity-alias"} and _has_action(component, SHARE_ACTIONS)


def _is_file_handler_activity(component: Component) -> bool:
    return component.type in {"activity", "activity-alias"} and _has_action(component, {"android.intent.action.VIEW"}) and (_has_data_scheme(component, FILE_HANDLER_SCHEMES) or _has_mime_type(component))


def _is_custom_tabs_service(component: Component) -> bool:
    return component.type == "service" and ("customtabs" in component.name.lower() or _has_action(component, {"android.support.customtabs.action.CustomTabsService"}))


def _is_car_service(component: Component) -> bool:
    name = component.name.lower()
    return component.type == "service" and ("androidauto" in name or "carapp" in name or _has_action(component, {"androidx.car.app.CarAppService"}))


def _is_widget_receiver(component: Component) -> bool:
    name = component.name.lower()
    return component.type == "receiver" and ("widget" in name or _has_action(component, {"android.appwidget.action.APPWIDGET_UPDATE"}))


def _is_deep_link_activity(component: Component) -> bool:
    if component.type not in {"activity", "activity-alias"}:
        return False
    for intent_filter in component.intent_filters:
        has_view = "android.intent.action.VIEW" in intent_filter.actions
        if not has_view and BROWSABLE_CATEGORY not in intent_filter.categories:
            continue
        if any((item.get("scheme") or "").lower() not in FILE_HANDLER_SCHEMES and (item.get("scheme") or item.get("host")) for item in intent_filter.data):
            return True
    return False
