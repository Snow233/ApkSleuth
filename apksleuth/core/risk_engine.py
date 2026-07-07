from __future__ import annotations

from apksleuth.models import AnalysisReport, Component, Finding


LAUNCHER_ACTION = "android.intent.action.MAIN"
LAUNCHER_CATEGORY = "android.intent.category.LAUNCHER"
BROWSABLE_CATEGORY = "android.intent.category.BROWSABLE"
MEDIA_ACTIONS = {"android.intent.action.MEDIA_BUTTON", "android.media.browse.MediaBrowserService"}


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

    if component.type == "service":
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


def _is_deep_link_activity(component: Component) -> bool:
    if component.type not in {"activity", "activity-alias"}:
        return False
    for intent_filter in component.intent_filters:
        if BROWSABLE_CATEGORY in intent_filter.categories:
            return True
        if any(item.get("scheme") or item.get("host") for item in intent_filter.data):
            return True
    return False
