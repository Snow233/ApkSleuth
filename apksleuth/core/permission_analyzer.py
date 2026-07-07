from __future__ import annotations

from apksleuth.models import PermissionAnalysis


HIGH_RISK_PERMISSIONS: dict[str, tuple[str, str]] = {
    "android.permission.READ_SMS": ("Reads SMS messages.", "Keep only for core SMS functionality and explain usage to users."),
    "android.permission.SEND_SMS": ("Sends SMS messages.", "Remove unless SMS sending is essential and user initiated."),
    "android.permission.RECEIVE_SMS": ("Receives SMS messages.", "Avoid unless the app is an SMS or verification app."),
    "android.permission.READ_CONTACTS": ("Reads contacts.", "Request only when contact access is directly required."),
    "android.permission.WRITE_CONTACTS": ("Modifies contacts.", "Avoid broad contact write access."),
    "android.permission.RECORD_AUDIO": ("Records microphone audio.", "Request only during visible audio capture flows."),
    "android.permission.CAMERA": ("Uses the camera.", "Request only during visible camera capture flows."),
    "android.permission.ACCESS_FINE_LOCATION": ("Reads precise location.", "Prefer approximate location or remove if not required."),
    "android.permission.READ_PHONE_STATE": ("Reads phone and device state.", "Avoid device identifiers when possible."),
    "android.permission.SYSTEM_ALERT_WINDOW": ("Draws overlays over other apps.", "Remove unless overlay behavior is essential."),
    "android.permission.REQUEST_INSTALL_PACKAGES": ("Requests package installation.", "Remove unless the app is an authorized installer/updater."),
}

SENSITIVE_PERMISSIONS: dict[str, tuple[str, str]] = {
    "android.permission.ACCESS_COARSE_LOCATION": ("Reads approximate location.", "Request only when location is required."),
    "android.permission.GET_ACCOUNTS": ("Reads account list.", "Avoid unless account discovery is necessary."),
    "android.permission.READ_CALENDAR": ("Reads calendar data.", "Request only for calendar features."),
    "android.permission.WRITE_CALENDAR": ("Writes calendar data.", "Request only for calendar features."),
    "android.permission.READ_EXTERNAL_STORAGE": ("Reads shared storage.", "Use scoped storage where possible."),
    "android.permission.WRITE_EXTERNAL_STORAGE": ("Writes shared storage.", "Use scoped storage where possible."),
    "android.permission.POST_NOTIFICATIONS": ("Posts notifications.", "Request only when notification value is clear."),
}


def analyze_permissions(permissions: list[str]) -> list[PermissionAnalysis]:
    results: list[PermissionAnalysis] = []
    for permission in sorted(permissions):
        if permission in HIGH_RISK_PERMISSIONS:
            description, recommendation = HIGH_RISK_PERMISSIONS[permission]
            level = "high"
        elif permission in SENSITIVE_PERMISSIONS:
            description, recommendation = SENSITIVE_PERMISSIONS[permission]
            level = "sensitive"
        else:
            description = "Standard Android permission or custom application permission."
            recommendation = "Keep only if this permission is required by a documented feature."
            level = "normal"
        results.append(PermissionAnalysis(permission, level, description, recommendation))
    return results
