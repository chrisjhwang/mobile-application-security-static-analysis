#!/usr/bin/env python3
"""
RQ4: Do apps use INTERNET combined with normal or dangerous permissions?

Run standalone on one APK:
    python internet_pii_permissions.py path/to/app.apk
"""

import sys
from pathlib import Path

# Optional: reuse unused_permissions.py's API map and evidence finder for
# code-location lookup. Both detectors live in the same package.
try:
    from .unused_permissions import (
        PERMISSION_API_MAP as _PERM_API_MAP,
    )
    from .unused_permissions import (
        _find_evidence as _find_ev,
    )
    _CODE_SCAN_AVAILABLE = True
except Exception:
    _CODE_SCAN_AVAILABLE = False


INTERNET = "android.permission.INTERNET"

NORMAL_PERMISSIONS = {
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.FOREGROUND_SERVICE_CAMERA",
    "android.permission.FOREGROUND_SERVICE_MICROPHONE",
    "android.permission.FOREGROUND_SERVICE_LOCATION",
    "android.permission.FOREGROUND_SERVICE_MEDIA_PLAYBACK",
    "android.permission.FOREGROUND_SERVICE_MEDIA_PROCESSING",
    "android.permission.FOREGROUND_SERVICE_PHONE_CALL",
    "android.permission.FOREGROUND_SERVICE_DATA_SYNC",
    "android.permission.FOREGROUND_SERVICE_CONNECTED_DEVICE",
    "android.permission.FOREGROUND_SERVICE_REMOTE_MESSAGING",
    "android.permission.FOREGROUND_SERVICE_SYSTEM_EXEMPTED",
    "android.permission.FOREGROUND_SERVICE_SPECIAL_USE",
    "android.permission.FOREGROUND_SERVICE_HEALTH",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.CHANGE_NETWORK_STATE",
    "android.permission.CHANGE_WIFI_STATE",
    "android.permission.CHANGE_WIFI_MULTICAST_STATE",
    "android.permission.HIGH_SAMPLING_RATE_SENSORS",
    "android.permission.KILL_BACKGROUND_PROCESSES",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.ACCESS_NOTIFICATION_POLICY",
    "android.permission.BLUETOOTH",
    "android.permission.BLUETOOTH_ADMIN",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.POST_PROMOTED_NOTIFICATIONS",
}

DANGEROUS_PERMISSIONS = {
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_MMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.CALL_PHONE",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.GET_ACCOUNTS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.READ_MEDIA_VISUAL_USER_SELECTED",
    "android.permission.ACCESS_MEDIA_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.BODY_SENSORS",
    "android.permission.BODY_SENSORS_BACKGROUND",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_ADVERTISE",
    "android.permission.NEARBY_WIFI_DEVICES",
    "android.permission.UWB_RANGING",
    "android.permission.RANGING",
    "android.permission.USE_SIP",
    "android.permission.ADD_VOICEMAIL",
}

# Permissions flagged as hard restricted by Android
HARD_RESTRICTED = {
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_MMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.BODY_SENSORS_BACKGROUND",
}


def check(apk, dex_list, dx=None):
    """
    Returns:
        found                  : bool — True if INTERNET is present with any other permission
        has_internet           : bool
        normal_permissions     : list of normal permissions declared alongside INTERNET
        dangerous_permissions  : list of dangerous permissions declared alongside INTERNET
        hard_restricted        : list of dangerous permissions that are also hard restricted
        risk_level             : 'high' | 'medium' | 'low' | 'none'
        notes                  : str
    """
    declared = set(apk.get_permissions())
    has_internet = INTERNET in declared

    normal_found    = sorted(declared & NORMAL_PERMISSIONS)
    dangerous_found = sorted(declared & DANGEROUS_PERMISSIONS)
    restricted_found = sorted(declared & HARD_RESTRICTED)

    if not has_internet:
        return {
            "found": False,
            "has_internet": False,
            "normal_permissions": normal_found,
            "dangerous_permissions": dangerous_found,
            "hard_restricted": restricted_found,
            "risk_level": "none",
            "notes": "INTERNET permission not declared.",
        }

    if not normal_found and not dangerous_found:
        return {
            "found": False,
            "has_internet": True,
            "normal_permissions": [],
            "dangerous_permissions": [],
            "hard_restricted": [],
            "risk_level": "none",
            "notes": "INTERNET declared but no categorized permissions found alongside it.",
        }

    if dangerous_found and restricted_found:
        risk_level = "high"
    elif dangerous_found:
        risk_level = "medium"
    else:
        risk_level = "low"

    combo_parts = []
    if normal_found:
        combo_parts.append(f"{len(normal_found)} normal permission(s)")
    if dangerous_found:
        combo_parts.append(f"{len(dangerous_found)} dangerous permission(s)")

    # Locate call sites for each dangerous permission so manual review can
    # confirm the API is actually invoked (not just declared in the manifest).
    code_locations = {}
    if _CODE_SCAN_AVAILABLE and dex_list and dangerous_found:
        for perm in dangerous_found:
            if perm in _PERM_API_MAP:
                locs = _find_ev(dex_list, _PERM_API_MAP[perm])
                if locs:
                    code_locations[perm] = locs

    return {
        "found": True,
        "has_internet": True,
        "normal_permissions": normal_found,
        "dangerous_permissions": dangerous_found,
        "hard_restricted": restricted_found,
        "risk_level": risk_level,
        "code_locations": code_locations,
        "notes": f"INTERNET combined with {' and '.join(combo_parts)}.",
    }


# ── Standalone mode ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m mobsec_scan.detectors.internet_pii_permissions <path/to/app.apk>")
        print("   or: mobsec scan <path/to/app.apk>")
        sys.exit(1)
    from androguard.misc import AnalyzeAPK
    apk_path = Path(sys.argv[1])
    print(f"Loading {apk_path.name} ...")
    apk, d, dx = AnalyzeAPK(str(apk_path))
    dex_list = d if isinstance(d, list) else [d]
    result = check(apk, dex_list, dx)

    print(f"\n[RQ4] INTERNET + Permission Categorization — {apk_path.name}")
    print(f"Status     : {'FOUND' if result['found'] else 'NONE'} (risk: {result['risk_level'].upper()})")
    print(f"Internet   : {'YES' if result['has_internet'] else 'NO'}")
    print(f"Notes      : {result['notes']}")

    print(f"\nNormal permissions found ({len(result['normal_permissions'])}):")
    if result["normal_permissions"]:
        for p in result["normal_permissions"]:
            print(f"  {p}")
    else:
        print("  (none)")

    print(f"\nDangerous permissions found ({len(result['dangerous_permissions'])}):")
    code_locations = result.get("code_locations", {})
    if result["dangerous_permissions"]:
        for p in result["dangerous_permissions"]:
            flag = " [HARD RESTRICTED]" if p in HARD_RESTRICTED else ""
            print(f"  {p}{flag}")
            for loc in code_locations.get(p, []):
                print(f"      @ {loc}")
    else:
        print("  (none)")
