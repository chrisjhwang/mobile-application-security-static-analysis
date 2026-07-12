#!/usr/bin/env python3
"""
RQ7: Are exported components missing a meaningful permission guard?

Covers Activity, Service, BroadcastReceiver, and ContentProvider.
Recognises legitimate exported-without-permission-guard patterns so they
are reported as safe rather than vulnerable.

Run standalone on one APK:
    python rq7.py path/to/app.apk
"""

import sys
from pathlib import Path
from xml.etree import ElementTree as ET


def _element_summary(element) -> str:
    """Render a manifest element as readable pseudo-XML for manual inspection."""
    def _short(tag):
        return tag.split("}")[-1] if "}" in tag else tag

    def _attrs(el):
        return " ".join(
            f'android:{_short(k)}="{v}"' for k, v in el.attrib.items()
        )

    def _render(el, indent=0):
        pad = "  " * indent
        tag = _short(el.tag)
        attrs = _attrs(el)
        children = list(el)
        if not children:
            inner = f" {attrs}" if attrs else ""
            return [f"{pad}<{tag}{inner} />"]
        lines = [f"{pad}<{tag}{' ' + attrs if attrs else ''}>"]
        for child in children:
            lines.extend(_render(child, indent + 1))
        lines.append(f"{pad}</{tag}>")
        return lines

    try:
        return "\n".join(_render(element))
    except Exception:
        return ET.tostring(element, encoding="unicode")


ANDROID_NS = "http://schemas.android.com/apk/res/android"

# Services protected by signature-level BIND_* permissions are safe exports
SIGNATURE_BIND_PERMISSIONS = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_INPUT_METHOD",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
    "android.permission.BIND_VPN_SERVICE",
    "android.permission.BIND_DREAM_SERVICE",
    "android.permission.BIND_PRINT_SERVICE",
    "android.permission.BIND_WALLPAPER",
    "android.permission.BIND_AUTOFILL_SERVICE",
    "android.permission.BIND_QUICK_ACCESS_WALLET_SERVICE",
    "android.permission.BIND_QUICK_SETTINGS_TILE",
    "android.permission.BIND_REMOTEVIEWS",
    "android.permission.BIND_TELECOM_CONNECTION_SERVICE",
    "android.permission.BIND_TV_INPUT",
    "android.permission.BIND_TV_INTERACTIVE_APP",
    "android.permission.BIND_TV_AD_SERVICE",
    "android.permission.BIND_VOICE_INTERACTION",
    "android.permission.BIND_CARRIER_SERVICES",
    "android.permission.BIND_CALL_REDIRECTION_SERVICE",
    "android.permission.BIND_INCALL_SERVICE",
    "android.permission.BIND_SCREENING_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.BIND_MIDI_DEVICE_SERVICE",
    "android.permission.BIND_NFC_SERVICE",
    "android.permission.BIND_CONDITION_PROVIDER_SERVICE",
    "android.permission.BIND_TEXT_SERVICE",
    "android.permission.BIND_CREDENTIAL_PROVIDER_SERVICE",
    "android.permission.BIND_VISUAL_VOICEMAIL_SERVICE",
    "android.permission.BIND_APP_FUNCTION_SERVICE",
    "android.permission.BIND_DATA_MIGRATION_FOR_PRIVATECOMPUTE",
}

# Activities with these actions are expected to be exported
SAFE_ACTIVITY_ACTIONS = {
    "android.intent.action.MAIN",
    "android.intent.action.VIEW",
    "android.intent.action.SEND",
    "android.intent.action.SEND_MULTIPLE",
    "android.intent.action.SENDTO",
    "android.intent.action.EDIT",
    "android.intent.action.PICK",
    "android.intent.action.GET_CONTENT",
    "android.intent.action.OPEN_DOCUMENT",
    "android.intent.action.CREATE_DOCUMENT",
    "android.media.action.IMAGE_CAPTURE",
    "android.media.action.VIDEO_CAPTURE",
    "android.intent.action.PROCESS_TEXT",
    "android.intent.action.SEARCH",
    "android.intent.action.WEB_SEARCH",
    "android.app.action.NEXT_ALARM_CLOCK_CHANGED",
}

# Broadcasts that can only be sent by the system process
SYSTEM_ONLY_BROADCASTS = {
    "android.intent.action.BOOT_COMPLETED",
    "android.intent.action.LOCKED_BOOT_COMPLETED",
    "android.intent.action.MY_PACKAGE_REPLACED",
    "android.intent.action.PACKAGE_REPLACED",
    "android.intent.action.PACKAGE_ADDED",
    "android.intent.action.PACKAGE_REMOVED",
    "android.intent.action.PACKAGE_CHANGED",
    "android.intent.action.LOCALE_CHANGED",
    "android.intent.action.TIMEZONE_CHANGED",
    "android.intent.action.TIME_SET",
    "android.intent.action.DATE_CHANGED",
    "android.intent.action.SCREEN_ON",
    "android.intent.action.SCREEN_OFF",
    "android.intent.action.USER_PRESENT",
    "android.intent.action.BATTERY_LOW",
    "android.intent.action.BATTERY_OKAY",
    "android.intent.action.POWER_CONNECTED",
    "android.intent.action.POWER_DISCONNECTED",
    "android.intent.action.ACTION_POWER_SAVE_MODE_CHANGED",
    "android.net.conn.CONNECTIVITY_CHANGE",
    "android.net.wifi.WIFI_STATE_CHANGED",
    "android.net.wifi.STATE_CHANGE",
    "android.appwidget.action.APPWIDGET_UPDATE",
    "android.appwidget.action.APPWIDGET_ENABLED",
    "android.appwidget.action.APPWIDGET_DISABLED",
    "android.appwidget.action.APPWIDGET_DELETED",
    "android.appwidget.action.APPWIDGET_OPTIONS_CHANGED",
    "android.intent.action.INPUT_METHOD_CHANGED",
    "android.intent.action.DREAMING_STARTED",
    "android.intent.action.DREAMING_STOPPED",
    "android.media.AUDIO_BECOMING_NOISY",
    "android.media.VOLUME_CHANGED_ACTION",
    "android.intent.action.HEADSET_PLUG",
    "com.android.vending.INSTALL_REFERRER",
    "android.intent.action.SIM_STATE_CHANGED",
    "android.telephony.action.CARRIER_CONFIG_CHANGED",
}

# Known safe ContentProvider base classes (handle access control internally)
SAFE_PROVIDER_CLASSES = {
    "androidx.core.content.FileProvider",
    "android.support.v4.content.FileProvider",
    "com.google.android.gms.security.ProviderInstaller",
}

# Normal protection-level permissions — declaring these as android:permission
# on a component grants no real access control
NORMAL_PERMISSIONS = {
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.CHANGE_NETWORK_STATE",
    "android.permission.CHANGE_WIFI_STATE",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.VIBRATE",
    "android.permission.WAKE_LOCK",
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.KILL_BACKGROUND_PROCESSES",
    "android.permission.NFC",
    "android.permission.BLUETOOTH",
    "android.permission.BLUETOOTH_ADMIN",
    "android.permission.BROADCAST_STICKY",
    "android.permission.EXPAND_STATUS_BAR",
    "android.permission.GET_PACKAGE_SIZE",
    "android.permission.INSTALL_SHORTCUT",
    "android.permission.REORDER_TASKS",
    "android.permission.SET_WALLPAPER",
    "android.permission.SET_WALLPAPER_HINTS",
    "android.permission.TRANSMIT_IR",
    "android.permission.USE_BIOMETRIC",
    "android.permission.USE_FINGERPRINT",
    "android.permission.USE_FULL_SCREEN_INTENT",
    "android.permission.DISABLE_KEYGUARD",
    "android.permission.MODIFY_AUDIO_SETTINGS",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.CHANGE_WIFI_MULTICAST_STATE",
    "android.permission.HIGH_SAMPLING_RATE_SENSORS",
    "android.permission.ACCESS_NOTIFICATION_POLICY",
    "android.permission.ACCESS_HIDDEN_PROFILES",
    "android.permission.CALL_COMPANION_APP",
    "android.permission.MANAGE_OWN_CALLS",
    "android.permission.REQUEST_DELETE_PACKAGES",
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
    "android.permission.REQUEST_PASSWORD_COMPLEXITY",
    "android.permission.RUN_USER_INITIATED_JOBS",
    "android.permission.UPDATE_PACKAGES_WITHOUT_USER_ACTION",
    "android.permission.READ_SYNC_SETTINGS",
    "android.permission.WRITE_SYNC_SETTINGS",
    "android.permission.READ_SYNC_STATS",
}

_COMPONENT_TAGS = ("activity", "service", "receiver", "provider")


def _attr(element, name):
    return element.get(f"{{{ANDROID_NS}}}{name}")


def _filter_actions(element):
    actions = set()
    for intent_filter in element.findall("intent-filter"):
        for action in intent_filter.findall("action"):
            val = _attr(action, "name")
            if val:
                actions.add(val)
    return actions


def _classify(element, comp_type):
    """
    Classify a single manifest component as one of:
      "clean"       — not exported, nothing to report
      "protected"   — exported with a meaningful (non-normal) permission guard
      "safe_export" — exported by design; no guard needed for this pattern
      "vulnerable"  — exported without meaningful protection

    Returns (status, entry_dict_or_None).
    """
    name       = _attr(element, "name") or "(unknown)"
    exported   = _attr(element, "exported")
    permission = _attr(element, "permission")
    has_filter = element.find("intent-filter") is not None
    actions    = _filter_actions(element)

    if exported == "true":
        export_how = "explicit (android:exported=true)"
    elif exported is None and has_filter:
        export_how = "implicit (intent-filter, no exported attr — defaults true on Android < 12)"
    else:
        return "clean", None

    # A real guard: permission is set and is not a normal-level permission
    has_real_guard = permission is not None and permission not in NORMAL_PERMISSIONS

    entry = {
        "name":        name,
        "type":        comp_type,
        "export_how":  export_how,
        "permission":  permission,
        "xml_snippet": _element_summary(element),
    }

    if has_real_guard:
        if permission in SIGNATURE_BIND_PERMISSIONS:
            entry["safe_reason"] = f"Bound only by system via signature permission: {permission}"
            return "safe_export", entry
        entry["safe_reason"] = f"Guarded by permission: {permission}"
        return "protected", entry

    # No real guard — check for legitimate no-guard export patterns
    safe_reason = None

    if comp_type == "activity":
        safe_actions = actions & SAFE_ACTIVITY_ACTIONS
        if safe_actions:
            safe_reason = f"Has expected public intent action(s): {', '.join(sorted(safe_actions))}"

    elif comp_type == "receiver":
        if actions and actions.issubset(SYSTEM_ONLY_BROADCASTS):
            safe_reason = (
                f"Receives only system-protected broadcast(s): {', '.join(sorted(actions))}"
            )

    elif comp_type == "provider":
        safe_class = next(
            (cls for cls in SAFE_PROVIDER_CLASSES if name == cls or name.endswith(cls.split(".")[-1])),
            None,
        )
        if safe_class:
            safe_reason = f"Known safe provider class ({safe_class}) — handles access control internally"

    if safe_reason:
        entry["safe_reason"] = safe_reason
        return "safe_export", entry

    perm_note = f" (declared permission '{permission}' is normal-level, offers no real guard)" if permission else ""
    entry["reason"] = f"Exported{perm_note} without a meaningful permission guard."
    return "vulnerable", entry


def check(apk, dex_list, dx=None):
    """
    Returns:
        found           : bool
        vulnerable      : list of dicts — components with no meaningful protection
        safe_exports    : list of dicts — components safely exported by design
        totals          : dict mapping component tag to count
        notes           : str
    """
    try:
        manifest_xml = apk.get_android_manifest_xml()
        if isinstance(manifest_xml, bytes):
            manifest_str = manifest_xml.decode("utf-8", errors="replace")
        else:
            manifest_str = ET.tostring(manifest_xml, encoding="unicode")
        root = ET.fromstring(manifest_str)
    except Exception as e:
        return {
            "found": False, "vulnerable": [], "safe_exports": [],
            "totals": {}, "notes": f"Manifest parse error: {e}",
        }

    application = root.find("application")
    if application is None:
        return {
            "found": False, "vulnerable": [], "safe_exports": [],
            "totals": {}, "notes": "No <application> element found.",
        }

    vulnerable   = []
    safe_exports = []
    totals       = {tag: 0 for tag in _COMPONENT_TAGS}

    for tag in _COMPONENT_TAGS:
        for element in application.findall(tag):
            totals[tag] += 1
            status, entry = _classify(element, tag)
            if status == "vulnerable":
                vulnerable.append(entry)
            elif status == "safe_export":
                safe_exports.append(entry)

    total_components = sum(totals.values())

    if not vulnerable:
        return {
            "found": False,
            "vulnerable": [],
            "safe_exports": safe_exports,
            "totals": totals,
            "notes": (
                f"No unprotected exported components detected across {total_components} component(s). "
                f"{len(safe_exports)} component(s) are safely exported by design."
            ),
        }

    return {
        "found": True,
        "vulnerable": vulnerable,
        "safe_exports": safe_exports,
        "totals": totals,
        "notes": (
            f"{len(vulnerable)} component(s) exported without meaningful protection "
            f"(of {total_components} total). "
            f"{len(safe_exports)} safe-by-design export(s) excluded from count."
        ),
    }


# ── Standalone mode ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python rq7.py <path/to/app.apk>")
        sys.exit(1)
    from androguard.misc import AnalyzeAPK
    apk_path = Path(sys.argv[1])
    print(f"Loading {apk_path.name} ...")
    apk, d, dx = AnalyzeAPK(str(apk_path))
    dex_list = d if isinstance(d, list) else [d]
    result = check(apk, dex_list, dx)

    print(f"\n[RQ7] EXPORTED COMPONENTS — {apk_path.name}")
    print(f"Status : {'VULNERABLE' if result['found'] else 'CLEAN'}")
    print(f"Totals : " + "  ".join(f"{t}={result['totals'].get(t, 0)}" for t in _COMPONENT_TAGS))
    print(f"Notes  : {result['notes']}")

    if result["vulnerable"]:
        print(f"\nVulnerable ({len(result['vulnerable'])}):")
        for c in result["vulnerable"]:
            perm = f"  permission={c['permission']}" if c["permission"] else ""
            print(f"  [{c['type'].upper()}] {c['name']}")
            print(f"    export : {c['export_how']}{perm}")
            print(f"    reason : {c['reason']}")
            if c.get("xml_snippet"):
                print("    manifest snippet:")
                for line in c["xml_snippet"].splitlines():
                    print(f"      {line}")

    if result["safe_exports"]:
        print(f"\nSafe exports ({len(result['safe_exports'])}):")
        for c in result["safe_exports"]:
            print(f"  [{c['type'].upper()}] {c['name']}")
            print(f"    reason : {c['safe_reason']}")
