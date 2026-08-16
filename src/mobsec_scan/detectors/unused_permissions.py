#!/usr/bin/env python3
"""
RQ5: Do apps declare permissions they never actually use?

Run standalone on one APK:
    python unused_permissions.py path/to/app.apk
"""

import sys
from pathlib import Path

# Maps each permission to API patterns that confirm it is being used
PERMISSION_API_MAP = {
    # ── Internet ──────────────────────────────────────────────────────────────
    "android.permission.INTERNET": [
        "java/net/URL", "java/net/HttpURLConnection",
        "okhttp3", "retrofit2", "android/webkit/WebView",
    ],

    # ── Normal permissions ────────────────────────────────────────────────────
    "android.permission.RECEIVE_BOOT_COMPLETED": [
        "BOOT_COMPLETED", "android/content/BroadcastReceiver",
    ],
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": [
        "android/os/PowerManager", "isIgnoringBatteryOptimizations",
        "ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
    ],
    "android.permission.FOREGROUND_SERVICE": [
        "startForeground", "android/app/Service",
    ],
    "android.permission.FOREGROUND_SERVICE_CAMERA": [
        "startForeground", "FOREGROUND_SERVICE_TYPE_CAMERA",
    ],
    "android.permission.FOREGROUND_SERVICE_MICROPHONE": [
        "startForeground", "FOREGROUND_SERVICE_TYPE_MICROPHONE",
    ],
    "android.permission.FOREGROUND_SERVICE_LOCATION": [
        "startForeground", "FOREGROUND_SERVICE_TYPE_LOCATION",
    ],
    "android.permission.FOREGROUND_SERVICE_MEDIA_PLAYBACK": [
        "startForeground", "FOREGROUND_SERVICE_TYPE_MEDIA_PLAYBACK",
    ],
    "android.permission.FOREGROUND_SERVICE_MEDIA_PROCESSING": [
        "startForeground", "FOREGROUND_SERVICE_TYPE_MEDIA_PROCESSING",
    ],
    "android.permission.FOREGROUND_SERVICE_PHONE_CALL": [
        "startForeground", "FOREGROUND_SERVICE_TYPE_PHONE_CALL",
    ],
    "android.permission.FOREGROUND_SERVICE_DATA_SYNC": [
        "startForeground", "FOREGROUND_SERVICE_TYPE_DATA_SYNC",
    ],
    "android.permission.FOREGROUND_SERVICE_CONNECTED_DEVICE": [
        "startForeground", "FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE",
    ],
    "android.permission.FOREGROUND_SERVICE_REMOTE_MESSAGING": [
        "startForeground", "FOREGROUND_SERVICE_TYPE_REMOTE_MESSAGING",
    ],
    "android.permission.FOREGROUND_SERVICE_SYSTEM_EXEMPTED": [
        "startForeground", "FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED",
    ],
    "android.permission.FOREGROUND_SERVICE_SPECIAL_USE": [
        "startForeground", "FOREGROUND_SERVICE_TYPE_SPECIAL_USE",
    ],
    "android.permission.FOREGROUND_SERVICE_HEALTH": [
        "startForeground", "FOREGROUND_SERVICE_TYPE_HEALTH",
    ],
    "android.permission.ACCESS_NETWORK_STATE": [
        "android/net/ConnectivityManager", "getActiveNetworkInfo",
        "getNetworkCapabilities",
    ],
    "android.permission.ACCESS_WIFI_STATE": [
        "android/net/wifi/WifiManager", "getConnectionInfo", "getWifiState",
    ],
    "android.permission.CHANGE_NETWORK_STATE": [
        "android/net/ConnectivityManager", "requestNetwork",
    ],
    "android.permission.CHANGE_WIFI_STATE": [
        "android/net/wifi/WifiManager", "setWifiEnabled", "disconnect",
    ],
    "android.permission.CHANGE_WIFI_MULTICAST_STATE": [
        "android/net/wifi/WifiManager", "createMulticastLock", "MulticastLock",
    ],
    "android.permission.HIGH_SAMPLING_RATE_SENSORS": [
        "android/hardware/SensorManager", "SENSOR_DELAY_FASTEST",
    ],
    "android.permission.KILL_BACKGROUND_PROCESSES": [
        "android/app/ActivityManager", "killBackgroundProcesses",
    ],
    "android.permission.PACKAGE_USAGE_STATS": [
        "android/app/usage/UsageStatsManager", "queryUsageStats",
    ],
    "android.permission.ACCESS_NOTIFICATION_POLICY": [
        "android/app/NotificationManager", "getNotificationPolicy",
    ],
    "android.permission.BLUETOOTH": [
        "android/bluetooth/BluetoothAdapter", "getDefaultAdapter",
    ],
    "android.permission.BLUETOOTH_ADMIN": [
        "android/bluetooth/BluetoothAdapter", "startDiscovery", "enable",
    ],
    "android.permission.SYSTEM_ALERT_WINDOW": [
        "android/view/WindowManager", "TYPE_APPLICATION_OVERLAY",
    ],
    "android.permission.POST_NOTIFICATIONS": [
        "android/app/NotificationManager", "notify",
        "android/app/NotificationChannel",
    ],
    "android.permission.POST_PROMOTED_NOTIFICATIONS": [
        "android/app/NotificationManager", "notify",
    ],

    # ── Dangerous permissions ─────────────────────────────────────────────────
    "android.permission.RECORD_AUDIO": [
        "android/media/MediaRecorder", "android/media/AudioRecord", "startRecording",
    ],
    "android.permission.CAMERA": [
        "android/hardware/Camera", "android/hardware/camera2", "CameraManager",
    ],
    "android.permission.ACCESS_FINE_LOCATION": [
        "android/location/LocationManager", "FusedLocationProviderClient",
        "requestLocationUpdates",
    ],
    "android.permission.ACCESS_BACKGROUND_LOCATION": [
        "android/location/LocationManager", "FusedLocationProviderClient",
    ],
    "android.permission.ACCESS_COARSE_LOCATION": [
        "android/location/LocationManager", "requestLocationUpdates",
    ],
    "android.permission.READ_SMS": [
        "android/provider/Telephony", "content://sms",
    ],
    "android.permission.RECEIVE_SMS": [
        "android/provider/Telephony", "SMS_RECEIVED",
    ],
    "android.permission.SEND_SMS": [
        "android/telephony/SmsManager", "sendTextMessage",
    ],
    "android.permission.RECEIVE_MMS": [
        "android/provider/Telephony", "WAP_PUSH_RECEIVED", "MMS_RECEIVED",
    ],
    "android.permission.RECEIVE_WAP_PUSH": [
        "android/provider/Telephony", "WAP_PUSH_RECEIVED",
    ],
    "android.permission.READ_CALL_LOG": [
        "android/provider/CallLog", "content://call_log",
    ],
    "android.permission.WRITE_CALL_LOG": [
        "android/provider/CallLog",
    ],
    "android.permission.PROCESS_OUTGOING_CALLS": [
        "NEW_OUTGOING_CALL", "android/telephony/TelephonyManager",
    ],
    "android.permission.ANSWER_PHONE_CALLS": [
        "android/telecom/TelecomManager", "acceptRingingCall",
    ],
    "android.permission.CALL_PHONE": [
        "ACTION_CALL", "tel:",
    ],
    "android.permission.READ_CONTACTS": [
        "android/provider/ContactsContract", "ContentResolver",
    ],
    "android.permission.WRITE_CONTACTS": [
        "android/provider/ContactsContract", "ContentResolver;->insert",
    ],
    "android.permission.READ_CALENDAR": [
        "android/provider/CalendarContract",
    ],
    "android.permission.WRITE_CALENDAR": [
        "android/provider/CalendarContract", "CalendarContract$Events;->insert",
    ],
    "android.permission.GET_ACCOUNTS": [
        "android/accounts/AccountManager", "getAccounts",
    ],
    "android.permission.READ_PHONE_STATE": [
        "android/telephony/TelephonyManager", "getDeviceId", "getImei",
    ],
    "android.permission.READ_PHONE_NUMBERS": [
        "android/telephony/TelephonyManager", "getLine1Number",
    ],
    "android.permission.READ_MEDIA_IMAGES": [
        "android/provider/MediaStore$Images", "MediaStore",
    ],
    "android.permission.READ_MEDIA_VIDEO": [
        "android/provider/MediaStore$Video", "MediaStore",
    ],
    "android.permission.READ_MEDIA_AUDIO": [
        "android/provider/MediaStore$Audio", "MediaStore",
    ],
    "android.permission.READ_MEDIA_VISUAL_USER_SELECTED": [
        "android/provider/MediaStore", "ACTION_PICK_IMAGES",
    ],
    "android.permission.ACCESS_MEDIA_LOCATION": [
        "android/provider/MediaStore", "EXTRA_EXIF_STREAM",
    ],
    "android.permission.READ_EXTERNAL_STORAGE": [
        "getExternalStorageDirectory", "getExternalFilesDir",
    ],
    "android.permission.WRITE_EXTERNAL_STORAGE": [
        "getExternalStorageDirectory", "getExternalFilesDir",
    ],
    "android.permission.BODY_SENSORS": [
        "android/hardware/SensorManager", "TYPE_HEART_RATE",
    ],
    "android.permission.BODY_SENSORS_BACKGROUND": [
        "android/hardware/SensorManager", "TYPE_HEART_RATE",
    ],
    "android.permission.ACTIVITY_RECOGNITION": [
        "com/google/android/gms/location/ActivityRecognitionClient",
        "requestActivityUpdates",
    ],
    "android.permission.BLUETOOTH_SCAN": [
        "android/bluetooth/le/BluetoothLeScanner", "startScan",
    ],
    "android.permission.BLUETOOTH_CONNECT": [
        "android/bluetooth/BluetoothDevice", "connect",
    ],
    "android.permission.BLUETOOTH_ADVERTISE": [
        "android/bluetooth/le/BluetoothLeAdvertiser", "startAdvertising",
    ],
    "android.permission.NEARBY_WIFI_DEVICES": [
        "android/net/wifi/WifiManager", "startScan",
        "android/net/wifi/p2p/WifiP2pManager",
    ],
    "android.permission.UWB_RANGING": [
        "android/uwb/UwbManager", "openRangingSession",
    ],
    "android.permission.RANGING": [
        "android/uwb/UwbManager", "openRangingSession",
    ],
    "android.permission.USE_SIP": [
        "android/net/sip/SipManager", "open",
    ],
    "android.permission.ADD_VOICEMAIL": [
        "android/provider/VoicemailContract", "Voicemails;->insert",
    ],
}


def _find_evidence(dex_list, patterns, max_hits=2) -> list:
    """Return up to max_hits 'ClassName -> methodName' strings where any pattern is found."""
    hits, seen = [], set()
    for dex in dex_list:
        for cls in dex.get_classes():
            if len(hits) >= max_hits:
                return hits
            cls_name = cls.get_name()
            for method in cls.get_methods():
                if len(hits) >= max_hits:
                    return hits
                meth_name = method.get_name()
                key = f"{cls_name}->{meth_name}"
                if key in seen:
                    continue
                text = cls_name + " " + meth_name
                code = method.get_code()
                if code:
                    try:
                        text += " " + str(code)
                    except Exception:
                        pass
                for p in patterns:
                    if p in text:
                        hits.append(f"{cls_name} -> {meth_name}")
                        seen.add(key)
                        break
    return hits


def _build_corpus(dex_list) -> str:
    """Collect all string literals + class/method names into one searchable string."""
    chunks = []
    for dex in dex_list:
        # All string literals in the DEX (Androguard 4.x API)
        for string_item in dex.get_strings():
            try:
                val = string_item.get_value()
                if val:
                    chunks.append(val)
            except Exception:
                pass
        # Class and method names (catches API references)
        for cls in dex.get_classes():
            chunks.append(cls.get_name())
            for method in cls.get_methods():
                chunks.append(method.get_name())
                code = method.get_code()
                if code:
                    try:
                        chunks.append(str(code))
                    except Exception:
                        pass
    return "\n".join(chunks)


def check(apk, dex_list, dx=None):
    """
    Returns:
        found               : bool
        unused_permissions  : list of permissions declared but API never found
        used_permissions    : list of permissions with matching API calls
        total_declared      : int
        total_checkable     : int
        notes               : str
    """
    declared  = set(apk.get_permissions())
    checkable = {p for p in declared if p in PERMISSION_API_MAP}

    if not checkable:
        return {
            "found": False,
            "unused_permissions": [],
            "used_permissions": [],
            "total_declared": len(declared),
            "total_checkable": 0,
            "notes": "No checkable permissions found in mapping database.",
        }

    corpus = _build_corpus(dex_list)
    unused, used = [], []

    for perm in sorted(checkable):
        if any(pattern in corpus for pattern in PERMISSION_API_MAP[perm]):
            used.append(perm)
        else:
            unused.append(perm)

    # Collect call-site evidence for used permissions so manual review can
    # confirm the match is a real API call and not an incidental string literal.
    evidence = {}
    for perm in used:
        locs = _find_evidence(dex_list, PERMISSION_API_MAP[perm])
        if locs:
            evidence[perm] = locs

    return {
        "found": len(unused) > 0,
        "unused_permissions": unused,
        "used_permissions": used,
        "evidence": evidence,
        "total_declared": len(declared),
        "total_checkable": len(checkable),
        "notes": (
            f"{len(unused)} of {len(checkable)} checkable permission(s) appear unused. "
            "Note: dynamic dispatch may cause false positives — manual review advised."
        ),
    }


# ── Standalone mode ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python unused_permissions.py <path/to/app.apk>")
        sys.exit(1)
    from androguard.misc import AnalyzeAPK
    apk_path = Path(sys.argv[1])
    print(f"Loading {apk_path.name} ...")
    apk, d, dx = AnalyzeAPK(str(apk_path))
    dex_list = d if isinstance(d, list) else [d]
    result = check(apk, dex_list, dx)
    print(f"\n[RQ5] UNUSED PERMISSIONS — {apk_path.name}")
    print(f"Status   : {'FLAGGED' if result['found'] else 'CLEAN'}")
    print(f"Declared : {result['total_declared']}  Checkable : {result['total_checkable']}")
    print(f"Unused ({len(result['unused_permissions'])}):")
    for p in result["unused_permissions"]:
        print(f"  - {p}")
    print(f"Used ({len(result['used_permissions'])}):")
    evidence = result.get("evidence", {})
    for p in result["used_permissions"]:
        print(f"  + {p}")
        for loc in evidence.get(p, []):
            print(f"      @ {loc}")
