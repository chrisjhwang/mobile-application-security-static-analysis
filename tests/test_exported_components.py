from conftest import FakeApk, make_manifest
from mobsec_scan.detectors import exported_components as rq7


def _check(application_body: str) -> dict:
    apk = FakeApk(manifest_xml=make_manifest(application_body))
    return rq7.check(apk, dex_list=[])


def test_unguarded_exported_activity_is_vulnerable():
    result = _check(
        '<activity android:name=".LeakyActivity" android:exported="true" />'
    )
    assert result["found"] is True
    names = [c["name"] for c in result["vulnerable"]]
    assert ".LeakyActivity" in names


def test_not_exported_activity_is_clean():
    result = _check(
        '<activity android:name=".PrivateActivity" android:exported="false" />'
    )
    assert result["vulnerable"] == []
    assert result["safe_exports"] == []


def test_launcher_activity_is_safe_by_design():
    result = _check(
        """
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
            </intent-filter>
        </activity>
        """
    )
    assert result["vulnerable"] == []
    safe_names = [c["name"] for c in result["safe_exports"]]
    assert ".MainActivity" in safe_names


def test_signature_bind_service_is_safe_export_not_vulnerable():
    result = _check(
        """
        <service android:name=".MyAccessibilityService" android:exported="true"
                 android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE" />
        """
    )
    assert result["vulnerable"] == []
    entry = result["safe_exports"][0]
    assert entry["type"] == "service"
    assert "signature permission" in entry["safe_reason"]


def test_normal_permission_guard_is_not_a_real_guard():
    """A component 'protected' only by a normal-level permission (e.g.
    INTERNET) offers no real access control and must not be treated as safe."""
    result = _check(
        """
        <receiver android:name=".UnguardedReceiver" android:exported="true"
                  android:permission="android.permission.INTERNET" />
        """
    )
    assert result["safe_exports"] == []
    assert len(result["vulnerable"]) == 1
    assert "normal-level" in result["vulnerable"][0]["reason"]


def test_meaningful_permission_guard_is_protected_not_vulnerable():
    result = _check(
        """
        <activity android:name=".AdminActivity" android:exported="true"
                  android:permission="com.example.test.permission.ADMIN_ONLY" />
        """
    )
    assert result["vulnerable"] == []
    assert result["safe_exports"] == []


def test_manifest_parse_error_returns_clean_result_not_exception():
    apk = FakeApk(manifest_xml=b"not valid xml <<<")
    result = rq7.check(apk, dex_list=[])
    assert result["found"] is False
    assert "error" in result["notes"].lower()
