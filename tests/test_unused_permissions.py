from conftest import FakeApk, FakeClass, FakeDex, FakeMethod
from mobsec_scan.detectors import unused_permissions as rq5


def test_permission_with_matching_api_call_is_used():
    apk = FakeApk(permissions=["android.permission.INTERNET"])
    dex = FakeDex(
        classes=[
            FakeClass(
                "Lcom/example/Net;",
                methods=[FakeMethod("fetch", code_text="invoke-virtual okhttp3/OkHttpClient")],
            )
        ]
    )
    result = rq5.check(apk, dex_list=[dex])
    assert result["used_permissions"] == ["android.permission.INTERNET"]
    assert result["unused_permissions"] == []
    assert result["found"] is False


def test_permission_with_no_matching_api_call_is_unused():
    apk = FakeApk(permissions=["android.permission.CAMERA"])
    dex = FakeDex(
        classes=[FakeClass("Lcom/example/Unrelated;", methods=[FakeMethod("doNothing")])]
    )
    result = rq5.check(apk, dex_list=[dex])
    assert result["unused_permissions"] == ["android.permission.CAMERA"]
    assert result["used_permissions"] == []
    assert result["found"] is True


def test_permission_not_in_mapping_is_uncheckable():
    apk = FakeApk(permissions=["android.permission.SOME_UNMAPPED_PERMISSION"])
    result = rq5.check(apk, dex_list=[FakeDex()])
    assert result["total_checkable"] == 0
    assert result["found"] is False
    assert result["unused_permissions"] == []


def test_used_permission_gets_call_site_evidence():
    apk = FakeApk(permissions=["android.permission.CAMERA"])
    dex = FakeDex(
        classes=[
            FakeClass(
                "Lcom/example/Cam;",
                methods=[FakeMethod("openCamera", code_text="android/hardware/camera2/CameraManager")],
            )
        ]
    )
    result = rq5.check(apk, dex_list=[dex])
    assert result["used_permissions"] == ["android.permission.CAMERA"]
    assert "android.permission.CAMERA" in result["evidence"]
    assert result["evidence"]["android.permission.CAMERA"][0] == "Lcom/example/Cam; -> openCamera"
