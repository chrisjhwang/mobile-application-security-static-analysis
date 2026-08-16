from conftest import FakeApk
from mobsec_scan.detectors import internet_pii_permissions as rq4


def _check(permissions: list[str]) -> dict:
    apk = FakeApk(permissions=permissions)
    return rq4.check(apk, dex_list=[])


def test_no_internet_is_none_risk():
    result = _check(["android.permission.CAMERA"])
    assert result["found"] is False
    assert result["has_internet"] is False
    assert result["risk_level"] == "none"


def test_internet_alone_is_none_risk():
    result = _check(["android.permission.INTERNET"])
    assert result["found"] is False
    assert result["risk_level"] == "none"


def test_internet_plus_normal_permission_is_low_risk():
    result = _check(["android.permission.INTERNET", "android.permission.BLUETOOTH"])
    assert result["found"] is True
    assert result["risk_level"] == "low"
    assert result["dangerous_permissions"] == []


def test_internet_plus_dangerous_permission_is_medium_risk():
    result = _check(["android.permission.INTERNET", "android.permission.CAMERA"])
    assert result["found"] is True
    assert result["risk_level"] == "medium"
    assert "android.permission.CAMERA" in result["dangerous_permissions"]


def test_internet_plus_hard_restricted_permission_is_high_risk():
    result = _check(["android.permission.INTERNET", "android.permission.READ_SMS"])
    assert result["found"] is True
    assert result["risk_level"] == "high"
    assert "android.permission.READ_SMS" in result["hard_restricted"]


def test_hard_restricted_alone_without_dangerous_flag_would_not_apply():
    """READ_SMS is itself dangerous+hard-restricted — this just documents that
    dangerous_found and restricted_found are the same set in that case, so
    'high' requires both being non-empty, not two independent permissions."""
    result = _check(["android.permission.INTERNET", "android.permission.RECEIVE_SMS"])
    assert result["dangerous_permissions"] == result["hard_restricted"]
    assert result["risk_level"] == "high"
