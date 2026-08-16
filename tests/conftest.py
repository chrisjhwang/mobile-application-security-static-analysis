"""Shared fixtures: lightweight fakes standing in for androguard's APK/DEX
objects, so detector logic can be tested without a real APK corpus (there
isn't one in this repo — see CLAUDE.md).

Each fake implements exactly the subset of androguard's real interface each
detector actually calls (`get_permissions()`, `get_android_manifest_xml()`,
`get_classes()`, `get_methods()`, `get_code()`, `get_strings()`) — nothing
more, so a fixture reads as a spec of what a detector depends on.
"""

from __future__ import annotations

ANDROID_NS = "http://schemas.android.com/apk/res/android"


class FakeApk:
    """Stands in for androguard's APK object."""

    def __init__(self, permissions: list[str] | None = None, manifest_xml: bytes | None = None):
        self._permissions = permissions or []
        self._manifest_xml = manifest_xml

    def get_permissions(self) -> list[str]:
        return list(self._permissions)

    def get_android_manifest_xml(self) -> bytes:
        return self._manifest_xml


class FakeMethod:
    """Stands in for androguard's EncodedMethod — get_code() returns
    something whose str() contains any API-pattern text a test wants
    findable, mirroring how _build_corpus / _find_evidence read it."""

    def __init__(self, name: str, code_text: str = ""):
        self._name = name
        self._code_text = code_text

    def get_name(self) -> str:
        return self._name

    def get_code(self):
        return self._code_text or None


class FakeClass:
    def __init__(self, name: str, methods: list[FakeMethod] | None = None):
        self._name = name
        self._methods = methods or []

    def get_name(self) -> str:
        return self._name

    def get_methods(self) -> list[FakeMethod]:
        return self._methods


class FakeStringItem:
    def __init__(self, value: str):
        self._value = value

    def get_value(self) -> str:
        return self._value


class FakeDex:
    def __init__(self, classes: list[FakeClass] | None = None, strings: list[str] | None = None):
        self._classes = classes or []
        self._strings = strings or []

    def get_classes(self) -> list[FakeClass]:
        return self._classes

    def get_strings(self) -> list[FakeStringItem]:
        return [FakeStringItem(s) for s in self._strings]


def make_manifest(application_body: str) -> bytes:
    """Build a minimal, well-formed AndroidManifest.xml as bytes, the shape
    `exported_components.check()` expects from `apk.get_android_manifest_xml()`."""
    xml = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="{ANDROID_NS}" package="com.example.test">
    <application>
        {application_body}
    </application>
</manifest>"""
    return xml.encode("utf-8")
