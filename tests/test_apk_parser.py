import io
import plistlib
import struct
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from apk_parser.server import parse_apk, parse_ipa


def _utf8_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    return bytes([len(value), len(raw)]) + raw + b"\0"


def _string_pool(values: list[str]) -> bytes:
    encoded = [_utf8_string(value) for value in values]
    header_size = 28
    strings_start = header_size + 4 * len(values)
    payload = b"".join(struct.pack("<I", sum(len(item) for item in encoded[:index])) for index in range(len(values)))
    payload += b"".join(encoded)
    size = header_size + len(payload)
    return struct.pack("<HHI", 1, header_size, size) + struct.pack("<IIIII", len(values), 0, 0x100, strings_start, 0) + payload


def _start_element(name_idx: int, attrs: list[tuple[int, int, int | None]]) -> bytes:
    attr_start, attr_size = 20, 20
    values = b""
    for key_idx, raw_idx, int_value in attrs:
        if int_value is None:
            value_type, value_data = 3, raw_idx
        else:
            value_type, value_data = 0x10, int_value
        values += struct.pack("<IIIHBBI", 0xFFFFFFFF, key_idx, raw_idx, 8, 0, value_type, value_data)
    ext = struct.pack("<IIHHHHHH", 0xFFFFFFFF, name_idx, attr_start, attr_size, len(attrs), 0, 0, 0)
    body = b"\0" * 8 + ext + values
    size = 8 + len(body)
    return struct.pack("<HHI", 0x0102, 16, size) + body


def _binary_manifest() -> bytes:
    strings = ["manifest", "package", "com.example.mobile", "versionName", "2.1", "versionCode",
               "uses-sdk", "targetSdkVersion", "33", "minSdkVersion", "24"]
    pool = _string_pool(strings)
    root = _start_element(0, [(1, 2, None), (3, 4, None), (5, 0xFFFFFFFF, 5)])
    sdk = _start_element(6, [(7, 8, 33), (9, 10, 24)])
    end = struct.pack("<HHI", 0x0003, 8, 8 + len(pool) + len(root) + len(sdk)) + pool + root + sdk
    return end


def _apk(manifest: bytes) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        archive.writestr("classes.dex", b"metadata parser must never execute this")
    return output.getvalue()


def test_parses_binary_manifest_without_extracting_or_executing_apk_content():
    result = parse_apk(_apk(_binary_manifest()))
    assert result["package_name"] == "com.example.mobile"
    assert result["version_name"] == "2.1"
    assert result["version_code"] == 5
    assert result["api_level"] == 33
    assert result["metadata"]["min_sdk"] == 24
    assert result["metadata"]["manifest_sha256"]


def test_android_static_adapter_reports_manifest_observations_without_claiming_findings():
    manifest = b'''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.mobile">
      <uses-permission android:name="android.permission.INTERNET"/>
      <application android:debuggable="true" android:allowBackup="true" android:usesCleartextTraffic="true">
        <activity android:name=".Main" android:exported="true"><intent-filter/></activity>
      </application></manifest>'''
    result = parse_apk(_apk(manifest))
    analysis = result["metadata"]["static_analysis"]
    assert analysis["review_state"] == "REVIEW_REQUIRED"
    assert {item["id"]: item["state"] for item in analysis["checks"]} == {
        "android.debuggable": "DECLARED_ENABLED",
        "android.backup_policy": "DECLARED_ENABLED",
        "android.cleartext_traffic": "DECLARED_ENABLED",
    }
    assert analysis["exported_components"][0]["state"] == "EXPLICITLY_EXPORTED"
    assert analysis["declared_permissions"] == ["android.permission.INTERNET"]
    assert "not confirmed vulnerabilities" in analysis["limitations"][0]


def test_ipa_import_reads_only_bounded_info_plist_metadata():
    info = plistlib.dumps({
        "CFBundleIdentifier": "com.example.iosapp",
        "CFBundleDisplayName": "Example",
        "CFBundleShortVersionString": "2.4",
        "CFBundleVersion": "24",
        "MinimumOSVersion": "16.0",
        "UIDeviceFamily": [1, 2],
        "LSApplicationQueriesSchemes": ["example"],
    })
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("Payload/Example.app/Info.plist", info)
        output.writestr("Payload/Example.app/FakeExecutable", b"not parsed")
    result = parse_ipa(archive.getvalue())
    assert result["bundle_id"] == "com.example.iosapp"
    assert result["display_name"] == "Example"
    assert result["version_name"] == "2.4"
    assert result["build_number"] == "24"
    assert result["metadata"]["device_family"] == [1, 2]
    assert result["metadata"]["application_query_scheme_count"] == 1
    assert "Info.plist metadata only" in result["metadata"]["analysis_scope"]


def test_ipa_import_rejects_unsafe_or_invalid_archive():
    with pytest.raises(ValueError, match="IPA size"):
        parse_ipa(b"")
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("Payload/../Info.plist", b"bad")
    with pytest.raises(ValueError, match="unsafe archive path"):
        parse_ipa(archive.getvalue())
    malformed = io.BytesIO()
    with zipfile.ZipFile(malformed, "w") as output:
        output.writestr("Payload/Example.app/Info.plist", b"not a plist")
    with pytest.raises(ValueError, match="Info.plist is malformed"):
        parse_ipa(malformed.getvalue())


def test_rejects_invalid_or_unsafe_apk_archives():
    with pytest.raises(ValueError, match="APK size"):
        parse_apk(b"")
    bad_path = io.BytesIO()
    with zipfile.ZipFile(bad_path, "w") as archive:
        archive.writestr("../AndroidManifest.xml", b"<manifest package='com.example.bad'/>")
        archive.writestr("AndroidManifest.xml", b"<manifest package='com.example.bad'/>")
    with pytest.raises(ValueError, match="unsafe archive path"):
        parse_apk(bad_path.getvalue())


def test_rejects_manifest_entities_and_bad_package_name():
    for manifest in (b"<!DOCTYPE x [<!ENTITY y 'x'>]><manifest package='com.example.bad'/>",
                     b"<manifest package='not-a-package'/>"):
        with pytest.raises(ValueError):
            parse_apk(_apk(manifest))
