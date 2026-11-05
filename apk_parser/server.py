"""No-extraction APK manifest parser intended to run in a network-isolated container."""
import hashlib
import http.server
import io
import json
import re
import struct
import sys
import threading
import xml.etree.ElementTree as ET
import zipfile

try:
    from .static_analysis import AndroidManifestStaticAnalysisAdapter
except ImportError:  # Container entrypoint executes this file as a top-level script.
    # Python's isolated (-I) mode omits the script directory from sys.path.
    sys.path.insert(0, "/app")
    from static_analysis import AndroidManifestStaticAnalysisAdapter

MAX_APK = 20 * 1024 * 1024
MAX_MANIFEST = 2 * 1024 * 1024
MAX_ENTRIES = 20_000
MAX_UNCOMPRESSED = 128 * 1024 * 1024


def _u8(data, offset):
    first = data[offset]
    if first & 0x80:
        return ((first & 0x7F) << 8) | data[offset + 1], offset + 2
    return first, offset + 1


def _u16len(data, offset):
    first = struct.unpack_from("<H", data, offset)[0]
    if first & 0x8000:
        second = struct.unpack_from("<H", data, offset + 2)[0]
        return ((first & 0x7FFF) << 16) | second, offset + 4
    return first, offset + 2


def _binary_xml(data):
    strings = []
    elements = []
    if len(data) < 8 or struct.unpack_from("<H", data, 0)[0] != 0x0003:
        raise ValueError("Invalid binary Android XML header")
    pos = 8
    while pos + 8 <= len(data):
        kind, header_size, size = struct.unpack_from("<HHI", data, pos)
        if size < header_size or size < 8 or pos + size > len(data):
            raise ValueError("Invalid Android XML chunk bounds")
        if kind == 0x0001:
            if header_size < 28 or size > MAX_MANIFEST:
                raise ValueError("Invalid Android XML string pool")
            string_count, _style_count, flags, strings_start, _styles_start = struct.unpack_from("<IIIII", data, pos + 8)
            if string_count > 100_000 or header_size + string_count * 4 > size:
                raise ValueError("Android XML string pool exceeds limits")
            utf8 = bool(flags & 0x100)
            offsets_start = pos + header_size
            for index in range(string_count):
                offset = struct.unpack_from("<I", data, offsets_start + index * 4)[0]
                cursor = pos + strings_start + offset
                if utf8:
                    _chars, cursor = _u8(data, cursor)
                    byte_len, cursor = _u8(data, cursor)
                    raw = data[cursor:cursor + byte_len]
                    if len(raw) != byte_len:
                        raise ValueError("Truncated Android XML string")
                    strings.append(raw.decode("utf-8", "strict"))
                else:
                    char_len, cursor = _u16len(data, cursor)
                    byte_len = char_len * 2
                    raw = data[cursor:cursor + byte_len]
                    if len(raw) != byte_len:
                        raise ValueError("Truncated Android XML string")
                    strings.append(raw.decode("utf-16le", "strict"))
        elif kind == 0x0102:
            if header_size < 16 or size < 36:
                raise ValueError("Invalid Android XML element")
            _ns, name_idx, attr_start, attr_size, attr_count = struct.unpack_from("<IIHHH", data, pos + 16)
            if attr_count > 4096 or attr_size < 20 or attr_start > size:
                raise ValueError("Android XML attributes exceed limits")
            name = strings[name_idx] if name_idx < len(strings) else ""
            attrs = {}
            first_attr = pos + 16 + attr_start
            for index in range(attr_count):
                offset = first_attr + index * attr_size
                if offset + 20 > pos + size:
                    raise ValueError("Truncated Android XML attribute")
                _attr_ns, key_idx, raw_idx = struct.unpack_from("<III", data, offset)
                value_size, _res0, value_type, value_data = struct.unpack_from("<HBBI", data, offset + 12)
                if value_size < 8:
                    raise ValueError("Invalid Android XML typed value")
                key = strings[key_idx] if key_idx < len(strings) else ""
                if raw_idx != 0xFFFFFFFF and raw_idx < len(strings):
                    value = strings[raw_idx]
                elif value_type == 0x03 and value_data < len(strings):
                    value = strings[value_data]
                elif value_type in {0x10, 0x11}:
                    value = str(value_data)
                else:
                    value = ""
                attrs[key] = value
            elements.append((name, attrs))
        pos += size
    return elements


def parse_apk(blob):
    if not blob or len(blob) > MAX_APK:
        raise ValueError("APK size is outside allowed limits")
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        entries = archive.infolist()
        if len(entries) > MAX_ENTRIES or sum(item.file_size for item in entries) > MAX_UNCOMPRESSED:
            raise ValueError("APK archive expands beyond parser limits")
        for item in entries:
            parts = item.filename.replace("\\", "/").split("/")
            if item.filename.startswith("/") or ".." in parts:
                raise ValueError("APK contains an unsafe archive path")
        matches = [item for item in entries if item.filename == "AndroidManifest.xml"]
        if len(matches) != 1:
            raise ValueError("APK must contain exactly one AndroidManifest.xml")
        info = matches[0]
        if info.file_size > MAX_MANIFEST or (info.compress_size == 0 and info.file_size > 0):
            raise ValueError("Android manifest exceeds parser limits")
        if info.compress_size and info.file_size / info.compress_size > 100:
            raise ValueError("Android manifest compression ratio exceeds parser limits")
        manifest = archive.read(info)
    manifest_sha256 = hashlib.sha256(manifest).hexdigest()
    if manifest.lstrip().startswith(b"<"):
        if b"<!DOCTYPE" in manifest.upper() or b"<!ENTITY" in manifest.upper():
            raise ValueError("Manifest declarations are unsupported")
        root = ET.fromstring(manifest)
        package = root.attrib.get("package", "")
        version_name = root.attrib.get("{http://schemas.android.com/apk/res/android}versionName", "")
        version_code = root.attrib.get("{http://schemas.android.com/apk/res/android}versionCode", "")
        sdk = next((node for node in root if node.tag.endswith("uses-sdk")), None)
        min_sdk = sdk.attrib.get("{http://schemas.android.com/apk/res/android}minSdkVersion", "") if sdk is not None else ""
        target_sdk = sdk.attrib.get("{http://schemas.android.com/apk/res/android}targetSdkVersion", "") if sdk is not None else ""
        android_manifest = _manifest_from_xml(root)
    else:
        elements = _binary_xml(manifest)
        manifest_attrs = next((attrs for name, attrs in elements if name == "manifest"), {})
        sdk_attrs = next((attrs for name, attrs in elements if name == "uses-sdk"), {})
        package = manifest_attrs.get("package", "")
        version_name = manifest_attrs.get("versionName", "")
        version_code = manifest_attrs.get("versionCode", "")
        min_sdk = sdk_attrs.get("minSdkVersion", "")
        target_sdk = sdk_attrs.get("targetSdkVersion", "")
        android_manifest = _manifest_from_binary(elements)
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+", package):
        raise ValueError("Manifest package name is invalid")
    for number in (version_code, min_sdk, target_sdk):
        if number and not str(number).isdigit():
            raise ValueError("Manifest numeric metadata is malformed")
    static_analysis = AndroidManifestStaticAnalysisAdapter().analyze(android_manifest)
    return {"package_name": package, "version_name": str(version_name)[:200],
            "version_code": int(version_code) if version_code else 0,
            "api_level": int(target_sdk) if target_sdk else None,
            "metadata": {"min_sdk": int(min_sdk) if min_sdk else None,
                         "target_sdk": int(target_sdk) if target_sdk else None,
                         "manifest_sha256": manifest_sha256, "parser_version": "1",
                         "static_analysis": static_analysis}}


ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def _manifest_from_xml(root):
    application = next((node for node in root if node.tag.endswith("application")), None)
    app_attrs = ({key.rsplit("}", 1)[-1]: value for key, value in application.attrib.items()}
                 if application is not None else {})
    components = []
    if application is not None:
        for node in application:
            kind = node.tag.rsplit("}", 1)[-1]
            if kind not in {"activity", "activity-alias", "service", "receiver", "provider"}:
                continue
            attrs = {key.rsplit("}", 1)[-1]: value for key, value in node.attrib.items()}
            components.append({"type": kind, "name": attrs.get("name", ""),
                               "exported": attrs.get("exported"),
                               "intent_filter": any(child.tag.endswith("intent-filter") for child in node)})
    permissions = []
    for node in root:
        if node.tag.rsplit("}", 1)[-1] in {"uses-permission", "uses-permission-sdk-23",
                                           "uses-permission-sdk-m"}:
            permissions.append(node.attrib.get(ANDROID_NS + "name", ""))
    return {"application": app_attrs, "components": components, "permissions": permissions}


def _manifest_from_binary(elements):
    app_attrs = next((attrs for name, attrs in elements if name == "application"), {})
    components = []
    for index, (name, attrs) in enumerate(elements):
        if name not in {"activity", "activity-alias", "service", "receiver", "provider"}:
            continue
        end = next((i for i in range(index + 1, len(elements))
                    if elements[i][0] in {"activity", "activity-alias", "service", "receiver", "provider", "application"}), len(elements))
        has_filter = any(child_name == "intent-filter" for child_name, _ in elements[index + 1:end])
        components.append({"type": name, "name": attrs.get("name", ""),
                           "exported": attrs.get("exported"), "intent_filter": has_filter})
    permissions = [attrs.get("name", "") for name, attrs in elements
                   if name in {"uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m"}]
    return {"application": app_attrs, "components": components, "permissions": permissions}



class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/health":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_POST(self):
        if self.path != "/parse":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > MAX_APK:
                raise ValueError("APK size is outside allowed limits")
            blob = self.rfile.read(length)
            if len(blob) != length:
                raise ValueError("Truncated APK upload")
            result = parse_apk(blob)
            status = 200
        except (ValueError, OSError, IndexError, struct.error, UnicodeError, zipfile.BadZipFile, ET.ParseError, OverflowError):
            result, status = {"detail": "APK could not be parsed safely"}, 422
        body = json.dumps(result, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass

    def setup(self):
        super().setup()
        self.connection.settimeout(6)


class BoundedServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    _slots = threading.BoundedSemaphore(2)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


if __name__ == "__main__":
    BoundedServer(("0.0.0.0", 8090), Handler).serve_forever()
