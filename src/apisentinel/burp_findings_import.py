"""Bounded parser for the documented Burp Scanner issues XML export subset."""

from __future__ import annotations

import base64
import re
from html import unescape
from urllib.parse import urlsplit
from xml.etree import ElementTree

ADAPTER_ID = "burp_scanner_issues_xml"
ADAPTER_VERSION = "1"
MAX_BYTES = 5 * 1024 * 1024
MAX_ISSUES = 500
SEVERITIES = {
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "information": "Informational",
    "informational": "Informational",
}
_TAG = re.compile(r"<[^>]*>")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SENSITIVE_HEADER = re.compile(
    r"(?im)\b(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key)\s*:\s*[^\r\n]+"
)


class BurpImportError(ValueError):
    pass


def _strip_doctype(blob: bytes) -> bytes:
    """Remove Burp's internal DTD without allowing entity declarations."""
    upper = blob.upper()
    if b"<!ENTITY" in upper:
        raise BurpImportError("XML entity declarations are not supported")
    start = upper.find(b"<!DOCTYPE")
    if start < 0:
        return blob
    quote = None
    bracket_depth = 0
    for index in range(start + 9, len(blob)):
        char = blob[index]
        if quote:
            if char == quote:
                quote = None
            continue
        if char in (ord('"'), ord("'")):
            quote = char
        elif char == ord("["):
            bracket_depth += 1
        elif char == ord("]"):
            bracket_depth = max(0, bracket_depth - 1)
        elif char == ord(">") and bracket_depth == 0:
            return blob[:start] + blob[index + 1 :]
    raise BurpImportError("Malformed XML document type declaration")


def _text(node: ElementTree.Element, name: str, limit: int = 12000) -> str:
    child = node.find(name)
    if child is None:
        return ""
    value = "".join(child.itertext())
    value = unescape(_TAG.sub(" ", value))
    value = _CONTROL.sub("", value)
    value = _SENSITIVE_HEADER.sub("[REDACTED HEADER]", value)
    return " ".join(value.split())[:limit]


def _host_and_path(issue: ElementTree.Element) -> tuple[str, str]:
    host = _text(issue, "host", 2048).strip()
    raw_path = _text(issue, "path", 4096).strip()
    if host.startswith(("http://", "https://")):
        parsed_host = urlsplit(host)
        if parsed_host.username or parsed_host.password or not parsed_host.hostname:
            raise BurpImportError("Issue contains an unsafe host URL")
        host = parsed_host.hostname + (f":{parsed_host.port}" if parsed_host.port else "")
    if raw_path.startswith(("http://", "https://")):
        parsed = urlsplit(raw_path)
        if parsed.username or parsed.password or not parsed.hostname:
            raise BurpImportError("Issue contains an unsafe URL")
        host = parsed.hostname
        if parsed.port:
            host = f"{host}:{parsed.port}"
        raw_path = parsed.path or "/"
    elif "@" in host or "/" in host or "?" in host:
        raise BurpImportError("Issue contains an invalid host")
    # Ignore query strings and fragments: they may contain secrets or identifiers.
    path = raw_path.split("?", 1)[0].split("#", 1)[0] or "/"
    if not path.startswith("/"):
        path = "/" + path
    return host[:255], path[:1000]


def _request_method(issue: ElementTree.Element) -> str | None:
    request = issue.find("request")
    if request is None or not request.text:
        return None
    raw = request.text.strip()
    try:
        message = base64.b64decode(raw, validate=True)[:4096]
    except (ValueError, base64.binascii.Error):
        message = raw.encode("utf-8", "ignore")[:4096]
    first_line = message.splitlines()[0].decode("ascii", "ignore") if message else ""
    match = re.match(r"^([A-Z]{3,10})\s+\S+\s+HTTP/\d(?:\.\d)?$", first_line)
    return match.group(1) if match else None


def parse_burp_scanner_xml(blob: bytes) -> list[dict]:
    if not blob or len(blob) > MAX_BYTES:
        raise BurpImportError("Burp XML must be non-empty and no larger than 5 MiB")
    try:
        root = ElementTree.fromstring(_strip_doctype(blob))
    except (ElementTree.ParseError, UnicodeDecodeError) as exc:
        raise BurpImportError("File is not a valid supported Burp Scanner XML export") from exc
    if root.tag != "issues":
        raise BurpImportError("Expected a Burp Scanner issues XML export")
    nodes = root.findall("issue")
    if len(nodes) > MAX_ISSUES:
        raise BurpImportError("Burp XML exceeds the 500 issue limit")
    results = []
    for node in nodes:
        severity = SEVERITIES.get(_text(node, "severity", 40).lower())
        name = _text(node, "name", 300)
        issue_type = _text(node, "type", 100)
        if not severity or not name:
            continue
        host, path = _host_and_path(node)
        results.append({
            "burp_version": " ".join((root.attrib.get("burpVersion") or "").split())[:100],
            "external_id": _text(node, "serialNumber", 100),
            "issue_type": issue_type,
            "name": name,
            "severity": severity,
            "external_severity": _text(node, "severity", 40),
            "external_confidence": _text(node, "confidence", 40),
            "host": host,
            "path": path,
            "method": _request_method(node),
            "description": _text(node, "issueBackground"),
            "detail": _text(node, "issueDetail"),
            "remediation": " ".join(filter(None, (
                _text(node, "remediationBackground"),
                _text(node, "remediationDetail"),
            )))[:12000],
        })
    return results
