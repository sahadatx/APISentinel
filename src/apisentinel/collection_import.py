"""Bounded passive import of Postman Collection v2.1 request metadata.

Request values and bodies are discarded; imports create endpoint inventory only.
"""

from __future__ import annotations

import re

from collections.abc import Mapping

from urllib.parse import parse_qsl, urlsplit

from fastapi import HTTPException

from .discovery import KNOWN_METHODS, _safe_text, _validate_path

MAX_ITEMS = 2_000

MAX_DEPTH = 32

_SENSITIVE = ("authorization", "proxy-authorization", "cookie", "set-cookie", "api-key", "apikey", "token", "secret", "password")

def _bad(message: str):
    raise HTTPException(422, message)

def _url(value: object) -> tuple[str, str, list[dict]]:
    if isinstance(value, dict):
        value = value.get("raw")
    if not isinstance(value, str) or not value or len(value) > 8192 or "{{" in value or "}}" in value:
        _bad("Imported request URL must be a resolved absolute URL")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        _bad("Imported request URL is malformed")
    if (parsed.scheme.lower() not in {"http", "https"} or not hostname
            or parsed.username is not None or parsed.password is not None):
        _bad("Imported request URL must use HTTP(S), include a host, and contain no user information")
    if parsed.fragment:
        _bad("Imported request URLs cannot include fragments")
    try:
        hostname = hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        _bad("Imported request hostname is malformed")
    if ":" in hostname:
        hostpart = f"[{hostname}]"
    else:
        hostpart = hostname
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    authority = hostpart if port is None or port == default_port else f"{hostpart}:{port}"
    path = parsed.path or "/"
    _validate_path(path)
    parameters = []
    seen = set()
    try:
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=200)
    except ValueError:
        _bad("Imported request URL contains too many query parameters")
    for name, _value in query_pairs:
        if name not in seen:
            parameters.append({"name": _safe_text(name, 200), "in": "query", "required": False,
                               "schema": {"type": "string"}})
            seen.add(name)
    return f"{parsed.scheme.lower()}://{authority}", path, parameters

def _auth_metadata(headers: object, auth_hint: object) -> list[dict]:
    detected: dict[str, dict] = {}
    hinted_type = auth_hint.get("type") if isinstance(auth_hint, dict) else auth_hint
    hinted_type = str(hinted_type).lower() if isinstance(hinted_type, str) else ""
    if hinted_type in {"bearer", "basic"}:
        detected[hinted_type] = {"id": f"imported_{hinted_type}",
                                 "definition": {"type": "http", "scheme": hinted_type}}
    elif hinted_type in {"apikey", "api_key"}:
        params = auth_hint.get("apikey", auth_hint.get("apiKey", [])) if isinstance(auth_hint, dict) else []
        values = {str(row.get("key", "")).lower(): row.get("value") for row in params if isinstance(row, dict)} if isinstance(params, list) else {}
        name = values.get("key")
        location = values.get("in", "header")
        if isinstance(name, str) and name and location in {"header", "query", "cookie"}:
            safe_name = name[:200]
            ident = re.sub(r"[^a-z0-9]+", "_", safe_name.lower()).strip("_")[:80] or "key"
            detected[f"{location}:{safe_name.lower()}"] = {
                "id": f"imported_{location}_{ident}",
                "definition": {"type": "apiKey", "in": location, "name": safe_name},
            }
    elif hinted_type in {"cookie", "cookies"}:
        detected["cookie"] = {"id": "imported_cookie",
                              "definition": {"type": "apiKey", "in": "cookie", "name": "session"}}

    if isinstance(headers, Mapping):
        pairs = [(str(name), str(value)) for name, value in list(headers.items())[:200]]
    elif isinstance(headers, list):
        pairs = [(str(header.get("key", header.get("name", ""))), str(header.get("value", "")))
                 for header in headers[:200] if isinstance(header, dict)]
    else:
        pairs = []
    for name, value in pairs:
        lowered = name.lower()
        if lowered == "authorization":
            scheme = "basic" if value.lower().startswith("basic ") else "bearer" if value.lower().startswith("bearer ") else ""
            if scheme:
                detected[scheme] = {"id": f"imported_{scheme}",
                                    "definition": {"type": "http", "scheme": scheme}}
            else:
                detected["unknown_authorization"] = {"id": "imported_authorization_metadata",
                    "definition": {"type": "apiKey", "in": "header", "name": "Authorization"}}
        elif lowered in {"cookie", "set-cookie"}:
            cookie_names = {part.split("=", 1)[0].strip() for part in value.split(";") if "=" in part}
            for cookie_name in cookie_names or {"session"}:
                ident = re.sub(r"[^a-z0-9]+", "_", cookie_name.lower()).strip("_")[:80] or "session"
                detected[f"cookie:{cookie_name.lower()}"] = {"id": f"imported_cookie_{ident}",
                    "definition": {"type": "apiKey", "in": "cookie", "name": cookie_name[:200]}}
        elif any(part in lowered for part in _SENSITIVE):
            safe_name = name[:200]
            ident = re.sub(r"[^a-z0-9]+", "_", safe_name.lower()).strip("_")[:80] or "key"
            detected[f"header:{safe_name.lower()}"] = {"id": f"imported_header_{ident}",
                "definition": {"type": "apiKey", "in": "header", "name": safe_name}}
    return list(detected.values())

def _insert(operations: dict, method: object, url: object, headers: object, auth_hint: object, summary: str):
    if not isinstance(method, str):
        _bad("Imported HTTP method must be a string")
    method = method.upper()
    if method not in KNOWN_METHODS:
        _bad("Imported collection contains an unsupported HTTP method")
    server, path, params = _url(url)
    key = (path, method.lower())
    operation = operations.setdefault(key, {"summary": _safe_text(summary, 200) or "Imported request",
        "operationId": f"import_{len(operations) + 1}", "servers": [], "parameters": [], "responses": {"default": {"description": "Imported traffic inventory"}}})
    if server not in [item["url"] for item in operation["servers"]]:
        operation["servers"].append({"url": server})
    known = {item["name"] for item in operation["parameters"]}
    operation["parameters"].extend(item for item in params if item["name"] not in known)
    auth = _auth_metadata(headers, auth_hint)
    if auth:
        operation["x-apisentinel-auth-schemes"] = auth
        operation["security"] = [{item["id"]: []} for item in auth]

def _postman_items(items: object, operations: dict, depth: int = 0, counter: list[int] | None = None) -> None:
    counter = counter if counter is not None else [0]
    if depth > MAX_DEPTH or not isinstance(items, list):
        _bad("Postman collection nesting or item structure is invalid")
    counter[0] += len(items)
    if counter[0] > MAX_ITEMS:
        _bad("Collection exceeds the endpoint limit")
    for item in items:
        if not isinstance(item, dict):
            _bad("Postman collection item must be an object")
        if "item" in item:
            _postman_items(item["item"], operations, depth + 1, counter)
            continue
        request = item.get("request")
        if not isinstance(request, dict):
            _bad("Postman collection request entry is malformed")
        _insert(operations, request.get("method", "GET"), request.get("url"), request.get("header"),
                request.get("auth", {}), "")

def postman_to_openapi(document: dict) -> dict:
    info = document.get("info")
    if not isinstance(info, dict) or not str(info.get("schema", "")).endswith("/collection/v2.1.0/collection.json"):
        _bad("Only Postman Collection v2.1 JSON is supported")
    operations: dict[tuple[str, str], dict] = {}
    _postman_items(document.get("item"), operations)
    return _to_openapi(operations, "Postman collection")

def _to_openapi(operations: dict, title: str) -> dict:
    if not operations:
        _bad("Import contains no HTTP requests")
    if len(operations) > MAX_ITEMS:
        _bad("Collection exceeds the endpoint limit")
    paths: dict[str, dict] = {}
    security_schemes = {}
    for (path, method), operation in operations.items():
        paths.setdefault(path, {})[method] = operation
        for item in operation.get("x-apisentinel-auth-schemes", []):
            security_schemes[item["id"]] = item["definition"]
    return {"openapi": "3.0.3", "info": {"title": title, "version": "imported"}, "paths": paths,
            "components": {"securitySchemes": security_schemes}}
