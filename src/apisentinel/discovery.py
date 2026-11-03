"""Bounded, deterministic, network-free import of the supported OpenAPI subset."""
from __future__ import annotations

import hashlib
import json
import re
from fnmatch import fnmatch
from urllib.parse import urlsplit

from fastapi import HTTPException
from sqlalchemy.orm import Session

from . import models
from .config import settings

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
KNOWN_METHODS = {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "TRACE"}
_PARAMETER = re.compile(r"\{([A-Za-z0-9_.-]+)\}")
_BAD_ESCAPE = re.compile(r"%(?![0-9a-fA-F]{2})")
_ENCODED_PATH_CONTROL = re.compile(r"%(?:2f|2F|5c|5C|2e|2E)")
_SENSITIVE_TEXT = re.compile(r"(?i)(\b(?:bearer\s+|[A-Za-z0-9_.-]*(?:api[_-]?key|access[_-]?token|refresh[_-]?token|password|secret|token)[A-Za-z0-9_.-]*\s*[:=]\s*[\"']?))[A-Za-z0-9._~+/=-]{4,}")


def _fail(message: str) -> None:
    raise HTTPException(422, message)


def _reject_duplicate_json_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_json_constant(_value):
    raise ValueError("invalid JSON number")


def _check_json_nesting(raw: bytes, max_depth: int = 128) -> None:
    depth = 0
    in_string = escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte in (0x7B, 0x5B):
            depth += 1
            if depth > max_depth:
                raise HTTPException(422, "Request JSON nesting exceeds the supported parser depth")
        elif byte in (0x7D, 0x5D):
            depth -= 1


def parse_import_envelope(raw: bytes, max_bytes: int) -> dict:
    """Parse only after the request body has been streamed under the configured cap."""
    if len(raw) > max_bytes:
        raise HTTPException(413, "OpenAPI document exceeds the configured size limit")
    try:
        _check_json_nesting(raw)
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_json_keys,
                           parse_constant=_reject_json_constant)
    except RecursionError:
        raise HTTPException(422, "Request JSON nesting exceeds the supported parser depth") from None
    except (ValueError, UnicodeDecodeError):
        raise HTTPException(422, "Request must contain valid JSON without duplicate object keys") from None
    if not isinstance(value, dict):
        raise HTTPException(422, "Import request must be a JSON object")
    return value


def _canonical_hash(value: object) -> str:
    try:
        canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError):
        _fail("OpenAPI document contains a value that cannot be represented as valid JSON")
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _artifact_metadata(spec: dict) -> dict:
    """Retain only bounded, non-secret Android/browser attribution fields."""
    info = spec.get("info", {})
    if not isinstance(info, dict):
        return {}
    output = {}
    app = info.get("x-apisentinel-app")
    if isinstance(app, dict):
        package = app.get("package_name")
        version = app.get("version_name")
        if (isinstance(package, str) and re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+", package)
                and isinstance(version, str)):
            output["android_app"] = {"package_name": package[:255], "version_name": _safe_text(version, 100)}
    origins = info.get("x-apisentinel-browser-origins")
    if isinstance(origins, list):
        safe_origins = set()
        for origin in origins[:100]:
            if not isinstance(origin, str) or len(origin) > 500:
                continue
            try:
                parsed = urlsplit(origin)
                if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None
                        or parsed.password is not None or parsed.path not in {"", "/"}
                        or parsed.query or parsed.fragment):
                    continue
                host = _normalized_host(parsed.hostname)
                port = parsed.port
                default_port = 443 if parsed.scheme == "https" else 80
                authority = f"[{host}]" if ":" in host else host
                if port not in {None, default_port}:
                    authority += f":{port}"
                safe_origins.add(f"{parsed.scheme}://{authority}")
            except (UnicodeError, ValueError):
                continue
        output["browser_origins"] = sorted(safe_origins)
    return output


def _safe_text(value: str, max_length: int) -> str:
    return _SENSITIVE_TEXT.sub(r"\1[REDACTED]", value)[:max_length]


def _reference_material(value, root: dict, seen: frozenset[str] = frozenset()):
    """Resolve local references into the definition fingerprint, never over the network."""
    refs = {}
    if isinstance(value, dict):
        ref = value.get("$ref")
        if ref is not None and ref not in seen:
            target = _pointer(root, ref)
            refs[ref] = _reference_material(target, root, seen | {ref})
        for child in value.values():
            refs.update(_reference_material(child, root, seen))
    elif isinstance(value, list):
        for child in value:
            refs.update(_reference_material(child, root, seen))
    return refs


def _pointer(root: dict, ref: str):
    if not isinstance(ref, str) or not ref.startswith("#/"):
        _fail("Only local OpenAPI references are supported; remote references are never fetched")
    current = root
    for raw_part in ref[2:].split("/"):
        if re.search(r"~(?![01])", raw_part):
            _fail("OpenAPI document contains a malformed local reference")
        part = raw_part.replace("~1", "/").replace("~0", "~")
        try:
            current = current[part]
        except (KeyError, TypeError):
            _fail("OpenAPI document contains an unresolved local reference")
    return current


def _validate_refs(value, root: dict, depth: int = 0):
    if depth > 64:
        _fail("OpenAPI reference nesting exceeds the supported limit")
    if isinstance(value, dict):
        ref = value.get("$ref")
        if ref is not None:
            _pointer(root, ref)
        for child in value.values():
            _validate_refs(child, root, depth + 1)
    elif isinstance(value, list):
        for child in value:
            _validate_refs(child, root, depth + 1)


def _resolve_object(value, root: dict, label: str) -> dict:
    seen = set()
    while isinstance(value, dict) and "$ref" in value:
        ref = value["$ref"]
        if ref in seen:
            _fail(f"OpenAPI {label} reference contains a cycle")
        seen.add(ref)
        value = _pointer(root, ref)
        if len(seen) > 16:
            _fail(f"OpenAPI {label} reference nesting exceeds the supported limit")
    if not isinstance(value, dict):
        _fail(f"OpenAPI {label} reference must resolve to an object")
    return value


def _safe_schema(value, root: dict, depth: int = 0, seen: frozenset[str] = frozenset()):
    """Retain schema structure while omitting examples/defaults that may contain secrets."""
    if depth > 24:
        return {"truncated": True}
    if isinstance(value, list):
        return [_safe_schema(item, root, depth + 1, seen) for item in value[:200]]
    if not isinstance(value, dict):
        return value if isinstance(value, (str, int, float, bool)) or value is None else None
    ref = value.get("$ref")
    if ref is not None:
        _pointer(root, ref)
        if ref in seen:
            return {"$ref": ref, "recursive": True}
        target = _pointer(root, ref)
        return {"$ref": ref, "resolved": _safe_schema(target, root, depth + 1, seen | {ref})}
    allowed = {
        "$schema", "type", "format", "title", "description", "required", "items", "properties",
        "additionalProperties", "oneOf", "anyOf", "allOf", "not", "nullable", "readOnly",
        "writeOnly", "minLength", "maxLength", "minimum", "maximum", "pattern", "minItems",
        "maxItems", "uniqueItems", "contentEncoding", "contentMediaType",
    }
    output = {}
    for key in sorted(allowed & value.keys()):
        child = value[key]
        if key == "properties" and isinstance(child, dict):
            output[key] = {
                _safe_text(str(name), 200): _safe_schema(schema, root, depth + 1, seen)
                for name, schema in sorted(child.items(), key=lambda item: str(item[0]))[:200]
            }
        elif key in {"title", "description", "format", "pattern"} and isinstance(child, str):
            output[key] = _safe_text(child, 1000)
        else:
            output[key] = _safe_schema(child, root, depth + 1, seen) if isinstance(child, (dict, list)) else child
    return output


def _validate_path(path: object) -> str:
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
        _fail("OpenAPI paths must be absolute path templates beginning with one slash")
    if len(path) > 1000 or "\\" in path or "?" in path or "#" in path:
        _fail("OpenAPI path is malformed or exceeds the supported length")
    if _BAD_ESCAPE.search(path) or _ENCODED_PATH_CONTROL.search(path) or "%" in path:
        _fail("Percent-encoded OpenAPI paths are unsupported to prevent path normalization bypasses")
    if any(ord(char) < 32 or ord(char) == 127 for char in path):
        _fail("OpenAPI path contains control characters")
    if any(part in {".", ".."} for part in path.split("/")):
        _fail("OpenAPI path traversal segments are not permitted")
    stripped = _PARAMETER.sub("", path)
    if "{" in stripped or "}" in stripped:
        _fail("OpenAPI path parameter template is malformed")
    return path


def _normalized_template(path: str) -> str:
    return _PARAMETER.sub("{}", path)


def _normalized_host(host: str) -> str:
    return host.rstrip(".").encode("idna").decode("ascii").lower()


def _host_in_scope(host: str, allowed_hosts: list) -> bool:
    normalized = _normalized_host(host)
    return any(normalized == _normalized_host(str(allowed)) or normalized.endswith("." + _normalized_host(str(allowed))) for allowed in allowed_hosts)


def _path_in_scope(path: str, assessment: models.Assessment) -> bool:
    allowed = assessment.allowed_paths or ["/**"]
    if not any(fnmatch(path, pattern) or (pattern.endswith("/**") and path.startswith(pattern[:-3])) for pattern in allowed):
        return False
    return not any(fnmatch(path, pattern) for pattern in (assessment.excluded_paths or []))


def _server_details(url: str, assessment: models.Assessment):
    """Return usable base path only for a single syntactically valid in-scope server."""
    try:
        parsed = urlsplit(url)
    except ValueError:
        _fail("OpenAPI server URL is malformed")
    if not parsed.scheme or not parsed.hostname or parsed.username is not None or parsed.password is not None:
        _fail("OpenAPI server entries must be absolute URLs without user information")
    scheme = parsed.scheme.lower()
    try:
        host = _normalized_host(parsed.hostname)
    except (UnicodeError, ValueError):
        _fail("OpenAPI server hostname is malformed")
    try:
        port = parsed.port or (443 if scheme == "https" else 80 if scheme == "http" else -1)
    except ValueError:
        _fail("OpenAPI server entry contains an invalid port")
    if parsed.query or parsed.fragment:
        _fail("OpenAPI server URLs cannot contain a query or fragment")
    if "{" in url or "}" in url:
        return "", "Server URL variables require manual review"
    local_lab = bool(settings.allow_local_lab and assessment.environment.lower() in {"development", "lab"})
    permitted_scheme = scheme == "https" or (scheme == "http" and local_lab and settings.runner_lab_allow_http)
    permitted_port = port == 443 or (local_lab and port in settings.lab_allowed_ports)
    if not permitted_scheme:
        return "", "Server scheme is not permitted by current assessment policy"
    if not permitted_port:
        return "", "Server port is not permitted by current assessment policy"
    if not _host_in_scope(host, assessment.allowed_hosts or []):
        return "", "Server host is outside the assessment's approved host scope"
    base_path = parsed.path or ""
    if base_path:
        _validate_path(base_path.rstrip("/") or "/")
        if not _path_in_scope(base_path.rstrip("/"), assessment):
            return "", "Server base path is outside the assessment's approved path scope"
    return base_path.rstrip("/"), ""


def _effective_servers(spec: dict, path_item: dict, operation: dict):
    if "servers" in operation:
        return operation["servers"]
    if "servers" in path_item:
        return path_item["servers"]
    return spec.get("servers", [])


def _params(path_item: dict, operation: dict, root: dict) -> list[dict]:
    merged = {}
    for level, items in (("path", path_item.get("parameters", []) or []), ("operation", operation.get("parameters", []) or [])):
        seen = set()
        if not isinstance(items, list):
            _fail("OpenAPI parameters must be a list")
        for item in items:
            item = _resolve_object(item, root, "parameter")
            location = item.get("in")
            name = item.get("name")
            if location not in {"path", "query", "header", "cookie"} or not isinstance(name, str) or not name:
                _fail("OpenAPI parameter must have a name and supported location")
            key = (name, location)
            if key in seen:
                _fail("OpenAPI parameter is duplicated at the same path or operation level")
            seen.add(key)
            schema = item.get("schema", {})
            merged[key] = {
            "name": _safe_text(name, 200),
                "in": location,
                "required": bool(item.get("required", False) or location == "path"),
                "schema": _safe_schema(schema, root),
            }
    return [merged[key] for key in sorted(merged)]


def _request_body(operation: dict, root: dict) -> dict:
    if "requestBody" not in operation:
        return {}
    body = _resolve_object(operation["requestBody"], root, "requestBody")
    content = body.get("content", {})
    if not isinstance(content, dict):
        _fail("OpenAPI requestBody content must be an object")
    if any(not isinstance(value, dict) for value in content.values()):
        _fail("Each OpenAPI requestBody media type must map to an object")
    return {
        "required": bool(body.get("required", False)),
        "content": {
            _safe_text(media, 200): {"schema": _safe_schema(media_value.get("schema", {}), root)}
            for media, media_value in sorted(content.items())
            if isinstance(media_value, dict)
        },
    }


def _response_metadata(operation: dict, root: dict) -> tuple[dict, list[str]]:
    responses = operation.get("responses", {}) or {}
    if not isinstance(responses, dict):
        _fail("OpenAPI responses must be an object")
    schemas = {}
    content_types = set()
    for status, response_value in sorted(responses.items(), key=lambda item: str(item[0]))[:100]:
        response = _resolve_object(response_value, root, "response")
        content = response.get("content", {}) or {}
        if not isinstance(content, dict):
            _fail("OpenAPI response content must be an object")
        for media, media_value in sorted(content.items()):
            if not isinstance(media_value, dict):
                _fail("OpenAPI response media entries must be objects")
            content_types.add(_safe_text(str(media), 200))
            if "schema" in media_value:
                schemas[f"{str(status)[:40]}:{_safe_text(str(media), 200)}"] = _safe_schema(media_value["schema"], root)
    return schemas, sorted(content_types)[:100]


def _operations(spec: dict, assessment: models.Assessment) -> tuple[list[dict], list[str]]:
    if not isinstance(spec, dict):
        _fail("OpenAPI document must be a JSON object")
    version = spec.get("openapi")
    if not isinstance(version, str) or not re.fullmatch(r"3\.[01]\.\d+(?:[-+][A-Za-z0-9.-]+)?", version):
        _fail("Supported OpenAPI versions are 3.0.x and 3.1.x; Swagger 2.x is not supported")
    info = spec.get("info")
    paths = spec.get("paths")
    if not isinstance(info, dict) or not isinstance(info.get("title"), str) or not isinstance(paths, dict):
        _fail("OpenAPI document requires an info.title and paths object")
    components = spec.get("components", {})
    if not isinstance(components, dict) or not isinstance(components.get("securitySchemes", {}), dict):
        _fail("OpenAPI components and securitySchemes must be objects")
    security_schemes = components.get("securitySchemes", {})
    _validate_refs(spec, spec)
    root_servers = spec.get("servers", [])
    if not isinstance(root_servers, list) or len(root_servers) > 50:
        _fail("OpenAPI servers must be a list with at most 50 entries")
    root_urls = []
    for server in root_servers:
        if not isinstance(server, dict) or not isinstance(server.get("url"), str) or not server["url"]:
            _fail("Each OpenAPI server entry must contain a URL string")
        # Parsing here catches malformed ports and characters; no network access occurs.
        _server_details(server["url"], assessment)
        root_urls.append(server["url"])

    parsed_ops = []
    issues = []
    normalized_paths = {}
    operation_ids = set()
    for path in sorted(paths):
        _validate_path(path)
        normalized = _normalized_template(path)
        if normalized in normalized_paths and normalized_paths[normalized] != path:
            _fail("OpenAPI document contains conflicting path templates")
        normalized_paths[normalized] = path
        path_item = paths[path]
        if not isinstance(path_item, dict):
            _fail("OpenAPI path entries must be objects")
        path_item = _resolve_object(path_item, spec, "path item")
        for method_raw, operation in sorted(path_item.items()):
            method = method_raw.upper()
            if method not in KNOWN_METHODS:
                continue
            if not isinstance(operation, dict):
                _fail("OpenAPI operations must be objects")
            operation_id = operation.get("operationId", "")
            if not isinstance(operation_id, str):
                _fail("OpenAPI operationId values must be strings")
            if operation_id and operation_id in operation_ids:
                _fail("OpenAPI operationId values must be unique")
            if operation_id:
                operation_ids.add(operation_id)
            tags = operation.get("tags", []) or []
            if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
                _fail("OpenAPI operation tags must be a list of strings")
            security = operation.get("security", spec.get("security", []))
            if not isinstance(security, list) or any(not isinstance(item, dict) for item in security):
                _fail("OpenAPI security requirements must be a list of objects")
            for requirement in security:
                if any(not isinstance(name, str) or not isinstance(scopes, list) or any(not isinstance(scope, str) for scope in scopes)
                       for name, scopes in requirement.items()):
                    _fail("OpenAPI security requirements must map scheme names to scope lists")
                if any(name not in security_schemes for name in requirement):
                    _fail("OpenAPI security requirement references an undefined security scheme")
            parameters = _params(path_item, operation, spec)
            server_issues = []
            placeholders = set(_PARAMETER.findall(path))
            declared = {item["name"] for item in parameters if item["in"] == "path"}
            if placeholders != declared:
                _fail("OpenAPI path parameters must match the path template")
            if placeholders:
                server_issues.append("Required path parameters cannot be populated by the current HTTP request mode")
            servers = _effective_servers(spec, path_item, operation)
            if not isinstance(servers, list) or len(servers) > 50:
                _fail("Operation servers must be a list with at most 50 entries")
            server_base_path = ""
            scope_issues = []
            scope_excluded = False
            if len(servers) > 1:
                server_issues.append("Multiple server declarations require explicit analyst review")
            validated_servers = []
            for server in servers:
                if not isinstance(server, dict) or not isinstance(server.get("url"), str) or not server["url"]:
                    _fail("Each OpenAPI server entry must contain a URL string")
                base, issue = _server_details(server["url"], assessment)
                validated_servers.append(server["url"])
                if issue:
                    server_issues.append(issue)
                    scope_issues.append(issue)
                elif len(servers) == 1:
                    composed = (base + path) if base else path
                    scope_excluded = any(fnmatch(composed, pattern) for pattern in (assessment.excluded_paths or []))
                    if scope_excluded:
                        server_issues.append("Endpoint path matches an explicit assessment exclusion")
                    elif not any(fnmatch(composed, pattern) or (pattern.endswith("/**") and composed.startswith(pattern[:-3]))
                                 for pattern in (assessment.allowed_paths or ["/**"])):
                        issue = "Composed server base path and endpoint are outside approved path scope"
                        server_issues.append(issue)
                        scope_issues.append(issue)
                    else:
                        server_base_path = base
            if method not in SAFE_METHODS:
                server_issues.append(f"HTTP method {method} is inventory-only and cannot execute in this release")
            summary = operation.get("summary", "")
            if not isinstance(summary, str):
                summary = ""
            description = operation.get("description", "")
            if not isinstance(description, str):
                description = ""
            response_schemas, content_types = _response_metadata(operation, spec)
            request_body = _request_body(operation, spec)
            content_types = sorted(set(content_types) | set(request_body.get("content", {})))[:100]
            server_origin = ""
            if len(servers) == 1 and isinstance(servers[0], dict):
                try:
                    parsed_server = urlsplit(servers[0]["url"])
                    host = _normalized_host(parsed_server.hostname or "")
                    port = parsed_server.port
                    authority = f"[{host}]" if ":" in host else host
                    if port and port != (443 if parsed_server.scheme.lower() == "https" else 80):
                        authority += f":{port}"
                    server_origin = f"{parsed_server.scheme.lower()}://{authority}"
                except (ValueError, UnicodeError):
                    server_origin = ""
            if not servers:
                scope_status, scope_reason = "UNRESOLVED", "Source does not declare a server; target is not inferred from the import"
            elif len(servers) != 1:
                scope_status, scope_reason = "UNRESOLVED", "Multiple server declarations require analyst scope review"
            elif scope_excluded:
                scope_status, scope_reason = "EXCLUDED", "Endpoint path matches an explicit assessment exclusion"
            elif scope_issues:
                issue = "; ".join(sorted(set(scope_issues)))
                scope_status = "OUT_OF_SCOPE" if any(token in issue.lower() for token in ("outside", "not permitted")) else "UNRESOLVED"
                scope_reason = issue
            else:
                composed_path = (server_base_path + path) if server_base_path else path
                excluded = any(fnmatch(composed_path, pattern) for pattern in (assessment.excluded_paths or []))
                in_paths = any(fnmatch(composed_path, pattern) or (pattern.endswith("/**") and composed_path.startswith(pattern[:-3]))
                               for pattern in (assessment.allowed_paths or ["/**"]))
                scope_status = "EXCLUDED" if excluded else "IN_SCOPE" if in_paths else "OUT_OF_SCOPE"
                scope_reason = "Path matches an explicit exclusion" if excluded else "Path is within approved assessment scope" if in_paths else "Path is outside approved assessment scope"
            used_security_schemes = sorted({name for requirement in security for name in requirement})
            relevant_definition = {
                "path_item": path_item,
                "operation": operation,
                "method": method,
                "path": path,
                "effective_servers": validated_servers,
                "effective_security": security,
                "security_scheme_definitions": {name: security_schemes.get(name) for name in used_security_schemes},
                "resolved_local_references": _reference_material({"path_item": path_item, "operation": operation}, spec),
            }
            parsed_ops.append({
                "method": method, "path": path, "summary": _safe_text(summary, 500), "operation_id": _safe_text(operation_id, 200),
                "parameters": parameters, "tags": sorted({_safe_text(tag, 100) for tag in tags}), "request_body": request_body,
                "security_requirements": security, "auth_required": bool(security),
                "server_base_path": server_base_path, "server_review_issues": sorted(set(server_issues)),
                "definition_hash": _canonical_hash(relevant_definition), "raw_definition": relevant_definition,
                "server_origin": server_origin, "scope_status": scope_status, "scope_reason": scope_reason,
                "api_title": _safe_text(str(info.get("title", "")), 300),
                "api_version": _safe_text(str(info.get("version", "")), 100),
                "description": _safe_text(description, 4000), "deprecated": bool(operation.get("deprecated", False)),
                "response_schemas": response_schemas, "content_types": content_types,
                "review_state": "REJECTED" if method not in SAFE_METHODS or placeholders else ("NEEDS_REVIEW" if server_issues else "IMPORTED"),
            })
            issues.extend(server_issues)
    if not parsed_ops:
        _fail("OpenAPI document contains no supported HTTP operations")
    return parsed_ops, sorted(set(issues))


def import_openapi(db: Session, assessment: models.Assessment, spec: dict, *, analyst_id: int, source: str = "inline_json") -> dict:
    operations, issues = _operations(spec, assessment)
    if source not in {"inline_json", "postman_v2.1", "burp_http_history", "browser_har_1.2", "android_http_capture_v1"}:
        _fail("Supported import sources are OpenAPI JSON, Postman v2.1, structured Burp HTTP history JSON, HAR 1.2, and APISentinel Android HTTP capture v1")
    version = spec["openapi"]
    content_hash = _canonical_hash(spec)
    artifact_metadata = _artifact_metadata(spec)
    root_servers = [_safe_text(entry["url"], 1000) for entry in spec.get("servers", [])]
    document = models.OpenAPIDocument(
        assessment_id=assessment.id, imported_by=analyst_id, source=source, openapi_version=version,
        content_hash=content_hash, artifact_metadata=artifact_metadata,
        server_declarations=root_servers, issues=issues,
    )
    db.add(document)
    db.flush()

    inventory_source = "openapi" if source == "inline_json" else source
    existing = (db.query(models.Endpoint).filter_by(assessment_id=assessment.id, inventory_current=True)
                .order_by(models.Endpoint.id.desc()).all())
    by_key = {}
    for endpoint in existing:
        by_key.setdefault((endpoint.method.upper(), endpoint.path, endpoint.server_origin), []).append(endpoint)
    current_keys = set()
    result_endpoints = []
    added = changed = unchanged = removed = 0
    for operation in operations:
        key = operation["method"], operation["path"], operation["server_origin"]
        current_keys.add(key)
        previous = [row for row in by_key.get(key, []) if row.source == inventory_source]
        equivalent = [row for row in by_key.get(key, []) if row.definition_hash == operation["definition_hash"]]
        matched = next(iter(equivalent), None)
        if matched is not None:
            provenance = list(matched.source_provenance or [])
            record = {"source": source, "import_id": document.id, "artifact_sha256": content_hash,
                      "artifact_metadata": artifact_metadata}
            if record not in provenance:
                provenance.append(record)
            matched.source_provenance = provenance[-100:]
            matched.import_id = document.id
            matched.last_discovered_at = models.now()
            if matched.scope_status != operation["scope_status"] or matched.scope_reason != operation["scope_reason"]:
                prior_scope = matched.scope_status
                matched.scope_status = operation["scope_status"]
                matched.scope_reason = operation["scope_reason"]
                matched.execution_approved = False
                matched.execution_approved_by = None
                matched.execution_approved_at = None
                matched.review_state = "NEEDS_REVIEW"
                matched.review_reason = "Assessment scope changed; endpoint approval requires fresh review"
                db.add(models.ExecutionAuditEvent(
                    actor_id=analyst_id, client_id=assessment.client_id, assessment_id=assessment.id,
                    event_type="ENDPOINT_SCOPE_REVALIDATED", outcome=operation["scope_status"],
                    metadata_json={"endpoint_id": matched.id, "prior_scope_status": prior_scope,
                                   "scope_status": operation["scope_status"], "import_id": document.id},
                ))
            for duplicate in by_key.get(key, []):
                if duplicate.id != matched.id and duplicate.source == inventory_source:
                    duplicate.inventory_current = False
                    duplicate.execution_approved = False
                    duplicate.review_state = "REJECTED"
                    duplicate.review_reason = "Superseded by duplicate inventory record during reconciliation"
            result_endpoints.append(matched)
            unchanged += 1
            continue
        for stale in previous:
            stale.inventory_current = False
            stale.execution_approved = False
            stale.review_state = "REJECTED"
            stale.review_reason = "Definition changed during OpenAPI re-import; prior approval invalidated"
            stale.execution_approved_by = analyst_id
            stale.execution_approved_at = models.now()
            db.add(models.ExecutionAuditEvent(
                actor_id=analyst_id, client_id=assessment.client_id, assessment_id=assessment.id,
                event_type="ENDPOINT_REVIEW_INVALIDATED", outcome="REJECTED",
                metadata_json={"endpoint_id": stale.id, "old_definition_hash": stale.definition_hash,
                               "new_definition_hash": operation["definition_hash"], "import_id": document.id},
            ))
        row = models.Endpoint(
            assessment_id=assessment.id, import_id=document.id, definition_hash=operation["definition_hash"],
            inventory_current=True, review_state=operation["review_state"],
            method=operation["method"], path=operation["path"], summary=operation["summary"],
            operation_id=operation["operation_id"], parameters=operation["parameters"], tags=operation["tags"],
            request_body=operation["request_body"], security_requirements=operation["security_requirements"],
            auth_required=operation["auth_required"], source=inventory_source, server_base_path=operation["server_base_path"],
            server_origin=operation["server_origin"], scope_status=operation["scope_status"],
            scope_reason=operation["scope_reason"], api_title=operation["api_title"], api_version=operation["api_version"],
            description=operation["description"], deprecated=operation["deprecated"],
            response_schemas=operation["response_schemas"], content_types=operation["content_types"],
            source_provenance=[{"source": source, "import_id": document.id,
                                "artifact_sha256": content_hash, "artifact_metadata": artifact_metadata}],
            server_review_issues=operation["server_review_issues"], execution_approved=False,
            review_reason="; ".join(operation["server_review_issues"]),
        )
        db.add(row)
        db.flush()
        result_endpoints.append(row)
        if previous:
            changed += 1
        else:
            added += 1

    for key, old_rows in by_key.items():
        if key not in current_keys:
            for stale in (row for row in old_rows if row.source == inventory_source):
                stale.inventory_current = False
                stale.execution_approved = False
                stale.review_state = "REJECTED"
                stale.review_reason = "Definition removed during OpenAPI re-import"
                stale.execution_approved_by = analyst_id
                stale.execution_approved_at = models.now()
                db.add(models.ExecutionAuditEvent(
                    actor_id=analyst_id, client_id=assessment.client_id, assessment_id=assessment.id,
                    event_type="ENDPOINT_REVIEW_INVALIDATED", outcome="REJECTED",
                    metadata_json={"endpoint_id": stale.id, "old_definition_hash": stale.definition_hash,
                                   "reason": "removed", "import_id": document.id},
                ))
                removed += 1

    document.endpoint_ids = [endpoint.id for endpoint in result_endpoints]
    document.change_summary = {"added": added, "changed": changed, "unchanged": unchanged, "removed": removed}
    db.add(models.ExecutionAuditEvent(
        actor_id=analyst_id, client_id=assessment.client_id, assessment_id=assessment.id,
        event_type={"inline_json": "OPENAPI_IMPORT_CREATED", "postman_v2.1": "POSTMAN_IMPORT_CREATED",
                    "burp_http_history": "BURP_IMPORT_CREATED", "browser_har_1.2": "HAR_IMPORT_CREATED",
                    "android_http_capture_v1": "ANDROID_TRAFFIC_IMPORT_CREATED"}[source], outcome="IMPORTED",
        metadata_json={"import_id": document.id, "content_hash": content_hash,
                       "openapi_version": version, "source": source, "change_summary": document.change_summary,
                       "issue_count": len(issues)},
    ))
    db.commit()
    db.refresh(document)
    for endpoint in result_endpoints:
        db.refresh(endpoint)
    scope_counts = {}
    for endpoint in result_endpoints:
        scope_counts[endpoint.scope_status] = scope_counts.get(endpoint.scope_status, 0) + 1
    return {"import_id": document.id, "version_id": content_hash, "content_hash": content_hash,
            "openapi_version": version, "source": source, "issues": issues,
            "change_summary": document.change_summary,
            "summary": {"raw_candidates": len(operations), "unique_endpoints": len(result_endpoints),
                        "deduplicated": unchanged, "rejected": sum(e.review_state == "REJECTED" for e in result_endpoints),
                        "unresolved": scope_counts.get("UNRESOLVED", 0),
                        "out_of_scope": scope_counts.get("OUT_OF_SCOPE", 0),
                        "excluded": scope_counts.get("EXCLUDED", 0), "by_scope_status": scope_counts,
                        "import_warnings": len(issues)},
            "endpoints": result_endpoints}
