"""Pure, side-effect-free construction of approved HTTP requests."""
from __future__ import annotations

import re
from urllib.parse import quote, urlencode, urlsplit, urlunsplit

_TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_FORBIDDEN_HEADERS = {"host", "authorization", "proxy-authorization", "cookie", "set-cookie", "connection", "content-length", "transfer-encoding", "proxy-connection"}


class RequestBuildError(ValueError):
    """A supplied parameter does not match the reviewed endpoint contract."""


def _scalar(value: object, schema: dict, name: str) -> str:
    if isinstance(value, bool):
        text = "true" if value else "false"
        kind = "boolean"
    elif isinstance(value, (str, int, float)):
        text, kind = str(value), "integer" if isinstance(value, int) else "number" if isinstance(value, float) else "string"
    else:
        raise RequestBuildError(f"Parameter {name} must be a scalar value")
    expected = schema.get("type")
    if expected and expected not in {kind, "number" if kind == "integer" else kind}:
        raise RequestBuildError(f"Parameter {name} has the wrong value type")
    if len(text) > 4096 or any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        raise RequestBuildError(f"Parameter {name} contains invalid or oversized data")
    if "enum" in schema and text not in {str(x) for x in schema["enum"]}:
        raise RequestBuildError(f"Parameter {name} is outside the allowed values")
    return text


def build_request(endpoint, base_url: str, *, path_parameters: dict | None = None,
                  query_parameters: dict | None = None, header_parameters: dict | None = None) -> tuple[str, dict[str, str]]:
    """Build an URL and safe caller headers; this function never opens a connection."""
    if endpoint.method.upper() not in {"GET", "HEAD", "OPTIONS"}:
        raise RequestBuildError("Only GET, HEAD, and OPTIONS can be queued")
    supplied = {"path": path_parameters or {}, "query": query_parameters or {}, "header": header_parameters or {}}
    declarations = {loc: {} for loc in supplied}
    for parameter in endpoint.parameters or []:
        loc = parameter.get("in")
        if loc in declarations:
            declarations[loc][parameter.get("name")] = parameter
    for loc, values in supplied.items():
        if not isinstance(values, dict):
            raise RequestBuildError(f"{loc} parameters must be an object")
        unknown = set(values) - declarations[loc].keys()
        if unknown:
            raise RequestBuildError(f"Undeclared {loc} parameter supplied")
    parts = urlsplit(base_url)
    path = parts.path
    placeholders = re.findall(r"\{([^{}]+)\}", path)
    if set(placeholders) != set(supplied["path"]):
        missing = set(placeholders) - supplied["path"].keys()
        if missing or set(supplied["path"]) - set(placeholders):
            raise RequestBuildError("Path parameters do not match the endpoint template")
    for name in placeholders:
        value = _scalar(supplied["path"][name], declarations["path"][name].get("schema", {}), name)
        if value in {".", ".."} or any(ch in value for ch in "/\\%"):
            raise RequestBuildError(f"Path parameter {name} contains an ambiguous path separator")
        path = path.replace("{" + name + "}", quote(value, safe=""))
    query = []
    for name, definition in declarations["query"].items():
        if name not in supplied["query"]:
            if definition.get("required"):
                raise RequestBuildError(f"Required query parameter {name} is missing")
            continue
        raw = supplied["query"][name]
        values = raw if isinstance(raw, list) else [raw]
        if not values or len(values) > 100:
            raise RequestBuildError(f"Query parameter {name} has too many values")
        schema = definition.get("schema", {})
        item_schema = schema.get("items", {}) if schema.get("type") == "array" else schema
        query.extend((name, _scalar(value, item_schema, name)) for value in values)
    headers = {}
    for name, definition in declarations["header"].items():
        if name not in supplied["header"]:
            if definition.get("required"):
                raise RequestBuildError(f"Required header parameter {name} is missing")
            continue
        if not _TOKEN.fullmatch(name) or name.lower() in _FORBIDDEN_HEADERS:
            raise RequestBuildError("Endpoint declares a forbidden request header")
        headers[name] = _scalar(supplied["header"][name], definition.get("schema", {}), name)
    if not parts.scheme or not parts.netloc or parts.query or parts.fragment or not path.startswith("/") or path.startswith("//") or "\\" in path:
        raise RequestBuildError("Endpoint URL cannot be built safely")
    return urlunsplit((parts.scheme, parts.netloc, path, urlencode(query, doseq=True), "")), headers
