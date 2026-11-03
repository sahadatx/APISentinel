"""Bounded, offline import of GraphQL introspection JSON metadata."""
from __future__ import annotations

import hashlib
import json
import re

from fastapi import HTTPException

from .discovery import _check_json_nesting, _reject_duplicate_json_keys, _reject_json_constant

_NAME = re.compile(r"^[_A-Za-z][_0-9A-Za-z]*$")
MAX_TYPES = 2_000
MAX_FIELDS = 10_000


def _fail(message: str) -> None:
    raise HTTPException(422, message)


def parse_graphql_introspection(raw: bytes, max_bytes: int) -> tuple[dict, str]:
    """Parse a client-supplied introspection export; never fetch a schema from a target."""
    if len(raw) > max_bytes:
        raise HTTPException(413, "GraphQL introspection document exceeds the configured size limit")
    try:
        _check_json_nesting(raw)
        document = json.loads(raw, object_pairs_hook=_reject_duplicate_json_keys,
                              parse_constant=_reject_json_constant)
    except RecursionError:
        _fail("GraphQL document nesting exceeds the supported parser depth")
    except (ValueError, UnicodeDecodeError):
        _fail("GraphQL import must contain valid JSON without duplicate object keys")
    if not isinstance(document, dict):
        _fail("GraphQL introspection import must be a JSON object")
    schema = document.get("data", {}).get("__schema") if isinstance(document.get("data"), dict) else None
    if schema is None:
        schema = document.get("__schema")
    if not isinstance(schema, dict) or not isinstance(schema.get("types"), list):
        _fail("Provide a GraphQL introspection JSON export containing data.__schema.types")
    source_types = schema["types"]
    if len(source_types) > MAX_TYPES:
        _fail("GraphQL schema exceeds the supported type limit")

    def valid_name(value: object, label: str) -> str:
        if not isinstance(value, str) or len(value) > 255 or not _NAME.fullmatch(value):
            _fail(f"GraphQL {label} has an invalid name")
        return value

    def type_ref(value: object, depth: int = 0) -> str:
        if depth > 16 or not isinstance(value, dict):
            _fail("GraphQL type reference is malformed or too deeply nested")
        kind = value.get("kind")
        if kind in {"NON_NULL", "LIST"}:
            inner = type_ref(value.get("ofType"), depth + 1)
            return f"{inner}!" if kind == "NON_NULL" else f"[{inner}]"
        name = value.get("name")
        return valid_name(name, "type reference") if name else _fail("GraphQL type reference is missing a named type")

    total_fields = 0
    types = []
    by_name = {}
    for item in source_types:
        if not isinstance(item, dict):
            _fail("GraphQL introspection type entries must be objects")
        name = item.get("name")
        if not isinstance(name, str) or name.startswith("__"):
            continue
        name = valid_name(name, "type")
        if name in by_name:
            _fail("GraphQL introspection contains duplicate type names")
        kind = item.get("kind")
        if kind not in {"SCALAR", "OBJECT", "INTERFACE", "UNION", "ENUM", "INPUT_OBJECT"}:
            _fail("GraphQL introspection contains an unsupported type kind")
        row = {"name": name, "kind": kind, "fields": [], "enum_values": [],
               "interfaces": [], "possible_types": []}
        for source_key, target_key in (("interfaces", "interfaces"), ("possibleTypes", "possible_types")):
            relationships = item.get(source_key, []) or []
            if not isinstance(relationships, list) or len(relationships) > MAX_TYPES:
                _fail("GraphQL type relationship list exceeds the supported limit")
            for relationship in relationships:
                if not isinstance(relationship, dict):
                    _fail("GraphQL type relationship entry is malformed")
                row[target_key].append(valid_name(relationship.get("name"), "related type"))
        source_fields = item.get("fields") if kind in {"OBJECT", "INTERFACE"} else item.get("inputFields") if kind == "INPUT_OBJECT" else []
        if source_fields is None:
            source_fields = []
        if not isinstance(source_fields, list) or len(source_fields) > MAX_FIELDS:
            _fail("GraphQL type contains too many fields")
        for field in source_fields:
            if not isinstance(field, dict):
                _fail("GraphQL field entries must be objects")
            field_name = valid_name(field.get("name"), "field")
            field_type = type_ref(field.get("type"))
            args = []
            raw_args = field.get("args", []) if kind != "INPUT_OBJECT" else []
            if not isinstance(raw_args, list) or len(raw_args) > 500:
                _fail("GraphQL field contains too many arguments")
            for argument in raw_args:
                if not isinstance(argument, dict):
                    _fail("GraphQL argument entries must be objects")
                args.append({"name": valid_name(argument.get("name"), "argument"),
                             "type": type_ref(argument.get("type"))})
            row["fields"].append({"name": field_name, "type": field_type,
                                  "arguments": args,
                                  "deprecated": bool(field.get("isDeprecated", False))})
            total_fields += 1
            if total_fields > MAX_FIELDS:
                _fail("GraphQL schema exceeds the supported field limit")
        raw_enums = item.get("enumValues", []) if kind == "ENUM" else []
        if raw_enums is None:
            raw_enums = []
        if not isinstance(raw_enums, list) or len(raw_enums) > MAX_FIELDS:
            _fail("GraphQL enum contains too many values")
        for enum_value in raw_enums:
            if not isinstance(enum_value, dict):
                _fail("GraphQL enum value entries must be objects")
            row["enum_values"].append(valid_name(enum_value.get("name"), "enum value"))
        types.append(row)
        by_name[name] = row

    roots = {}
    for operation in ("queryType", "mutationType", "subscriptionType"):
        root = schema.get(operation)
        if root is not None:
            if not isinstance(root, dict):
                _fail("GraphQL operation root type is malformed")
            roots[operation.removesuffix("Type")] = valid_name(root.get("name"), "root type")
    for operation, root_name in roots.items():
        if root_name not in by_name or by_name[root_name]["kind"] != "OBJECT":
            _fail("GraphQL operation root does not resolve to a declared type")
    types.sort(key=lambda item: (item["kind"], item["name"]))
    safe = {
        "format": "graphql-introspection-metadata-v1",
        "roots": roots,
        "type_count": len(types),
        "field_count": total_fields,
        "types": types,
        "limitations": "Offline schema inventory only. No GraphQL operation was sent or security behavior tested.",
    }
    try:
        canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError):
        _fail("GraphQL document contains a value that cannot be represented as valid JSON")
    return safe, hashlib.sha256(canonical.encode("utf-8")).hexdigest()
