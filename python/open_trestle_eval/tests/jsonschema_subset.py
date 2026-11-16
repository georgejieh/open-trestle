"""A test-only checker for the JSON Schema keywords the evaluation schemas use.

It mirrors internal/schemacheck: unknown keywords are refused so a schema
cannot silently stop checking, and booleans are never numbers.
"""

from __future__ import annotations

import json
import re
from typing import Any

_KNOWN = {
    "$schema", "$id", "$defs", "$ref", "title", "description", "type", "const", "enum", "minLength",
    "maxLength", "pattern", "minimum", "maximum", "required", "properties", "additionalProperties",
    "dependentRequired", "items", "minItems", "maxItems", "uniqueItems", "contains", "allOf", "anyOf",
    "oneOf", "not", "if", "then", "else",
}


class SchemaError(AssertionError):
    pass


def _kind(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "integer" if value.is_integer() else "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "unknown"


def _same(left: Any, right: Any) -> bool:
    return json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True)


def _resolve(root: dict[str, Any], reference: str) -> Any:
    if not reference.startswith("#"):
        raise SchemaError(f"external reference {reference} is not supported")
    target: Any = root
    for part in [item for item in reference[1:].split("/") if item]:
        target = target[part.replace("~1", "/").replace("~0", "~")]
    return target


def validate(schema: Any, value: Any, root: dict[str, Any] | None = None, at: str = "$") -> None:
    root = root if root is not None else schema
    if schema is True:
        return
    if schema is False:
        raise SchemaError(f"{at}: false schema")
    unknown = set(schema) - _KNOWN
    if unknown:
        raise SchemaError(f"{at}: unsupported keywords {sorted(unknown)}")
    if "$ref" in schema:
        validate(_resolve(root, schema["$ref"]), value, root, at)
    if "type" in schema:
        names = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        actual = _kind(value)
        if actual not in names and not (actual == "integer" and "number" in names):
            raise SchemaError(f"{at}: {actual} is not {names}")
    if "const" in schema and not _same(schema["const"], value):
        raise SchemaError(f"{at}: {value!r} is not the const")
    if "enum" in schema and not any(_same(option, value) for option in schema["enum"]):
        raise SchemaError(f"{at}: {value!r} not in enum")
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", len(value)):
            raise SchemaError(f"{at}: string length out of bounds")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            raise SchemaError(f"{at}: {value!r} does not match {schema['pattern']}")
    if _kind(value) in ("integer", "number"):
        if "minimum" in schema and value < schema["minimum"]:
            raise SchemaError(f"{at}: {value} below minimum")
        if "maximum" in schema and value > schema["maximum"]:
            raise SchemaError(f"{at}: {value} above maximum")
    if isinstance(value, dict):
        for name in schema.get("required", []):
            if name not in value:
                raise SchemaError(f"{at}: required property {name} missing")
        for name, needs in schema.get("dependentRequired", {}).items():
            if name in value and any(need not in value for need in needs):
                raise SchemaError(f"{at}: {name} requires {needs}")
        properties = schema.get("properties", {})
        for name, member in value.items():
            if name in properties:
                validate(properties[name], member, root, f"{at}.{name}")
            elif "additionalProperties" in schema:
                validate(schema["additionalProperties"], member, root, f"{at}.{name}")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", len(value)):
            raise SchemaError(f"{at}: array length out of bounds")
        if schema.get("uniqueItems"):
            encoded = [json.dumps(item, sort_keys=True) for item in value]
            if len(set(encoded)) != len(encoded):
                raise SchemaError(f"{at}: items repeat")
        if "items" in schema:
            for index, item in enumerate(value):
                validate(schema["items"], item, root, f"{at}[{index}]")
        if "contains" in schema and not any(_passes(schema["contains"], item, root) for item in value):
            raise SchemaError(f"{at}: no item matches contains")
    for sub in schema.get("allOf", []):
        validate(sub, value, root, at)
    if "anyOf" in schema and not any(_passes(sub, value, root) for sub in schema["anyOf"]):
        raise SchemaError(f"{at}: no anyOf branch matches")
    if "oneOf" in schema and sum(_passes(sub, value, root) for sub in schema["oneOf"]) != 1:
        raise SchemaError(f"{at}: oneOf does not match exactly one branch")
    if "not" in schema and _passes(schema["not"], value, root):
        raise SchemaError(f"{at}: value matches a not schema")
    if "if" in schema:
        branch = "then" if _passes(schema["if"], value, root) else "else"
        if branch in schema:
            validate(schema[branch], value, root, at)


def _passes(schema: Any, value: Any, root: dict[str, Any]) -> bool:
    try:
        validate(schema, value, root)
    except SchemaError:
        return False
    return True
