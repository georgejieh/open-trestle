"""Strict decoding for untrusted model candidate responses."""

from __future__ import annotations

import json
import math
from enum import Enum
from typing import NoReturn

_MAX_RESPONSE_BYTES = 256 * 1024
_MAX_CONTAINER_DEPTH = 8


class CandidateResponseErrorCode(str, Enum):
    """Stable reasons for rejecting candidate response bytes."""

    TOO_LARGE = "too_large"
    INVALID_UTF8 = "invalid_utf8"
    INVALID_JSON = "invalid_json"
    DUPLICATE_KEY = "duplicate_key"
    NON_FINITE_NUMBER = "non_finite_number"
    CONTAINER_DEPTH_EXCEEDED = "container_depth_exceeded"
    UNPAIRED_SURROGATE = "unpaired_surrogate"


_ERROR_MESSAGES = {
    CandidateResponseErrorCode.TOO_LARGE: "candidate response exceeds the byte limit",
    CandidateResponseErrorCode.INVALID_UTF8: "candidate response is not valid UTF-8",
    CandidateResponseErrorCode.INVALID_JSON: "candidate response is not strict JSON",
    CandidateResponseErrorCode.DUPLICATE_KEY: (
        "candidate response contains a duplicate key"
    ),
    CandidateResponseErrorCode.NON_FINITE_NUMBER: (
        "candidate response contains a non-finite number"
    ),
    CandidateResponseErrorCode.CONTAINER_DEPTH_EXCEEDED: (
        "candidate response exceeds the depth limit"
    ),
    CandidateResponseErrorCode.UNPAIRED_SURROGATE: (
        "candidate response contains an unpaired surrogate"
    ),
}


class CandidateResponseDecodeError(ValueError):
    """Reports one stable candidate response rejection reason."""

    def __init__(self, code: CandidateResponseErrorCode) -> None:
        self.code: CandidateResponseErrorCode = code
        super().__init__(_ERROR_MESSAGES[code])


def _raise_decode_error(code: CandidateResponseErrorCode) -> NoReturn:
    raise CandidateResponseDecodeError(code)


def _check_lexical_depth(text: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
        elif character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > _MAX_CONTAINER_DEPTH:
                _raise_decode_error(
                    CandidateResponseErrorCode.CONTAINER_DEPTH_EXCEEDED
                )
        elif character in "]}":
            depth -= 1


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _raise_decode_error(CandidateResponseErrorCode.DUPLICATE_KEY)
        result[key] = value
    return result


def _reject_nonfinite_constant(_: str) -> NoReturn:
    _raise_decode_error(CandidateResponseErrorCode.NON_FINITE_NUMBER)


def _parse_finite_float(token: str) -> float:
    try:
        value = float(token)
    except (OverflowError, ValueError):
        _raise_decode_error(CandidateResponseErrorCode.INVALID_JSON)
    if not math.isfinite(value):
        _raise_decode_error(CandidateResponseErrorCode.NON_FINITE_NUMBER)
    return value


def _contains_surrogate(value: str) -> bool:
    return any(0xD800 <= ord(character) <= 0xDFFF for character in value)


def _validate_decoded_value(root: object) -> None:
    stack: list[tuple[object, int]] = [(root, 0)]
    while stack:
        value, parent_depth = stack.pop()
        if isinstance(value, dict):
            depth = parent_depth + 1
            if depth > _MAX_CONTAINER_DEPTH:
                _raise_decode_error(
                    CandidateResponseErrorCode.CONTAINER_DEPTH_EXCEEDED
                )
            for key, child in value.items():
                if _contains_surrogate(key):
                    _raise_decode_error(CandidateResponseErrorCode.UNPAIRED_SURROGATE)
                stack.append((child, depth))
        elif isinstance(value, list):
            depth = parent_depth + 1
            if depth > _MAX_CONTAINER_DEPTH:
                _raise_decode_error(
                    CandidateResponseErrorCode.CONTAINER_DEPTH_EXCEEDED
                )
            stack.extend((child, depth) for child in value)
        elif isinstance(value, str) and _contains_surrogate(value):
            _raise_decode_error(CandidateResponseErrorCode.UNPAIRED_SURROGATE)
        elif isinstance(value, float) and not math.isfinite(value):
            _raise_decode_error(CandidateResponseErrorCode.NON_FINITE_NUMBER)


def decode_candidate_response(payload: bytes) -> object:
    """Decodes one bounded strict JSON value without schema validation."""
    if not isinstance(payload, bytes):
        raise TypeError("candidate response must be bytes")
    if len(payload) > _MAX_RESPONSE_BYTES:
        _raise_decode_error(CandidateResponseErrorCode.TOO_LARGE)
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise CandidateResponseDecodeError(
            CandidateResponseErrorCode.INVALID_UTF8
        ) from None
    _check_lexical_depth(text)
    try:
        value = json.loads(
            text,
            strict=True,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite_constant,
            parse_float=_parse_finite_float,
        )
    except CandidateResponseDecodeError:
        raise
    except RecursionError:
        raise CandidateResponseDecodeError(
            CandidateResponseErrorCode.CONTAINER_DEPTH_EXCEEDED
        ) from None
    except (OverflowError, ValueError):
        raise CandidateResponseDecodeError(
            CandidateResponseErrorCode.INVALID_JSON
        ) from None
    _validate_decoded_value(value)
    return value
