"""Regular-file I/O, symlink guards, and bounded strict JSON helpers for product-lifecycle."""

from __future__ import annotations

import errno
import hashlib
import json
import math
import os
import stat
from pathlib import Path
from typing import Any

MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_INT_DIGITS = 400
MAX_JSON_INT_ABS = 10**MAX_JSON_INT_DIGITS - 1

__all__ = [
    "ContractError",
    "MAX_INPUT_BYTES",
    "MAX_JSON_DEPTH",
    "MAX_JSON_INT_ABS",
    "MAX_JSON_INT_DIGITS",
    "canonical",
    "digest",
    "enforce_json_bounds",
    "file_digest",
    "has_control_chars",
    "has_symlink_ancestor",
    "is_valid_utf8",
    "read_regular_bytes",
    "read_regular_utf8",
    "strict_loads",
]


class ContractError(ValueError):
    """A bounded error that never repeats untrusted commercial or host data."""


def is_valid_utf8(value: str) -> bool:
    try:
        value.encode("utf-8")
        return True
    except UnicodeEncodeError:
        return False


def has_control_chars(value: str, *, allow_newlines: bool = False) -> bool:
    for ch in value:
        code = ord(ch)
        if code == 0x7F:
            return True
        if code < 0x20:
            if allow_newlines and ch in {"\n", "\t"}:
                continue
            return True
    return False


def _check_json_scalar(value: Any) -> None:
    if isinstance(value, str) and not is_valid_utf8(value):
        raise ContractError("invalid UTF-8 surrogate in JSON string")
    if isinstance(value, float) and not math.isfinite(value):
        raise ContractError("non-finite JSON float is forbidden")
    if isinstance(value, int) and not isinstance(value, bool) and abs(value) > MAX_JSON_INT_ABS:
        raise ContractError("JSON integer out of range")


def enforce_json_bounds(root: Any, *, max_depth: int = MAX_JSON_DEPTH) -> None:
    stack: list[tuple[Any, int]] = [(root, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > max_depth:
            raise ContractError("JSON nesting depth exceeded")
        if isinstance(current, dict):
            next_depth = depth + 1
            if next_depth > max_depth and current:
                raise ContractError("JSON nesting depth exceeded")
            for key, child in current.items():
                if not isinstance(key, str) or not is_valid_utf8(key):
                    raise ContractError("JSON object key must be valid UTF-8 text")
                if isinstance(child, (dict, list)):
                    stack.append((child, next_depth))
                else:
                    _check_json_scalar(child)
        elif isinstance(current, list):
            next_depth = depth + 1
            if next_depth > max_depth and current:
                raise ContractError("JSON nesting depth exceeded")
            for child in current:
                if isinstance(child, (dict, list)):
                    stack.append((child, next_depth))
                else:
                    _check_json_scalar(child)
        else:
            _check_json_scalar(current)


def has_symlink_ancestor(path: Path, *, include_self: bool = False) -> bool:
    try:
        if include_self and path.is_symlink():
            return True
    except OSError:
        return True
    parts = path.parts if include_self else path.parts[:-1]
    if not path.is_absolute():
        cur = Path()
        for part in parts:
            cur = cur / part
            try:
                if cur.is_symlink():
                    return True
            except OSError:
                return True
        cwd = Path.cwd()
        for anc in (cwd, *cwd.parents):
            if len(anc.parts) <= 2:
                break
            try:
                if anc.is_symlink():
                    return True
            except OSError:
                return True
        return False
    if not parts:
        return False
    cur = Path(parts[0])
    for idx, part in enumerate(parts[1:], start=2):
        cur = cur / part
        if idx <= 2 and not (include_self and idx == len(parts)):
            continue
        try:
            if cur.is_symlink():
                return True
        except OSError:
            return True
    return False


def read_regular_bytes(path: str | Path, *, max_bytes: int = MAX_INPUT_BYTES) -> bytes:
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes <= 0:
        raise ContractError("max_bytes must be a positive integer")
    path_obj = Path(os.fspath(path))
    if has_symlink_ancestor(path_obj, include_self=False):
        raise ContractError("symlink JSON input is forbidden")
    raw_path = os.fspath(path_obj)
    try:
        st = os.lstat(raw_path)
    except OSError as err:
        raise ContractError("JSON input cannot be stat'd") from err
    if stat.S_ISLNK(st.st_mode):
        raise ContractError("symlink JSON input is forbidden")
    if not stat.S_ISREG(st.st_mode):
        raise ContractError("JSON input must be a regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(raw_path, flags)
    except OSError as err:
        if err.errno == errno.ELOOP:
            raise ContractError("symlink JSON input is forbidden") from err
        raise ContractError("JSON input cannot be opened") from err
    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode) or (st.st_dev, st.st_ino) != (fst.st_dev, fst.st_ino):
            raise ContractError("JSON input must be an unchanged regular file")
        if fst.st_size > max_bytes:
            raise ContractError("JSON input exceeds maximum size")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(65536, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise ContractError("JSON input exceeds maximum size")
        return b"".join(chunks)
    finally:
        os.close(fd)


def read_regular_utf8(path: str | Path, *, max_bytes: int = MAX_INPUT_BYTES) -> str:
    raw = read_regular_bytes(path, max_bytes=max_bytes)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as err:
        raise ContractError("invalid UTF-8 JSON input") from err


def strict_loads(raw: str) -> Any:
    if not isinstance(raw, str) or not is_valid_utf8(raw):
        raise ContractError("JSON input must be valid UTF-8 text")
    if len(raw.encode("utf-8")) > MAX_INPUT_BYTES:
        raise ContractError("JSON input exceeds maximum size")

    def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        obj: dict[str, Any] = {}
        for key, val in pairs:
            if not isinstance(key, str):
                raise ContractError("JSON object key must be a string")
            if key in obj:
                raise ContractError("duplicate JSON key")
            obj[key] = val
        return obj

    def _reject_constant(token: str) -> Any:
        raise ContractError("non-finite JSON constant is forbidden")

    def _parse_finite_float(token: str) -> float:
        parsed = float(token)
        if not math.isfinite(parsed):
            raise ContractError("JSON float out of finite IEEE-754 range")
        return parsed

    def _parse_bounded_int(token: str) -> int:
        digits = token[1:] if token.startswith("-") else token
        if len(digits) > MAX_JSON_INT_DIGITS:
            raise ContractError("JSON integer out of range")
        parsed = int(token)
        if abs(parsed) > MAX_JSON_INT_ABS:
            raise ContractError("JSON integer out of range")
        return parsed

    try:
        data = json.loads(
            raw,
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
            parse_float=_parse_finite_float,
            parse_int=_parse_bounded_int,
        )
    except ContractError:
        raise
    except RecursionError as err:
        raise ContractError("JSON nesting depth exceeded") from err
    except ValueError as err:
        raise ContractError("malformed JSON input") from err
    enforce_json_bounds(data)
    return data


def canonical(value: Any) -> str:
    enforce_json_bounds(value)
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


def digest(value: str) -> str:
    if not isinstance(value, str) or not is_valid_utf8(value):
        raise ContractError("digest input must be valid UTF-8 text")
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def file_digest(path: Path) -> str:
    return hashlib.sha256(read_regular_bytes(path)).hexdigest()
