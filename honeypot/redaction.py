"""Redaction helpers for persisted honeypot telemetry."""
import json
import re
from urllib.parse import parse_qsl, urlencode

_SENSITIVE_KEY = re.compile(
    r"(?:authorization|cookie|password|passwd|pwd|token|secret|api[_-]?key|credential)", re.I)
_SENSITIVE_VALUE = re.compile(
    r"(?i)(\b(?:authorization|password|passwd|pwd|token|secret|api[_-]?key)\b"
    r"\s*[:=]\s*)([^&\s,;]+)")
REDACTED = "[REDACTED]"


def redact_mapping(value):
    if isinstance(value, dict):
        return {key: (REDACTED if _SENSITIVE_KEY.search(str(key)) else redact_mapping(item))
                for key, item in value.items()}
    if isinstance(value, list):
        return [redact_mapping(item) for item in value]
    if isinstance(value, str):
        if value.lstrip().startswith(("{", "[")):
            try:
                parsed = json.loads(value)
                if isinstance(parsed, (dict, list)):
                    return json.dumps(redact_mapping(parsed), ensure_ascii=False)
            except json.JSONDecodeError:
                pass
        return _SENSITIVE_VALUE.sub(r"\1" + REDACTED, value)
    return value


def redact_headers(headers: dict) -> dict:
    return redact_mapping(headers)


def redact_query(query: str) -> str:
    fields = parse_qsl(query, keep_blank_values=True)
    return urlencode([(key, REDACTED if _SENSITIVE_KEY.search(key)
                       else _SENSITIVE_VALUE.sub(r"\1" + REDACTED, value))
                      for key, value in fields])


def redact_payload(body: str, content_type: str = "") -> str:
    if not body:
        return body
    media_type = content_type.split(";", 1)[0].strip().lower()
    if media_type == "multipart/form-data":
        return "[REDACTED_MULTIPART_BODY]"
    if media_type == "application/json" or media_type.endswith("+json"):
        try:
            return json.dumps(redact_mapping(json.loads(body)), ensure_ascii=False)
        except (json.JSONDecodeError, TypeError):
            pass
    if media_type == "application/x-www-form-urlencoded":
        return redact_query(body)
    return _SENSITIVE_VALUE.sub(r"\1" + REDACTED, body)