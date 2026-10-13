"""Gateway body handling (SPEC guardrail 2): bodies are data.

Bodies are classified by pattern matching only. Nothing here executes, evaluates, renders
or follows anything a body contains.
"""

import re
from enum import StrEnum

IC_DOMAIN_SUFFIXES = ("icp0.io", "ic0.app", "icp-api.io")

_URL_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://\S+$", re.IGNORECASE)
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/_\-]{16,}={0,2}$")
_SHELL_RE = re.compile(
    r"(^#!\s*/\S*(?:sh|bash|python[0-9.]*)\b"
    r"|\|\s*(?:ba|z|da)?sh\b"
    r"|^\s*(?:curl|wget|chmod|chown|bash|sh|nohup|systemctl|crontab|echo|cd|rm|mkdir|touch"
    r"|mv|cp|export|eval|base64|python3?|node|perl)\b"
    r"|&&|/tmp/\S+|\$\(\s*\w)",
    re.MULTILINE,
)
_TEXT_CONTROL = set(range(32)) - {9, 10, 13}


class BodyClass(StrEnum):
    EMPTY = "empty"
    URL = "url"
    BASE64_BLOB = "base64_blob"
    SHELL_FRAGMENT = "shell_fragment"
    BINARY = "binary"
    OTHER = "other"


def is_ic_domain(host: str) -> bool:
    """True for IC gateway and boundary-node hosts (and their subdomains)."""
    host = host.lower().rstrip(".")
    return any(host == s or host.endswith("." + s) for s in IC_DOMAIN_SUFFIXES)


def _decode_text(body: bytes) -> str | None:
    if b"\x00" in body:
        return None
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None
    controls = sum(1 for ch in text if ord(ch) in _TEXT_CONTROL)
    return None if controls > len(text) // 20 else text


def classify_body(body: bytes) -> BodyClass:
    """Classify a body as URL, base64 blob, shell fragment, binary, empty or other."""
    if not body.strip():
        return BodyClass.EMPTY
    text = _decode_text(body)
    if text is None:
        return BodyClass.BINARY
    stripped = text.strip()
    if _URL_RE.match(stripped):
        return BodyClass.URL
    compact = "".join(stripped.split())
    if _BASE64_RE.match(compact) and len(compact) % 4 in (0, 2, 3):
        return BodyClass.BASE64_BLOB
    if _SHELL_RE.search(stripped):
        return BodyClass.SHELL_FRAGMENT
    return BodyClass.OTHER
