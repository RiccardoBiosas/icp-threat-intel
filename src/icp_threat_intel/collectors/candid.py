"""Parse ``candid:service`` text into a method list (name, args, rets, mode).

Pure text processing, no I/O. Covers the Candid service grammar we meet in public
metadata: comments, ``type`` definitions, quoted method names, service and func type
references, init arguments (``service : (Init) -> {...}``) and the ``query``,
``composite_query`` and ``oneway`` annotations. A method without annotation is an update
method. Argument and result types are kept as normalised text, not resolved.
Reference: https://github.com/dfinity/candid/blob/master/spec/Candid.md
"""

import re
from dataclasses import dataclass
from typing import Any

MODES = ("query", "composite_query", "oneway")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_SPACE = re.compile(r"\s+")
_OPEN = {"(": ")", "{": "}"}


class CandidParseError(ValueError):
    """The text is not a Candid service description we can read."""


@dataclass(frozen=True)
class CandidMethod:
    name: str
    args: tuple[str, ...]
    rets: tuple[str, ...]
    mode: str  # "update", "query", "composite_query" or "oneway"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "args": list(self.args),
            "rets": list(self.rets),
            "mode": self.mode,
        }


def strip_comments(text: str) -> str:
    """Remove ``//`` and (nested) ``/* */`` comments outside string literals."""
    out: list[str] = []
    i, depth, in_str = 0, 0, False
    while i < len(text):
        ch, pair = text[i], text[i : i + 2]
        if depth:
            if pair == "/*":
                depth, i = depth + 1, i + 2
            elif pair == "*/":
                depth, i = depth - 1, i + 2
            else:
                i += 1
            continue
        if in_str:
            out.append(ch)
            if ch == "\\":
                out.append(text[i + 1 : i + 2])
                i += 1
            elif ch == '"':
                in_str = False
            i += 1
        elif pair == "//":
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
        elif pair == "/*":
            depth, i = 1, i + 2
        else:
            in_str = ch == '"'
            out.append(ch)
            i += 1
    if depth:
        raise CandidParseError("unterminated block comment")
    return "".join(out)


def split_top(text: str, sep: str) -> list[str]:
    """Split on ``sep`` outside brackets and string literals; drop empty parts."""
    parts: list[str] = []
    stack: list[str] = []
    start, i, in_str = 0, 0, False
    while i < len(text):
        ch = text[i]
        if in_str:
            if ch == "\\":
                i += 1
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in _OPEN:
            stack.append(_OPEN[ch])
        elif ch in ")}":
            if not stack or stack.pop() != ch:
                raise CandidParseError(f"unbalanced {ch!r} at offset {i}")
        elif ch == sep and not stack:
            parts.append(text[start:i])
            start = i + 1
        i += 1
    if stack or in_str:
        raise CandidParseError("unbalanced brackets or string")
    parts.append(text[start:])
    return [p.strip() for p in parts if p.strip()]


def _balanced(text: str, start: int) -> int:
    """Index just past the bracket group that opens at ``start``."""
    close = _OPEN[text[start]]
    level, in_str, i = 0, False, start
    while i < len(text):
        ch = text[i]
        if in_str:
            if ch == "\\":
                i += 1
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in _OPEN:
            level += 1
        elif ch in ")}":
            level -= 1
            if level == 0:
                if ch != close:
                    raise CandidParseError("mismatched brackets")
                return i + 1
        i += 1
    raise CandidParseError("unterminated bracket group")


def _norm(text: str) -> str:
    return _SPACE.sub(" ", text).strip()


def _type_defs(statements: list[str]) -> dict[str, str]:
    defs: dict[str, str] = {}
    for stmt in statements:
        m = re.match(r"type\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\Z", stmt, re.S)
        if m:
            defs[m.group(1)] = m.group(2).strip()
    return defs


def _resolve(text: str, defs: dict[str, str], keyword: str) -> str:
    """Follow ``Name`` references until text starts with ``keyword`` or a bracket."""
    seen: set[str] = set()
    while _IDENT.fullmatch(text) and text not in (keyword,):
        if text in seen or text not in defs:
            raise CandidParseError(f"unresolved type reference {text!r}")
        seen.add(text)
        text = defs[text]
    return text


def _service_body(actor: str, defs: dict[str, str]) -> str:
    m = re.match(r"service\s*(?:[A-Za-z_][A-Za-z0-9_]*\s*)?:\s*(.*)\Z", actor, re.S)
    if not m:
        raise CandidParseError("malformed service declaration")
    rest = m.group(1).strip()
    if rest.startswith("("):  # init arguments: (Init) -> Service
        end = _balanced(rest, 0)
        rest = rest[end:].strip()
        if not rest.startswith("->"):
            raise CandidParseError("expected '->' after service init arguments")
        rest = rest[2:].strip()
    rest = _resolve(rest, defs, "service")
    if rest.startswith("service"):
        rest = rest[len("service") :].strip()
    if not rest.startswith("{"):
        raise CandidParseError("service body is not a method block")
    end = _balanced(rest, 0)
    return rest[1 : end - 1]


def _parse_func(sig: str, defs: dict[str, str]) -> tuple[tuple[str, ...], tuple[str, ...], str]:
    sig = _resolve(sig.strip(), defs, "func")
    if sig.startswith("func"):
        sig = sig[len("func") :].strip()
    if not sig.startswith("("):
        raise CandidParseError(f"not a function signature: {sig[:60]!r}")
    a_end = _balanced(sig, 0)
    rest = sig[a_end:].strip()
    if not rest.startswith("->"):
        raise CandidParseError("expected '->' in function signature")
    rest = rest[2:].strip()
    if not rest.startswith("("):
        raise CandidParseError("function results must be parenthesised")
    r_end = _balanced(rest, 0)
    anns = rest[r_end:].split()
    unknown = [a for a in anns if a not in MODES]
    if unknown or len(anns) > 1:
        raise CandidParseError(f"unexpected function annotations {anns}")
    args = tuple(_norm(a) for a in split_top(sig[1 : a_end - 1], ","))
    rets = tuple(_norm(r) for r in split_top(rest[1 : r_end - 1], ","))
    return args, rets, anns[0] if anns else "update"


def _method_name(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith('"') and raw.endswith('"') and len(raw) >= 2:
        return raw[1:-1].encode("utf-8").decode("unicode_escape")
    if not _IDENT.fullmatch(raw):
        raise CandidParseError(f"bad method name {raw!r}")
    return raw


def parse_service(text: str) -> list[CandidMethod]:
    """Return the methods of the actor service in ``text``, in declaration order."""
    statements = split_top(strip_comments(text), ";")
    actors = [s for s in statements if re.match(r"service\b", s)]
    if len(actors) != 1:
        raise CandidParseError(f"expected one service declaration, found {len(actors)}")
    defs = _type_defs(statements)
    methods: list[CandidMethod] = []
    for entry in split_top(_service_body(actors[0], defs), ";"):
        name_part, sep, sig = _split_name(entry)
        if not sep:
            raise CandidParseError(f"method entry without ':' {entry[:60]!r}")
        args, rets, mode = _parse_func(sig, defs)
        methods.append(CandidMethod(_method_name(name_part), args, rets, mode))
    return methods


def _split_name(entry: str) -> tuple[str, str, str]:
    if entry.startswith('"'):
        end = 1
        while end < len(entry) and entry[end] != '"':
            end += 2 if entry[end] == "\\" else 1
        name, rest = entry[: end + 1], entry[end + 1 :].strip()
        if not rest.startswith(":"):
            return name, "", rest
        return name, ":", rest[1:]
    return entry.partition(":")
