"""What the signals-feed parser looks for in forum posts, besides canister ids.

* ``KEYWORDS``: threat terms, as label -> whole-word pattern (case-insensitive). Labels are
  what events, the digest and rules see. Terms common in ordinary developer talk are only
  matched in a threat context: bare "hack", "abuse", "worm", "compromise", "payload" and
  "seed phrase" are not keywords.
* IOC terms: non-canister IOC values from the ``iocs`` table (package names, file paths,
  systemd units, URLs, domains), matched as whole terms. Canister ids are matched separately
  (``enrichment/ioc_join.CANISTER_ID_RE``); ledger accounts are not matched in text.
"""

import re
from collections.abc import Iterable
from dataclasses import dataclass

from icp_threat_intel.core.enums import IocType

KEYWORDS: dict[str, str] = {
    "malicious": r"malicious",
    "malware": r"malware",
    "phishing": r"phishing",
    "scam": r"scam(?:s|mer|mers|med)?",
    "exploit": r"exploit(?:s|ed)?",
    "backdoor": r"backdoor(?:s|ed)?",
    "c2": r"c2|command[- ]and[- ]control",
    "exfiltration": r"exfiltrat(?:e|ed|es|ing|ion)",
    "denylist": r"deny-?list(?:s|ed)?|block-?list(?:s|ed)?",
    "takedown": r"take-?down|taken down",
    "abuse": r"abusive|abuse reports?|report(?:ed|ing)? (?:for |as )?abuse",
    "compromised": r"compromised",
    "worm": r"(?:npm|self[- ]propagating|supply[- ]chain|crypto) worms?|worms? (?:attack|campaign)",
    "drainer": r"drainers?",
    "stolen": r"stolen|stole",
    "hacked": r"hacked|hackers?",
    "supply_chain": r"supply[- ]chain (?:attacks?|compromise|incident)",
    "install_hook": r"(?:pre|post)install (?:scripts?|hooks?)",
    "dead_drop": r"dead[- ]drops?",
    "dropper": r"droppers?",
    "stealer": r"(?:info)?stealers?|credential (?:theft|stealing|harvesting)",
    "rug_pull": r"rug[- ]?pull(?:s|ed)?",
    "impersonation": (
        r"impersonat(?:e|es|ed|ing|ion|or|ors)"
        r"|fake (?:airdrops?|tokens?|sites?|websites?|frontends?|wallets?|nns|dapps?)"
    ),
    "seed_phrase": (
        r"(?:stole|stolen|steal|leaked|drained) (?:my |the |their |your )?seed phrases?"
        r"|seed phrases? (?:stolen|leaked|phishing|scam)"
    ),
    "campaign": r"canisterworm|canistersprawl|teampcp|shai[- ]hulud",
}
_KEYWORD_RES = {k: re.compile(rf"\b(?:{p})\b", re.IGNORECASE) for k, p in KEYWORDS.items()}

MIN_TERM_CHARS = 4  # shorter IOC values would match ordinary words
_TEXT_IOC_TYPES = frozenset(
    {IocType.URL, IocType.DOMAIN, IocType.PACKAGE_VERSION, IocType.FILE_PATH, IocType.SYSTEMD_UNIT}
)
_PACKAGE_VERSION = re.compile(r"(?:==|@)[^@/=]*$")


def keywords_in(text: str) -> list[str]:
    """Sorted labels of every keyword found in ``text``."""
    return sorted(k for k, pattern in _KEYWORD_RES.items() if pattern.search(text))


@dataclass(frozen=True)
class IocTerm:
    ioc_type: str
    term: str  # lowercase, normalised


def ioc_term(ioc_type: IocType, value: str) -> IocTerm | None:
    """The text a post would contain for this IOC, or ``None`` if it is not matched in text.

    Packages are matched by name (``npm:@scope/name@1.2.3`` -> ``@scope/name``), since posts
    rarely spell the version the same way; URLs without a trailing slash.
    """
    if ioc_type not in _TEXT_IOC_TYPES:
        return None
    term = value.strip().lower()
    if ioc_type is IocType.PACKAGE_VERSION:
        term = term.split(":", 1)[1] if term.startswith(("npm:", "pypi:")) else term
        term = _PACKAGE_VERSION.sub("", term)
    elif ioc_type is IocType.URL:
        term = term.rstrip("/")
    if len(term) < MIN_TERM_CHARS:
        return None
    return IocTerm(ioc_type.value, term)


def _term_re(term: str) -> re.Pattern[str]:
    return re.compile(rf"(?<![\w@/.-]){re.escape(term)}(?!\.?[\w-])", re.IGNORECASE)


def find_ioc_terms(text: str, terms: Iterable[IocTerm]) -> list[str]:
    """Sorted IOC terms that appear in ``text`` as whole terms."""
    return sorted({t.term for t in terms if _term_re(t.term).search(text)})


# Forum search (``collectors/signals_search.py``). Discourse logs every query, so only these
# generic threat terms are ever sent: words a curious reader would type, never an identifier
# or anything from the ``iocs`` table. Campaign names are public reporting, not IOC values.
SEARCH_TERMS: tuple[str, ...] = (
    "malicious canister",
    "malware",
    "phishing",
    "scam",
    "scammer",
    "drainer",
    "exploit",
    "backdoor",
    "hacked",
    "compromised",
    "stolen",
    "exfiltration",
    "denylist",
    "takedown",
    "supply chain attack",
    "dead drop",
    "rug pull",
    "impersonating",
    "fake airdrop",
    "infostealer",
    "command and control",
    "canisterworm",
    "canistersprawl",
    "teampcp",
    "shai-hulud",
)
MAX_SEARCH_TERM_CHARS = 60
_SEARCH_TERM_SHAPE = re.compile(r"^[a-z][a-z -]*[a-z]$")
_PRINCIPAL_SHAPE = re.compile(r"\b[a-z2-7]{5}(?:-[a-z2-7]{1,5})+\b")
_HEX_RUN = re.compile(r"[0-9a-f]{16,}")
_TOKEN = re.compile(r"[a-z0-9]+")


class UnsafeSearchTerm(ValueError):
    """A search term that could reveal an identifier or a tracked IOC value."""


def check_search_term(term: str, ioc_values: Iterable[str] = ()) -> str:
    """Return ``term`` if it is safe to send to a forum search, else raise ``UnsafeSearchTerm``.

    Safe means: lowercase letters, spaces and hyphens only (no digits, dots, slashes or
    ``@``, so no ids, hashes, URLs, domains, paths, packages or units), no principal-shaped
    or long hex token, and no IOC value or IOC value token (4+ characters) inside it.
    """
    if not 0 < len(term) <= MAX_SEARCH_TERM_CHARS or not _SEARCH_TERM_SHAPE.match(term):
        raise UnsafeSearchTerm(f"search term must be lowercase words: {term!r}")
    if _PRINCIPAL_SHAPE.search(term) or _HEX_RUN.search(term):
        raise UnsafeSearchTerm(f"search term looks like an identifier: {term!r}")
    words = set(_TOKEN.findall(term))
    for value in ioc_values:
        value = value.strip().lower()
        tokens = {t for t in _TOKEN.findall(value) if len(t) >= MIN_TERM_CHARS}
        if (len(value) >= MIN_TERM_CHARS and value in term) or tokens & words:
            raise UnsafeSearchTerm(f"search term contains an IOC value: {term!r}")
    return term


# Hacker News search (``collectors/signals_hn.py``). Algolia logs queries too, and Hacker News
# is not about ICP, so each query carries ICP context and passes ``check_search_term``;
# threat keywords are matched locally in the results, never sent.
HN_QUERIES: tuple[str, ...] = (
    "internet computer",
    "dfinity",
    "icp canister",
    "canisterworm",
    "canistersprawl",
    "teampcp",
)
# Sent as exact phrases ("..."): unquoted, Algolia matches the two words anywhere
# ("internet computer": 31,902 hits unquoted, 309 quoted on 2026-10-16).
HN_EXACT_PHRASES: frozenset[str] = frozenset({"internet computer"})

# ICP context for sources that are not about ICP (Hacker News): an item counts only if its own
# text or its story title clearly refers to the Internet Computer. Case matters for
# "Internet Computer" (the proper noun, not "my internet computer"); bare "ICP" and
# "canister" are too ambiguous on their own. Canister ids and IOC terms also count.
_ICP_CONTEXT = (
    re.compile(r"\bInternet Computer\b"),
    re.compile(r"\bdfinity\b", re.IGNORECASE),
    re.compile(r"\b(?:icp0\.io|ic0\.app|icp-api\.io)\b", re.IGNORECASE),
    re.compile(r"\b(?:canisterworm|canistersprawl|teampcp|shai[- ]hulud)\b", re.IGNORECASE),
)


def has_icp_context(text: str) -> bool:
    """True when ``text`` clearly refers to the Internet Computer."""
    return any(pattern.search(text) for pattern in _ICP_CONTEXT)
