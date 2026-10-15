"""Signals-feed keyword list and IOC value matching (beyond canister ids)."""

import pytest

from icp_threat_intel.core.enums import IocType
from icp_threat_intel.parsers.signals_keywords import IocTerm, find_ioc_terms, ioc_term, keywords_in

MATCHES = [
    ("malicious", "this package is malicious"),
    ("malware", "Malware in the release"),
    ("phishing", "a phishing site"),
    ("scam", "the scammers moved on"),
    ("exploit", "an exploit for the canister"),
    ("backdoor", "backdoored build"),
    ("c2", "it acts as command-and-control"),
    ("exfiltration", "data exfiltration"),
    ("denylist", "the canister was denylisted"),
    ("takedown", "after the take-down"),
    ("abuse", "I filed an abuse report"),
    ("abuse", "abusive frontend"),
    ("compromised", "my account was compromised"),
    ("worm", "a self-propagating worm"),
    ("worm", "the npm worm"),
    ("drainer", "wallet drainer"),
    ("stolen", "tokens were stolen"),
    ("hacked", "we got hacked"),
    ("hacked", "the hackers used"),
    ("supply_chain", "a supply-chain attack on npm"),
    ("install_hook", "a malicious postinstall script"),
    ("dead_drop", "used as a dead drop"),
    ("dropper", "the dropper writes a binary"),
    ("stealer", "an infostealer"),
    ("stealer", "credential harvesting"),
    ("rug_pull", "this was a rug pull"),
    ("impersonation", "impersonating the NNS"),
    ("impersonation", "a fake airdrop"),
    ("seed_phrase", "they stole my seed phrase"),
    ("campaign", "CanisterWorm is back"),
    ("campaign", "TeamPCP again"),
    ("campaign", "shai-hulud wave"),
]

NOT_MATCHES = [
    "a quick hack to fix the build",  # bare "hack" dropped
    "don't abuse the query API",  # bare "abuse" dropped
    "a design compromise",  # "compromise" (noun) dropped
    "the worm emoji",  # bare "worm" dropped
    "postinstall runs the build",  # install hooks only as script/hook
    "store your seed phrase offline",  # seed phrase only with theft context
    "a hackathon and a scampi",
    "the JSON payload is small",
]


@pytest.mark.parametrize(("label", "text"), MATCHES)
def test_keyword_matches(label: str, text: str) -> None:
    assert label in keywords_in(text)


@pytest.mark.parametrize("text", NOT_MATCHES)
def test_noise_does_not_match(text: str) -> None:
    assert keywords_in(text) == []


def test_keywords_sorted_and_unique() -> None:
    assert keywords_in("malware, MALWARE and a phishing malware") == ["malware", "phishing"]


@pytest.mark.parametrize(
    ("ioc_type", "value", "term"),
    [
        (IocType.PACKAGE_VERSION, "npm:@opengov/form-renderer@0.2.20", "@opengov/form-renderer"),
        (IocType.PACKAGE_VERSION, "pypi:somepkg==1.2.3", "somepkg"),
        (IocType.PACKAGE_VERSION, "npm:pgserve@1.1.11", "pgserve"),
        (IocType.FILE_PATH, "/tmp/pglog", "/tmp/pglog"),
        (IocType.SYSTEMD_UNIT, "pgmon.service", "pgmon.service"),
        (IocType.URL, "https://x.raw.icp0.io/", "https://x.raw.icp0.io"),
        (IocType.DOMAIN, "Evil.Example", "evil.example"),
    ],
)
def test_ioc_term_normalisation(ioc_type: IocType, value: str, term: str) -> None:
    assert ioc_term(ioc_type, value) == IocTerm(ioc_type.value, term)


@pytest.mark.parametrize("ioc_type", [IocType.CANISTER_ID, IocType.ACCOUNT])
def test_ioc_types_not_matched_as_text(ioc_type: IocType) -> None:
    assert ioc_term(ioc_type, "anything") is None


def test_short_terms_are_ignored() -> None:
    assert ioc_term(IocType.PACKAGE_VERSION, "npm:ab@1.0.0") is None


TERMS = (
    IocTerm("package_version", "@opengov/form-renderer"),
    IocTerm("package_version", "pgserve"),
    IocTerm("file_path", "/tmp/pglog"),
    IocTerm("systemd_unit", "pgmon.service"),
    IocTerm("url", "https://x.raw.icp0.io"),
)


def test_find_ioc_terms() -> None:
    text = (
        "After installing @opengov/form-renderer 0.2.20 I found /tmp/pglog and a "
        "pgmon.service unit; it polled https://x.raw.icp0.io/ every hour. PGSERVE too."
    )
    assert find_ioc_terms(text, TERMS) == [
        "/tmp/pglog",
        "@opengov/form-renderer",
        "https://x.raw.icp0.io",
        "pgmon.service",
        "pgserve",
    ]


@pytest.mark.parametrize(
    "text",
    [
        "/tmp/pglogs is a different file",
        "pgserver is another package",
        "@opengov/form-renderer-extra is unrelated",
        "my-pgserve fork",
    ],
)
def test_find_ioc_terms_needs_whole_terms(text: str) -> None:
    assert find_ioc_terms(text, TERMS) == []
