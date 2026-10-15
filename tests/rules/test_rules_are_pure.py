"""Rules never touch the network, the database or collectors (PLAN rule contract 3)."""

from pathlib import Path

import pytest

from tests.guardrails._support import SRC, imported_modules

FORBIDDEN = ("httpx", "socket", "sqlalchemy", "icp_threat_intel.core.http",
             "icp_threat_intel.core.ic_client", "icp_threat_intel.collectors")  # fmt: skip
RULE_FILES = sorted((SRC / "rules").glob("*.py"))


def test_rule_modules_found() -> None:
    names = {p.name for p in RULE_FILES}
    assert {"base.py", "engine.py", "h1_dead_drop.py", "h6_mass_creation.py"} <= names


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: p.name)
def test_rule_module_imports_nothing_impure(path: Path) -> None:
    bad = [
        name
        for name in imported_modules(path)
        if any(name == f or name.startswith(f + ".") for f in FORBIDDEN)
    ]
    assert bad == [], f"{path.name} imports {bad}"


def test_rule_modules_do_not_read_the_clock() -> None:
    for path in RULE_FILES:
        text = path.read_text(encoding="utf-8")
        assert ".now(" not in text and "time.time" not in text, path.name
