"""Smoke test: the package imports, the CLI lists every SPEC command, the protocols exist."""

from typing import Protocol

import pytest
from typer.testing import CliRunner

import icp_threat_intel
from icp_threat_intel.cli.app import app
from icp_threat_intel.core import interfaces

runner = CliRunner()

STAGE_PROTOCOLS = (
    "Collector",
    "RawStore",
    "Parser",
    "Enricher",
    "Rule",
    "Verifier",
    "Notifier",
    "Exporter",
)
TOP_LEVEL_COMMANDS = (
    "collect",
    "census",
    "parse",
    "enrich",
    "score",
    "verify",
    "digest",
    "publish",
    "db",
    "canister",
)


def test_package_has_version() -> None:
    assert icp_threat_intel.__version__


@pytest.mark.parametrize("name", STAGE_PROTOCOLS)
def test_stage_protocol_exists(name: str) -> None:
    proto = getattr(interfaces, name)
    assert issubclass(proto, Protocol)  # type: ignore[arg-type]
    assert name in interfaces.__all__


def test_help_lists_every_command() -> None:
    result = runner.invoke(app, ["--help"], terminal_width=200)
    assert result.exit_code == 0
    for command in TOP_LEVEL_COMMANDS:
        assert command in result.output


@pytest.mark.parametrize(
    ("group", "commands"), [("db", ("migrate", "seed")), ("canister", ("inspect",))]
)
def test_subcommands_listed(group: str, commands: tuple[str, ...]) -> None:
    result = runner.invoke(app, [group, "--help"], terminal_width=200)
    assert result.exit_code == 0
    for command in commands:
        assert command in result.output


def test_canister_inspect_accepts_offline_flag() -> None:
    result = runner.invoke(app, ["canister", "inspect", "--help"], terminal_width=200)
    assert result.exit_code == 0
    assert "--offline" in result.output


def test_stub_exits_two() -> None:
    result = runner.invoke(app, ["census"])
    assert result.exit_code == 2
