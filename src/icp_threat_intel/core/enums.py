"""Enumerations shared by every stage (values match the PLAN.md data model)."""

from enum import StrEnum


class SourceType(StrEnum):
    IC_READ_STATE = "ic_read_state"
    RAW_GATEWAY = "raw_gateway"
    DASHBOARD_API = "dashboard_api"
    ICP_LEDGER = "icp_ledger"
    NNS = "nns"
    NPM = "npm"
    PYPI = "pypi"
    THREATFOX = "threatfox"
    URLHAUS = "urlhaus"
    GITHUB_ADVISORIES = "github_advisories"
    VENDOR_RSS = "vendor_rss"
    SIGNALS_FEED = "signals_feed"


class DetectionStatus(StrEnum):
    CANDIDATE = "candidate"
    VERIFIED = "verified"
    DISMISSED = "dismissed"


class CanisterStatus(StrEnum):
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    UNKNOWN = "unknown"


class IocType(StrEnum):
    CANISTER_ID = "canister_id"
    URL = "url"
    DOMAIN = "domain"
    PACKAGE_VERSION = "package_version"
    FILE_PATH = "file_path"
    SYSTEMD_UNIT = "systemd_unit"
    ACCOUNT = "account"


class Ecosystem(StrEnum):
    NPM = "npm"
    PYPI = "pypi"
