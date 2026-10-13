"""Settings from ``ICP_THREAT_INTEL_*`` environment variables (SPEC D7).

Secrets come from the environment only. The two optional API keys use the names SPEC D3
gives them, without the prefix.
"""

import os
from collections.abc import Mapping

from pydantic import BaseModel, ConfigDict, Field

PREFIX = "ICP_THREAT_INTEL_"
_UNPREFIXED = {"abusech_auth_key": "ABUSECH_AUTH_KEY", "github_token": "GITHUB_TOKEN"}


class Settings(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")

    database_url: str = "sqlite:///./icp_threat_intel.db"
    contact: str | None = None
    log_level: str = "INFO"
    census_max_canisters: int = Field(default=50_000, gt=0)
    record: bool = False
    webhook_url: str | None = None
    github_code_search: bool = False
    abusech_auth_key: str | None = Field(default=None, repr=False)
    github_token: str | None = Field(default=None, repr=False)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Settings":
        """Build settings from ``env`` (default ``os.environ``); empty values count as unset."""
        source = os.environ if env is None else env
        values: dict[str, str] = {}
        for name in cls.model_fields:
            key = _UNPREFIXED.get(name, PREFIX + name.upper())
            value = source.get(key, "").strip()
            if value:
                values[name] = value
        return cls.model_validate(values)
