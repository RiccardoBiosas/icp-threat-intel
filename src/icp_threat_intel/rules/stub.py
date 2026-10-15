"""Base for rules whose collectors do not exist yet: documented, registered, inert."""

from collections.abc import Sequence

import structlog

from icp_threat_intel.core.models import Detection, Event
from icp_threat_intel.rules.base import BaseRule

log = structlog.get_logger(__name__)


class StubRule(BaseRule):
    """A rule stub: ``score`` logs ``rule_stub`` with the rule id and returns ``None``."""

    stub = True

    def signals(self, events: Sequence[Event]) -> dict[str, list[Event]]:
        return {}

    def score(self, events: Sequence[Event]) -> Detection | None:
        log.info("rule_stub", rule_id=self.id, events=len(events))
        return None
