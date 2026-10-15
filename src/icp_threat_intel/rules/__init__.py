"""Detection rules H1-H6: pure functions over events, one module per hypothesis."""

from icp_threat_intel.rules.base import BaseRule
from icp_threat_intel.rules.h1_dead_drop import H1DeadDropC2
from icp_threat_intel.rules.h2_lifecycle import H2KnownBadLifecycle
from icp_threat_intel.rules.h3_supply_chain import H3SupplyChainReference
from icp_threat_intel.rules.h4_cycles_funding import H4CyclesFunding
from icp_threat_intel.rules.h5_governance import H5GovernanceResponse
from icp_threat_intel.rules.h6_mass_creation import H6MassCreation

REGISTRY: dict[str, type[BaseRule]] = {
    rule.id: rule
    for rule in (
        H1DeadDropC2,
        H2KnownBadLifecycle,
        H3SupplyChainReference,
        H4CyclesFunding,
        H5GovernanceResponse,
        H6MassCreation,
    )
}


def all_rules() -> list[BaseRule]:
    """One instance of every registered rule, in id order."""
    return [REGISTRY[rule_id]() for rule_id in sorted(REGISTRY)]


__all__ = ["REGISTRY", "all_rules"]
