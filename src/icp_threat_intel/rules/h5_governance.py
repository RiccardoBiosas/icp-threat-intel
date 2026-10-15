"""H5: governance response (stub)."""

from typing import ClassVar

from icp_threat_intel.rules.stub import StubRule


class H5GovernanceResponse(StubRule):
    """Governance response to IOC canisters: what was done and how fast. STUB.

    Precedent (SPEC section 3): after CanisterWorm was disclosed, about 26 hours passed
    before ``tdtqy-oyaaa-aaaae-af2dq-cai`` was disabled, and a disabled canister can be
    re-enabled. docs/sources/nns-governance.md found no proposal naming the canister: the
    disable was probably a boundary-node policy block, so the absence of a proposal must
    never be read as "not disabled".

    Required signal, once the NNS collector exists:

    * ``proposal_reference``: a ``proposal.references_target`` event, an NNS proposal whose
      payload or summary names an IOC canister or its subnet (matched client-side with the
      canister-ID regex; the Dashboard API cannot filter by canister).

    Planned scoring: time-to-action in hours from first IOC report to the action, and
    proposals that revert an earlier stop. Gateway 451 ``denylisted`` answers (already in
    ``gateway.body_observed``) are the other takedown signal.
    """

    id: ClassVar[str] = "H5"
    hypothesis: ClassVar[str] = "Governance response"
    required_signals: ClassVar[frozenset[str]] = frozenset({"proposal_reference"})
