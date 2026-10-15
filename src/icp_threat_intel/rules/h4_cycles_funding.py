"""H4: cycles funding trail (stub)."""

from typing import ClassVar

from icp_threat_intel.rules.stub import StubRule

CMC_CANISTER = "rkp4c-7iaaa-aaaaa-aaaca-cai"


class H4CyclesFunding(StubRule):
    """Cycles funding trail: who pays to keep an IOC canister alive. STUB.

    Precedent (SPEC section 3): the CanisterWorm (``tdtqy-oyaaa-aaaae-af2dq-cai``) and
    CanisterSprawl (``cjn37-uyaaa-aaaac-qgnva-cai``) canisters must burn cycles to keep
    answering; someone tops them up through the Cycles Minting Canister.

    Required signals, once the ledger collector exists (docs/sources/icp-ledger-cmc.md):

    * ``cmc_topup``: a ``ledger.cmc_topup`` event, an ICP transfer to the CMC
      (``rkp4c-7iaaa-aaaaa-aaaca-cai``) whose subaccount is the IOC canister's top-up
      subaccount and whose memo is ``TPUP`` (0x50555054).
    * ``ioc_canister``: the topped-up canister is an IOC.

    Planned scoring: higher when one funding account tops up several IOC canisters, or when
    top-ups cluster around campaign waves.
    """

    id: ClassVar[str] = "H4"
    hypothesis: ClassVar[str] = "Cycles funding trail"
    required_signals: ClassVar[frozenset[str]] = frozenset({"cmc_topup", "ioc_canister"})
