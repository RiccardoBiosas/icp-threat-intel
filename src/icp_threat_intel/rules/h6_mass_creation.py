"""H6: mass creation and malformed modules (stub; hypothesis is unverified)."""

from typing import ClassVar

from icp_threat_intel.rules.stub import StubRule


class H6MassCreation(StubRule):
    """Mass canister creation with opaque, identical modules. STUB.

    Precedent: UNVERIFIED. On 1 September 2026 an ICP community account claimed hundreds
    of malicious canisters and malformed Wasm modules in an "AI-enabled attack"; no
    technical post-mortem exists (SPEC section 3). This rule tests that claim as a
    hypothesis; it is not a known fact.

    Required signals, once the census (T15) emits them:

    * ``creation_burst``: ``census.canister_added`` events clustered on one subnet or under
      one controller within minutes.
    * ``opaque_module``: those canisters have no public Candid and share small or identical
      module hashes (module bytes cannot be downloaded, so the hash is all we see).
    """

    id: ClassVar[str] = "H6"
    hypothesis: ClassVar[str] = "Mass creation and malformed modules (unverified)"
    required_signals: ClassVar[frozenset[str]] = frozenset({"creation_burst", "opaque_module"})
