"""Documented extension points that are deliberately not implemented (SPEC section 8).

* LLM classification: no LLM classifies anything yet. A future ``LlmClassifier`` would
  read already-stored, redacted event payloads (never live bodies), return a label plus a
  rationale, and its output would be one more *candidate* signal. It could never verify a
  detection on its own, because the two-signal rule counts source types, not opinions.
* Wasm static analysis: canister module bytes cannot be downloaded from the IC (SPEC §3).
  A future ``WasmAnalyzer`` would run ``ic-wasm`` / ``wasm-tools`` over modules obtained
  legitimately from public source repositories, matched to on-chain module hashes, in a
  sandbox without network access.

Both are Protocols only; ``NOT_IMPLEMENTED`` lists them so tests and docs can check that
nothing silently pretends to provide them.
"""

from collections.abc import Sequence
from typing import Protocol

from icp_threat_intel.core.models import Event

NOT_IMPLEMENTED = ("llm_classifier", "wasm_analyzer")


class LlmClassifier(Protocol):
    """Labels stored, redacted events; output is a candidate signal only."""

    def classify(self, events: Sequence[Event]) -> list[tuple[str, str]]: ...


class WasmAnalyzer(Protocol):
    """Analyses a Wasm module obtained from source (never from the IC) by its sha256."""

    def analyze(self, module_sha256: str, module: bytes) -> dict[str, object]: ...
