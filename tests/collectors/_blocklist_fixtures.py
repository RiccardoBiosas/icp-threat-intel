"""Synthetic PhishDestroy-shaped blocklists (``list.json``: a JSON array of hostnames).

Every hostname is invented except the public SPEC §3 seed canister. Canister ids come from
``synthetic_canister``, so they are valid principals with correct checksums.
"""

import json

from icp_threat_intel.core.ic_encoding import principal_to_text

IOC_CANISTER = "tdtqy-oyaaa-aaaae-af2dq-cai"  # SPEC §3 seed IOC


def synthetic_canister(n: int) -> str:
    """A valid canister id (8-byte index + 0x01 0x01 suffix), clearly not a real one."""
    return principal_to_text((0xFFFF_0000_0000_0000 + n).to_bytes(8, "big") + b"\x01\x01")


CAN_A = synthetic_canister(1)
CAN_B = synthetic_canister(2)
CAN_C = synthetic_canister(3)

LIST = json.dumps(
    [
        "0-synthetic-phish.example",
        f"{CAN_A}.icp0.io",
        f"{CAN_A}.raw.icp0.io",  # same canister twice
        f"{CAN_B}.ic0.app",
        CAN_C.replace("-", "") + ".icp0.io",  # hyphens stripped, as some entries are
        "zzzzzzzzzzzzzzzzzzzzcai.icp0.io",  # canister-shaped but bad checksum
        f"{IOC_CANISTER}.icp0.io",
        "custom-name.icp0.io",  # gateway host without a canister id
        "icp0.io.evil.example",  # lookalike, not a gateway host
        "fake-internet-identity.example",
        42,  # not a string
    ]
).encode()
