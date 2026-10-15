Status: VERIFIED

# ICP ledger transfers to the Cycles Minting Canister (CMC top-ups)

## Summary

The Cycles Minting Canister (CMC, `rkp4c-7iaaa-aaaaa-aaaca-cai`) converts ICP into cycles. To top up a
canister, the payer sends an ICP ledger transfer to the account identifier
`AccountIdentifier(CMC, Subaccount::from(&target_canister))`. The transfer uses memo
`MEMO_TOP_UP_CANISTER = 0x50555054` (`'TPUP'`) and is followed by a `notify_top_up { block_index, canister_id }`
update call to the CMC. Because the target canister is encoded in the destination subaccount, the ledger
alone shows which canister was funded and by which ICP account. That lets us link a malicious canister to its
funding wallet without calling the CMC.

The derivation below was reproduced locally with Python stdlib against official DFINITY test vectors (see
"How the derivation was checked"). This VERIFIED status covers the derivation only. SPEC still requires
the collector to match one known on-chain top-up before it relies on the derivation in production
(see Open questions).

## Endpoints

All read-only. None of these were called during this research; only their documentation and interface
definitions were read.

1. **ICP Ledger API (dashboard REST)**: `https://ledger-api.internetcomputer.org`. The official docs give the
   base URL as `https://ledger-api.internetcomputer.org/api/v1/`. Swagger is at `/swagger-ui/` and the spec at `/openapi.json`.
   - `GET /v2/accounts/{account_identifier}/transactions`: cursor pagination (`before`/`after`), `limit`
     default 10, max 100. Filters: `from_account`, `to_account`, `transfer_type`
     (`transfer,mint,burn,approve`), `max_block_index`, `created_at_start`, `created_at_end`, `block_height`,
     `transaction_hash`, `sort_by` (`-block_height` etc.).
   - `GET /v2/transactions?to_account=<cmc_topup_account>` is the same set of filters without the path account.
   - `GET /transactions/{transaction_hash}`, `GET /accounts/{account_identifier}`.
   - The v1 `/accounts/{id}/transactions` and `/transactions` endpoints (offset pagination) are marked deprecated.
   - No memo filter exists as a query parameter. `memo` and `icrc1_memo` appear only in responses.
2. **ICP Rosetta `/search/transactions`** (POST, Mesh/Rosetta Data API). Needs a self-hosted node
   (`dfinity/rosetta-api` docker image, port 8081) or a third-party host (Validation Cloud). DFINITY documents
   no public endpoint. Body: `{"network_identifier": {"blockchain": "Internet Computer", "network":
   "00000000000000020101"}, "account_identifier": {"address": "<hex>"}, "limit": N, "offset": N,
   "max_block": N}`. Optional `transaction_identifier` and `type`. The server's `MAX_SEARCH_LIMIT` is 10 000
   (`rs/rosetta-api/icp/src/request_handler.rs`), and docs say a search covers at most 10 000 blocks.
3. **ICP index canister** (`qhbym-qaaaa-aaaaa-aaafq-cai`), query methods (from `rs/ledger_suite/icp/index/index.did`):
   - `get_account_identifier_transactions : (record { account_identifier : text; start : opt nat64;
     max_results : nat64 }) -> (variant { Ok : record { balance : nat64; transactions : vec
     TransactionWithId; oldest_tx_id : opt nat64 }; Err : ... }) query`
   - `get_blocks : (record { start : nat; length : nat }) -> (record { blocks : vec vec nat8; chain_length : nat64 }) query`
   - The index canister has **no** `query_blocks`. `query_blocks : (GetBlocksArgs{start; length}) ->
     (QueryBlocksResponse) query` lives on the **ICP ledger canister** (`ryjl3-tyaaa-aaaaa-aaaba-cai`). Its
     response can point to archive canisters (`archived_blocks`) for older ranges.

## Auth

- Ledger API: the official docs state the dashboard APIs "are read-only and require no authentication".
- Rosetta: none on a self-hosted node. A third-party host may require an API key. That key is a secret, so it
  goes in env config only and never in files.
- Index and ledger canisters: anonymous query calls through a boundary node (`icp-api.io`) need no identity.
  SPEC D6 permits query calls only. Never send update calls such as `notify_top_up` or `transfer`.

## Rate limits

- Ledger API: none documented. The OpenAPI spec caps page size at 100 transactions (50 accounts). The
  collector should throttle conservatively (≤1 req/s) and back off on HTTP 429/5xx.
- Rosetta: limited by the node operator. The server caps a search at 10 000.
- Canister queries: boundary-node rate limits apply but are not documented per method. Use small `max_results`
  (≤100) and paginate with `start`.

## Sample response

This sample is illustrative and was **built from the OpenAPI schema field names. It is not a captured
response**, and no live endpoint was called:

```json
{
  "blocks": [{
    "block_height": "<string>", "block_hash": "<hex>", "transaction_hash": "<hex>",
    "transfer_type": "transfer", "amount": "<e8s string>", "fee": "10000",
    "memo": "1347768404", "icrc1_memo": null, "created_at": 0,
    "from_account_identifier": "<payer hex>",
    "to_account_identifier": "<CMC top-up account hex>",
    "spender_account_identifier": null
  }]
}
```

The `blocks` envelope key is unconfirmed (see Open questions). For a top-up, `memo` is `1347768404` (=
`0x50555054`) and `to_account_identifier` is the derived CMC top-up account of the target canister.

## Account identifier derivation

Source: `rs/ledger_suite/icp/src/account_identifier.rs` (dfinity/ic) and
`packages/canisters/src/ledger/icp/account_identifier.ts` (dfinity/ic-js):

```
h          = SHA224( b"\x0Aaccount-id" || principal_bytes || subaccount32 )   # subaccount defaults to 32 zero bytes
checksum   = CRC32(h) as 4 bytes big-endian                                    # crc32fast / zlib.crc32
account_id = checksum || h        (32 bytes, shown as 64 lowercase hex chars)
```

To decode a principal from text, strip the dashes, uppercase, pad to a multiple of 8 with `=`, then base32-decode.
The first 4 bytes are the big-endian CRC32 of the remaining bytes, and those remaining bytes are the principal.

## CMC top-up subaccount derivation

Source: `impl From<&PrincipalId> for Subaccount` (dfinity/ic `account_identifier.rs`) and `SubAccount.fromPrincipal`
(ic-js):

```
sub = [len(principal_bytes)] || principal_bytes || zero padding to 32 bytes
top_up_account = account_id(CMC principal, sub(target_canister))
```

- Memos are defined in `rs/nns/cmc/src/lib.rs`: `MEMO_CREATE_CANISTER = 0x41455243 // 'CREA'`,
  `MEMO_TOP_UP_CANISTER = 0x50555054 // 'TPUP'`, `MEMO_MINT_CYCLES = 0x544e494d // 'MINT'`. Read as a u64,
  the ASCII spelling is little-endian ('TPUP' is reversed in the big-endian hex). dfx hardcodes
  `MEMO_TOP_UP_CANISTER: u64 = 1347768404` (`src/dfx/src/commands/ledger/top_up.rs`). Per the CMC comment,
  the operation can also be indicated via `icrc1_memo`, and new memo values may be added later.
- Flow (dfx `ledger top-up` and `operations/cmc.rs`): `transfer_cmc` sends ICP to
  `AccountIdentifier::new(MAINNET_CYCLE_MINTER_CANISTER_ID, Some(Subaccount::from(&to_principal)))`
  with memo TPUP, then calls `notify_top_up(NotifyTopUpArg { block_index, canister_id })` (an update call).
  The result is `Ok: Cycles`, or one of `Err: Refunded | Processing | TransactionTooOld | InvalidTransaction | Other`.
  A `Refunded` error means the CMC sent the ICP back, which appears as a second ledger transfer.
- For create-canister (`'CREA'`), the subaccount is derived from the **controller/creator principal**, not a
  canister id. The same function applies but identifies the paying principal instead of the canister.

## How the derivation was checked

Test vectors come from `packages/canisters/src/ledger/icp/account_identifier.spec.ts` in dfinity/ic-js (file last
changed 2026-04-16), plus the checksum vector from dfinity/ic `account_identifier.rs` tests. I reproduced them
with stdlib only (`hashlib.sha224`, `zlib.crc32`, `base64.b32decode`), running
`python3 -I acct.py`, a scratch script that implements exactly the formulas above:

| Input | Expected (from source) | Computed | Match |
|---|---|---|---|
| acct(`bwz3t-ercuj-owo6s-4adfr-sbu4o-l72hg-kfhc5-5sapm-tj6bn-3scho-uqe`, sub=0) | `df4ad42194201b15ecbbe66ff68559a126854d8141fd935c5bd53433c2fb28d4` | same | yes |
| same principal, sub=fromID(1) (31 zero bytes + `01`) | `16c3ca805340f0e426023bea907488100f93d5e2a654644d5d6881c7a7b2071e` | same | yes |
| same principal, sub=fromID(255) | `f9d8833b97d142d888d00606e2cadec4e70b9798d71c35091a20daaa14082e67` | same | yes |
| subFromPrincipal(`kb4lg-bqaaa-aaaab-qabfq-cai`) (a canister id) | `[10,0,0,0,0,0,48,0,75,1,1,0,...0]` | same | yes |
| subFromPrincipal(`bl375-kyc3r-...-p7kkm-oae`) | `[29,2,220,105,...,28,2,0,0]` | same | yes |
| subFromPrincipal(`aaaaa-aa`) | 32 zero bytes | same | yes |
| CRC32 of 28 zero bytes (ic Rust test) | `807077e9` | `807077e9` | yes |

The principal-text CRC32 check passed for every principal decoded. Result: **all 7 vectors reproduced**.
`hex(1347768404) == 0x50555054` was also confirmed.

**Computed top-up accounts for seed canisters.** These were computed, not observed: no on-chain transfer to
them has been confirmed. CMC principal bytes are `00000000000000040101`.

| Target canister | Top-up subaccount (hex) | CMC top-up account identifier |
|---|---|---|
| `tdtqy-oyaaa-aaaae-af2dq-cai` | `0a0000000000802e870101` + 21×`00` | `d06453844959546d8359fe460caa45eb261331cec1aea9ecb59a0675b2246378` |
| `cjn37-uyaaa-aaaac-qgnva-cai` | `0a000000000050336a0101` + 21×`00` | `59df9c2352f8826adcf943ad65c8415cd814fb3f9b650c5d1514be7e81c0b30b` |

## How the collector will use it

1. For each seed or discovered canister id, derive `top_up_account` offline (pure function, unit-tested against
   the vectors above, kept as fixtures).
2. Query transfers **to** that account. Use Ledger API `/v2/accounts/{top_up_account}/transactions`
   (`transfer_type=transfer`, cursor-paginated, ≤100 per page), with the index canister
   `get_account_identifier_transactions` as a fallback through a query-only client.
3. Keep only transfers whose `memo == 1347768404`, or whose `icrc1_memo` decodes to the TPUP value. Record
   `from_account_identifier` (the funding wallet), amount, block height and timestamp as raw evidence
   in the raw store.
4. Pivot: list other outgoing transfers from the funding account to CMC top-up accounts, then
   reverse-match each against the derived top-up accounts of known canisters. A payer account that funds
   several flagged canisters is a strong clustering signal. An unknown destination cannot be inverted
   (SHA224 is one-way), so it stays an unattributed "CMC top-up to unknown canister" edge.
5. Do not call `notify_top_up`, transfer, or any other update method.

## Open questions

- Before use, check the derivation against one known on-chain top-up: find a dfx/NNS-dapp top-up whose
  target canister is public, confirm that `to_account_identifier` equals the derived account and that memo is
  1347768404. SPEC requires this.
- The Ledger API base path is unclear: the docs say `/api/v1/`, but the OpenAPI spec lists bare `/v2/...` and
  `/transactions` paths with no `servers` entry. The response envelope key (`blocks` vs other) is also
  unconfirmed. Settle both with the first live call that SPEC D6 allows.
- The OpenAPI spec declares some v2 filters as `in: path`, which looks like a spec bug.
- The index canister id `qhbym-qaaaa-aaaaa-aaafq-cai` comes from general knowledge; confirm it against the NNS canister list.
- How often top-ups use `icrc1_transfer` with `icrc1_memo` instead of the legacy u64 memo, and how the
  Ledger API renders such memos.
- NNS-dapp and wallets other than dfx may top up through other paths (e.g. cycles ledger `withdraw`). Those
  leave no CMC subaccount trail on the ICP ledger.

## URLs consulted

All accessed 2026-10-15.

- https://raw.githubusercontent.com/dfinity/ic/master/rs/nns/cmc/src/lib.rs
- https://raw.githubusercontent.com/dfinity/ic/master/rs/nns/cmc/cmc.did
- https://raw.githubusercontent.com/dfinity/ic/master/rs/ledger_suite/icp/src/account_identifier.rs
- https://raw.githubusercontent.com/dfinity/ic/master/rs/ledger_suite/icp/index/index.did
- https://github.com/dfinity/ic/blob/8ac830931a8b2ca633064197322c2ae535650060/rs/ledger_suite/icp/ledger.did
- https://github.com/dfinity/ic/blob/8ac830931a8b2ca633064197322c2ae535650060/rs/rosetta-api/common/rosetta_core/src/request_types.rs
- https://github.com/dfinity/ic/blob/8ac830931a8b2ca633064197322c2ae535650060/rs/rosetta-api/icp/src/request_handler.rs
- https://raw.githubusercontent.com/dfinity/ic/master/rs/rosetta-api/examples/icp/python/rosetta_client.py
- https://github.com/dfinity/ic-js/blob/main/packages/canisters/src/ledger/icp/account_identifier.spec.ts
- https://github.com/dfinity/ic-js/blob/main/packages/canisters/src/ledger/icp/account_identifier.ts
- https://raw.githubusercontent.com/dfinity/sdk/master/src/dfx/src/lib/operations/cmc.rs
- https://github.com/dfinity/sdk/blob/271392a3b7746df539925a6333b4cd7ddc9f1972/src/dfx/src/commands/ledger/top_up.rs
- https://docs.internetcomputer.org/references/ic-dashboard-api/
- https://docs.internetcomputer.org/guides/digital-assets/rosetta.md
- https://ledger-api.internetcomputer.org/openapi.json
