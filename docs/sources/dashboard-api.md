Status: EXPERIMENTAL

# IC Dashboard API (ic-api.internetcomputer.org)

## Summary

The public API behind the ICP Dashboard. The OpenAPI 3.0.3 spec (`info.title` "Public Dashboard API", `info.version` "v3") is at
`https://ic-api.internetcomputer.org/api/v3/openapi.json`. Swagger UI is at `/api/v3/swagger`. The spec has both `/api/v3/...` and `/api/v4/...` paths.
DFINITY's ic-dashboard skill recommends v4 for canisters and subnets, because v4 uses cursor pagination.

Every path below appears in the spec. Status is EXPERIMENTAL because the spec documents **no 200 response schema** for
`/api/v3/canisters/{canister_id}`, `/api/v3/canisters` or `/api/v3/proposals[/{id}]`. The canister fields we need
(`controllers`, `module_hash`, `updated_at`, ...) therefore cannot be confirmed from official docs. See Open questions.

## Endpoints

All are `GET`, read-only, JSON by default. Many list endpoints also accept `format=csv`.

| Path | Params (from spec) | What we use it for |
|---|---|---|
| `/api/v3/canisters/{canister_id}` | path `canister_id`, pattern `^([a-zA-Z0-9]{5}-){4}[a-zA-Z0-9]{3}$` | Single-canister enrichment: subnet, controllers, module hash, type, timestamps. **Response fields UNVERIFIED.** |
| `/api/v3/canisters/{canister_id}/name` | path `canister_id` | Display name, if any |
| `/api/v3/canisters` | `subnet_id`, `limit` (default 50, max 100), `offset` (default 0), `max_canister_index`, `has_name`, `controller_id`, `language`, `sort_by` (default `canister_id`) | Legacy offset-paged list. Filter by subnet or controller. |
| `/api/v4/canisters` | `subnet_id`, `controller_id`, `has_name`, `language[]`, `canister_type[]`, `query` (2-100 chars), `sort_by` (canister_id, canister_type, controllers, language, subnet_id, each also `-`-prefixed), `after`/`before` (array, 1-2 items), `limit` (default 50, max 100) | Preferred list. Canisters on a subnet, or sharing a controller (pivot from an IOC canister to siblings). |
| `/api/v4/canisters/count` | same filters as `/api/v4/canisters`, plus `node_class` (mainnet, cloud_engine, all) | Canister counts per subnet or controller |
| `/api/v3/subnets` | `dc_id`, `sev_enabled` | Legacy subnet list |
| `/api/v3/subnets/{subnet_id}` | path `subnet_id`, pattern `^([a-zA-Z0-9]{5}-){10}[a-zA-Z0-9]{3}$` | Legacy subnet detail |
| `/api/v4/subnets` | `dc_id`, `subnet_type[]`, `subnet_authorization[]`, `subnet_specialization[]`, `sev_enabled`, `after`/`before`, `limit` (default 20), `sort_by` (incl. `total_canisters`), `include_replica_versions` | Subnet list with canister counts. Response schema `ListSubnetsResponse` is documented. |
| `/api/v4/subnets/{subnet_id}` | path `subnet_id` | Subnet detail. Response schema `Subnet` is documented (includes `total_canisters`, `running_canisters`, `stopped_canisters`). |
| `/api/v4/subnets/count` | subnet filters | `CountSubnetsResponse` {`total`} |
| `/api/v3/proposals` | `limit` (default 50, max 100), `offset`, `max_proposal_index`, `include_topic[]`, `include_status[]`, `include_action[]`, `include_action_nns_function[]`, `include_proposer_group[]`, `include_classification[]`, `include_reward_status[]`, `proposer`, `manage_neuron_id` | NNS proposals by topic or status. Used to find governance action against an IOC canister. |
| `/api/v3/proposals/{proposal_id}` | path `proposal_id` (int >= 0) | Proposal detail (payload, timestamps). **Response fields UNVERIFIED.** |
| `/api/v3/latest-proposal-id`, `/api/v3/proposals-count` | none | Incremental sync watermark |
| `/api/v3/` | none | Smoke test (returns 200, per the DFINITY skill) |

Enum values relevant to us, quoted from the spec:
- `include_topic`: includes `TOPIC_APPLICATION_CANISTER_MANAGEMENT`, `TOPIC_PROTOCOL_CANISTER_MANAGEMENT`, `TOPIC_NETWORK_CANISTER_MANAGEMENT`, `TOPIC_SUBNET_MANAGEMENT`, `TOPIC_GOVERNANCE`, `TOPIC_SERVICE_NERVOUS_SYSTEM_MANAGEMENT` (20 values in total).
- `include_status`: `UNKNOWN`, `UNSPECIFIED`, `OPEN`, `REJECTED`, `ADOPTED`, `EXECUTED`, `FAILED`.
- `include_action`: includes `StopOrStartCanister`, `UpdateCanisterSettings`, `InstallCode`, `TakeCanisterSnapshot`, `LoadCanisterSnapshot`, `ExecuteNnsFunction`, `Motion`.
- `canister_type` (v4): archive, btc_checker, dapp, faucet, governance, index, ledger, minter, orchestrator, root, swap.

**Filtering proposals by canister id: not supported.** `/api/v3/proposals` has no canister-id parameter. The collector must page
through the relevant topics and actions and match the canister id inside each proposal's payload or summary, client-side.

Not used by this project: the `/api/v4/dashboards`, `user-icp-accounts`, `user-neurons` and `user-account-neuron-links` paths
(POST/PUT/DELETE for an "authenticated user"), plus the metrics, nodes and neurons paths.

## Auth

None for the read endpoints we use. The spec defines no `securitySchemes`. Only the v4 user/dashboard endpoints refer to an
"authenticated user", and we never call them. We send no credentials.

## Rate limits

Not documented in the OpenAPI spec. A DFINITY forum post (user "jeff", 2024-04-05) says ic-api, icrc-api and sns-api are
"rate-limited to 50 requests per second". It is not an official doc and the author's affiliation is not stated.
**Our conservative default:** 1 request/second per host, sequential (no concurrency), exponential backoff on 429/5xx, and
honour `Retry-After` if present. In development, network calls happen only via `make record` and only for the two seed canisters (SPEC D6).

## Sample response

The spec has no example payloads. The first sample is **synthetic, built from the schema at
https://ic-api.internetcomputer.org/api/v3/openapi.json** (`ListSubnetsResponse` / `Subnet`). The schema types most numeric fields as strings. Values are placeholders.

```json
{
  "data": [
    {
      "subnet_id": "<63-char subnet principal>",
      "subnet_type": "application",
      "subnet_specialization": null,
      "display_name": "<name>",
      "up_nodes": "13", "total_nodes": "13",
      "running_canisters": "0", "stopped_canisters": "0", "total_canisters": "0",
      "total_countries": "0", "total_node_providers": "0",
      "memory_usage": "0", "instruction_rate": "0", "message_execution_rate": "0",
      "subnet_authorization": "public",
      "sev_enabled": false,
      "decentralization_score": {"nakamoto_coefficient_overall": "0", "...": "..."},
      "replica_versions": [{"proposal_id": "0", "replica_version_id": "<hex>", "executed_timestamp_seconds": "0"}],
      "data_centers": [{"dc_id": "xx1", "owner": "<owner>", "region": "<region>", "name": "<name>", "latitude": "0", "longitude": "0"}]
    }
  ],
  "previous_cursor": "<opaque>",
  "next_cursor": "<opaque>"
}
```

Canister detail (`/api/v3/canisters/{id}`): **UNVERIFIED**. The spec has no schema. The `/api/v4/canisters` `sort_by` enum implies
list items carry `canister_id`, `canister_type`, `controllers`, `language`, `subnet_id`. `module_hash` and `updated_at` are unconfirmed.
The first `make record` cassette for a seed canister becomes the authoritative sample.

## Pagination / quirks

- v4 (canisters, subnets): cursor-based. Responses carry `next_cursor` / `previous_cursor`, and requests send `after` / `before` (array of 1-2 strings) plus `limit`.
  The spec's `after`/`before` descriptions read "Only match values after this ledger_canister_id", which looks copy-pasted, so treat cursors as opaque.
- v3 lists (canisters, proposals): `limit` (max 100) plus `offset`, or `max_*_index` for stable descending paging.
- Array query params are sent as repeated form keys (`style: form, explode: true`), e.g. `include_topic=A&include_topic=B`.
- IDs are validated by regex: canister ids are 27 chars (5x4 groups + 3), subnet ids are 63 chars. Errors return 422 (`UNPROCESSABLE_ENTITY`) or the default `Error` {`code`, `status`, `message`, `errors`}.
- Numeric metrics are typed as strings in the `Subnet` schema, so parse them defensively.
- Several v3 paths are marked `deprecated`, and `/api/subnet-list` and similar paths redirect to v3. Do not follow cross-host redirects.

Other hosts named in docs (all `*.internetcomputer.org`, not needed for this source):
`icrc-api.internetcomputer.org` (ICRC ledgers, docs `/docs`), `sns-api.internetcomputer.org` (SNS, docs `/docs`),
`ledger-api.internetcomputer.org` (mainnet ICP ledger, Swagger `/swagger-ui/`), and `metrics-api.internetcomputer.org` (`/api/v1/`).
Our allowlist only needs `ic-api.internetcomputer.org`. Adding the others would require a SPEC change.

## How the collector will use it

1. For each canister IOC (seed: `tdtqy-oyaaa-aaaae-af2dq-cai`, `cjn37-uyaaa-aaaac-qgnva-cai`), GET `/api/v3/canisters/{id}` via
   the allowlist client. Store the raw JSON in the raw store, then map the known fields (subnet_id, controllers, module hash, type, timestamps)
   into the model. Unknown or missing fields stay null rather than guessed.
2. Pivot: GET `/api/v4/canisters?controller_id=<controller>&limit=100`, following `next_cursor`, to list sibling canisters of the same controller.
   These are recorded as "related" leads, never as IOCs on their own.
3. Subnet context: GET `/api/v4/subnets/{subnet_id}` for `total_canisters`, `subnet_type` and `subnet_authorization`.
4. Governance: page `/api/v3/proposals?include_topic=TOPIC_APPLICATION_CANISTER_MANAGEMENT&include_action=StopOrStartCanister&include_action=UpdateCanisterSettings`
   (plus `TOPIC_PROTOCOL_CANISTER_MANAGEMENT`), and match canister ids client-side to find disable/re-enable proposals and their timestamps.
5. Sequential requests at 1 req/s with backoff, replayed from cassettes in tests. The collector makes no update calls and never contacts any IC replica directly.

## Open questions

- Exact response fields of `/api/v3/canisters/{canister_id}` (is `module_hash` present? are there `updated_at` / upgrade history fields?). UNVERIFIED; check https://ic-api.internetcomputer.org/api/v3/swagger or the first recorded cassette.
- Response shape of `/api/v3/proposals` and `/api/v3/proposals/{id}`: where the target canister id appears in the payload. UNVERIFIED; same check.
- Whether `/api/v3/canisters/{id}` reflects a canister disabled by governance (status field?). UNVERIFIED.
- Is there a v4 single-canister endpoint? The spec shows none. The DFINITY skill also lists none.
- Official rate limit: only the forum figure (50 req/s) is available. Check https://forum.dfinity.org/t/rate-limit-for-icp/29374 for updates.
- Format of v4 cursors (`after`/`before` 1-2 items, probably sort key plus id). Not described in the spec.

## URLs consulted

All accessed 2026-10-15.
- https://ic-api.internetcomputer.org/api/v3/openapi.json
- https://ic-api.internetcomputer.org/api/v3/swagger
- https://raw.githubusercontent.com/dfinity/icskills/main/skills/ic-dashboard/SKILL.md
- https://forum.dfinity.org/t/rate-limit-for-icp/29374
- https://forum.dfinity.org/t/finding-out-a-canisters-subnet/16454
