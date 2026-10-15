Status: EXPERIMENTAL

# NNS governance proposals (IC Dashboard API and governance canister)

## Summary

The Network Nervous System (NNS) governance canister `rrkah-fqaaa-aaaaa-aaaaq-cai` stores every
NNS proposal. Two read paths exist:

1. The **IC Dashboard API** (`https://ic-api.internetcomputer.org/api/v3/proposals`), a plain HTTPS
   JSON index of proposals with server-side filters for topic, status, action and NNS function.
2. The governance canister's **query** methods `list_proposals` and `get_proposal_info`
   (Candid, query calls only; no update call is ever needed or allowed).

Why we care: a proposal is the only on-chain way for the NNS to act on a canister or a subnet.
But proposal actions such as `StopOrStartCanister` and `UpdateCanisterSettings` only work on
canisters **controlled by NNS Root**. An ordinary user canister on an application subnet (such as
`tdtqy-oyaaa-aaaae-af2dq-cai`) is not an NNS-controlled canister. So a malicious-canister takedown
may never show up as a canister-level proposal. It is more likely to happen at the boundary layer:
the HTTP gateway content filter, or the NNS-governed API boundary node rate-limit/filter canister.
See the CanisterWorm notes under "Proposal types relevant to us".

Status is EXPERIMENTAL for two reasons. The Dashboard OpenAPI spec documents the request
parameters but has **no response schema**. And no primary source says which mechanism disabled
the CanisterWorm canister.

## Endpoints

Dashboard API (OpenAPI "Public Dashboard API" v3, spec at `/api/v3/openapi.json`):

| Method/path | Purpose |
|---|---|
| `GET /api/v3/proposals` | Paged proposal list with filters (below) |
| `GET /api/v3/proposals/{proposal_id}` | One proposal |
| `GET /api/v3/proposals/{proposal_id}/tallies` | Vote tallies over time |
| `GET /api/v3/proposals/{proposal_id}/deadline-extensions` | Wait-for-quiet extensions |
| `GET /api/v3/proposals-count`, `/api/v3/latest-proposal-id` | Cursor helpers for incremental polling |
| `GET /api/nns/proposals` | Deprecated, redirects to `/api/v3/proposals` |

Query parameters of `GET /api/v3/proposals` (from the spec):

- `limit` (int, default 50, max 100), `offset` (int, default 0), `max_proposal_index` (int, page backwards from an id)
- `format` = `json` (default) or `csv`
- `include_topic` (repeatable): `TOPIC_SUBNET_MANAGEMENT`, `TOPIC_APPLICATION_CANISTER_MANAGEMENT`,
  `TOPIC_PROTOCOL_CANISTER_MANAGEMENT`, `TOPIC_NETWORK_CANISTER_MANAGEMENT`,
  `TOPIC_SERVICE_NERVOUS_SYSTEM_MANAGEMENT`, `TOPIC_API_BOUNDARY_NODE_MANAGEMENT`, `TOPIC_GOVERNANCE`, ... (20 values)
- `include_status` (repeatable): `UNKNOWN`, `UNSPECIFIED`, `OPEN`, `REJECTED`, `ADOPTED`, `EXECUTED`, `FAILED`
- `include_reward_status`, `include_proposer_group` (`dfinity`/`known`/`other`), `include_classification`
  (`abusive`/`constructive`/`non_actionable`/`unknown`), `proposer` (neuron id), `manage_neuron_id`
- `include_action` (repeatable): includes `StopOrStartCanister`, `UpdateCanisterSettings`, `InstallCode`,
  `TakeCanisterSnapshot`, `LoadCanisterSnapshot`, `CreateCanisterAndInstallCode`, `ExecuteNnsFunction`, `Motion`
- `include_action_nns_function` (repeatable): includes `StopOrStartNnsCanister`, `UninstallCode`,
  `HardResetNnsRootToVersion`, `UpdateConfigOfSubnet`, `SetSubnetOperationalLevel`, `RecoverSubnet`,
  `DeleteSubnet`, `RerouteCanisterRanges`, `PrepareCanisterMigration`, `AddFirewallRules`, `SetFirewallConfig`

The API has **no free-text or canister-ID filter**.

Governance canister (`rrkah-fqaaa-aaaaa-aaaaq-cai`, Candid from `governance.did`):

- `list_proposals : (ListProposalInfoRequest) -> (ListProposalInfoResponse) query;`
  The request has `limit : nat32`, `before_proposal : opt ProposalId`, `exclude_topic : vec int32`,
  `include_status : vec int32`, `include_reward_status : vec int32`, `omit_large_fields : opt bool`,
  `include_all_manage_neuron_proposals : opt bool` and `return_self_describing_action : opt bool`.
- `get_proposal_info : (nat64) -> (opt ProposalInfo) query;`

## Auth

None for either path. The Dashboard API is public HTTPS. Canister queries are anonymous query
calls through an allowlisted API boundary node (`icp-api.io` / `ic0.app`). We never sign
update calls (SPEC D6, PROMPT section 3).

## Rate limits

The OpenAPI spec documents none. The page size is capped at 100 for the Dashboard API. On the
canister path, API boundary nodes apply rate limits that are not published as numbers. The
collector should poll at most every 15 minutes, page by `max_proposal_index`, and back off
on 429 or 5xx responses.

## Sample response

The OpenAPI spec has no 200-response schema, so this sample is **synthetic, built from
https://raw.githubusercontent.com/dfinity/ic/master/rs/nns/governance/canister/governance.did**
(the `ProposalInfo`, `Proposal` and `StopOrStartCanister` records), with dashboard-style field names.
The field names must be confirmed against a `make record` cassette before the parser is frozen.

```json
{
  "data": [
    {
      "proposal_id": 999999,
      "title": "Stop canister (synthetic example)",
      "summary": "Synthetic. Stop canister xxxxx-xxxxx-xxxxx-xxxxx-cai pending review.",
      "url": "",
      "topic": "TOPIC_PROTOCOL_CANISTER_MANAGEMENT",
      "action": "StopOrStartCanister",
      "action_nns_function": null,
      "status": "EXECUTED",
      "proposer": "1",
      "proposal_timestamp_seconds": 1774000000,
      "decided_timestamp_seconds": 1774003600,
      "executed_timestamp_seconds": 1774003601,
      "payload": { "canister_id": "xxxxx-xxxxx-xxxxx-xxxxx-cai", "action": 1 }
    }
  ]
}
```

In the Candid `StopOrStartCanister`, `action` is `1` = STOP and `2` = START (proto enum
`CanisterAction`). `ProposalInfo.status` is an int: 1 OPEN, 2 REJECTED, 3 ADOPTED, 4 EXECUTED, 5 FAILED.

## Filtering by canister ID and subnet

- Neither path offers server-side filtering by canister or subnet. We filter on the client side.
- The canister IDs we care about can appear in these places:
  - `payload.canister_id` for StopOrStartCanister, UpdateCanisterSettings, InstallCode and snapshot actions;
  - the decoded `ExecuteNnsFunction` payload (`nns_function` + Candid `payload` blob, which the
    dashboard renders) for UninstallCode, StopOrStartNnsCanister, RerouteCanisterRanges and migrations;
  - free text in `title`, `summary` and `url`, especially for `Motion` proposals and boundary-node items.
- Recipe: fetch with `include_topic` narrowed to the topics listed below, then run the regex
  `\b(?:[a-z2-7]{5}-){4}cai\b` (plus the 63-char subnet-principal form `\b(?:[a-z2-7]{5}-){10}[a-z2-7]{3}\b`)
  over the JSON-serialised `payload`, `title` and `summary`. Match against the IOC and known-canister tables.
- Subnet-scoped proposals (`UpdateConfigOfSubnet`, `SetSubnetOperationalLevel`, `RecoverSubnet`,
  `DeleteSubnet`) carry `subnet_id` in the payload. Join them to a canister through the canister's subnet,
  which needs a separate registry/dashboard lookup.

## Proposal types relevant to us

| Signal | Topic (int) | Action / NNS function (code) | Effect |
|---|---|---|---|
| Stop/start a canister | 8 or 17 | `StopOrStartCanister` | Only for canisters controlled by NNS Root (not Governance or Lifeline) |
| Change settings/controllers | 8 or 17 | `UpdateCanisterSettings` | `update_settings`, including the controllers list, on an NNS-controlled canister |
| Reinstall/upgrade code | 8 or 17 | `InstallCode` | NNS-controlled canisters only |
| Snapshot / restore | 8 or 17 | `TakeCanisterSnapshot`, `LoadCanisterSnapshot` | Evidence-preservation analogue |
| Uninstall code | 8 or 17 | `ExecuteNnsFunction` `UninstallCode` (19) | Wipes the Wasm module |
| Legacy stop/start | 8 or 17 | `StopOrStartNnsCanister` (17) | Older form of the stop/start action |
| Root recovery | 17 | `HardResetNnsRootToVersion` (42) | NNS-internal |
| Subnet actions | 7 | `UpdateConfigOfSubnet` (7), `SetSubnetOperationalLevel` (55), `RecoverSubnet` (6), `DeleteSubnet` (57), `RerouteCanisterRanges` (24) | Act on every canister of a subnet |
| Boundary-node policy | 15 | API boundary node management, `AddFirewallRules` (25) | Node-level, not per canister |
| Policy / intent | 4 | `Motion` | Free text only; a takedown policy would appear here |

What we know about the CanisterWorm disable (March 2026):

- Wiz reported that the canister was "Unavailable Due to Policy Violation" as of 2026-03-22 21:31 UTC.
- The CSA note, citing Aikido, says "on-chain governance" disabled it about 26 hours after disclosure.
  The same note also says the NNS "does not have an emergency disable mechanism".
- "Unavailable Due to Policy Violation" matches DFINITY's HTTP gateway content filter for icp0.io
  and ic0.app under the Code of Conduct. That filter blocks access through the gateway and leaves the
  canister intact on chain, which is consistent with a block that can be reversed.
- Since 2024, API boundary nodes are NNS-controlled. The NNS approved an incident-handling design
  (proposal 134031) with a rate-limit canister on subnet `uzr34`. NNS-authorized principals can add
  hidden "rate-limit or block" rules there, which must be disclosed after the incident.
- No primary source found yet names an NNS proposal against `tdtqy-oyaaa-aaaae-af2dq-cai`.

## How the collector will use it

1. Poll `GET /api/v3/proposals?include_topic=...&limit=100`, filtered to topics 4, 7, 8, 15, 17 and
   `TOPIC_NETWORK_CANISTER_MANAGEMENT`. Page with `max_proposal_index` and keep a cursor of the
   highest id seen. During development, use only `make record` and cassettes (SPEC D6).
2. Store each raw proposal in the raw store unchanged, then extract canister and subnet principals with
   the regexes above.
3. When a principal matches a tracked IOC canister (or its subnet), emit a `governance_action` event
   with the proposal id, action, NNS function, status and timestamps. A STOP followed by a START, or a
   later status flip, produces a "re-enabled" event.
4. As a fallback or cross-check, run the same logic over `list_proposals` /
   `get_proposal_info` query calls to `rrkah-fqaaa-aaaaa-aaaaq-cai`.
5. Do not treat "no matching proposal" as "not disabled": gateway and boundary-node blocks are not
   recorded as per-canister proposals.

## Open questions

- Which mechanism disabled `tdtqy-oyaaa-aaaae-af2dq-cai`: an HTTP gateway denylist, a rate-limit
  canister block rule, or an NNS proposal? Who re-enables it, and is that change visible anywhere?
- Is the rate-limit canister's rule set readable through query calls after disclosure? If so, it is a
  better takedown signal than proposals and deserves its own source note.
- The exact JSON field names in the Dashboard API (`payload`, `action`, `topic` as string or int?). To
  confirm, record one cassette for a single known proposal id.
- `TOPIC_NETWORK_CANISTER_MANAGEMENT` appears in the Dashboard enum but not in the proto excerpt we
  read. What is its integer value, and which actions does it cover?
- Does the dashboard decode the `ExecuteNnsFunction` payload blob for every NNS function?

## URLs consulted

All accessed 2026-10-15.

- https://ic-api.internetcomputer.org/api/v3/openapi.json
- https://raw.githubusercontent.com/dfinity/ic/master/rs/nns/governance/canister/governance.did
- https://raw.githubusercontent.com/dfinity/ic/master/rs/nns/governance/proto/ic_nns_governance/pb/v1/governance.proto
- https://www.wiz.io/blog/trivy-compromised-teampcp-supply-chain-attack
- https://labs.cloudsecurityalliance.org/research/csa-research-note-trivy-canisterworm-blockchain-c2-supply-ch/
- https://forum.dfinity.org/t/incident-handling-with-the-new-boundary-node-architecture/36390
- https://support.dfinity.org/hc/en-us/articles/6365309327380-I-came-across-a-malicious-website-or-scam-on-the-Internet-Computer-How-do-I-report-the-violation
- https://support.dfinity.org/hc/en-us/articles/6521617228308-Appealing-a-Violation-of-the-Code-of-Conduct
- https://forum.dfinity.org/t/regarding-nns-controlling-application-canisters/35614
- https://learn.internetcomputer.org/hc/en-us/articles/34140518658068-Proposal-Topics-and-Types (HTTP 403, not read)
