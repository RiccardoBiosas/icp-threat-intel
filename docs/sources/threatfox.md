Status: EXPERIMENTAL

# ThreatFox (abuse.ch) API

## Summary

ThreatFox is abuse.ch's community IOC-sharing platform, run with Spamhaus. Its
JSON API sits at `https://threatfox-api.abuse.ch/api/v1/`. Every call is an
HTTP POST with a JSON body whose `query` field selects the operation. The
endpoint is documented at https://threatfox.abuse.ch/api/. For this project,
ThreatFox is the primary public source of ICP canister IOCs. The SPEC seed IOC
is ThreatFox 1781006, which is tagged `ICP-C2`.

This note is marked EXPERIMENTAL for three reasons:

- The API was not called (D6 forbids it outside `make record`, and that target
  only reaches IC hosts).
- The public IOC page for 1781006 could not be fetched (see below).
- Since 2025-05-01 the API excludes IOCs older than six months. IOC 1781006 was
  first seen on 2026-04-04, so it is probably no longer returned by the API as
  of 2026-10-15.

### Cross-check of SPEC ground truth (IOC 1781006)

On 2026-10-15, fetching https://threatfox.abuse.ch/ioc/1781006/ returned only
the "Checking your browser" interstitial and no IOC fields. **Result: page not
fetched, so the SPEC facts are neither confirmed nor contradicted.** The SPEC
values stand unchanged:

| Field | SPEC value |
|---|---|
| ioc | `https://tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io/` |
| ioc_type | `url` |
| threat_type | `payload_delivery` |
| malware_printable | `Unknown malware` |
| confidence_level | `90` |
| first_seen | `2026-04-04 11:52:12 UTC` |
| reporter | `tipo_deincognito` |
| tags | `ICP-C2`, `npm-worm`, `supply-chain`, `systemd-dropper` |

## Endpoints

The base URL is `POST https://threatfox-api.abuse.ch/api/v1/`, with a JSON
body, the `Auth-Key` header, and a `query` field in the body.

| Use | `query` | Parameters (from docs) | Notes |
|---|---|---|---|
| Search IOC | `search_ioc` | `search_term` (required), `exact_match` (bool, default `false`, which means wildcard) | Search by canister ID (wildcard) or by full gateway URL (exact). |
| Tag info | `taginfo` | `tag` (required), `limit` (default 100, max 1000) | Returns IOCs carrying the tag, e.g. `ICP-C2`. |
| IOC by ID | `ioc` | `id` | Full record, including `comment`, `credits` and `malware_samples`. |
| Recent IOCs | `get_iocs` | `days` (1-7, default 3) | Filters on `first_seen`. Returns nothing older than 7 days. |
| Malware info | `malwareinfo` | `malware` (Malpedia name, required), `limit` (default 100, max 1000) | Useful only once a family name is known. "Unknown malware" is not useful here. |
| (helper) | `types`, `tag_list`, `malware_list`, `get_label`, `search_hash` | | Used to validate exporter enums. Not used for collection. |
| **Submission, documented only, never called** | `submit_ioc` | see "Submission format" | We only generate the file. A human submits it manually. |

All of these return `{"query_status": "...", "data": ...}`. The status is `ok`
on success. Other statuses, such as no result, an unknown tag, or an
illegal/missing parameter, must be handled as "no data" and not as an error.
The exact error strings were not re-verified (see "Open questions").

## Auth

- The docs say: "Whenever you interact with the ThreatFox API, you must
  include the HTTP header `Auth-Key` with your Auth-Key."
- Keys are free from the abuse.ch Authentication Portal, https://auth.abuse.ch/.
- In this project the key comes **only** from the env var `ABUSECH_AUTH_KEY`
  (SPEC D3). When it is absent, the ThreatFox collector is disabled and logs
  that it was skipped. The key is never written to a file, cassette, log or
  report, and the redaction layer must strip the `Auth-Key` header from
  recorded requests.
- `threatfox-api.abuse.ch` is not an IC host. The collector must go through
  the allowlist client, and the host must be added to the allowlist explicitly
  when the collector task lands.

## Rate limits

- No numeric limit is published. The API is free "under the fair use
  principles". The abuse.ch Terms of Use define query volume limits as
  "volumes reasonably expected for non-commercial or non-profit purposes". If
  these are exceeded, access may be restricted or revoked without notice.
- The terms prohibit "high volume automatic ... process to access, search or
  harvest information".
- Commercial or for-profit use "may require a paid subscription" through
  Spamhaus.
- Our policy is conservative:
  - at most 1 request per 2 s
  - a fixed small query set per run (one `taginfo`, one `search_ioc` per
    known canister)
  - daily cadence at most
  - backoff on any non-`ok` HTTP status
  - no bulk export scraping

## Sample response

The following is **synthetic, built from https://threatfox.abuse.ch/api/**,
using the documented field names. The values are the SPEC seed facts. Fields
not in SPEC are placeholders or null. This is not an API capture.

```json
{
  "query_status": "ok",
  "data": [
    {
      "id": "1781006",
      "ioc": "https://tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io/",
      "threat_type": "payload_delivery",
      "threat_type_desc": "<placeholder>",
      "ioc_type": "url",
      "ioc_type_desc": "<placeholder>",
      "malware": "unknown",
      "malware_printable": "Unknown malware",
      "malware_alias": null,
      "malware_malpedia": null,
      "confidence_level": 90,
      "first_seen": "2026-04-04 11:52:12 UTC",
      "last_seen": null,
      "reference": null,
      "reporter": "tipo_deincognito",
      "tags": ["ICP-C2", "npm-worm", "supply-chain", "systemd-dropper"],
      "malware_samples": []
    }
  ]
}
```

The documented response fields are: `id`, `ioc`, `ioc_type`, `ioc_type_desc`,
`threat_type`, `threat_type_desc`, `malware`, `malware_printable`,
`malware_alias`, `malware_malpedia`, `confidence_level`, `first_seen`,
`last_seen`, `reference`, `reporter` and `tags`. `malware_samples[]` holds
`time_stamp`, `md5_hash`, `sha256_hash` and `malware_bazaar`. `ioc` by ID also
returns `comment` and `credits`.

The `id` type (string vs int), the internal `malware` value for "Unknown
malware" (`unknown`?) and the `last_seen` format are assumptions. They are
listed under "Open questions".

## Submission format

The exporter writes a JSON file in the `submit_ioc` body shape. **It never
POSTs it.** A human reviews the file and submits it. The fields come from the
API docs and https://github.com/abusech/ThreatFox (`threatfox_submit-ioc.py`).

| Field | Req. | Value / rule |
|---|---|---|
| `query` | yes | `"submit_ioc"` |
| `threat_type` | yes | e.g. `payload_delivery` (gateway URL serving a payload) or `botnet_cc` (C2). Validate against the `types` list. |
| `ioc_type` | yes | e.g. `url`, `domain`, `ip:port`, `sha256_hash`. Validate against `types`. |
| `malware` | yes | Malpedia name. Use the "unknown" family when no family is known (exact value to be checked with `malware_list`/`get_label`). |
| `iocs` | yes | List of IOC strings, all of the same `ioc_type`. |
| `confidence_level` | no | 0-100, default 50. The docs say to use high values only for manually vetted IOCs. |
| `is_compromised` | no | bool, default false. Use false for attacker-created canisters. |
| `reference` | no | URL of the public write-up. |
| `tags` | no | List. The allowed characters are letters, digits, `.`, `-` and space. Always include `ICP-C2`. |
| `comment` | no | Free text: canister ID, subnet, gateway, evidence summary. |
| `anonymous` | no | `0`/`1`, default 0. |

Submission policy constraints for the disclosure checklist:

- only confirmed or vetted IOCs
- no spam or phishing IOCs
- avoid IOCs older than 10 days
- submissions are reviewed by a human
- repeat violations can get the account banned

## How the collector will use it

1. If `ABUSECH_AUTH_KEY` is unset, skip and report the collector as disabled.
2. Run `taginfo` with `tag: "ICP-C2"` and `limit: 1000`. This is the main
   discovery query.
3. For each known canister ID, run `search_ioc` with `search_term: <canister-id>`
   and `exact_match: false`. Wildcard matching catches every gateway form
   (`<id>.icp0.io`, `<id>.raw.icp0.io`, `<id>.ic0.app`, `<id>.raw.ic0.app`).
   Then run `search_ioc` with the full gateway URL and `exact_match: true`.
4. Optionally run `get_iocs` with `days: 1` and filter locally for
   `icp0.io`/`ic0.app` hosts. This catches untagged new IOCs.
5. Run `ioc` by `id` for new hits to fetch `comment` and `credits`.
6. Extract canister IDs from `ioc` values with the canister-ID regex and
   validate the checksum. Store the raw JSON in the raw store, keyed by query
   and timestamp, and map fields to the data model. Seed IOC 1781006 comes
   from `data/seed_iocs.yaml` and not from the API (it has expired; see
   above).
7. Tests use cassettes or fixtures only. Until a real capture exists, the
   fixture is the synthetic sample above with `synthetic: true`.

## Open questions

- **Licence:** older abuse.ch material and third-party summaries say ThreatFox
  data and submissions are CC0 / TLP:WHITE. On 2026-10-15, the ThreatFox FAQ
  and API pages contain no "CC0", "TLP" or licence wording. The abuse.ch Terms
  of Use name no data licence, and they forbid derivative works of the
  Platforms without consent. **Conservative choice:**
  - redistribute only individual IOCs needed for reports
  - always attribute ThreatFox with the IOC link
  - do not mirror the dataset
  - confirm the licence with abuse.ch/Spamhaus before bulk redistribution
- Expiry: IOC 1781006 is older than six months, so the API probably no longer
  returns it. The seed YAML stays the source for it. Can the UI page be
  verified by a human?
- The exact `query_status` strings for no result or a bad tag, and whether
  `id` is a string or an int, need a real capture.
- Is the exact `malware` value for "Unknown malware" `unknown`? Confirm with
  `get_label`/`malware_list` before the exporter hard-codes it.
- Is `ICP-C2` the canonical tag casing in `tag_list`? Is `taginfo`
  case-sensitive?
- Adding `threatfox-api.abuse.ch` to the allowlist needs a SPEC D6 decision
  (the current D6 covers only IC hosts).

## URLs consulted

All accessed 2026-10-15.

- https://threatfox.abuse.ch/api/ (fetched: base URL, queries, Auth-Key, fields, expiry, fair use)
- https://threatfox.abuse.ch/faq/ (fetched: submission policy, 10-day freshness, 6-month expiry; no licence text found)
- https://threatfox.abuse.ch/ioc/1781006/ (NOT fetched: browser-check interstitial only)
- https://abuse.ch/terms-of-use/ (fetched: fair use, query volume limits, commercial use, no named licence)
- https://abuse.ch/fair-use-policy/ (404)
- https://auth.abuse.ch/ (referenced, not fetched)
- https://github.com/abusech/ThreatFox (fetched: example scripts, Auth-Key usage)
- https://raw.githubusercontent.com/abusech/ThreatFox/main/threatfox_submit-ioc.py (fetched: submit_ioc field list)
- https://threatfox-api.abuse.ch/faq (301 redirect to https://threatfox.abuse.ch/api/)
