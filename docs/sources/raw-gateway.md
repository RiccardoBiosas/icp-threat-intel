Status: EXPERIMENTAL

# Raw HTTP gateway (`<canister-id>.raw.icp0.io` / `<canister-id>.raw.ic0.app`)

## Summary

The raw domain is the IC HTTP gateway with response verification turned off. A `GET https://<id>.raw.icp0.io/<path>`
is translated by the gateway (`ic-gateway`, built on `ic-http-gateway-protocol`) into a call to the canister's
`http_request` **query** method, per the HTTP Gateway Protocol spec. The canister's `HttpResponse` (`status_code`,
`headers`, `body`) becomes the HTTP response. On the certified domain (`<id>.icp0.io`) the gateway checks the
`IC-Certificate` proof and refuses unverifiable responses (503 `backend_response_verification`). On the raw domain
it calls `unsafe_set_skip_verification(true)` and forwards whatever the replica returned.

This is the delivery channel seen in the seed IOC (`https://tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io/`): malware
uses raw because it does not need to certify its dynamic payloads. For us it gives the H1 signal (small text body:
URL, base64 or shell fragment). Status is EXPERIMENTAL: everything below comes from docs and gateway source code.
Nothing has been checked against a live response.

## Endpoints

| Endpoint | Meaning |
|---|---|
| `GET https://<id>.raw.icp0.io/<path>` | Uncertified gateway, current domain |
| `GET https://<id>.raw.ic0.app/<path>` | Uncertified gateway, legacy domain. `ic-gateway` resolves it the same way (see Quirks) |
| `GET https://<id>.icp0.io/<path>` | Certified gateway (reference only, not used by this collector) |
| `GET https://raw.icp0.io/` (no canister id) | 307 to `https://dashboard.internetcomputer.org/` (ic-gateway `routing/mod.rs`) |

How hosts are resolved (`ic-gateway` `routing/domain.rs`, `resolve_domain`): the host must sit one or two labels
below a base domain. Two labels means raw, and the second label must be `raw`. The first label is parsed as a
principal after removing any `prefix--`. An unparseable label gives no canister id (400 `canister_id_not_resolved`
or similar). Deeper hosts are rejected (400 `client_unknown_domain`).

Canister interface, from the spec's `http-gateway.did` (paraphrased):
`http_request: (HttpRequest) -> (HttpResponse) query` and `http_request_update: (HttpUpdateRequest) -> (HttpResponse)`
(update). `HttpRequest = {method; url; headers: vec record{text;text}; body: blob; certificate_version: opt nat16}`.
`HttpResponse = {status_code: nat16; headers; body: blob; upgrade: opt bool; streaming_strategy: opt ...}`.

## Auth

None. The gateway calls the canister as the anonymous principal. No keys or tokens are needed or used. The
`x-ratelimit-bypass-token` header exists in `ic-gateway` (`cli.rs`, `RateLimit`) for operator use only. We never
send it.

## Rate limits

- No official per-client limits are documented for the HTTP gateway.
- `ic-gateway` returns **429** with `X-IC-Error-Cause: rate_limited` ("Your request has exceeded the rate limit.")
  or `load_shed` ("The HTTP gateway is experiencing high load ..."). It also sheds load when its moving-average
  latency goes over a threshold (README).
- A DFINITY forum post (undated defaults, may be stale) cites 100 req/s per IP and 500 queries/s per subnet per
  boundary node. Emergency rate limits and filters are applied during incidents (forum, "Incident Handling with the
  New Boundary Node Architecture").
- Our cadence (SPEC: raw gateway for IOC canisters every 6 h) is far below any of these. A 429 is stored as an
  observation and is never retried in a tight loop.

## Sample response

Synthetic, built from https://raw.githubusercontent.com/dfinity/ic-gateway/main/src/routing/error_cause.rs. This
is the 404 a non-browser client (a non-browser `User-Agent`, as our fetcher sends) gets for a canister that does
not exist:

```
HTTP/2 404
content-type: application/json
x-ic-error-cause: canister_not_found
strict-transport-security: max-age=31536000; includeSubDomains

{
  "error_type": "canister_not_found",
  "description": "The requested canister (aaaaa-aa) does not exist or is no longer available on the Internet Computer.",
  "details": null
}
```

Synthetic, built from https://docs.internetcomputer.org/references/http-gateway-protocol-spec and `ic-gateway`
`routing/middleware/headers.rs`. A successful raw response (the body is whatever `http_request` returned):

```
HTTP/2 200
content-type: text/plain
x-ic-canister-id: aaaaa-aa
strict-transport-security: max-age=31536000; includeSubDomains

https://example.invalid/stage2.bin
```

Error map from `ic-gateway` `error_cause.rs`. The `X-IC-Error-Cause` value is listed first:

| Cause | HTTP | Meaning |
|---|---|---|
| `canister_not_found`, `canister_route_not_found` | 404 | Canister missing or deleted |
| `canister_error` | 503 | Canister trapped or rejected with an error. `details` holds the reject message. Expected for a **stopped** canister and for one **without `http_request`** (inferred: no dedicated variant exists) |
| `canister_reject` | 503 | Explicit reject |
| `canister_frozen` | 503 | Out of cycles ("The canister has run out of cycles.") |
| `canister_id_not_resolved`, `canister_id_incorrect` | 400 | Bad host label |
| `client_unknown_domain` | 400 | "The requested domain is not served by this HTTP gateway. Please check that the address is correct." |
| `client_domain_canister_mismatch` | 400 | Canister not served through this gateway |
| `denylisted` | 451 | "Unavailable Due to Policy Violation" (code-of-conduct takedown). **This is a strong signal for H5** |
| `forbidden` | 403 | Firewall rule |
| `subnet_updating` | 503 | Subnet upgrade in progress. Transient |
| `rate_limited`, `load_shed` | 429 | See Rate limits |
| `backend_*` | 503 | "Upstream Unavailable" |
| `internal_server_error` | 500 | Gateway fault |

## Fetch policy

Per SPEC section 4 (`raw-gateway.md` row) and D6:

- Request: `GET` only, with no body and no cookies. Use a fixed non-browser `User-Agent` (for example
  `icp-threat-intel/<version>`) so errors come back as JSON, not HTML.
- **1 MB cap**: stream the body and abort at 1,048,576 bytes. Record `truncated: true` and keep the partial bytes.
  `ic-gateway` itself allows up to 3 MB per IC response (`ic_response_max_size`), so the cap is ours to enforce.
- **10 s timeout** total, covering connect and read.
- **Redirects**: never follow automatically. Follow at most one hop, and only if the `Location` host matches
  `^[a-z0-9-]+(\.raw)?\.(icp0\.io|ic0\.app)$` and is in the allowlist. Every other `Location` is recorded as data
  (it is itself an IOC) and not fetched. This matters because canisters set their own status and headers on
  raw, which makes a canister-issued 3xx an attacker-controlled redirect.
- **No JavaScript**: never render or execute anything. Store `text/html` as bytes. No headless browser.
- Store the body **verbatim**, before any parsing, in `raw_snapshots`, along with the status, the response headers
  (including `x-ic-error-cause` and `x-ic-canister-id`), the request URL, the UTC timestamp and the
  **sha256** of the body bytes.
- Only allowlisted hosts. During development, only the two seed canisters, via `make record` (D6).

## Quirks

- **Upgrade to update call happens on raw too, and the gateway triggers it, not us.** Spec: "If the canister sets
  `upgrade = opt true` in the `HttpResponse` reply from the `http_request` call ... the HTTP Gateway performs an
  update call to `http_request_update`." In `ic-http-gateway-protocol` v0.6.1 (`protocol/handler.rs`,
  `process_request`), `is_update_call = agent_response.upgrade == Some(true)` is evaluated whatever
  `skip_verification` is set to, and then `http_request_update_custom(...).call_and_wait()` runs. So a plain GET to
  `<id>.raw.icp0.io` can make the gateway run an **update call** (state change, cycles burned, possibly a counter
  or beacon in a C2 canister) as the anonymous principal. Our client never sends that update itself, but the
  request causes it. The response gives no marker that this happened: the `upgraded_to_update_call` metadata is
  internal, and the latency is the only hint (seconds rather than milliseconds).
- An attacker canister can also log raw GETs (the `Host`, `User-Agent` and URL arrive in `HttpRequest.headers`)
  and so notice our polling. This fits with keeping the cadence low and the `User-Agent` honest.
- On raw, canisters control status codes and headers, and these are not certified. A v1 verification rule
  ("Response verification v1 does not allow redirects") only applies on certified domains.
- `ic-gateway` strips `ic-boundary` service headers (`x-ic-node-id`, `x-ic-subnet-id`, `x-ic-sender`,
  `x-ic-method-name`, `x-ic-retries`, `x-ic-cache-*`, `x-ic-country-code` and others) and adds `x-ic-canister-id`,
  HSTS and `x-request-id`. Subnet and node ids are **not** available from this source. They come from `read-state.md`.
- Error bodies are HTML for browser user agents (`pc`/`smartphone` by UA parse) and pretty JSON
  `{error_type, description, details}` for everything else. All error responses set `X-IC-Error-Cause`.
- **Raw can be refused by the canister**: asset canisters with `"allow_raw_access": false` answer raw requests
  with a **308** to the certified host (`raw.icp0.io` to `icp0.io`, `raw.ic0.app` to `ic0.app`), based on the
  `Host` header. A 308 that stays on the same canister counts as an allowed one-hop redirect. Custom canisters can
  do anything.
- `ic0.app` is still a base domain in `ic-gateway` (its tests resolve `aaaaa-aa.raw.ic0.app`). No source code or
  docs show a redirect from ic0.app to icp0.io. Live behaviour is unconfirmed.
- Newer docs (the certification guide) also show `<id>.raw.icp.net`. That host is not yet allowlisted. See Open
  questions.
- Streaming (`streaming_strategy` callback) bodies are assembled by the gateway. The 1 MB cap still applies on
  our side.

## How the collector will use it

1. For each IOC canister (every 6 h), `GET https://<id>.raw.icp0.io/`. Fall back to `.raw.ic0.app` only on a
   network-level failure, never because of a 4xx or 5xx.
2. Store a raw snapshot (verbatim, sha256 and metadata) before any parsing. If the hash has not changed since the
   last snapshot, record a "no change" event.
3. The parser classifies the body for H1: URL, base64 blob, shell fragment, binary (magic bytes) or HTML. It
   extracts URLs and hashes as candidate IOCs. A non-allowlisted `Location` header becomes an IOC candidate too.
4. Status and `x-ic-error-cause` give lifecycle events (H2 and H5): `canister_not_found` (deleted),
   `canister_error` with a "stopped" reject (stopped), `canister_frozen`, and `denylisted` (451, takedown).
   A transition between snapshots, for example 451 to 200, is itself an event.
5. **Query-only guardrail (proposed, conservative):** before any raw GET, call `http_request` ourselves as an
   anonymous **query** (`POST https://icp-api.io/api/v2/canister/<id>/query`, the same path as
   `read-state.md`) with `{method:"GET", url:"/", headers:[], body:b""}`. If the reply has `upgrade = opt true`,
   **do not** do the raw GET. Record `upgrade_requested: true` and store the query reply body. This keeps every
   network action we cause a query, and gives H1 the same body without the gateway. Whether to drop the raw GET
   entirely in favour of this direct query is logged as an open question.

## Open questions

- Should the collector use only the direct `http_request` query (fully query-only, no gateway) and treat
  `raw.icp0.io` as a fallback? Conservative choice: query first, and raw only when `upgrade` is not set. To be
  logged in `OPEN_QUESTIONS.md` by the implementing task.
- Exact `X-IC-Error-Cause` and `details` for a **stopped** canister, and for one **without `http_request`**
  (expected `canister_error`, 503). Needs a recorded cassette.
- Does `ic0.app` still serve identically, or does it redirect to `icp0.io`, in production today?
- Should `*.raw.icp.net` (seen in current docs) be added to the allowlist? Default: no, until the SPEC allowlist
  includes it.
- Current production rate-limit values. The forum figures are dated.

## URLs consulted

Accessed 2026-10-15:

- https://docs.internetcomputer.org/references/http-gateway-protocol-spec
- https://docs.internetcomputer.org/guides/frontends/certification.md
- https://docs.internetcomputer.org/guides/frontends/certification/
- https://github.com/dfinity/ic-gateway
- https://raw.githubusercontent.com/dfinity/ic-gateway/main/src/routing/error_cause.rs
- https://raw.githubusercontent.com/dfinity/ic-gateway/main/src/routing/domain.rs
- https://raw.githubusercontent.com/dfinity/ic-gateway/main/src/routing/mod.rs
- https://raw.githubusercontent.com/dfinity/ic-gateway/main/src/routing/ic/handler.rs
- https://raw.githubusercontent.com/dfinity/ic-gateway/main/src/routing/middleware/headers.rs
- https://raw.githubusercontent.com/dfinity/ic-gateway/main/src/routing/middleware/preprocess.rs
- https://raw.githubusercontent.com/dfinity/ic-gateway/main/src/cli.rs
- https://raw.githubusercontent.com/dfinity/ic-gateway/main/Cargo.toml
- https://raw.githubusercontent.com/dfinity/ic-http-gateway-protocol/v0.6.1/packages/ic-http-gateway-protocol/src/protocol/handler.rs
- https://forum.dfinity.org/t/how-would-internet-identity-handle-a-denial-of-service-attack/12791/7
- https://forum.dfinity.org/t/incident-handling-with-the-new-boundary-node-architecture/36390
