Status: EXPERIMENTAL

# URLhaus (abuse.ch) API

## Summary

URLhaus is abuse.ch's database of URLs that serve malware payloads. abuse.ch runs it with
Spamhaus. Its Community API (`https://urlhaus-api.abuse.ch/v1/`) accepts form-encoded POST
lookups by host, URL, tag, signature and payload hash, and GET requests for recent URLs and
payloads. Since 30 June 2025 every request has needed an `Auth-Key` header.

The status is EXPERIMENTAL for these reasons:

- The endpoints, parameters and response fields were checked against the official docs on
  2026-10-15.
- No live call was made. SPEC D6 allows live traffic only to allowlisted IC hosts, and the
  note rules forbid POSTing to the API.
- The docs do not say how a host lookup treats subdomains, which matters for `icp0.io`
  (see Open questions).
- The docs list no numeric rate limit.

For this project, URLhaus is an enrichment source. It answers whether a known IOC canister's
gateway hostname has been reported as a malware distribution site, and it lists URLs under
a tag. URLhaus accepts only URLs that serve a malware payload. Phishing sites, plain
redirectors and URL shorteners are out of scope, so canisters used purely as C2 or for
exfiltration (CanisterSprawl) may never appear in it.

## Endpoints

Base URL: `https://urlhaus-api.abuse.ch/v1/`. Every request carries the `Auth-Key` header.
POST bodies are `application/x-www-form-urlencoded`.

| Purpose | Method + path | Parameter | Result cap |
|---|---|---|---|
| Host lookup | `POST /v1/host/` | `host` (IPv4, hostname or domain; case-insensitive) | 100 URLs |
| URL lookup | `POST /v1/url/` | `url` | 100 payloads |
| URL by ID | `POST /v1/urlid/` | `urlid` (the doc's table says `id`; see Open questions) | n/a |
| Tag lookup | `POST /v1/tag/` | `tag` (case-insensitive) | 1000 URLs |
| Signature lookup | `POST /v1/signature/` | `signature` (malware family) | 1000 URLs |
| Payload info | `POST /v1/payload/` | `md5_hash` or `sha256_hash` | 100 URLs |
| Recent URLs | `GET /v1/urls/recent/` (optional `limit/<n>/`) | none | past 3 days, at most 1000 |
| Recent payloads | `GET /v1/payloads/recent/` (optional `limit/<n>/`) | none | past 3 days, at most 1000 |
| Payload download | `GET /v1/download/<sha256>/` | none | **Never used by this project** |

`query_status` takes the values `ok`, `no_results`, `http_post_expected` and
`http_get_expected`, plus input errors such as `invalid_host`, `invalid_url`, `invalid_md5`
and `invalid_sha256`.

Host lookup returns `firstseen`, `url_count` and `blacklists` (`spamhaus_dbl` and `surbl`;
none for IPv4 queries), plus `urls[]`. Each entry in `urls[]` has `id`, `urlhaus_reference`,
`url`, `url_status` (`online`, `offline` or `unknown`), `date_added`, `threat`, `reporter`,
`larted`, `takedown_time_seconds` and `tags`.

Tags are set by the reporter. Signatures are assigned by URLhaus and the reporter cannot set
them.

**Bulk feeds** (https://urlhaus.abuse.ch/api/):

- **Dumps.** Database dumps in CSV and JSON come in three variants: full (active or added
  within 90 days), active-only, and the last 30 days. They are regenerated every 5 minutes;
  do not fetch them more often than that.
- **Other feeds.** A plain-text URL list, a hostfile and a DNS RPZ zone (both hold hosts
  active or added in the past 48 hours, with the Tranco top 1M excluded), Snort/Suricata
  rules, ClamAV signatures, daily MISP events, and a payload hash CSV. The FAQ also mentions
  ASN, Country and TLD feeds.
- **Auth in feed URLs.** Feed URLs carry the auth key in the path, for example
  `.../v2/files/exports/<AUTH-KEY>/recent.csv`. Those URLs must never be logged or stored
  (see Auth).
- **No host-filtered feed.** No feed is filtered by host or domain. A TLD feed would cover
  all of `.io` and `.app`, far too broad.

The Tranco exclusion may drop `ic0.app` or `icp0.io` hostnames from the hostfile and RPZ;
this is unverified. Filtering by hostname has to happen client-side on the CSV or JSON dump.

## Auth

- The key is free and comes from the abuse.ch Authentication Portal (https://auth.abuse.ch/).
  It is sent as the HTTP header `Auth-Key: <key>`, and the bulk feeds put it in the path.
- abuse.ch made authentication mandatory on 30 June 2025. A third-party README says one key
  covers URLhaus, ThreatFox and MalwareBazaar; this is unverified, but SPEC D3 already
  assumes it.
- The key is read only from env `ABUSECH_AUTH_KEY` (SPEC D3). When it is absent, the
  collector is disabled and logs that once. It is never an error.
- The key must never appear in files, cassettes, logs or exception messages. Redaction must
  cover both the header and any feed URL path segment.

## Rate limits

- The docs give no numeric rate limit.
- The abuse.ch Terms of Use (effective 4 November 2025) define fair use with these terms:
  - Free access is for authenticated users with not-for-profit purposes. Commercial use
    may require a paid Spamhaus subscription.
  - The "Query Volume Limits" are whatever is "reasonably expected for non-commercial or
    non-profit purposes", measured in API queries.
  - High-volume automated harvesting (robots, spiders, scripts) is prohibited.
  - Access can be revoked without notice.
- Dumps: no more than once every 5 minutes.
- Conservative choice for this project: at most 1 request per second, one host lookup per
  IOC hostname per run, a daily schedule by default, and exponential backoff on HTTP 429/5xx.

## Sample response

Synthetic, built from https://urlhaus-api.abuse.ch/ (the host-lookup example structure).
The values are invented, and the key spelling follows the field list (the doc's own example
misspells `query_status` as `query_staus`). No real API call was made.

```json
{
  "query_status": "ok",
  "urlhaus_reference": "https://urlhaus.abuse.ch/host/example-cai.raw.icp0.io/",
  "host": "example-cai.raw.icp0.io",
  "firstseen": "2026-04-04 12:00:00 UTC",
  "url_count": "1",
  "blacklists": {"spamhaus_dbl": "not listed", "surbl": "not listed"},
  "urls": [
    {
      "id": "0000000",
      "urlhaus_reference": "https://urlhaus.abuse.ch/url/0000000/",
      "url": "https://example-cai.raw.icp0.io/",
      "url_status": "online",
      "date_added": "2026-04-04 12:00:00 UTC",
      "threat": "malware_download",
      "reporter": "example_reporter",
      "larted": "false",
      "takedown_time_seconds": null,
      "tags": ["ICP-C2"]
    }
  ]
}
```

A host with no entries returns `{"query_status": "no_results"}`. Note that `url_count` is a
string in the docs' examples, so parse it defensively.

## How the collector will use it

1. **Guard.** If `ABUSECH_AUTH_KEY` is unset, return no events. The host
   `urlhaus-api.abuse.ch` must be on the HTTP allowlist used by the guardrail client.
2. **Host lookups.** For every IOC canister ID `<cid>`, POST `host=` for each of:
   - `<cid>.icp0.io`
   - `<cid>.raw.icp0.io`
   - `<cid>.ic0.app`
   - `<cid>.raw.ic0.app`

   That is four lookups per canister.
3. **Never the bare gateway.** Never query the bare parent domains (`icp0.io`, `ic0.app`,
   `raw.icp0.io`, `raw.ic0.app`, `icp-api.io`). They are shared by every canister and by
   legitimate dapps, so any result there says nothing about a specific canister.
4. **Attribute strictly.** For each returned `urls[].url`, parse the hostname. Attribute
   the result to a canister only when the leftmost label equals that canister ID exactly.
   Discard anything else: a parent-domain match, another canister, or a custom domain.
5. **Tag lookups.** Query `tag=` for each tag in config, with defaults `ICP-C2`, `icp0`,
   `ic0` and `canister`. Extract canister IDs from the URL hostnames with the principal
   regex and emit them as *candidate* IOCs (low confidence, needing analyst confirmation),
   never as confirmed ones.
6. **Record provenance.** Keep `urlhaus_reference`, `date_added`, `url_status`, `threat`,
   `tags`, `reporter` and `firstseen`.
7. **Store raw.** Keep raw responses in the raw store with the key redacted.
8. **No payloads.** `/payload/` is used only for hash metadata already listed on a matched
   URL. `/download/` is never called.
9. **Tests.** Tests use synthetic cassettes (SPEC D6) marked `synthetic: true`.

**False-positive risk.** All canisters share the gateway domains, so a host match on a
parent domain is meaningless. Even a correct canister-subdomain match only shows that the
canister *served* malware at some time. Check `url_status` and dates before using it as a
liveness signal.

## Open questions

1. Does `POST /v1/host/` with a parent domain (`icp0.io`) return URLs on its subdomains, or
   only exact-host matches? The docs are silent. The collector assumes either is possible,
   which is why it never queries parents and filters by exact hostname.
2. Does URLhaus normalise `<cid>.icp0.io` and `<cid>.raw.icp0.io` to the same host? This is
   assumed not, so both are queried.
3. Is the `/v1/urlid/` parameter `id` or `urlid`? The doc's table and its wget example
   disagree. This project does not use the endpoint.
4. What is the redistribution licence for IOCs? The Terms of Use state no data licence.
   Spamhaus is the "primary licensee", derivative works need consent, and free use is
   limited to not-for-profit purposes. Conservative choice: this project publishes only
   references (canister ID plus the `urlhaus_reference` link) with attribution "Source:
   abuse.ch URLhaus". It does not republish bulk URLhaus records, and it never commits raw
   responses to the repo. This should be logged in `OPEN_QUESTIONS.md`.
5. Do the hostfile and RPZ exclusions (Tranco top 1M) suppress `ic0.app` or `icp0.io`
   hosts? This is unverified, and the collector does not depend on those feeds.
6. Are there numeric fair-use limits per key? They are undocumented. Use the conservative
   pacing above.

## URLs consulted

All accessed 2026-10-15.

- https://urlhaus-api.abuse.ch/
- https://urlhaus.abuse.ch/api/
- https://urlhaus.abuse.ch/api/#policy
- https://urlhaus.abuse.ch/about/
- https://urlhaus.abuse.ch/faq/
- https://abuse.ch/terms-of-use/
- https://abuse.ch/terms-and-conditions/
- https://abuse.ch/blog/community-first/
- https://auth.abuse.ch/
- https://xsoar.pan.dev/docs/reference/integrations/feed-ur-lhaus
