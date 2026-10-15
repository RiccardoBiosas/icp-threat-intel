Status: VERIFIED

# PhishDestroy blocklist (signals feed, blocklist kind)

## Summary

PhishDestroy is a volunteer-run, non-commercial project that publishes a list of phishing,
crypto-drainer and scam domains. Its full list is an append-only JSON array of hostnames on
GitLab. On 2026-10-16 it held **222,032 entries**, of which **48 were ICP gateway hosts naming
44 distinct canisters** (checksums valid, 0 unmapped). None of DFINITY's own domains
(`icp0.io`, `ic0.app`, `internetcomputer.org`, `dfinity.org`, NNS, Internet Identity) was
listed, and neither seed IOC canister was.

It is consumed as part of the **signals feed**, not as an authoritative IOC feed:

- source type `signals_feed`, `sources` row `phishdestroy`, default reliability **40**;
- never counted by the two-signal rule (`core/evidence.py`): the operators are anonymous,
  entries are community-reported, and the false-positive rate (about 0.01%) is self-reported.

Status is VERIFIED for the `list.json` download only: fetched and parsed on 2026-10-16.

## Endpoints

| Request | Confirmed | Date checked |
|---|---|---|
| `GET https://gitlab.com/phishdestroy/destroylist/-/raw/main/list.json` | 200, `text/plain; charset=utf-8`, 5,730,568 bytes, a JSON array of 222,032 lowercase hostnames, no redirect; `cache-control: max-age=60`, an `etag` | 2026-10-16 |
| `GET https://gitlab.com/phishdestroy/destroylist/-/raw/main/dns/active_domains.json` | 200, 3,731,165 bytes, 136,164 hostnames still resolving; the same 48 ICP hosts | 2026-10-16 |

Used: `list.json` only. ICP gateway hosts always resolve (wildcard DNS), so the "active"
list adds nothing for canisters.

**Not used, by design:**

- the per-domain REST API (`https://api.destroy.tools`, and lookups on `phishdestroy.io`):
  every lookup would tell the operator which domain or canister is being checked;
- the STIX (147 MB) and MISP feeds: far larger, same hostnames;
- the HuggingFace copy: same data, another host.

## Auth

None. GitLab raw files are public. No account, token or cookie is sent.

## Rate limits

None documented for raw files. One GET per run; the shared client's limits and backoff apply.
Run it by hand (`collect blocklists`) or at most daily: the list changes continuously, so
almost every run stores a new 5.7 MB snapshot (about 2 GB a year if run daily).

## Sample response

Shape only (values invented):

```json
["0-synthetic-phish.example", "<canister id>.icp0.io", "<canister id>.raw.icp0.io"]
```

Quirk: a few entries carry the canister id **without hyphens**
(`<23 characters ending in cai>.icp0.io`). The collector restores the hyphens and keeps the
id only if the principal checksum is valid.

## How the collector uses it

- `collectors/signals_blocklist.py`: `SignalsBlocklistCollector(blocklist_http(contact))`.
  GitLab is allowed only through `blocklist_http` (`SafeHttpClient(extra_hosts=...)`), never the
  global `ALLOWLIST`. This client alone raises the body cap to 32 MB (`MAX_BLOCKLIST_BYTES`);
  the shared 1 MB default for gateway bodies is unchanged.
- The body is stored verbatim (after secret redaction; none found on 2026-10-16) and never
  rendered. Hostnames are **never resolved or visited**.
- `parsers/signals_blocklist.py` emits:
  - `signal.blocklist_polled` (subject: the feed): status (`ok`, `error`, `unusable_body`,
    `truncated`), entry count, ICP gateway hosts, canisters, unmapped ICP hosts;
  - `signal.canister_listed` (subject: the canister), one per canister with all its listed
    hosts. IOC enrichment marks canisters already in the `iocs` table.
- The digest lists them in a **Blocklisted ICP canisters (low authority)** section, hosts as
  code, never as links. It is left out when `--keyword` is used; `--ioc-only` keeps only IOC
  canisters.

## Licensing

The project's own pages conflict: the dataset page says CC0 1.0 (repository code MIT), the
HuggingFace card says MIT, and another page says CC-BY-4.0. Internal research use is fine
under all three. Before republishing entries (e.g. in an export), credit PhishDestroy and
confirm the licence.

## Safety review (2026-10-16)

- **Machine:** only GitLab is contacted; it learns this machine's IP and the User-Agent
  contact. PhishDestroy's own servers are never contacted. The body is inert text parsed as
  JSON by the standard library; nothing in it is executed, resolved or visited.
- **OPSEC:** a bulk download reveals nothing about what is tracked; per-domain lookups would,
  so they are not used.
- **Data quality:** anonymous operators, community reports, self-reported accuracy, an appeals
  process for false positives. Hence low authority; a listed canister should be confirmed with
  the project's own read-only collectors before any action.
- **Size:** 5.7 MB per changed snapshot.

## Open questions

- Which licence applies to the list (CC0, MIT or CC-BY-4.0)?
- Should listed canisters be added to monitoring (`canister inspect`, watched canisters)?
  That sends read-only queries to phishing canisters, an OPSEC decision for the maintainer.

## URLs consulted

- https://phishdestroy.io/dataset (2026-10-16)
- https://phishdestroy.io/policy, https://phishdestroy.io/about, https://phishdestroy.io/appeals
- https://gitlab.com/phishdestroy/destroylist/-/raw/main/list.json (2026-10-16)
- https://gitlab.com/phishdestroy/destroylist/-/raw/main/dns/active_domains.json (2026-10-16)
