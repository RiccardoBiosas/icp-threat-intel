Status: VERIFIED

# Hacker News (Algolia HN Search API), signals feed

## Summary

Hacker News is a general technology forum, not an ICP community, but security researchers and
developers discuss supply-chain incidents there early; on 2026-10-16 a search for
`"internet computer" canister` returned a March 2026 comment on the LiteLLM/TeamPCP compromise
noting that the actor used the Internet Computer. It is consumed as part of the **signals
feed**: source type `signals_feed`, `sources` row `hackernews`, default reliability **40**,
never counted by the two-signal rule.

Volume is low: the query above returned 10 hits in total.

Status is VERIFIED for `search_by_date` and the hit fields below (checked 2026-10-16). The
official documentation page (https://hn.algolia.com/api) renders with JavaScript and could
not be read by the fetch tool, so the rate limit is not confirmed (see Rate limits).

## Endpoints

| Request | Confirmed | Date checked |
|---|---|---|
| `GET https://hn.algolia.com/api/v1/search_by_date?query=<q>&tags=(story,comment)&hitsPerPage=N&page=P` | 200, JSON with `hits`, `nbHits`, `page`, `nbPages`, `hitsPerPage`; newest first | 2026-10-16 |
| `numericFilters=created_at_i>UNIX` | documented filter for "after this date"; sent by `--since` | 2026-10-16 (third-party guides) |

Hit fields used (all checked on a live response):

| Field | Stories | Comments |
|---|---|---|
| `objectID` (string of digits) | yes | yes |
| `created_at` (ISO 8601 UTC), `created_at_i` | yes | yes |
| `author` | yes | yes |
| `title` | yes | – |
| `story_title` | – | yes |
| `story_id` | yes (its own id) | yes (the parent story) |
| `story_text` (HTML, optional) | sometimes | – |
| `comment_text` (HTML) | – | yes |

Permalink: `https://news.ycombinator.com/item?id=<objectID>`.

## Auth

None. No account, token or cookie.

## Rate limits

Not confirmed from the official page (JavaScript-rendered). Third-party guides describe the
API as free with no key. The collector is conservative: one query at a time, 1 s between
queries, at most 10 pages of 100 hits per query (Algolia returns at most 1,000 hits per
query), plus the shared client's per-host limit and backoff on 429/5xx.

## How the collector uses it

- `collectors/signals_hn.py`: `HackerNewsCollector(hn_http(contact))`. The host
  `hn.algolia.com` is allowed only through `hn_http` (`SafeHttpClient(extra_hosts=...)`).
- **Exact words (`hn_query_text`):** `internet computer` is sent as a quoted phrase, and every
  other word is quoted on its own, which turns off Algolia's typo tolerance. Checked on
  2026-10-16:

  | Query | Unquoted | Quoted |
  |---|---|---|
  | internet computer | 31,902 hits (the two words anywhere) | 309 (`"internet computer"`) |
  | dfinity | 1,498 hits, none of the first 50 containing the word ("infinity"-like typos) | 189, all containing it |
  | teampcp | 1,423 hits, 18 of the first 50 containing it | 89, all containing it |
  | icp canister | 7 hits | 1 (`"icp" "canister"`) |
  | canisterworm | 6 | 7 |
- **ICP-context gate (parser v3):** Hacker News is not about ICP, so an item counts only if
  its own text or its story title clearly refers to ICP: "Internet Computer" with that
  capitalisation, DFINITY, an ICP gateway host (`icp0.io`, `ic0.app`, `icp-api.io`), a
  campaign name (CanisterWorm, CanisterSprawl, TeamPCP, Shai-Hulud), a canister id or an IOC
  term. Bare "ICP" and "canister" are too ambiguous to count. Without ICP context, general
  security words (`malicious`, `exploit`, `c2`, `supply_chain`, ...) never make a signal;
  `signal.feed_polled` reports how many items were dropped (`out_of_context`). Keywords are
  matched in the item's own text only, never in the story title. Forum sources are not gated.
- **Queries:** Algolia logs searches. Only the curated `HN_QUERIES` in
  `parsers/signals_keywords.py` are sent (`internet computer`, `dfinity`, `icp canister`,
  `canisterworm`, `canistersprawl`, `teampcp`). Each carries ICP context, passes
  `check_search_term` and is refused if it contains an IOC value. Threat keywords are never
  sent; they are matched locally in the results.
- **Text:** `story_text` and `comment_text` are HTML. `html_to_text` extracts text with the
  standard-library HTML parser and decodes entities; nothing is rendered and links are never
  followed. For stories the title is part of the matched text; for comments the story title
  is kept as context (`topic_title`) but not matched.
- Each hit becomes a post (`ForumPost` with its permalink) and goes through the same parser
  path as forum posts: `signal.feed_polled` (with `request: hn_search` and the query),
  `signal.post_observed`, `signal.canister_reference`. Subjects are `hackernews:<objectID>`.
- CLI: `collect hackernews [--pages N] [--since YYYY-MM-DD] [--no-parse]`.

## After upgrading the parser

Run `python -m icp_threat_intel.cli parse` after a parser version change. Re-parsing adds new
events beside the old ones; the digest then uses, for each stored response, only the events of
its newest parse (`alerting/parses.py`), so items a stricter parser drops stop showing. Until a
response is re-parsed, its older events still count.

## Sample response

Shape only (values invented):

```json
{"hits": [{"objectID": "9101", "created_at": "2026-04-16T00:40:00Z", "created_at_i": 1776300000,
           "author": "someone", "comment_text": "<p>text</p>", "story_id": 9000,
           "story_title": "A story"}],
 "nbHits": 1, "page": 0, "nbPages": 1, "hitsPerPage": 100}
```

## Open questions

- Official rate limit of the HN Search API.
- Precision: general words such as "malicious" also match ordinary discussion (see
  `local-docs/signals-enhancement-precision-v1.0.0.md` for the planned measurement).

## URLs consulted

- https://hn.algolia.com/api (JavaScript-rendered; 2026-10-16)
- https://hn.algolia.com/api/v1/search_by_date?query=%22internet%20computer%22%20canister&tags=(story,comment)&hitsPerPage=5 (2026-10-16)
- https://cotera.co/articles/hacker-news-api-guide (third-party guide)
