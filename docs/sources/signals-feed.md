Status: VERIFIED

# Signals feed: community forums (DFINITY developer forum first)

## Summary

The signals feed collects **low-authority** sources: public community forums where anyone
can post. It is separate from `vendor-rss.md`, which carries vendor research written up by
named security teams. Forum posts are early, noisy hints: a developer asking whether a
canister is malicious, a report of a phishing frontend, a DFINITY staff note about a
boundary-node block or a takedown. They help an analyst look somewhere, but never verify
anything by themselves:

- source type `signals_feed`, default reliability **40** (vendor RSS is 60);
- `signals_feed` evidence **never counts towards the two-signal rule**
  (`core/evidence.py`, `tests/guardrails/test_signal_sources.py`): `verified` still needs
  two different authoritative source types.

Each forum is one `SignalFeed` entry in `collectors/signals_feed.py` and its own `sources`
row (named after the feed), so a forum's reliability can be tuned on its own. The first and
only feed is the DFINITY developer forum, `dfinity-forum`.

Status is VERIFIED for `/posts.json` on `forum.dfinity.org` only: on 2026-10-15 the endpoint
and its `before` parameter answered as described below. Any new forum needs its own check
before its entry is added.

## Endpoints

| Feed | Request | Confirmed | Date checked |
|---|---|---|---|
| `dfinity-forum` | `GET https://forum.dfinity.org/posts.json` | 200, `application/json`, 50 posts, header `x-discourse-route: posts/latest` | 2026-10-15 |
| `dfinity-forum` | `GET https://forum.dfinity.org/posts.json?before=<post id>` | 200, the 50 posts with ids below `<post id>` | 2026-10-15 |
| `dfinity-forum` | `GET https://forum.dfinity.org/search.json?q=<term> order:latest&page=N` | 200, up to 50 hits (one per topic: `posts[].id/topic_id/post_number`, a short `blurb`), `grouped_search_result.more_full_page_results`; `phishing` returned 34 topics from 2020 to 2026 | 2026-10-15 |
| `dfinity-forum` | `GET https://forum.dfinity.org/t/<id>.json?include_raw=true` | 200, topic `title`/`slug`/`category_id`, `post_stream.posts` (first 20, with `raw`), `post_stream.stream` (every post id) | 2026-10-15 |
| `dfinity-forum` | `GET https://forum.dfinity.org/t/<id>/posts.json?post_ids[]=..&include_raw=true` | 200, `post_stream.posts` with `raw` for the given ids (no topic title) | 2026-10-15 |

Also checked and **not used**:

- `/latest.json` (topic list, no post text) and `/categories.json` (anonymous view lists the
  Developers category and its subcategories; other categories may be hidden from
  anonymous users);

## Search (`collect signals --search`)

The forum **logs every search** (its response carries a `search_log_id`). Searching for
canister ids or unpublished IOC values would tell the forum operator what is tracked, so:

- only the curated generic threat terms in `parsers/signals_keywords.SEARCH_TERMS` are sent
  (e.g. `phishing`, `drainer`, `malicious canister`, campaign names from public reporting);
- every term passes `check_search_term`: lowercase letters, spaces and hyphens only, no
  principal-shaped or hex token, no IOC value from the `iocs` table
  (`tests/guardrails/test_signals_search_terms.py`); there is no free-text search option;
- searches are 5 s apart (anonymous search limits); 429s back off in the shared client.

Search pages are stored as evidence (`signal.search_polled`), but blurbs are truncated, so
posts are taken from the topics: `/t/<id>.json?include_raw=true` once per topic (first 20
posts) and `/t/<id>/posts.json?post_ids[]=...` for hit posts beyond them. Default: 1 result
page per term (`--search-pages`, up to 5) and 50 topics per run (`--max-topics`, up to 500).
A full run is about 25 searches (about 2 minutes) plus one request per topic.

## Auth

None. No credentials and no cookies are sent; the collector reads only what an anonymous
visitor sees.

## Rate limits

No limit is documented for this forum, and no rate-limit headers were returned on
2026-10-15 (`cache-control: no-cache, no-store`). The shared client's default applies
(2 requests/second per host, burst 4, backoff on 429/5xx, `Retry-After` honoured). One poll
is 1 request per page; the default is 1 page and at most 10 (`MAX_PAGES`), or 200 with
`--backfill` (`MAX_BACKFILL_PAGES`, about 10,000 posts, back to early 2026 at the current
rate of about 28 posts a day); `--since YYYY-MM-DD` stops the walk earlier. The forum gets
about 50 posts in a day or two, so one page per poll every few hours keeps up.

## Sample response

Shape only (field names confirmed on 2026-10-15; values here are invented):

```json
{
  "latest_posts": [
    {
      "id": 103,
      "topic_id": 900,
      "topic_slug": "synthetic-topic-900",
      "topic_title": "Synthetic topic 900",
      "post_number": 1,
      "created_at": "2026-10-15T05:00:00.000Z",
      "username": "synthetic_user",
      "staff": false,
      "admin": false,
      "moderator": false,
      "category_id": 14,
      "raw": "Markdown source of the post",
      "cooked": "<p>HTML rendering of the post</p>"
    }
  ]
}
```

Each post object has about 70 keys; the collector reads only the ones above. `id`,
`topic_id`, `post_number` and `category_id` are integers. Posts are newest first.

## Pagination / quirks

- `before=<id>` returns posts with lower ids, so the collector walks back from the lowest
  id it has seen. An empty page, an error or an unusable body stops the walk.
- Every post on 2026-10-15 had `truncated: true`, yet `raw` held full-length text (up to
  about 7,800 characters). The flag is not used.
- About 1 in 6 posts named some canister id (developers share their own), so a canister
  mention alone is not suspicious. The parser records it, and IOC enrichment marks the ones
  that name a known IOC canister.

## How the collector uses it

- `collectors/signals_feed.py`: `SignalsFeedCollector(signals_http(contact), pages=1)`;
  targets are feed names, empty means all feeds. The forum host is allowed only through
  `SafeHttpClient(extra_hosts=...)` (`signals_http`), never the global `ALLOWLIST`.
- Bodies are stored verbatim (after secret redaction, since people paste keys into
  forums) and never rendered; links in posts are never followed.
- `parsers/signals_feed.py` reads the Markdown `raw` field as plain text, never the HTML,
  and emits:
  - `signal.feed_polled` per page (subject: the feed; status, post count, id range);
  - `signal.post_observed` per post naming a canister id, a threat keyword or an IOC term
    (subject `<feed>:<post id>`; url, author, staff flag, keywords, IOC terms, canister
    ids, IC hosts, a 280-character excerpt); `is_ioc` when it names an IOC term;
  - `signal.canister_reference` per canister id in such a post (subject: the canister).

## What is matched (parser v2)

- **Keywords** (`parsers/signals_keywords.py`, `KEYWORDS`): case-insensitive whole-word
  threat terms with a label each (`malicious`, `phishing`, `c2`, `supply_chain`,
  `dead_drop`, `stealer`, `rug_pull`, `impersonation`, `campaign` for CanisterWorm /
  CanisterSprawl / TeamPCP / Shai-Hulud, ...). Words common in ordinary developer talk are
  matched only in a threat context: bare "hack", "abuse", "worm", "compromise", "payload",
  "postinstall" and "seed phrase" are not keywords.
- **IOC terms**: non-canister values from the `iocs` table, read at ingest. Packages match
  by name (`npm:@scope/name@1.2.3` -> `@scope/name`), URLs without a trailing slash; file
  paths, systemd units and domains as they are. Whole terms only, values under 4 characters
  are skipped. IOCs added later apply when snapshots are parsed again (`parse`).
- **Canister ids** (SPEC regex) and **IC hosts** (recorded only).

## Operating rules

- Read only. Never post, reply, react or log in from the project.
- Never put undisclosed findings, or IOC values that are not yet public, into a forum: it
  is public and attackers read it.
- The forum is not a disclosure channel; disclosure goes through the private route in
  the Markdown export's checklist (`publishing/markdown.py`).

## Open questions

- Whether anonymous users see every public category (the anonymous `/categories.json` lists
  only Developers).
- Production rate limits of `forum.dfinity.org`.
- Which other forums are worth a feed (each needs its own check and an `OPEN_QUESTIONS.md`
  entry).

## URLs consulted

- https://forum.dfinity.org/posts.json (2026-10-15)
- https://forum.dfinity.org/posts.json?before=262921 (2026-10-15)
- https://forum.dfinity.org/latest.json, /categories.json, /search.json (2026-10-15)
- Discourse API reference (to recheck when adding another Discourse forum):
  https://docs.discourse.org/
