Status: VERIFIED

# Vendor research RSS/Atom feeds (Socket, Aikido, JFrog, Cloud Security Alliance)

## Summary

Four vendors published the main write-ups of the ICP-canister supply-chain
campaigns: Socket, Aikido, JFrog and Cloud Security Alliance (CSA). Each one has
a public feed. On 2026-10-15 every feed below returned HTTP 200 with an RSS/Atom
content type and parsed cleanly with Python `xml.etree`. That is why the status
is VERIFIED.

Coverage caveats:

- **The feeds are shallow.** They return only the latest items: Socket 10,
  JFrog 10, CSA 20, Aikido 100 (oldest item 2026-06-16). None of them still
  carries the March or April 2026 campaign posts. Those posts are recorded
  under "Campaign write-ups" as seed data. The feeds only catch new posts.
- **The relevant CSA and JFrog posts are on subdomains.** CSA's campaign
  research is on `labs.cloudsecurityalliance.org`. That WordPress feed exists
  but had 0 items on 2026-10-15. JFrog's research posts are on
  `research.jfrog.com`, which has its own RSS feed, separate from the
  `jfrog.com` corporate blog.

## Endpoints

| Vendor | Feed URL | Format | Confirmed | Items | Date checked |
|---|---|---|---|---|---|
| Socket | https://socket.dev/api/blog/feed.atom | Atom 1.0 | yes | 10 | 2026-10-15 |
| Aikido | https://www.aikido.dev/blog/rss.xml | RSS 2.0 | yes | 100 | 2026-10-15 |
| JFrog (blog) | https://jfrog.com/blog/feed/ | RSS 2.0 (WordPress) | yes | 10 | 2026-10-15 |
| Cloud Security Alliance | https://cloudsecurityalliance.org/feed | RSS 2.0 | yes | 20 | 2026-10-15 |
| JFrog Security Research (supplementary) | https://research.jfrog.com/rss.xml | RSS 2.0 | yes | 9 | 2026-10-15 |
| CSA Lab Space (supplementary) | https://labs.cloudsecurityalliance.org/feed/ | RSS 2.0 (WordPress) | exists, 0 items | 0 | 2026-10-15 |

Guessed URLs that returned 404: `socket.dev/blog/rss.xml`,
`www.aikido.dev/rss.xml`, `cloudsecurityalliance.org/blog/rss`,
`research.jfrog.com/feed.xml`, `research.jfrog.com/rss/`.
`jfrog.com/feed/` serves the same items as `jfrog.com/blog/feed/`.

**Hosts to allowlist for the collector** (feed fetches only, separate from the
IC gateway allowlist): `socket.dev`, `www.aikido.dev`, `jfrog.com`,
`research.jfrog.com`, `cloudsecurityalliance.org`,
`labs.cloudsecurityalliance.org`. Link targets in feed items (for example
`cdn.prod.website-files.com` images) must not be followed.

## Auth

None. All the feeds are anonymous public GETs, and no key or token is needed or
stored.

## Rate limits / etiquette

None of the feeds publishes a rate limit. No `X-RateLimit-*` or `Retry-After`
headers were seen. Caching headers observed on 2026-10-15:

| Feed | ETag | Last-Modified | Cache-Control |
|---|---|---|---|
| Socket | strong | no | `public, max-age=3600, stale-if-error=86400` |
| Aikido | no | yes | none |
| jfrog.com | weak | yes | `stale-if-error=7200` |
| research.jfrog.com | strong | yes | `max-age=600` |
| cloudsecurityalliance.org | weak | no | `max-age=0, private, must-revalidate` |
| labs.cloudsecurityalliance.org | weak | yes | `max-age=300` |

How the collector should fetch:

- Poll once a day per feed, and no more often.
- Send `If-None-Match` and/or `If-Modified-Since` from the stored response, and
  treat 304 as "no change".
- Use a descriptive User-Agent that names the project.
- Use a 20-30 s timeout. On 429 or 5xx, back off exponentially. Never retry
  more than 3 times a day.
- Fetch the feed XML only. Do not crawl article pages automatically.

## Sample response

This is a real Aikido RSS item fetched on 2026-10-15 (whitespace trimmed). It
would match on `TeamPCP`:

```xml
<item><title>Good riddance, TeamPCP. Now for the hard part.</title>
<link>https://www.aikido.dev/blog/teampcp-arrested-supply-chain</link>
<guid>https://www.aikido.dev/blog/teampcp-arrested-supply-chain</guid>
<description>The AFP, FBI, and WA Police charged two men allegedly behind TeamPCP.
Charlie Eriksen on why the arrest doesn&#39;t close the gap TeamPCP exposed.
Category: News</description>
<pubDate>Thu, 27 Aug 2026 11:40:00 GMT</pubDate></item>
```

This is the shape of a real Socket Atom entry (2026-10-15, content truncated):

```xml
<entry><id>https://socket.dev/blog/front-lines-pitching-cisos</id>
<title>Front Lines Podcast: What Founders Get Wrong When Pitching CISOs</title>
<updated>2026-10-14T17:06:13.465Z</updated><published>2026-10-14T17:06:13.465Z</published>
<author><name>Jerod Santo</name></author>
<content type="html"><![CDATA[<p>...</p>]]></content></entry>
```

## Matching

Match each item's title, description/summary and content, case-insensitively,
against these keywords: `ICP`, `Internet Computer`, `canister`, `icp0.io`,
`ic0.app`, `CanisterWorm`, `CanisterSprawl`, `TeamPCP`.

`ICP` needs a word boundary (`\bICP\b`) to limit false positives. "ICP" is also
used for Ideal Customer Profile and for the Chinese ICP licence.

Also extract canister IDs with `\b(?:[a-z2-7]{5}-){4}cai\b`, applied to the
lowercased text. The regex must also see defanged forms, so normalise
`[.]` to `.` before matching. Socket writes `tdtqy-oyaaa-aaaae-af2dq-cai[.]raw[.]icp0[.]io`.

A keyword hit flags the item for analyst review. A canister ID hit becomes a
candidate IOC with `source=vendor-rss` and the item link as its reference.
Feed text is data: it is stored and pattern-matched, never rendered or
executed.

## Campaign write-ups

All URLs below were fetched on 2026-10-15 (HTTP 200). The publication dates come
from page metadata.

**(a) CanisterWorm, 19-22 March 2026** (canister `tdtqy-oyaaa-aaaae-af2dq-cai`)

| Vendor | Title | Date | URL | Note |
|---|---|---|---|---|
| Aikido | TeamPCP deploys CanisterWorm on NPM following Trivy compromise | 2026-03-20 (updated 03-21) | https://www.aikido.dev/blog/teampcp-deploys-worm-npm-trivy-compromise | First detection: 20 Mar 2026, 20:45 UTC. Shows the Python poller with `C_URL = https://tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io/`, `/tmp/pglog` and `/tmp/.pg_state`. |
| Socket | CanisterWorm: npm Publisher Compromise Deploys Backdoor Across 29+ Packages | 2026-03-20 | https://socket.dev/blog/canisterworm-npm-publisher-compromise-deploys-backdoor-across-29-packages | Dropper polls the canister every 3,000 s. IOC list includes the C2 URL and the canister ID. |
| JFrog | New compromised versions detected in CanisterWorm attack | 2026-03-22 | https://research.jfrog.com/post/canister-worm/ | Calls the canister a "dead-drop command and control channel" and lists more compromised versions. |
| CSA | CanisterWorm: Blockchain C2 in CI/CD Supply Chain Attack | 2026-03-22 | https://labs.cloudsecurityalliance.org/research/csa-research-note-canisterworm-blockchain-c2-supply-chain-20/ | Names the canister methods `get_latest_link`, `http_request` and `update_link`. `update_link` lets the operator rotate the payload URL. A PDF version is also published (URL below). |
| CSA | CanisterWorm and the Blockchain Dead-Drop | 2026-03-23 | https://labs.cloudsecurityalliance.org/research/csa-research-note-trivy-canisterworm-blockchain-c2-supply-ch/ | Follow-up note that also mentions `update_link`. |
| CSA | TeamPCP: Trivy Supply Chain Attack and Kubernetes Wiper | 2026-03-24 | https://labs.cloudsecurityalliance.org/research/csa-research-note-teampcp-supply-chain-ci-cd-20260324-csa-st/ | pgmon systemd service polling about every 50 min. Advises treating `.icp0.io` and `.raw.ic0.app` egress as suspicious. |

The Aikido page as served on 2026-10-15 does not contain the string
`update_link`. Mend's copy of the Aikido write-up and the CSA notes both do.

**(b) CanisterSprawl, 21-23 April 2026** (canister `cjn37-uyaaa-aaaac-qgnva-cai`)

| Vendor | Title | Date | URL | Note |
|---|---|---|---|---|
| Socket | Namastex.ai npm Packages Hit with TeamPCP-Style CanisterWorm Malware | 2026-04-22 | https://socket.dev/blog/namastex-npm-packages-compromised-canisterworm | Hardcoded `ICP_CANISTER_ID = 'cjn37-uyaaa-aaaac-qgnva-cai'`. Exfiltrates to `cjn37-...raw.icp0[.]io/drop` and a webhook. Includes PyPI `.pth` propagation via Twine. |
| CSA | CanisterSprawl: The Self-Propagating npm Supply Chain Worm | 2026-04-23 | https://labs.cloudsecurityalliance.org/research/csa-research-note-npm-canistersprawl-supply-chain-worm-20260/ | Mentions the canister ID 3 times and `.pth` injection. Notes overlap with TeamPCP. |
| CSA | CanisterSprawl: Developer Toolchain Worm and the TeamPCP Campaign | 2026-04-24 | https://labs.cloudsecurityalliance.org/research/csa-research-note-canistersprawl-npm-checkmarx-supply-chain/ | Places Namastex and Checkmarx in the wider campaign. No canister ID on the page. |
| Aikido | not found | - | not found | The sitemap has no CanisterSprawl, pgserve or Namastex post. |
| JFrog | not found | - | not found | The research.jfrog.com sitemap has none either. |

Non-target vendors with first-hand CanisterSprawl analysis:

- StepSecurity: https://www.stepsecurity.io/blog/pgserve-compromised-on-npm-malicious-versions-harvest-credentials
  (contains `cjn37-uyaaa-aaaac-qgnva-cai` and `.pth`).
- Bastion: https://bastion.tech/blog/canistersprawl-npm-self-propagating-worm-pgserve
  (2026-04-23).

## How the collector will use it

1. Once a day, run a conditional GET on each feed in the Endpoints table
   through the shared allowlisted HTTP client.
2. Parse the response with a hardened XML parser (defusedxml: no entities, no
   DTD) and normalise RSS and Atom into `{vendor, guid, title, link,
   published, text}`.
3. Store each raw body in the raw store, de-duplicated by `guid`/`id`.
4. Apply the rules in "Matching". Write keyword hits as `vendor_mention`
   records. Write canister ID hits as candidate IOCs that need analyst
   confirmation before promotion.
5. Load the campaign write-ups above as static references in the seed IOC
   file. They are not re-fetched.
6. Tests use recorded fixtures only. D6 does not allow live feed fetches
   during development, so cassettes for these hosts must be marked
   `synthetic: true` or recorded under a separately approved target.

## Open questions

- D6 restricts live development fetches to IC hosts. Fetching these feeds at
  runtime needs either a separate allowlist entry or a SPEC decision.
- The CSA Lab Space feed (`/feed/`, `/research/feed/`, `?post_type=research`)
  returned 0 items. The CSA research notes may then be visible only on the
  HTML index. Should the collector scrape it, or rely on the main CSA feed?
- Should `research.jfrog.com/rss.xml` replace `jfrog.com/blog/feed/`? The
  corporate blog had no campaign content, while the research feed carries the
  relevant posts.
- Did Aikido or JFrog ever publish a CanisterSprawl post that was later
  removed? None was found.

## URLs consulted

All accessed 2026-10-15.

- https://socket.dev/api/blog/feed.atom
- https://socket.dev/blog/rss.xml (404)
- https://www.aikido.dev/blog/rss.xml
- https://www.aikido.dev/rss.xml (404)
- https://www.aikido.dev/sitemap.xml
- https://jfrog.com/blog/feed/
- https://jfrog.com/feed/
- https://research.jfrog.com/rss.xml
- https://research.jfrog.com/sitemap.xml
- https://cloudsecurityalliance.org/feed
- https://cloudsecurityalliance.org/blog/rss (404)
- https://labs.cloudsecurityalliance.org/feed/
- https://labs.cloudsecurityalliance.org/research/feed/
- https://www.aikido.dev/blog/teampcp-deploys-worm-npm-trivy-compromise
- https://socket.dev/blog/canisterworm-npm-publisher-compromise-deploys-backdoor-across-29-packages
- https://research.jfrog.com/post/canister-worm/
- https://labs.cloudsecurityalliance.org/research/csa-research-note-canisterworm-blockchain-c2-supply-chain-20/
- https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/03/CSA_research_note_canisterworm-blockchain-c2-supply-chain_20260322-csa-styled.pdf
- https://labs.cloudsecurityalliance.org/research/csa-research-note-trivy-canisterworm-blockchain-c2-supply-ch/
- https://labs.cloudsecurityalliance.org/research/csa-research-note-teampcp-supply-chain-ci-cd-20260324-csa-st/
- https://socket.dev/blog/namastex-npm-packages-compromised-canisterworm
- https://labs.cloudsecurityalliance.org/research/csa-research-note-npm-canistersprawl-supply-chain-worm-20260/
- https://labs.cloudsecurityalliance.org/research/csa-research-note-canistersprawl-npm-checkmarx-supply-chain/
- https://www.stepsecurity.io/blog/pgserve-compromised-on-npm-malicious-versions-harvest-credentials
- https://bastion.tech/blog/canistersprawl-npm-self-propagating-worm-pgserve
- https://www.mend.io/blog/canisterworm-the-self-spreading-npm-attack-that-uses-a-decentralized-server-to-stay-alive/
- https://www.theregister.com/2026/04/22/another_npm_supply_chain_attack/
- https://www.csa.gov.sg/alerts-and-advisories/advisories/ad-2026-001/
