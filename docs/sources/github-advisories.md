Status: VERIFIED

# GitHub Advisory Database (global advisories, malware type)

## Summary

The GitHub Advisory Database publishes global security advisories (GHSA IDs) through the REST
endpoint `GET /advisories` and the GraphQL `securityAdvisories` query. Advisories of type
`malware` are imported automatically from the npm security team and the OpenSSF Malicious
Packages repository. They have no patched version, carry CWE-506 ("Embedded Malicious Code"),
and show up in OSV as aliases of `MAL-*` records. For this project the database is a
**corroborating source**: it confirms that a package version was malicious and supplies
GHSA/MAL cross-references. It does **not** usually carry canister IDs. Those come from OSV
`database_specific` IOCs or from vendor write-ups.

Endpoints, filters and limits were checked against docs.github.com on 2026-10-15. Campaign GHSA
IDs were checked on public github.com/advisories and osv.dev pages. No call was made to
api.github.com and the gh CLI was not used.

## Endpoints

Base `https://api.github.com`. Headers: `Accept: application/vnd.github+json`,
`X-GitHub-Api-Version: <pinned date>`. The docs page currently shows `2026-03-10`.

**`GET /advisories`** lists global advisories. Relevant query parameters:

| Param | Values / notes |
|---|---|
| `type` | `reviewed` (default), `malware`, `unreviewed`. Malware is **excluded unless `type=malware`**. |
| `ecosystem` | `npm`, `pip`, plus rubygems, maven, nuget, composer, go, rust, erlang, actions, pub, swift, other |
| `affects` | `package` or `package@version`, comma-separated or repeated `affects[]=`. Max 1000 packages. |
| `published`, `updated` | date or range in search syntax (`>=2026-03-01`, `2026-03-19..2026-03-31`) |
| `modified` | same syntax; matches **either** updated **or** published. Use for incremental sync. |
| `ghsa_id`, `cve_id`, `severity`, `cwes`, `is_withdrawn` | direct filters (`cwes=506` is useful for malware) |
| `sort` / `direction` | `published` (default), `updated`, `epss_*`; `asc` / `desc` (default `desc`) |
| `per_page`, `before`, `after` | max 100, default 30; cursor pagination via the `Link` header |

Status codes: 200, 422 (validation failed), 429 (rate limited).

Example incremental poll: `GET /advisories?type=malware&ecosystem=npm&modified=>=2026-10-14&sort=updated&direction=asc&per_page=100`,
then the same call with `ecosystem=pip`.

**`GET /advisories/{ghsa_id}`** returns a single advisory (200 or 404).

**GraphQL alternative** (`POST https://api.github.com/graphql`, needs a token): query
`securityAdvisories(classifications: [MALWARE], publishedSince:, updatedSince:, orderBy: {field: UPDATED_AT, direction: ASC}, first: 100, after:)`.
`SecurityAdvisoryClassification` is `GENERAL | MALWARE`. `securityAdvisories` has **no
`ecosystem` argument**. Filter on `vulnerabilities(ecosystem: NPM|PIP)` inside the node, or use
`securityVulnerabilities(ecosystem:, classifications:)`. Fields include `ghsaId`,
`classification`, `identifiers`, `summary`, `description`, `references`, `publishedAt`,
`updatedAt`, `withdrawnAt`, `cwes`, `vulnerabilities`. REST is preferred because it works
without a token and filters on ecosystem server-side.

**Optional code search, `GET /search/code` (OFF by default).** It always requires
authentication. Its limit is 10 requests/minute, separate from and stricter than the general
search limit. It returns at most 1000 results per query (`per_page` max 100). It searches only
the default branch and only files under 384 KB. Queries are limited to 256 characters
(excluding qualifiers) and at most five AND/OR/NOT operators. `sort` and `order` are marked
"closing down". The only use here would be looking for canister-ID literals
(`"raw.icp0.io"`, a known canister ID) in public repos. It would be opt-in behind a separate
setting and a token.

## Auth

- Token comes from the environment only: `GITHUB_TOKEN`. It is never written to config,
  cassettes, logs or notes, and the redaction layer must mask it.
- **The collector is disabled when `GITHUB_TOKEN` is absent.** This is the conservative
  project choice. The REST advisory endpoints themselves accept unauthenticated requests, but
  only at 60 requests/hour per IP.
- A fine-grained PAT with no repository permissions is enough for public advisory data.
  GraphQL and code search always need a token.
- Code search needs a second explicit opt-in flag in addition to the token.

## Rate limits

Primary limits, per docs.github.com:

- Unauthenticated: 60 requests/hour per originating IP.
- Authenticated user (PAT or OAuth): 5,000 requests/hour.
- `GITHUB_TOKEN` in Actions: 1,000 requests/hour per repository.
- GitHub App installations: 5,000 to 12,500 requests/hour.

Secondary limits:

- At most 100 concurrent requests, shared between REST and GraphQL.
- 900 points/minute for REST (a GET costs 1) and 2,000 points/minute for GraphQL.
- At most 90 s of CPU time per 60 s of real time.

Search limits: 30 requests/minute authenticated and 10/minute unauthenticated for search
endpoints. Code search is always 10/minute and authenticated only.

Response headers: `x-ratelimit-limit`, `-remaining`, `-used`, `-reset` (UTC epoch) and
`-resource`, plus `retry-after` on secondary-limit errors.

Backoff: when a 403/429 has `retry-after`, wait that many seconds. When `remaining == 0`, wait
until `reset`. Otherwise wait at least 60 s, then back off exponentially and give up after N
retries. The docs warn that continuing to call while limited can get the integration banned.
The collector runs sequentially (concurrency 1) and has a budget well under the limits.

## Sample response

This is **synthetic**, built from https://docs.github.com/en/rest/security-advisories/global-advisories
(schema) and the public page https://github.com/advisories/GHSA-j3x7-94xp-wf43 (values).
Fields that public page does not show (timestamps to the second, nulls) are illustrative.

```json
[
  {
    "ghsa_id": "GHSA-j3x7-94xp-wf43",
    "cve_id": null,
    "url": "https://api.github.com/advisories/GHSA-j3x7-94xp-wf43",
    "html_url": "https://github.com/advisories/GHSA-j3x7-94xp-wf43",
    "repository_advisory_url": null,
    "summary": "Malware in @opengov/form-renderer",
    "description": "Any computer that has this package installed or running should be considered fully compromised. ...",
    "type": "malware",
    "severity": "critical",
    "source_code_location": null,
    "identifiers": [{"type": "GHSA", "value": "GHSA-j3x7-94xp-wf43"}],
    "references": ["https://github.com/advisories/GHSA-j3x7-94xp-wf43"],
    "published_at": "2026-04-07T22:54:50Z",
    "updated_at": "2026-04-07T22:54:50Z",
    "github_reviewed_at": "2026-04-07T22:54:50Z",
    "nvd_published_at": null,
    "withdrawn_at": null,
    "vulnerabilities": [
      {
        "package": {"ecosystem": "npm", "name": "@opengov/form-renderer"},
        "vulnerable_version_range": "= 0.2.20",
        "first_patched_version": null,
        "vulnerable_functions": []
      }
    ],
    "cwes": [{"cwe_id": "CWE-506", "name": "Embedded Malicious Code"}]
  }
]
```

## Malware advisories

- **Type and source.** `type: "malware"` (GraphQL `classification: MALWARE`). They are
  published automatically from the npm security team and OpenSSF Malicious Packages. IDs match
  `GHSA(-[23456789cfghjmpqrvwx]{4}){3}`. There is never a fixed version. Dependabot can raise
  malware alerts, and the only remedy is to remove the package.
- **Mapping to OSV.** The matching OSV record is a `MAL-YYYY-N` ID (ossf/malicious-packages)
  that lists the GHSA under `aliases`. Its `database_specific.malicious-packages-origins` lists
  `ghsa-malware` as one source, next to e.g. `google-open-source-security` and
  `amazon-inspector`. Example: MAL-2026-2211 has alias GHSA-j3x7-94xp-wf43, and the ghsa-malware
  origin was imported 2026-04-07. OSV, not GHSA, carries the IOCs. MAL-2026-2211 lists the URL
  `https://tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io/` and the domain `litellm.cloud`. Join on GHSA
  ID or (ecosystem, name, version).
- **npm security-holder packages.** After npm security removes a malicious package, the name is
  often republished as version `0.0.1-security` with a "security holding" notice linking to the
  npm advisory search. If a GHSA lists a package whose registry `latest` is now
  `0.0.1-security`, that confirms the takedown. The malicious versions are no longer installable,
  so the GHSA/OSV record is the durable evidence. Compromised legitimate packages (e.g. the
  `@opengov` scope) are usually not replaced by placeholders.

### Campaign lookups (accessed 2026-10-15)

| Campaign | Package (ecosystem) | GHSA | Status |
|---|---|---|---|
| CanisterWorm (Mar 2026, canister `tdtqy-oyaaa-aaaae-af2dq-cai`) | `@opengov/form-renderer` 0.2.20 (npm) | GHSA-j3x7-94xp-wf43 (OSV alias of MAL-2026-2211) | **found** |
| CanisterSprawl (Apr 2026, canister `cjn37-uyaaa-aaaac-qgnva-cai`) | `pgserve` 1.1.11-1.1.14 (npm) | GHSA-v892-cmx2-hjq8 (OSV alias of MAL-2026-2991) | **found** |
| CanisterSprawl | `@automagik/genie` (npm) | GHSA-ppw4-42v6-538v | **found** (versions not checked) |
| CanisterSprawl | PyPI packages | none identified | **not found** (not searched exhaustively) |

Other `@opengov` packages in CanisterWorm (`@opengov/form-builder` 0.12.3,
`@opengov/form-utils` 0.7.2) have GitLab advisories GMS-2026-48 and GMS-2026-50 and OSV MAL
records (MAL-2026-2210, MAL-2026-2212). Their GHSA IDs were **not checked**.

The pgserve OSV record (MAL-2026-2991) does **not** list the CanisterSprawl canister ID as an
IOC. The link between that record and the canister comes from vendor write-ups only.

## How the collector will use it

1. Disabled unless `GITHUB_TOKEN` is set. Code search stays off unless separately opted in. The
   allowlisted HTTP client only reaches `api.github.com` paths `/advisories*` (and
   `/search/code` when opted in). It is read-only, GET only.
2. Incremental sync: `type=malware`, `ecosystem` in {npm, pip}, `modified=>=<cursor>`,
   `sort=updated&direction=asc`, `per_page=100`, following `Link` cursors. The cursor is stored
   as the max `updated_at` seen.
3. Targeted lookups: `affects=<pkg>@<ver>` for packages already linked to a canister by other
   sources (OSV, ThreatFox, vendor reports), and `GET /advisories/{ghsa_id}` for aliases found
   in OSV.
4. Store the raw JSON in the raw store unchanged, then normalise to
   (ghsa_id, ecosystem, package, version_range, published_at, withdrawn_at, aliases).
   Canister-ID extraction runs over `description` and `references` with the shared principal
   regex, but most hits are expected from the OSV join, not from GHSA text.
5. A GHSA raises confidence in a package-to-campaign link. It never creates a canister IOC by
   itself. Withdrawn advisories (`withdrawn_at` set) downgrade the link.
6. Tests use cassettes built from the synthetic sample above (`synthetic: true`).

## Open questions

- Should the collector run unauthenticated at 60/hour when no token is present? The current
  choice is no, matching the task brief.
- Is the `ecosystem=pip` malware coverage comparable to npm? The docs do not state which
  ecosystems malware advisories cover.
- Which `X-GitHub-Api-Version` should be pinned? The docs show `2026-03-10`. Confirm it at
  implementation time.
- Do CanisterSprawl PyPI packages have GHSA malware advisories? None were found in this pass.
- Does github/advisory-database (the git repo) include malware advisories? The docs do not say.
  If it does, that would be an offline alternative to the API.
- What licence applies to advisory data reuse? It was not stated on the pages consulted.

## URLs consulted

All accessed 2026-10-15.

- https://docs.github.com/en/rest/security-advisories/global-advisories
- https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api
- https://docs.github.com/en/rest/search/search
- https://docs.github.com/en/graphql/reference/security-advisories
- https://docs.github.com/en/code-security/security-advisories/working-with-global-security-advisories-from-the-github-advisory-database/about-the-github-advisory-database
- https://github.com/advisories/GHSA-j3x7-94xp-wf43
- https://github.com/advisories?query=type%3Amalware+pgserve
- https://github.com/advisories?query=type%3Amalware+automagik
- https://osv.dev/vulnerability/MAL-2026-2211
- https://osv.dev/vulnerability/MAL-2026-2991
- https://advisories.gitlab.com/npm/@opengov/form-utils/GMS-2026-50/
- https://advisories.gitlab.com/npm/@opengov/form-builder/GMS-2026-48/
- https://bastion.tech/blog/canistersprawl-npm-self-propagating-worm-pgserve
- https://labs.cloudsecurityalliance.org/research/csa-research-note-npm-canistersprawl-supply-chain-worm-20260/
- https://expel.com/blog/more-supply-chain-compromises-namaste-xinference-and-more/
- https://npmjs.com/package/amzn
