Status: EXPERIMENTAL

# npm registry APIs (packuments, replication feed, search, downloads, advisories)

## Summary

The public npm registry is the main feed for SPEC H3: a new npm version that adds a canister ID
(`\b(?:[a-z2-7]{5}-){4}cai\b`) or an IC gateway host (`icp0.io`, `ic0.app`, `raw.icp0.io`,
`icp-api.io`) to an install hook or an obfuscated string. All read endpoints below are anonymous
HTTPS GETs. The status is EXPERIMENTAL because this note relies on documentation only (no live
call was made, per SPEC D6). Rate limits are not published, and the `_changes` feed was rebuilt
in 2025 and has had reported reliability problems since.

Known case: `@opengov/form-renderer` 0.2.20 (CanisterWorm, TeamPCP, March 2026), OSV
`MAL-2026-2211` / `GHSA-j3x7-94xp-wf43`. Its IOC URL is
`https://tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io/`, the same canister as the SPEC §3 seed.
Sibling packages: `@opengov/form-builder` 0.12.3 (MAL-2026-2210) and `@opengov/form-utils` 0.7.2
(MAL-2026-2063). The CSA note on CanisterSprawl describes the payload as firing from a
`postinstall` hook. This collector must never download or install these packages.

## Endpoints

| Purpose | Request | Notes |
|---|---|---|
| Full packument | `GET https://registry.npmjs.org/<name>` | No `Accept` header returns the full doc: `time`, per-version `scripts`, `maintainers`, `readme`. It can exceed 10 MB uncompressed. |
| Abbreviated packument | same URL, `Accept: application/vnd.npm.install-v1+json` | Top level: `name`, `modified`, `dist-tags`, `versions`. Per version: `hasInstallScript`, `deprecated`, `dist`, deps. No `time`, no `scripts`. |
| Version doc | `GET https://registry.npmjs.org/<name>/<version>` (`version` may be `latest`) | One version's manifest, including `scripts` and `dist`. |
| Scoped names | `@scope/name` becomes `@scope%2fname` in the path | The `/` must be percent-encoded. The `@` stays literal. |
| Registry root | `GET https://registry.npmjs.org/` | Returns `db_name: "registry"` and `update_seq`. |
| Changes feed | `GET https://replicate.npmjs.com/registry/_changes?since=<seq>&limit=<n>` | Rebuilt in 2025; details below. |
| All docs | `GET/POST https://replicate.npmjs.com/registry/_all_docs` | Page with `startkey`. `skip` is not supported. |
| Replication root | `GET https://replicate.npmjs.com/` | Returns `db_name`, `engine`, `doc_count`, `update_seq` (the current sequence). |
| Search | `GET https://registry.npmjs.org/-/v1/search?text=<q>&size=<n>&from=<off>` | `size` defaults to 20, max 250. Qualifiers: `scope:`, `author:`, `maintainer:`, `keywords:`, `is:insecure`, `not:unstable`. Response: `objects[]`, `total`, `time`. The text must be at least 3 characters. |
| Downloads | `GET https://api.npmjs.org/downloads/point/<period>/<pkg>`, `/downloads/range/<period>/<pkg>`, `/versions/<pkg>/last-week` | Bulk queries allow up to 128 packages and 365 days, but not scoped packages. Single-package queries cover at most 18 months. Data starts 2015-01-10. Scoped names use `%2F` in `/versions`. |
| Bulk advisories | `POST https://registry.npmjs.org/-/npm/v1/security/advisories/bulk` | Body: `{name: [versions...]}`. Each advisory has `id`, `url`, `title`, `severity`, `vulnerable_versions`, `name`. Used by `npm audit` since npm v7. |

**Packument fields we use**

- `time`: a map from version to its ISO publish timestamp, plus `created` and `modified`. It is only in
  the full doc. Unpublished packages are believed to keep `time` (with an `unpublished` key)
  while losing `versions`. This is not confirmed in the docs; see Open questions.
- `versions[v].dist`: `tarball` (URL on `registry.npmjs.org/<name>/-/<file>.tgz`), `shasum`
  (SHA-1), `integrity` (SRI, normally `sha512-…`), `fileCount`, `unpackedSize`, `signatures`.
- `versions[v].scripts.preinstall|install|postinstall` (and `prepare`, which runs only on a
  local install without arguments). If a package has `binding.gyp` and no `install` or
  `preinstall` script, npm runs `node-gyp rebuild` by default, so treat `binding.gyp` as an
  implicit hook.
- `versions[v].hasInstallScript` (abbreviated doc only): a cheap pre-filter.
- `versions[v].deprecated`: a string with the deprecation message.
- Security holder: after npm removes a malicious package, the name is republished as version
  `0.0.1-security` (a placeholder with no code). This is a strong "was malicious" signal, and a
  version diff against it is meaningless.

**Changes feed (state as of 2025-2026).** GitHub deprecated the old CouchDB-style replication
API on 2025-05-29, after brownouts from 2025-04-02. The `npm-replication-opt-in: true` header
is now ignored. `skimdb.npmjs.com` returns a 301 to `replicate.npmjs.com`, which serves only
`/registry/_changes`, `/registry/_all_docs` and `/`. `_changes` accepts `since`, `limit`
(default 1000, max 10000), `descending`, `doc_ids` and `last-event-id`. `include_docs`, `feed`
(longpoll, continuous and eventsource), `filter`, `heartbeat` and `style` were removed. Each
change gives only an id and seq, so every packument has to be fetched separately from
`registry.npmjs.org`. Comments in the community thread report outages and sequence-number
regressions after the cutover.

## Auth

No auth is needed for any read endpoint above. npm documents higher rate allowances for
logged-in users, but SPEC forbids storing tokens, so the collector stays anonymous. It never
sends an `Authorization` header and never reads `~/.npmrc` or `NPM_TOKEN` (CanisterWorm
spread by stealing exactly these tokens).

## Rate limits

npm publishes no numeric limits. The 2017 npm blog states that every registry API is
rate-limited, that anonymous clients get less than logged-in ones, that clients must handle
HTTP 429, and that limits may tighten without notice. Search needs at least 3 characters of
text. Downloads limits are listed in the table above. Policy for the collector:

- At most 1 request per second per host, with one in-flight request.
- On 429 or 503, honour `Retry-After` if present. Otherwise use exponential backoff with
  jitter (base 2 s, cap 10 min).
- Prefer abbreviated packuments, and fetch the full doc (for `time` and `scripts`) only when
  `hasInstallScript` is true or the version is new.
- Cache by `ETag` / `If-None-Match` and the `modified` field.

## Sample response

Synthetic, built from https://github.com/npm/registry/blob/main/docs/responses/package-metadata.md
(field layout) and https://osv.dev/vulnerability/MAL-2026-2211 (name and version). The values
are illustrative, not real registry output. The hashes and the hook body are placeholders.

```json
{
  "name": "@opengov/form-renderer",
  "dist-tags": { "latest": "0.2.20" },
  "time": {
    "created": "2025-01-01T00:00:00.000Z",
    "modified": "2026-03-21T00:00:00.000Z",
    "0.2.19": "2025-12-01T00:00:00.000Z",
    "0.2.20": "2026-03-21T00:00:00.000Z"
  },
  "versions": {
    "0.2.20": {
      "name": "@opengov/form-renderer",
      "version": "0.2.20",
      "scripts": { "postinstall": "node <placeholder>.js" },
      "dist": {
        "tarball": "https://registry.npmjs.org/@opengov/form-renderer/-/form-renderer-0.2.20.tgz",
        "shasum": "<sha1-hex-placeholder>",
        "integrity": "sha512-<base64-placeholder>",
        "fileCount": 0,
        "unpackedSize": 0
      }
    }
  }
}
```

Synthetic `_changes` page, built from https://github.com/orgs/community/discussions/152515:
`{"results":[{"seq":123,"id":"@opengov/form-renderer","changes":[{"rev":"<rev>"}]}],"last_seq":123}`.

## Version diff and install-hook extraction

For each changed package id from `_changes` (or from a watchlist of scopes or names):

1. Fetch the abbreviated packument and compare `versions` with our stored set. Anything new is a
   candidate. If the only version is `0.0.1-security`, record a takedown event and stop.
2. For each new version, fetch the full packument once and take `time[v]` as the publish
   timestamp. Then extract the `scripts` values for `preinstall`, `install`, `postinstall` and
   `prepare`, and note whether `binding.gyp` is present.
3. **Metadata diff (no tarball).** Compare the hook strings, `dependencies`,
   `optionalDependencies`, `bin` and `main` with the previous version (by semver order, not
   publish order). A hook that is new or changed in a patch bump is a high-weight signal; the
   CanisterWorm pattern was a bumped patch version republished with a stolen token.
4. **Content scan (tarball).** Only for candidates. Scan every text file of the new and previous
   tarballs for the canister regex, the IC hosts above, `/tmp/pglog`, `pgmon.service` and
   `systemd --user` units. Before matching, decode common obfuscations: string-concatenation
   folding, hex and `\x`/`\u` escapes, base64 runs of 20 or more characters (one decode level,
   then rescan), `String.fromCharCode` arrays and reversed strings. Record only matches that are
   absent from the previous version.
5. Emit an H3 observation: package, version, publish time, file path, matched indicator, decode
   chain, tarball sha512 and the previous version. Canister IDs that are found go to the seed
   or watch queue for the IC collectors. They are never contacted from here.

## Tarball handling

- Download only through the shared allowlist client, from `registry.npmjs.org` `dist.tarball`
  URLs. Reject a tarball URL on any other host.
- Stream to a temp file with a hard size cap (proposed: 50 MB compressed). Compute SHA-512 and
  SHA-1 and compare them with `dist.integrity` / `dist.shasum`. Discard the file on mismatch.
  Store it content-addressed (`raw/npm/<sha512>.tgz`), read-only, locally only. Never upload a
  tarball or its hash-addressed content anywhere, never `npm install`, `npm pack` or `require`
  it, and never run any script it contains.
- Prefer not extracting to disk at all. Iterate members in memory with Python `tarfile`, using
  `filter="data"` (PEP 706) when extraction is unavoidable. Reject absolute paths, `..`
  components, symlinks, hardlinks and device files. Cap the member count (10 000), the
  per-member size (10 MB read for scanning) and the total uncompressed size (200 MB) to stop
  gzip and tar bombs. Treat all content as bytes, decode with `errors="replace"`, and scan only.
- Tarballs are untrusted data. The scanner runs under `python -I` in a directory that is
  separate from the store.

## How the collector will use it

- Allowlist additions (all HTTPS, GET only except the advisory POST, which is optional):
  `registry.npmjs.org`, `replicate.npmjs.com`, `api.npmjs.org`. Do not add
  `skimdb.npmjs.com`; it only redirects. Do not add `www.npmjs.com`; it serves the HTML UI.
- Poll `replicate.npmjs.com/registry/_changes` with a persisted `since` cursor (limit 1000,
  every 5 to 15 minutes), and fall back to the watchlist plus search
  (`/-/v1/search?text=scope:<s>`) if the feed stalls or the seq goes backwards.
- Enrich with downloads (`api.npmjs.org`) to rank blast radius, and with OSV/GHSA (separate
  source notes) to cross-label MAL ids.
- Tests use recorded or synthetic fixtures only (SPEC D6). Live recording against npm hosts is
  outside D6 today (D6 allows IC hosts only) and needs a spec decision; see Open questions.

## Open questions

1. SPEC D6 allows live recording only against IC hosts, so npm hosts cannot be recorded without
   a spec change. Until then, use synthetic fixtures only (conservative choice).
2. The exact shape of an unpublished or security-held packument (`time.unpublished`, removed
   `versions`) is not in the official docs and needs a recorded sample.
3. Does `_changes` deliver every publish reliably after the 2025 cutover? The community thread
   reports gaps, so a periodic reconciliation through `_all_docs` or the watchlist may be
   needed.
4. The registry publishes no numeric rate limits; 1 request per second is our own guess.
5. Is the bulk advisory endpoint stable for third-party use? It is documented only through
   `npm audit`, and OSV/GHSA may be the better advisory source.
6. Which file did the 0.2.20 payload hide in, and what obfuscation did it use? Public sources
   cite a `postinstall` hook and the raw.icp0.io URL, but not the exact file or the encoding.

## URLs consulted

All accessed 2026-10-15.

- https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md
- https://github.com/npm/registry/blob/main/docs/responses/package-metadata.md
- https://github.com/npm/registry/blob/main/docs/download-counts.md
- https://github.blog/changelog/2025-02-27-changes-and-deprecation-notice-for-npm-replication-apis/
- https://github.blog/changelog/2025-04-22-reminder-for-changes-to-npm-replication-feeds-apis/
- https://github.com/orgs/community/discussions/152515
- https://blog.npmjs.org/post/164799520460/api-rate-limiting-rolling-out
- https://docs.npmjs.com/cli/v11/using-npm/scripts
- https://docs.npmjs.com/cli/v12/commands/npm-audit/
- https://docs.npmjs.com/policies/unpublish/
- https://osv.dev/vulnerability/MAL-2026-2211
- https://osv.dev/vulnerability/MAL-2026-2210
- https://osv.dev/vulnerability/MAL-2026-2063
- https://labs.cloudsecurityalliance.org/research/csa-research-note-canisterworm-blockchain-c2-supply-chain-20/
- https://labs.cloudsecurityalliance.org/research/csa-research-note-canistersprawl-npm-checkmarx-supply-chain/
- https://peps.python.org/pep-0706/
