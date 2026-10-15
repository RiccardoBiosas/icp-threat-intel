Status: VERIFIED

# PyPI registry APIs (JSON, Simple index, RSS)

## Summary

PyPI exposes read-only, unauthenticated metadata APIs. The collector uses them to find new releases (RSS),
list a project's files and status (Simple API, PEP 691 JSON), read release metadata and digests (JSON API),
and fetch the distribution files that rule H3 inspects. All endpoints below come from the official docs at
docs.pypi.org. Items not confirmed in official docs are marked **(unverified)**. Our use is strictly read-only:
we never upload, never report automatically and never install.

## Endpoints

| Purpose | Method and URL | Notes |
|---|---|---|
| New releases (all projects) | `GET https://pypi.org/rss/updates.xml` | Recommended polling method. Items: project name, description, version, release link. |
| New projects | `GET https://pypi.org/rss/packages.xml` | Newly created projects. |
| Per-project releases | `GET https://pypi.org/rss/project/<project>/releases.xml` | Latest releases of one project. |
| Project metadata | `GET https://pypi.org/pypi/<project>/json` | `info` (latest version), `releases` (deprecated), `urls`, `vulnerabilities`, `last_serial`, `ownership`. |
| Release metadata | `GET https://pypi.org/pypi/<project>/<version>/json` | Same, without `releases`; `urls` = files of that release. |
| Simple index (project) | `GET https://pypi.org/simple/<project>/` with `Accept: application/vnd.pypi.simple.v1+json` | PEP 691 JSON. Without the header, HTML is returned. `meta.api-version` is `1.4`; `meta._last-serial`; header `X-PyPI-Last-Serial`. |
| Core metadata file (PEP 658/714) | `GET <file url>.metadata` | Present when a file's `core-metadata` is a hash object (not `false`). Lets us read `METADATA` without downloading the wheel. |
| Distribution file | `GET https://files.pythonhosted.org/packages/...` | URL taken verbatim from `urls[].url` / Simple `files[].url`. Never constructed by hand. |
| XML-RPC (`changelog_since_serial` etc.) | `POST https://pypi.org/pypi` | **Do not use.** Legacy, "planned for deprecation"; may be rate limited. RSS + serials replace it. |
| BigQuery download stats | n/a | Not needed. |

Key JSON API fields (official docs):

- `info`: `name`, `version`, `summary`, `author`, `classifiers`, `project_urls`, `requires_dist`, `requires_python`, `yanked`, `yanked_reason`.
- File objects (`urls[]`, `releases[ver][]`): `filename`, `packagetype` (`sdist`/`bdist_wheel`), `size`,
  `upload_time`, `upload_time_iso_8601`, `digests` (`sha256`, `blake2b_256`, `md5`), `core-metadata`,
  `requires_python`, `url`, `yanked`, `yanked_reason`. Deprecated fixed values: `downloads` (-1), `has_sig` (false), `bugtrack_url` (null).
- `vulnerabilities[]`: `id`, `aliases`, `summary`, `details`, `fixed_in`, `link`, `source`, `withdrawn`.
- `releases` is deprecated; the docs recommend the Simple (Index) API for listing all files and versions.

Project status markers (PEP 792, Final 2025-07-08; canonical spec on packaging.python.org):

- Simple JSON carries `project-status: {"status": ..., "reason": ...}`; HTML uses `pypi:project-status` and
  `pypi:project-status-reason` meta tags. Values: `active` (default), `archived`, `quarantined`, `deprecated`.
- `quarantined` = considered unsafe (e.g. malware): the index MUST NOT accept uploads and MUST NOT offer any
  distributions; the PEP example shows an empty `files` list. PyPI's quarantine (blog, 2024-12-30) hides the
  project from the Simple index so pip cannot install it; admins later either clear it or remove it.
- Removed projects return 404 from JSON and Simple endpoints **(unverified; assumption, not stated in
  docs)**. A 404 after we previously saw a version is itself an event worth recording.
- The PEP bullet text says `project-status.state` while its example uses `status`; parse both.

## Auth

None for any read endpoint. Upload (`upload.pypi.org`) and the secret-disclosure API
(`POST /_/secrets/disclose-token`, signed, case-by-case access) need credentials and are out of scope. The
malware "Observations" reporting API is an invitation-only beta for trusted reporters; we will not call it.
Any report to PyPI is a human action through the disclosure gate (SPEC), never automated.

Send a `User-Agent` that identifies the client and a contact, e.g. `icp-threat-intel/<version> (+<repo URL>)`.

## Rate limits

- Official docs: PyPI does not rate limit the JSON, RSS or Index APIs at the edge; XML-RPC may be limited.
  Abusive clients may be blocked temporarily or permanently. Spread bulk work out over time; consider a mirror.
- All responses are CDN cached (PyPI is fronted by Fastly; the docs page does not name the vendor). Inspect
  `X-Cache` / `X-Cache-Hits`; send `If-None-Match` with the stored `ETag` to avoid refetching unchanged bodies.
- Collector budget (our choice, conservative): poll `updates.xml` every 5 minutes, at most 1 request/second
  overall to pypi.org and files.pythonhosted.org, exponential backoff on 429/5xx, honour `Retry-After`.

## Sample response

Synthetic, built from https://docs.pypi.org/api/json/ (field names and shapes from the docs; values invented):

```json
{
  "info": {"name": "sampleproject", "version": "4.0.0", "requires_python": ">=3.9",
           "yanked": false, "yanked_reason": null},
  "last_serial": 22406780,
  "urls": [{
    "filename": "sampleproject-4.0.0-py3-none-any.whl",
    "packagetype": "bdist_wheel",
    "size": 4662,
    "upload_time_iso_8601": "2024-07-24T13:58:52.123456Z",
    "url": "https://files.pythonhosted.org/packages/.../sampleproject-4.0.0-py3-none-any.whl",
    "digests": {"sha256": "c23e447ea90d796d1e645c35c4b2de125040add12a845825546f91c93f391b6b",
                "blake2b_256": "...", "md5": "..."},
    "core-metadata": {"sha256": "a1d0c6e83f027327d8461063f4ac58a6e4a7a5d0a0e0d5b6c3b2e1f0a9b8c7d6"},
    "yanked": false, "yanked_reason": null
  }],
  "vulnerabilities": []
}
```

Simple API excerpt (from https://docs.pypi.org/api/index-api/ and the PEP 792 example):
`{"meta": {"_last-serial": 22406780, "api-version": "1.4"}, "name": "...", "project-status": {"status": "quarantined", "reason": "..."}, "files": []}`

## Version diff and install-hook extraction

Goal (SPEC H3): flag a new version that introduces a canister ID (`\b(?:[a-z2-7]{5}-){4}cai\b`) or an IC
gateway host (`icp0.io`, `ic0.app`, `raw.icp0.io`, `icp-api.io`) in code that runs without an explicit import.

1. RSS `updates.xml` item -> release JSON -> file list with `sha256` and `size`.
2. Find the previous version from the Simple JSON (`files`, sorted by `upload-time`), already stored or fetched once.
3. Download both versions' sdist and/or wheel (artifact rules below), list members, and diff only
   **added or changed** text members; matches present in both versions are lower signal.
4. Inspect, as text only:
   - `setup.py`, `setup.cfg`, `pyproject.toml` (custom build backends, `cmdclass` overrides such as `install`/`develop`/`egg_info`): run at sdist build/install time.
   - `*.pth` at the wheel root (installed into `site-packages`) or declared via `data_files`. **Why this matters:**
     per the `site` module docs, `.pth` lines starting with `import` (followed by space or tab) are executed
     with `exec()` at every interpreter startup, unless `-S` is given, whether or not the package is ever
     imported. A single `import os;exec(...)` line in a `.pth` therefore runs on every `python` invocation in
     that environment. Python 3.15 deprecates these lines (ignored in 3.18/3.19 when a matching `.start` file
     exists), so also inspect new `*.start` entry-point files. Legitimate `.pth` files (e.g. `distutils-precedence.pth`, editable installs) usually hold paths or one well-known import; flag any `.pth` that is new, long, or contains `exec`, `base64`, `subprocess`, `urllib`, `socket` or a URL.
   - `__init__.py` of top-level packages and `*.dist-info/entry_points.txt`.
   - Obfuscated strings: decode base64/hex/zlib/rot13 literals and `bytes.fromhex`/`codecs.decode` arguments
     statically (bounded depth 3, bounded output size) and re-run the regexes on the decoded text. Never `eval`.
5. Also run the regexes on core metadata (`.metadata` file) `Project-URL`/`Home-page` fields.
6. Emit a candidate detection (status `candidate`) with evidence refs: project, version, file name, member
   path, line number, matched string, artifact sha256.

## Artifact handling

- Only fetch file URLs returned by the APIs, only from `files.pythonhosted.org`. Verify size against `size`
  and sha256 against `digests.sha256` before any parsing; mismatch -> discard and log.
- Store the raw archive locally content-addressed by sha256 (raw store, `raw_snapshots`); never upload it
  anywhere, never re-share samples, never submit to third-party scanners.
- Never execute, build, install or import anything from an artifact: no `pip`, no `setup.py`, no
  `python -m build`, no `importlib`. Parse Python only with `ast` (no exec) or regex on text.
- Safe extraction, in-memory or into a fresh empty directory outside the repo: use `zipfile`/`tarfile`
  members as data (`tarfile` `filter="data"`), reject absolute paths, `..`, symlinks, hardlinks, devices;
  caps: archive <= 50 MiB, member <= 10 MiB, total uncompressed <= 200 MiB, <= 5,000 members, compression
  ratio <= 100:1 (zip-bomb guard). Skip binary members except to hash them.
- Any process reading extracted files runs Python with `-I`, never from inside the extraction directory.

## How the collector will use it

- Scheduler job `pypi_updates`: poll `updates.xml` with ETag; for each item, store the raw body, then fetch
  release JSON only for watched projects (seed list, names in IOCs, projects sharing owners with flagged
  ones via `ownership.roles`) plus a sampled share of all updates to stay within the budget.
- Write `packages` / `package_versions` rows (name, version, upload time, digests, yanked, project-status).
- Run the H3 extraction above; matched canister IDs feed the canister enrichment queue (IC query calls only).
- Re-check Simple JSON for flagged projects to record transitions to `quarantined`, yanked or 404 as events.
- Allowlist hosts needed: `pypi.org` (JSON, Simple, RSS) and `files.pythonhosted.org` (files and `.metadata`).
  Not needed: `upload.pypi.org`, `test.pypi.org`, BigQuery. Per SPEC D6, these are only reached once a task
  permits it; tests use cassettes/synthetic fixtures.

## Known case: CanisterSprawl (April 2026)

- Socket (2026-04-22) and CSA (2026-04-23) report a worm in Namastex.ai-linked npm packages (`@automagik/genie`
  4.260421.33-.39, `pgserve` 1.1.11-1.1.13, plus `@fairwords/*`, `@openwebconcept/*`), first malicious
  `pgserve` publish 2026-04-21 22:14 UTC. Exfiltration to `cjn37-uyaaa-aaaac-qgnva-cai.raw.icp0.io/drop`
  and `telemetry.api-monitor.com`. IOC strings include `pypi-pth-exfil`, `dist-propagation-report`,
  "Technique: .pth file injection (TeamPCP/LiteLLM method)".
- PyPI side: when PyPI credentials are found, the payload builds a `.pth`-based Python payload and uploads
  it with Twine to projects the victim can publish. **No public source we consulted names affected PyPI
  projects or versions** (uncertain; not confirmed either way). The `.pth` file name and content are not published.
- Related but separate: TeamPCP's LiteLLM 1.82.7/1.82.8 and telnyx 4.87.1/4.87.2 (March 2026, PYSEC-2026-2/-3)
  used the `.pth` technique; PyPI quarantined both within ~2.5-3.7 h. xinference 2.6.0-2.6.2 (April 2026)
  is reported by secondary sources; attribution disputed, no link to this canister found.

## Open questions

1. Which PyPI projects/versions (if any) CanisterSprawl published; check OSV (`PYSEC`/`MAL-` entries) in a later task.
2. Exact JSON API behaviour for a quarantined project (200 with empty `urls`, or 404?) and whether
   `files.pythonhosted.org` still serves files; not stated in official docs.
3. Current XML-RPC docs page (docs.pypi.org/api/xml-rpc/ returned 404 on 2026-10-15); irrelevant if unused.
4. Whether PyPI's RSS `updates.xml` window (item count) is large enough at 5-minute polling during bursts; not documented.

## URLs consulted

Accessed 2026-10-15.

- https://docs.pypi.org/api/
- https://docs.pypi.org/api/json/
- https://docs.pypi.org/api/index-api/
- https://docs.pypi.org/api/feeds/
- https://docs.pypi.org/api/secrets/
- https://peps.python.org/pep-0792/
- https://docs.python.org/3/library/site.html
- https://blog.pypi.org/posts/2024-12-30-quarantine/
- https://blog.pypi.org/posts/2024-03-06-malware-reporting-evolved/
- https://blog.pypi.org/posts/2026-04-02-incident-report-litellm-telnyx-supply-chain-attack/
- https://socket.dev/blog/namastex-npm-packages-compromised-canisterworm
- https://labs.cloudsecurityalliance.org/research/csa-research-note-npm-canistersprawl-supply-chain-worm-20260/
- https://blog.ibvl.in/index.php/2026/04/27/teampcp-supply-chain-campaign-update-008-26-day-pause-ends-with-three-concurrent-compromises-checkmarx-kics-bitwarden-cli-cascade-xinference-pypi-canistersprawl-npm-worm-identified-and-tier-1/
