# SPEC: icp-threat-intel

Stable specification for the loop. The agent reads this every iteration and never edits it. Change it only by hand, between loop runs.

## 1. Product

**icp-threat-intel** is an open-source threat-intelligence and threat-hunting platform for the Internet Computer Protocol (ICP). It focuses on canisters abused as attack infrastructure (dead-drop C2, exfiltration endpoints, payload hosting) and on the supply-chain campaigns that use them.

**Mission:** maintain the first public, continuously updated census of ICP canisters used as attack infrastructure; detect new ones from on-chain and registry signals; verify with a two-signal rule before labelling anything malicious; publish IOCs in formats the threat-intel community already ingests.

## 2. Decisions (pre-answered; do not ask about these)

| ID | Decision |
|---|---|
| D1 | Standalone repo. Python package `icp_threat_intel` in a `src/` layout. Stage interfaces live in `src/icp_threat_intel/core/interfaces.py` with the names: `Collector`, `RawStore`, `Parser`, `Enricher`, `Rule`, `Verifier`, `Notifier`, `Exporter`. |
| D2 | Unit tests never need Docker, a database server or the network. Tests that need Postgres are marked `integration`; tests that hit live hosts are marked `live`. `make test` deselects both with `-m "not integration and not live"`. Unit tests use SQLite through SQLAlchemy where a database is needed, with Postgres-only features (pgvector, JSONB operators) behind a dialect check. |
| D3 | No API key is required for the core. Optional keys, each disabling its collector when absent: `ABUSECH_AUTH_KEY` (ThreatFox, URLhaus), `GITHUB_TOKEN` (advisories, code search). Code search is off by default. |
| D4 | Licence: Apache-2.0. |
| D5 | Python 3.12 only. No TypeScript, no web UI. |
| D6 | Live network access during development is allowed only through `make record`, only to allowlisted IC hosts, and only for the two seed canisters in §3. If the network is unreachable, build a fixture from a documented sample response, set `synthetic: true` in the cassette metadata, and log it in `OPEN_QUESTIONS.md`. |
| D7 | Environment variable prefix: `ICP_THREAT_INTEL_`. CLI entry point: `icp-threat-intel`. |

## 3. Ground truth (verified facts to design around; do not embellish)

- **CanisterWorm (19–22 March 2026).** TeamPCP compromised the Trivy scanner, then npm packages. Canister `tdtqy-oyaaa-aaaae-af2dq-cai` served as a dead-drop resolver: a Python backdoor polled it roughly every 50 minutes, and an `update_link` method let the operator rotate the payload URL without redeploying. First documented use of an ICP canister as C2. 141 artifacts and 66+ packages; written up by Cloud Security Alliance, Aikido, JFrog and Socket. Governance took about 26 hours after disclosure to disable the canister; a disabled canister can be re-enabled.
- **ThreatFox IOC 1781006.**
  - IOC: `https://tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io/` (type `url`), threat type `payload_delivery`, malware "Unknown malware", confidence 90%.
  - First seen 2026-04-04 11:52:12 UTC; last seen never; expired 2026-10-05 01:15:01 UTC; reporter `tipo_deincognito`.
  - Tags: `ICP-C2`, `npm-worm`, `supply-chain`, `systemd-dropper`.
  - Reporter note: npm `@opengov/form-renderer` 0.2.20 used the canister as C2 to deliver a binary payload to `/tmp/pglog`, executed via a persistent systemd user service `pgmon.service`, as part of a 3-stage attack including an npm worm spread with a stolen `_authToken`.
  - Source: https://threatfox.abuse.ch/ioc/1781006/
- **CanisterSprawl (21–23 April 2026).** A second wave hit Namastex.ai tooling on npm and PyPI, with cross-ecosystem propagation via `.pth` injection. Canister `cjn37-uyaaa-aaaac-qgnva-cai` was used for exfiltration rather than C2.
- **Unverified (1 September 2026).** An ICP community account claimed hundreds of malicious canisters and malformed Wasm modules in an "AI-enabled attack". No technical post-mortem exists. Treat as hypothesis H6, never as fact.
- **Platform limit.** Canister module bytes cannot be downloaded from the network. Observable: module hash, Candid interface (when the `candid:service` metadata section is public), other public metadata, controllers, status. Every rule must work within that limit.

## 4. Hypotheses (one rule module each)

Each rule is a class with `id`, `hypothesis`, `required_signals`, `score(events) -> Detection | None`, and a docstring citing its precedent in §3. Rules never call external APIs or touch the network.

| ID | Hypothesis | Signal |
|---|---|---|
| H1 | Dead-drop C2 canisters | Candid interface exposing unauthenticated setter/getter pairs (`update_link`/`get_link`, `set`/`get`, `put`/`fetch`) AND a raw-gateway body that is small text parsing as a URL, base64 blob or shell fragment |
| H2 | Known-bad canister lifecycle | Status flip (stopped → running), controller change or module-hash change on any IOC canister; hours since the last governance action |
| H3 | Supply-chain references | A new npm/PyPI version or public commit introducing a canister ID or IC gateway host (`icp0.io`, `ic0.app`, `raw.icp0.io`, `icp-api.io`) in install hooks, `.pth` files or obfuscated strings; host indicators `/tmp/pglog`, `pgmon.service`, systemd user units |
| H4 | Cycles funding trail | ICP ledger transfers to the Cycles Minting Canister (`rkp4c-7iaaa-aaaaa-aaaca-cai`) topping up an IOC canister; funding accounts shared across IOC canisters; timing correlated with campaign waves |
| H5 | Governance response | NNS proposals referencing IOC canisters or their subnets; time-to-action in hours; proposals reverting an earlier stop |
| H6 | Mass creation and malformed modules | Creation bursts on one subnet or under one controller within minutes; canisters without public Candid and with small or identical module hashes across many instances |

Canister-ID regex: `\b(?:[a-z2-7]{5}-){4}cai\b`.

## 5. Data sources (one collector module each, behind `Collector`)

| Note file (`docs/sources/`) | Source |
|---|---|
| `dashboard-api.md` | IC Dashboard API (`ic-api.internetcomputer.org`, v3): canister metadata, subnet membership, controllers, timestamps, NNS proposals, subnet canister counts. Find its OpenAPI/swagger first. |
| `read-state.md` | IC `read_state` with the anonymous sender: paths `module_hash`, `controllers`, `metadata/candid:service`. Use `icp-py-core` if it works, else raw CBOR over HTTPS (`httpx` + `cbor2`) per the interface spec at `internetcomputer.org/docs/references/ic-interface-spec`. |
| `raw-gateway.md` | `GET https://<id>.raw.icp0.io/` and `.raw.ic0.app`: 1 MB cap, 10 s timeout, no redirects off IC domains, no JavaScript, body stored verbatim and hashed. |
| `icp-ledger-cmc.md` | Ledger API or Rosetta for transfers to the CMC; top-up subaccount derivation per CMC docs, verified against a known top-up before use. |
| `nns-governance.md` | Proposals via Dashboard API or `icq`, filtered by canister ID and subnet. |
| `npm.md`, `pypi.md` | Registry APIs, version diffs, install-hook extraction (`preinstall`, `postinstall`, `setup.py`, `.pth`). |
| `threatfox.md`, `urlhaus.md` | abuse.ch APIs: ThreatFox by tag `ICP-C2` and by canister ID; URLhaus by host. |
| `github-advisories.md` | GitHub Security Advisories (and optional code search). |
| `vendor-rss.md` | RSS from Socket, Aikido, JFrog and Cloud Security Alliance. |

Each note records endpoints, auth, rate limits, a sample response and a first line `Status: VERIFIED` or `Status: EXPERIMENTAL`. A client is written against its note. An `EXPERIMENTAL` client says so in its docstring and carries a TODO with the URL to check. Never guess an endpoint silently.

## 6. Architecture (non-negotiable)

- **Tooling:** `uv`, `pyproject.toml`, type hints everywhere, `ruff` (lint and format) and `mypy --strict` clean.
- **Libraries:** `httpx`, `cbor2`, `pydantic`, `sqlalchemy`, `alembic`, `psycopg[binary]`, `pgvector`, `typer`, `structlog`, `apscheduler`, `pytest`, `pytest-cov`, `respx`. Add others only when a task needs them, and say why in `NOTES.md`.
- **Storage:** PostgreSQL 16 + `pgvector`, Alembic migrations. Tables: `sources`, `canisters` (id, subnet, controllers, module_hash, status, first_seen, last_seen, candid_methods JSON), `canister_snapshots` (immutable point-in-time state), `raw_snapshots` (every fetched body, content-hashed, timestamped, source-tagged), `events`, `packages`, `package_versions`, `ledger_transfers`, `proposals`, `detections` (rule_id, score, evidence_refs, status: candidate | verified | dismissed), `iocs`, `publications`.
- **Raw store is the evidence trail.** Every response is stored verbatim before parsing; parsers are re-runnable over history.
- **Two-signal verification in code.** A detection becomes `verified` only with ≥2 evidence refs from different source types; enforced by a guarded state transition and tested.
- **Source trust:** each source has a 0–100 reliability weight applied at ingest; detections report weighted confidence.
- **Census:** `census` package walks subnets via the Dashboard API, records each canister's public state, diffs against the previous run.
- **Seed IOCs:** `data/seed_iocs.yaml` with the two canisters, ThreatFox 1781006 fields, compromised packages and versions, host indicators, campaign dates and source URLs; loaded by `icp-threat-intel db seed` (`--dry-run` prints what would load).
- **Scheduling:** APScheduler with per-collector cadence config. Defaults: IOC canister state hourly; raw gateway for IOC canisters every 6 h; registries, ledger and proposals daily; full census weekly.
- **Alerting:** daily digest (Markdown and JSON); immediate alerts for `verified` detections; notifiers: stdout and webhook.
- **Publishing:** ThreatFox submission format, STIX 2.1 bundle, MISP event JSON, Markdown case report with a disclosure checklist naming the DFINITY security contact.
- **CLI:** `icp-threat-intel` with `collect`, `census`, `parse`, `enrich`, `score`, `verify`, `digest`, `publish`, `db {migrate,seed}`, `canister inspect <id> [--offline]`. `--offline` reads from the raw store or recorded cassettes, never the network.
- **Containers:** `docker-compose.yml` (Postgres+pgvector and the app).
- **Config:** `.env.example` lists every variable; secrets come from the environment only. The database URL is `ICP_THREAT_INTEL_DATABASE_URL`, and Alembic's `env.py` reads it (offline `--sql` mode must work without a running server).

### Repo layout

```
src/icp_threat_intel/{core,collectors,raw_store,parsers,enrichment,rules,verification,alerting,publishing,census,cli}/
tests/{unit,collectors,parsers,rules,guardrails,exporters}/
tests/cassettes/            # recorded HTTP fixtures, metadata includes synthetic: true|false
data/seed_iocs.yaml
docs/sources/  docs/ARCHITECTURE.md
```

### Makefile contract (verify commands depend on these exact targets)

| Target | Does |
|---|---|
| `setup` | `uv sync --all-extras` |
| `lint` | `uv run ruff check . && uv run ruff format --check .` |
| `typecheck` | `uv run mypy --strict src` |
| `test` | `uv run pytest -q -m "not integration and not live"` |
| `check` | `lint` + `typecheck` + `test` |
| `coverage` | unit tests with `--cov` on `rules`, `verification`, `raw_store` and the IC client module, `--cov-fail-under=80` |
| `migrate` | `uv run alembic upgrade head` |
| `record` | re-record cassettes against live allowlisted hosts (sets `ICP_THREAT_INTEL_RECORD=1`; runs `-m live`) |
| `bootstrap` | `db seed` then `canister inspect` on both seed canisters |
| `run` | start the scheduler |

## 7. Guardrails (code and tests, not just docs)

Each guardrail has a test file in `tests/guardrails/`. Once a guardrail test passes and is committed, it is locked: the pre-commit checks in `PROMPT.md` section 5 fail if it was modified or deleted, and the task cannot be committed. New guardrail test files may be added.

1. **Query-only against the IC** (`test_query_only.py`). The IC client exposes `query` and `read_state` only. Constructing an update `call`, installing or upgrading code, creating canisters, or transferring ICP or cycles is impossible through the public API and fails a test.
2. **Fetched bodies are data** (`test_bodies_are_data.py`). Gateway bodies are stored and pattern-matched; nothing is executed, rendered, or followed off the IC domain allowlist.
3. **Host allowlist** (`test_allowlist.py`). A shared HTTP client refuses any host outside `ALLOWLIST` and logs the refusal.
4. **Rate limits and etiquette** (`test_rate_limit.py`). Per-host limits with backoff; census ceiling configurable; `User-Agent` names the project and a contact address.
5. **Secret redaction** (`test_redaction.py`). Anything resembling a private key, seed phrase, identity PEM or API token is redacted before storage; only a hash and `redacted=true` are kept. Test samples are assembled at runtime from fragments (for example `"-----BEGIN " + "PRIVATE KEY-----"`) so no secret-shaped literal ever appears in the repo.
6. **No sample uploads** (`test_no_upload.py`). Package tarballs are hashed and stored locally; no upload path exists without an explicit flag.
7. **Disclosure first** (`test_disclosure_gate.py`). `publish` refuses a case without `disclosed_at`.
8. **Two-signal verification** (`test_two_signal.py`). A single-signal detection cannot reach `verified`.

## 8. Engineering rules

- Tests first for every rule, state transition and guardrail.
- Never add `pytest.mark.skip`, `pytest.mark.xfail`, `pytest.skip()` or `pytest.xfail()`. Use the `integration` and `live` markers instead; the pre-commit checks in `PROMPT.md` section 5 reject any added skip or xfail.
- Never weaken an assertion, lower a coverage threshold or delete a test to make a check pass.
- Keep every module under 300 lines; split rather than grow.
- No features beyond this spec. No LLM classification yet: leave a documented extension point in `enrichment/`. No Wasm static analysis: leave an extension point for `ic-wasm` and `wasm-tools` for modules obtained legitimately from source repositories.
- When an IC endpoint, Candid encoding or CMC subaccount derivation is uncertain, verify against the interface spec or a known-good example, and record what you verified in the source note.
- If this spec conflicts with a guardrail, the guardrail wins; record the conflict in `OPEN_QUESTIONS.md`.

## 9. Definition of done

Every task in `.loop/tasks.json` is `done` (set only through `PROMPT.md` section 5, after its verify command exits 0, in the same commit as the task's work), `make check` and `make coverage` pass, and `CLAUDE.md`, `README.md` and `docs/ARCHITECTURE.md` exist. `docs/ARCHITECTURE.md` has a Mermaid pipeline diagram and a section titled "What the IC does not let us see".
