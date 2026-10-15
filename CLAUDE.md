# CLAUDE.md

## Loop contract

Every task in `.loop/tasks.json` is done through the loop contract below. There is no runner script: the agent verifies and commits each task itself, following section 5 of the contract. Task T17 extends this file with conventions, make targets and guardrails; keep this section and the import.

@PROMPT.md

## Project in one paragraph

`icp-threat-intel` finds Internet Computer canisters used as attack infrastructure (dead-drop C2, exfiltration, payload hosting), verifies findings with a two-signal rule and publishes IOCs. `SPEC.md` is the source of truth, `PLAN.md` the design, `docs/ARCHITECTURE.md` the overview, `OPEN_QUESTIONS.md` the decisions taken without a human, `NOTES.md` the iteration log.

## Stage contract

The stage interfaces live in `src/icp_threat_intel/core/interfaces.py` (SPEC D1). Their names, signatures and pipeline order are stable; change them only through SPEC.

Pipeline order: collectors → raw_store → parsers → enrichment → rules → verification → alerting → publishing.

| Protocol | Signature | Contract |
|---|---|---|
| `Collector` | `name: str`, `source_type: SourceType`, `collect(targets: Sequence[str]) -> Iterator[RawFetch]` | Network only through `core/http.py` (`SafeHttpClient`) or `core/ic_client.py` (`IcClient`). Yields every response, errors included. |
| `RawStore` | `save(fetch: RawFetch) -> RawSnapshotRef`, `get(snapshot_id: int) -> RawSnapshot`, `iter_snapshots(source_type, since=None) -> Iterator[RawSnapshot]` | Redact, hash, store verbatim before anything parses. Idempotent on (source, url, sha256). |
| `Parser` | `source_type: SourceType`, `version: str`, `parse(snapshot: RawSnapshot) -> ParseResult` | Pure: no I/O, no clock. Same snapshot, same events (dedup key in `parsers/base.py`). |
| `Enricher` | `name: str`, `enrich(events: Sequence[Event]) -> list[Event]` | Trust weight at ingest (`enrichment/trust.py`), IOC membership (`enrichment/ioc_join.py`). |
| `Rule` | `id`, `hypothesis`, `required_signals: frozenset[str]`, `score(events: Sequence[Event]) -> Detection \| None` | Pure (no network, DB, collectors or clock; `tests/rules/test_rules_are_pure.py`). Emits `candidate` only. Docstring cites its SPEC §3 precedent. |
| `Verifier` | `transition(detection, to, *, actor, reason) -> Detection` | Two-signal rule; `verification/state_machine.py`. |
| `Notifier` | `name: str`, `notify(message: Notification) -> None` | stdout, webhook (via `SafeHttpClient` with one extra host). |
| `Exporter` | `format: str`, `export(case: Case) -> bytes` | Refuses a case without `disclosed_at` (`publishing/gate.py`). |

Domain types passed between stages are pydantic models in `core/models.py`, never ORM rows.

## Read the docs before writing a client

Every collector is written against its note in `docs/sources/` (one per source, SPEC §5). Before adding or changing a client:

1. Read the note. Its first line is `Status: VERIFIED` or `Status: EXPERIMENTAL`.
2. An EXPERIMENTAL client says so in its module docstring with a TODO naming the URL to check.
3. Never guess an endpoint, field or encoding silently. If the note does not settle it, verify against the official spec or a known-good example, record what you verified in the note, and log the decision in `OPEN_QUESTIONS.md`.
4. Add a non-IC host to the allowlist only through the client (`SafeHttpClient(extra_hosts=...)`), never by widening `ALLOWLIST` in `core/http.py`.

## Make targets

| Target | Does |
|---|---|
| `make setup` | `uv sync --all-extras` |
| `make lint` | `ruff check .` and `ruff format --check .` |
| `make typecheck` | `mypy --strict src` |
| `make test` | unit tests: `pytest -q -m "not integration and not live"` |
| `make check` | lint + typecheck + test; keep it green after every task |
| `make coverage` | unit tests with coverage on `rules`, `verification`, `raw_store`, `core.ic_client`, `--cov-fail-under=80` |
| `make migrate` | `alembic upgrade head` (reads `ICP_THREAT_INTEL_DATABASE_URL`) |
| `make record` | re-records cassettes against live allowlisted hosts (`ICP_THREAT_INTEL_RECORD=1`, `-m live`); needs `ICP_THREAT_INTEL_CONTACT` |
| `make bootstrap` | `db seed`, then live `canister inspect` on both seed canisters (needs a migrated DB and a contact) |
| `make run` | starts the APScheduler loop (`scheduler/jobs.py` cadences) |

## Guardrails (SPEC §7)

Each has a test in `tests/guardrails/`. A committed guardrail test is locked: never modify or delete it; add new files instead.

1. **Query-only IC client** (`test_query_only.py`): `IcClient` exposes only `query` and `read_state`; no update call, install, canister creation or ICP/cycles transfer exists.
2. **Bodies are data** (`test_bodies_are_data.py`): gateway bodies are stored and pattern-matched, never executed, rendered or followed off IC domains. The raw-gateway fetcher runs an `http_request` query first and skips the GET if the canister asks for an update-call upgrade.
3. **Host allowlist** (`test_allowlist.py`): `SafeHttpClient` refuses hosts outside `ALLOWLIST` and logs the refusal. Only `core/http.py` imports `httpx`.
4. **Rate limits and etiquette** (`test_rate_limit.py`): per-host limits with backoff; census ceiling; User-Agent names the project and a contact.
5. **Secret redaction** (`test_redaction.py`): keys, seed phrases, identity PEMs and tokens are redacted before storage. Test samples are assembled from fragments; no secret-shaped literal in the repo.
6. **No sample uploads** (`test_no_upload.py`): artifacts are hashed and stored locally; any upload/submit function needs keyword-only `allow_upload=False`.
7. **Disclosure first** (`test_disclosure_gate.py`): publishing refuses a case without a past, timezone-aware `disclosed_at`.
8. **Two-signal verification** (`test_two_signal.py`): `verified` needs ≥2 evidence refs from different source types, enforced in the state machine, the `Detection` model (including `model_copy`) and the `detections` table. Signal sources (`signals_feed`) never count towards the two (`test_signal_sources.py`).

If the spec conflicts with a guardrail, the guardrail wins; record it in `OPEN_QUESTIONS.md`.

## Conventions

- Python 3.12, `src/` layout, type hints everywhere, `mypy --strict` and `ruff` clean. Modules stay under 300 lines; split rather than grow.
- Tests first for rules, state transitions and guardrails. Never add skip/xfail markers, weaken assertions, lower thresholds or delete tests to get a pass. Use the `integration` (Postgres) and `live` (network) markers; unit tests have sockets blocked.
- Unit tests use SQLite; Postgres-only features sit behind a dialect check.
- Cassettes in `tests/cassettes/` record `synthetic: true|false` in their metadata. Builders: `python -m tests.collectors._cassettes` (read_state), `._gateway_cassettes`, `._dashboard_cassettes`.
- Settings come from `ICP_THREAT_INTEL_*` environment variables (`core/config.py`); secrets only from the environment, never files. `ABUSECH_AUTH_KEY` and `GITHUB_TOKEN` are optional and disable their collector when absent.
- Live network access during development only via `make record`, only to allowlisted IC hosts, only for the two seed canisters (SPEC D6).
- Event kinds and payload shapes rules rely on: `canister.state_observed`, `canister.candid_observed`, `canister.subnet_observed`, `gateway.http_request_queried`, `gateway.body_observed`, `census.canister_added|removed|changed` (`changes = {field: {from, to}}`), `census.run_completed`, `package.version_published`, `package.canister_reference` (`location`, `text`/`texts`), `proposal.references_target`, `ledger.cmc_topup`, `signal.feed_polled`, `signal.post_observed` (`keywords`, `ioc_terms`, `canister_ids`, `url`, `author_staff`), `signal.canister_reference`.
- Rule ids H1-H7 are registered in `rules/__init__.py` (`REGISTRY`); H4-H6 are documented stubs until their collectors exist. H7 (exfiltration store) is an extension beyond SPEC §4, logged in `OPEN_QUESTIONS.md`.
- Source authority: vendor reporting goes in `vendor_rss` (authoritative prose); community forums go in the signals feed (`collectors/signals_feed.py`, `docs/sources/signals-feed.md`), one `SignalFeed` entry and `sources` row per forum, reliability 40, never counted by the two-signal rule. The collector polls latest posts and matches locally; it never searches a forum.
- Detections are stored one per rule and subject (`verification/store.record_detection`): re-scoring merges new evidence into the open detection; a dismissed one reopens only on evidence it never had.
