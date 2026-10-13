# PLAN: icp-threat-intel

Implementation plan derived from `SPEC.md`. SPEC wins on any conflict; this file only fixes the details SPEC leaves open. Decisions not covered by SPEC section 2 are listed in `OPEN_QUESTIONS.md` with the default used here.

## Architecture

### Pipeline

One direction, eight stages, each behind a protocol in `core/interfaces.py` (SPEC D1):

```
collectors -> raw_store -> parsers -> enrichment -> rules -> verification -> alerting -> publishing
                  ^                                                                         |
                  +------------- census (Dashboard API walk + diff) -----------------------+
```

| Stage | Protocol | Input | Output | Side effects |
|---|---|---|---|---|
| collectors | `Collector` | targets (canister IDs, package names, block ranges) | `RawFetch` records | network, only through the shared HTTP client or the query-only IC client |
| raw_store | `RawStore` | `RawFetch` | `raw_snapshots` row (verbatim, sha256, redacted) | DB write; never parses |
| parsers | `Parser` | `raw_snapshots` row | `events`, `canister_snapshots`, domain rows | DB write; deterministic and re-runnable |
| enrichment | `Enricher` | events | events with trust weight, IOC membership, subject links | none outside DB; LLM and Wasm extension points are stubs |
| rules | `Rule` | sequence of events for one subject | `Detection` or `None` | none: pure functions, no network, no DB |
| verification | `Verifier` | detection + target status | detection with new status | guarded state machine, audit trail |
| alerting | `Notifier` | verified detections, digest | stdout / webhook message | outbound webhook only to a configured URL |
| publishing | `Exporter` | a `Case` with `disclosed_at` | ThreatFox JSON, STIX 2.1, MISP JSON, Markdown | file write; no upload without explicit flag |

### Protocol signatures (`core/interfaces.py`)

These names, these signatures and the pipeline order above are the stable stage contract. Domain types are pydantic models in `core/models.py`, not ORM rows, so stages can be mounted elsewhere.

```python
class Collector(Protocol):
    name: str
    source_type: SourceType
    def collect(self, targets: Sequence[str]) -> Iterator[RawFetch]: ...

class RawStore(Protocol):
    def save(self, fetch: RawFetch) -> RawSnapshotRef: ...          # idempotent on (source, url, sha256)
    def get(self, snapshot_id: int) -> RawSnapshot: ...
    def iter_snapshots(self, source_type: SourceType, since: datetime | None = None) -> Iterator[RawSnapshot]: ...

class Parser(Protocol):
    source_type: SourceType
    version: str
    def parse(self, snapshot: RawSnapshot) -> ParseResult: ...       # events + canister snapshots, no I/O

class Enricher(Protocol):
    name: str
    def enrich(self, events: Sequence[Event]) -> list[Event]: ...

class Rule(Protocol):
    id: str
    hypothesis: str
    required_signals: frozenset[str]
    def score(self, events: Sequence[Event]) -> Detection | None: ...

class Verifier(Protocol):
    def transition(self, detection: Detection, to: DetectionStatus, *, actor: str, reason: str) -> Detection: ...

class Notifier(Protocol):
    name: str
    def notify(self, message: Notification) -> None: ...

class Exporter(Protocol):
    format: str
    def export(self, case: Case) -> bytes: ...                       # raises DisclosureRequired without disclosed_at
```

### Cross-cutting components (`core/`)

- **`core/http.py`**: the only `httpx.Client` factory. Enforces `ALLOWLIST` (exact hosts plus `*.raw.icp0.io`, `*.raw.ic0.app`, `*.icp0.io`, `*.ic0.app`), logs and raises `HostNotAllowed` on refusal, sets `User-Agent: icp-threat-intel/<version> (+<contact>)`, applies per-host token-bucket limits with exponential backoff on 429/5xx, disables automatic redirects and re-checks every `Location` against the allowlist, caps body size by streaming, and uses a 10 s timeout.
- **`core/ic_client.py`**: query-only IC client. Public surface is exactly `query(canister_id, method, arg)` and `read_state(canister_id, paths)`, anonymous sender, CBOR over HTTPS via `cbor2`. No `call`, `install_code`, `create_canister`, ledger or CMC transfer method exists; the request builder rejects any `request_type` other than `query` and `read_state`.
- **`core/redaction.py`**: detectors for PEM private keys, identity PEMs, BIP-39-like seed phrases, and API-token shapes. Each matching span is replaced by `[REDACTED:<kind>:<sha256-prefix>]` before storage; the row gets `redacted=true`.
- **`core/bodies.py`**: gateway body classification (URL, base64 blob, shell fragment, other) by pattern matching only. Never executes, renders, evaluates or follows anything.
- **`core/config.py`**: settings from `ICP_THREAT_INTEL_*` environment variables (SPEC D7) via a pydantic model; no secrets in files.
- **`core/trust.py`**: source reliability weights (0-100) and the weighted-confidence formula `1 - prod(1 - w_i/100)` over distinct source types in a detection's evidence.
- **`core/logging.py`**: structlog configuration; JSON logs in the scheduler, console logs in the CLI.

### Runtime

- The CLI (typer) is the entry point: `collect`, `census`, `parse`, `enrich`, `score`, `verify`, `digest`, `publish`, `db {migrate,seed}`, `canister inspect <id> [--offline]`.
- `make run` starts APScheduler with per-collector cadences from config: IOC canister state hourly, raw gateway for IOC canisters every 6 h, registries, ledger and proposals daily, full census weekly.
- Storage is Postgres 16 + pgvector via Alembic. Unit tests use SQLite through the same models (SPEC D2). Postgres-only features (JSONB, the `vector` extension, immutability triggers) sit behind `dialect.name == "postgresql"`.
- Offline mode (`--offline`, all unit tests) reads from the raw store or `tests/cassettes/` and never opens a socket. A pytest fixture blocks `socket.connect` for every test not marked `live`.

### Guardrail placement

| Guardrail (SPEC section 7) | Enforced in | Test |
|---|---|---|
| 1 query-only | `core/ic_client.py` | `tests/guardrails/test_query_only.py` |
| 2 bodies are data | `core/bodies.py`, `core/http.py` redirect policy | `tests/guardrails/test_bodies_are_data.py` |
| 3 host allowlist | `core/http.py` | `tests/guardrails/test_allowlist.py` |
| 4 rate limits, UA | `core/http.py`, `census/walker.py` ceiling | `tests/guardrails/test_rate_limit.py` |
| 5 secret redaction | `core/redaction.py`, called by `raw_store` | `tests/guardrails/test_redaction.py` |
| 6 no sample uploads | `collectors/registry_common.py`, `publishing/` | `tests/guardrails/test_no_upload.py` |
| 7 disclosure first | `publishing/gate.py` | `tests/guardrails/test_disclosure_gate.py` |
| 8 two-signal | `verification/state_machine.py` | `tests/guardrails/test_two_signal.py` |

## Repo layout

Every module stays under 300 lines (SPEC section 8); split when it grows.

```
pyproject.toml  uv.lock  Makefile  Dockerfile  docker-compose.yml  .env.example  LICENSE
alembic.ini
alembic/env.py                      # reads ICP_THREAT_INTEL_DATABASE_URL; --sql works offline
alembic/versions/0001_initial.py    # all tables, pgvector extension, immutability triggers (PG only)
.github/workflows/ci.yml            # lint, typecheck, tests
data/seed_iocs.yaml
docs/ARCHITECTURE.md
docs/sources/{dashboard-api,read-state,raw-gateway,icp-ledger-cmc,nns-governance,npm,pypi,threatfox,urlhaus,github-advisories,vendor-rss}.md

src/icp_threat_intel/
  __init__.py                       # __version__
  core/
    interfaces.py                   # the eight protocols (D1)
    models.py                       # pydantic domain types: RawFetch, RawSnapshot, Event, Detection, Case, ...
    enums.py                        # SourceType, DetectionStatus, CanisterStatus, IocType, Ecosystem
    config.py                       # Settings from ICP_THREAT_INTEL_* env vars
    http.py                         # allowlisted, rate-limited shared client
    ratelimit.py                    # per-host token bucket + backoff
    ic_client.py                    # query + read_state only
    ic_encoding.py                  # request envelope, request-id hashing, principal text codec
    redaction.py
    bodies.py
    trust.py
    logging.py
  db/
    base.py                         # declarative base, JSON/JSONB and BigInteger variants
    models.py                       # SQLAlchemy tables (see Data model)
    immutability.py                 # ORM before_update/before_delete guards
    session.py
  raw_store/
    store.py                        # SqlRawStore: redact -> hash -> insert-or-get
  collectors/
    read_state.py                   # T07
    candid.py                       # candid:service text -> method list
    raw_gateway.py                  # T08
    dashboard.py                    # T09 (also used by census)
    ledger_cmc.py  nns.py  npm.py  pypi.py  registry_common.py
    threatfox.py  urlhaus.py  github_advisories.py  vendor_rss.py
  parsers/
    base.py                         # dedup key, determinism helpers
    read_state.py  raw_gateway.py  dashboard.py  ...   # one per collector
  enrichment/
    trust.py                        # apply source weight at ingest
    ioc_join.py                     # mark events whose subject is an IOC
    extension_points.py             # documented LLM and ic-wasm/wasm-tools hooks, not implemented
  rules/
    __init__.py                     # REGISTRY: {"H1": H1DeadDropC2, ...}
    base.py                         # BaseRule, signal extraction helpers, canister-ID regex
    engine.py                       # group events by subject, run rules, persist candidates
    h1_dead_drop.py  h2_lifecycle.py  h3_supply_chain.py
    h4_cycles_funding.py  h5_governance.py  h6_mass_creation.py
  verification/
    state_machine.py                # guarded transitions, two-signal rule, audit trail
  alerting/
    digest.py  stdout.py  webhook.py
  publishing/
    gate.py                         # disclosure gate
    case.py                         # build Case from verified detections + IOCs
    threatfox.py  stix.py  misp.py  markdown.py
  census/
    walker.py                       # subnet/canister walk with ceiling
    diff.py                         # pure diff between runs
    run.py                          # orchestration, events for added/removed/changed
  scheduler/
    jobs.py                         # APScheduler cadences
  cli/
    __init__.py  app.py             # typer app, console script icp-threat-intel
    canister.py  db.py  pipeline.py

tests/
  conftest.py                       # SQLite session, network block, cassette loader
  unit/        test_smoke.py  test_models.py  test_raw_store.py  test_seed.py  test_census.py  test_trust.py
  collectors/  test_read_state.py  test_raw_gateway.py  test_dashboard.py
  parsers/     test_read_state_parser.py  test_gateway_parser.py  test_dashboard_parser.py  test_determinism.py
  rules/       test_h1.py  test_h2.py  test_h3.py  test_stubs.py  test_rules_are_pure.py
  guardrails/  test_allowlist.py  test_query_only.py  test_redaction.py  test_disclosure_gate.py
               test_bodies_are_data.py  test_rate_limit.py  test_no_upload.py  test_two_signal.py
  exporters/   test_threatfox.py  test_stix.py  test_misp.py  test_markdown.py  test_digest.py  test_webhook.py
  cassettes/   read_state_*  raw_gateway_*  dashboard_*   # each with metadata incl. synthetic: true|false
```

## Data model

Types are given as SQLAlchemy types; the Postgres column type follows in brackets where it differs. `JSON` becomes `JSONB` on Postgres through `JSON().with_variant(JSONB, "postgresql")`. All timestamps are `DateTime(timezone=True)` [timestamptz] in UTC. Primary keys are `BigInteger` with an `Integer` variant on SQLite so autoincrement works.

### `sources`

| Column | Type | Notes |
|---|---|---|
| id | Integer PK | |
| name | String(64) unique | e.g. `ic-read-state`, `threatfox` |
| source_type | Enum(SourceType) | `ic_read_state`, `raw_gateway`, `dashboard_api`, `icp_ledger`, `nns`, `npm`, `pypi`, `threatfox`, `urlhaus`, `github_advisories`, `vendor_rss` |
| base_url | Text | |
| reliability | SmallInteger | CHECK 0-100; applied at ingest |
| status | String(16) | `VERIFIED` or `EXPERIMENTAL`, mirrors `docs/sources/` |
| enabled | Boolean | false when an optional key is missing (D3) |
| created_at | DateTime(tz) | |

### `canisters` (current view, one row per canister)

| Column | Type | Notes |
|---|---|---|
| id | String(27) PK | canister principal text; validated against `\b(?:[a-z2-7]{5}-){4}cai\b` |
| subnet | String(63) nullable | subnet principal |
| controllers | JSON | list of principal strings, sorted |
| module_hash | String(64) nullable | hex sha256; null when no module installed |
| status | Enum(CanisterStatus) | `running`, `stopping`, `stopped`, `unknown` |
| first_seen | DateTime(tz) | |
| last_seen | DateTime(tz) | |
| candid_methods | JSON nullable | list of `{name, args, rets, mode}`; null when `candid:service` is not public |
| candid_sha256 | String(64) nullable | hash of the raw `candid:service` text |
| is_ioc | Boolean | true for seed and verified IOC canisters |
| updated_at | DateTime(tz) | |

### `canister_snapshots` (immutable)

| Column | Type | Notes |
|---|---|---|
| id | BigInteger PK | |
| canister_id | String(27) FK canisters.id | |
| observed_at | DateTime(tz) | |
| source_id | Integer FK sources.id | |
| raw_snapshot_id | BigInteger FK raw_snapshots.id nullable | the evidence it was parsed from |
| census_run_id | String(36) nullable | UUID of the census run that wrote it |
| subnet | String(63) nullable | |
| controllers | JSON | |
| module_hash | String(64) nullable | |
| status | Enum(CanisterStatus) | |
| candid_methods | JSON nullable | |
| candid_sha256 | String(64) nullable | |

Unique `(canister_id, source_id, raw_snapshot_id)`. Immutable: an ORM `before_update`/`before_delete` listener raises `ImmutableRowError`; on Postgres a trigger also rejects `UPDATE` and `DELETE`.

### `raw_snapshots` (immutable evidence trail)

| Column | Type | Notes |
|---|---|---|
| id | BigInteger PK | |
| source_id | Integer FK sources.id | |
| url | Text | request URL, or `ic://<canister>/read_state/<path>` for IC reads |
| fetched_at | DateTime(tz) | first fetch of this content |
| sha256 | String(64) | hash of the original bytes as received |
| body | LargeBinary [bytea] | stored bytes after redaction |
| stored_sha256 | String(64) | hash of `body` as stored (differs from `sha256` only when redacted) |
| size_bytes | Integer | original size |
| truncated | Boolean | true when the 1 MB cap cut the body |
| http_status | SmallInteger nullable | |
| content_type | String(255) nullable | |
| headers | JSON | response headers, redacted |
| redacted | Boolean | |
| redaction_kinds | JSON | list of detector kinds that fired |
| synthetic | Boolean | true for fixtures built per SPEC D6 |
| request_meta | JSON | method, paths, collector name and version |

Unique `(source_id, url, sha256)`; `save()` returns the existing row on a repeat. Immutable like `canister_snapshots`.

### `events`

| Column | Type | Notes |
|---|---|---|
| id | BigInteger PK | |
| kind | String(64) | e.g. `canister.state_observed`, `canister.status_changed`, `canister.controllers_changed`, `canister.module_hash_changed`, `canister.candid_observed`, `gateway.body_observed`, `census.canister_added`, `census.canister_removed`, `census.canister_changed`, `census.run_completed`, `package.version_published`, `package.canister_reference`, `ledger.cmc_topup`, `proposal.references_target`, `ioc.reported` |
| subject_type | String(16) | `canister`, `package`, `account`, `proposal`, `census_run` |
| subject_id | Text | |
| canister_id | String(27) nullable | indexed, set whenever the event concerns a canister |
| observed_at | DateTime(tz) | |
| source_id | Integer FK sources.id | |
| source_type | Enum(SourceType) | denormalised for the two-signal check |
| raw_snapshot_id | BigInteger FK raw_snapshots.id nullable | |
| parser | String(64) | parser name and version |
| weight | SmallInteger | source reliability at ingest |
| is_ioc | Boolean | set by enrichment |
| payload | JSON | kind-specific fields |
| dedup_key | String(64) unique | sha256 of parser, raw_snapshot_id, kind, subject and canonical payload; makes re-parsing idempotent |

### `packages`

| Column | Type | Notes |
|---|---|---|
| id | Integer PK | |
| ecosystem | Enum(Ecosystem) | `npm`, `pypi` |
| name | Text | unique with ecosystem |
| first_seen | DateTime(tz) | |
| last_seen | DateTime(tz) | |
| is_ioc | Boolean | |

### `package_versions`

| Column | Type | Notes |
|---|---|---|
| id | BigInteger PK | |
| package_id | Integer FK packages.id | |
| version | String(128) | unique with package_id |
| published_at | DateTime(tz) nullable | |
| tarball_sha256 | String(64) nullable | tarball hashed and kept locally only (guardrail 6) |
| tarball_path | Text nullable | local path under `data/local/` |
| install_hooks | JSON | `preinstall`, `postinstall`, `setup.py`, `.pth` excerpts (redacted) |
| canister_refs | JSON | canister IDs and gateway hosts found |
| host_indicators | JSON | e.g. `/tmp/pglog`, `pgmon.service`, systemd user units |
| raw_snapshot_id | BigInteger FK raw_snapshots.id nullable | |
| is_ioc | Boolean | |

### `ledger_transfers`

| Column | Type | Notes |
|---|---|---|
| id | BigInteger PK | |
| block_index | BigInteger unique | |
| from_account | String(64) | account identifier hex |
| to_account | String(64) | |
| amount_e8s | Numeric(30, 0) | |
| fee_e8s | Numeric(30, 0) | |
| memo | Numeric(30, 0) nullable | CMC top-up memo is checked here |
| created_at | DateTime(tz) | |
| is_cmc_topup | Boolean | to-account is a CMC subaccount and memo matches top-up |
| target_canister_id | String(27) nullable | decoded from the CMC top-up subaccount (derivation per `docs/sources/icp-ledger-cmc.md`) |
| raw_snapshot_id | BigInteger FK raw_snapshots.id | |

### `proposals`

| Column | Type | Notes |
|---|---|---|
| id | BigInteger PK | NNS proposal ID |
| title | Text | |
| topic | String(64) | |
| action_type | String(64) | |
| status | String(32) | |
| proposer | String(64) nullable | neuron ID |
| created_at | DateTime(tz) | |
| decided_at | DateTime(tz) nullable | |
| executed_at | DateTime(tz) nullable | |
| referenced_canisters | JSON | canister IDs matched in payload or summary |
| referenced_subnets | JSON | |
| summary | Text | |
| raw_snapshot_id | BigInteger FK raw_snapshots.id | |

### `detections`

| Column | Type | Notes |
|---|---|---|
| id | BigInteger PK | |
| rule_id | String(8) | `H1` to `H6` |
| rule_version | String(16) | |
| subject_type | String(16) | |
| subject_id | Text | |
| canister_id | String(27) nullable | |
| score | Float | rule score 0-1 |
| weighted_confidence | Float | trust-weighted, 0-1 (`core/trust.py`) |
| signals | JSON | names of the signals that matched |
| evidence_refs | JSON | list of `{ref_type: event or raw_snapshot or ioc, id, source_type}` |
| status | Enum(DetectionStatus) | `candidate`, `verified`, `dismissed` |
| status_history | JSON | append-only list of `{from, to, actor, reason, at}` |
| created_at | DateTime(tz) | |
| updated_at | DateTime(tz) | |
| verified_at | DateTime(tz) nullable | |
| dismissed_at | DateTime(tz) nullable | |
| dedup_key | String(64) unique | rule_id + subject + sorted evidence ids |

### `iocs`

| Column | Type | Notes |
|---|---|---|
| id | Integer PK | |
| ioc_type | Enum(IocType) | `canister_id`, `url`, `domain`, `package_version`, `file_path`, `systemd_unit`, `account` |
| value | Text | |
| threat_type | String(64) nullable | e.g. `payload_delivery` |
| malware | String(128) nullable | |
| confidence | SmallInteger nullable | 0-100 |
| first_seen | DateTime(tz) nullable | |
| last_seen | DateTime(tz) nullable | |
| expires_at | DateTime(tz) nullable | |
| tags | JSON | |
| reporter | String(128) nullable | |
| campaign | String(64) nullable | `CanisterWorm`, `CanisterSprawl` |
| source_id | Integer FK sources.id | the original publisher's source type, not a separate "seed" type |
| source_ref | String(128) | e.g. `threatfox:1781006` |
| source_url | Text | |
| notes | Text nullable | |
| detection_id | BigInteger FK detections.id nullable | set when the IOC came from our own verified detection |

Unique `(ioc_type, value, source_ref)`.

### `publications`

| Column | Type | Notes |
|---|---|---|
| id | BigInteger PK | |
| case_id | String(36) | UUID |
| format | String(16) | `threatfox`, `stix21`, `misp`, `markdown` |
| detection_ids | JSON | |
| ioc_ids | JSON | |
| disclosed_at | DateTime(tz) | NOT NULL; the gate refuses earlier |
| disclosure_contact | Text | DFINITY security contact recorded in the checklist |
| created_at | DateTime(tz) | |
| payload_sha256 | String(64) | |
| path | Text | local output file |
| submitted | Boolean | default false; only true via an explicit flag |
| submitted_at | DateTime(tz) nullable | |

Postgres-only migration steps (behind a dialect check): `CREATE EXTENSION IF NOT EXISTS vector`, JSONB variants and the immutability triggers. No `vector` column is created yet; the extension point is described in `enrichment/extension_points.py`.

## Rule interface

```python
CANISTER_ID_RE = re.compile(r"\b(?:[a-z2-7]{5}-){4}cai\b")

class Detection(BaseModel):
    rule_id: str
    subject_type: str
    subject_id: str
    canister_id: str | None
    score: float                       # 0..1, rule-specific
    weighted_confidence: float         # from core.trust over distinct source types in evidence
    signals: frozenset[str]
    evidence_refs: tuple[EvidenceRef, ...]
    explanation: str
    status: DetectionStatus = DetectionStatus.CANDIDATE

class BaseRule:
    id: ClassVar[str]
    hypothesis: ClassVar[str]
    required_signals: ClassVar[frozenset[str]]
    version: ClassVar[str] = "1"

    def signals(self, events: Sequence[Event]) -> dict[str, list[Event]]: ...   # signal name -> supporting events
    def score(self, events: Sequence[Event]) -> Detection | None: ...
```

Contract:

1. `score(events)` receives all events for one subject (one canister or one package) inside the rule's look-back window, already enriched (trust weight, `is_ioc`). The engine (`rules/engine.py`) does the grouping; rules never query the DB.
2. A rule returns a `Detection` only when every name in `required_signals` has at least one supporting event; otherwise `None`. Each supporting event becomes an `EvidenceRef`.
3. Rules are pure: no network, no DB, no clock reads (`now` comes from the newest event). `tests/rules/test_rules_are_pure.py` fails if any module in `rules/` imports `httpx`, `socket`, `core.http`, `core.ic_client`, `sqlalchemy` or `collectors`.
4. Every rule class has a docstring citing its precedent in SPEC section 3 (CanisterWorm, ThreatFox 1781006, CanisterSprawl, or H6's unverified claim, labelled as unverified).
5. A rule always emits `candidate`. Only `verification/` can change the status.
6. Stub rules (T13) return `None` and log `rule_stub` with their id.

Signals per rule:

| Rule | required_signals | Supporting event kinds |
|---|---|---|
| H1 dead-drop C2 | `setter_getter_pair`, `small_text_body` | `canister.candid_observed` with an unauthenticated pair (`update_link`/`get_link`, `set`/`get`, `put`/`fetch`); `gateway.body_observed` classified URL, base64 or shell fragment and under the small-body threshold |
| H2 lifecycle | `ioc_canister`, `lifecycle_change` | `is_ioc` events plus `canister.status_changed` (stopped -> running), `canister.controllers_changed` or `canister.module_hash_changed`; the explanation reports hours since the last `proposal.references_target` |
| H3 supply chain | `registry_artifact`, `ic_reference` | `package.version_published` plus `package.canister_reference` matching the canister-ID regex, a gateway host (`icp0.io`, `ic0.app`, `raw.icp0.io`, `icp-api.io`) or the host indicators `/tmp/pglog`, `pgmon.service`, systemd user units |
| H4 cycles funding (stub) | `cmc_topup`, `ioc_canister` | `ledger.cmc_topup` to `rkp4c-7iaaa-aaaaa-aaaca-cai` for an IOC canister; shared funding accounts |
| H5 governance (stub) | `proposal_reference` | `proposal.references_target` for IOC canisters or subnets; reverts of an earlier stop |
| H6 mass creation (stub) | `creation_burst`, `opaque_module` | `census.canister_added` bursts per subnet or controller; no public Candid with identical module hashes |

Verification (`verification/state_machine.py`): `candidate -> verified` only when `evidence_refs` cover at least two distinct `source_type` values; two refs from the same source type raise `InsufficientEvidence`. `candidate -> dismissed` is allowed. `verified -> dismissed` needs `explicit=True` and a non-empty reason, and is appended to `status_history`. Every other transition raises `IllegalTransition`.

## Census algorithm

The census lives in the `census` package. It walks subnets through the Dashboard API client from T09, records each canister's public state, and diffs the result against the previous run.

1. **Start.** Allocate `run_id` (UUID4) and `started_at`. Load the ceiling `ICP_THREAT_INTEL_CENSUS_MAX_CANISTERS` and the per-host rate limit from config.
2. **Subnets.** Fetch the subnet list from the Dashboard API (endpoint per `docs/sources/dashboard-api.md`). Every page goes through `raw_store.save()` before parsing. Sort subnet IDs so runs are deterministic.
3. **Canisters per subnet.** Page through each subnet's canisters with the documented limit/offset or cursor. Store each page raw, then parse it into one `CanisterState(id, subnet, controllers, module_hash, status, updated_at)` per canister. A subnet is `complete` only if all its pages were fetched without error and before the ceiling.
4. **Ceiling and errors.** When the ceiling is reached or a subnet fails after retries, stop that subnet, mark it incomplete, and continue or finish. Neither case aborts the run.
5. **Targeted deep reads.** For IOC canisters, and for canisters that are new or whose module hash changed in step 6, schedule a `read_state` (module_hash, controllers, `candid:service`) through the query-only client, within a per-run budget. These run as separate collector jobs, so the census itself only makes Dashboard API calls.
6. **Diff.** `census/diff.py` is a pure function `diff_runs(previous, current, complete_in_both) -> CensusDiff`, where `previous` and `current` map canister ID to `CanisterState`:
   - `added`: in `current`, not in `previous`.
   - `removed`: in `previous`, not in `current`, **and** its subnet is complete in both runs. A partial walk never reports removals.
   - `changed`: in both, with a per-field diff over `subnet`, `controllers` (compared as sets), `module_hash`, `status` and `candid_sha256`.
7. **Persist.** For every canister observed, write a `canister_snapshots` row tagged with `census_run_id` and upsert `canisters` (`first_seen`, `last_seen`, current fields). Emit `census.canister_added`, `census.canister_removed` and `census.canister_changed` events (the payload carries the field diff) plus one `census.run_completed` event with counts, `ceiling_hit`, and complete and incomplete subnet lists. These events feed H2 and H6.
8. **Previous run.** The previous run is the latest `census.run_completed` event before this run; its snapshots are loaded by `census_run_id`. The first run reports everything as `added` and no removals.

`canister inspect <id> --offline` reuses the parsers: it loads the newest raw snapshots for the canister (or cassettes when the DB is empty) and prints status, controllers, module hash, Candid methods and a raw-body summary (size, sha256, classification, first 200 printable characters).

## Task mapping

| Task | Modules | Tests |
|---|---|---|
| T02 skeleton, tooling, CI | `pyproject.toml`, `uv.lock`, `Makefile`, `Dockerfile`, `docker-compose.yml`, `.env.example`, `LICENSE`, `.github/workflows/ci.yml`, empty stage packages, `core/interfaces.py`, `core/models.py` (types the protocols need), `core/enums.py`, `cli/app.py` with stub commands | `tests/unit/test_smoke.py` (imports the package, CLI `--help` lists every command, the eight protocols exist) |
| T03 guardrails first | `core/http.py`, `core/ratelimit.py`, `core/ic_client.py`, `core/ic_encoding.py`, `core/redaction.py`, `core/bodies.py`, `publishing/gate.py`, `collectors/registry_common.py` (hash-and-store, no upload) | `tests/guardrails/test_allowlist.py`, `test_query_only.py`, `test_redaction.py`, `test_disclosure_gate.py`, `test_bodies_are_data.py`, `test_rate_limit.py`, `test_no_upload.py` (written before the code) |
| T04 data model, Alembic | `db/base.py`, `db/models.py`, `db/immutability.py`, `db/session.py`, `alembic.ini`, `alembic/env.py`, `alembic/versions/0001_initial.py` | `tests/unit/test_models.py` (constraints, `DetectionStatus` enum, immutability of `raw_snapshots` and `canister_snapshots`); verify also runs `alembic upgrade head --sql` against a Postgres URL |
| T05 raw store, seed IOCs | `raw_store/store.py`, `data/seed_iocs.yaml`, `cli/db.py` (`db seed [--dry-run]`), seed loader in `raw_store` or `db` | `tests/unit/test_raw_store.py` (verbatim, sha256, idempotent, redaction before persistence), `tests/unit/test_seed.py` (every SPEC section 3 fact present, nothing extra) |
| T06 source notes | `docs/sources/*.md` (11 notes), one research subagent per source | verify checks the status line and URLs; no Python tests |
| T07 read_state collector | `collectors/read_state.py`, `collectors/candid.py`, `parsers/read_state.py` (Candid method extraction), `tests/cassettes/read_state_*` | `tests/collectors/test_read_state.py` (cassette replay, Candid parsing with query/update annotation) |
| T08 raw gateway fetcher | `collectors/raw_gateway.py` (on `core/http.py` and `raw_store`), `tests/cassettes/raw_gateway_*` | `tests/collectors/test_raw_gateway.py` (1 MB cap, 10 s timeout, off-domain redirect refused, body stored via raw store) |
| T09 Dashboard API collector | `collectors/dashboard.py`, `tests/cassettes/dashboard_*` | `tests/collectors/test_dashboard.py` (canister metadata, subnet membership, controllers from cassettes) |
| T10 parsers to events | `parsers/base.py`, `parsers/read_state.py`, `parsers/raw_gateway.py`, `parsers/dashboard.py`, `enrichment/trust.py`, `enrichment/ioc_join.py`, `enrichment/extension_points.py`, `core/trust.py` | `tests/parsers/test_read_state_parser.py`, `test_gateway_parser.py`, `test_dashboard_parser.py`, `test_determinism.py` (re-running gives identical events), `tests/unit/test_trust.py` |
| T11 rule H1 | `rules/base.py`, `rules/engine.py`, `rules/h1_dead_drop.py` | `tests/rules/test_h1.py` (positive; negative for the setter/getter pair alone and for the small body alone) |
| T12 rules H2, H3 | `rules/h2_lifecycle.py`, `rules/h3_supply_chain.py` | `tests/rules/test_h2.py`, `tests/rules/test_h3.py` (positive and negative synthetic events; H3 covers the regex, gateway hosts, `/tmp/pglog`, `pgmon.service`) |
| T13 stubs H4-H6, registry | `rules/h4_cycles_funding.py`, `rules/h5_governance.py`, `rules/h6_mass_creation.py`, `rules/__init__.py` (`REGISTRY`) | `tests/rules/test_stubs.py` (return `None` and log), `tests/rules/test_rules_are_pure.py`; verify asserts `REGISTRY` covers H1-H6 |
| T14 verification | `verification/state_machine.py`, `cli/pipeline.py` (`verify` command) | `tests/guardrails/test_two_signal.py` (single signal and two refs from one source type cannot verify), `tests/unit/test_state_machine.py` (all transitions, audited dismissal) |
| T15 census, inspect | `census/walker.py`, `census/diff.py`, `census/run.py`, `cli/canister.py` (`canister inspect <id> --offline`), `cli/pipeline.py` (`census`) | `tests/unit/test_census.py` (added, removed, changed; partial runs never report removals; ceiling); verify runs `canister inspect` offline on a seed canister |
| T16 exporters, digest | `publishing/case.py`, `publishing/threatfox.py`, `publishing/stix.py`, `publishing/misp.py`, `publishing/markdown.py` (disclosure checklist), `alerting/digest.py`, `alerting/stdout.py`, `alerting/webhook.py`, `scheduler/jobs.py` | `tests/exporters/test_threatfox.py`, `test_stix.py`, `test_misp.py`, `test_markdown.py` (each refuses a case without `disclosed_at`), `test_digest.py`, `test_webhook.py` (respx) |
| T17 docs | `CLAUDE.md` (conventions, make targets, guardrails, read-docs-before-clients, stage contract), `README.md` (10-minute quickstart, out-of-scope section), `docs/ARCHITECTURE.md` (mermaid pipeline, "What the IC does not let us see") | verify greps; no Python tests |
| T18 final gate | tests added where coverage is short in `rules/`, `verification/`, `raw_store/`, `core/ic_client.py`; `OPEN_QUESTIONS.md` review; final `NOTES.md` summary | `make check`, `make coverage` (`--cov-fail-under=80`, no exclusions added) |

`make check` stays green from T02 onwards. Tests come before implementation for every rule, state transition and guardrail (SPEC section 8).
