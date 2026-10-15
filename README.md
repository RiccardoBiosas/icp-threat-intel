# icp-threat-intel

Threat intelligence and threat hunting for Internet Computer (ICP) canisters used as attack
infrastructure: dead-drop C2, exfiltration endpoints and payload hosting, as in the
CanisterWorm (March 2026) and CanisterSprawl (April 2026) supply-chain campaigns. It
collects public on-chain and registry signals, keeps every response as evidence, scores
them with one rule per hypothesis, verifies with a two-signal rule and exports IOCs as
ThreatFox, STIX 2.1, MISP and Markdown.

See `SPEC.md` for scope, `PLAN.md` for the design and `docs/ARCHITECTURE.md` for the
pipeline and what the IC does not let us see. Licensed under Apache-2.0.

## 10-minute quickstart (Docker Compose)

Needs Docker with Compose, [uv](https://docs.astral.sh/uv/) and make (Python 3.12 is
installed by uv if missing; see the development setup below for details).

```bash
# 1. Install (about 1 minute)
git clone <repo-url> icp-threat-intel && cd icp-threat-intel
make setup                                   # uv sync --all-extras

# 2. Configure: pick a Postgres password and a contact address for the User-Agent
cp .env.example .env
#    edit .env: POSTGRES_PASSWORD=<pw>, the same <pw> inside ICP_THREAT_INTEL_DATABASE_URL,
#    and ICP_THREAT_INTEL_CONTACT=<your email or URL> (required for any live request)
set -a; source .env; set +a                  # the app reads the environment, not .env

# 3. Database: Postgres 16 + pgvector on 127.0.0.1:5432
docker compose up -d db
make migrate                                 # alembic upgrade head (runs on the host)

# 4. Seed the known IOCs and inspect both seed canisters live (read-only)
make bootstrap
```

`make bootstrap` loads `data/seed_iocs.yaml` (the CanisterWorm and CanisterSprawl canisters,
ThreatFox IOC 1781006, packages and host indicators), then runs
`icp-threat-intel canister inspect` on `tdtqy-oyaaa-aaaae-af2dq-cai` and
`cjn37-uyaaa-aaaac-qgnva-cai`. Each inspect makes anonymous, query-only requests to
allowlisted IC hosts (certified `read_state`, an `http_request` query, the raw gateway and
the Dashboard API), stores every response in the raw store and prints status, controllers,
module hash, Candid methods and a summary of the gateway body.

Next steps:

```bash
uv run icp-threat-intel canister inspect <canister-id>            # any canister, live
uv run icp-threat-intel canister inspect <canister-id> --offline  # raw store or cassettes, no network
uv run icp-threat-intel census --ceiling 500                       # bounded census walk + diff
uv run icp-threat-intel parse                                      # raw snapshots -> events
uv run icp-threat-intel score                                      # rules H1-H6 -> candidate detections
uv run icp-threat-intel digest --out digests                       # daily digest (.md + .json)
docker compose up -d app                                           # scheduler (make run in a container)
```

No network or contact address? `uv run icp-threat-intel canister inspect
tdtqy-oyaaa-aaaae-af2dq-cai --offline` renders the bundled (synthetic) cassettes.

## Development setup

### 1. Prerequisites

- **Python 3.12** exactly (`requires-python = ">=3.12,<3.13"`; `.python-version` pins 3.12).
- **[uv](https://docs.astral.sh/uv/)** for the virtualenv, dependencies and running tools.
- **git** and **make**.
- Optional: **Docker** with Compose, only for the Postgres database. Unit tests never need it.

### 2. Install uv and Python 3.12

uv can install and manage Python itself, so you do not need a system Python 3.12.

```bash
# Install uv (Linux/macOS). On Windows: powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
curl -LsSf https://astral.sh/uv/install.sh | sh
# or: pipx install uv   /   brew install uv

uv --version
uv python install 3.12        # downloads a managed CPython 3.12 if none is found
uv python find 3.12           # shows which interpreter uv will use
```

If you prefer your own interpreter (pyenv, deadsnakes, python.org), make sure
`python3.12 --version` works; uv picks it up automatically.

### 3. Create the virtualenv and install dependencies

```bash
git clone <repo-url> icp-threat-intel
cd icp-threat-intel

make setup                    # = uv sync --all-extras
```

`uv sync` creates `.venv/` with Python 3.12, installs the runtime dependencies from
`uv.lock` (exact versions) plus the dev tools (pytest, ruff, mypy), and installs the
package itself in editable mode. You do not need to activate the venv: prefix commands with
`uv run`. If you do want a shell inside it:

```bash
source .venv/bin/activate     # Windows: .venv\Scripts\activate
python --version              # Python 3.12.x
icp-threat-intel --help
deactivate
```

Without uv, a plain venv also works (versions are then not pinned by the lock file):

```bash
    python3.12 -m venv .venv && source .venv/bin/activate
pip install -e . pytest pytest-cov respx ruff mypy types-PyYAML
```

### 4. Configure the environment

```bash
cp .env.example .env          # never commit .env
```

Settings come only from environment variables prefixed `ICP_THREAT_INTEL_` (secrets are
never read from files by the app). The app does not load `.env` by itself; export it into
your shell when you need it:

```bash
set -a; source .env; set +a
```

With no environment at all, the database defaults to a local SQLite file
(`sqlite:///./icp_threat_intel.db`), which is enough for everything below except Postgres.

| Variable | Needed for |
|---|---|
| `ICP_THREAT_INTEL_DATABASE_URL` | Postgres; unset means local SQLite |
| `POSTGRES_PASSWORD` | the bundled Postgres in `docker-compose.yml` |
| `ICP_THREAT_INTEL_CONTACT` | any live network access (sent in the User-Agent); live collection refuses to start without it |
| `ABUSECH_AUTH_KEY`, `GITHUB_TOKEN` | optional collectors; each is disabled when its key is absent |

### 5. Run the checks and tests

Unit tests use no network, no Docker and no database server (sockets are blocked in tests).

```bash
make check                    # ruff lint + format check, mypy --strict, unit tests
make test                     # unit tests only (-m "not integration and not live")
make coverage                 # coverage gate (>= 80%) on rules, verification, raw_store, IC client
```

Run one stage at a time:

```bash
uv run pytest -q tests/guardrails                       # safety guardrails (query-only, allowlist, redaction, ...)
uv run pytest -q tests/collectors/test_read_state.py    # read_state collector + certificate decoding
uv run pytest -q tests/collectors/test_raw_gateway.py   # raw gateway fetcher (1 MB cap, timeout, redirects)
uv run pytest -q tests/collectors/test_dashboard.py     # Dashboard API collector
uv run pytest -q tests/parsers                          # raw snapshots -> events, trust weights, idempotent ingest
uv run pytest -q tests/rules                            # detection rules on synthetic events
```

`tests/parsers` is the closest thing to an end-to-end run today: it replays every recorded
cassette through the collectors into an in-memory raw store, then parses, enriches and
stores the events.

### 6. Set up the database

**SQLite (default, no server):**

```bash
uv run alembic upgrade head                 # creates ./icp_threat_intel.db
uv run icp-threat-intel db seed --dry-run   # show the seed IOCs, campaigns and sources
uv run icp-threat-intel db seed             # load them (re-running changes nothing)
```

**Postgres 16 + pgvector (Docker):**

```bash
# in .env: set POSTGRES_PASSWORD and the same password in ICP_THREAT_INTEL_DATABASE_URL
set -a; source .env; set +a
docker compose up -d db                     # Postgres on 127.0.0.1:5432
make migrate                                # uv run alembic upgrade head
uv run icp-threat-intel db seed
```

To inspect the Postgres migration SQL without a server, export a `postgresql+psycopg://`
`ICP_THREAT_INTEL_DATABASE_URL` and run `uv run alembic upgrade head --sql` (with no URL set
it prints the SQLite variant).

### 7. Cassettes and live recording

Collector tests replay HTTP cassettes from `tests/cassettes/`. Each cassette records in its
metadata whether it is `synthetic` (built from documentation) or recorded live. The current
ones are synthetic. Rebuild them with:

```bash
uv run python -m tests.collectors._cassettes            # read_state
uv run python -m tests.collectors._gateway_cassettes    # raw gateway
uv run python -m tests.collectors._dashboard_cassettes  # Dashboard API
```

To replace them with live responses (read-only, only the two seed canisters, only
allowlisted IC hosts, per SPEC D6):

```bash
export ICP_THREAT_INTEL_CONTACT="you@example.org"
make record                                 # runs the tests marked `live`
make check                                  # cassette tests may need updating for real data
```

### 8. What runs today

| Command | State |
|---|---|
| `db seed [--dry-run]` | works |
| `canister inspect <id> [--offline]` | works: live collection into the raw store, or offline from the raw store / cassettes |
| `census [--ceiling N]` | works: Dashboard API walk, diff against the previous run, events |
| `verify <id> --to verified\|dismissed --actor ... --reason ...` | works: two-signal state machine |
| `publish --case case.json --format threatfox\|stix\|misp\|markdown --out FILE` | works: refuses cases without `disclosed_at`; writes a local file only |
| `digest [--out DIR] [--hours N]` | works: Markdown + JSON |
| `parse` | works: turns stored raw snapshots into events and canister snapshots (trust weights and IOC flags applied at ingest); safe to re-run |
| `enrich` | works: re-applies IOC membership to stored events after IOCs change (e.g. a re-seed) |
| `score` | works: runs rules H1-H6 over stored events and records **candidate** detections (deduplicated) |
| `collect`, `db migrate` | not wired yet (exit 2). Use `canister inspect` or `census` to collect, and `make migrate` for migrations. |

`make run` starts the scheduler with the default cadences (IOC state hourly, raw gateway
every 6 h, registries, ledger and proposals daily, census weekly, digest daily). Only the
digest job does work so far; the other jobs log `job_not_available` until wired.

### Troubleshooting

- `uv: command not found`: open a new shell after installing, or add `~/.local/bin` to `PATH`.
- `requires-python` errors: run `uv python install 3.12`, then `make setup` again.
- `POSTGRES_PASSWORD` error from Compose: set it in `.env` and export it as shown above.
- A test failing with `NetworkBlocked`: something tried to reach the network in a unit
  test; live access belongs only in tests marked `live` (`make record`).

## Out of scope

This project observes; it does not engage. Specifically out of scope:

- **Decoys and honeypots.** No decoy canisters, fake victims, canary packages or bait
  infrastructure are deployed.
- **Live probing beyond read-only observation.** No update calls, no calls to arbitrary
  canister methods, no fuzzing, scanning, credential testing or interaction with attacker
  infrastructure. The only live requests are anonymous `read_state` and `query` calls
  (including `http_request` as a query), GETs of raw-gateway URLs on IC domains, and
  read-only API reads, all through the host allowlist and rate limits. Gateway bodies are
  stored and pattern-matched, never executed, rendered or followed off IC domains.
- **Takedowns and automatic reporting.** The tool never asks the NNS or boundary nodes to
  act, and never submits to ThreatFox, MISP or anyone else: exports are local files for a
  human to review after disclosure to DFINITY.
- **Malware handling.** Package tarballs are hashed and stored locally only; nothing is
  uploaded, run or imported. Canister Wasm cannot be downloaded from the IC at all.
- **A web UI** (SPEC D5) and **LLM classification** (documented extension point only).

