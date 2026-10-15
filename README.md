# icp-threat-intel

Threat intelligence and threat hunting for Internet Computer (ICP) canisters used as attack
infrastructure. See `SPEC.md` for scope and `PLAN.md` for the design.

Licensed under Apache-2.0.

## Quickstart

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

The CLI is installed as `icp-threat-intel` (`uv run icp-threat-intel --help`). `db seed`
works; the pipeline commands (`collect`, `census`, `parse`, `enrich`, `score`, `verify`,
`digest`, `publish`, `canister inspect`) are placeholders that print "not implemented"
until later tasks wire them to the collectors, parsers and rules that already exist as
library code and tests. `make run` (the scheduler) and `make bootstrap` likewise depend on
those commands.

### Troubleshooting

- `uv: command not found`: open a new shell after installing, or add `~/.local/bin` to `PATH`.
- `requires-python` errors: run `uv python install 3.12`, then `make setup` again.
- `POSTGRES_PASSWORD` error from Compose: set it in `.env` and export it as shown above.
- A test failing with `NetworkBlocked`: something tried to reach the network in a unit
  test; live access belongs only in tests marked `live` (`make record`).
