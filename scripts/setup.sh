#!/usr/bin/env bash
# Full local setup for icp-threat-intel: dependencies, checks, database, seed, pipeline, digest.
#
# Offline by default. Live network access is opt-in per step (--signals, --inspect, --live)
# and needs ICP_THREAT_INTEL_CONTACT (a role address; it is sent in the User-Agent).
# Re-running is safe: migrations, seed, parse and score are idempotent, and an existing
# SQLite database is backed up (timestamped *.bak, git-ignored) before it is migrated.
#
# Usage: scripts/setup.sh [options]
#   --postgres        start the bundled Postgres (docker compose) instead of using SQLite
#   --skip-checks     skip `make check` (lint, mypy, unit tests)
#   --signals         live: poll the signals feed (community forums) into the raw store
#   --inspect         live: `canister inspect` the two seed IOC canisters (query-only)
#   --live            both --signals and --inspect
#   --signals-only    only the signals feed: back up + migrate the DB, poll and parse the
#                     forum, write the digest (no deps, checks, seed, inspect or scoring)
#   --pages N         forum pages for --signals (1-10, default 1)
#   --digest-dir DIR  where the digest goes (default local-docs/digests)
#   -h, --help        show this help

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

POSTGRES=0 CHECKS=1 SIGNALS=0 INSPECT=0 ONLY_SIGNALS=0 PAGES=1 DIGEST_DIR="local-docs/digests"
SEED_CANISTERS=(tdtqy-oyaaa-aaaae-af2dq-cai cjn37-uyaaa-aaaac-qgnva-cai)

usage() { sed -n '2,/^$/p' "$0" | sed -E 's/^# ?//'; }
step() { printf '\n==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --postgres) POSTGRES=1 ;;
    --skip-checks) CHECKS=0 ;;
    --signals) SIGNALS=1 ;;
    --inspect) INSPECT=1 ;;
    --live) SIGNALS=1 INSPECT=1 ;;
    --signals-only|--signal-only) ONLY_SIGNALS=1 SIGNALS=1 ;;
    --pages) PAGES="${2:?--pages needs a number}"; shift ;;
    --digest-dir) DIGEST_DIR="${2:?--digest-dir needs a path}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown option: $1" ;;
  esac
  shift
done
[[ "$PAGES" =~ ^([1-9]|10)$ ]] || die "--pages must be 1-10"
[[ $ONLY_SIGNALS -eq 1 && $INSPECT -eq 1 ]] && die "--signals-only cannot be combined with --inspect/--live"

# .env: fill in only variables not already set in the shell; values are never printed or
# evaluated as shell code.
load_env() {
  [[ -f .env ]] || return 0
  local line key value
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
    [[ "$line" =~ ^[[:space:]]*(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]] || continue
    key="${BASH_REMATCH[2]}" value="${BASH_REMATCH[3]}"
    value="${value%\"}" value="${value#\"}" value="${value%\'}" value="${value#\'}"
    [[ -n "${!key+x}" ]] || export "$key=$value"
  done < .env
  echo "loaded .env (shell variables take precedence)"
}

step "Prerequisites"
command -v uv >/dev/null || die "uv not found: curl -LsSf https://astral.sh/uv/install.sh | sh"
load_env
if [[ $POSTGRES -eq 1 ]]; then
  command -v docker >/dev/null || die "--postgres needs docker"
  [[ -n "${POSTGRES_PASSWORD:-}" ]] || die "--postgres needs POSTGRES_PASSWORD (see .env.example)"
  [[ "${ICP_THREAT_INTEL_DATABASE_URL:-}" == postgresql* ]] \
    || die "--postgres needs a postgresql+psycopg:// ICP_THREAT_INTEL_DATABASE_URL"
fi
if [[ $SIGNALS -eq 1 || $INSPECT -eq 1 ]]; then
  [[ -n "${ICP_THREAT_INTEL_CONTACT:-}" ]] \
    || die "live steps need ICP_THREAT_INTEL_CONTACT (use a role address, not a personal one)"
fi

if [[ $ONLY_SIGNALS -eq 0 ]]; then
  step "Dependencies (uv sync --all-extras)"
  make setup
fi

if [[ $CHECKS -eq 1 && $ONLY_SIGNALS -eq 0 ]]; then
  step "Checks (ruff, mypy --strict, unit tests)"
  make check
fi

DB_URL="${ICP_THREAT_INTEL_DATABASE_URL:-sqlite:///./icp_threat_intel.db}"
if [[ $POSTGRES -eq 1 ]]; then
  step "Postgres (docker compose up -d db)"
  docker compose up -d db
  for _ in $(seq 1 30); do
    docker compose exec -T db pg_isready -U icp_threat_intel -d icp_threat_intel >/dev/null 2>&1 \
      && break
    sleep 2
  done
  docker compose exec -T db pg_isready -U icp_threat_intel -d icp_threat_intel >/dev/null \
    || die "Postgres did not become ready"
elif [[ "$DB_URL" == sqlite:///* ]]; then
  DB_FILE="${DB_URL#sqlite:///}"
  if [[ -s "$DB_FILE" ]]; then
    BACKUP="${DB_FILE}.$(date -u +%Y%m%dT%H%M%SZ).bak"
    step "Backing up $DB_FILE to $BACKUP"
    cp -p "$DB_FILE" "$BACKUP"
  fi
fi

step "Database migrations (alembic upgrade head)"
make migrate

if [[ $ONLY_SIGNALS -eq 0 ]]; then
  step "Seed IOCs, campaigns and sources (db seed)"
  uv run icp-threat-intel db seed
fi

if [[ $SIGNALS -eq 1 ]]; then
  step "Live: signals feed (read-only forum GETs, $PAGES page(s))"
  if [[ $ONLY_SIGNALS -eq 1 ]]; then
    uv run icp-threat-intel collect signals --pages "$PAGES"  # parses what it stored
  else
    uv run icp-threat-intel collect signals --pages "$PAGES" --no-parse
  fi
fi
if [[ $INSPECT -eq 1 ]]; then
  step "Live: canister inspect on the seed IOC canisters (query-only)"
  for id in "${SEED_CANISTERS[@]}"; do
    uv run icp-threat-intel canister inspect "$id"
  done
fi

if [[ $ONLY_SIGNALS -eq 0 ]]; then
  step "Pipeline: parse, enrich, score"
  uv run icp-threat-intel parse
  uv run icp-threat-intel enrich
  uv run icp-threat-intel score
fi

step "Digest ($DIGEST_DIR)"
uv run icp-threat-intel digest --out "$DIGEST_DIR"

step "Done"
cat <<EOF
Database: ${DB_URL%%://*} ($([[ $POSTGRES -eq 1 ]] && echo docker compose db || echo "${DB_URL#sqlite:///}"))
Live steps: signals=$SIGNALS inspect=$INSPECT
Next: review the digest in $DIGEST_DIR; never open URLs found in collected bodies.
EOF
