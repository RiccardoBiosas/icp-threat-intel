# Targets follow the Makefile contract in SPEC.md section 6; verify commands depend on them.
.PHONY: setup lint typecheck test check coverage migrate record bootstrap run

COV_TARGETS = --cov=icp_threat_intel.rules --cov=icp_threat_intel.verification \
	--cov=icp_threat_intel.raw_store --cov=icp_threat_intel.core.ic_client
SEED_CANISTERS = tdtqy-oyaaa-aaaae-af2dq-cai cjn37-uyaaa-aaaac-qgnva-cai

setup:
	uv sync --all-extras

lint:
	uv run ruff check . && uv run ruff format --check .

typecheck:
	uv run mypy --strict src

test:
	uv run pytest -q -m "not integration and not live"

check: lint typecheck test

coverage:
	uv run pytest -q -m "not integration and not live" $(COV_TARGETS) \
		--cov-report=term-missing --cov-fail-under=80

migrate:
	uv run alembic upgrade head

record:
	ICP_THREAT_INTEL_RECORD=1 uv run pytest -q -m live

bootstrap:
	uv run icp-threat-intel db seed
	for id in $(SEED_CANISTERS); do uv run icp-threat-intel canister inspect $$id || exit 1; done

run:
	uv run python -m icp_threat_intel.scheduler
