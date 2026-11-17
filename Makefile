.RECIPEPREFIX := >
PY := .venv/bin/python
.PHONY: doctor monitor-check monitor-run test-capture verify-capture verify-capture-active verify-detection verify-detection-standin eval-plan eval-reset eval-smoke eval-tuning eval-evaluation eval-capacity e2e-latency stack-resources scale-db-up scale-db-down seed-scale stack-api-scale bench-parser run-api create-admin migrate migrate-check migration docs-schema setup init-env db-init check-db lab-up lab-down lab-status lab-verify test test-integration lint typecheck frontend-install frontend-build frontend-dev frontend-test frontend-lint freeze

setup:
> @if [ -f .venv/bin/pip ] && ! head -1 .venv/bin/pip | grep -qF "$(CURDIR)/.venv/bin/python"; then echo 'virtualenv was created in another location (project moved or copied): rebuilding it'; rm -rf .venv; fi
> python3 -m venv .venv
> $(PY) -m pip install --upgrade pip
> $(PY) -m pip install -r requirements-dev.txt

doctor:
> scripts/doctor.sh

init-env:
> scripts/init_env.sh

db-init:
> scripts/db_init.sh

migrate:
> $(PY) -m alembic upgrade head

migrate-check:
> $(PY) -m alembic check

migration:
> @test -n "$(m)" || { echo 'usage: make migration m="describe change"'; exit 2; }
> $(PY) -m alembic revision --autogenerate -m "$(m)"

docs-schema:
> $(PY) scripts/gen_schema_doc.py > docs/database-schema.md

monitor-check:
> sudo scripts/run-with-caps.sh $(PY) -m netguard_monitor.main check

monitor-run:
> sudo scripts/run-with-caps.sh $(PY) -m netguard_monitor.main run

test-capture:
> sudo scripts/run-with-caps.sh env NETGUARD_TEST_INTEGRATION=1 $(PY) -m pytest monitor/tests/test_capture_socket.py monitor/tests/test_service.py monitor/tests/test_service_ids.py -p no:cacheprovider

verify-capture:
> sudo $(PY) lab/verify_capture.py

verify-capture-active:
> sudo $(PY) lab/verify_capture.py --active

verify-detection:
> sudo $(PY) lab/verify_detection.py

verify-detection-standin:
> sudo $(PY) lab/verify_detection.py --standin-auth

eval-plan:
> $(PY) lab/evaluate.py plan

eval-reset:
> $(PY) lab/evaluate.py reset-rules

eval-smoke:
> sudo $(PY) lab/evaluate.py run --split tuning --limit-per-group 1

eval-tuning:
> sudo $(PY) lab/evaluate.py run --split tuning

eval-evaluation:
> sudo $(PY) lab/evaluate.py run --split evaluation

eval-capacity:
> sudo $(PY) lab/capacity.py

# Phase 7 (needs lab-up, the monitor with NETGUARD_PROMISCUOUS=true, and the API running; ADMIN = a dashboard admin;
# the password is prompted for)
e2e-latency:
> @test -n "$(ADMIN)" || { echo "usage: make e2e-latency ADMIN=name"; exit 2; }
> sudo -E $(PY) lab/e2e_latency.py --user "$(ADMIN)"

stack-resources:
> @test -n "$(ADMIN)" || { echo "usage: make stack-resources ADMIN=name"; exit 2; }
> sudo -E $(PY) lab/stack_resources.py --user "$(ADMIN)"

# API response times with the tables as big as retention allows (synthetic rows, scratch database; see ADR 0019)
scale-db-up:
> scripts/scale_db.sh up

seed-scale:
> NETGUARD_DB_NAME=netguard_scale $(PY) lab/seed_scale.py

# start the API on the scratch database first: NETGUARD_DB_NAME=netguard_scale NETGUARD_API_PORT=8001 make run-api
# and create an admin there: NETGUARD_DB_NAME=netguard_scale make create-admin USERNAME=name
stack-api-scale:
> @test -n "$(ADMIN)" || { echo "usage: make stack-api-scale ADMIN=name"; exit 2; }
> sudo -E $(PY) lab/stack_resources.py --user "$(ADMIN)" --api http://127.0.0.1:8001 --api-only --db-name netguard_scale

scale-db-down:
> scripts/scale_db.sh down

bench-parser:
> $(PY) lab/bench_parser.py

run-api:
> $(PY) -m app

# usage: make create-admin USERNAME=benjamin   (the password is prompted for, never put on the command line)
create-admin:
> @test -n "$(USERNAME)" || { echo "usage: make create-admin USERNAME=name"; exit 2; }
> $(PY) -m app.cli create-user --username "$(USERNAME)" --role admin

check-db:
> $(PY) -m netguard_common.check_db --role api
> $(PY) -m netguard_common.check_db --role monitor
> $(PY) -m netguard_common.check_db --role migrator

lab-up:
> sudo lab/setup_lab.sh up
lab-down:
> sudo lab/setup_lab.sh down
lab-status:
> lab/setup_lab.sh status
lab-verify:
> sudo lab/setup_lab.sh verify

test:
> $(PY) -m pytest

test-integration:
> NETGUARD_TEST_INTEGRATION=1 $(PY) -m pytest

lint:
> $(PY) -m ruff check .
typecheck:
> $(PY) -m mypy shared/netguard_common backend/app monitor/netguard_monitor

frontend-install:
> cd frontend && npm install
frontend-build:
> cd frontend && npm run build
frontend-dev:
> cd frontend && npm run dev
frontend-test:
> cd frontend && npx vitest run
frontend-lint:
> cd frontend && npm run lint

freeze:
> $(PY) -m pip freeze --exclude-editable > requirements.lock
