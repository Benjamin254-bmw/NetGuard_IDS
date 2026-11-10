.RECIPEPREFIX := >
PY := .venv/bin/python
.PHONY: doctor monitor-check monitor-run test-capture verify-capture verify-capture-active verify-detection verify-detection-standin migrate migrate-check migration docs-schema setup init-env db-init check-db lab-up lab-down lab-status lab-verify test test-integration lint typecheck frontend-install frontend-build freeze

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

freeze:
> $(PY) -m pip freeze --exclude-editable > requirements.lock
