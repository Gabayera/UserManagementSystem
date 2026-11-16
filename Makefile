SHELL := /bin/bash
.DEFAULT_GOAL := help

MIGRATIONS_DIR := migrations
MIGRATE := $(shell go env GOPATH)/bin/migrate

# DATABASE_URL: prefer shell env, fall back to .env, empty if neither.
DATABASE_URL ?= $(shell grep -E '^DATABASE_URL=' .env 2>/dev/null | head -1 | cut -d= -f2-)
export DATABASE_URL

.PHONY: help db-info migrate-up migrate-down migrate-version migrate-force migrate-create migrate-reset

help:
	@echo "Targets:"
	@echo "  db-info             Show which DB migrations will target (password redacted)"
	@echo "  migrate-up          Apply all pending migrations"
	@echo "  migrate-down        Roll back ONE migration"
	@echo "  migrate-version     Show current version (and dirty flag if set)"
	@echo "  migrate-force       Force version, clearing dirty flag. Requires VERSION=N"
	@echo "  migrate-create      Create a new up/down pair. Requires NAME=xxx"
	@echo "  migrate-reset       Roll back ALL migrations (dangerous)"

db-info:
	@if [ -z "$(DATABASE_URL)" ]; then \
		echo "ERROR: DATABASE_URL is empty (set it in .env or your shell)"; \
		exit 1; \
	fi; \
	echo "DB: $$(echo '$(DATABASE_URL)' | sed -E 's#(postgres(ql)?://[^:]+):[^@]+@#\1:***@#')"

migrate-up: db-info
	$(MIGRATE) -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" up

migrate-down: db-info
	$(MIGRATE) -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" down 1

migrate-version: db-info
	@$(MIGRATE) -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" version \
		|| echo "(no version — migrations never applied, or schema_migrations missing)"

migrate-force: db-info
	@if [ -z "$(VERSION)" ]; then echo "ERROR: VERSION=N is required (e.g. make migrate-force VERSION=1)"; exit 1; fi
	$(MIGRATE) -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" force $(VERSION)

migrate-create:
	@if [ -z "$(NAME)" ]; then echo "ERROR: NAME=xxx is required (e.g. make migrate-create NAME=add_something)"; exit 1; fi
	$(MIGRATE) create -ext sql -dir $(MIGRATIONS_DIR) -seq $(NAME)

migrate-reset: db-info
	@echo "WARNING: this will roll back ALL migrations on $$(echo '$(DATABASE_URL)' | sed -E 's#(postgres(ql)?://[^:]+):[^@]+@#\1:***@#')"
	@read -p "Type 'yes' to continue: " CONFIRM; [ "$$CONFIRM" = "yes" ] || { echo "aborted"; exit 1; }; \
	$(MIGRATE) -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" down -all

migrate-to:
	@if [ -z "$(VERSION)" ]; then echo "ERROR: VERSION=N is required"; exit 1; fi
	$(MIGRATE) -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" goto $(VERSION)

.PHONY: db-up
db-up:
	@if docker ps -a --format '{{.Names}}' | grep -qx um-pg; then \
	  echo "starting existing um-pg"; docker start um-pg; \
	else \
	  echo "creating fresh um-pg with named volume"; \
	  docker run --name um-pg \
	    -e POSTGRES_PASSWORD=pass \
	    -e POSTGRES_DB=user_management \
	    -p 5433:5432 \
	    -v um-pg-data:/var/lib/postgresql/data \
	    -d postgres:16; \
	fi
	@timeout 30 bash -c 'until docker exec um-pg pg_isready -U postgres -d user_management >/dev/null 2>&1; do sleep 1; done' \
	  || { echo "TIMED OUT"; docker logs --tail 30 um-pg; exit 1; }
	@echo "um-pg ready"