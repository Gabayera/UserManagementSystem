SHELL := /bin/bash
.DEFAULT_GOAL := help

MIGRATIONS_DIR := migrations

# DATABASE_URL: prefer shell env, fall back to .env, empty if neither.
DATABASE_URL ?= $(shell grep -E '^DATABASE_URL=' .env 2>/dev/null | head -1 | cut -d= -f2-)

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
	migrate -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" up

migrate-down: db-info
	migrate -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" down 1

migrate-version: db-info
	@migrate -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" version \
		|| echo "(no version — migrations never applied, or schema_migrations missing)"

migrate-force: db-info
	@if [ -z "$(VERSION)" ]; then echo "ERROR: VERSION=N is required (e.g. make migrate-force VERSION=1)"; exit 1; fi
	migrate -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" force $(VERSION)

migrate-create:
	@if [ -z "$(NAME)" ]; then echo "ERROR: NAME=xxx is required (e.g. make migrate-create NAME=add_something)"; exit 1; fi
	migrate create -ext sql -dir $(MIGRATIONS_DIR) -seq $(NAME)

migrate-reset: db-info
	@echo "WARNING: this will roll back ALL migrations on $$(echo '$(DATABASE_URL)' | sed -E 's#(postgres(ql)?://[^:]+):[^@]+@#\1:***@#')"
	@read -p "Type 'yes' to continue: ' CONFIRM; [ "$$CONFIRM" = "yes" ] || { echo "aborted"; exit 1; }; \
	migrate -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" down -all