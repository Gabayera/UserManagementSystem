# UserManagementSystem

## Integration tests

The repository and service tests require a disposable PostgreSQL database. Start
the project database with `docker compose up -d postgres`, then run:

```sh
DATABASE_URL='postgres://postgres:pass@127.0.0.1:5433/user_management?sslmode=disable' go test ./...
```

The integration test setup creates and drops the `repo_test` and `svc_test`
schemas in the configured database. Do not point `DATABASE_URL` at production
or any database containing data you need to keep.
