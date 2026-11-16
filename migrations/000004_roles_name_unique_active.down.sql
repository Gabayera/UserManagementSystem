DROP INDEX IF EXISTS idx_roles_name_active;
ALTER TABLE roles ADD CONSTRAINT roles_name_key UNIQUE (name);