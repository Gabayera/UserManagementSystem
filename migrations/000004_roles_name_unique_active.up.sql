-- Role names must be unique only among live roles. The original column-level
-- UNIQUE also counted soft-deleted rows, so a deleted role's name could never
-- be reused (POST /roles returned 409 forever).
ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_name_key;
CREATE UNIQUE INDEX IF NOT EXISTS idx_roles_name_active ON roles(name) WHERE deleted_at IS NULL;