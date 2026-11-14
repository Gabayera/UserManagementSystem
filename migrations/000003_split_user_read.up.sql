-- Split the over-broad `user.read` permission.
--
-- Before: role `user` held `user.read` ("read users"), so once permissions are
-- enforced every ordinary user could list ALL users, contradicting the role's
-- own description ("read-only on own profile").
--
-- After:
--   user.read.all  — read any user (admin, editor)   [renamed from user.read]
--   user.read.self — read own profile (user)         [new]

UPDATE permissions
SET code = 'user.read.all', description = 'read any user', updated_at = NOW()
WHERE id = '00000000-0000-4000-8000-000000000101' AND code = 'user.read';

INSERT INTO permissions (id, code, description) VALUES
    ('00000000-0000-4000-8000-000000000113', 'user.read.self', 'read own user profile');

-- role `user`: swap read.all -> read.self
DELETE FROM role_permissions
WHERE role_id       = '00000000-0000-4000-8000-000000000003'
  AND permission_id = '00000000-0000-4000-8000-000000000101';

INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('00000000-0000-4000-8000-000000000003', '00000000-0000-4000-8000-000000000113');

-- admin and editor also get read.self (a superset of what a plain user can do).
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('00000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000113'),
    ('00000000-0000-4000-8000-000000000002', '00000000-0000-4000-8000-000000000113');
