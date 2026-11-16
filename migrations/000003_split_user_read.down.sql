-- Reverse 000003: restore the single `user.read` permission on role `user`.
DELETE FROM role_permissions
WHERE permission_id = '00000000-0000-4000-8000-000000000113';

DELETE FROM permissions
WHERE id = '00000000-0000-4000-8000-000000000113';

UPDATE permissions
SET code = 'user.read', description = 'read users', updated_at = NOW()
WHERE id = '00000000-0000-4000-8000-000000000101' AND code = 'user.read.all';

INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('00000000-0000-4000-8000-000000000003', '00000000-0000-4000-8000-000000000101')
ON CONFLICT DO NOTHING;
