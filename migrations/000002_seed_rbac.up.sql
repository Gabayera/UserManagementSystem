INSERT INTO roles (id, name, description) VALUES
    ('00000000-0000-4000-8000-000000000001', 'admin',  'full access'),
    ('00000000-0000-4000-8000-000000000002', 'editor', 'manage content'),
    ('00000000-0000-4000-8000-000000000003', 'user',   'read-only on own profile');

INSERT INTO permissions (id, code, description) VALUES
    ('00000000-0000-4000-8000-000000000101', 'user.read',         'read users'),
    ('00000000-0000-4000-8000-000000000102', 'user.create',       'create users'),
    ('00000000-0000-4000-8000-000000000103', 'user.update',       'update users'),
    ('00000000-0000-4000-8000-000000000104', 'user.delete',       'delete users'),
    ('00000000-0000-4000-8000-000000000105', 'role.read',         'read roles'),
    ('00000000-0000-4000-8000-000000000106', 'role.create',       'create roles'),
    ('00000000-0000-4000-8000-000000000107', 'role.update',       'update roles'),
    ('00000000-0000-4000-8000-000000000108', 'role.delete',       'delete roles'),
    ('00000000-0000-4000-8000-000000000109', 'permission.read',   'read permissions'),
    ('00000000-0000-4000-8000-000000000110', 'permission.create', 'create permissions'),
    ('00000000-0000-4000-8000-000000000111', 'permission.update', 'update permissions'),
    ('00000000-0000-4000-8000-000000000112', 'permission.delete', 'delete permissions');

-- admin: every permission
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'admin';

-- editor: read + update users
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'editor'
  AND p.code IN ('user.read', 'user.update');

-- user: read-only
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'user'
  AND p.code = 'user.read';