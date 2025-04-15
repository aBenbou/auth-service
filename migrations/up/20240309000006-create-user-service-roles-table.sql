-- Migration: Create User Service Roles Table
-- Created at: 2024-03-09T00:00:06

-- Write your UP migration SQL here

CREATE TABLE IF NOT EXISTS user_service_roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    service_id INTEGER NOT NULL,
    role_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    UNIQUE (user_id, service_id, role_id)
);

-- Create index on user_id for faster lookups
CREATE INDEX IF NOT EXISTS idx_user_service_roles_user_id ON user_service_roles(user_id);

-- Create index on service_id for faster lookups
CREATE INDEX IF NOT EXISTS idx_user_service_roles_service_id ON user_service_roles(service_id);

-- Create index on role_id for faster lookups
CREATE INDEX IF NOT EXISTS idx_user_service_roles_role_id ON user_service_roles(role_id); 