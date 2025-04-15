-- Migration: Create Role Permissions Table
-- Created at: 2024-03-09T00:00:05

-- Write your DOWN migration SQL here

-- Drop indexes first
DROP INDEX IF EXISTS idx_role_permissions_role_id;
DROP INDEX IF EXISTS idx_role_permissions_permission_id;

-- Drop the table
DROP TABLE IF EXISTS role_permissions; 