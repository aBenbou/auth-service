-- Migration: Create User Service Roles Table
-- Created at: 2024-03-09T00:00:06

-- Write your DOWN migration SQL here

-- Drop indexes first
DROP INDEX IF EXISTS idx_user_service_roles_user_id;
DROP INDEX IF EXISTS idx_user_service_roles_service_id;
DROP INDEX IF EXISTS idx_user_service_roles_role_id;

-- Drop the table
DROP TABLE IF EXISTS user_service_roles; 