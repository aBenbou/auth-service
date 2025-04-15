-- Migration: Create Roles Table
-- Created at: 2024-03-09T00:00:04

-- Write your DOWN migration SQL here

-- Drop indexes first
DROP INDEX IF EXISTS idx_roles_name;
DROP INDEX IF EXISTS idx_roles_service_id;

-- Drop the table
DROP TABLE IF EXISTS roles; 