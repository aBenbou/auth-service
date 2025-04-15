-- Migration: Create Permissions Table
-- Created at: 2024-03-09T00:00:03

-- Write your DOWN migration SQL here

-- Drop index first
DROP INDEX IF EXISTS idx_permissions_name;

-- Drop the table
DROP TABLE IF EXISTS permissions; 