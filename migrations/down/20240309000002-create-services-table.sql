-- Migration: Create Services Table
-- Created at: 2024-03-09T00:00:02

-- Write your DOWN migration SQL here

-- Drop indexes first
DROP INDEX IF EXISTS idx_services_name;
DROP INDEX IF EXISTS idx_services_public_id;

-- Drop the table
DROP TABLE IF EXISTS services; 