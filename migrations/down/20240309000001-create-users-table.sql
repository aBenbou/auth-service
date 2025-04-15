-- Migration: Create Users Table
-- Created at: 2024-03-09T00:00:01

-- Write your DOWN migration SQL here

-- Drop indexes first
DROP INDEX IF EXISTS idx_users_email;
DROP INDEX IF EXISTS idx_users_public_id;

-- Drop the table
DROP TABLE IF EXISTS users; 